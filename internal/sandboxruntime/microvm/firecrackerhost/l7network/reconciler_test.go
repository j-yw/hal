package l7network

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

func TestFirecrackerHostTopologyReconcilerQuarantinesBeforeVMStopHandoff(t *testing.T) {
	sequence := &callSequence{}
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	record := journalRecord{identity: identity, stage: journalStageInspected, tapName: spec.name,
		tapFingerprint: spec.fingerprint(), tapIfIndex: 41, ruleDigest: "old-rule-digest", proxyAddress: spec.proxyAddress.String(), proxyPort: spec.proxyPort}
	journal := &loadedJournalStore{sequence: sequence, record: record}
	topology := newFakeTopology(sequence)
	recovery := &fakeRecoveryTopology{sequence: sequence, lifecycle: topology}
	reconciler, err := NewReconciler(ReconcilerOptions{Recovery: recovery, TAP: &fakeTAP{sequence: sequence},
		Rules: &fakeRules{sequence: sequence}, VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
		Journal: journal, CleanupTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	session, err := reconciler.Recover(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	metadata := session.Metadata()
	if metadata.Status != StatusQuarantined || metadata.Status == StatusActive || metadata.StructuralInspected ||
		metadata.TAPInspected || metadata.RulesInspected || metadata.RawPacketIsolationVerified || metadata.RuleDigest != "" {
		t.Fatalf("recovered metadata = %#v, want quarantine without active/inspection proof", metadata)
	}
	if got, want := sequence.snapshot(), []string{"journal_acquire", "journal_load", "recovery_open", "topology_borrow", "rules_quarantine", "journal_save_quarantined"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("recovery sequence = %#v, want %#v", got, want)
	}
	sequence.reset()
	if err := session.AbortBeforeVM(context.Background(), identity); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("AbortBeforeVM(recovered quarantine) = %v, want ErrCleanupIncomplete", err)
	}
	if len(sequence.snapshot()) != 0 {
		t.Fatalf("AbortBeforeVM(recovered quarantine) mutated resources: %#v", sequence.snapshot())
	}
	if err := session.CleanupAfterVMQuiesced(context.Background(), identity, nil); !errors.Is(err, ErrVMNotQuiesced) {
		t.Fatalf("unconfirmed cleanup = %v", err)
	}
	if len(sequence.snapshot()) != 0 {
		t.Fatalf("reconciler mutated before VM confirmation: %#v", sequence.snapshot())
	}
	if err := session.CleanupAfterVMQuiesced(context.Background(), identity, testTerminatedVMBinding()); err != nil {
		t.Fatal(err)
	}
	assertSubsequence(t, sequence.snapshot(), []string{"rules_cleanup", "tap_delete", "topology_stop", "journal_remove", "journal_release"})
}

func TestFirecrackerHostTopologyReconcilerFailsClosedWithoutExactRecoveryProof(t *testing.T) {
	sequence := &callSequence{}
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	record := journalRecord{identity: identity, stage: journalStageInspected, tapName: spec.name,
		tapFingerprint: spec.fingerprint(), tapIfIndex: 41, proxyAddress: spec.proxyAddress.String(), proxyPort: spec.proxyPort}
	recovery := &fakeRecoveryTopology{sequence: sequence, err: errors.New("pid=4242 /proc/private mismatch")}
	reconciler, err := NewReconciler(ReconcilerOptions{Recovery: recovery, TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
		Journal:       &loadedJournalStore{sequence: sequence, record: record}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Recover(context.Background(), identity); !errors.Is(err, ErrStaleTopologyUnverified) {
		t.Fatalf("Recover() = %v", err)
	} else if strings.Contains(err.Error(), "4242") || strings.Contains(err.Error(), "/proc/private") {
		t.Fatalf("Recover() leaked raw recovery detail: %v", err)
	}
	if contains(sequence.snapshot(), "rules_quarantine") || contains(sequence.snapshot(), "tap_delete") || contains(sequence.snapshot(), "topology_stop") {
		t.Fatalf("unverified recovery mutated resources: %#v", sequence.snapshot())
	}
}

func TestFirecrackerHostTopologyReconcilerRejectsPreparedProofAsRecoveryAuthority(t *testing.T) {
	sequence := &callSequence{}
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	record := journalRecord{identity: identity, stage: journalStageInspected, tapName: spec.name,
		tapFingerprint: spec.fingerprint(), tapIfIndex: 41, proxyAddress: spec.proxyAddress.String(), proxyPort: spec.proxyPort}
	topology := newFakeTopology(sequence)
	reconciler, err := NewReconciler(ReconcilerOptions{
		Recovery: &preparedRecoveryTopology{sequence: sequence, lifecycle: topology},
		TAP:      &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
		Journal:       &loadedJournalStore{sequence: sequence, record: record},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session, recoverErr := reconciler.Recover(context.Background(), identity); session != nil || !errors.Is(recoverErr, ErrStaleTopologyUnverified) {
		t.Fatalf("Recover(prepared proof) = %T, %v; want cleanup-only rejection", session, recoverErr)
	}
	if contains(sequence.snapshot(), "rules_quarantine") {
		t.Fatalf("prepared proof authorized recovery mutation: %#v", sequence.snapshot())
	}
}

type preparedRecoveryTopology struct {
	sequence  *callSequence
	lifecycle *fakeTopology
}

func TestFirecrackerHostTopologyPrepareRejectsCleanupOnlyRecoveryMetadata(t *testing.T) {
	sequence := &callSequence{}
	options := validCoordinatorOptions(sequence)
	options.Topology = &cleanupOnlyStartTopology{sequence: sequence}
	coordinator := mustCoordinator(t, options)
	if session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()}); session != nil || !errors.Is(err, ErrProofMismatch) {
		t.Fatalf("Prepare(cleanup-only topology) = %T, %v", session, err)
	}
	if contains(sequence.snapshot(), "tap_create") || contains(sequence.snapshot(), "rules_apply_inspect") {
		t.Fatalf("cleanup-only metadata reached proof-producing steps: %#v", sequence.snapshot())
	}
}

type cleanupOnlyStartTopology struct{ sequence *callSequence }

func (t *cleanupOnlyStartTopology) Start(_ context.Context, request linuxtopology.StartRequest) (TopologySession, error) {
	t.sequence.add("topology_start")
	return &cleanupOnlyTopologySession{sequence: t.sequence, identity: request.Identity}, nil
}

func (t *cleanupOnlyStartTopology) Stop(context.Context, linuxtopology.Identity) (linuxtopology.Metadata, error) {
	t.sequence.add("topology_stop")
	return linuxtopology.Metadata{Status: linuxtopology.StatusStopped}, nil
}

type cleanupOnlyTopologySession struct {
	sequence *callSequence
	identity linuxtopology.Identity
}

func (s *cleanupOnlyTopologySession) Metadata() linuxtopology.Metadata {
	return linuxtopology.Metadata{Identity: s.identity, Status: linuxtopology.StatusRecoveryOnly}
}
func (*cleanupOnlyTopologySession) Losses() <-chan linuxtopology.Loss {
	losses := make(chan linuxtopology.Loss)
	close(losses)
	return losses
}
func (s *cleanupOnlyTopologySession) BorrowNamespace() (NamespaceLease, error) {
	s.sequence.add("topology_borrow")
	return &fakeNamespaceLease{rules: linuxrules.NewNamespaceHandle(10, 11)}, nil
}

func (r *preparedRecoveryTopology) Recover(_ context.Context, identity Identity) (TopologyLifecycle, TopologySession, error) {
	r.sequence.add("recovery_open")
	r.lifecycle.session.identity = topologyIdentity(identity)
	return r.lifecycle, r.lifecycle.session, nil
}

type fakeRecoveryTopology struct {
	sequence  *callSequence
	lifecycle *fakeTopology
	err       error
}

func (r *fakeRecoveryTopology) Recover(_ context.Context, identity Identity) (TopologyLifecycle, TopologySession, error) {
	r.sequence.add("recovery_open")
	if r.err != nil {
		return nil, nil, r.err
	}
	r.lifecycle.session.identity = topologyIdentity(identity)
	r.lifecycle.session.recoveryOnly = true
	return r.lifecycle, r.lifecycle.session, nil
}

type loadedJournalStore struct {
	sequence *callSequence
	record   journalRecord
}

func (s *loadedJournalStore) Acquire(context.Context, Identity) (JournalLease, error) {
	s.sequence.add("journal_acquire")
	return &loadedJournalLease{sequence: s.sequence, record: s.record}, nil
}

type loadedJournalLease struct {
	sequence *callSequence
	record   journalRecord
}

func (l *loadedJournalLease) Load() (journalRecord, error) {
	l.sequence.add("journal_load")
	return l.record, nil
}
func (l *loadedJournalLease) Save(_ context.Context, record journalRecord) error {
	l.record = record
	l.sequence.add("journal_save_" + string(record.stage))
	return nil
}
func (l *loadedJournalLease) Remove() error  { l.sequence.add("journal_remove"); return nil }
func (l *loadedJournalLease) Release() error { l.sequence.add("journal_release"); return nil }
