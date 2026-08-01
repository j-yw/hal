package l7network

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFirecrackerHostTopologyReconcilerQuarantinesBeforeVMStopHandoff(t *testing.T) {
	sequence := &callSequence{}
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	record := journalRecord{identity: identity, stage: journalStageInspected, tapName: spec.name,
		tapFingerprint: spec.fingerprint(), ruleDigest: "old-rule-digest", proxyAddress: spec.proxyAddress.String(), proxyPort: spec.proxyPort}
	journal := &loadedJournalStore{sequence: sequence, record: record}
	topology := newFakeTopology(sequence)
	recovery := &fakeRecoveryTopology{sequence: sequence, lifecycle: topology}
	reconciler, err := NewReconciler(ReconcilerOptions{Recovery: recovery, TAP: &fakeTAP{sequence: sequence},
		Rules: &fakeRules{sequence: sequence}, Journal: journal, CleanupTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	session, err := reconciler.Recover(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if session.Metadata().Status != StatusQuarantined || session.Metadata().Status == StatusActive {
		t.Fatalf("recovered metadata = %#v", session.Metadata())
	}
	if got, want := sequence.snapshot(), []string{"journal_acquire", "journal_load", "recovery_open", "topology_borrow", "rules_quarantine", "journal_save_quarantined"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("recovery sequence = %#v, want %#v", got, want)
	}
	sequence.reset()
	if err := session.CleanupAfterVMQuiesced(context.Background(), identity, false); !errors.Is(err, ErrVMNotQuiesced) {
		t.Fatalf("unconfirmed cleanup = %v", err)
	}
	if len(sequence.snapshot()) != 0 {
		t.Fatalf("reconciler mutated before VM confirmation: %#v", sequence.snapshot())
	}
	if err := session.CleanupAfterVMQuiesced(context.Background(), identity, true); err != nil {
		t.Fatal(err)
	}
	assertSubsequence(t, sequence.snapshot(), []string{"rules_cleanup", "tap_delete", "topology_stop", "journal_remove", "journal_release"})
}

func TestFirecrackerHostTopologyReconcilerFailsClosedWithoutExactRecoveryProof(t *testing.T) {
	sequence := &callSequence{}
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	record := journalRecord{identity: identity, stage: journalStageInspected, tapName: spec.name,
		tapFingerprint: spec.fingerprint(), proxyAddress: spec.proxyAddress.String(), proxyPort: spec.proxyPort}
	recovery := &fakeRecoveryTopology{sequence: sequence, err: errors.New("pid=4242 /proc/private mismatch")}
	reconciler, err := NewReconciler(ReconcilerOptions{Recovery: recovery, TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		Journal: &loadedJournalStore{sequence: sequence, record: record}})
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
