package l7network

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology"
)

func TestFirecrackerHostTopologyConstructorsRejectTypedNilDependencies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Options)
	}{
		{name: "proxy", mutate: func(o *Options) { var value *fakeProxy; o.Proxy = value }},
		{name: "topology", mutate: func(o *Options) { var value *fakeTopology; o.Topology = value }},
		{name: "TAP", mutate: func(o *Options) { var value *fakeTAP; o.TAP = value }},
		{name: "rules", mutate: func(o *Options) { var value *fakeRules; o.Rules = value }},
		{name: "journal", mutate: func(o *Options) { var value *fakeJournalStore; o.Journal = value }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sequence := &callSequence{}
			options := validCoordinatorOptions(sequence)
			tc.mutate(&options)
			if _, err := New(options); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("New() = %v, want ErrInvalidConfiguration", err)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		mutate func(*ReconcilerOptions)
	}{
		{name: "recovery", mutate: func(o *ReconcilerOptions) { var value *fakeRecoveryTopology; o.Recovery = value }},
		{name: "TAP", mutate: func(o *ReconcilerOptions) { var value *fakeTAP; o.TAP = value }},
		{name: "rules", mutate: func(o *ReconcilerOptions) { var value *fakeRules; o.Rules = value }},
		{name: "journal", mutate: func(o *ReconcilerOptions) { var value *loadedJournalStore; o.Journal = value }},
	} {
		t.Run("reconciler "+tc.name, func(t *testing.T) {
			sequence := &callSequence{}
			topology := newFakeTopology(sequence)
			options := ReconcilerOptions{
				Recovery: &fakeRecoveryTopology{sequence: sequence, lifecycle: topology},
				TAP:      &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
				VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
				Journal:       &loadedJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
			}
			tc.mutate(&options)
			if _, err := NewReconciler(options); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewReconciler() = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestFirecrackerHostTopologyPrepareRejectsTypedNilReturnedInterfaces(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*Options, *callSequence)
		want      []error
		retained  bool
		blocked   bool
		cleanup   []string
	}{
		{name: "journal lease", configure: func(o *Options, sequence *callSequence) {
			o.Journal = &typedNilJournalLeaseStore{sequence: sequence}
		}, want: []error{ErrCleanupIncomplete}, retained: true, blocked: true},
		{name: "proxy generation", configure: func(o *Options, sequence *callSequence) {
			o.Proxy = &typedNilGenerationProxy{sequence: sequence}
		}, want: []error{ErrProxyUnavailable, ErrCleanupIncomplete}, retained: true},
		{name: "topology session", configure: func(o *Options, sequence *callSequence) {
			o.Topology = &typedNilSessionTopology{sequence: sequence}
		}, want: []error{ErrTopologyPrepareFailed, ErrCleanupIncomplete}, retained: true, cleanup: []string{"proxy_stop"}},
		{name: "namespace lease", configure: func(o *Options, sequence *callSequence) {
			o.Topology = &typedNilNamespaceTopology{sequence: sequence}
		}, want: []error{ErrTopologyPrepareFailed}, cleanup: []string{"topology_stop", "proxy_stop", "journal_remove", "journal_release"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sequence := &callSequence{}
			options := validCoordinatorOptions(sequence)
			tc.configure(&options, sequence)
			coordinator := mustCoordinator(t, options)
			session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
			for _, want := range tc.want {
				if !errors.Is(err, want) {
					t.Fatalf("Prepare() = %v, want %v", err, want)
				}
			}
			if tc.retained != (session != nil) {
				t.Fatalf("Prepare() retained session = %t, want %t", session != nil, tc.retained)
			}
			if tc.blocked {
				identity := alternateIdentity()
				if _, nextErr := coordinator.Prepare(context.Background(), PrepareRequest{Identity: identity, Plan: planForIdentity(identity)}); !errors.Is(nextErr, ErrTopologyCollision) {
					t.Fatalf("Prepare(after untracked acquisition) = %v, want ErrTopologyCollision", nextErr)
				}
			}
			assertSubsequence(t, sequence.snapshot(), tc.cleanup)
		})
	}
}

func TestFirecrackerHostTopologyRetainsJournalUntilReleaseRetrySucceeds(t *testing.T) {
	sequence := &callSequence{}
	store := &releaseRetryJournalStore{sequence: sequence, firstSaveErr: errors.New("private journal save failure"), firstReleaseFailures: 1}
	options := validCoordinatorOptions(sequence)
	options.Journal = store
	coordinator := mustCoordinator(t, options)
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if session == nil || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Prepare() = session %T, error %v; want retained cleanup-incomplete lease", session, err)
	}
	identity := alternateIdentity()
	if _, nextErr := coordinator.Prepare(context.Background(), PrepareRequest{Identity: identity, Plan: planForIdentity(identity)}); !errors.Is(nextErr, ErrTopologyCollision) {
		t.Fatalf("Prepare(before release retry) = %v, want ErrTopologyCollision", nextErr)
	}
	if err := session.RetryRetainedCleanup(context.Background(), testIdentity()); err != nil {
		t.Fatalf("RetryRetainedCleanup() = %v", err)
	}
	if store.first.releaseCalls != 2 {
		t.Fatalf("exact journal release calls = %d, want 2", store.first.releaseCalls)
	}
	if _, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: identity, Plan: planForIdentity(identity)}); err != nil {
		t.Fatalf("Prepare(after release retry) = %v", err)
	}
}

func TestFirecrackerHostTopologyRetainsLeaseReturnedWithAcquireError(t *testing.T) {
	for _, operation := range []string{"prepare", "recover"} {
		t.Run(operation, func(t *testing.T) {
			sequence := &callSequence{}
			store := &releaseRetryJournalStore{sequence: sequence, acquireErr: errors.New("private journal acquire failure"), firstReleaseFailures: 1}
			var session *Session
			var err error
			if operation == "prepare" {
				options := validCoordinatorOptions(sequence)
				options.Journal = store
				session, err = mustCoordinator(t, options).Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
			} else {
				topology := newFakeTopology(sequence)
				reconciler, newErr := NewReconciler(ReconcilerOptions{
					Recovery: &fakeRecoveryTopology{sequence: sequence, lifecycle: topology},
					TAP:      &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
					VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
					Journal:       store, CleanupTimeout: time.Second,
				})
				if newErr != nil {
					t.Fatal(newErr)
				}
				session, err = reconciler.Recover(context.Background(), testIdentity())
			}
			if session == nil || !errors.Is(err, ErrCleanupIncomplete) {
				t.Fatalf("%s = session %T, error %v; want retained cleanup-incomplete lease", operation, session, err)
			}
			if err := session.RetryRetainedCleanup(context.Background(), testIdentity()); err != nil {
				t.Fatalf("RetryRetainedCleanup() = %v", err)
			}
			wantStatus := StatusStopped
			if operation == "recover" {
				wantStatus = StatusCleanupIncomplete
			}
			if got := session.Metadata().Status; got != wantStatus {
				t.Fatalf("retained cleanup status = %q, want %q", got, wantStatus)
			}
			if store.first.releaseCalls != 2 {
				t.Fatalf("exact journal release calls = %d, want 2", store.first.releaseCalls)
			}
		})
	}
}

func TestFirecrackerHostTopologyRetainsNamespaceReturnedWithBorrowError(t *testing.T) {
	sequence := &callSequence{}
	topology := newRetryNamespaceTopology(sequence)
	topology.session.borrowErr = errors.New("private namespace borrow failure")
	options := validCoordinatorOptions(sequence)
	options.Topology = topology
	coordinator := mustCoordinator(t, options)
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if session == nil || !errors.Is(err, ErrTopologyPrepareFailed) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Prepare() = session %T, error %v; want retained partial namespace cleanup", session, err)
	}
	if topology.lease.closeCalls != 1 || topology.lease.closed {
		t.Fatalf("first namespace close = calls %d, closed %t; want retained exact handle", topology.lease.closeCalls, topology.lease.closed)
	}
	if err := session.RetryFailedPrepareCleanup(context.Background(), testIdentity()); err != nil {
		t.Fatalf("RetryFailedPrepareCleanup() = %v", err)
	}
	if topology.lease.closeCalls != 2 || !topology.lease.closed {
		t.Fatalf("retried namespace close = calls %d, closed %t", topology.lease.closeCalls, topology.lease.closed)
	}
}

func TestFirecrackerHostTopologyRetainsTAPReturnedWithCreateError(t *testing.T) {
	sequence := &callSequence{}
	tap := &fakeTAP{sequence: sequence, createErr: errors.New("private TAP creation failure"), returnStateOnCreateErr: true, deleteFailures: 1}
	options := validCoordinatorOptions(sequence)
	options.TAP = tap
	coordinator := mustCoordinator(t, options)
	session, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if session == nil || !errors.Is(err, ErrTopologyPrepareFailed) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Prepare() = session %T, error %v; want retained partial TAP cleanup", session, err)
	}
	if tap.deleteCalls != 1 || contains(sequence.snapshot(), "topology_stop") {
		t.Fatalf("first cleanup = TAP deletes %d, sequence %#v; want exact TAP retained before topology stop", tap.deleteCalls, sequence.snapshot())
	}
	sequence.reset()
	if err := session.RetryFailedPrepareCleanup(context.Background(), testIdentity()); err != nil {
		t.Fatalf("RetryFailedPrepareCleanup() = %v", err)
	}
	if tap.deleteCalls != 2 {
		t.Fatalf("exact TAP delete calls = %d, want 2", tap.deleteCalls)
	}
	assertSubsequence(t, sequence.snapshot(), []string{"tap_delete", "topology_stop", "proxy_stop", "journal_remove", "journal_release"})
}

func TestFirecrackerHostTopologyReconcilerRetainsNamespaceReturnedWithBorrowError(t *testing.T) {
	sequence := &callSequence{}
	identity := testIdentity()
	topology := newRetryNamespaceTopology(sequence)
	topology.session.borrowErr = errors.New("private namespace borrow failure")
	store := &releaseRetryJournalStore{sequence: sequence, record: journalRecord{identity: identity, stage: journalStageTAPCreated}}
	reconciler, err := NewReconciler(ReconcilerOptions{
		Recovery: &retryNamespaceRecovery{topology: topology}, TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
		Journal:       store, CleanupTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := reconciler.Recover(context.Background(), identity)
	if session == nil || !errors.Is(err, ErrStaleTopologyUnverified) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Recover() = session %T, error %v; want retained partial namespace cleanup", session, err)
	}
	if topology.lease.closeCalls != 1 || topology.lease.closed || store.first.releaseCalls != 0 {
		t.Fatalf("first cleanup = namespace calls %d, closed %t, journal calls %d", topology.lease.closeCalls, topology.lease.closed, store.first.releaseCalls)
	}
	if err := session.RetryRetainedCleanup(context.Background(), identity); err != nil {
		t.Fatalf("RetryRetainedCleanup() = %v", err)
	}
	if topology.lease.closeCalls != 2 || !topology.lease.closed || store.first.releaseCalls != 1 {
		t.Fatalf("retry cleanup = namespace calls %d, closed %t, journal calls %d", topology.lease.closeCalls, topology.lease.closed, store.first.releaseCalls)
	}
	if got := session.Metadata().Status; got != StatusCleanupIncomplete {
		t.Fatalf("recovered stale cleanup status = %q, want %q", got, StatusCleanupIncomplete)
	}
}

func TestFirecrackerHostTopologyReconcilerRetainsFailedEarlyRelease(t *testing.T) {
	sequence := &callSequence{}
	store := &releaseRetryJournalStore{sequence: sequence, firstLoadErr: errors.New("private journal load failure"), firstReleaseFailures: 1}
	topology := newFakeTopology(sequence)
	reconciler, err := NewReconciler(ReconcilerOptions{
		Recovery: &fakeRecoveryTopology{sequence: sequence, lifecycle: topology},
		TAP:      &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
		Journal:       store, CleanupTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := reconciler.Recover(context.Background(), testIdentity())
	if session == nil || !errors.Is(err, ErrStaleTopologyUnverified) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Recover() = session %T, error %v; want retained stale cleanup", session, err)
	}
	if err := session.RetryRetainedCleanup(context.Background(), testIdentity()); err != nil {
		t.Fatalf("RetryRetainedCleanup() = %v", err)
	}
	if got := session.Metadata().Status; got != StatusCleanupIncomplete {
		t.Fatalf("recovered stale cleanup status = %q, want %q", got, StatusCleanupIncomplete)
	}
	if store.first.releaseCalls != 2 {
		t.Fatalf("exact reconciler journal release calls = %d, want 2", store.first.releaseCalls)
	}
}

func TestFirecrackerHostTopologyReconcilerRetainsBorrowedNamespaceUntilCloseRetry(t *testing.T) {
	sequence := &callSequence{}
	identity := testIdentity()
	topology := newRetryNamespaceTopology(sequence)
	store := &releaseRetryJournalStore{sequence: sequence, record: journalRecord{
		identity: identity, stage: journalStageTAPCreated, proxyAddress: "invalid",
	}}
	reconciler, err := NewReconciler(ReconcilerOptions{
		Recovery: &retryNamespaceRecovery{topology: topology}, TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
		Journal:       store, CleanupTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := reconciler.Recover(context.Background(), identity)
	if session == nil || !errors.Is(err, ErrStaleTopologyUnverified) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Recover() = session %T, error %v; want retained stale namespace cleanup", session, err)
	}
	if topology.lease.closeCalls != 1 || topology.lease.closed {
		t.Fatalf("first namespace close = calls %d, closed %t; want retained failed handle", topology.lease.closeCalls, topology.lease.closed)
	}
	if store.first.releaseCalls != 0 {
		t.Fatalf("journal released before namespace close = %d calls", store.first.releaseCalls)
	}
	if err := session.RetryRetainedCleanup(context.Background(), identity); err != nil {
		t.Fatalf("RetryRetainedCleanup() = %v", err)
	}
	if got := session.Metadata().Status; got != StatusCleanupIncomplete {
		t.Fatalf("recovered stale cleanup status = %q, want %q", got, StatusCleanupIncomplete)
	}
	if topology.lease.closeCalls != 2 || !topology.lease.closed || store.first.releaseCalls != 1 {
		t.Fatalf("retry cleanup = namespace calls %d, closed %t, journal calls %d", topology.lease.closeCalls, topology.lease.closed, store.first.releaseCalls)
	}
}

func TestFirecrackerHostTopologyReconcilerRetainsJournalAfterBorrowValidationFailure(t *testing.T) {
	sequence := &callSequence{}
	identity := testIdentity()
	topology := newRetryNamespaceTopology(sequence)
	topology.lease.closeFailures = 0
	store := &releaseRetryJournalStore{sequence: sequence, firstReleaseFailures: 1, record: journalRecord{
		identity: identity, stage: journalStageTAPCreated, proxyAddress: "invalid",
	}}
	reconciler, err := NewReconciler(ReconcilerOptions{
		Recovery: &retryNamespaceRecovery{topology: topology}, TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
		Journal:       store, CleanupTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := reconciler.Recover(context.Background(), identity)
	if session == nil || !errors.Is(err, ErrStaleTopologyUnverified) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Recover() = session %T, error %v; want retained stale journal cleanup", session, err)
	}
	if err := session.RetryRetainedCleanup(context.Background(), identity); err != nil {
		t.Fatalf("RetryRetainedCleanup() = %v", err)
	}
	if got := session.Metadata().Status; got != StatusCleanupIncomplete {
		t.Fatalf("recovered stale cleanup status = %q, want %q", got, StatusCleanupIncomplete)
	}
	if topology.lease.closeCalls != 1 || !topology.lease.closed || store.first.releaseCalls != 2 {
		t.Fatalf("cleanup = namespace calls %d, closed %t, journal calls %d", topology.lease.closeCalls, topology.lease.closed, store.first.releaseCalls)
	}
}

func TestFirecrackerHostTopologyRecoverRejectsTypedNilReturnedInterfaces(t *testing.T) {
	identity := testIdentity()
	spec := staticTAPSpec(identity, netip.MustParseAddr("192.0.2.2"), 43123)
	record := journalRecord{identity: identity, stage: journalStageInspected, tapName: spec.name,
		tapFingerprint: spec.fingerprint(), tapIfIndex: 41, proxyAddress: spec.proxyAddress.String(), proxyPort: spec.proxyPort}
	for _, tc := range []struct {
		name     string
		journal  func(*callSequence) JournalStore
		recovery func(*callSequence) RecoveryTopology
	}{
		{name: "journal lease", journal: func(sequence *callSequence) JournalStore {
			return &typedNilLoadedJournalLeaseStore{sequence: sequence}
		}},
		{name: "recovery lifecycle", recovery: func(sequence *callSequence) RecoveryTopology {
			return &typedNilRecoveryResult{sequence: sequence, lifecycleNil: true}
		}},
		{name: "recovery session", recovery: func(sequence *callSequence) RecoveryTopology {
			return &typedNilRecoveryResult{sequence: sequence, sessionNil: true}
		}},
		{name: "namespace lease", recovery: func(sequence *callSequence) RecoveryTopology {
			return &typedNilRecoveryResult{sequence: sequence, namespaceNil: true}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sequence := &callSequence{}
			journal := JournalStore(&loadedJournalStore{sequence: sequence, record: record})
			if tc.journal != nil {
				journal = tc.journal(sequence)
			}
			recovery := RecoveryTopology(&typedNilRecoveryResult{sequence: sequence})
			if tc.recovery != nil {
				recovery = tc.recovery(sequence)
			}
			reconciler, err := NewReconciler(ReconcilerOptions{
				Recovery: recovery, TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
				VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
				Journal:       journal, CleanupTimeout: time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reconciler.Recover(context.Background(), identity); !errors.Is(err, ErrStaleTopologyUnverified) {
				t.Fatalf("Recover() = %v, want ErrStaleTopologyUnverified", err)
			}
		})
	}
}

func TestFirecrackerHostTopologySuccessfulCleanupRetiresCoordinatorSession(t *testing.T) {
	sequence := &callSequence{}
	coordinator := mustCoordinator(t, validCoordinatorOptions(sequence))
	first, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: testIdentity(), Plan: testPlan()})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Quarantine(context.Background(), testIdentity()); err != nil {
		t.Fatal(err)
	}
	if err := first.CleanupAfterVMQuiesced(context.Background(), testIdentity(), testTerminatedVMBinding()); err != nil {
		t.Fatal(err)
	}
	identity := alternateIdentity()
	if _, err := coordinator.Prepare(context.Background(), PrepareRequest{Identity: identity, Plan: planForIdentity(identity)}); err != nil {
		t.Fatalf("replacement Prepare() = %v, want success after exact cleanup", err)
	}
}

func validCoordinatorOptions(sequence *callSequence) Options {
	return Options{
		Enabled: true, Proxy: newFakeProxy(sequence), Topology: newFakeTopology(sequence),
		TAP: &fakeTAP{sequence: sequence}, Rules: &fakeRules{sequence: sequence},
		GuestIsolation: &fakeRawPacketVerifier{}, VMTermination: &fakeVMTerminationVerifier{stopped: true, reaped: true},
		Journal: &fakeJournalStore{sequence: sequence}, CleanupTimeout: time.Second,
	}
}

type typedNilJournalLeaseStore struct{ sequence *callSequence }

func (s *typedNilJournalLeaseStore) Acquire(context.Context, Identity) (JournalLease, error) {
	s.sequence.add("journal_acquire")
	var lease *fakeJournalLease
	return lease, nil
}

type releaseRetryJournalStore struct {
	sequence             *callSequence
	record               journalRecord
	acquireErr           error
	firstLoadErr         error
	firstSaveErr         error
	firstReleaseFailures int
	acquires             int
	first                *releaseRetryJournalLease
}

func (s *releaseRetryJournalStore) Acquire(context.Context, Identity) (JournalLease, error) {
	s.sequence.add("journal_acquire")
	s.acquires++
	if s.acquires == 1 {
		s.first = &releaseRetryJournalLease{sequence: s.sequence, loadErr: s.firstLoadErr,
			record: s.record, saveErr: s.firstSaveErr, releaseFailures: s.firstReleaseFailures}
		return s.first, s.acquireErr
	}
	return &fakeJournalLease{sequence: s.sequence}, nil
}

type releaseRetryJournalLease struct {
	sequence        *callSequence
	record          journalRecord
	loadErr         error
	saveErr         error
	releaseFailures int
	releaseCalls    int
}

func (l *releaseRetryJournalLease) Load() (journalRecord, error) {
	l.sequence.add("journal_load")
	if l.loadErr != nil {
		return journalRecord{}, l.loadErr
	}
	if validIdentity(l.record.identity) {
		return l.record, nil
	}
	return journalRecord{}, ErrJournalNotFound
}

func (l *releaseRetryJournalLease) Save(_ context.Context, record journalRecord) error {
	l.sequence.add("journal_save_" + string(record.stage))
	return l.saveErr
}

type retryNamespaceRecovery struct{ topology *retryNamespaceTopology }

func (r *retryNamespaceRecovery) Recover(_ context.Context, identity Identity) (TopologyLifecycle, TopologySession, error) {
	r.topology.session.identity = topologyIdentity(identity)
	return r.topology, r.topology.session, nil
}

func (l *releaseRetryJournalLease) Remove() error {
	l.sequence.add("journal_remove")
	return nil
}

func (l *releaseRetryJournalLease) Release() error {
	l.sequence.add("journal_release")
	l.releaseCalls++
	if l.releaseCalls <= l.releaseFailures {
		return errors.New("private journal release failure")
	}
	return nil
}

type typedNilGenerationProxy struct{ sequence *callSequence }

func (p *typedNilGenerationProxy) Start(context.Context, networkenforcement.Plan) (ProxyGeneration, error) {
	p.sequence.add("proxy_start")
	var generation *fakeGeneration
	return generation, nil
}
func (*typedNilGenerationProxy) Endpoint(ProxyGeneration) (string, error) { return "", nil }
func (*typedNilGenerationProxy) Active(context.Context, networkenforcement.Plan, ProxyGeneration) error {
	return nil
}
func (p *typedNilGenerationProxy) Stop(context.Context, networkenforcement.Plan, ProxyGeneration) error {
	p.sequence.add("proxy_stop")
	return nil
}

type typedNilSessionTopology struct{ sequence *callSequence }

func (t *typedNilSessionTopology) Start(context.Context, linuxtopology.StartRequest) (TopologySession, error) {
	t.sequence.add("topology_start")
	var session *fakeTopologySession
	return session, nil
}
func (t *typedNilSessionTopology) Stop(context.Context, linuxtopology.Identity) (linuxtopology.Metadata, error) {
	t.sequence.add("topology_stop")
	return linuxtopology.Metadata{Status: linuxtopology.StatusStopped}, nil
}

type typedNilNamespaceTopology struct{ sequence *callSequence }

func (t *typedNilNamespaceTopology) Start(_ context.Context, request linuxtopology.StartRequest) (TopologySession, error) {
	t.sequence.add("topology_start")
	return &typedNilBorrowSession{sequence: t.sequence, identity: request.Identity}, nil
}
func (t *typedNilNamespaceTopology) Stop(context.Context, linuxtopology.Identity) (linuxtopology.Metadata, error) {
	t.sequence.add("topology_stop")
	return linuxtopology.Metadata{Status: linuxtopology.StatusStopped}, nil
}

type typedNilBorrowSession struct {
	sequence *callSequence
	identity linuxtopology.Identity
}

func (s *typedNilBorrowSession) Metadata() linuxtopology.Metadata {
	return linuxtopology.Metadata{Identity: s.identity, Status: linuxtopology.StatusPrepared, StructuralInspected: true, MappingReachable: true}
}
func (s *typedNilBorrowSession) BorrowNamespace() (NamespaceLease, error) {
	s.sequence.add("topology_borrow")
	var lease *fakeNamespaceLease
	return lease, nil
}

type typedNilLoadedJournalLeaseStore struct{ sequence *callSequence }

func (s *typedNilLoadedJournalLeaseStore) Acquire(context.Context, Identity) (JournalLease, error) {
	s.sequence.add("journal_acquire")
	var lease *loadedJournalLease
	return lease, nil
}

type typedNilRecoveryResult struct {
	sequence     *callSequence
	lifecycleNil bool
	sessionNil   bool
	namespaceNil bool
}

func (r *typedNilRecoveryResult) Recover(_ context.Context, identity Identity) (TopologyLifecycle, TopologySession, error) {
	r.sequence.add("recovery_open")
	var lifecycle TopologyLifecycle = newFakeTopology(r.sequence)
	if r.lifecycleNil {
		var value *fakeTopology
		lifecycle = value
	}
	var session TopologySession = &typedNilBorrowSession{sequence: r.sequence, identity: topologyIdentity(identity)}
	if r.sessionNil {
		var value *typedNilBorrowSession
		session = value
	} else if !r.namespaceNil {
		topology := newFakeTopology(r.sequence)
		topology.session.identity = topologyIdentity(identity)
		session = topology.session
	}
	return lifecycle, session, nil
}

func alternateIdentity() Identity {
	return Identity{SandboxID: "sandbox-b", ExecutionID: "execution-b", WorkerID: "worker-b", RuntimeGenerationID: "runtime-b",
		PlanID: "plan-b", PolicySnapshotID: "policy-b", ProxySessionID: "proxy-session-b", ProxyGenerationID: "proxy-generation-b",
		TopologyGenerationID: "topology-generation-b", RuleGenerationID: "rule-generation-b"}
}

func planForIdentity(identity Identity) networkenforcement.Plan {
	plan := testPlan()
	plan.ID = identity.PlanID
	plan.PolicySnapshot.ID = identity.PolicySnapshotID
	plan.Proxy.ProxySessionID = identity.ProxySessionID
	return plan
}
