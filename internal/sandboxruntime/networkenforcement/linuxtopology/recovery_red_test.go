package linuxtopology

import (
	"context"
	"errors"
	"testing"
	"time"
)

type recoveryTestOwnershipStore struct {
	base   *memoryOwnershipStore
	keeper ProcessHandle
	mapper ProcessHandle
	err    error
}

func (s *recoveryTestOwnershipStore) Acquire(ctx context.Context, identity Identity) (OwnershipLease, error) {
	return s.base.Acquire(ctx, identity)
}

func (s *recoveryTestOwnershipStore) AcquireRecovery(ctx context.Context, request RecoveryRequest) (RecoveredOwnership, error) {
	if s.err != nil {
		return RecoveredOwnership{}, s.err
	}
	lease, err := s.base.Acquire(ctx, request.Identity)
	if err != nil {
		return RecoveredOwnership{}, err
	}
	namespace, err := request.Namespace.Duplicate()
	if err != nil {
		_ = lease.Release()
		return RecoveredOwnership{}, err
	}
	return RecoveredOwnership{Lease: lease, Keeper: s.keeper, Mapper: s.mapper, Namespace: namespace}, nil
}

func TestLinuxTopologyRecoverInstallsCleanupOnlySession(t *testing.T) {
	starter := newFakeStarter()
	namespaces := newFakeNamespaces(t, &starter.events)
	keeper := newFakeProcess(7101, ProcessRoleKeeper, &starter.events)
	mapper := newFakeProcess(7102, ProcessRoleMapping, &starter.events)
	ownership := &recoveryTestOwnershipStore{base: newMemoryOwnershipStore(), keeper: keeper, mapper: mapper}
	lifecycle, err := New(Config{
		Enabled: true, Tools: testTools(), Starter: starter,
		Runner: &fakeRunner{output: goodLinkJSON()}, OpenNamespaces: namespaces.Open,
		Reachability: &fakeReachabilityProber{}, Ownership: ownership,
		CleanupTimeout: 250 * time.Millisecond, InspectionTimeout: 250 * time.Millisecond,
		InspectionInterval: time.Millisecond, OutputLimit: 8 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	input, err := namespaces.base.Duplicate()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	identity := testIdentity("topology-gen-recovery-only")
	session, err := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: identity, Namespace: input})
	if err != nil {
		t.Fatal(err)
	}
	metadata := session.Metadata()
	if metadata.Identity != identity || metadata.Status != StatusRecoveryOnly || metadata.StructuralInspected || metadata.MappingReachable {
		t.Fatalf("recovered metadata = %#v, want cleanup-only authority", metadata)
	}
	borrowed, err := session.NamespaceHandle()
	if err != nil {
		t.Fatalf("borrow recovered namespace: %v", err)
	}
	if !borrowed.Correlates(input) {
		t.Fatal("recovered namespace did not preserve exact kernel identity")
	}
	if err := borrowed.Close(); err != nil {
		t.Fatal(err)
	}
	if input.Closed() {
		t.Fatal("Recover consumed caller-owned namespace")
	}
	stopped, err := lifecycle.Stop(context.Background(), identity)
	if err != nil || stopped.Status != StatusStopped || stopped.StructuralInspected || stopped.MappingReachable {
		t.Fatalf("Stop(recovered) = %#v, %v", stopped, err)
	}
	if keeper.terminateCount != 1 || mapper.terminateCount != 1 {
		t.Fatalf("cleanup counts = keeper %d mapper %d, want one each", keeper.terminateCount, mapper.terminateCount)
	}
}

func TestLinuxTopologyRecoverRejectsUnprovedAuthorityWithoutMutation(t *testing.T) {
	starter := newFakeStarter()
	namespaces := newFakeNamespaces(t, &starter.events)
	ownership := &recoveryTestOwnershipStore{base: newMemoryOwnershipStore(), err: errors.New("private pid and namespace detail")}
	lifecycle, err := New(Config{
		Enabled: true, Tools: testTools(), Starter: starter,
		Runner: &fakeRunner{output: goodLinkJSON()}, OpenNamespaces: namespaces.Open,
		Reachability: &fakeReachabilityProber{}, Ownership: ownership,
	})
	if err != nil {
		t.Fatal(err)
	}
	input, err := namespaces.base.Duplicate()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	for _, request := range []RecoveryRequest{
		{Identity: testIdentity("topology-gen-recovery-missing")},
		{Identity: testIdentity("topology-gen-recovery-unsafe"), Namespace: input},
	} {
		if request.Namespace != nil {
			request.Identity.WorkerID = "../private"
		}
		if session, recoverErr := lifecycle.Recover(context.Background(), request); session != nil || recoverErr == nil {
			t.Fatalf("Recover(%#v) = %T, %v; want fail closed", request.Identity, session, recoverErr)
		}
	}
	identity := testIdentity("topology-gen-recovery-private")
	if session, recoverErr := lifecycle.Recover(context.Background(), RecoveryRequest{Identity: identity, Namespace: input}); session != nil ||
		!errors.Is(recoverErr, ErrStaleTopologyUnverified) || recoverErr.Error() != ErrStaleTopologyUnverified.Error() {
		t.Fatalf("Recover(private failure) = %T, %v; want sanitized stale error", session, recoverErr)
	}
	if keeper := starter.latest(ProcessRoleKeeper); keeper != nil {
		t.Fatal("recovery failure started or mutated a process")
	}
	if input.Closed() {
		t.Fatal("recovery failure consumed caller namespace")
	}
}
