//go:build linux

package firecrackerhost

import (
	"context"
	"slices"
	"sync"
	"testing"
)

// This observer delegates every mutation and reads the real selected store.
// It does not fake a receipt, block retirement, or replace protocol responses.
type minimalFinalizationObservedStore struct {
	l8RuntimeOwnerRecordStore
	mu              sync.Mutex
	finalized       firecrackerRuntimeOwnerRecordV1
	readback        firecrackerRuntimeOwnerRecordV1
	readErr         error
	finalizedWrites int
	retireCalls     int
}

func (store *minimalFinalizationObservedStore) Transition(ctx context.Context, revision uint64, next firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error) {
	actual, err := store.l8RuntimeOwnerRecordStore.Transition(ctx, revision, next)
	if err == nil && actual.State == "finalized" && next.ControllerState == "controlled" {
		readback, readErr := store.l8RuntimeOwnerRecordStore.Load(ctx)
		store.mu.Lock()
		store.finalized, store.readback, store.readErr = actual, readback, readErr
		store.finalizedWrites++
		store.mu.Unlock()
	}
	return actual, err
}

func (store *minimalFinalizationObservedStore) RetireFinalized(ctx context.Context, revision uint64, commit string) error {
	store.mu.Lock()
	store.retireCalls++
	store.mu.Unlock()
	return store.l8RuntimeOwnerRecordStore.RetireFinalized(ctx, revision, commit)
}

func (store *minimalFinalizationObservedStore) observedFinalization(t *testing.T) (firecrackerRuntimeOwnerRecordV1, int) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.finalizedWrites != 1 || store.readErr != nil || store.readback != store.finalized {
		t.Fatalf("fixture did not persist and read back one actual finalization: writes=%d readErr=%v equal=%v", store.finalizedWrites, store.readErr, store.readback == store.finalized)
	}
	record := store.finalized
	if record.State != "finalized" || record.ControllerState != "controlled" || record.FinalizeTargetRevision != record.Revision || record.FinalizedCommitID == "" || record.AbsenceRevision == 0 || record.AbsenceObservedAtUnixNano <= 0 {
		t.Fatal("fixture never reached the actual finalized checkpoint")
	}
	return record, store.retireCalls
}

func TestMinimalJailerFinalizationLeavesRecordBeforeCommit(t *testing.T) {
	// This is actual client authentication, canonical selected-store publication,
	// and seqpacket/FSM exchange. Host/process/peer and VM observations remain
	// the existing injected fixture; there is no eight-role or L7 cleanup proof.
	f := newJailerRecoveryWireFixture(t)
	store := &minimalFinalizationObservedStore{l8RuntimeOwnerRecordStore: f.owned.store}
	f.owner.opts.Store = store
	client := f.fresh(t)
	// The scaffold cannot issue a handle. First prove the reached protocol/store
	// gap independently of that unavailable result; later handle tests are separate.
	_, _ = client.finalizeMinimalCleanup(context.Background())
	f.waitConnection()
	finalized, retireCalls := store.observedFinalization(t)
	f.mu.Lock()
	operations := slices.Clone(f.operations)
	f.mu.Unlock()
	if !slices.Equal(operations, []uint16{l8RuntimeOwnerOpcodeStopReap, l8RuntimeOwnerOpcodeFinalize}) {
		t.Errorf("selected finalization sent Commit before the persistence handoff: operations=%v", operations)
	}
	if retireCalls != 0 {
		t.Errorf("selected finalization retired the original record before handoff: calls=%d", retireCalls)
	}
	current, err := f.owned.store.Load(context.Background())
	if err != nil {
		t.Fatalf("actual finalized record no longer exists before Commit admission: %v", err)
	}
	// Disconnect may only unclaim this controller. All finalization, process,
	// job, config, listener and absence fields must remain exactly pinned.
	if current.ControllerState != "unclaimed" || current.Revision != finalized.Revision+1 || current.ReconnectSecret == finalized.ReconnectSecret {
		t.Fatal("selected finalization did not end its one-use controller session")
	}
	current.Revision, current.ControllerState, current.ReconnectSecret = finalized.Revision, finalized.ControllerState, finalized.ReconnectSecret
	if current != finalized {
		t.Fatal("finalized record changed beyond controller disconnect fields")
	}
}

func TestMinimalJailerFinalizationLegacyStopAndCommitControl(t *testing.T) {
	f := newJailerRecoveryWireFixture(t)
	store := &minimalFinalizationObservedStore{l8RuntimeOwnerRecordStore: f.owned.store}
	f.owner.opts.Store = store
	client := f.fresh(t)
	if err := client.stopAndCommit(context.Background()); err != nil {
		t.Fatalf("legacy cleanup failed: %v", err)
	}
	f.waitConnection()
	_, retireCalls := store.observedFinalization(t)
	f.mu.Lock()
	operations := slices.Clone(f.operations)
	f.mu.Unlock()
	if !slices.Equal(operations, []uint16{l8RuntimeOwnerOpcodeStopReap, l8RuntimeOwnerOpcodeFinalize, l8RuntimeOwnerOpcodeCommit}) || retireCalls != 1 || !client.committed {
		t.Fatalf("legacy transcript/acknowledgment changed: operations=%v retireCalls=%d committed=%v", operations, retireCalls, client.committed)
	}
	if _, err := f.owned.store.Load(context.Background()); err == nil || !f.owned.store.selected.retired {
		t.Fatal("legacy Commit did not actually retire the original selected record")
	}
}
