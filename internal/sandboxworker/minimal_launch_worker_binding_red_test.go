package sandboxworker

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// This independent passing prerequisite uses the actual service, original
// principal/selection/reservation/Claim, and retained worker store. It is not
// early registration, a workload result, or a cleanup proof.
func TestMinimalWorkerBindingOriginalStoreControl(t *testing.T) {
	f := newMinimalLaunchOwnedContextFixture(t, time.Minute)
	f.start(t, context.Background())
	f.assertRetained(t, false)
	manager, reservation := f.service.jobs, f.provider.reservation
	identity := reservation.Identity()
	manager.mu.Lock()
	entry := manager.minimalLive[identity.WorkerJobID]
	if entry == nil || entry.reservation != reservation || entry.owner == nil || manager.stateLock == nil || manager.store.checkMinimalAuthority(manager.stateLock) != nil {
		manager.mu.Unlock()
		t.Fatal("actual original reservation/store/lock authority unavailable")
	}
	stored, readErr := manager.store.readMinimalLaunchFile(identity.WorkerJobID + ".json")
	want, wantErr := encodeStoredJobStateV2(manager.states[identity.WorkerJobID])
	got, gotErr := encodeStoredJobStateV2(stored)
	manager.mu.Unlock()
	if readErr != nil || wantErr != nil || gotErr != nil || !bytes.Equal(want, got) || stored.MinimalLaunch == nil || stored.MinimalLaunch.Phase != "dispatching" || stored.MinimalLaunch.Revision != 2 || stored.RequestKey != identity.RequestKey {
		t.Fatal("original lock-protected dispatch readback did not match")
	}
	if _, err := reservation.ClaimLaunch(reservation.Context()); err == nil || f.provider.starts != 1 {
		t.Fatal("original worker Claim was not consumed exactly once")
	}
	other, err := NewL8DurableService(f.base.options())
	if other != nil {
		other.Close()
	}
	if err == nil || other != nil {
		t.Fatal("second service acquired the original held state lock")
	}
}
