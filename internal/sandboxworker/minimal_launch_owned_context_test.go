package sandboxworker

import (
	"context"
	"testing"
)

func TestMinimalLaunchServiceOwnedContextRetainsPartialFailure(t *testing.T) {
	for _, mode := range []string{"partial provider error", "authority loss during Start"} {
		t.Run(mode, func(t *testing.T) {
			f := newMinimalLaunchCancelFixture(t, mode == "partial provider error")
			owned := f.entered.reservation.OwnedContext()
			if owned == nil || owned.Err() != nil {
				t.Fatal("claimed provider did not receive original owned lifetime")
			}
			if mode == "authority loss during Start" {
				f.base.authorizer.Close()
				waitMinimalLaunchOwnedContext(t, owned)
			}
			f.unblock()
			if response := f.waitStart(t); response.OK {
				t.Fatal("partial/lost owner manufactured successful execution")
			}
			waitMinimalLaunchOwnedContext(t, owned)
			if owned.Err() != context.Canceled || owned != f.entered.reservation.OwnedContext() {
				t.Fatal("partial failure did not revoke the original owned lifetime")
			}
			f.assertRetained(t, true)
			f.assertNoCleanup(t)
			f.lockManager(t)
			state := f.service.jobs.states[f.entered.identity.WorkerJobID]
			f.service.jobs.mu.Unlock()
			if state.MinimalLaunch.Phase != "dispatching" || state.MinimalLaunch.Revision != 2 || state.JobV2.CancelRequested || state.JobV2.StartedAt != nil || state.JobV2.FinishedAt != nil || state.JobV2.ExitCode != nil {
				t.Fatal("failed Start fabricated cancel or completion metadata")
			}
		})
	}
}
