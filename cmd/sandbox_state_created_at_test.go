package cmd

import (
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

// Worker sandboxes are first recorded by command persistence, not by
// `hal sandbox create`, so that save must stamp the creation time once.
func TestPersistSelectedWorkerSandboxStampsCreatedAtOnce(t *testing.T) {
	persist := func(target *sandbox.SandboxState) *sandbox.SandboxState {
		t.Helper()
		var saved *sandbox.SandboxState
		err := persistSandboxCommandSelectedState(sandboxCommandStatePersistenceRequest{
			SandboxHostID:  "host-1",
			SandboxRuntime: sandbox.SandboxRuntimeDriverRootlessPodman,
			Target:         target,
			Save: func(state *sandbox.SandboxState) error {
				saved = state
				return nil
			},
		})
		if err != nil {
			t.Fatalf("persistSandboxCommandSelectedState() error: %v", err)
		}
		if saved == nil {
			t.Fatal("worker sandbox state was not saved")
		}
		return saved
	}

	before := time.Now()
	fresh := workerRootlessCachedSandbox("worker-rootless")
	fresh.CreatedAt = time.Time{}
	saved := persist(fresh)
	after := time.Now()
	if saved.CreatedAt.IsZero() || saved.CreatedAt.Before(before) || saved.CreatedAt.After(after) {
		t.Fatalf("new worker sandbox CreatedAt = %v, want a stamp between %v and %v", saved.CreatedAt, before, after)
	}

	existing := workerRootlessCachedSandbox("worker-rootless")
	original := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	existing.CreatedAt = original
	if got := persist(existing).CreatedAt; !got.Equal(original) {
		t.Fatalf("reused worker sandbox CreatedAt = %v, want preserved %v", got, original)
	}
}
