package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// A reused sandbox's registry record keeps the lease reference of the run that
// last used it. That lease belongs to the earlier run and is already released;
// carrying it into a new execution made finalization try to release it again,
// fail with lease_release_failed, and leave the manifest stuck at "running".
func TestResolveSandboxCommandExecutionTargetDropsInheritedLeaseOnReuse(t *testing.T) {
	host := runSandboxSchedulerLeaseHost("worker-existing", "worker existing")
	for _, tc := range []struct {
		name        string
		sandboxName string
	}{
		{name: "explicit sandbox name", sandboxName: "main"},
		{name: "branch-derived reuse", sandboxName: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existing := &sandbox.SandboxState{
				Name:     "main",
				Provider: "local",
				Status:   sandbox.StatusRunning,
				Host:     cloneSandboxHost(host),
				Runtime: &sandbox.SandboxRuntimeState{
					Driver:    sandboxruntime.DriverRootlessPodman,
					RuntimeID: "existing-runtime",
					WorkerID:  host.ID,
				},
				Lease: &sandbox.SandboxLeaseRef{ID: "run-previous", RunID: "run-previous", HostID: host.ID},
			}
			target, err := resolveSandboxCommandExecutionTarget(
				context.Background(),
				sandboxCommandTargetRequest{
					Purpose:        sandbox.SandboxLeasePurposeRun,
					SandboxName:    tc.sandboxName,
					SandboxHostID:  host.ID,
					SandboxRuntime: sandboxruntime.DriverRootlessPodman,
					Branch:         "main",
					LoadContext:    "reused worker sandbox",
				},
				sandboxCommandTargetDeps{
					loadSandbox: func(string) (*sandbox.SandboxState, error) { return existing, nil },
					listHosts: func() ([]*sandbox.SandboxHost, error) {
						return []*sandbox.SandboxHost{host}, nil
					},
				},
				sandboxCommandScheduledTargetRequest{
					Purpose:        sandbox.SandboxLeasePurposeRun,
					SandboxName:    tc.sandboxName,
					SandboxHostID:  host.ID,
					SandboxRuntime: sandboxruntime.DriverRootlessPodman,
					Branch:         "main",
				},
				sandboxCommandScheduledTargetDeps{
					listLeases: func() ([]*sandbox.SandboxLease, error) {
						t.Fatal("scheduler must not run for a reused sandbox")
						return nil, nil
					},
					acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
						t.Fatal("lease acquisition must not run for a reused sandbox")
						return nil, nil
					},
				},
			)
			if err != nil {
				t.Fatalf("resolveSandboxCommandExecutionTarget() error: %v", err)
			}
			if target == nil || target.Name != "main" {
				t.Fatalf("resolved target = %#v, want reused sandbox main", target)
			}
			if target.Lease != nil {
				t.Fatalf("reused target lease = %#v, want no lease inherited from an earlier run", target.Lease)
			}
			if existing.Lease == nil {
				t.Fatal("dropping the inherited lease mutated the cached registry record")
			}
		})
	}
}
