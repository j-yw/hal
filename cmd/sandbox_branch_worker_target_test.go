package cmd

import (
	"context"
	"fmt"
	"io/fs"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

type branchWorkerTargetCalls struct {
	loads    []string
	schedule int
}

func resolveBranchWorkerTarget(t *testing.T, host *sandbox.SandboxHost, load func(string) (*sandbox.SandboxState, error)) (*sandbox.SandboxState, error, *branchWorkerTargetCalls) {
	t.Helper()
	calls := &branchWorkerTargetCalls{}
	target, err := resolveSandboxCommandExecutionTarget(
		context.Background(),
		sandboxCommandTargetRequest{
			Purpose:        sandbox.SandboxLeasePurposeRun,
			SandboxHostID:  host.ID,
			SandboxRuntime: sandboxruntime.DriverRootlessPodman,
			Branch:         "main",
			LoadContext:    "branch worker sandbox",
		},
		sandboxCommandTargetDeps{
			loadSandbox: func(name string) (*sandbox.SandboxState, error) {
				calls.loads = append(calls.loads, name)
				return load(name)
			},
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				return []*sandbox.SandboxHost{host}, nil
			},
			provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
				t.Fatal("legacy provisioning must not run for a worker target")
				return nil, nil
			},
		},
		sandboxCommandScheduledTargetRequest{
			Purpose:        sandbox.SandboxLeasePurposeRun,
			SandboxHostID:  host.ID,
			SandboxRuntime: sandboxruntime.DriverRootlessPodman,
			Branch:         "main",
		},
		sandboxCommandScheduledTargetDeps{
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				return []*sandbox.SandboxHost{host}, nil
			},
			listLeases: func() ([]*sandbox.SandboxLease, error) {
				calls.schedule++
				return nil, nil
			},
			acquireLease: func(req sandbox.SandboxLeaseAcquireRequest, _ time.Duration) (*sandbox.SandboxLease, error) {
				return &sandbox.SandboxLease{ID: "lease-1", Status: sandbox.SandboxLeaseStatusActive}, nil
			},
			now: func() time.Time { return time.Date(2026, 10, 1, 14, 0, 0, 0, time.UTC) },
		},
	)
	return target, err, calls
}

func branchWorkerSandbox(host *sandbox.SandboxHost) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		Name:     "main",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host:     cloneSandboxHost(host),
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:    sandboxruntime.DriverRootlessPodman,
			RuntimeID: "existing-runtime",
			WorkerID:  host.ID,
		},
	}
}

// Rerunning `hal run --sandbox --sandbox-host H --sandbox-runtime rootless_podman`
// on the same branch must reuse the sandbox the previous run created, exactly as
// if --sandbox-name named it, instead of scheduling a second create that
// collides with the existing container name.
func TestResolveSandboxCommandExecutionTargetReusesExistingBranchWorkerWithoutName(t *testing.T) {
	host := runSandboxSchedulerLeaseHost("worker-existing", "worker existing")
	target, err, calls := resolveBranchWorkerTarget(t, host, func(string) (*sandbox.SandboxState, error) {
		return branchWorkerSandbox(host), nil
	})
	if err != nil {
		t.Fatalf("resolveSandboxCommandExecutionTarget() error: %v", err)
	}
	if calls.schedule != 0 {
		t.Fatalf("scheduler calls = %d, want 0 when the branch sandbox already exists", calls.schedule)
	}
	if len(calls.loads) == 0 || calls.loads[0] != "main" {
		t.Fatalf("registry loads = %q, want the branch-derived name first", calls.loads)
	}
	if target == nil || target.Name != "main" || target.Runtime == nil || target.Runtime.RuntimeID != "existing-runtime" {
		t.Fatalf("resolved target = %#v, want the existing branch sandbox", target)
	}
}

func TestResolveSandboxCommandExecutionTargetSchedulesMissingBranchWorker(t *testing.T) {
	host := runSandboxSchedulerLeaseHost("worker-existing", "worker existing")
	target, err, calls := resolveBranchWorkerTarget(t, host, func(name string) (*sandbox.SandboxState, error) {
		return nil, fmt.Errorf("load sandbox %q: %w", name, fs.ErrNotExist)
	})
	if err != nil {
		t.Fatalf("resolveSandboxCommandExecutionTarget() error: %v", err)
	}
	if calls.schedule == 0 {
		t.Fatal("scheduler was not used for a branch without an existing sandbox")
	}
	if target == nil || target.Name != "main" {
		t.Fatalf("scheduled target = %#v, want a new branch-named sandbox", target)
	}
}

func TestResolveSandboxCommandExecutionTargetRejectsBranchWorkerOnAnotherHost(t *testing.T) {
	host := runSandboxSchedulerLeaseHost("worker-existing", "worker existing")
	other := runSandboxSchedulerLeaseHost("worker-other", "worker other")
	_, err, calls := resolveBranchWorkerTarget(t, host, func(string) (*sandbox.SandboxState, error) {
		return branchWorkerSandbox(other), nil
	})
	if err == nil {
		t.Fatal("resolveSandboxCommandExecutionTarget() error = nil, want a host mismatch for the existing branch sandbox")
	}
	if calls.schedule != 0 {
		t.Fatalf("scheduler calls = %d, want 0: a mismatched branch sandbox must not be replaced", calls.schedule)
	}
}
