package sandboxtarget

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

const branchReuseSandboxName = "hal-target-host"

func branchReuseWorkerHost(id string) *sandbox.SandboxHost {
	return &sandbox.SandboxHost{
		ID:                id,
		Name:              id,
		Kind:              sandbox.SandboxHostKindWorker,
		Health:            &sandbox.HostHealth{Status: "healthy"},
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
	}
}

func branchReuseSandbox(hostID string) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:     "sandbox-1",
		Name:   branchReuseSandboxName,
		Status: sandbox.StatusRunning,
		Host:   &sandbox.SandboxHost{ID: hostID, Name: hostID, Kind: sandbox.SandboxHostKindWorker},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID:      "runtime-1",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
}

func selectBranchReuse(t *testing.T, load func(string) (*sandbox.SandboxState, error)) (Result, []string) {
	t.Helper()
	var loaded []string
	result := Select(Request{
		HostID:        "worker-a",
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
		Project:       ProjectContext{Branch: "hal/target-host"},
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{branchReuseWorkerHost("worker-a"), branchReuseWorkerHost("worker-b")}, nil
		},
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			loaded = append(loaded, name)
			return load(name)
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not be called for a host-constrained request")
			return nil, nil
		},
	})
	return result, loaded
}

// Rerunning a host-constrained command on the same branch must reuse the
// sandbox the previous run created instead of planning a second create that
// collides with the existing runtime resource name.
func TestSelectRequestedHostReusesExistingBranchSandbox(t *testing.T) {
	result, loaded := selectBranchReuse(t, func(string) (*sandbox.SandboxState, error) {
		return branchReuseSandbox("worker-a"), nil
	})

	if len(loaded) != 1 || loaded[0] != branchReuseSandboxName {
		t.Fatalf("LoadSandbox names = %q, want the branch-derived name %q", loaded, branchReuseSandboxName)
	}
	if result.Failed() {
		t.Fatalf("result failed: %#v", result.Failure)
	}
	if result.NeedsProvisioning() {
		t.Fatalf("provisioning = %#v, want reuse of the existing branch sandbox", result.Provisioning)
	}
	if result.Sandbox == nil || result.Sandbox.Name != branchReuseSandboxName {
		t.Fatalf("sandbox = %#v, want existing %q", result.Sandbox, branchReuseSandboxName)
	}
	if result.Host == nil || result.Host.ID != "worker-a" {
		t.Fatalf("host = %#v, want requested host worker-a", result.Host)
	}
	if result.Runtime == nil || result.Runtime.RuntimeID != "runtime-1" {
		t.Fatalf("runtime = %#v, want the existing sandbox runtime identity preserved", result.Runtime)
	}
}

func TestSelectRequestedHostRejectsBranchSandboxOnAnotherHost(t *testing.T) {
	result, _ := selectBranchReuse(t, func(string) (*sandbox.SandboxState, error) {
		return branchReuseSandbox("worker-b"), nil
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want a host mismatch instead of a colliding create", result)
	}
	if result.Failure.Reason != FailureReasonHostMismatch {
		t.Fatalf("failure reason = %q, want %q", result.Failure.Reason, FailureReasonHostMismatch)
	}
	if result.NeedsProvisioning() {
		t.Fatal("a mismatched existing branch sandbox must not plan provisioning")
	}
}

func TestSelectRequestedHostProvisionsMissingBranchSandbox(t *testing.T) {
	result, loaded := selectBranchReuse(t, func(name string) (*sandbox.SandboxState, error) {
		return nil, fmt.Errorf("load sandbox %q: %w", name, fs.ErrNotExist)
	})

	if len(loaded) != 1 {
		t.Fatalf("LoadSandbox calls = %d, want one branch lookup", len(loaded))
	}
	if result.Failed() || !result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want branch provisioning when no sandbox exists", result)
	}
	if result.Provisioning.SandboxName != branchReuseSandboxName || result.Source.Kind != SourceFallbackProvisioning {
		t.Fatalf("provisioning/source = %#v/%#v, want branch provisioning", result.Provisioning, result.Source)
	}
}

func TestSelectRequestedHostFailsClosedOnBranchSandboxLoadError(t *testing.T) {
	result, _ := selectBranchReuse(t, func(string) (*sandbox.SandboxState, error) {
		return nil, errors.New("registry unreadable")
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want failure when the branch sandbox cannot be inspected", result)
	}
	if result.NeedsProvisioning() {
		t.Fatal("an unreadable branch sandbox record must not plan provisioning")
	}
}
