package sandboxtarget

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestSelectExplicitSandboxLoadsSuppliedName(t *testing.T) {
	target := &sandbox.SandboxState{Name: "chosen", Status: sandbox.StatusStopped}
	var loadedName string

	result := Select(Request{SandboxName: " chosen "}, CachedState{
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			loadedName = name
			return target, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not be called for an explicit sandbox")
			return nil, nil
		},
	})

	if loadedName != "chosen" {
		t.Fatalf("loaded sandbox name = %q, want trimmed explicit name", loadedName)
	}
	if result.Failed() || result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want selected explicit sandbox without fallback provisioning", result)
	}
	if result.Sandbox != target || result.Source.Kind != SourceExplicitSandbox || result.Source.Detail != "chosen" {
		t.Fatalf("result = %#v, want explicit sandbox selection", result)
	}
	if result.Runtime == nil || result.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("runtime = %#v, want legacy SSH-machine default", result.Runtime)
	}
}

func TestSelectExplicitMissingSandboxKeepsExplicitProvisioningAvailable(t *testing.T) {
	result := Select(Request{
		SandboxName: "missing",
		Project:     ProjectContext{Branch: "hal/story", Repository: "github.com/jywlabs/hal"},
	}, CachedState{
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "missing" {
				t.Fatalf("loaded sandbox name = %q, want missing", name)
			}
			return nil, fs.ErrNotExist
		},
	})

	if result.Failed() || !result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want explicit provisioning fallback", result)
	}
	if result.Provisioning.SandboxName != "missing" || result.Provisioning.Branch != "hal/story" || result.Provisioning.Repository != "github.com/jywlabs/hal" {
		t.Fatalf("provisioning = %#v, want explicit sandbox provisioning plan", result.Provisioning)
	}
	if result.Source.Kind != SourceFallbackProvisioning || !result.Fallback.Used || result.Fallback.Reason != "explicit sandbox not found" {
		t.Fatalf("source/fallback = %#v/%#v, want explicit missing fallback metadata", result.Source, result.Fallback)
	}
}

func TestSelectDefaultUsesOnlyRunningSandbox(t *testing.T) {
	running := &sandbox.SandboxState{Name: "run-box", Status: sandbox.StatusRunning}
	stopped := &sandbox.SandboxState{Name: "stopped-box", Status: sandbox.StatusStopped}

	result := Select(Request{}, CachedState{
		LoadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("LoadSandbox should not be called when no explicit sandbox is requested")
			return nil, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			return []*sandbox.SandboxState{stopped, running}, nil
		},
	})

	if result.Failed() || result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want selected default running sandbox", result)
	}
	if result.Sandbox != running || result.Source.Kind != SourceDefaultRunningSandbox {
		t.Fatalf("result = %#v, want default running sandbox", result)
	}
	if !result.Fallback.Used || result.Fallback.Source != SourceDefaultRunningSandbox || result.Fallback.Reason != "no explicit sandbox name" {
		t.Fatalf("fallback = %#v, want default-running fallback metadata", result.Fallback)
	}
}

func TestSelectDefaultMultipleRunningSandboxesFailsDeterministically(t *testing.T) {
	result := Select(Request{}, CachedState{
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			return []*sandbox.SandboxState{
				{Name: "zulu", Status: sandbox.StatusRunning},
				{Name: "alpha", Status: sandbox.StatusRunning},
			}, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want ambiguous target failure", result)
	}
	if result.Failure.Reason != FailureReasonAmbiguousTarget || result.Failure.Error() != "multiple sandboxes found: alpha, zulu" {
		t.Fatalf("failure = %#v, want deterministic multiple-running error", result.Failure)
	}
}

func TestSelectNoRunningSandboxPlansBranchProvisioning(t *testing.T) {
	result := Select(Request{
		Project: ProjectContext{
			Branch:     "feature/Auth API",
			Repository: "github.com/jywlabs/hal",
		},
	}, CachedState{
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			return []*sandbox.SandboxState{{Name: "stopped", Status: sandbox.StatusStopped}}, nil
		},
	})

	if result.Failed() || !result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want branch provisioning plan", result)
	}
	if result.Provisioning.SandboxName != "feature-auth-api" || result.Provisioning.Branch != "feature/Auth API" {
		t.Fatalf("provisioning = %#v, want branch-derived sandbox name and branch context", result.Provisioning)
	}
	if result.Source.Kind != SourceFallbackProvisioning || result.Fallback.Source != SourceFallbackProvisioning || result.Fallback.Reason != "no running sandbox selected" {
		t.Fatalf("source/fallback = %#v/%#v, want branch provisioning fallback", result.Source, result.Fallback)
	}
}

func TestSelectWithoutTargetConstraintsDoesNotRequireDurableHostMetadata(t *testing.T) {
	target := &sandbox.SandboxState{
		Name:    "legacy",
		Status:  sandbox.StatusRunning,
		Host:    nil,
		Runtime: nil,
	}

	result := Select(Request{}, CachedState{
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			return []*sandbox.SandboxState{target}, nil
		},
	})

	if result.Failed() || result.Sandbox != target {
		t.Fatalf("result = %#v, want selected legacy sandbox without host metadata", result)
	}
	if result.Host != nil {
		t.Fatalf("host = %#v, want no durable host metadata requirement", result.Host)
	}
	if result.Runtime == nil || result.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("runtime = %#v, want SSH-machine compatibility default", result.Runtime)
	}
}

func TestRuntimeForSandboxDefaultsMissingMetadataToSSHMachine(t *testing.T) {
	for _, target := range []*sandbox.SandboxState{
		nil,
		{},
		{Runtime: &sandbox.SandboxRuntimeState{}},
		{Runtime: &sandbox.SandboxRuntimeState{Driver: "   "}},
	} {
		runtime := RuntimeForSandbox(target)
		if runtime.Driver != sandboxruntime.DriverSSHMachine {
			t.Fatalf("RuntimeForSandbox(%#v).Driver = %q, want %q", target, runtime.Driver, sandboxruntime.DriverSSHMachine)
		}
	}
}

func TestRuntimeForSandboxPreservesDurableRuntimeMetadata(t *testing.T) {
	runtime := RuntimeForSandbox(&sandbox.SandboxState{
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID:      "ctr-1",
			Image:          "localhost/hal:test",
			WorkerID:       "worker-1",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	})

	if runtime.Driver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		runtime.RuntimeID != "ctr-1" ||
		runtime.Image != "localhost/hal:test" ||
		runtime.WorkerID != "worker-1" ||
		runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("runtime = %#v, want durable metadata preserved", runtime)
	}
}

func TestSelectPropagatesCachedStateErrorsAsSafeFailures(t *testing.T) {
	loadErr := errors.New("permission denied")
	result := Select(Request{SandboxName: "chosen"}, CachedState{
		LoadSandbox: func(string) (*sandbox.SandboxState, error) {
			return nil, loadErr
		},
	})

	if !result.Failed() || result.Failure.Reason != FailureReasonInvalidRequest {
		t.Fatalf("result = %#v, want deterministic load failure", result)
	}
	if result.Failure.SandboxName != "chosen" {
		t.Fatalf("failure sandbox name = %q, want requested name", result.Failure.SandboxName)
	}
}

func TestSelectRequestedHostMissingFailsDeterministically(t *testing.T) {
	result := Select(Request{HostID: "worker-a"}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{ID: "worker-b", Name: "worker b", Kind: sandbox.SandboxHostKindWorker},
			}, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not be called when requested host is missing")
			return nil, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want missing host failure", result)
	}
	if result.Failure.Reason != FailureReasonHostNotFound ||
		result.Failure.HostID != "worker-a" ||
		result.Failure.Error() != `host "worker-a" does not exist` {
		t.Fatalf("failure = %#v, want deterministic requested-host missing failure", result.Failure)
	}
}

func TestSelectRequestedHostDuplicateMatchesFail(t *testing.T) {
	result := Select(Request{HostID: "worker-a"}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{ID: "worker-a", Name: "alpha", Kind: sandbox.SandboxHostKindWorker},
				{ID: "worker-a", Name: "duplicate", Kind: sandbox.SandboxHostKindWorker},
			}, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want duplicate requested-host failure", result)
	}
	if result.Failure.Reason != FailureReasonAmbiguousTarget ||
		result.Failure.HostID != "worker-a" ||
		result.Failure.Error() != `host "worker-a" matched multiple durable host records` {
		t.Fatalf("failure = %#v, want deterministic duplicate host failure", result.Failure)
	}
}

func TestSelectRequestedHostUnhealthyFailsWithoutEndpointLeak(t *testing.T) {
	result := Select(Request{HostID: "worker-a"}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:       "worker-a",
					Name:     "worker a",
					Kind:     sandbox.SandboxHostKindWorker,
					Endpoint: "unix:///tmp/secret-worker.sock?token=super-secret",
					Health: &sandbox.HostHealth{
						Status:  "unhealthy",
						Message: "token=super-secret",
					},
				},
			}, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want unhealthy requested-host failure", result)
	}
	if result.Failure.Reason != FailureReasonHostUnhealthy ||
		result.Failure.HostID != "worker-a" ||
		result.Failure.Error() != `host "worker-a" is not healthy: unhealthy` {
		t.Fatalf("failure = %#v, want deterministic unhealthy host failure", result.Failure)
	}
	for _, leaked := range []string{"unix://", "/tmp/secret-worker.sock", "super-secret"} {
		if strings.Contains(result.Failure.Error(), leaked) {
			t.Fatalf("failure %q leaked %q", result.Failure.Error(), leaked)
		}
	}
}

func TestSelectRequestedHostUnsupportedRuntimeFailsWithoutEndpointLeak(t *testing.T) {
	result := Select(Request{
		HostID:        "worker-a",
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "worker-a",
					Name:              "worker a",
					Kind:              sandbox.SandboxHostKindWorker,
					Endpoint:          "ssh://user:secret@example.test",
					Health:            &sandbox.HostHealth{Status: "healthy"},
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
				},
			}, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want unsupported runtime failure", result)
	}
	if result.Failure.Reason != FailureReasonRuntimeUnsupported ||
		result.Failure.HostID != "worker-a" ||
		result.Failure.RuntimeDriver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		result.Failure.Error() != `host "worker-a" does not support requested runtime "rootless_podman"` {
		t.Fatalf("failure = %#v, want deterministic unsupported-runtime failure", result.Failure)
	}
	for _, leaked := range []string{"ssh://", "secret@example.test"} {
		if strings.Contains(result.Failure.Error(), leaked) {
			t.Fatalf("failure %q leaked %q", result.Failure.Error(), leaked)
		}
	}
}

func TestSelectRequestedHostMatchUsesCachedMetadataOnly(t *testing.T) {
	result := Select(Request{
		HostID:        "worker-a",
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
		Project: ProjectContext{
			Branch:     "hal/target-host",
			Repository: "github.com/jywlabs/hal",
		},
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "worker-a",
					Name:              "worker a",
					Kind:              sandbox.SandboxHostKindWorker,
					Endpoint:          "unix:///tmp/worker.sock",
					Health:            &sandbox.HostHealth{Status: "healthy"},
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
				},
			}, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not be called for a host-constrained provisioning selection")
			return nil, nil
		},
	})

	if result.Failed() || !result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want selected host with branch provisioning", result)
	}
	if result.Host == nil || result.Host.ID != "worker-a" {
		t.Fatalf("host = %#v, want selected cached requested host", result.Host)
	}
	if result.Runtime == nil || result.Runtime.Driver != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("runtime = %#v, want requested runtime metadata", result.Runtime)
	}
	if result.Provisioning.SandboxName != "hal-target-host" || result.Source.Kind != SourceFallbackProvisioning {
		t.Fatalf("provisioning/source = %#v/%#v, want branch provisioning after host selection", result.Provisioning, result.Source)
	}
}

func TestSelectRequestedHostDoesNotUseUnrelatedDefaultRunningSandbox(t *testing.T) {
	result := Select(Request{
		HostID: "worker-a",
		Project: ProjectContext{
			Branch: "hal/target-host",
		},
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:     "worker-a",
					Name:   "worker a",
					Kind:   sandbox.SandboxHostKindWorker,
					Health: &sandbox.HostHealth{Status: "healthy"},
				},
			}, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not be called for a host-constrained request without an explicit sandbox")
			return nil, nil
		},
	})

	if result.Failed() || !result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want host-constrained branch provisioning", result)
	}
	if result.Sandbox != nil {
		t.Fatalf("sandbox = %#v, want no default-running sandbox for host-constrained request", result.Sandbox)
	}
	if result.Host == nil || result.Host.ID != "worker-a" {
		t.Fatalf("host = %#v, want selected requested host", result.Host)
	}
}
