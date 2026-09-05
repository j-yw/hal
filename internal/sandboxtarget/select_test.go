package sandboxtarget

import (
	"errors"
	"io/fs"
	"reflect"
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

func TestSelectExplicitSandboxDerivesHostReadinessDiagnosticsFromReadiness(t *testing.T) {
	readiness := &sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{
			{
				State: sandbox.SandboxSecurityCapabilityReadinessUnsupported,
				Requested: &sandbox.SandboxSecurityCapabilityMetadata{
					Family:     sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
					Capability: sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
					Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
				},
				ReasonCode: sandbox.SandboxSecurityCapabilityReasonCapabilityMissing,
			},
		},
	}
	staleDiagnostics := &sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary{
		Status:               sandbox.SandboxSecurityCapabilityDiagnosticSummaryStatusReady,
		AdvisoryOnly:         false,
		WouldBlockStrictGate: false,
	}
	result := selectExplicitSandboxWithHostSecurity(t, &sandbox.SandboxSecurity{
		CapabilityReadiness:            readiness,
		CapabilityReadinessDiagnostics: staleDiagnostics,
	})

	got := result.Sandbox.Host.Security.CapabilityReadinessDiagnostics
	if got == nil {
		t.Fatal("capability readiness diagnostics = nil, want derived diagnostics")
	}
	want := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*readiness)
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("capability readiness diagnostics = %#v, want derived %#v", *got, want)
	}
	if got == staleDiagnostics || got.Status == staleDiagnostics.Status || !got.AdvisoryOnly || !got.WouldBlockStrictGate {
		t.Fatalf("capability readiness diagnostics preserved stale metadata: %#v", got)
	}
}

func TestSelectExplicitSandboxDropsStandaloneReadinessDiagnosticsWithoutReadiness(t *testing.T) {
	result := selectExplicitSandboxWithHostSecurity(t, &sandbox.SandboxSecurity{
		CapabilityReadinessDiagnostics: &sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary{
			Status:       sandbox.SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked,
			AdvisoryOnly: true,
		},
	})

	if result.Sandbox.Host.Security.CapabilityReadinessDiagnostics != nil {
		t.Fatalf("capability readiness diagnostics = %#v, want omitted without readiness", result.Sandbox.Host.Security.CapabilityReadinessDiagnostics)
	}
}

func TestSelectExplicitSandboxPropagatesSelectedHostAndRuntimeMetadata(t *testing.T) {
	cachedHost := &sandbox.SandboxHost{
		ID:                "worker-a",
		Name:              "worker a",
		Kind:              sandbox.SandboxHostKindWorker,
		Labels:            map[string]string{"pool": "ci"},
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
		Health:            &sandbox.HostHealth{Status: "healthy"},
		Security: &sandbox.SandboxSecurity{
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeEnv},
				ActiveModes:    []string{sandbox.SandboxSecretModeEnv},
			},
		},
	}
	selectedSandbox := &sandbox.SandboxState{
		Name:     "podman-dev",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:   "worker-a",
			Name: "worker a",
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:    sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID: "ctr-1",
			Image:     "localhost/hal:test",
			WorkerID:  "worker-a",
		},
	}

	result := Select(Request{
		SandboxName:   "podman-dev",
		HostID:        "worker-a",
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{cachedHost}, nil
		},
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "podman-dev" {
				t.Fatalf("loaded sandbox name = %q, want podman-dev", name)
			}
			return selectedSandbox, nil
		},
	})

	if result.Failed() || result.Sandbox != selectedSandbox {
		t.Fatalf("result = %#v, want selected explicit sandbox", result)
	}
	if result.Host == nil || result.Host == cachedHost || result.Sandbox.Host == nil || result.Sandbox.Host == cachedHost {
		t.Fatalf("host result/state = %#v/%#v, want copied selected host metadata", result.Host, result.Sandbox.Host)
	}
	if result.Sandbox.Host.ID != "worker-a" || result.Sandbox.Host.Labels["pool"] != "ci" || result.Sandbox.Host.SupportedRuntimes[0] != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("sandbox host metadata = %#v, want selected cached host metadata", result.Sandbox.Host)
	}
	if result.Sandbox.Host.Security == nil || result.Sandbox.Host.Security.Secrets == nil || len(result.Sandbox.Host.Security.Secrets.ActiveModes) != 1 {
		t.Fatalf("sandbox host security metadata = %#v, want copied nested metadata", result.Sandbox.Host.Security)
	}

	cachedHost.Labels["pool"] = "mutated"
	cachedHost.SupportedRuntimes[0] = sandbox.SandboxRuntimeDriverSSHMachine
	cachedHost.Health.Status = "unhealthy"
	cachedHost.Security.Secrets.ActiveModes[0] = sandbox.SandboxSecretModeHTTPProxy
	if result.Sandbox.Host.Labels["pool"] != "ci" ||
		result.Sandbox.Host.SupportedRuntimes[0] != sandbox.SandboxRuntimeDriverRootlessPodman ||
		result.Sandbox.Host.Health.Status != "healthy" ||
		result.Sandbox.Host.Security.Secrets.ActiveModes[0] != sandbox.SandboxSecretModeEnv {
		t.Fatalf("sandbox host metadata = %#v, want independent copy of cached host", result.Sandbox.Host)
	}

	if result.Runtime == nil || result.Sandbox.Runtime == nil {
		t.Fatalf("runtime result/state = %#v/%#v, want selected runtime metadata", result.Runtime, result.Sandbox.Runtime)
	}
	if result.Runtime.Driver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		result.Runtime.RuntimeID != "ctr-1" ||
		result.Runtime.Image != "localhost/hal:test" ||
		result.Runtime.WorkerID != "worker-a" ||
		result.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("runtime result = %#v, want merged selected and durable runtime metadata", result.Runtime)
	}
	if result.Sandbox.Runtime.Driver != result.Runtime.Driver ||
		result.Sandbox.Runtime.RuntimeID != result.Runtime.RuntimeID ||
		result.Sandbox.Runtime.Image != result.Runtime.Image ||
		result.Sandbox.Runtime.WorkerID != result.Runtime.WorkerID ||
		result.Sandbox.Runtime.IsolationLevel != result.Runtime.IsolationLevel {
		t.Fatalf("sandbox runtime = %#v, want result runtime %#v", result.Sandbox.Runtime, result.Runtime)
	}
}

func selectExplicitSandboxWithHostSecurity(t *testing.T, security *sandbox.SandboxSecurity) Result {
	t.Helper()
	cachedHost := &sandbox.SandboxHost{
		ID:                "worker-a",
		Name:              "worker a",
		Kind:              sandbox.SandboxHostKindWorker,
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
		Security:          security,
	}
	selectedSandbox := &sandbox.SandboxState{
		Name:     "podman-dev",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:   "worker-a",
			Name: "worker a",
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:    sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID: "ctr-1",
			WorkerID:  "worker-a",
		},
	}
	result := Select(Request{
		SandboxName:   "podman-dev",
		HostID:        "worker-a",
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{cachedHost}, nil
		},
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "podman-dev" {
				t.Fatalf("loaded sandbox name = %q, want podman-dev", name)
			}
			return selectedSandbox, nil
		},
	})
	if result.Failed() || result.Sandbox == nil || result.Sandbox.Host == nil || result.Sandbox.Host.Security == nil {
		t.Fatalf("result = %#v, want selected sandbox with host security", result)
	}
	return result
}

func TestSelectExplicitSandboxRejectsRequestedHostMismatch(t *testing.T) {
	result := Select(Request{
		SandboxName: "podman-dev",
		HostID:      "worker-b",
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{{
				ID:     "worker-b",
				Name:   "worker b",
				Kind:   sandbox.SandboxHostKindWorker,
				Health: &sandbox.HostHealth{Status: "healthy"},
			}}, nil
		},
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "podman-dev" {
				t.Fatalf("loaded sandbox name = %q, want podman-dev", name)
			}
			return &sandbox.SandboxState{
				Name: "podman-dev",
				Host: &sandbox.SandboxHost{
					ID:   "worker-a",
					Name: "worker a",
				},
			}, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want host mismatch failure", result)
	}
	if result.Failure.Reason != FailureReasonHostMismatch ||
		result.Failure.SandboxName != "podman-dev" ||
		result.Failure.HostID != "worker-b" ||
		result.Failure.Error() != `sandbox "podman-dev" is on host "worker-a", not requested host "worker-b"` {
		t.Fatalf("failure = %#v, want explicit host mismatch", result.Failure)
	}
}

func TestSelectExplicitSandboxRejectsMissingHostMetadataForRequestedHost(t *testing.T) {
	result := Select(Request{
		SandboxName: "legacy",
		HostID:      "worker-b",
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{{
				ID:     "worker-b",
				Name:   "worker b",
				Kind:   sandbox.SandboxHostKindWorker,
				Health: &sandbox.HostHealth{Status: "healthy"},
			}}, nil
		},
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "legacy" {
				t.Fatalf("loaded sandbox name = %q, want legacy", name)
			}
			return &sandbox.SandboxState{Name: "legacy"}, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want missing host metadata failure", result)
	}
	if result.Failure.Reason != FailureReasonHostMismatch ||
		result.Failure.Error() != `sandbox "legacy" has no durable host metadata for requested host "worker-b"` {
		t.Fatalf("failure = %#v, want missing host metadata mismatch", result.Failure)
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

func TestSelectRequestedRuntimeScansDurableHosts(t *testing.T) {
	result := Select(Request{
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
		Project: ProjectContext{
			Branch:     "hal/runtime-target",
			Repository: "github.com/jywlabs/hal",
		},
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "ssh-1",
					Name:              "aaa-ssh",
					Kind:              sandbox.SandboxHostKindSSH,
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
				},
				{
					ID:   "worker-empty",
					Name: "bbb-missing-runtime",
					Kind: sandbox.SandboxHostKindWorker,
				},
				{
					ID:                "worker-a",
					Name:              "ccc-rootless",
					Kind:              sandbox.SandboxHostKindWorker,
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
				},
			}, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not be called for a runtime-constrained provisioning selection")
			return nil, nil
		},
	})

	if result.Failed() || !result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want selected runtime with branch provisioning", result)
	}
	if result.Host == nil || result.Host.ID != "worker-a" {
		t.Fatalf("host = %#v, want durable host advertising requested runtime", result.Host)
	}
	if result.Runtime == nil || result.Runtime.Driver != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("runtime = %#v, want requested runtime metadata", result.Runtime)
	}
	if result.Provisioning.SandboxName != "hal-runtime-target" ||
		result.Source.Kind != SourceFallbackProvisioning ||
		result.Fallback.Reason != "requested runtime selected" {
		t.Fatalf("provisioning/source/fallback = %#v/%#v/%#v, want runtime-constrained provisioning", result.Provisioning, result.Source, result.Fallback)
	}
}

func TestSelectRequestedRuntimeNoEligibleHostFailsWithoutEndpointLeak(t *testing.T) {
	result := Select(Request{
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "ssh-1",
					Name:              "ssh one",
					Kind:              sandbox.SandboxHostKindSSH,
					Endpoint:          "ssh://deploy:secret@example.test?token=super-secret",
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
				},
				{
					ID:       "worker-empty",
					Name:     "worker empty",
					Kind:     sandbox.SandboxHostKindWorker,
					Endpoint: "unix:///tmp/private-worker.sock?token=super-secret",
				},
			}, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not be called when requested runtime has no eligible host")
			return nil, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want no eligible runtime host failure", result)
	}
	if result.Failure.Reason != FailureReasonRuntimeUnsupported ||
		result.Failure.RuntimeDriver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		result.Failure.Error() != `no durable host supports requested runtime "rootless_podman"` {
		t.Fatalf("failure = %#v, want deterministic requested-runtime failure", result.Failure)
	}
	for _, leaked := range []string{"ssh://", "secret@example.test", "/tmp/private-worker.sock", "super-secret"} {
		if strings.Contains(result.Failure.Error(), leaked) {
			t.Fatalf("failure %q leaked %q", result.Failure.Error(), leaked)
		}
	}
}

func TestSelectRequestedRuntimeChoosesDeterministicHostOrder(t *testing.T) {
	result := Select(Request{
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
		Project:       ProjectContext{Branch: "hal/runtime-ordering"},
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "worker-z",
					Name:              "zeta",
					Kind:              sandbox.SandboxHostKindWorker,
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
				},
				{
					ID:                "worker-b",
					Name:              "builder",
					Kind:              sandbox.SandboxHostKindWorker,
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
				},
				{
					ID:                "worker-a",
					Name:              "builder",
					Kind:              sandbox.SandboxHostKindWorker,
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
				},
			}, nil
		},
	})

	if result.Failed() || !result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want deterministic runtime-constrained provisioning", result)
	}
	if result.Host == nil || result.Host.ID != "worker-a" {
		t.Fatalf("host = %#v, want name-then-ID first matching host", result.Host)
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

func TestSelectRequestedIsolationExactMatches(t *testing.T) {
	tests := []struct {
		name      string
		isolation string
		runtime   string
		hostID    string
	}{
		{
			name:      "host",
			isolation: sandbox.SandboxIsolationLevelHost,
			runtime:   sandbox.SandboxRuntimeDriverSSHMachine,
			hostID:    "ssh-a",
		},
		{
			name:      "container",
			isolation: sandbox.SandboxIsolationLevelContainer,
			runtime:   sandbox.SandboxRuntimeDriverRootlessPodman,
			hostID:    "worker-a",
		},
		{
			name:      "vm",
			isolation: sandbox.SandboxIsolationLevelVM,
			runtime:   sandbox.SandboxRuntimeDriverMicroVM,
			hostID:    "vm-a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Select(Request{
				IsolationLevel: tt.isolation,
				Project:        ProjectContext{Branch: "hal/isolation-target"},
			}, CachedState{
				ListHosts: func() ([]*sandbox.SandboxHost, error) {
					return []*sandbox.SandboxHost{
						{
							ID:                tt.hostID,
							Name:              tt.hostID,
							Kind:              sandbox.SandboxHostKindWorker,
							SupportedRuntimes: []string{tt.runtime},
						},
					}, nil
				},
				ListSandboxes: func() ([]*sandbox.SandboxState, error) {
					t.Fatal("ListSandboxes should not be called for an isolation-constrained provisioning selection")
					return nil, nil
				},
			})

			if result.Failed() || !result.NeedsProvisioning() {
				t.Fatalf("result = %#v, want isolation-constrained provisioning", result)
			}
			if result.Host == nil || result.Host.ID != tt.hostID {
				t.Fatalf("host = %#v, want host supporting requested isolation", result.Host)
			}
			if result.Runtime == nil || result.Runtime.Driver != tt.runtime || result.Runtime.IsolationLevel != tt.isolation {
				t.Fatalf("runtime = %#v, want requested isolation runtime metadata", result.Runtime)
			}
			if result.Source.Kind != SourceFallbackProvisioning || result.Fallback.Reason != "requested isolation selected" {
				t.Fatalf("source/fallback = %#v/%#v, want isolation-constrained branch provisioning", result.Source, result.Fallback)
			}
		})
	}
}

func TestSelectRequestedIsolationUnavailableDoesNotUseWeakerRuntimeFallback(t *testing.T) {
	result := Select(Request{
		IsolationLevel: sandbox.SandboxIsolationLevelVM,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "ssh-a",
					Name:              "ssh a",
					Endpoint:          "ssh://deploy:secret@example.test",
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
				},
				{
					ID:                "worker-a",
					Name:              "worker a",
					Endpoint:          "unix:///tmp/private-worker.sock?token=super-secret",
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
				},
			}, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not be called when requested isolation has no eligible host")
			return nil, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want unavailable isolation failure", result)
	}
	if result.Failure.Reason != FailureReasonIsolationUnavailable ||
		result.Failure.IsolationLevel != sandbox.SandboxIsolationLevelVM ||
		result.Failure.Error() != `no durable host supports requested isolation "vm"` {
		t.Fatalf("failure = %#v, want deterministic unavailable-isolation failure", result.Failure)
	}
	for _, leaked := range []string{"ssh://", "secret@example.test", "/tmp/private-worker.sock", "super-secret"} {
		if strings.Contains(result.Failure.Error(), leaked) {
			t.Fatalf("failure %q leaked %q", result.Failure.Error(), leaked)
		}
	}
}

func TestSelectRequestedMicroVMRuntimeDoesNotUseWeakerRuntimeFallback(t *testing.T) {
	result := Select(Request{
		RuntimeDriver: sandbox.SandboxRuntimeDriverMicroVM,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "ssh-a",
					Name:              "ssh a",
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
				},
				{
					ID:                "worker-a",
					Name:              "worker a",
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
				},
			}, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not be called when requested runtime has no eligible host")
			return nil, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want unavailable microvm runtime failure", result)
	}
	if result.Failure.Reason != FailureReasonRuntimeUnsupported ||
		result.Failure.RuntimeDriver != sandbox.SandboxRuntimeDriverMicroVM ||
		result.Failure.Error() != `no durable host supports requested runtime "microvm"` {
		t.Fatalf("failure = %#v, want deterministic microvm runtime failure", result.Failure)
	}
}

func TestSelectExplicitSandboxRejectsRuntimeWithIncompatibleDurableIsolation(t *testing.T) {
	result := Select(Request{
		SandboxName:   "legacy",
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "worker-a",
					Name:              "worker a",
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
				},
			}, nil
		},
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "legacy" {
				t.Fatalf("loaded sandbox name = %q, want legacy", name)
			}
			return &sandbox.SandboxState{
				Name: "legacy",
				Runtime: &sandbox.SandboxRuntimeState{
					Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
					IsolationLevel: sandbox.SandboxIsolationLevelHost,
				},
			}, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want incompatible durable runtime failure", result)
	}
	if result.Failure.Reason != FailureReasonRuntimeUnsupported ||
		result.Failure.RuntimeDriver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		result.Failure.IsolationLevel != sandbox.SandboxIsolationLevelContainer ||
		result.Failure.Error() != `sandbox "legacy" runtime "rootless_podman" does not satisfy requested runtime category "container"` {
		t.Fatalf("failure = %#v, want deterministic runtime-category failure", result.Failure)
	}
}

func TestSelectExplicitSandboxRejectsRequestedVMIsolationOnWeakerRuntime(t *testing.T) {
	result := Select(Request{
		SandboxName:    "legacy",
		IsolationLevel: sandbox.SandboxIsolationLevelVM,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "vm-a",
					Name:              "vm a",
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverMicroVM},
				},
			}, nil
		},
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "legacy" {
				t.Fatalf("loaded sandbox name = %q, want legacy", name)
			}
			return &sandbox.SandboxState{
				Name:    "legacy",
				Runtime: &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
			}, nil
		},
	})

	if !result.Failed() {
		t.Fatalf("result = %#v, want requested VM isolation failure", result)
	}
	if result.Failure.Reason != FailureReasonIsolationUnavailable ||
		result.Failure.RuntimeDriver != sandbox.SandboxRuntimeDriverSSHMachine ||
		result.Failure.IsolationLevel != sandbox.SandboxIsolationLevelVM ||
		result.Failure.Error() != `sandbox "legacy" does not satisfy requested isolation "vm"` {
		t.Fatalf("failure = %#v, want deterministic VM isolation failure", result.Failure)
	}
}
