package sandboxtarget

import (
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestRequestZeroValueKeepsLegacyFallbackAndNoExplicitConstraints(t *testing.T) {
	var req Request

	if req.Purpose != "" || req.SandboxName != "" || req.HostID != "" || req.RuntimeDriver != "" || req.IsolationLevel != "" {
		t.Fatalf("zero-value request has unexpected explicit fields: %#v", req)
	}
	if req.HasExplicitSandboxName() {
		t.Fatal("zero-value request unexpectedly has explicit sandbox name")
	}
	if req.HasHostConstraint() {
		t.Fatal("zero-value request unexpectedly has host constraint")
	}
	if req.HasRuntimeConstraint() {
		t.Fatal("zero-value request unexpectedly has runtime constraint")
	}
	if req.HasIsolationConstraint() {
		t.Fatal("zero-value request unexpectedly has isolation constraint")
	}

	policy := req.EffectiveFallbackPolicy()
	if !policy.AllowDefaultRunningSandbox || !policy.AllowBranchProvisioning || policy.Disabled {
		t.Fatalf("zero-value fallback policy = %#v, want legacy-compatible default fallbacks", policy)
	}
}

func TestRequestCarriesTargetSelectionIntent(t *testing.T) {
	req := Request{
		Purpose:        PurposeFactory,
		SandboxName:    "factory-dev",
		HostID:         "host-1",
		RuntimeDriver:  sandbox.SandboxRuntimeDriverRootlessPodman,
		IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		Project: ProjectContext{
			Dir:        "/repo",
			Repository: "github.com/jywlabs/hal",
			Branch:     "hal/target-selection",
		},
		Fallback: FallbackPolicy{Disabled: true},
	}

	if !req.HasExplicitSandboxName() || !req.HasHostConstraint() || !req.HasRuntimeConstraint() || !req.HasIsolationConstraint() {
		t.Fatalf("request helper methods did not recognize explicit target intent: %#v", req)
	}
	if req.Purpose != PurposeFactory {
		t.Fatalf("Purpose = %q, want %q", req.Purpose, PurposeFactory)
	}
	if req.Project.Dir != "/repo" || req.Project.Repository != "github.com/jywlabs/hal" || req.Project.Branch != "hal/target-selection" {
		t.Fatalf("Project = %#v, want full project context", req.Project)
	}
	if policy := req.EffectiveFallbackPolicy(); !policy.Disabled || policy.AllowDefaultRunningSandbox || policy.AllowBranchProvisioning {
		t.Fatalf("disabled fallback policy = %#v, want disabled with no fallbacks", policy)
	}
}

func TestResultZeroValueHasNoSelectionFailureOrFallback(t *testing.T) {
	var result Result

	if result.Selected() {
		t.Fatalf("zero-value result unexpectedly selected target metadata: %#v", result)
	}
	if result.Failed() {
		t.Fatalf("zero-value result unexpectedly failed: %#v", result)
	}
	if result.Source.Kind != SourceUnknown {
		t.Fatalf("zero-value source kind = %q, want unknown", result.Source.Kind)
	}
	if result.Fallback.Used {
		t.Fatalf("zero-value fallback metadata = %#v, want unused fallback", result.Fallback)
	}
}

func TestResultCarriesSelectedSandboxHostRuntimeAndMetadata(t *testing.T) {
	runtime := sandboxruntime.RuntimeState{
		Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
		RuntimeID:      "ctr-1",
		IsolationLevel: sandbox.SandboxIsolationLevelContainer,
	}
	result := Result{
		Sandbox: &sandbox.SandboxState{
			ID:     "sandbox-1",
			Name:   "dev",
			Status: sandbox.StatusRunning,
		},
		Host: &sandbox.SandboxHost{
			ID:                "host-1",
			Name:              "local",
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
		},
		Runtime: &runtime,
		Source: SourceMetadata{
			Kind:   SourceRequestedRuntime,
			Detail: "durable host runtime metadata",
		},
		Fallback: FallbackMetadata{
			Policy: DefaultFallbackPolicy(),
			Used:   true,
			Source: SourceDefaultRunningSandbox,
			Reason: "no explicit sandbox name",
		},
	}

	if !result.Selected() {
		t.Fatal("result did not report selected metadata")
	}
	if result.Failed() {
		t.Fatalf("result unexpectedly failed: %#v", result.Failure)
	}
	if result.Sandbox.Name != "dev" || result.Host.ID != "host-1" || result.Runtime.Driver != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("result selected metadata = %#v, want sandbox, host, and runtime", result)
	}
	if result.Source.Kind != SourceRequestedRuntime || !result.Fallback.Used || result.Fallback.Source != SourceDefaultRunningSandbox {
		t.Fatalf("result source/fallback metadata = %#v/%#v, want requested runtime with fallback metadata", result.Source, result.Fallback)
	}
}

func TestFailureCarriesDeterministicReasonAndSafeRequestContext(t *testing.T) {
	failure := Failure{
		Reason:         FailureReasonRuntimeUnsupported,
		HostID:         "host-1",
		RuntimeDriver:  sandbox.SandboxRuntimeDriverMicroVM,
		IsolationLevel: sandbox.SandboxIsolationLevelVM,
	}

	if failure.Error() != "sandbox target selection failed: runtime_unsupported" {
		t.Fatalf("Error() = %q, want deterministic reason", failure.Error())
	}
	if failure.HostID != "host-1" || failure.RuntimeDriver != sandbox.SandboxRuntimeDriverMicroVM || failure.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("failure context = %#v, want requested host/runtime/isolation only", failure)
	}

	failure.Message = "host host-1 does not support requested runtime microvm"
	if failure.Error() != failure.Message {
		t.Fatalf("Error() = %q, want explicit message %q", failure.Error(), failure.Message)
	}
}
