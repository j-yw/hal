package sandboxexec

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestRunDoesNotRejectWorkerTargetWithStrictBlockingSecurityReadiness(t *testing.T) {
	readiness, diagnostics := sandboxexecStrictBlockingReadinessFixture(t)
	target := &sandbox.SandboxState{
		Name:     "podman-dev",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:   "worker-blocked",
			Name: "worker blocked",
			Kind: sandbox.SandboxHostKindWorker,
			Security: &sandbox.SandboxSecurity{
				CapabilityReadiness:            &readiness,
				CapabilityReadinessDiagnostics: &diagnostics,
			},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID:      "ctr-blocked",
			WorkerID:       "worker-blocked",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
	var readySecurity *sandbox.SandboxSecurity
	var runCalled bool
	var gotRunTarget sandboxruntime.Target

	result, err := Run(context.Background(), CommandRequest{
		SandboxName: "podman-dev",
		Command:     []string{"hal", "status"},
	}, Dependencies{
		ResolveTarget: func(context.Context, TargetRequest) (*sandbox.SandboxState, error) {
			return target, nil
		},
		OnTargetReady: func(_ context.Context, ready *sandbox.SandboxState) error {
			readySecurity = ready.Security
			return nil
		},
		ResolveDriver: func(_ context.Context, runtimeTarget sandboxruntime.Target) (sandboxruntime.Driver, error) {
			if runtimeTarget.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("resolved runtime driver = %q, want rootless_podman", runtimeTarget.Runtime.Driver)
			}
			return fakeRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}, nil
		},
		RunCommand: func(_ context.Context, run RunContext, _ CommandRequest) error {
			runCalled = true
			gotRunTarget = run.Target
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if !runCalled {
		t.Fatal("RunCommand was not called; readiness gate diagnostics must not reject sandboxexec targets")
	}
	if result == nil || result.Target.Name != "podman-dev" || result.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("result target = %#v, want selected rootless target", result)
	}
	if gotRunTarget.Name != "podman-dev" || gotRunTarget.Runtime.WorkerID != "worker-blocked" {
		t.Fatalf("run target = %#v, want worker-backed runtime target", gotRunTarget)
	}
	if readySecurity == nil || readySecurity.CapabilityReadinessDiagnostics == nil ||
		!readySecurity.CapabilityReadinessDiagnostics.WouldBlockStrictGate {
		t.Fatalf("ready security = %#v, want strict-blocking readiness diagnostics preserved", readySecurity)
	}
	decision := sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		readySecurity.CapabilityReadinessDiagnostics,
	)
	if decision.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
		t.Fatalf("strict gate decision = %#v, want blocking fixture left unevaluated by sandboxexec", decision)
	}
}

func sandboxexecStrictBlockingReadinessFixture(t *testing.T) (sandbox.SandboxSecurityCapabilityReadinessOutput, sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary) {
	t.Helper()
	requested := &sandbox.SandboxSecurityCapabilityMetadata{
		ID:         "requested-deny-by-default",
		Family:     sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
		Capability: sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
		Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
	}
	ready := &sandbox.SandboxSecurityCapabilityMetadata{
		ID:         "runtime-deny-by-default",
		Family:     sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
		Capability: sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
		Source:     sandbox.SandboxSecurityCapabilitySourceRuntime,
		Status:     sandbox.SandboxSecurityCapabilityReadinessBlocked,
		ReasonCode: sandbox.SandboxSecurityCapabilityReasonCapabilityBlocked,
	}
	output := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{
			{
				State:      sandbox.SandboxSecurityCapabilityReadinessBlocked,
				Requested:  requested,
				Ready:      ready,
				ReasonCode: sandbox.SandboxSecurityCapabilityReasonCapabilityBlocked,
				WarningCodes: []sandbox.SandboxSecurityCapabilityWarningCode{
					sandbox.SandboxSecurityCapabilityWarningBlockedByPolicy,
				},
			},
		},
	})
	diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(output)
	decision := sandbox.EvaluateSandboxSecurityCapabilityReadinessGate(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict, diagnostics)
	if decision.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked ||
		!diagnostics.WouldBlockStrictGate {
		t.Fatalf("readiness fixture decision/diagnostics = %#v/%#v, want strict gate block", decision, diagnostics)
	}
	return output, diagnostics
}
