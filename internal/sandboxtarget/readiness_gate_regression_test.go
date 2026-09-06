package sandboxtarget

import (
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestScheduleIgnoresStrictBlockingSecurityReadinessForFilteringAndLease(t *testing.T) {
	readiness, diagnostics := strictBlockingSecurityReadinessFixture(t)
	blockedHost := schedulerHealthyTestHost("worker-blocked", "alpha", 1)
	blockedHost.Security = &sandbox.SandboxSecurity{
		CapabilityReadiness:            &readiness,
		CapabilityReadinessDiagnostics: &diagnostics,
	}
	otherHost := schedulerHealthyTestHost("worker-other", "zeta", 1)

	var listedLeases bool
	result := Schedule(SchedulerRequest{
		Intent:  SchedulerIntentAnyEligibleTarget,
		Purpose: PurposeRun,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{otherHost, blockedHost}, nil
		},
		ListLeases: func() ([]*sandbox.SandboxLease, error) {
			listedLeases = true
			return nil, nil
		},
		Now: func() time.Time {
			return schedulerTestNow
		},
	})

	if !listedLeases {
		t.Fatal("lease lister was not called; readiness gate diagnostics must not short-circuit capacity evaluation")
	}
	if !result.Selected() || result.Rejected() {
		t.Fatalf("result = %#v, want selected candidate despite strict-blocking readiness diagnostics", result)
	}
	if result.Selection.Identity.HostID != "worker-blocked" {
		t.Fatalf("selection identity = %#v, want normal ranked host selection to ignore readiness gate diagnostics", result.Selection.Identity)
	}
	if !result.RequiresLease() || result.Lease.ResourceKey != "host:worker-blocked" || result.Lease.Purpose != PurposeRun {
		t.Fatalf("lease requirement = %#v, want selected host lease requirement unaffected by readiness gate diagnostics", result.Lease)
	}
	if result.Selection.Host == nil || result.Selection.Host.Security == nil ||
		result.Selection.Host.Security.CapabilityReadinessDiagnostics == nil ||
		!result.Selection.Host.Security.CapabilityReadinessDiagnostics.WouldBlockStrictGate {
		t.Fatalf("selected host readiness diagnostics = %#v, want preserved strict-blocking advisory metadata", result.Selection.Host)
	}
}

func TestScheduleCapacityRejectionIgnoresStrictBlockingSecurityReadiness(t *testing.T) {
	readiness, diagnostics := strictBlockingSecurityReadinessFixture(t)
	host := schedulerHealthyTestHost("worker-full", "alpha", 1)
	host.Security = &sandbox.SandboxSecurity{
		CapabilityReadiness:            &readiness,
		CapabilityReadinessDiagnostics: &diagnostics,
	}

	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, schedulerTestCache([]*sandbox.SandboxHost{host}, []*sandbox.SandboxLease{
		schedulerTestLease("lease-full", "host:worker-full", sandbox.SandboxLeaseStatusActive, schedulerTestNow.Add(time.Hour)),
	}))

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want capacity rejection", result)
	}
	if result.Rejection.Reason != FailureReasonCapacityBlocked ||
		result.Capacity.Reason != SchedulerDecisionReasonCapacityBlocked {
		t.Fatalf("result = %#v, want capacity-only rejection reason", result)
	}
	if strings.Contains(result.Rejection.Error(), "readiness") || strings.Contains(result.Rejection.Error(), "gate") {
		t.Fatalf("capacity rejection referenced readiness gate diagnostics: %q", result.Rejection.Error())
	}
}

func TestSelectExplicitSandboxDoesNotRejectStrictBlockingSecurityReadiness(t *testing.T) {
	readiness, diagnostics := strictBlockingSecurityReadinessFixture(t)
	cachedHost := &sandbox.SandboxHost{
		ID:                "worker-blocked",
		Name:              "worker blocked",
		Kind:              sandbox.SandboxHostKindWorker,
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
		Security: &sandbox.SandboxSecurity{
			CapabilityReadiness:            &readiness,
			CapabilityReadinessDiagnostics: &diagnostics,
		},
	}
	selectedSandbox := &sandbox.SandboxState{
		Name:     "podman-dev",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:   "worker-blocked",
			Name: "worker blocked",
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID:      "ctr-blocked",
			WorkerID:       "worker-blocked",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}

	result := Select(Request{
		SandboxName:   "podman-dev",
		HostID:        "worker-blocked",
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
		t.Fatalf("result = %#v, want explicit target selected despite strict-blocking readiness diagnostics", result)
	}
	if result.Source.Kind != SourceExplicitSandbox {
		t.Fatalf("source = %#v, want explicit sandbox selection", result.Source)
	}
	if result.Sandbox.Host == nil || result.Sandbox.Host.Security == nil ||
		result.Sandbox.Host.Security.CapabilityReadinessDiagnostics == nil ||
		!result.Sandbox.Host.Security.CapabilityReadinessDiagnostics.WouldBlockStrictGate {
		t.Fatalf("selected sandbox host security = %#v, want strict-blocking advisory diagnostics preserved", result.Sandbox.Host)
	}
}

func strictBlockingSecurityReadinessFixture(t *testing.T) (sandbox.SandboxSecurityCapabilityReadinessOutput, sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary) {
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
