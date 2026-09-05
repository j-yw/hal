package sandboxtarget

import (
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestSchedulerRequestCarriesIntentProjectWorkspaceAndConstraints(t *testing.T) {
	req := SchedulerRequest{
		Purpose:        PurposeRun,
		SandboxName:    "dev",
		HostID:         "host-1",
		RuntimeDriver:  sandbox.SandboxRuntimeDriverRootlessPodman,
		IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		Intent:         SchedulerIntentExplicitTarget,
		Project: ProjectContext{
			Dir:        "/repo",
			Repository: "github.com/jywlabs/hal",
			Branch:     "hal/phase-20",
		},
		Workspace: WorkspaceContext{
			ID:          "workspace-1",
			ResourceKey: "workspace:hal-phase-20",
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
			Repository:  "github.com/jywlabs/hal",
			Branch:      "hal/phase-20",
			SyncRef:     "refs/heads/hal/phase-20",
		},
		Fallback: FallbackPolicy{Disabled: true},
	}

	if !req.HasSchedulerIntent() || !req.HasHostConstraint() || !req.HasRuntimeConstraint() || !req.HasIsolationConstraint() {
		t.Fatalf("scheduler request helper methods did not recognize intent and constraints: %#v", req)
	}
	if req.Purpose != PurposeRun || req.SandboxName != "dev" {
		t.Fatalf("scheduler request purpose/sandbox = %q/%q, want run/dev", req.Purpose, req.SandboxName)
	}
	if req.Project.Repository != "github.com/jywlabs/hal" || req.Workspace.ResourceKey != "workspace:hal-phase-20" {
		t.Fatalf("scheduler request project/workspace = %#v/%#v, want stable identity", req.Project, req.Workspace)
	}
	if policy := req.EffectiveFallbackPolicy(); !policy.Disabled || policy.AllowDefaultRunningSandbox || policy.AllowBranchProvisioning {
		t.Fatalf("scheduler request fallback policy = %#v, want disabled", policy)
	}
}

func TestSchedulerRequestZeroValueHasNoIntentAndKeepsLegacyFallbackPolicy(t *testing.T) {
	var req SchedulerRequest

	if req.HasSchedulerIntent() || req.HasHostConstraint() || req.HasRuntimeConstraint() || req.HasIsolationConstraint() {
		t.Fatalf("zero-value scheduler request unexpectedly has intent or constraints: %#v", req)
	}
	policy := req.EffectiveFallbackPolicy()
	if !policy.AllowDefaultRunningSandbox || !policy.AllowBranchProvisioning || policy.Disabled {
		t.Fatalf("zero-value scheduler fallback policy = %#v, want legacy-compatible effective policy", policy)
	}
}

func TestSchedulerResultCarriesSelectionCapacityDecisionAndLeaseRequirement(t *testing.T) {
	ttl := 45 * time.Minute
	result := SchedulerResult{
		Selection: &SchedulerSelection{
			Identity: SchedulerTargetIdentity{
				SandboxID:      "sandbox-1",
				SandboxName:    "dev",
				HostID:         "host-1",
				HostName:       "local-worker",
				HostKind:       sandbox.SandboxHostKindWorker,
				RuntimeDriver:  sandbox.SandboxRuntimeDriverRootlessPodman,
				RuntimeID:      "ctr-1",
				IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			},
			Sandbox: &sandbox.SandboxState{
				ID:     "sandbox-1",
				Name:   "dev",
				Status: sandbox.StatusRunning,
			},
			Host: &sandbox.SandboxHost{
				ID:                "host-1",
				Name:              "local-worker",
				Kind:              sandbox.SandboxHostKindWorker,
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
				Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
			},
			Runtime: &sandboxruntime.RuntimeState{
				Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
				RuntimeID:      "ctr-1",
				IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			},
		},
		DecisionReason: SchedulerDecisionReasonExplicitHost,
		Capacity: SchedulerCapacityDecision{
			Known:                  true,
			Allowed:                true,
			MaxConcurrentSandboxes: 2,
			ActiveLeases:           1,
			AvailableSlots:         1,
			Reason:                 SchedulerDecisionReasonCapacityAvailable,
		},
		Lease: SchedulerLeaseRequirement{
			Required:    true,
			ResourceKey: "host:host-1",
			Holder:      "hal-run",
			Purpose:     PurposeRun,
			RunID:       "run-1",
			TTL:         ttl,
		},
	}

	if !result.Selected() || result.Rejected() || !result.RequiresLease() {
		t.Fatalf("scheduler result selected/rejected/lease = %v/%v/%v, want selected lease requirement", result.Selected(), result.Rejected(), result.RequiresLease())
	}
	if result.Selection.Identity.HostID != "host-1" || result.Selection.Identity.RuntimeDriver != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("scheduler selected identity = %#v, want host/runtime identity", result.Selection.Identity)
	}
	if result.Selection.Host.Capacity.MaxConcurrentSandboxes != 2 || result.Capacity.ActiveLeases != 1 || result.Capacity.AvailableSlots != 1 {
		t.Fatalf("scheduler capacity decision = %#v, want cached capacity with lease counts", result.Capacity)
	}
	if result.Lease.ResourceKey != "host:host-1" || result.Lease.TTL != ttl {
		t.Fatalf("scheduler lease requirement = %#v, want host lease and ttl", result.Lease)
	}
	if result.DecisionReason != SchedulerDecisionReasonExplicitHost || result.Capacity.Reason != SchedulerDecisionReasonCapacityAvailable {
		t.Fatalf("scheduler reasons = %q/%q, want stable decision reasons", result.DecisionReason, result.Capacity.Reason)
	}
}

func TestSchedulerRejectionCarriesStableReasonAndSafeRequestContext(t *testing.T) {
	rejection := SchedulerRejection{
		Reason:         FailureReasonCapacityBlocked,
		HostID:         "host-1",
		RuntimeDriver:  sandbox.SandboxRuntimeDriverRootlessPodman,
		IsolationLevel: sandbox.SandboxIsolationLevelContainer,
	}
	result := SchedulerResult{Rejection: &rejection}

	if result.Selected() || !result.Rejected() {
		t.Fatalf("scheduler rejection selected/rejected = %v/%v, want rejected only", result.Selected(), result.Rejected())
	}
	if rejection.Error() != "sandbox target scheduling failed: capacity_blocked" {
		t.Fatalf("rejection Error() = %q, want stable classification", rejection.Error())
	}
	if rejection.HostID != "host-1" || rejection.RuntimeDriver != sandbox.SandboxRuntimeDriverRootlessPodman || rejection.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("rejection context = %#v, want requested target context only", rejection)
	}

	rejection.Message = "host host-1 has no available cached capacity"
	if rejection.Error() != rejection.Message {
		t.Fatalf("rejection Error() = %q, want explicit message %q", rejection.Error(), rejection.Message)
	}
}
