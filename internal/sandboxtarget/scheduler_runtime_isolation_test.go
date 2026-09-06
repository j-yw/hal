package sandboxtarget

import (
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestScheduleFiltersCachedCandidatesByRequestedRuntime(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent:        SchedulerIntentAnyEligibleTarget,
		RuntimeDriver: " " + sandbox.SandboxRuntimeDriverRootlessPodman + " ",
	}, schedulerTestCache([]*sandbox.SandboxHost{
		{
			ID:                "worker-ssh",
			Name:              "alpha",
			Kind:              sandbox.SandboxHostKindWorker,
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
		},
		{
			ID:                "worker-rootless",
			Name:              "beta",
			Kind:              sandbox.SandboxHostKindWorker,
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
			Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
		},
	}, nil))

	if !result.Selected() || result.Rejected() {
		t.Fatalf("result = %#v, want selected rootless cached candidate", result)
	}
	if result.Selection.Identity.HostID != "worker-rootless" {
		t.Fatalf("selection identity = %#v, want runtime-matching host", result.Selection.Identity)
	}
	if result.Selection.Runtime == nil ||
		result.Selection.Runtime.Driver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		result.Selection.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("selection runtime = %#v, want requested rootless runtime metadata", result.Selection.Runtime)
	}
	if result.Selection.Identity.RuntimeDriver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		result.Selection.Identity.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("selection identity = %#v, want runtime identity from selected candidate", result.Selection.Identity)
	}
}

func TestScheduleRequestedRuntimeMatchesOnlyCachedSupportedRuntimes(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent:        SchedulerIntentAnyEligibleTarget,
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:       "worker-runtime-only",
					Name:     "alpha",
					Kind:     sandbox.SandboxHostKindWorker,
					Endpoint: "unix:/tmp/private-worker.sock?token=super-secret",
				},
			}, nil
		},
	})

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want unsupported runtime rejection", result)
	}
	if result.Rejection.Reason != FailureReasonRuntimeUnsupported ||
		result.Rejection.RuntimeDriver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		result.Rejection.Error() != `no durable host supports requested runtime "rootless_podman"` {
		t.Fatalf("rejection = %#v, want durable supported-runtime rejection", result.Rejection)
	}
	for _, leaked := range []string{"/tmp/private-worker.sock", "super-secret"} {
		if strings.Contains(result.Rejection.Error(), leaked) {
			t.Fatalf("rejection %q leaked %q", result.Rejection.Error(), leaked)
		}
	}
}

func TestScheduleFiltersCachedCandidatesByRequestedIsolation(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent:         SchedulerIntentAnyEligibleTarget,
		IsolationLevel: sandbox.SandboxIsolationLevelVM,
	}, schedulerTestCache([]*sandbox.SandboxHost{
		{
			ID:                "worker-container",
			Name:              "alpha",
			Kind:              sandbox.SandboxHostKindWorker,
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
		},
		{
			ID:                "worker-vm",
			Name:              "beta",
			Kind:              sandbox.SandboxHostKindWorker,
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverMicroVM},
			Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
		},
	}, nil))

	if !result.Selected() || result.Rejected() {
		t.Fatalf("result = %#v, want selected VM-isolation cached candidate", result)
	}
	if result.Selection.Identity.HostID != "worker-vm" {
		t.Fatalf("selection identity = %#v, want VM-capable host", result.Selection.Identity)
	}
	if result.Selection.Runtime == nil ||
		result.Selection.Runtime.Driver != sandbox.SandboxRuntimeDriverMicroVM ||
		result.Selection.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("selection runtime = %#v, want microVM runtime metadata", result.Selection.Runtime)
	}
}

func TestScheduleDoesNotDowngradeRequestedStrongerIsolation(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent:         SchedulerIntentAnyEligibleTarget,
		IsolationLevel: sandbox.SandboxIsolationLevelVM,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "worker-container",
					Name:              "alpha",
					Kind:              sandbox.SandboxHostKindWorker,
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
				},
			}, nil
		},
	})

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want unavailable isolation rejection", result)
	}
	if result.Rejection.Reason != FailureReasonIsolationUnavailable ||
		result.Rejection.IsolationLevel != sandbox.SandboxIsolationLevelVM ||
		result.Rejection.Error() != `no durable host supports requested isolation "vm"` {
		t.Fatalf("rejection = %#v, want no VM-isolation rejection", result.Rejection)
	}
}

func TestScheduleRejectsIncompatibleRequestedRuntimeIsolation(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent:         SchedulerIntentAnyEligibleTarget,
		RuntimeDriver:  sandbox.SandboxRuntimeDriverRootlessPodman,
		IsolationLevel: sandbox.SandboxIsolationLevelVM,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("ListHosts should not be called when requested runtime cannot satisfy isolation")
			return nil, nil
		},
	})

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want incompatible runtime/isolation rejection", result)
	}
	if result.Rejection.Reason != FailureReasonIsolationUnavailable ||
		result.Rejection.RuntimeDriver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		result.Rejection.IsolationLevel != sandbox.SandboxIsolationLevelVM ||
		result.Rejection.Error() != `requested runtime "rootless_podman" provides isolation "container", not requested isolation "vm"` {
		t.Fatalf("rejection = %#v, want runtime/isolation compatibility rejection", result.Rejection)
	}
}

func TestSchedulerFilteringUsesPersistedRuntimeIsolationWhenPresent(t *testing.T) {
	candidateSet := SchedulerCandidateSet{Candidates: []SchedulerCandidate{
		{
			Identity: SchedulerTargetIdentity{
				HostID:   "worker-rootless",
				HostName: "alpha",
				HostKind: sandbox.SandboxHostKindWorker,
			},
			Host: &sandbox.SandboxHost{
				ID:                "worker-rootless",
				Name:              "alpha",
				Kind:              sandbox.SandboxHostKindWorker,
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
			},
			Runtime: &sandboxruntime.RuntimeState{
				Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
				RuntimeID:      "ctr-1",
				IsolationLevel: sandbox.SandboxIsolationLevelVM,
			},
		},
	}}

	filtered := filterSchedulerCandidatesByRuntimeAndIsolation(SchedulerRequest{
		Intent:         SchedulerIntentAnyEligibleTarget,
		IsolationLevel: sandbox.SandboxIsolationLevelContainer,
	}, candidateSet)
	if !filtered.Failed() ||
		filtered.Rejection.Reason != FailureReasonIsolationUnavailable ||
		filtered.Rejection.Error() != `no durable host supports requested isolation "container"` {
		t.Fatalf("filtered = %#v, want persisted isolation to override runtime category mapping", filtered)
	}

	filtered = filterSchedulerCandidatesByRuntimeAndIsolation(SchedulerRequest{
		Intent:         SchedulerIntentAnyEligibleTarget,
		IsolationLevel: sandbox.SandboxIsolationLevelVM,
	}, candidateSet)
	if filtered.Failed() || len(filtered.Candidates) != 1 {
		t.Fatalf("filtered = %#v, want candidate selected by persisted runtime isolation", filtered)
	}
	runtime := filtered.Candidates[0].Runtime
	if runtime == nil ||
		runtime.Driver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		runtime.RuntimeID != "ctr-1" ||
		runtime.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("runtime = %#v, want persisted runtime metadata", runtime)
	}
}

func TestPhase32SchedulerDoesNotInferMicroVMRuntimeWithoutExplicitConstraint(t *testing.T) {
	candidateSet := SchedulerCandidateSet{Candidates: []SchedulerCandidate{
		{
			Identity: SchedulerTargetIdentity{
				HostID:   "worker-microvm",
				HostName: "microvm worker",
				HostKind: sandbox.SandboxHostKindWorker,
			},
			Host: &sandbox.SandboxHost{
				ID:                "worker-microvm",
				Name:              "microvm worker",
				Kind:              sandbox.SandboxHostKindWorker,
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverMicroVM},
				Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
			},
		},
	}}

	filtered := filterSchedulerCandidatesByRuntimeAndIsolation(SchedulerRequest{}, candidateSet)
	if filtered.Failed() || len(filtered.Candidates) != 1 {
		t.Fatalf("filtered = %#v, want unconstrained candidate set preserved", filtered)
	}
	if filtered.Candidates[0].Runtime != nil || filtered.Candidates[0].Identity.RuntimeDriver != "" || filtered.Candidates[0].Identity.IsolationLevel != "" {
		t.Fatalf("filtered candidate = %#v, want no inferred microVM runtime without explicit scheduler constraint", filtered.Candidates[0])
	}
}
