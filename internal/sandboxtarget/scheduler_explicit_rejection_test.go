package sandboxtarget

import (
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestScheduleExplicitMissingHostRejectsWithoutFallbackSelection(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentExplicitTarget,
		HostID: "missing-host",
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				schedulerTestHost("worker-a", "alpha", 1),
			}, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not be called for explicit scheduler host rejection")
			return nil, nil
		},
		LoadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("LoadSandbox should not be called for explicit scheduler host rejection")
			return nil, nil
		},
		ListLeases: func() ([]*sandbox.SandboxLease, error) {
			t.Fatal("ListLeases should not be called after explicit missing host rejection")
			return nil, nil
		},
		Now: func() time.Time {
			t.Fatal("Now should not be called after explicit missing host rejection")
			return time.Time{}
		},
	})

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want explicit host rejection", result)
	}
	if result.Rejection.Reason != FailureReasonHostNotFound ||
		result.Rejection.HostID != "missing-host" ||
		result.Rejection.Error() != `host "missing-host" does not exist` {
		t.Fatalf("rejection = %#v, want deterministic missing explicit-host rejection", result.Rejection)
	}
}

func TestScheduleExplicitHostUnsupportedRuntimeRejectsWithoutSelectingAnotherHost(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent:        SchedulerIntentExplicitTarget,
		HostID:        "worker-ssh",
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "worker-ssh",
					Name:              "alpha",
					Kind:              sandbox.SandboxHostKindWorker,
					Endpoint:          "unix:/tmp/private-worker.sock?token=super-secret",
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
					Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
				},
				{
					ID:                "worker-rootless",
					Name:              "beta",
					Kind:              sandbox.SandboxHostKindWorker,
					SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
					Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
				},
			}, nil
		},
		ListLeases: func() ([]*sandbox.SandboxLease, error) {
			t.Fatal("ListLeases should not be called after explicit unsupported-runtime rejection")
			return nil, nil
		},
		Now: func() time.Time {
			t.Fatal("Now should not be called after explicit unsupported-runtime rejection")
			return time.Time{}
		},
	})

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want explicit runtime rejection", result)
	}
	if result.Rejection.Reason != FailureReasonRuntimeUnsupported ||
		result.Rejection.HostID != "worker-ssh" ||
		result.Rejection.RuntimeDriver != sandbox.SandboxRuntimeDriverRootlessPodman ||
		result.Rejection.Error() != `host "worker-ssh" does not support requested runtime "rootless_podman"` {
		t.Fatalf("rejection = %#v, want explicit unsupported-runtime rejection", result.Rejection)
	}
	for _, leaked := range []string{"/tmp/private-worker.sock", "super-secret"} {
		if strings.Contains(result.Rejection.Error(), leaked) {
			t.Fatalf("rejection %q leaked %q", result.Rejection.Error(), leaked)
		}
	}
}

func TestScheduleExplicitHostUnavailableIsolationRejectsWithoutSelectingAnotherHost(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent:         SchedulerIntentExplicitTarget,
		HostID:         "worker-container",
		IsolationLevel: sandbox.SandboxIsolationLevelVM,
	}, schedulerTestCache([]*sandbox.SandboxHost{
		{
			ID:                "worker-container",
			Name:              "alpha",
			Kind:              sandbox.SandboxHostKindWorker,
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
			Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
		},
		{
			ID:                "worker-vm",
			Name:              "beta",
			Kind:              sandbox.SandboxHostKindWorker,
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverMicroVM},
			Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
		},
	}, nil))

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want explicit isolation rejection", result)
	}
	if result.Rejection.Reason != FailureReasonIsolationUnavailable ||
		result.Rejection.HostID != "worker-container" ||
		result.Rejection.IsolationLevel != sandbox.SandboxIsolationLevelVM ||
		result.Rejection.Error() != `host "worker-container" does not support requested isolation "vm"` {
		t.Fatalf("rejection = %#v, want explicit unavailable-isolation rejection", result.Rejection)
	}
}

func TestScheduleExplicitHostCapacityBlockedRejectsWithoutSelectingAnotherHost(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentExplicitTarget,
		HostID: "worker-full",
	}, schedulerTestCache([]*sandbox.SandboxHost{
		schedulerTestHost("worker-full", "alpha", 1),
		schedulerTestHost("worker-open", "beta", 1),
	}, []*sandbox.SandboxLease{
		schedulerTestLease("lease-full", "host:worker-full", sandbox.SandboxLeaseStatusActive, schedulerTestNow.Add(time.Hour)),
	}))

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want explicit capacity-blocked rejection", result)
	}
	if result.Rejection.Reason != FailureReasonCapacityBlocked ||
		result.Rejection.HostID != "worker-full" ||
		result.Rejection.Error() != `host "worker-full" has no available cached capacity` {
		t.Fatalf("rejection = %#v, want explicit capacity-blocked rejection", result.Rejection)
	}
	if result.Capacity.Known != true ||
		result.Capacity.Allowed != false ||
		result.Capacity.MaxConcurrentSandboxes != 1 ||
		result.Capacity.ActiveLeases != 1 ||
		result.Capacity.AvailableSlots != 0 ||
		result.Capacity.Reason != SchedulerDecisionReasonCapacityBlocked {
		t.Fatalf("capacity decision = %#v, want blocked explicit-host capacity facts", result.Capacity)
	}
}
