package sandboxtarget

import (
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestScheduleExcludesUnhealthyCachedHostsFromAutomaticScheduling(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, schedulerTestCache([]*sandbox.SandboxHost{
		{
			ID:       "worker-unhealthy",
			Name:     "alpha",
			Kind:     sandbox.SandboxHostKindWorker,
			Health:   &sandbox.HostHealth{Status: "unhealthy"},
			Endpoint: "unix:///tmp/private-worker.sock?token=super-secret",
		},
		{
			ID:       "worker-healthy",
			Name:     "beta",
			Kind:     sandbox.SandboxHostKindWorker,
			Health:   &sandbox.HostHealth{Status: "healthy"},
			Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
		},
	}, nil))

	if !result.Selected() || result.Rejected() {
		t.Fatalf("result = %#v, want selected healthy cached candidate", result)
	}
	if result.Selection.Identity.HostID != "worker-healthy" {
		t.Fatalf("selection identity = %#v, want unhealthy host excluded", result.Selection.Identity)
	}
}

func TestScheduleAllowsCachedHostsWithUnknownOrMissingHealth(t *testing.T) {
	for _, tt := range []struct {
		name   string
		health *sandbox.HostHealth
	}{
		{name: "missing health", health: nil},
		{name: "empty status", health: &sandbox.HostHealth{}},
		{name: "unknown status", health: &sandbox.HostHealth{Status: " unknown "}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := Schedule(SchedulerRequest{
				Intent: SchedulerIntentAnyEligibleTarget,
			}, schedulerTestCache([]*sandbox.SandboxHost{{
				ID:       "worker-a",
				Name:     "alpha",
				Kind:     sandbox.SandboxHostKindWorker,
				Health:   tt.health,
				Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
			}}, nil))

			if !result.Selected() || result.Selection.Identity.HostID != "worker-a" {
				t.Fatalf("result = %#v, want cached host eligible", result)
			}
		})
	}
}

func TestScheduleRejectsWhenAllCachedHostsAreUnhealthy(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:     "worker-degraded",
					Name:   "alpha",
					Kind:   sandbox.SandboxHostKindWorker,
					Health: &sandbox.HostHealth{Status: "degraded", Message: "slow on /tmp/private-worker.sock"},
				},
				{
					ID:       "worker-unavailable",
					Name:     "beta",
					Kind:     sandbox.SandboxHostKindWorker,
					Endpoint: "unix:///tmp/secret-worker.sock?token=super-secret",
					Health:   &sandbox.HostHealth{Status: "unavailable"},
				},
			}, nil
		},
	})

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want no healthy cached host rejection", result)
	}
	if result.Rejection.Reason != FailureReasonHostUnhealthy ||
		result.Rejection.Error() != "no healthy cached sandbox hosts" {
		t.Fatalf("rejection = %#v, want stable host-unhealthy rejection", result.Rejection)
	}
	for _, leaked := range []string{"unix://", "/tmp/secret-worker.sock", "/tmp/private-worker.sock", "super-secret"} {
		if strings.Contains(result.Rejection.Error(), leaked) {
			t.Fatalf("rejection %q leaked %q", result.Rejection.Error(), leaked)
		}
	}
}

func TestScheduleExplicitUnhealthyHostFailsWithoutEndpointLeak(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentExplicitTarget,
		HostID: " worker-a ",
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:       "worker-a",
					Name:     "alpha",
					Kind:     sandbox.SandboxHostKindWorker,
					Endpoint: "unix:///tmp/secret-worker.sock?token=super-secret",
					Health: &sandbox.HostHealth{
						Status:  "degraded",
						Message: "token=super-secret",
					},
				},
				{
					ID:     "worker-b",
					Name:   "beta",
					Kind:   sandbox.SandboxHostKindWorker,
					Health: &sandbox.HostHealth{Status: "healthy"},
				},
			}, nil
		},
	})

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want unhealthy explicit-host rejection", result)
	}
	if result.Rejection.Reason != FailureReasonHostUnhealthy ||
		result.Rejection.HostID != "worker-a" ||
		result.Rejection.Error() != `host "worker-a" is not healthy: degraded` {
		t.Fatalf("rejection = %#v, want deterministic unhealthy host rejection", result.Rejection)
	}
	for _, leaked := range []string{"unix://", "/tmp/secret-worker.sock", "super-secret"} {
		if strings.Contains(result.Rejection.Error(), leaked) {
			t.Fatalf("rejection %q leaked %q", result.Rejection.Error(), leaked)
		}
	}
}

func TestScheduleSanitizesUnsafeCachedHealthStatus(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentExplicitTarget,
		HostID: "worker-a",
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{{
				ID:       "worker-a",
				Name:     "alpha",
				Kind:     sandbox.SandboxHostKindWorker,
				Endpoint: "unix:///tmp/secret-worker.sock?token=super-secret",
				Health:   &sandbox.HostHealth{Status: "degraded token=super-secret /tmp/secret-worker.sock"},
			}}, nil
		},
	})

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want unsafe health status rejection", result)
	}
	if result.Rejection.Reason != FailureReasonHostUnhealthy ||
		result.Rejection.Error() != `host "worker-a" is not healthy: unhealthy` {
		t.Fatalf("rejection = %#v, want sanitized health status", result.Rejection)
	}
	for _, leaked := range []string{"/tmp/secret-worker.sock", "super-secret"} {
		if strings.Contains(result.Rejection.Error(), leaked) {
			t.Fatalf("rejection %q leaked %q", result.Rejection.Error(), leaked)
		}
	}
}
