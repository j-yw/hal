package sandboxtarget

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

var schedulerTestNow = time.Date(2026, 7, 1, 13, 0, 0, 0, time.UTC)

func TestScheduleCountsActiveNonExpiredHostLeasesAgainstCapacity(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent:  SchedulerIntentAnyEligibleTarget,
		Purpose: PurposeRun,
	}, schedulerTestCache([]*sandbox.SandboxHost{
		schedulerTestHost("worker-a", "alpha", 2),
		schedulerTestHost("worker-b", "beta", 1),
	}, []*sandbox.SandboxLease{
		schedulerTestLease("lease-a", "host:worker-a", sandbox.SandboxLeaseStatusActive, schedulerTestNow.Add(time.Hour)),
		schedulerTestLease("lease-b", "host:worker-b", sandbox.SandboxLeaseStatusActive, schedulerTestNow.Add(time.Hour)),
	}))

	if !result.Selected() || result.Rejected() {
		t.Fatalf("result = %#v, want selected candidate with available capacity", result)
	}
	if result.Selection.Identity.HostID != "worker-a" {
		t.Fatalf("selection identity = %#v, want first candidate with remaining capacity", result.Selection.Identity)
	}
	if result.Capacity.Known != true ||
		result.Capacity.Allowed != true ||
		result.Capacity.MaxConcurrentSandboxes != 2 ||
		result.Capacity.ActiveLeases != 1 ||
		result.Capacity.AvailableSlots != 1 ||
		result.Capacity.Reason != SchedulerDecisionReasonCapacityAvailable {
		t.Fatalf("capacity decision = %#v, want one active lease counted against capacity two", result.Capacity)
	}
	if !result.RequiresLease() ||
		result.Lease.ResourceKey != "host:worker-a" ||
		result.Lease.Purpose != PurposeRun {
		t.Fatalf("lease requirement = %#v, want host lease requirement for selected candidate", result.Lease)
	}
}

func TestScheduleIgnoresExpiredAndReleasedLeasesForCapacity(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent:  SchedulerIntentAnyEligibleTarget,
		Purpose: PurposeAuto,
	}, schedulerTestCache([]*sandbox.SandboxHost{
		schedulerTestHost("worker-a", "alpha", 1),
	}, []*sandbox.SandboxLease{
		schedulerTestLease("expired-status", "host:worker-a", sandbox.SandboxLeaseStatusExpired, schedulerTestNow.Add(time.Hour)),
		schedulerTestLease("expired-time", "host:worker-a", sandbox.SandboxLeaseStatusActive, schedulerTestNow),
		schedulerTestLease("released", "host:worker-a", sandbox.SandboxLeaseStatusReleased, schedulerTestNow.Add(time.Hour)),
		schedulerTestLease("other-host", "host:worker-b", sandbox.SandboxLeaseStatusActive, schedulerTestNow.Add(time.Hour)),
	}))

	if !result.Selected() || result.Rejected() {
		t.Fatalf("result = %#v, want expired/released leases ignored", result)
	}
	if result.Capacity.ActiveLeases != 0 ||
		result.Capacity.AvailableSlots != 1 ||
		result.Capacity.Reason != SchedulerDecisionReasonCapacityAvailable {
		t.Fatalf("capacity decision = %#v, want no counted active leases", result.Capacity)
	}
	if result.Lease.ResourceKey != "host:worker-a" || result.Lease.Purpose != PurposeAuto {
		t.Fatalf("lease requirement = %#v, want selected host auto lease", result.Lease)
	}
}

func TestScheduleRejectsWhenAllCandidatesAreCapacityBlocked(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, schedulerTestCache([]*sandbox.SandboxHost{
		schedulerTestHost("worker-a", "alpha", 1),
		schedulerTestHost("worker-b", "beta", 2),
	}, []*sandbox.SandboxLease{
		schedulerTestLease("lease-a", "host:worker-a", sandbox.SandboxLeaseStatusActive, schedulerTestNow.Add(time.Hour)),
		schedulerTestLease("lease-b1", "host:worker-b", sandbox.SandboxLeaseStatusActive, schedulerTestNow.Add(time.Hour)),
		schedulerTestLease("lease-b2", "host:worker-b", sandbox.SandboxLeaseStatusActive, schedulerTestNow.Add(time.Hour)),
	}))

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want capacity-blocked rejection", result)
	}
	if result.Rejection.Reason != FailureReasonCapacityBlocked ||
		result.Rejection.Error() != "no cached sandbox hosts have available capacity" {
		t.Fatalf("rejection = %#v, want stable capacity-blocked rejection", result.Rejection)
	}
	if result.Capacity.Known != true ||
		result.Capacity.Allowed != false ||
		result.Capacity.ActiveLeases != 1 ||
		result.Capacity.AvailableSlots != 0 ||
		result.Capacity.Reason != SchedulerDecisionReasonCapacityBlocked {
		t.Fatalf("capacity decision = %#v, want first blocked candidate decision", result.Capacity)
	}
}

func TestScheduleRejectsMissingOrZeroCapacityConservatively(t *testing.T) {
	for _, tt := range []struct {
		name string
		host *sandbox.SandboxHost
	}{
		{
			name: "missing capacity",
			host: &sandbox.SandboxHost{
				ID:   "worker-a",
				Name: "alpha",
				Kind: sandbox.SandboxHostKindWorker,
			},
		},
		{
			name: "zero capacity",
			host: schedulerTestHost("worker-a", "alpha", 0),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := Schedule(SchedulerRequest{
				Intent: SchedulerIntentAnyEligibleTarget,
			}, schedulerTestCache([]*sandbox.SandboxHost{tt.host}, nil))

			if result.Selected() || !result.Rejected() {
				t.Fatalf("result = %#v, want conservative capacity rejection", result)
			}
			if result.Rejection.Reason != FailureReasonCapacityUnavailable ||
				result.Rejection.Error() != "no cached sandbox hosts have usable capacity metadata" {
				t.Fatalf("rejection = %#v, want stable capacity-unavailable rejection", result.Rejection)
			}
			if result.Capacity.Known ||
				result.Capacity.Allowed ||
				!result.Capacity.ConservativeUnavailable ||
				result.Capacity.Reason != SchedulerDecisionReasonCapacityUnavailable {
				t.Fatalf("capacity decision = %#v, want conservative unavailable capacity", result.Capacity)
			}
		})
	}
}

func TestScheduleCapacityRequiresInjectedLeaseListerAndClock(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*CachedState)
		want   string
	}{
		{
			name: "missing lease lister",
			mutate: func(cache *CachedState) {
				cache.ListLeases = nil
			},
			want: "cached lease lister is required",
		},
		{
			name: "missing clock",
			mutate: func(cache *CachedState) {
				cache.Now = nil
			},
			want: "scheduler clock is required",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cache := schedulerTestCache([]*sandbox.SandboxHost{
				schedulerTestHost("worker-a", "alpha", 1),
			}, nil)
			tt.mutate(&cache)

			result := Schedule(SchedulerRequest{
				Intent: SchedulerIntentAnyEligibleTarget,
			}, cache)

			if result.Selected() || !result.Rejected() {
				t.Fatalf("result = %#v, want dependency rejection", result)
			}
			if result.Rejection.Reason != FailureReasonCapacityUnavailable ||
				result.Rejection.Error() != tt.want ||
				!result.Capacity.ConservativeUnavailable ||
				result.Capacity.Reason != SchedulerDecisionReasonCapacityUnavailable {
				t.Fatalf("result = %#v, want capacity dependency rejection %q", result, tt.want)
			}
		})
	}
}

func TestScheduleCapacityListFailureIsEndpointSafe(t *testing.T) {
	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{schedulerTestHost("worker-a", "alpha", 1)}, nil
		},
		ListLeases: func() ([]*sandbox.SandboxLease, error) {
			return nil, errors.New("open /tmp/private-worker.sock: token=super-secret")
		},
		Now: func() time.Time {
			return schedulerTestNow
		},
	})

	if result.Selected() || !result.Rejected() {
		t.Fatalf("result = %#v, want sanitized lease-list failure", result)
	}
	if result.Rejection.Reason != FailureReasonCapacityUnavailable ||
		result.Rejection.Error() != "list cached sandbox leases failed" {
		t.Fatalf("rejection = %#v, want stable lease-list failure rejection", result.Rejection)
	}
	for _, leaked := range []string{"/tmp/private-worker.sock", "super-secret"} {
		if strings.Contains(result.Rejection.Error(), leaked) {
			t.Fatalf("rejection %q leaked %q", result.Rejection.Error(), leaked)
		}
	}
}

func schedulerTestCache(hosts []*sandbox.SandboxHost, leases []*sandbox.SandboxLease) CachedState {
	return CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return hosts, nil
		},
		ListLeases: func() ([]*sandbox.SandboxLease, error) {
			return leases, nil
		},
		Now: func() time.Time {
			return schedulerTestNow
		},
	}
}

func schedulerTestHost(id, name string, maxConcurrent int) *sandbox.SandboxHost {
	return &sandbox.SandboxHost{
		ID:       id,
		Name:     name,
		Kind:     sandbox.SandboxHostKindWorker,
		Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: maxConcurrent},
	}
}

func schedulerTestLease(id, resourceKey, status string, expiresAt time.Time) *sandbox.SandboxLease {
	return &sandbox.SandboxLease{
		ID:          id,
		ResourceKey: resourceKey,
		Status:      status,
		ExpiresAt:   expiresAt,
	}
}
