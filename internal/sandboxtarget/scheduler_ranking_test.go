package sandboxtarget

import (
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestScheduleRanksEligibleCandidatesByAvailableCapacityBeforeNameTieBreak(t *testing.T) {
	hosts := []*sandbox.SandboxHost{
		schedulerHealthyTestHost("worker-z", "zeta", 4),
		schedulerHealthyTestHost("worker-a", "alpha", 2),
	}

	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, schedulerTestCache(hosts, []*sandbox.SandboxLease{
		schedulerTestLease("lease-a", "host:worker-a", sandbox.SandboxLeaseStatusActive, schedulerTestNow.Add(time.Hour)),
		schedulerTestLease("lease-z", "host:worker-z", sandbox.SandboxLeaseStatusActive, schedulerTestNow.Add(time.Hour)),
	}))

	if !result.Selected() || result.Rejected() {
		t.Fatalf("result = %#v, want ranked selected candidate", result)
	}
	if result.Selection.Identity.HostID != "worker-z" {
		t.Fatalf("selection identity = %#v, want candidate with most available cached capacity", result.Selection.Identity)
	}
	if result.Capacity.MaxConcurrentSandboxes != 4 ||
		result.Capacity.ActiveLeases != 1 ||
		result.Capacity.AvailableSlots != 3 ||
		result.Capacity.Reason != SchedulerDecisionReasonCapacityAvailable {
		t.Fatalf("capacity decision = %#v, want selected high-capacity candidate facts", result.Capacity)
	}
}

func TestScheduleRanksHealthyReadinessBeforeUnknownWhenCapacityTies(t *testing.T) {
	unknown := schedulerTestHost("worker-unknown", "alpha", 1)
	unknown.Health = &sandbox.HostHealth{Status: "unknown"}
	healthy := schedulerHealthyTestHost("worker-healthy", "zeta", 1)

	result := Schedule(SchedulerRequest{
		Intent: SchedulerIntentAnyEligibleTarget,
	}, schedulerTestCache([]*sandbox.SandboxHost{unknown, healthy}, nil))

	if !result.Selected() || result.Rejected() {
		t.Fatalf("result = %#v, want selected ranked candidate", result)
	}
	if result.Selection.Identity.HostID != "worker-healthy" {
		t.Fatalf("selection identity = %#v, want healthy cached candidate before unknown-readiness candidate", result.Selection.Identity)
	}
}

func TestScheduleTieBreaksEqualRankedCandidatesByNameThenIDAcrossShuffledInput(t *testing.T) {
	hostA := schedulerHealthyTestHost("worker-a", "builder", 1)
	hostB := schedulerHealthyTestHost("worker-b", "builder", 1)
	hostC := schedulerHealthyTestHost("worker-c", "builder", 1)

	for _, tt := range []struct {
		name  string
		hosts []*sandbox.SandboxHost
	}{
		{name: "abc", hosts: []*sandbox.SandboxHost{hostA, hostB, hostC}},
		{name: "cba", hosts: []*sandbox.SandboxHost{hostC, hostB, hostA}},
		{name: "bac", hosts: []*sandbox.SandboxHost{hostB, hostA, hostC}},
		{name: "cab", hosts: []*sandbox.SandboxHost{hostC, hostA, hostB}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := Schedule(SchedulerRequest{
				Intent: SchedulerIntentAnyEligibleTarget,
			}, schedulerTestCache(tt.hosts, nil))

			if !result.Selected() || result.Rejected() {
				t.Fatalf("result = %#v, want deterministic ranked candidate", result)
			}
			if result.Selection.Identity.HostID != "worker-a" {
				t.Fatalf("selection identity = %#v, want stable host ID tie-break independent of input order", result.Selection.Identity)
			}
		})
	}
}

func schedulerHealthyTestHost(id, name string, maxConcurrent int) *sandbox.SandboxHost {
	host := schedulerTestHost(id, name, maxConcurrent)
	host.Health = &sandbox.HostHealth{Status: "healthy"}
	return host
}
