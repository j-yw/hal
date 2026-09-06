package firecrackerhost

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestJailerCgroupCoordinatorCleanupQuarantinesEveryOwnedFailure(t *testing.T) {
	for _, failure := range []string{"kill", "events", "populated malformed", "identity", "root", "remove", "close", "uncertain start"} {
		t.Run(failure, func(t *testing.T) {
			events := []string{}
			root := &coordinatorFakeRoot{events: &events}
			life := &coordinatorFakeLifecycle{events: &events}
			coordinator := coordinatorForStateTest(&events, root, life)
			fs := newFakeJailerCgroupFilesystem()
			coordinator.deps.prepareCgroup = func(ctx context.Context, r strictJailerCgroupRequest) (*strictJailerCgroupLease, error) {
				return prepareFakeJailerCgroup(ctx, r, fs)
			}
			if failure == "uncertain start" {
				life.startErr = errStrictJailerNamespaceCleanupIncomplete
			}
			session, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
			if failure == "uncertain start" {
				if !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			fs.events = &events
			switch failure {
			case "kill", "uncertain start":
				fs.fail = "write:cgroup.kill"
			case "events":
				fs.fail = "read:cgroup.events"
			case "populated malformed":
				fs.holdPopulated = true
				fs.values["cgroup.events"] = "populated invalid\n"
			case "identity":
				fs.fail = "verify-cgroup"
			case "root":
				root.removeErrors = []error{errors.New("fixture root removal"), nil}
			case "remove":
				fs.fail = "remove-cgroup"
			case "close":
				fs.fail = "close-cgroup"
			}
			if failure == "uncertain start" {
				err = coordinator.retryCleanup(context.Background(), session)
			} else {
				err = coordinator.stop(context.Background(), session)
			}
			if !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) || coordinator.generation == nil {
				t.Fatalf("uncertain cleanup released generation: %v", err)
			}
			if _, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t)); !errors.Is(err, errStrictJailerCoordinatorBusy) {
				t.Fatal("uncertain resource reused")
			}
			if failure != "root" && failure != "remove" && failure != "close" && slices.Contains(events, "release") {
				t.Fatal("jail released before empty proof")
			}
			fs.fail = ""
			fs.holdPopulated = false
			fs.values["cgroup.events"] = "populated 0\nfrozen 0\n"
			if err := coordinator.retryCleanup(context.Background(), session); err != nil {
				t.Fatal(err)
			}
			if coordinator.generation != nil || !fs.closed || fs.created() {
				t.Fatal("owned retry did not converge")
			}
			kill, release, remove := slices.Index(events, "write:cgroup.kill"), slices.Index(events, "release"), slices.Index(events, "remove-cgroup")
			if kill < 0 || release < kill || remove < release {
				t.Fatalf("unsafe cleanup order %v", events)
			}
		})
	}
}

func TestJailerCgroupCoordinatorRechecksLimitsAfterPlan(t *testing.T) {
	events := []string{}
	root := &coordinatorFakeRoot{events: &events}
	life := &coordinatorFakeLifecycle{events: &events}
	coordinator := coordinatorForStateTest(&events, root, life)
	fs := newFakeJailerCgroupFilesystem()
	coordinator.deps.prepareCgroup = func(ctx context.Context, r strictJailerCgroupRequest) (*strictJailerCgroupLease, error) {
		return prepareFakeJailerCgroup(ctx, r, fs)
	}
	plan := coordinator.deps.plan
	coordinator.deps.plan = func(r strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
		fs.values["pids.max"] = "max\n"
		return plan(r)
	}
	if _, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t)); err == nil || slices.Contains(events, "start") {
		t.Fatal("changed limits reached lifecycle start")
	}
	if !fs.closed || coordinator.generation != nil || !slices.Contains(events, "release") {
		t.Fatal("failed launch leaked owned roots")
	}
}

func TestJailerCgroupCoordinatorRetainsUnidentifiedStagingFailure(t *testing.T) {
	events := []string{}
	coordinator := coordinatorForStateTest(&events, &coordinatorFakeRoot{events: &events}, &coordinatorFakeLifecycle{events: &events})
	coordinator.deps.stage = func(jailerStagingFilesystem, jailerStagingRequest) (jailerStagingResult, error) {
		return jailerStagingResult{}, newJailerStagingError(errJailerStagingCleanupIncomplete, "root")
	}
	session, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
	if !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) || coordinator.generation == nil {
		t.Fatal("unknown root lost quarantine")
	}
	if coordinator.retryCleanup(context.Background(), session) == nil || coordinator.generation == nil {
		t.Fatal("unknown root promoted to absence")
	}
}
