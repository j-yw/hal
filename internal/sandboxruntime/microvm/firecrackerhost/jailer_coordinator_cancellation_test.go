package firecrackerhost

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestStrictJailerCoordinatorCancellationBeforeProcess(t *testing.T) {
	for _, phase := range []string{"before", "stage", "plan"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			events := []string{}
			root := &coordinatorFakeRoot{events: &events}
			lifecycle := &coordinatorFakeLifecycle{events: &events}
			coordinator := coordinatorForStateTest(&events, root, lifecycle)
			stage := coordinator.deps.stage
			coordinator.deps.stage = func(fs jailerStagingFilesystem, request jailerStagingRequest) (jailerStagingResult, error) {
				events = append(events, "stage")
				if phase == "stage" {
					cancel()
				}
				return stage(fs, request)
			}
			plan := coordinator.deps.plan
			coordinator.deps.plan = func(request strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
				if phase == "plan" {
					cancel()
				}
				return plan(request)
			}
			if phase == "before" {
				cancel()
			}
			_, err := coordinator.start(ctx, validStrictJailerCoordinatorRequest(t))
			if err == nil || slices.Contains(events, "start") {
				t.Fatalf("canceled coordinator launched: error=%v events=%v", err, events)
			}
			if phase == "before" && slices.Contains(events, "stage") {
				t.Fatal("pre-canceled request staged files")
			}
			if phase != "before" && !slices.Contains(events, "release") {
				t.Fatalf("canceled staged root not released: %v", events)
			}
		})
	}
}

func TestStrictJailerCoordinatorCancellationRetainsUncertainCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := []string{}
	root := &coordinatorFakeRoot{events: &events, removeErrors: []error{errors.New("injected remove failure"), nil}}
	lifecycle := &coordinatorFakeLifecycle{events: &events}
	coordinator := coordinatorForStateTest(&events, root, lifecycle)
	plan := coordinator.deps.plan
	coordinator.deps.plan = func(request strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
		cancel()
		return plan(request)
	}
	session, err := coordinator.start(ctx, validStrictJailerCoordinatorRequest(t))
	if !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) || slices.Contains(events, "start") {
		t.Fatalf("canceled cleanup ownership lost: error=%v events=%v", err, events)
	}
	if err := coordinator.retryCleanup(context.Background(), session); err != nil {
		t.Fatalf("retry exact root cleanup: %v", err)
	}
	if coordinator.generation != nil {
		t.Fatal("cleanup retry retained finished generation")
	}
}
