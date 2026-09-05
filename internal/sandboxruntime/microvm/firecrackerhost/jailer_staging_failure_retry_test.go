package firecrackerhost

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestStageStrictJailerResourcesDoesNotRetainTerminalFailureCleanup(t *testing.T) {
	request := validJailerStagingRequest()
	filesystem := newFakeJailerStagingFilesystem()
	filesystem.failCreatePath = "run/fc-run-alpha/firecracker-config.json"
	filesystem.failure = errors.New("write failed at /srv/private/config-secret")
	filesystem.rootCloseErr = errors.New("close failed at /srv/private/root-secret")

	result, err := stageStrictJailerResources(filesystem, request)
	if !errors.Is(err, errJailerStagingFailed) || !errors.Is(err, errJailerStagingCleanupIncomplete) {
		t.Fatalf("error = %v, want staging and cleanup sentinels", err)
	}
	if result.retainsOwnedRoot() || result.lease != nil {
		t.Fatalf("terminal staging result = %#v, want no retry authority", result)
	}
	if filesystem.root == nil || filesystem.root.removeCalls != 1 || filesystem.root.closeCalls != 1 {
		t.Fatalf("terminal partial cleanup = %#v, want remove and close exactly once", filesystem.root)
	}
	assertJailerStagingErrorRedacted(t, err)
}

func TestStrictJailerCoordinatorRetainsFailedStagingCleanupUntilExactRetry(t *testing.T) {
	events := []string{}
	firstRoot := &coordinatorFakeRoot{
		events:       &events,
		removeErrors: []error{errors.New("private retry failure"), nil},
	}
	secondRoot := &coordinatorFakeRoot{events: &events}
	lifecycle := &coordinatorFakeLifecycle{events: &events, process: strictJailerLifecycleProcess{runtimeUID: 1001}}
	stageCalls := 0
	coordinator := newStrictJailerCoordinatorWithDependencies(strictJailerCoordinatorDependencies{
		inspect: func(strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
			events = append(events, "inspect")
			return validCoordinatorInspection(), nil
		},
		newFilesystem: func(jailerStagingAuthority) (jailerStagingFilesystem, error) {
			events = append(events, "filesystem")
			return &coordinatorFakeFS{events: &events}, nil
		},
		stage: func(jailerStagingFilesystem, jailerStagingRequest) (jailerStagingResult, error) {
			events = append(events, "stage")
			stageCalls++
			if stageCalls == 1 {
				return jailerStagingResult{lease: &jailerStagingLease{root: firstRoot, uncertain: true}}, errors.Join(
					newJailerStagingError(errJailerStagingFailed, "write"),
					newJailerStagingError(errJailerStagingCleanupIncomplete, "root"),
				)
			}
			return jailerStagingResult{lease: &jailerStagingLease{root: secondRoot}}, nil
		},
		plan: func(request strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
			events = append(events, "plan")
			return strictJailerLaunchPlan{hostPaths: request.HostPaths}, nil
		},
		lifecycle: lifecycle,
	})

	session, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
	if !errors.Is(err, errStrictJailerCoordinatorFailed) || !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) {
		t.Fatalf("start() error = %v, want staging failure plus cleanup incomplete", err)
	}
	if containsAny(err.Error(), "private", "retry failure", "/srv/") {
		t.Fatalf("start() error leaked staging or cleanup detail: %q", err)
	}
	if session.coordinator != coordinator || session.generation == 0 {
		t.Fatalf("start() session = %#v, want opaque cleanup authority", session)
	}
	if got, want := events, []string{"inspect", "filesystem", "stage"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("staging failure events = %v, want %v", got, want)
	}
	if _, busyErr := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t)); !errors.Is(busyErr, errStrictJailerCoordinatorBusy) {
		t.Fatalf("start while cleanup pending = %v, want busy", busyErr)
	}
	if retryErr := coordinator.retryCleanup(context.Background(), session); !errors.Is(retryErr, errStrictJailerCoordinatorCleanupIncomplete) {
		t.Fatalf("first retryCleanup() error = %v, want cleanup incomplete", retryErr)
	}
	if _, busyErr := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t)); !errors.Is(busyErr, errStrictJailerCoordinatorBusy) {
		t.Fatalf("start after failed retry = %v, want busy", busyErr)
	}
	if retryErr := coordinator.retryCleanup(context.Background(), session); retryErr != nil {
		t.Fatalf("second retryCleanup() error = %v, want nil", retryErr)
	}
	if slicesContain(events, "start") || slicesContain(events, "stop") || slicesContain(events, "terminated") || slicesContain(events, "forget") {
		t.Fatalf("staging cleanup invoked process lifecycle: %v", events)
	}

	secondSession, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
	if err != nil {
		t.Fatalf("start after exact cleanup = %v, want nil", err)
	}
	if secondSession.generation == session.generation {
		t.Fatalf("generation after cleanup = %d, want new generation", secondSession.generation)
	}
}

func TestStrictJailerCoordinatorDoesNotRetainTerminalFailedStagingCleanup(t *testing.T) {
	events := []string{}
	lifecycle := &coordinatorFakeLifecycle{events: &events}
	coordinator := newStrictJailerCoordinatorWithDependencies(strictJailerCoordinatorDependencies{
		inspect: func(strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
			return validCoordinatorInspection(), nil
		},
		newFilesystem: func(jailerStagingAuthority) (jailerStagingFilesystem, error) {
			return &coordinatorFakeFS{events: &events}, nil
		},
		stage: func(jailerStagingFilesystem, jailerStagingRequest) (jailerStagingResult, error) {
			return jailerStagingResult{}, errors.Join(
				newJailerStagingError(errJailerStagingFailed, "write"),
				newJailerStagingError(errJailerStagingCleanupIncomplete, "root_close"),
			)
		},
		plan: func(strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
			return strictJailerLaunchPlan{}, errors.New("must not plan")
		},
		lifecycle: lifecycle,
	})

	session, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
	if !errors.Is(err, errStrictJailerCoordinatorFailed) || !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) {
		t.Fatalf("start() error = %v, want staging failure plus terminal cleanup warning", err)
	}
	if containsAny(err.Error(), "private", "root-secret", "/srv/") {
		t.Fatalf("start() error leaked staging or cleanup detail: %q", err)
	}
	if session != (strictJailerSession{}) {
		t.Fatalf("terminal staging cleanup session = %#v, want zero", session)
	}
	if _, nextErr := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t)); errors.Is(nextErr, errStrictJailerCoordinatorBusy) {
		t.Fatalf("terminal staging cleanup retained coordinator generation: %v", nextErr)
	}
	if len(events) != 0 {
		t.Fatalf("terminal staging failure invoked process lifecycle: %v", events)
	}
}
