package firecrackerhost

import (
	"context"
	"errors"
	"testing"
)

type quarantinedCreationFilesystem struct {
	root       jailerStagingRoot
	createErr  error
	closeCalls int
}

func (filesystem *quarantinedCreationFilesystem) createExclusiveRoot(jailerStagingRootRequest) (jailerStagingRoot, error) {
	return filesystem.root, filesystem.createErr
}

func (filesystem *quarantinedCreationFilesystem) close() error {
	filesystem.closeCalls++
	return nil
}

func TestStageStrictJailerResourcesRetainsQuarantinedCreationAuthority(t *testing.T) {
	root := &fakeJailerStagingRoot{
		removeErr: errors.New("temporary cleanup failure"),
	}
	filesystem := &quarantinedCreationFilesystem{
		root:      root,
		createErr: errors.New("post-mkdir identity check failed"),
	}

	result, err := stageStrictJailerResources(filesystem, validJailerStagingRequest())
	if !errors.Is(err, errJailerStagingFailed) || !errors.Is(err, errJailerStagingCleanupIncomplete) {
		t.Fatalf("stage error = %v, want failed and cleanup-incomplete", err)
	}
	if !result.retainsOwnedRoot() {
		t.Fatal("post-mkdir creation failure discarded exact cleanup authority")
	}
	if root.removeCalls != 0 || root.closeCalls != 0 {
		t.Fatalf("quarantined root cleanup calls = remove:%d close:%d, want deferred 0/0", root.removeCalls, root.closeCalls)
	}
	if filesystem.closeCalls != 1 {
		t.Fatalf("filesystem close calls = %d, want 1 without closing transferred root authority", filesystem.closeCalls)
	}
	if releaseErr := result.releaseOwnedRoot(); !errors.Is(releaseErr, errJailerStagingCleanupIncomplete) {
		t.Fatalf("first release error = %v, want cleanup-incomplete", releaseErr)
	}
	if !result.retainsOwnedRoot() {
		t.Fatal("failed exact cleanup did not retain quarantine authority")
	}
	root.removeErr = nil
	if releaseErr := result.releaseOwnedRoot(); releaseErr != nil {
		t.Fatalf("second release error = %v, want nil", releaseErr)
	}
	if result.retainsOwnedRoot() || root.removeCalls != 2 || root.closeCalls != 1 {
		t.Fatalf("terminal cleanup = retained:%t remove:%d close:%d, want false/2/1", result.retainsOwnedRoot(), root.removeCalls, root.closeCalls)
	}
}

func TestStrictJailerCoordinatorQuarantinesCreationFailureUntilTerminalCleanup(t *testing.T) {
	events := []string{}
	root := &coordinatorFakeRoot{
		events:       &events,
		removeErrors: []error{errors.New("temporary cleanup failure"), nil},
	}
	coordinator := newStrictJailerCoordinatorWithDependencies(strictJailerCoordinatorDependencies{
		inspect: func(strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error) {
			return validCoordinatorInspection(), nil
		},
		newFilesystem: func(jailerStagingAuthority) (jailerStagingFilesystem, error) {
			return &quarantinedCreationFilesystem{
				root:      root,
				createErr: errors.New("post-mkdir identity check failed"),
			}, nil
		},
		stage: stageStrictJailerResources,
		plan: func(strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
			return strictJailerLaunchPlan{}, errors.New("must not plan a quarantined generation")
		},
		lifecycle: &coordinatorFakeLifecycle{events: &events},
	})

	session, err := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t))
	if !errors.Is(err, errStrictJailerCoordinatorFailed) || !errors.Is(err, errStrictJailerCoordinatorCleanupIncomplete) {
		t.Fatalf("start error = %v, want failed and cleanup-incomplete", err)
	}
	if session.coordinator != coordinator || session.generation == 0 {
		t.Fatalf("cleanup session = %#v, want retained generation authority", session)
	}
	if _, busyErr := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t)); !errors.Is(busyErr, errStrictJailerCoordinatorBusy) {
		t.Fatalf("start before cleanup = %v, want busy", busyErr)
	}
	if retryErr := coordinator.retryCleanup(context.Background(), session); !errors.Is(retryErr, errStrictJailerCoordinatorCleanupIncomplete) {
		t.Fatalf("first retry = %v, want cleanup-incomplete", retryErr)
	}
	if _, busyErr := coordinator.start(context.Background(), validStrictJailerCoordinatorRequest(t)); !errors.Is(busyErr, errStrictJailerCoordinatorBusy) {
		t.Fatalf("start after failed cleanup = %v, want busy", busyErr)
	}
	if retryErr := coordinator.retryCleanup(context.Background(), session); retryErr != nil {
		t.Fatalf("terminal retry = %v, want nil", retryErr)
	}
	if coordinator.generation != nil {
		t.Fatal("terminal cleanup retained coordinator generation")
	}
}

func TestStrictJailerNamespaceRunnerClosedDoneProvesTerminalCleanup(t *testing.T) {
	process := newAtomicJailerTestProcess()
	process.mu.Lock()
	process.closeLocked()
	process.killErr = errors.New("process already exited")
	process.waitErr = errors.New("exit status 1")
	process.mu.Unlock()
	runner, _, _ := atomicJailerTestRunner(t, process, errors.New("partial start failure"))

	_, err := runner.StartHostProcess(context.Background(), atomicJailerTestPlan(t, "run-alpha").processRequest())
	if !errors.Is(err, errStrictJailerNamespaceStartFailed) {
		t.Fatalf("StartHostProcess() error = %v, want start failure", err)
	}
	if errors.Is(err, errStrictJailerNamespaceCleanupIncomplete) {
		t.Fatalf("closed Done channel was not accepted as positive terminal proof: %v", err)
	}
	if runner.retained != nil {
		t.Fatal("terminal process remained permanently retained")
	}
	if process.killCalls != 1 || process.waitCalls != 1 {
		t.Fatalf("cleanup calls = kill:%d wait:%d, want 1/1", process.killCalls, process.waitCalls)
	}
}

var _ jailerStagingRoot = (*fakeJailerStagingRoot)(nil)
