package firecracker

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestPhase36LiveStartedStopAndDeleteDelegateToInjectedProcessManager(t *testing.T) {
	manager := &phase36LiveLifecycleManager{
		handle: ProcessHandleMetadata{
			ID:     "phase36-live-handle",
			Source: "phase36-test",
		},
	}
	stateRoot := firecrackerShortSocketTestRoot(t)
	config := validMicroVMConfig()
	backend := NewBackend(BackendOptions{
		BaseStateDir:         stateRoot,
		ProcessAdapter:       ProcessLaunchAdapter{Starter: manager},
		BootAcceptanceWaiter: manager,
		LiveProcessManager:   manager,
		LiveStart:            true,
	})

	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    config,
		Name:      "phase36-live-lifecycle",
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}

	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Start() error = %v, want nil", err)
	}
	if manager.startCalls != 1 || manager.waitCalls != 1 {
		t.Fatalf("live start calls = start:%d wait:%d, want one start and one host API socket acceptance wait", manager.startCalls, manager.waitCalls)
	}
	assertPhase36AcceptedLaunch(t, started, manager.handle)

	stopped, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStop,
		Config:    config,
		Target:    *started,
	})
	if err != nil {
		t.Fatalf("Stop() error = %v, want nil", err)
	}
	if manager.stopCalls != 1 {
		t.Fatalf("StopLiveProcess calls = %d, want one call on injected live process manager", manager.stopCalls)
	}
	if manager.cleanupCalls != 0 || manager.deleteCalls != 0 {
		t.Fatalf("unexpected lifecycle calls after Stop(): cleanup:%d delete:%d, want none", manager.cleanupCalls, manager.deleteCalls)
	}
	assertPhase36LifecycleRequest(t, manager.stopRequests[0], manager.handle, stateRoot, started)

	if err := controller.Delete(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationDelete,
		Config:    config,
		Target:    *stopped,
	}); err != nil {
		t.Fatalf("Delete() error = %v, want nil", err)
	}
	if manager.deleteCalls != 1 {
		t.Fatalf("DeleteLiveProcess calls = %d, want one call on injected live process manager", manager.deleteCalls)
	}
	if manager.cleanupCalls != 0 {
		t.Fatalf("CleanupLiveProcess calls = %d, want none during stop/delete lifecycle", manager.cleanupCalls)
	}
	assertPhase36LifecycleRequest(t, manager.deleteRequests[0], manager.handle, stateRoot, stopped)
}

type phase36LiveLifecycleManager struct {
	handle ProcessHandleMetadata

	startCalls   int
	waitCalls    int
	cleanupCalls int
	stopCalls    int
	deleteCalls  int

	stopRequests   []LiveProcessRequest
	deleteRequests []LiveProcessRequest
}

var _ ProcessStarter = (*phase36LiveLifecycleManager)(nil)
var _ BootAcceptanceWaiter = (*phase36LiveLifecycleManager)(nil)
var _ LiveProcessManager = (*phase36LiveLifecycleManager)(nil)

func (manager *phase36LiveLifecycleManager) StartProcess(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
	manager.startCalls++
	return manager.handle, nil
}

func (manager *phase36LiveLifecycleManager) WaitForBootAcceptance(context.Context, BootAcceptanceRequest) (BootAcceptanceResult, error) {
	manager.waitCalls++
	return BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	}, nil
}

func (manager *phase36LiveLifecycleManager) CleanupLiveProcess(context.Context, LiveProcessRequest) error {
	manager.cleanupCalls++
	return nil
}

func (manager *phase36LiveLifecycleManager) StopLiveProcess(_ context.Context, req LiveProcessRequest) error {
	manager.stopCalls++
	manager.stopRequests = append(manager.stopRequests, req)
	return nil
}

func (manager *phase36LiveLifecycleManager) DeleteLiveProcess(_ context.Context, req LiveProcessRequest) error {
	manager.deleteCalls++
	manager.deleteRequests = append(manager.deleteRequests, req)
	return nil
}

func assertPhase36AcceptedLaunch(t *testing.T, target *sandboxruntime.Target, handle ProcessHandleMetadata) {
	t.Helper()
	if target == nil || target.Runtime.Metadata == nil || target.Runtime.Metadata.ProcessLaunch == nil {
		t.Fatalf("started target launch metadata = %#v, want accepted live process metadata", target)
	}
	launch := target.Runtime.Metadata.ProcessLaunch
	if launch.State != string(ProcessLaunchStateAccepted) {
		t.Fatalf("ProcessLaunch.State = %q, want %q", launch.State, ProcessLaunchStateAccepted)
	}
	if launch.ProcessID != handle.ID || launch.ProcessIDSource != handle.Source {
		t.Fatalf("ProcessLaunch handle = %#v, want %#v", launch, handle)
	}
}

func assertPhase36LifecycleRequest(t *testing.T, req LiveProcessRequest, handle ProcessHandleMetadata, stateRoot string, target *sandboxruntime.Target) {
	t.Helper()
	if req.Handle != handle {
		t.Fatalf("live lifecycle request handle = %#v, want accepted handle %#v", req.Handle, handle)
	}
	wantPaths, err := PlanPaths(PathPlanRequest{
		RuntimeID:    target.Runtime.RuntimeID,
		BaseStateDir: stateRoot,
	})
	if err != nil {
		t.Fatalf("PlanPaths() error = %v, want nil", err)
	}
	if req.Paths != wantPaths {
		t.Fatalf("live lifecycle paths = %#v, want %#v", req.Paths, wantPaths)
	}
}
