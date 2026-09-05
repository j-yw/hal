//go:build linux

package firecracker

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestL8StartValueAndErrorCleansLiveHandleBeforeLease(t *testing.T) {
	probe := &l8AuthorityLifecycleProbe{}
	manager := &l8LifecycleProcessManager{cleanupProvesAbsence: true}
	controller, _, target := l8LifecycleController(t, probe, manager, "runtime-l8-value-error")
	adapter := &fakeProcessAdapter{}
	var borrowed []*os.File
	claimedDuringStart := false
	adapter.start = func(_ context.Context, request ProcessStartRequest) (ProcessHandleMetadata, error) {
		borrowed = append([]*os.File(nil), request.InheritedFiles...)
		claimedDuringStart = controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID)
		return ProcessHandleMetadata{ID: "value-error-pid", Source: "fake"}, errors.New("private start failure /host/path token=secret")
	}
	controller.processAdapter = adapter

	_, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	if err == nil {
		t.Fatal("Start() error = nil")
	}
	if strings.Contains(err.Error(), "/host/path") || strings.Contains(err.Error(), "token=secret") {
		t.Fatalf("Start() leaked private adapter error: %v", err)
	}
	if manager.cleanupCalls != 1 || manager.lastHandle.ID != "value-error-pid" {
		t.Fatalf("value+error cleanup = calls %d handle %#v", manager.cleanupCalls, manager.lastHandle)
	}
	if !claimedDuringStart {
		t.Fatal("L8 process and lease ownership was not claimed before ProcessAdapter call")
	}
	if probe.closeCalls != 1 || manager.cleanupOrder >= probe.closeOrder {
		t.Fatalf("cleanup/lease order = cleanup %d@%d close %d@%d", manager.cleanupCalls, manager.cleanupOrder, probe.closeCalls, probe.closeOrder)
	}
	if len(borrowed) != 2 {
		t.Fatalf("borrowed inherited files = %d, want 2", len(borrowed))
	}
	for index, file := range borrowed {
		if _, statErr := file.Stat(); statErr == nil {
			t.Fatalf("borrowed inherited file %d remains open", index)
		}
	}
	if controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID) {
		t.Fatal("proved value+error cleanup retained L8 lease")
	}
}

func TestL8DuplicateStartDoesNotCleanupHealthyActiveRuntime(t *testing.T) {
	probe := &l8AuthorityLifecycleProbe{}
	manager := &l8LifecycleProcessManager{cleanupProvesAbsence: true}
	controller, provider, target := l8LifecycleController(t, probe, manager, "runtime-l8-duplicate-active")
	adapter := controller.processAdapter.(*fakeProcessAdapter)
	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	if err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("duplicate Start() error = %v, want stable active-runtime rejection", err)
	}
	if provider.calls != 1 || adapter.startCalls != 1 || manager.cleanupCalls != 0 || probe.closeCalls != 0 {
		t.Fatalf("duplicate Start() mutated active runtime: providers %d starts %d cleanup %d close %d", provider.calls, adapter.startCalls, manager.cleanupCalls, probe.closeCalls)
	}
	if !controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "fake-pid") {
		t.Fatal("duplicate Start() discarded active L8 ownership")
	}
	if _, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStop, Target: *started}); err != nil {
		t.Fatal(err)
	}
}

func TestL8ConcurrentDuplicateStartCannotEnterUncertainCleanupRoute(t *testing.T) {
	probe := &l8AuthorityLifecycleProbe{}
	controller, provider, target := l8LifecycleController(t, probe, &l8LifecycleProcessManager{}, "runtime-l8-concurrent-active")
	manager := &l8PanicProcessManager{terminated: false}
	controller.liveProcessManager = manager
	adapter := controller.processAdapter.(*fakeProcessAdapter)
	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	if err != nil {
		t.Fatal(err)
	}

	const duplicates = 12
	errorsByCall := make(chan error, duplicates)
	var wait sync.WaitGroup
	for range duplicates {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, duplicateErr := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
				Operation: microvm.OperationStart,
				Config:    validMicroVMConfig(),
				Target:    target,
			})
			errorsByCall <- duplicateErr
		}()
	}
	wait.Wait()
	close(errorsByCall)
	for duplicateErr := range errorsByCall {
		if duplicateErr == nil || !strings.Contains(duplicateErr.Error(), "already active") {
			t.Fatalf("concurrent duplicate Start() error = %v", duplicateErr)
		}
	}
	manager.mu.Lock()
	cleanupCalls := manager.cleanupCalls
	manager.terminated = true
	manager.mu.Unlock()
	if provider.calls != 1 || adapter.startCalls != 1 || cleanupCalls != 0 || probe.closeCalls != 0 {
		t.Fatalf("concurrent active/uncertain control = providers %d starts %d cleanup %d close %d", provider.calls, adapter.startCalls, cleanupCalls, probe.closeCalls)
	}
	if _, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStop, Target: *started}); err != nil {
		t.Fatal(err)
	}
}

func TestL8TerminalActiveProcessIsRetiredAndRestartedUnderOneLifecycle(t *testing.T) {
	probe := &l8AuthorityLifecycleProbe{}
	manager := &l8HandleTerminalManager{terminated: map[string]bool{"old-pid": true}}
	controller, provider, target := l8LifecycleController(t, probe, &l8LifecycleProcessManager{}, "runtime-l8-terminal-restart")
	controller.liveProcessManager = manager
	adapter := &fakeProcessAdapter{}
	adapter.start = func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
		if adapter.startCalls == 1 {
			return ProcessHandleMetadata{ID: "old-pid", Source: "fake"}, nil
		}
		return ProcessHandleMetadata{ID: "new-pid", Source: "fake"}, nil
	}
	controller.processAdapter = adapter
	if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target}); err != nil {
		t.Fatal(err)
	}

	restarted, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Runtime.Metadata == nil || restarted.Runtime.Metadata.ProcessLaunch == nil || restarted.Runtime.Metadata.ProcessLaunch.ProcessID != "new-pid" {
		t.Fatalf("restarted process metadata = %#v", restarted.Runtime.Metadata)
	}
	if provider.calls != 2 || adapter.startCalls != 2 || manager.cleanupCallCount() != 0 || probe.closeCalls != 1 {
		t.Fatalf("terminal restart = providers %d starts %d cleanup %d closes %d", provider.calls, adapter.startCalls, manager.cleanupCallCount(), probe.closeCalls)
	}
	if controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "old-pid") || !controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "new-pid") {
		t.Fatalf("terminal restart ownership = old %t new %t", controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "old-pid"), controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "new-pid"))
	}
}

func TestL8ActiveTerminalProofFailureIsNonmutating(t *testing.T) {
	for _, test := range []struct {
		name    string
		manager LiveProcessManager
		calls   func() int
	}{
		{name: "absent", manager: fakeLiveBootSafetyHooks{}, calls: func() int { return 0 }},
		{name: "false", manager: &l8HandleTerminalManager{}, calls: func() int { return 1 }},
		{name: "panic", manager: &l8HandleTerminalManager{verifyPanic: true}, calls: func() int { return 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe := &l8AuthorityLifecycleProbe{}
			controller, provider, target := l8LifecycleController(t, probe, &l8LifecycleProcessManager{}, "runtime-l8-active-proof-"+test.name)
			controller.liveProcessManager = test.manager
			adapter := controller.processAdapter.(*fakeProcessAdapter)
			if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target}); err != nil {
				t.Fatal(err)
			}
			_, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target})
			if err == nil || !strings.Contains(err.Error(), "already active") || strings.Contains(err.Error(), "private") {
				t.Fatalf("active terminal proof %s error = %v", test.name, err)
			}
			if verifier, ok := test.manager.(*l8HandleTerminalManager); ok && verifier.verifyCallCount() != test.calls() {
				t.Fatalf("active terminal proof %s verifier calls = %d", test.name, verifier.verifyCallCount())
			}
			if provider.calls != 1 || adapter.startCalls != 1 || probe.closeCalls != 0 || !controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "fake-pid") {
				t.Fatalf("active terminal proof %s mutated runtime: providers %d starts %d closes %d retained %t", test.name, provider.calls, adapter.startCalls, probe.closeCalls, controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "fake-pid"))
			}
		})
	}
}

func TestL8TerminalActiveInvalidationUncertaintyEntersCleanupOnlyState(t *testing.T) {
	for _, failure := range []string{"bridge_panic", "lease_close_error"} {
		t.Run(failure, func(t *testing.T) {
			probe := &l8AuthorityLifecycleProbe{}
			manager := &l8HandleTerminalManager{terminated: map[string]bool{"fake-pid": true}}
			controller, provider, target := l8LifecycleController(t, probe, &l8LifecycleProcessManager{}, "runtime-l8-terminal-uncertain-"+failure)
			controller.liveProcessManager = manager
			bridge := &l8ControlledBridge{}
			controller.productionBridge = bridge
			adapter := controller.processAdapter.(*fakeProcessAdapter)
			if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target}); err != nil {
				t.Fatal(err)
			}
			if failure == "bridge_panic" {
				bridge.invalidatePanic = true
			} else {
				probe.closeError = errors.New("private close error /host/path token=secret")
			}

			_, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target})
			if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "/host/path") {
				t.Fatalf("terminal invalidation %s error = %v", failure, err)
			}
			_, state, owned := controller.liveSessions.L8ProcessOwnership(target.Runtime.RuntimeID)
			if !owned || state != l8ProcessOwnershipCleanupUncertain {
				t.Fatalf("terminal invalidation %s ownership = owned %t state %d", failure, owned, state)
			}
			if provider.calls != 1 || adapter.startCalls != 1 || manager.cleanupCallCount() != 0 {
				t.Fatalf("terminal invalidation %s launched/cleaned: providers %d starts %d cleanup %d", failure, provider.calls, adapter.startCalls, manager.cleanupCallCount())
			}
		})
	}
}

func TestL8ConcurrentTerminalRestartStartsExactlyOneReplacement(t *testing.T) {
	probe := &l8AuthorityLifecycleProbe{}
	manager := &l8HandleTerminalManager{terminated: map[string]bool{"old-pid": true}}
	controller, provider, target := l8LifecycleController(t, probe, &l8LifecycleProcessManager{}, "runtime-l8-concurrent-terminal-restart")
	controller.liveProcessManager = manager
	adapter := &l8SequenceProcessAdapter{handles: []ProcessHandleMetadata{{ID: "old-pid", Source: "fake"}, {ID: "new-pid", Source: "fake"}}}
	controller.processAdapter = adapter
	if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target}); err != nil {
		t.Fatal(err)
	}

	const attempts = 12
	results := make(chan error, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, restartErr := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target})
			results <- restartErr
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for resultErr := range results {
		if resultErr == nil {
			successes++
			continue
		}
		if !strings.Contains(resultErr.Error(), "already active") && !strings.Contains(resultErr.Error(), "already in progress") {
			t.Fatalf("concurrent terminal restart error = %v", resultErr)
		}
	}
	if successes != 1 || provider.calls != 2 || adapter.callCount() != 2 || manager.cleanupCallCount() != 0 || probe.closeCalls != 1 {
		t.Fatalf("concurrent terminal restart = successes %d providers %d starts %d cleanup %d close %d", successes, provider.calls, adapter.callCount(), manager.cleanupCallCount(), probe.closeCalls)
	}
	if !controller.liveSessions.HasL8Lease(target.Runtime.RuntimeID, "new-pid") {
		t.Fatal("concurrent terminal restart did not retain replacement ownership")
	}
}

func TestL8ProcessLaunchAdapterPreservesValueAndContainsStarterPanicAndTypedNil(t *testing.T) {
	plan := validFirecrackerStartOperationPlan(t)
	descriptor, err := ProcessCommandDescriptorFromStartPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("value_and_error", func(t *testing.T) {
		starter := &fakeProcessStarter{start: func(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
			return ProcessHandleMetadata{ID: "starter-pid", Source: "starter"}, errors.New("private starter failure /host/path token=secret")
		}}
		handle, startErr := (ProcessLaunchAdapter{Starter: starter}).StartProcess(context.Background(), ProcessStartRequest{Descriptor: descriptor})
		if startErr == nil || handle.ID != "starter-pid" || handle.Source != "starter" {
			t.Fatalf("value+error = handle %#v error %v", handle, startErr)
		}
		if strings.Contains(startErr.Error(), "/host/path") || strings.Contains(startErr.Error(), "token=secret") {
			t.Fatalf("starter error leaked: %v", startErr)
		}
	})
	t.Run("panic", func(t *testing.T) {
		starter := &fakeProcessStarter{start: func(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
			panic("private starter panic /host/path token=secret")
		}}
		_, startErr := (ProcessLaunchAdapter{Starter: starter}).StartProcess(context.Background(), ProcessStartRequest{Descriptor: descriptor})
		if startErr == nil || strings.Contains(startErr.Error(), "private") || strings.Contains(startErr.Error(), "/host/path") {
			t.Fatalf("starter panic error = %v", startErr)
		}
	})
	t.Run("typed_nil", func(t *testing.T) {
		var starter *fakeProcessStarter
		_, startErr := (ProcessLaunchAdapter{Starter: starter}).StartProcess(context.Background(), ProcessStartRequest{Descriptor: descriptor})
		if startErr == nil {
			t.Fatal("typed-nil starter error = nil")
		}
	})
}

func TestL8CleanupErrorAndPanicRetainUntilEventualRetrySuccess(t *testing.T) {
	for _, failure := range []string{"error", "panic"} {
		t.Run(failure, func(t *testing.T) {
			probe := &l8AuthorityLifecycleProbe{}
			manager := &l8PanicProcessManager{terminated: true}
			if failure == "error" {
				manager.cleanupErr = errors.New("private cleanup error /host/path token=secret")
			} else {
				manager.cleanupPanic = true
			}
			controller, _, target := l8LifecycleController(t, probe, &l8LifecycleProcessManager{}, "runtime-l8-cleanup-"+failure)
			controller.liveProcessManager = manager
			controller.processAdapter = &fakeProcessAdapter{start: func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
				return ProcessHandleMetadata{ID: "cleanup-pid", Source: "fake"}, errors.New("private start failure")
			}}

			_, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target})
			if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "/host/path") || strings.Contains(err.Error(), "token=secret") {
				t.Fatalf("initial cleanup %s error = %v", failure, err)
			}
			if !controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID) || probe.closeCalls != 0 {
				t.Fatalf("cleanup %s uncertainty = retained %t close %d", failure, controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID), probe.closeCalls)
			}

			manager.mu.Lock()
			manager.cleanupErr = nil
			manager.cleanupPanic = false
			manager.mu.Unlock()
			if _, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStop, Target: target}); err != nil {
				t.Fatal(err)
			}
			if controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID) || probe.closeCalls != 1 {
				t.Fatalf("eventual cleanup %s = retained %t close %d", failure, controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID), probe.closeCalls)
			}
		})
	}
}

func TestL8StopAndDeletePanicsRetainUntilEventualRetrySuccess(t *testing.T) {
	for _, operation := range []string{"stop", "delete"} {
		t.Run(operation, func(t *testing.T) {
			probe := &l8AuthorityLifecycleProbe{}
			manager := &l8PanicProcessManager{terminated: false}
			controller, _, target := l8LifecycleController(t, probe, &l8LifecycleProcessManager{}, "runtime-l8-manager-panic-"+operation)
			controller.liveProcessManager = manager
			controller.processAdapter = &fakeProcessAdapter{start: func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
				return ProcessHandleMetadata{ID: "manager-pid", Source: "fake"}, errors.New("start failure")
			}}
			if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target}); err == nil {
				t.Fatal("initial Start() error = nil")
			}
			manager.mu.Lock()
			manager.terminated = true
			manager.stopPanic = operation == "stop"
			manager.deletePanic = operation == "delete"
			manager.mu.Unlock()

			var err error
			if operation == "stop" {
				_, err = controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStop, Target: target})
			} else {
				err = controller.Delete(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationDelete, Target: target})
			}
			if err == nil || strings.Contains(err.Error(), "private") || !controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID) {
				t.Fatalf("%s panic result = err %v retained %t", operation, err, controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID))
			}

			manager.mu.Lock()
			manager.stopPanic = false
			manager.deletePanic = false
			manager.mu.Unlock()
			if operation == "stop" {
				_, err = controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStop, Target: target})
			} else {
				err = controller.Delete(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationDelete, Target: target})
			}
			if err != nil || controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID) || probe.closeCalls != 1 {
				t.Fatalf("eventual %s = err %v retained %t close %d", operation, err, controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID), probe.closeCalls)
			}
		})
	}
}

func TestL8BridgeInspectionAndInvalidationPanicsRetainOwnership(t *testing.T) {
	t.Run("session_active", func(t *testing.T) {
		bridge := &l8ControlledBridge{sessionActivePanic: true}
		controller := firecrackerController{
			productionVsock:  true,
			productionBridge: bridge,
			liveSessions:     newLiveSessionRegistry(),
		}
		proof := liveSessionProof{RuntimeID: "runtime-l8-bridge-active", ProcessGeneration: "bridge-pid", ProcessSource: "fake", BridgeGeneration: "bridge-generation"}
		controller.liveSessions.Activate(proof)
		controller.liveSessions.InvalidateProcess(liveProcessProof{RuntimeID: proof.RuntimeID, ProcessGeneration: proof.ProcessGeneration, ProcessSource: proof.ProcessSource})
		err := controller.rejectActiveProductionVsockSession(proof.RuntimeID)
		if err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("SessionActive panic error = %v", err)
		}
		if _, ok := controller.liveSessions.ProofForRuntime(proof.RuntimeID); !ok {
			t.Fatal("SessionActive panic discarded session ownership")
		}
	})

	t.Run("invalidate", func(t *testing.T) {
		probe := &l8AuthorityLifecycleProbe{}
		manager := &l8LifecycleProcessManager{cleanupProvesAbsence: true}
		controller, _, target := l8LifecycleController(t, probe, manager, "runtime-l8-bridge-invalidate")
		bridge := &l8ControlledBridge{invalidatePanic: true}
		controller.productionBridge = bridge
		started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target})
		if err != nil {
			t.Fatal(err)
		}
		_, err = controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStop, Target: *started})
		if err == nil || strings.Contains(err.Error(), "private") || !controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID) || probe.closeCalls != 0 {
			t.Fatalf("Invalidate panic = err %v retained %t close %d", err, controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID), probe.closeCalls)
		}
		bridge.invalidatePanic = false
		if _, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStop, Target: target}); err != nil {
			t.Fatal(err)
		}
		if controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID) || probe.closeCalls != 1 {
			t.Fatalf("eventual bridge invalidation = retained %t close %d", controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID), probe.closeCalls)
		}
	})
}

func TestL8RetainedCleanupIsReachableFromOriginalTarget(t *testing.T) {
	for _, operation := range []string{"start", "stop", "delete"} {
		t.Run(operation, func(t *testing.T) {
			probe := &l8AuthorityLifecycleProbe{}
			manager := &l8LifecycleProcessManager{cleanupProvesAbsence: false}
			controller, provider, target := l8LifecycleController(t, probe, manager, "runtime-l8-retry-"+operation)
			adapter := &fakeProcessAdapter{start: func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
				return ProcessHandleMetadata{ID: "retained-pid", Source: "fake"}, errors.New("private start failure")
			}}
			controller.processAdapter = adapter
			if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
				Operation: microvm.OperationStart,
				Config:    validMicroVMConfig(),
				Target:    target,
			}); err == nil {
				t.Fatal("initial Start() error = nil")
			}
			if !controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID) || probe.closeCalls != 0 {
				t.Fatalf("uncertain ownership = retained %t close %d", controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID), probe.closeCalls)
			}

			manager.cleanupProvesAbsence = true
			switch operation {
			case "start":
				_, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
					Operation: microvm.OperationStart,
					Config:    validMicroVMConfig(),
					Target:    target,
				})
				if err == nil || !strings.Contains(err.Error(), "retry") {
					t.Fatalf("retained cleanup Start() error = %v, want explicit retry", err)
				}
				if adapter.startCalls != 1 || provider.calls != 1 {
					t.Fatalf("retained cleanup launched/acquired again: starts %d providers %d", adapter.startCalls, provider.calls)
				}
			case "stop":
				if _, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStop, Target: target}); err != nil {
					t.Fatal(err)
				}
				if manager.stopCalls != 1 {
					t.Fatalf("StopLiveProcess calls = %d", manager.stopCalls)
				}
			case "delete":
				if err := controller.Delete(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationDelete, Target: target}); err != nil {
					t.Fatal(err)
				}
				if manager.deleteCalls != 1 {
					t.Fatalf("DeleteLiveProcess calls = %d", manager.deleteCalls)
				}
			}
			if probe.closeCalls != 1 || controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID) {
				t.Fatalf("eventual cleanup = close %d retained %t", probe.closeCalls, controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID))
			}
		})
	}
}

func TestL8ExternalBoundaryPanicsAreContainedAndCleaned(t *testing.T) {
	for _, boundary := range []string{"process_adapter", "boot_waiter", "bridge", "cleanup_manager", "terminal_verifier"} {
		t.Run(boundary, func(t *testing.T) {
			probe := &l8AuthorityLifecycleProbe{}
			manager := &l8PanicProcessManager{terminated: true}
			controller, _, target := l8LifecycleController(t, probe, &l8LifecycleProcessManager{}, "runtime-l8-panic-"+boundary)
			controller.liveProcessManager = manager
			adapter := &fakeProcessAdapter{}
			controller.processAdapter = adapter
			switch boundary {
			case "process_adapter":
				adapter.start = func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
					panic("private adapter panic /host/path token=secret")
				}
			case "boot_waiter":
				controller.bootAcceptanceWaiter = (*l8PanickingBootWaiter)(nil)
				controller.bootAcceptanceWaiter = &l8PanickingBootWaiter{}
			case "bridge":
				controller.productionBridge = &l8PanickingBridge{}
			case "cleanup_manager":
				adapter.start = func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
					return ProcessHandleMetadata{ID: "panic-pid", Source: "fake"}, errors.New("start failure")
				}
				manager.cleanupPanic = true
			case "terminal_verifier":
				adapter.start = func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
					return ProcessHandleMetadata{ID: "panic-pid", Source: "fake"}, errors.New("start failure")
				}
				manager.verifyPanic = true
			}

			var startErr error
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Errorf("%s panic escaped: %v", boundary, recovered)
					}
				}()
				_, startErr = controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
					Operation: microvm.OperationStart,
					Config:    validMicroVMConfig(),
					Target:    target,
				})
			}()
			if startErr == nil {
				t.Fatalf("%s Start() error = nil", boundary)
			}
			if strings.Contains(startErr.Error(), "private") || strings.Contains(startErr.Error(), "/host/path") || strings.Contains(startErr.Error(), "token=secret") {
				t.Fatalf("%s panic payload leaked: %v", boundary, startErr)
			}
			if boundary == "cleanup_manager" || boundary == "terminal_verifier" {
				if !controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID) || probe.closeCalls != 0 {
					t.Fatalf("%s uncertainty discarded ownership: retained %t close %d", boundary, controller.liveSessions.HasAnyL8Lease(target.Runtime.RuntimeID), probe.closeCalls)
				}
			}
		})
	}
}

func TestL8TypedNilLiveDependenciesFailBeforeProvider(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*firecrackerController)
	}{
		{name: "process_adapter", mutate: func(controller *firecrackerController) { controller.processAdapter = (*fakeProcessAdapter)(nil) }},
		{name: "boot_waiter", mutate: func(controller *firecrackerController) {
			controller.bootAcceptanceWaiter = (*l8PanickingBootWaiter)(nil)
		}},
		{name: "process_manager", mutate: func(controller *firecrackerController) { controller.liveProcessManager = (*l8PanicProcessManager)(nil) }},
		{name: "production_bridge", mutate: func(controller *firecrackerController) { controller.productionBridge = (*l8PanickingBridge)(nil) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe := &l8AuthorityLifecycleProbe{}
			controller, provider, target := l8LifecycleController(t, probe, &l8LifecycleProcessManager{}, "runtime-l8-typed-nil-"+test.name)
			test.mutate(&controller)
			if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target}); err == nil {
				t.Fatal("typed-nil Start() error = nil")
			}
			if provider.calls != 0 || probe.prepareCalls != 0 {
				t.Fatalf("typed nil crossed provider/render boundary: provider %d prepare %d", provider.calls, probe.prepareCalls)
			}
		})
	}
}

func TestL8ConcurrentRetainedCleanupRetryIsSerializedAndIdempotent(t *testing.T) {
	probe := &l8AuthorityLifecycleProbe{}
	manager := &l8PanicProcessManager{terminated: false}
	controller, _, target := l8LifecycleController(t, probe, &l8LifecycleProcessManager{}, "runtime-l8-concurrent-retry")
	controller.liveProcessManager = manager
	adapter := &fakeProcessAdapter{start: func(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
		return ProcessHandleMetadata{ID: "retry-pid", Source: "fake"}, errors.New("start failure")
	}}
	controller.processAdapter = adapter
	if _, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: validMicroVMConfig(), Target: target}); err == nil {
		t.Fatal("initial Start() error = nil")
	}
	manager.mu.Lock()
	manager.terminated = true
	manager.stopEntered = make(chan struct{})
	manager.stopRelease = make(chan struct{})
	manager.mu.Unlock()

	first := make(chan error, 1)
	go func() {
		_, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStop, Target: target})
		first <- err
	}()
	<-manager.stopEntered
	_, secondErr := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStop, Target: target})
	if secondErr == nil || !strings.Contains(secondErr.Error(), "already in progress") {
		t.Fatalf("concurrent retry error = %v", secondErr)
	}
	close(manager.stopRelease)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{Operation: microvm.OperationStop, Target: target}); err != nil {
		t.Fatal(err)
	}
	if manager.stopCallCount() != 1 || probe.closeCalls != 1 || adapter.startCalls != 1 {
		t.Fatalf("serialized/idempotent retry = stops %d closes %d starts %d", manager.stopCallCount(), probe.closeCalls, adapter.startCalls)
	}
}

type l8PanicProcessManager struct {
	mu           sync.Mutex
	cleanupPanic bool
	cleanupErr   error
	stopPanic    bool
	deletePanic  bool
	verifyPanic  bool
	terminated   bool
	cleanupCalls int
	stopCalls    int
	deleteCalls  int
	stopEntered  chan struct{}
	stopRelease  chan struct{}
}

type l8HandleTerminalManager struct {
	mu           sync.Mutex
	terminated   map[string]bool
	verifyPanic  bool
	verifyCalls  int
	cleanupCalls int
}

func (manager *l8HandleTerminalManager) CleanupLiveProcess(context.Context, LiveProcessRequest) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.cleanupCalls++
	return nil
}

func (*l8HandleTerminalManager) StopLiveProcess(context.Context, LiveProcessRequest) error {
	return nil
}

func (*l8HandleTerminalManager) DeleteLiveProcess(context.Context, LiveProcessRequest) error {
	return nil
}

func (manager *l8HandleTerminalManager) LiveProcessTerminated(request LiveProcessRequest) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.verifyCalls++
	if manager.verifyPanic {
		panic("private terminal verifier panic /host/path token=secret")
	}
	return manager.terminated != nil && manager.terminated[request.Handle.ID]
}

func (manager *l8HandleTerminalManager) verifyCallCount() int {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.verifyCalls
}

func (manager *l8HandleTerminalManager) cleanupCallCount() int {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.cleanupCalls
}

type l8SequenceProcessAdapter struct {
	mu      sync.Mutex
	calls   int
	handles []ProcessHandleMetadata
}

func (*l8SequenceProcessAdapter) PrepareStartCommand(_ context.Context, request ProcessStartCommandRequest) (ProcessCommandDescriptor, error) {
	return ProcessCommandDescriptorFromStartPlan(request.Plan)
}

func (adapter *l8SequenceProcessAdapter) StartProcess(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.calls++
	if adapter.calls > len(adapter.handles) {
		return ProcessHandleMetadata{}, errors.New("unexpected duplicate process start")
	}
	return adapter.handles[adapter.calls-1], nil
}

func (adapter *l8SequenceProcessAdapter) callCount() int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.calls
}

func (manager *l8PanicProcessManager) CleanupLiveProcess(context.Context, LiveProcessRequest) error {
	manager.mu.Lock()
	manager.cleanupCalls++
	panicNow := manager.cleanupPanic
	cleanupErr := manager.cleanupErr
	manager.mu.Unlock()
	if panicNow {
		panic("private cleanup panic /host/path token=secret")
	}
	return cleanupErr
}

func (manager *l8PanicProcessManager) StopLiveProcess(context.Context, LiveProcessRequest) error {
	manager.mu.Lock()
	manager.stopCalls++
	panicNow := manager.stopPanic
	entered, release := manager.stopEntered, manager.stopRelease
	manager.mu.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
	if panicNow {
		panic("private stop panic /host/path token=secret")
	}
	return nil
}

func (manager *l8PanicProcessManager) DeleteLiveProcess(context.Context, LiveProcessRequest) error {
	manager.mu.Lock()
	manager.deleteCalls++
	panicNow := manager.deletePanic
	manager.mu.Unlock()
	if panicNow {
		panic("private delete panic /host/path token=secret")
	}
	return nil
}

func (manager *l8PanicProcessManager) LiveProcessTerminated(LiveProcessRequest) bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.verifyPanic {
		panic("private verifier panic /host/path token=secret")
	}
	return manager.terminated
}

func (manager *l8PanicProcessManager) stopCallCount() int {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.stopCalls
}

type l8PanickingBootWaiter struct{}

func (*l8PanickingBootWaiter) WaitForBootAcceptance(context.Context, BootAcceptanceRequest) (BootAcceptanceResult, error) {
	panic("private waiter panic /host/path token=secret")
}

type l8PanickingBridge struct{ l5NoopGuestTransport }

func (*l8PanickingBridge) ActivateSession(context.Context, ProductionVsockSessionRequest) (GuestReadinessResult, string, error) {
	panic("private bridge panic /host/path token=secret")
}

func (*l8PanickingBridge) SessionActive(ProductionVsockSessionRequest, string) bool {
	panic("private bridge active panic /host/path token=secret")
}

func (*l8PanickingBridge) InvalidateSession(ProductionVsockSessionRequest, string) {
	panic("private bridge invalidate panic /host/path token=secret")
}

type l8ControlledBridge struct {
	l5NoopGuestTransport
	sessionActivePanic bool
	invalidatePanic    bool
}

func (*l8ControlledBridge) ActivateSession(context.Context, ProductionVsockSessionRequest) (GuestReadinessResult, string, error) {
	return NewGuestReadinessResult(sandboxruntime.RuntimeGuestReadinessStateReady, "vsock", []string{"protocol_v1", "runtime_bound", "probe_ok"}), "bridge-generation", nil
}

func (bridge *l8ControlledBridge) SessionActive(ProductionVsockSessionRequest, string) bool {
	if bridge.sessionActivePanic {
		panic("private bridge active panic /host/path token=secret")
	}
	return false
}

func (bridge *l8ControlledBridge) InvalidateSession(ProductionVsockSessionRequest, string) {
	if bridge.invalidatePanic {
		panic("private bridge invalidate panic /host/path token=secret")
	}
}
