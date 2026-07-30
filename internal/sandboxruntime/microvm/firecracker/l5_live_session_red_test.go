package firecracker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestL5GuestTransportSessionInvalidationDistinguishesCallerCancellation(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		context.Canceled,
		context.DeadlineExceeded,
		errors.Join(errors.New("wrapped"), context.Canceled),
		errors.Join(errors.New("wrapped"), context.DeadlineExceeded),
	} {
		if shouldInvalidateGuestTransportSession(err) {
			t.Fatalf("shouldInvalidateGuestTransportSession(%v) = true, want false", err)
		}
	}
	if !shouldInvalidateGuestTransportSession(errors.New("transport failed")) {
		t.Fatal("shouldInvalidateGuestTransportSession(transport failure) = false, want true")
	}
}

func TestL5CallerCarriedReadinessCannotAuthorizeGuestTransport(t *testing.T) {
	controller := firecrackerController{
		liveStart:       true,
		guestTransport:  l5NoopGuestTransport{},
		productionVsock: true,
	}
	target := sandboxruntime.Target{
		ID: "fc-manufactured",
		Runtime: sandboxruntime.RuntimeState{
			Driver:    sandboxruntime.DriverMicroVM,
			RuntimeID: "fc-manufactured",
			Metadata: &sandboxruntime.RuntimeMetadata{
				GuestReadiness: sandboxruntime.NewRuntimeGuestReadinessMetadata(
					sandboxruntime.RuntimeGuestReadinessStateReady,
					"vsock",
					[]string{"protocol_v1", "runtime_bound", "probe_ok"},
				),
			},
		},
	}
	if controller.canDelegateGuestTransport(target) {
		t.Fatal("caller-carried ready metadata authorized guest transport without host-owned live-session proof")
	}
}

func TestL5LiveSessionProofIsRuntimeAndGenerationScoped(t *testing.T) {
	registry := newLiveSessionRegistry()
	proof := liveSessionProof{
		RuntimeID:         "fc-runtime-a",
		ProcessGeneration: "fc-handle-1",
		BridgeGeneration:  "bridge-1",
	}
	registry.Activate(proof)
	if !registry.Authorize(proof) {
		t.Fatal("exact active live-session proof was not authorized")
	}
	for _, stale := range []liveSessionProof{
		{RuntimeID: "fc-runtime-b", ProcessGeneration: proof.ProcessGeneration, BridgeGeneration: proof.BridgeGeneration},
		{RuntimeID: proof.RuntimeID, ProcessGeneration: "fc-handle-2", BridgeGeneration: proof.BridgeGeneration},
		{RuntimeID: proof.RuntimeID, ProcessGeneration: proof.ProcessGeneration, BridgeGeneration: "bridge-2"},
	} {
		if registry.Authorize(stale) {
			t.Fatalf("stale or cross-runtime proof authorized: %#v", stale)
		}
	}
	registry.Invalidate(proof)
	if registry.Authorize(proof) {
		t.Fatal("invalidated proof remained authorized")
	}
}

func TestL5ProductionVsockRejectsCallerGuestComposition(t *testing.T) {
	controller := firecrackerController{
		liveStart:       true,
		productionVsock: true,
		guestTransport:  l5NoopGuestTransport{},
	}
	err := controller.validateLiveBootContract()
	if err == nil {
		t.Fatal("validateLiveBootContract() error = nil, want ambiguous guest composition rejection")
	}
}

func TestL5StartFailureKeepsActiveProductionVsockSession(t *testing.T) {
	proof := liveSessionProof{
		RuntimeID:         "fc-runtime-a",
		ProcessGeneration: "fc-handle-1",
		ProcessSource:     "firecrackerhost",
		BridgeGeneration:  "bridge-1",
	}
	registry := newLiveSessionRegistry()
	registry.Activate(proof)
	bridge := &l5RestartRetentionBridge{active: true}
	controller := firecrackerController{
		productionBridge: bridge,
		liveSessions:     registry,
	}

	_, err := controller.startLiveProcess(context.Background(), ProcessCommandDescriptor{}, BackendConfig{RuntimeID: proof.RuntimeID})
	if err == nil {
		t.Fatal("startLiveProcess() error = nil, want start failure")
	}
	if bridge.invalidations != 0 {
		t.Fatalf("bridge invalidations = %d, want no invalidation after a failed replacement start", bridge.invalidations)
	}
	if !registry.Authorize(proof) {
		t.Fatal("failed replacement start invalidated the active live-session proof")
	}
}

func TestL5LifecycleRejectionPreservesActiveProductionVsockSession(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(firecrackerController, sandboxruntime.Target) error
	}{
		{
			name: "stop",
			run: func(controller firecrackerController, target sandboxruntime.Target) error {
				_, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
					Operation: microvm.OperationStop,
					Target:    target,
				})
				return err
			},
		},
		{
			name: "delete",
			run: func(controller firecrackerController, target sandboxruntime.Target) error {
				return controller.Delete(context.Background(), microvm.ControllerLifecycleRequest{
					Operation: microvm.OperationDelete,
					Target:    target,
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := liveSessionProof{
				RuntimeID:         "fc-runtime-a",
				ProcessGeneration: "fc-handle-1",
				ProcessSource:     "firecrackerhost",
				BridgeGeneration:  "bridge-1",
			}
			registry := newLiveSessionRegistry()
			registry.Activate(proof)
			bridge := &l5RestartRetentionBridge{active: true}
			managerErr := errors.New("lifecycle request rejected")
			controller := firecrackerController{
				baseStateDir:       firecrackerShortSocketTestRoot(t),
				liveStart:          true,
				liveProcessManager: l5LifecycleRejectionManager{err: managerErr},
				productionVsock:    true,
				productionBridge:   bridge,
				liveSessions:       registry,
			}
			target := l5LiveSessionTarget(proof)
			if !controller.canDelegateGuestTransport(target) {
				t.Fatal("precondition: active guest session was not authorized")
			}

			err := test.run(controller, target)
			if !errors.Is(err, managerErr) {
				t.Fatalf("%s error = %v, want lifecycle manager rejection", test.name, err)
			}
			if bridge.invalidations != 0 {
				t.Fatalf("bridge invalidations = %d, want none after failed %s", bridge.invalidations, test.name)
			}
			if !registry.Authorize(proof) {
				t.Fatalf("failed %s invalidated the active live-session proof", test.name)
			}
			if !controller.canDelegateGuestTransport(target) {
				t.Fatalf("failed %s left the active guest session unavailable", test.name)
			}
		})
	}
}

func TestL5ActiveRestartDoesNotRewriteLiveBootFiles(t *testing.T) {
	stateRoot := firecrackerShortSocketTestRoot(t)
	config := phase34LiveBootFakeConfig(t)
	bridge := &l5RestartRetentionBridge{active: true}
	starter := &phase34RenderLaunchStarter{}
	backend := NewBackend(BackendOptions{
		BaseStateDir:         stateRoot,
		ProcessAdapter:       ProcessLaunchAdapter{Starter: starter},
		BootAcceptanceWaiter: fakeLiveBootSafetyHooks{},
		LiveProcessManager:   fakeLiveBootSafetyHooks{},
		LiveStart:            true,
		ProductionVsock:      true,
		ProductionBridge:     bridge,
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    config,
		Name:      "l5-active-restart-files",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	paths := phase34ExpectedLiveBootConfig(t, config, stateRoot, created.Runtime.RuntimeID).Paths
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(state directory) error = %v", err)
	}
	want := map[string][]byte{
		paths.ConfigPath:  []byte("active-config"),
		paths.LogPath:     []byte("active-log"),
		paths.MetricsPath: []byte("active-metrics"),
	}
	for path, contents := range want {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("WriteFile(active boot file) error = %v", err)
		}
	}

	proof := liveSessionProof{
		RuntimeID:         created.Runtime.RuntimeID,
		ProcessGeneration: "fc-handle-1",
		ProcessSource:     "firecrackerhost",
		BridgeGeneration:  "bridge-1",
	}
	backend.liveSessions.Activate(proof)
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    l5LiveSessionTarget(proof),
	})
	if err != nil {
		t.Fatalf("Controller() error = %v", err)
	}

	_, err = controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    l5LiveSessionTarget(proof),
	})
	if err == nil {
		t.Fatal("Start() error = nil, want active-session rejection")
	}
	if starter.startCalls != 0 {
		t.Fatalf("starter calls = %d, want no second launch", starter.startCalls)
	}
	for path, contents := range want {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(active boot file) error = %v", err)
		}
		if !bytes.Equal(got, contents) {
			t.Fatalf("active boot file changed before rejected restart")
		}
	}
}

func TestL5ConcurrentStartsCannotLaunchSameRuntimeTwice(t *testing.T) {
	stateRoot := firecrackerShortSocketTestRoot(t)
	config := phase34LiveBootFakeConfig(t)
	starter := &l5ConcurrentStartStarter{entered: make(chan struct{}), release: make(chan struct{})}
	backend := NewBackend(BackendOptions{
		BaseStateDir:         stateRoot,
		ProcessAdapter:       ProcessLaunchAdapter{Starter: starter},
		BootAcceptanceWaiter: fakeLiveBootSafetyHooks{},
		LiveProcessManager:   fakeLiveBootSafetyHooks{},
		LiveStart:            true,
		ProductionVsock:      true,
		ProductionBridge:     l5ConcurrentStartBridge{},
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{Operation: microvm.OperationCreate, Config: config, Name: "l5-concurrent-start"})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{Operation: microvm.OperationStart, Config: config, Target: *created})
	if err != nil {
		t.Fatalf("Controller() error = %v", err)
	}
	request := microvm.ControllerLifecycleRequest{Operation: microvm.OperationStart, Config: config, Target: *created}
	first := make(chan error, 1)
	go func() { _, err := controller.Start(context.Background(), request); first <- err }()
	<-starter.entered
	if _, err := controller.Start(context.Background(), request); err == nil {
		t.Fatal("second Start() error = nil, want in-progress start rejection")
	}
	if calls := starter.Calls(); calls != 1 {
		t.Fatalf("launch calls = %d, want 1", calls)
	}
	close(starter.release)
	if err := <-first; err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
}

func l5LiveSessionTarget(proof liveSessionProof) sandboxruntime.Target {
	return sandboxruntime.Target{
		ID: proof.RuntimeID,
		Runtime: sandboxruntime.RuntimeState{
			Driver:    sandboxruntime.DriverMicroVM,
			RuntimeID: proof.RuntimeID,
			Metadata: &sandboxruntime.RuntimeMetadata{
				ProcessLaunch: NewProcessLaunchMetadata(ProcessLaunchStateAccepted, ProcessHandleMetadata{
					ID:     proof.ProcessGeneration,
					Source: proof.ProcessSource,
				}).RuntimeMetadata(),
				GuestReadiness: sandboxruntime.NewRuntimeGuestReadinessMetadata(
					sandboxruntime.RuntimeGuestReadinessStateReady,
					"vsock",
					[]string{"protocol_v1", "runtime_bound", "probe_ok"},
				),
			},
		},
	}
}

type l5NoopGuestTransport struct{}

func (l5NoopGuestTransport) Exec(context.Context, GuestExecRequest) (*sandboxruntime.ExecResult, error) {
	return &sandboxruntime.ExecResult{}, nil
}
func (l5NoopGuestTransport) CopyIn(context.Context, GuestCopyRequest) error  { return nil }
func (l5NoopGuestTransport) CopyOut(context.Context, GuestCopyRequest) error { return nil }

type l5ConcurrentStartStarter struct {
	mu      sync.Mutex
	calls   int
	entered chan struct{}
	release chan struct{}
}

func (starter *l5ConcurrentStartStarter) StartProcess(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
	starter.mu.Lock()
	starter.calls++
	calls := starter.calls
	starter.mu.Unlock()
	if calls != 1 {
		return ProcessHandleMetadata{}, errors.New("duplicate process launch")
	}
	close(starter.entered)
	<-starter.release
	return ProcessHandleMetadata{ID: "fc-handle-1", Source: "fake-starter"}, nil
}

func (starter *l5ConcurrentStartStarter) Calls() int {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	return starter.calls
}

type l5ConcurrentStartBridge struct{ l5NoopGuestTransport }

func (l5ConcurrentStartBridge) ActivateSession(context.Context, ProductionVsockSessionRequest) (GuestReadinessResult, string, error) {
	return NewGuestReadinessResult(sandboxruntime.RuntimeGuestReadinessStateReady, "vsock", []string{"protocol_v1", "runtime_bound", "probe_ok"}), "bridge-1", nil
}

func (l5ConcurrentStartBridge) SessionActive(ProductionVsockSessionRequest, string) bool {
	return false
}
func (l5ConcurrentStartBridge) InvalidateSession(ProductionVsockSessionRequest, string) {}

type l5RestartRetentionBridge struct {
	l5NoopGuestTransport
	active        bool
	invalidations int
}

func (*l5RestartRetentionBridge) ActivateSession(context.Context, ProductionVsockSessionRequest) (GuestReadinessResult, string, error) {
	return GuestReadinessResult{}, "", nil
}

func (bridge *l5RestartRetentionBridge) SessionActive(ProductionVsockSessionRequest, string) bool {
	return bridge.active
}

func (bridge *l5RestartRetentionBridge) InvalidateSession(ProductionVsockSessionRequest, string) {
	bridge.invalidations++
	bridge.active = false
}

type l5LifecycleRejectionManager struct {
	err error
}

func (manager l5LifecycleRejectionManager) CleanupLiveProcess(context.Context, LiveProcessRequest) error {
	return manager.err
}

func (manager l5LifecycleRejectionManager) StopLiveProcess(context.Context, LiveProcessRequest) error {
	return manager.err
}

func (manager l5LifecycleRejectionManager) DeleteLiveProcess(context.Context, LiveProcessRequest) error {
	return manager.err
}
