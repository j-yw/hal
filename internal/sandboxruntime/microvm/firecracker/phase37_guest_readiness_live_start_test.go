package firecracker

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestPhase37LiveStartSkipsGuestReadinessWhenNoWaiterConfigured(t *testing.T) {
	deps := newPhase37GuestReadinessDeps()
	backend := phase37GuestReadinessBackend(t, deps, false)

	started, err := phase34CreateAndStart(t, backend, validMicroVMConfig(), "phase37-no-guest-waiter")
	if err != nil {
		t.Fatalf("Start() error = %v, want nil without configured guest readiness waiter", err)
	}

	if !reflect.DeepEqual(deps.events, []string{"start", "boot_acceptance"}) {
		t.Fatalf("live start events = %#v, want host start and acceptance only", deps.events)
	}
	if deps.guestReadinessCalls != 0 {
		t.Fatalf("guest readiness calls = %d, want none without configured waiter", deps.guestReadinessCalls)
	}
	assertPhase37AcceptedLiveStartWithoutGuestReadiness(t, started)
	assertFirecrackerRuntimeMetadataDoesNotClaimUnsupportedLiveCapabilities(t, started)
}

func TestPhase37LiveStartWaitsForGuestReadinessAfterHostAcceptance(t *testing.T) {
	deps := newPhase37GuestReadinessDeps()
	deps.readinessResult = NewGuestReadinessResult(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"VSOCK",
		[]string{
			"probe_ok",
			"ready",
			"/Users/alice/private/firecracker.sock",
			"exec_support",
			"copy_support",
			"network_proxy",
			"credential_proxy",
		},
	)
	backend := phase37GuestReadinessBackend(t, deps, true)

	created, controller := phase37CreateController(t, backend, validMicroVMConfig(), "phase37-ready")
	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Start() error = %v, want nil after host acceptance and guest readiness", err)
	}

	if !reflect.DeepEqual(deps.events, []string{"start", "boot_acceptance", "guest_readiness"}) {
		t.Fatalf("live start events = %#v, want guest readiness after host acceptance", deps.events)
	}
	if deps.guestReadinessRequest.Handle != deps.handle {
		t.Fatalf("guest readiness handle = %#v, want accepted host handle %#v", deps.guestReadinessRequest.Handle, deps.handle)
	}
	if deps.guestReadinessRequest.RuntimeID != created.Runtime.RuntimeID {
		t.Fatalf("guest readiness runtime ID = %q, want %q", deps.guestReadinessRequest.RuntimeID, created.Runtime.RuntimeID)
	}

	if started == nil || started.Runtime.Metadata == nil || started.Runtime.Metadata.GuestReadiness == nil {
		t.Fatalf("started metadata = %#v, want guest readiness metadata", started)
	}
	readiness := started.Runtime.Metadata.GuestReadiness
	if readiness.State != sandboxruntime.RuntimeGuestReadinessStateReady {
		t.Fatalf("GuestReadiness.State = %q, want ready", readiness.State)
	}
	if readiness.Transport != "vsock" {
		t.Fatalf("GuestReadiness.Transport = %q, want sanitized transport label", readiness.Transport)
	}
	if !reflect.DeepEqual(readiness.Labels, []string{"ready", "probe_ok"}) {
		t.Fatalf("GuestReadiness.Labels = %#v, want sanitized labels", readiness.Labels)
	}
	if deps.cleanupCalls != 0 {
		t.Fatalf("cleanup calls = %d, want none after successful guest readiness", deps.cleanupCalls)
	}
	assertFirecrackerRuntimeMetadataDoesNotClaimUnsupportedLiveCapabilities(t, started)
}

func TestPhase37LiveStartDoesNotWaitForGuestReadinessBeforeHostAcceptance(t *testing.T) {
	deps := newPhase37GuestReadinessDeps()
	deps.bootResult = BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: false,
	}
	backend := phase37GuestReadinessBackend(t, deps, true)

	started, err := phase34CreateAndStart(t, backend, validMicroVMConfig(), "phase37-host-not-accepted")

	if err == nil {
		t.Fatal("Start() error = nil, want host acceptance failure")
	}
	if started != nil {
		t.Fatalf("Start() target = %#v, want nil after host acceptance failure", started)
	}
	if !reflect.DeepEqual(deps.events, []string{"start", "boot_acceptance", "cleanup"}) {
		t.Fatalf("live start events = %#v, want cleanup before any guest readiness wait", deps.events)
	}
	if deps.guestReadinessCalls != 0 {
		t.Fatalf("guest readiness calls = %d, want none before host process and API socket acceptance", deps.guestReadinessCalls)
	}
	if !errors.Is(err, errBootAcceptanceAPISocketUnavailable) {
		t.Fatalf("errors.Is(Start() error, api socket unavailable) = false for %v", err)
	}
}

func TestPhase37GuestReadinessFailureCleansUpLiveStartedProcessAndRedactsError(t *testing.T) {
	readinessErr := errors.New("guest readiness failed path=/Users/alice/private/firecracker.sock endpoint=https://secret.example.test:8443/status token=ghp_secret pid=424242 OPENAI_API_KEY=sk-live-secret")
	deps := newPhase37GuestReadinessDeps()
	deps.readinessErr = readinessErr
	backend := phase37GuestReadinessBackend(t, deps, true)

	started, err := phase34CreateAndStart(t, backend, validMicroVMConfig(), "phase37-guest-readiness-failure")

	if err == nil {
		t.Fatal("Start() error = nil, want guest readiness failure")
	}
	if started != nil {
		t.Fatalf("Start() target = %#v, want nil after guest readiness failure", started)
	}
	if !reflect.DeepEqual(deps.events, []string{"start", "boot_acceptance", "guest_readiness", "cleanup"}) {
		t.Fatalf("live start events = %#v, want guest readiness failure followed by cleanup", deps.events)
	}
	if deps.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want cleanup after guest readiness failure", deps.cleanupCalls)
	}
	if len(deps.cleanupRequests) != 1 || deps.cleanupRequests[0].Handle != deps.handle {
		t.Fatalf("cleanup requests = %#v, want cleanup for live process handle %#v", deps.cleanupRequests, deps.handle)
	}
	if !errors.Is(err, readinessErr) {
		t.Fatalf("errors.Is(Start() error, readinessErr) = false for %v", err)
	}
	assertFirecrackerStartOperationError(t, err, microvm.ErrorCodeBackendOperationFailed, liveGuestReadinessOperation, "guestReadinessWaiter")
	assertFirecrackerErrorDoesNotLeak(t, err,
		"/Users/alice",
		"private",
		"firecracker.sock",
		"secret.example.test",
		"8443",
		"ghp_secret",
		"424242",
		"OPENAI_API_KEY",
		"sk-live-secret",
	)
}

func TestPhase37GuestReadinessFailureCleanupIgnoresCanceledStartContext(t *testing.T) {
	deps := newPhase37GuestReadinessDeps()
	deps.readinessErr = context.Canceled
	ctx, cancel := context.WithCancel(context.Background())
	deps.guestReadinessHook = cancel
	backend := phase37GuestReadinessBackend(t, deps, true)

	created, controller := phase37CreateController(t, backend, validMicroVMConfig(), "phase37-guest-readiness-canceled")
	started, err := controller.Start(ctx, microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    validMicroVMConfig(),
		Target:    *created,
	})

	if err == nil {
		t.Fatal("Start() error = nil, want guest readiness context failure")
	}
	if started != nil {
		t.Fatalf("Start() target = %#v, want nil after guest readiness context failure", started)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("errors.Is(Start() error, context.Canceled) = false for %v", err)
	}
	if !reflect.DeepEqual(deps.events, []string{"start", "boot_acceptance", "guest_readiness", "cleanup"}) {
		t.Fatalf("live start events = %#v, want guest readiness context failure followed by cleanup", deps.events)
	}
	if deps.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want cleanup after canceled readiness", deps.cleanupCalls)
	}
	if deps.cleanupContextErr != nil {
		t.Fatalf("cleanup context error = %v, want uncanceled cleanup context", deps.cleanupContextErr)
	}
}

func phase37GuestReadinessBackend(t *testing.T, deps *phase37GuestReadinessDeps, includeGuestWaiter bool) *Backend {
	t.Helper()

	options := BackendOptions{
		BaseStateDir:         filepath.Join(t.TempDir(), "firecracker-state"),
		ProcessAdapter:       ProcessLaunchAdapter{Starter: deps},
		BootAcceptanceWaiter: deps,
		LiveProcessManager:   deps,
		LiveStart:            true,
	}
	if includeGuestWaiter {
		options.GuestReadinessWaiter = deps
	}
	return NewBackend(options)
}

func phase37CreateController(t *testing.T, backend *Backend, config microvm.Config, name string) (*sandboxruntime.Target, microvm.Controller) {
	t.Helper()

	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    config,
		Name:      name,
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
	return created, controller
}

func assertPhase37AcceptedLiveStartWithoutGuestReadiness(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()

	if target == nil || target.Runtime.Metadata == nil {
		t.Fatalf("target = %#v, want live-start Firecracker metadata", target)
	}
	launch := target.Runtime.Metadata.ProcessLaunch
	if launch == nil || launch.State != string(ProcessLaunchStateAccepted) {
		t.Fatalf("ProcessLaunch = %#v, want accepted host process metadata", launch)
	}
	if target.Runtime.Metadata.GuestReadiness != nil {
		t.Fatalf("GuestReadiness = %#v, want absent when no waiter is configured", target.Runtime.Metadata.GuestReadiness)
	}
}

type phase37GuestReadinessDeps struct {
	handle ProcessHandleMetadata

	bootResult         BootAcceptanceResult
	bootErr            error
	readinessResult    GuestReadinessResult
	readinessErr       error
	guestReadinessHook func()
	cleanupErr         error

	events              []string
	startCalls          int
	bootAcceptanceCalls int
	guestReadinessCalls int
	cleanupCalls        int
	stopCalls           int
	deleteCalls         int

	guestReadinessRequest GuestReadinessRequest
	cleanupRequests       []LiveProcessRequest
	cleanupContextErr     error
}

var _ ProcessStarter = (*phase37GuestReadinessDeps)(nil)
var _ BootAcceptanceWaiter = (*phase37GuestReadinessDeps)(nil)
var _ GuestReadinessWaiter = (*phase37GuestReadinessDeps)(nil)
var _ LiveProcessManager = (*phase37GuestReadinessDeps)(nil)

func newPhase37GuestReadinessDeps() *phase37GuestReadinessDeps {
	return &phase37GuestReadinessDeps{
		handle: ProcessHandleMetadata{
			ID:     "phase37-handle",
			Source: "phase37-test",
		},
		bootResult: BootAcceptanceResult{
			ProcessAccepted:    true,
			APISocketAvailable: true,
		},
		readinessResult: NewGuestReadinessResult(
			sandboxruntime.RuntimeGuestReadinessStateReady,
			"vsock",
			[]string{"probe_ok"},
		),
	}
}

func (deps *phase37GuestReadinessDeps) StartProcess(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
	deps.startCalls++
	deps.events = append(deps.events, "start")
	return deps.handle, nil
}

func (deps *phase37GuestReadinessDeps) WaitForBootAcceptance(context.Context, BootAcceptanceRequest) (BootAcceptanceResult, error) {
	deps.bootAcceptanceCalls++
	deps.events = append(deps.events, "boot_acceptance")
	return deps.bootResult, deps.bootErr
}

func (deps *phase37GuestReadinessDeps) WaitForGuestReadiness(_ context.Context, req GuestReadinessRequest) (GuestReadinessResult, error) {
	deps.guestReadinessCalls++
	deps.events = append(deps.events, "guest_readiness")
	deps.guestReadinessRequest = req
	if deps.guestReadinessHook != nil {
		deps.guestReadinessHook()
	}
	return deps.readinessResult, deps.readinessErr
}

func (deps *phase37GuestReadinessDeps) CleanupLiveProcess(ctx context.Context, req LiveProcessRequest) error {
	deps.cleanupCalls++
	deps.events = append(deps.events, "cleanup")
	deps.cleanupRequests = append(deps.cleanupRequests, req)
	deps.cleanupContextErr = ctx.Err()
	return deps.cleanupErr
}

func (deps *phase37GuestReadinessDeps) StopLiveProcess(context.Context, LiveProcessRequest) error {
	deps.stopCalls++
	return nil
}

func (deps *phase37GuestReadinessDeps) DeleteLiveProcess(context.Context, LiveProcessRequest) error {
	deps.deleteCalls++
	return nil
}

func TestPhase37LiveStartRejectsNonReadyGuestReadinessResult(t *testing.T) {
	deps := newPhase37GuestReadinessDeps()
	deps.readinessResult = NewGuestReadinessResult(
		sandboxruntime.RuntimeGuestReadinessStateWaiting,
		"vsock",
		[]string{"still_waiting"},
	)
	backend := phase37GuestReadinessBackend(t, deps, true)

	started, err := phase34CreateAndStart(t, backend, validMicroVMConfig(), "phase37-guest-not-ready")

	if err == nil {
		t.Fatal("Start() error = nil, want failure when waiter returns without ready state")
	}
	if started != nil {
		t.Fatalf("Start() target = %#v, want nil after non-ready guest readiness result", started)
	}
	if !errors.Is(err, errGuestReadinessNotReady) {
		t.Fatalf("errors.Is(Start() error, errGuestReadinessNotReady) = false for %v", err)
	}
	if deps.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want cleanup after non-ready guest readiness result", deps.cleanupCalls)
	}
	assertFirecrackerStartOperationError(t, err, microvm.ErrorCodeBackendOperationFailed, liveGuestReadinessOperation, "guestReadinessState")
	if strings.Contains(err.Error(), "still_waiting") {
		t.Fatalf("non-ready error leaked waiter labels in %q", err.Error())
	}
}
