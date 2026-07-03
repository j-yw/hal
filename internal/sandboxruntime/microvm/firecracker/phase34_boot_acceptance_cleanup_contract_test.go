package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

var (
	errPhase34ProcessNotAccepted   = errors.New("host process was not accepted")
	errPhase34APISocketUnavailable = errors.New("api socket unavailable at /Users/alice/private/firecracker.sock token=ghp_secret")
	errPhase34BootWaiterFailed     = errors.New("boot waiter failed at /Users/alice/private/firecracker.sock endpoint=https://secret.example.test:8443/api token=ghp_secret")
)

func TestPhase34LiveBootWaitsForHostSideAcceptanceBeforeAcceptedMetadata(t *testing.T) {
	deps := phase34NewBootAcceptanceCleanupProbe(phase34BootAcceptanceOutcome{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	})
	stateRoot := filepath.Join(t.TempDir(), "firecracker-state")
	backend := phase34LiveBootAcceptanceBackend(stateRoot, deps)

	started, err := phase34CreateAndStart(t, backend, phase34LiveBootFakeConfig(t), "phase34-host-acceptance")
	if err != nil {
		t.Fatalf("Start() error = %v, want nil after host-side process and API socket acceptance", err)
	}

	if deps.startCalls != 1 {
		t.Fatalf("starter calls = %d, want one live-started process", deps.startCalls)
	}
	if deps.waitCalls != 1 {
		t.Fatalf("waiter calls = %d, want one host-side boot acceptance wait after process start", deps.waitCalls)
	}
	if len(deps.waitRequests) != 1 {
		t.Fatalf("wait requests = %#v, want one request", deps.waitRequests)
	}
	waitReq := deps.waitRequests[0]
	if waitReq.Handle != deps.handle {
		t.Fatalf("wait handle = %#v, want sanitized live process handle %#v", waitReq.Handle, deps.handle)
	}
	if waitReq.APISocket.Role != OperationPathRoleAPISocket || strings.TrimSpace(waitReq.APISocket.Path) == "" {
		t.Fatalf("wait API socket = %#v, want API socket path role for host-side availability check", waitReq.APISocket)
	}

	phase34AssertHostSideAcceptedMetadata(t, started)
	phase34AssertPublicTargetOmitsUnsafeBootAcceptanceDetails(t, started,
		stateRoot,
		"/Users/alice",
		"private",
		"firecracker.sock",
		"firecracker-config.json",
		"firecracker.log",
		"firecracker.metrics",
		"vmlinux",
		"rootfs.ext4",
		"initrd.img",
		"ghp_secret",
		"OPENAI_API_KEY",
		"secret.example.test",
		"8443",
	)
}

func TestPhase34BootAcceptanceFailuresCleanupLiveStartedProcessState(t *testing.T) {
	tests := []struct {
		name    string
		outcome phase34BootAcceptanceOutcome
		wantErr error
	}{
		{
			name: "process not accepted",
			outcome: phase34BootAcceptanceOutcome{
				ProcessAccepted:    false,
				APISocketAvailable: true,
			},
			wantErr: errPhase34ProcessNotAccepted,
		},
		{
			name: "API socket unavailable",
			outcome: phase34BootAcceptanceOutcome{
				ProcessAccepted:    true,
				APISocketAvailable: false,
			},
			wantErr: errPhase34APISocketUnavailable,
		},
		{
			name: "timeout",
			outcome: phase34BootAcceptanceOutcome{
				Timeout: true,
			},
			wantErr: context.DeadlineExceeded,
		},
		{
			name: "waiter error",
			outcome: phase34BootAcceptanceOutcome{
				Err: errPhase34BootWaiterFailed,
			},
			wantErr: errPhase34BootWaiterFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := phase34NewBootAcceptanceCleanupProbe(tt.outcome)
			backend := phase34LiveBootAcceptanceBackend(filepath.Join(t.TempDir(), "firecracker-state"), deps)

			started, err := phase34CreateAndStart(t, backend, phase34LiveBootFakeConfig(t), "phase34-acceptance-"+strings.ReplaceAll(tt.name, " ", "-"))

			if err == nil {
				t.Fatal("Start() error = nil, want boot acceptance failure")
			}
			if started != nil {
				t.Fatalf("Start() target = %#v, want nil after boot acceptance failure", started)
			}
			if deps.startCalls != 1 {
				t.Fatalf("starter calls = %d, want one live-started process before acceptance failure", deps.startCalls)
			}
			if deps.waitCalls != 1 {
				t.Fatalf("waiter calls = %d, want one host-side boot acceptance attempt", deps.waitCalls)
			}
			if deps.cleanupCalls != 1 {
				t.Fatalf("cleanup calls = %d, want cleanup for live-started process after acceptance failure", deps.cleanupCalls)
			}
			if len(deps.cleanupRequests) != 1 || deps.cleanupRequests[0].Handle != deps.handle {
				t.Fatalf("cleanup requests = %#v, want cleanup for live process handle %#v", deps.cleanupRequests, deps.handle)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("errors.Is(Start() error, %v) = false for %v", tt.wantErr, err)
			}
			assertFirecrackerErrorDoesNotLeak(t, err,
				"/Users/alice",
				"private",
				"firecracker.sock",
				"secret.example.test",
				"8443",
				"ghp_secret",
				"OPENAI_API_KEY",
			)
		})
	}
}

func TestPhase34StopDeleteUseLiveProcessManagerOnlyForLiveStartedTargets(t *testing.T) {
	t.Run("live-started target", func(t *testing.T) {
		deps := phase34NewBootAcceptanceCleanupProbe(phase34BootAcceptanceOutcome{
			ProcessAccepted:    true,
			APISocketAvailable: true,
		})
		stateRoot := filepath.Join(t.TempDir(), "firecracker-state")
		backend := phase34LiveBootAcceptanceBackend(stateRoot, deps)
		started, controller, err := phase34CreateStartAndController(t, backend, phase34LiveBootFakeConfig(t), "phase34-live-cleanup")
		if err != nil {
			t.Fatalf("Start() error = %v, want nil for accepted live-started target", err)
		}

		stopped, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStop,
			Config:    phase34LiveBootFakeConfig(t),
			Target:    *started,
		})
		if err != nil {
			t.Fatalf("Stop() error = %v, want nil after live process manager cleanup", err)
		}
		if deps.stopCalls != 1 {
			t.Fatalf("stop manager calls = %d, want one live process stop for live-started target", deps.stopCalls)
		}
		if len(deps.stopRequests) != 1 || deps.stopRequests[0].Handle != deps.handle {
			t.Fatalf("stop requests = %#v, want live process handle %#v", deps.stopRequests, deps.handle)
		}
		phase34AssertCleanupRequestScopedToStateRoot(t, deps.stopRequests[0], stateRoot)

		if err := controller.Delete(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationDelete,
			Config:    phase34LiveBootFakeConfig(t),
			Target:    *stopped,
		}); err != nil {
			t.Fatalf("Delete() error = %v, want nil after live process manager cleanup", err)
		}
		if deps.deleteCalls != 1 {
			t.Fatalf("delete manager calls = %d, want one live process delete for live-started target", deps.deleteCalls)
		}
		if len(deps.deleteRequests) != 1 || deps.deleteRequests[0].Handle != deps.handle {
			t.Fatalf("delete requests = %#v, want live process handle %#v", deps.deleteRequests, deps.handle)
		}
		phase34AssertCleanupRequestScopedToStateRoot(t, deps.deleteRequests[0], stateRoot)
	})

	t.Run("planning-only target", func(t *testing.T) {
		deps := phase34NewBootAcceptanceCleanupProbe(phase34BootAcceptanceOutcome{
			ProcessAccepted:    true,
			APISocketAvailable: true,
		})
		backend := NewBackend(BackendOptions{
			BaseStateDir:         filepath.Join(t.TempDir(), "firecracker-state"),
			ProcessAdapter:       ProcessLaunchAdapter{Starter: deps},
			BootAcceptanceWaiter: deps,
			LiveProcessManager:   deps,
		})
		started, controller, err := phase34CreateStartAndController(t, backend, validMicroVMConfig(), "phase34-planning-cleanup")
		if err != nil {
			t.Fatalf("Start() error = %v, want planning-only start", err)
		}

		stopped, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStop,
			Config:    validMicroVMConfig(),
			Target:    *started,
		})
		if err != nil {
			t.Fatalf("Stop() planning-only error = %v, want nil", err)
		}
		if err := controller.Delete(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationDelete,
			Config:    validMicroVMConfig(),
			Target:    *stopped,
		}); err != nil {
			t.Fatalf("Delete() planning-only error = %v, want nil", err)
		}
		if deps.startCalls != 0 || deps.waitCalls != 0 || deps.cleanupCalls != 0 || deps.stopCalls != 0 || deps.deleteCalls != 0 {
			t.Fatalf("live process calls for planning-only target = start:%d wait:%d cleanup:%d stop:%d delete:%d, want none",
				deps.startCalls, deps.waitCalls, deps.cleanupCalls, deps.stopCalls, deps.deleteCalls)
		}
	})
}

func TestPhase34LiveProcessManagerFailuresAreSanitized(t *testing.T) {
	unsafeManagerErr := errors.New("manager failed state=/Users/alice/private/firecracker-state/firecracker.sock endpoint=https://secret.example.test:8443/api token=ghp_secret pid=424242 OPENAI_API_KEY=sk-live-secret")

	t.Run("acceptance cleanup", func(t *testing.T) {
		deps := phase34NewBootAcceptanceCleanupProbe(phase34BootAcceptanceOutcome{
			Err: errPhase34BootWaiterFailed,
		})
		deps.cleanupErr = unsafeManagerErr
		backend := phase34LiveBootAcceptanceBackend(filepath.Join(t.TempDir(), "firecracker-state"), deps)

		started, err := phase34CreateAndStart(t, backend, phase34LiveBootFakeConfig(t), "phase34-cleanup-failure")

		if err == nil {
			t.Fatal("Start() error = nil, want boot acceptance and cleanup failure")
		}
		if started != nil {
			t.Fatalf("Start() target = %#v, want nil after cleanup failure", started)
		}
		if deps.cleanupCalls != 1 {
			t.Fatalf("cleanup calls = %d, want one cleanup attempt", deps.cleanupCalls)
		}
		if !errors.Is(err, unsafeManagerErr) {
			t.Fatalf("errors.Is(Start() error, managerErr) = false for %v", err)
		}
		phase34AssertLiveProcessManagerErrorRedacted(t, err)
	})

	t.Run("stop", func(t *testing.T) {
		deps := phase34NewBootAcceptanceCleanupProbe(phase34BootAcceptanceOutcome{
			ProcessAccepted:    true,
			APISocketAvailable: true,
		})
		deps.stopErr = unsafeManagerErr
		backend := phase34LiveBootAcceptanceBackend(filepath.Join(t.TempDir(), "firecracker-state"), deps)
		started, controller, err := phase34CreateStartAndController(t, backend, phase34LiveBootFakeConfig(t), "phase34-stop-failure")
		if err != nil {
			t.Fatalf("Start() error = %v, want nil before stop failure", err)
		}

		stopped, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStop,
			Config:    phase34LiveBootFakeConfig(t),
			Target:    *started,
		})

		if err == nil {
			t.Fatal("Stop() error = nil, want live process manager failure")
		}
		if stopped != nil {
			t.Fatalf("Stop() target = %#v, want nil after manager failure", stopped)
		}
		if deps.stopCalls != 1 {
			t.Fatalf("stop calls = %d, want one stop attempt", deps.stopCalls)
		}
		if !errors.Is(err, unsafeManagerErr) {
			t.Fatalf("errors.Is(Stop() error, managerErr) = false for %v", err)
		}
		phase34AssertLiveProcessManagerErrorRedacted(t, err)
	})

	t.Run("delete", func(t *testing.T) {
		deps := phase34NewBootAcceptanceCleanupProbe(phase34BootAcceptanceOutcome{
			ProcessAccepted:    true,
			APISocketAvailable: true,
		})
		backend := phase34LiveBootAcceptanceBackend(filepath.Join(t.TempDir(), "firecracker-state"), deps)
		started, controller, err := phase34CreateStartAndController(t, backend, phase34LiveBootFakeConfig(t), "phase34-delete-failure")
		if err != nil {
			t.Fatalf("Start() error = %v, want nil before delete failure", err)
		}
		stopped, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStop,
			Config:    phase34LiveBootFakeConfig(t),
			Target:    *started,
		})
		if err != nil {
			t.Fatalf("Stop() error = %v, want nil before delete failure", err)
		}
		deps.deleteErr = unsafeManagerErr

		err = controller.Delete(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationDelete,
			Config:    phase34LiveBootFakeConfig(t),
			Target:    *stopped,
		})

		if err == nil {
			t.Fatal("Delete() error = nil, want live process manager failure")
		}
		if deps.deleteCalls != 1 {
			t.Fatalf("delete calls = %d, want one delete attempt", deps.deleteCalls)
		}
		if !errors.Is(err, unsafeManagerErr) {
			t.Fatalf("errors.Is(Delete() error, managerErr) = false for %v", err)
		}
		phase34AssertLiveProcessManagerErrorRedacted(t, err)
	})
}

func TestPhase34BootAcceptanceCleanupKeepsCallerOwnedPathsOutsideStateDir(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "firecracker-state")
	callerOwnedRoot := filepath.Join(root, "caller-owned")
	callerOwnedPaths := []string{
		filepath.Join(callerOwnedRoot, "bin", "firecracker"),
		filepath.Join(callerOwnedRoot, "images", "vmlinux"),
		filepath.Join(callerOwnedRoot, "images", "rootfs.ext4"),
		filepath.Join(callerOwnedRoot, "images", "initrd.img"),
	}
	phase34WriteCallerOwnedFiles(t, callerOwnedPaths)

	config := validMicroVMConfig()
	config.HypervisorPath = callerOwnedPaths[0]
	config.KernelImagePath = callerOwnedPaths[1]
	config.RootfsPath = callerOwnedPaths[2]
	config.InitrdPath = callerOwnedPaths[3]
	deps := phase34NewBootAcceptanceCleanupProbe(phase34BootAcceptanceOutcome{
		Err: errPhase34BootWaiterFailed,
	})
	backend := phase34LiveBootAcceptanceBackend(stateRoot, deps)

	started, err := phase34CreateAndStart(t, backend, config, "phase34-cleanup-scope")

	if err == nil {
		t.Fatal("Start() error = nil, want boot acceptance failure that triggers cleanup")
	}
	if started != nil {
		t.Fatalf("Start() target = %#v, want nil after cleanup-triggering acceptance failure", started)
	}
	if deps.cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want cleanup for live-started process", deps.cleanupCalls)
	}
	if len(deps.cleanupRequests) != 1 {
		t.Fatalf("cleanup requests = %#v, want one cleanup request", deps.cleanupRequests)
	}
	phase34AssertCleanupRequestScopedToStateRoot(t, deps.cleanupRequests[0], stateRoot)
	phase34AssertCallerOwnedFilesRemain(t, callerOwnedPaths)
}

type phase34BootAcceptanceOutcome struct {
	ProcessAccepted    bool
	APISocketAvailable bool
	Timeout            bool
	Err                error
}

type phase34BootAcceptanceCleanupProbe struct {
	handle  ProcessHandleMetadata
	outcome phase34BootAcceptanceOutcome

	cleanupErr error
	stopErr    error
	deleteErr  error

	startCalls   int
	waitCalls    int
	cleanupCalls int
	stopCalls    int
	deleteCalls  int

	waitRequests    []bootAcceptanceRequest
	cleanupRequests []LiveProcessRequest
	stopRequests    []LiveProcessRequest
	deleteRequests  []LiveProcessRequest
}

var _ ProcessStarter = (*phase34BootAcceptanceCleanupProbe)(nil)
var _ bootAcceptanceWaiter = (*phase34BootAcceptanceCleanupProbe)(nil)
var _ LiveProcessManager = (*phase34BootAcceptanceCleanupProbe)(nil)

func phase34NewBootAcceptanceCleanupProbe(outcome phase34BootAcceptanceOutcome) *phase34BootAcceptanceCleanupProbe {
	return &phase34BootAcceptanceCleanupProbe{
		handle: ProcessHandleMetadata{
			ID:     "phase34-live-handle",
			Source: "phase34-fake",
		},
		outcome: outcome,
	}
}

func (probe *phase34BootAcceptanceCleanupProbe) StartProcess(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
	probe.startCalls++
	return probe.handle, nil
}

func (probe *phase34BootAcceptanceCleanupProbe) WaitForBootAcceptance(_ context.Context, req bootAcceptanceRequest) (bootAcceptanceResult, error) {
	probe.waitCalls++
	probe.waitRequests = append(probe.waitRequests, req)
	switch {
	case probe.outcome.Err != nil:
		return bootAcceptanceResult{}, probe.outcome.Err
	case probe.outcome.Timeout:
		return bootAcceptanceResult{}, context.DeadlineExceeded
	case !probe.outcome.ProcessAccepted:
		return bootAcceptanceResult{}, errPhase34ProcessNotAccepted
	case !probe.outcome.APISocketAvailable:
		return bootAcceptanceResult{}, errPhase34APISocketUnavailable
	default:
		return bootAcceptanceResult{
			ProcessAccepted:    true,
			APISocketAvailable: true,
		}, nil
	}
}

func (probe *phase34BootAcceptanceCleanupProbe) CleanupLiveProcess(_ context.Context, req LiveProcessRequest) error {
	probe.cleanupCalls++
	probe.cleanupRequests = append(probe.cleanupRequests, req)
	return probe.cleanupErr
}

func (probe *phase34BootAcceptanceCleanupProbe) StopLiveProcess(_ context.Context, req LiveProcessRequest) error {
	probe.stopCalls++
	probe.stopRequests = append(probe.stopRequests, req)
	return probe.stopErr
}

func (probe *phase34BootAcceptanceCleanupProbe) DeleteLiveProcess(_ context.Context, req LiveProcessRequest) error {
	probe.deleteCalls++
	probe.deleteRequests = append(probe.deleteRequests, req)
	return probe.deleteErr
}

func phase34LiveBootAcceptanceBackend(stateRoot string, deps *phase34BootAcceptanceCleanupProbe) *Backend {
	return NewBackend(BackendOptions{
		BaseStateDir:         stateRoot,
		ProcessAdapter:       ProcessLaunchAdapter{Starter: deps},
		BootAcceptanceWaiter: deps,
		LiveProcessManager:   deps,
		LiveStart:            true,
	})
}

func phase34CreateStartAndController(t *testing.T, backend *Backend, config microvm.Config, name string) (*sandboxruntime.Target, microvm.Controller, error) {
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
	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    *created,
	})
	return started, controller, err
}

func phase34AssertHostSideAcceptedMetadata(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()

	if target == nil {
		t.Fatal("Start() target = nil, want accepted host-side launch metadata")
	}
	if target.Status != sandbox.StatusStopped {
		t.Fatalf("Start() status = %q, want %q because host-side acceptance does not claim guest readiness", target.Status, sandbox.StatusStopped)
	}
	if target.Connection.Address != "" || target.Connection.PublicIP != "" || target.Connection.TailscaleIP != "" || target.Connection.WorkspaceID != "" {
		t.Fatalf("connection metadata = %#v, want no guest readiness or network reachability claims", target.Connection)
	}
	if target.Runtime.Metadata == nil || target.Runtime.Metadata.ProcessLaunch == nil {
		t.Fatalf("ProcessLaunch metadata = %#v, want host-side launch metadata", target.Runtime.Metadata)
	}
	launch := target.Runtime.Metadata.ProcessLaunch
	if launch.State != string(ProcessLaunchStateAccepted) {
		t.Fatalf("ProcessLaunch.State = %q, want %q after host-side acceptance", launch.State, ProcessLaunchStateAccepted)
	}
	if !safeLaunchTokenForTest(launch.ProcessID) || !safeLaunchTokenForTest(launch.ProcessIDSource) {
		t.Fatalf("ProcessLaunch handle metadata = %#v, want strict redaction-safe process identity labels", launch)
	}
	assertFirecrackerRuntimeMetadataDoesNotClaimUnsupportedLiveCapabilities(t, target)
}

func phase34AssertPublicTargetOmitsUnsafeBootAcceptanceDetails(t *testing.T, target *sandboxruntime.Target, unsafeFragments ...string) {
	t.Helper()

	encoded, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("Marshal(target) error = %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range unsafeFragments {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("public live boot target leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}

func phase34WriteCallerOwnedFiles(t *testing.T, paths []string) {
	t.Helper()

	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q) error = %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte("caller-owned"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", path, err)
		}
	}
}

func phase34AssertCleanupRequestScopedToStateRoot(t *testing.T, req LiveProcessRequest, stateRoot string) {
	t.Helper()

	if req.Handle.ID == "" {
		t.Fatalf("cleanup request handle = %#v, want live process handle", req.Handle)
	}
	if strings.TrimSpace(req.Paths.StateDir) == "" {
		t.Fatalf("cleanup request paths = %#v, want configured Firecracker state paths", req.Paths)
	}
	for _, path := range []string{
		req.Paths.StateDir,
		req.Paths.APISocketPath,
		req.Paths.ConfigPath,
		req.Paths.LogPath,
		req.Paths.MetricsPath,
	} {
		phase34AssertPathUnderBaseStateRoot(t, path, stateRoot)
	}
}

func phase34AssertPathUnderBaseStateRoot(t *testing.T, path, stateRoot string) {
	t.Helper()

	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(stateRoot)
	if cleanPath != cleanRoot && !strings.HasPrefix(cleanPath, cleanRoot+string(filepath.Separator)) {
		t.Fatalf("cleanup path %q is outside configured Firecracker state root %q", path, stateRoot)
	}
}

func phase34AssertCallerOwnedFilesRemain(t *testing.T, paths []string) {
	t.Helper()

	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("caller-owned path %q was removed or changed by cleanup: %v", path, err)
		}
	}
}

func phase34AssertLiveProcessManagerErrorRedacted(t *testing.T, err error) {
	t.Helper()

	opErr := phase34FindLiveProcessManagerOperationError(err)
	if opErr == nil {
		t.Fatalf("live process manager error not found in chain: %v", err)
	}
	if opErr.Code != microvm.ErrorCodeBackendOperationFailed {
		t.Fatalf("live process manager error code = %q, want %q", opErr.Code, microvm.ErrorCodeBackendOperationFailed)
	}
	if opErr.Operation != liveProcessManagerOperation {
		t.Fatalf("live process manager operation = %q, want %q", opErr.Operation, liveProcessManagerOperation)
	}

	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(live process manager error) error = %v", marshalErr)
	}
	publicText := err.Error() + " " + string(encoded)
	for unwrapped := errors.Unwrap(opErr); unwrapped != nil; unwrapped = errors.Unwrap(unwrapped) {
		publicText += " " + unwrapped.Error()
	}
	assertFirecrackerErrorDoesNotLeak(t, errors.New(publicText),
		"/Users/alice",
		"private",
		"firecracker.sock",
		"secret.example.test",
		"8443",
		"ghp_secret",
		"424242",
		"pid=424242",
		"OPENAI_API_KEY",
		"sk-live-secret",
	)
}

func phase34FindLiveProcessManagerOperationError(err error) *microvm.OperationError {
	var opErr *microvm.OperationError
	if errors.As(err, &opErr) && opErr.Operation == liveProcessManagerOperation {
		return opErr
	}
	type multiUnwrapper interface {
		Unwrap() []error
	}
	if joined, ok := err.(multiUnwrapper); ok {
		for _, child := range joined.Unwrap() {
			if found := phase34FindLiveProcessManagerOperationError(child); found != nil {
				return found
			}
		}
	}
	type unwrapper interface {
		Unwrap() error
	}
	if wrapped, ok := err.(unwrapper); ok {
		return phase34FindLiveProcessManagerOperationError(wrapped.Unwrap())
	}
	return nil
}
