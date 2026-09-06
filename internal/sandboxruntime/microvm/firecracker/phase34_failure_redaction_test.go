package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestPhase34LiveBootFailurePathsRedactSeededSensitiveValues(t *testing.T) {
	t.Run("render", func(t *testing.T) {
		fixture := phase34NewSensitiveRedactionFixture(t)
		phase34US010BlockStateRoot(t, fixture.StateRoot)
		deps := phase34NewFailureRedactionDeps()
		created, controller, paths := phase34US010CreateController(t, fixture, deps)

		started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStart,
			Config:    fixture.Config,
			Target:    *created,
		})

		if started != nil {
			t.Fatalf("Start() target = %#v, want nil after render failure", started)
		}
		if deps.startCalls != 0 {
			t.Fatalf("starter calls = %d, want render failure before process launch", deps.startCalls)
		}
		phase34US010AssertFailureRedacted(t, "render failure", err, fixture, paths)
		phase34US010AssertOperationError(t, err, liveBootRenderOperation, microvm.ErrorCodeBackendOperationFailed)
	})

	t.Run("launch", func(t *testing.T) {
		fixture := phase34NewSensitiveRedactionFixture(t)
		deps := phase34NewFailureRedactionDeps()
		created, controller, paths := phase34US010CreateController(t, fixture, deps)
		deps.startErr = phase34US010UnsafeError("launch", fixture, paths)

		started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStart,
			Config:    fixture.Config,
			Target:    *created,
		})

		if started != nil {
			t.Fatalf("Start() target = %#v, want nil after launch failure", started)
		}
		if deps.startCalls != 1 || deps.waitCalls != 0 || deps.cleanupCalls != 0 {
			t.Fatalf("calls = start:%d wait:%d cleanup:%d, want launch failure before wait/cleanup", deps.startCalls, deps.waitCalls, deps.cleanupCalls)
		}
		if !errors.Is(err, deps.startErr) {
			t.Fatalf("errors.Is(Start() error, launchErr) = false for %v", err)
		}
		phase34US010AssertFailureRedacted(t, "launch failure", err, fixture, paths)
		phase34US010AssertOperationError(t, err, ProcessBoundaryOperation, microvm.ErrorCodeBackendOperationFailed)
	})

	t.Run("wait", func(t *testing.T) {
		fixture := phase34NewSensitiveRedactionFixture(t)
		deps := phase34NewFailureRedactionDeps()
		created, controller, paths := phase34US010CreateController(t, fixture, deps)
		deps.waitErr = phase34US010UnsafeError("wait", fixture, paths)

		started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStart,
			Config:    fixture.Config,
			Target:    *created,
		})

		if started != nil {
			t.Fatalf("Start() target = %#v, want nil after wait failure", started)
		}
		if deps.startCalls != 1 || deps.waitCalls != 1 || deps.cleanupCalls != 1 {
			t.Fatalf("calls = start:%d wait:%d cleanup:%d, want failed wait followed by cleanup", deps.startCalls, deps.waitCalls, deps.cleanupCalls)
		}
		if !errors.Is(err, deps.waitErr) {
			t.Fatalf("errors.Is(Start() error, waitErr) = false for %v", err)
		}
		phase34US010AssertFailureRedacted(t, "wait failure", err, fixture, paths)
		phase34US010AssertOperationError(t, err, liveBootAcceptanceOperation, microvm.ErrorCodeBackendOperationFailed)
	})

	t.Run("timeout", func(t *testing.T) {
		fixture := phase34NewSensitiveRedactionFixture(t)
		deps := phase34NewFailureRedactionDeps()
		created, controller, paths := phase34US010CreateController(t, fixture, deps)
		deps.waitErr = context.DeadlineExceeded

		started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStart,
			Config:    fixture.Config,
			Target:    *created,
		})

		if started != nil {
			t.Fatalf("Start() target = %#v, want nil after timeout", started)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("errors.Is(Start() error, DeadlineExceeded) = false for %v", err)
		}
		phase34US010AssertFailureRedacted(t, "timeout failure", err, fixture, paths)
		opErr := phase34US010AssertOperationError(t, err, liveBootAcceptanceOperation, microvm.ErrorCodeBackendOperationFailed)
		if !strings.Contains(opErr.Error(), "timed out") {
			t.Fatalf("timeout error = %q, want actionable timeout label", opErr.Error())
		}
	})

	t.Run("acceptance cleanup", func(t *testing.T) {
		fixture := phase34NewSensitiveRedactionFixture(t)
		deps := phase34NewFailureRedactionDeps()
		created, controller, paths := phase34US010CreateController(t, fixture, deps)
		deps.waitErr = phase34US010UnsafeError("wait", fixture, paths)
		deps.cleanupErr = phase34US010UnsafeError("cleanup", fixture, paths)

		started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStart,
			Config:    fixture.Config,
			Target:    *created,
		})

		if started != nil {
			t.Fatalf("Start() target = %#v, want nil after cleanup failure", started)
		}
		if deps.cleanupCalls != 1 {
			t.Fatalf("cleanup calls = %d, want one cleanup attempt after acceptance failure", deps.cleanupCalls)
		}
		if !errors.Is(err, deps.waitErr) || !errors.Is(err, deps.cleanupErr) {
			t.Fatalf("joined Start() error = %v, want wait and cleanup causes preserved", err)
		}
		phase34US010AssertFailureRedacted(t, "acceptance cleanup failure", err, fixture, paths)
		phase34US010AssertOperationError(t, err, liveBootAcceptanceOperation, microvm.ErrorCodeBackendOperationFailed)
		phase34US010AssertOperationError(t, err, liveProcessManagerOperation, microvm.ErrorCodeBackendOperationFailed)
	})

	t.Run("stop cleanup", func(t *testing.T) {
		fixture := phase34NewSensitiveRedactionFixture(t)
		deps := phase34NewFailureRedactionDeps()
		started, controller, paths := phase34US010StartAccepted(t, fixture, deps)
		deps.stopErr = phase34US010UnsafeError("stop cleanup", fixture, paths)

		stopped, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStop,
			Config:    fixture.Config,
			Target:    *started,
		})

		if stopped != nil {
			t.Fatalf("Stop() target = %#v, want nil after cleanup failure", stopped)
		}
		if !errors.Is(err, deps.stopErr) {
			t.Fatalf("errors.Is(Stop() error, stopErr) = false for %v", err)
		}
		phase34US010AssertFailureRedacted(t, "stop cleanup failure", err, fixture, paths)
		phase34US010AssertOperationError(t, err, liveProcessManagerOperation, microvm.ErrorCodeBackendOperationFailed)
	})

	t.Run("delete cleanup", func(t *testing.T) {
		fixture := phase34NewSensitiveRedactionFixture(t)
		deps := phase34NewFailureRedactionDeps()
		started, controller, paths := phase34US010StartAccepted(t, fixture, deps)
		stopped, err := controller.Stop(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationStop,
			Config:    fixture.Config,
			Target:    *started,
		})
		if err != nil {
			t.Fatalf("Stop() error = %v, want nil before delete failure", err)
		}
		deps.deleteErr = phase34US010UnsafeError("delete cleanup", fixture, paths)

		err = controller.Delete(context.Background(), microvm.ControllerLifecycleRequest{
			Operation: microvm.OperationDelete,
			Config:    fixture.Config,
			Target:    *stopped,
		})

		if !errors.Is(err, deps.deleteErr) {
			t.Fatalf("errors.Is(Delete() error, deleteErr) = false for %v", err)
		}
		phase34US010AssertFailureRedacted(t, "delete cleanup failure", err, fixture, paths)
		phase34US010AssertOperationError(t, err, liveProcessManagerOperation, microvm.ErrorCodeBackendOperationFailed)
	})
}

func TestPhase34NestedProcessBoundaryFailureDetailsAreSanitized(t *testing.T) {
	fixture := phase34NewSensitiveRedactionFixture(t)
	deps := phase34NewFailureRedactionDeps()
	created, controller, paths := phase34US010CreateController(t, fixture, deps)
	rawCause := phase34US010UnsafeError("nested process boundary", fixture, paths)
	deps.startErr = microvm.NewBackendOperationFailedError(ProcessBoundaryOperation, rawCause)

	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    fixture.Config,
		Target:    *created,
	})

	if started != nil {
		t.Fatalf("Start() target = %#v, want nil after nested launch failure", started)
	}
	if !errors.Is(err, rawCause) {
		t.Fatalf("errors.Is(Start() error, rawCause) = false for %v", err)
	}
	phase34US010AssertFailureRedacted(t, "nested process-boundary failure", err, fixture, paths)
	phase34US010AssertOperationError(t, err, ProcessBoundaryOperation, microvm.ErrorCodeBackendOperationFailed)
}

type phase34FailureRedactionDeps struct {
	handle ProcessHandleMetadata

	startErr   error
	waitErr    error
	cleanupErr error
	stopErr    error
	deleteErr  error

	startCalls   int
	waitCalls    int
	cleanupCalls int
	stopCalls    int
	deleteCalls  int
}

var _ ProcessStarter = (*phase34FailureRedactionDeps)(nil)
var _ BootAcceptanceWaiter = (*phase34FailureRedactionDeps)(nil)
var _ LiveProcessManager = (*phase34FailureRedactionDeps)(nil)

func phase34NewFailureRedactionDeps() *phase34FailureRedactionDeps {
	return &phase34FailureRedactionDeps{
		handle: ProcessHandleMetadata{
			ID:     "phase34-us010-handle",
			Source: "phase34-us010-fake",
		},
	}
}

func (deps *phase34FailureRedactionDeps) StartProcess(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
	deps.startCalls++
	if deps.startErr != nil {
		return ProcessHandleMetadata{}, deps.startErr
	}
	return deps.handle, nil
}

func (deps *phase34FailureRedactionDeps) WaitForBootAcceptance(context.Context, BootAcceptanceRequest) (BootAcceptanceResult, error) {
	deps.waitCalls++
	if deps.waitErr != nil {
		return BootAcceptanceResult{}, deps.waitErr
	}
	return BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	}, nil
}

func (deps *phase34FailureRedactionDeps) CleanupLiveProcess(context.Context, LiveProcessRequest) error {
	deps.cleanupCalls++
	return deps.cleanupErr
}

func (deps *phase34FailureRedactionDeps) StopLiveProcess(context.Context, LiveProcessRequest) error {
	deps.stopCalls++
	return deps.stopErr
}

func (deps *phase34FailureRedactionDeps) DeleteLiveProcess(context.Context, LiveProcessRequest) error {
	deps.deleteCalls++
	return deps.deleteErr
}

func phase34US010CreateController(t *testing.T, fixture phase34SensitiveRedactionFixture, deps *phase34FailureRedactionDeps) (*sandboxruntime.Target, microvm.Controller, PathPlan) {
	t.Helper()

	backend := NewBackend(BackendOptions{
		BaseStateDir:         fixture.StateRoot,
		ProcessAdapter:       ProcessLaunchAdapter{Starter: deps},
		BootAcceptanceWaiter: deps,
		LiveProcessManager:   deps,
		LiveStart:            true,
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    fixture.Config,
		Name:      fixture.UnsafeTargetName,
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Config:    fixture.Config,
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}
	return created, controller, fixture.PathsForRuntime(t, created.Runtime.RuntimeID)
}

func phase34US010StartAccepted(t *testing.T, fixture phase34SensitiveRedactionFixture, deps *phase34FailureRedactionDeps) (*sandboxruntime.Target, microvm.Controller, PathPlan) {
	t.Helper()

	created, controller, paths := phase34US010CreateController(t, fixture, deps)
	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    fixture.Config,
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Start() error = %v, want accepted live boot before cleanup failure", err)
	}
	if started == nil {
		t.Fatal("Start() target = nil, want accepted live boot before cleanup failure")
	}
	publicText := phase34PublicJSON(t, started)
	phase34AssertPublicTextRedacted(t, "accepted live boot public metadata", publicText, fixture.UnsafeFragments(&paths)...)
	return started, controller, paths
}

func phase34US010UnsafeError(phase string, fixture phase34SensitiveRedactionFixture, paths PathPlan) error {
	return errors.New(fmt.Sprintf(
		"%s failed stateDir=%s apiSocket=%s config=%s log=%s metrics=%s kernel=%s rootfs=%s initrd=%s argv=%q endpoint=%s env OPENAI_API_KEY=%s SECRET_TOKEN=%s token=%s pid=424242 process_id=424242",
		phase,
		paths.StateDir,
		paths.APISocketPath,
		paths.ConfigPath,
		paths.LogPath,
		paths.MetricsPath,
		fixture.Config.KernelImagePath,
		fixture.Config.RootfsPath,
		fixture.Config.InitrdPath,
		fixture.RawArgv(paths),
		fixture.Endpoint,
		fixture.EnvValue,
		fixture.SecretValue,
		fixture.TokenValue,
	))
}

func phase34US010BlockStateRoot(t *testing.T, stateRoot string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(stateRoot), 0o700); err != nil {
		t.Fatalf("MkdirAll(state root parent) error = %v", err)
	}
	if err := os.WriteFile(stateRoot, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile(state root blocker) error = %v", err)
	}
}

func phase34US010AssertFailureRedacted(t *testing.T, label string, err error, fixture phase34SensitiveRedactionFixture, paths PathPlan) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s error = nil, want failure to inspect", label)
	}
	publicText := phase34US010PublicErrorText(t, err)
	unsafeFragments := append(fixture.UnsafeFragments(&paths),
		"424242",
		"pid=424242",
		"process_id=424242",
	)
	phase34AssertPublicTextRedacted(t, label, publicText, unsafeFragments...)
}

func phase34US010PublicErrorText(t *testing.T, err error) string {
	t.Helper()

	var builder strings.Builder
	var appendErr func(error, int)
	appendErr = func(current error, depth int) {
		if current == nil || depth > 12 {
			return
		}
		builder.WriteByte(' ')
		builder.WriteString(current.Error())
		if encoded, marshalErr := json.Marshal(current); marshalErr == nil {
			builder.WriteByte(' ')
			builder.Write(encoded)
		}
		type multiUnwrapper interface {
			Unwrap() []error
		}
		if joined, ok := current.(multiUnwrapper); ok {
			for _, child := range joined.Unwrap() {
				appendErr(child, depth+1)
			}
			return
		}
		type unwrapper interface {
			Unwrap() error
		}
		if wrapped, ok := current.(unwrapper); ok {
			appendErr(wrapped.Unwrap(), depth+1)
		}
	}
	appendErr(err, 0)
	return builder.String()
}

func phase34US010AssertOperationError(t *testing.T, err error, operation string, code microvm.ErrorCode) *microvm.OperationError {
	t.Helper()

	opErr := phase34US010FindOperationError(err, operation)
	if opErr == nil {
		t.Fatalf("operation error %q not found in %v", operation, err)
	}
	if opErr.Code != code {
		t.Fatalf("%s OperationError.Code = %q, want %q", operation, opErr.Code, code)
	}
	if strings.TrimSpace(opErr.Operation) == "" {
		t.Fatalf("%s OperationError.Operation is empty: %#v", operation, opErr)
	}
	return opErr
}

func phase34US010FindOperationError(err error, operation string) *microvm.OperationError {
	if err == nil {
		return nil
	}
	var opErr *microvm.OperationError
	if errors.As(err, &opErr) && opErr.Operation == operation {
		return opErr
	}
	type multiUnwrapper interface {
		Unwrap() []error
	}
	if joined, ok := err.(multiUnwrapper); ok {
		for _, child := range joined.Unwrap() {
			if found := phase34US010FindOperationError(child, operation); found != nil {
				return found
			}
		}
		return nil
	}
	type unwrapper interface {
		Unwrap() error
	}
	if wrapped, ok := err.(unwrapper); ok {
		return phase34US010FindOperationError(wrapped.Unwrap(), operation)
	}
	return nil
}
