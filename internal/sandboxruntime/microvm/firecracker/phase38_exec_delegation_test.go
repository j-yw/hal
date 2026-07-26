package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestPhase38FirecrackerExecRequiresLiveGuestTransportAndReadyGuestReadiness(t *testing.T) {
	readyTarget := phase38ExecTarget(sandboxruntime.NewRuntimeGuestReadinessMetadata(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"vsock",
		[]string{"ready"},
	))

	t.Run("default backend", func(t *testing.T) {
		controller := phase38ExecController(t, NewBackend(BackendOptions{}), readyTarget)
		_, err := controller.Exec(context.Background(), microvm.ControllerExecRequest{
			Operation: microvm.OperationExec,
			Target:    readyTarget,
			Args:      []string{"sh", "-lc", "cat /Users/alice/private/socket token=ghp_secret"},
			Env:       map[string]string{"SECRET_TOKEN": "ghp_secret"},
			WorkDir:   "/Users/alice/private/workspace",
		})
		assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationExec)
		assertFirecrackerErrorDoesNotLeak(t, err, "sh", "SECRET_TOKEN", "ghp_secret", "/Users/alice", "private")
	})

	t.Run("live backend without guest transport", func(t *testing.T) {
		controller := phase38ExecController(t, NewBackend(BackendOptions{LiveStart: true}), readyTarget)
		_, err := controller.Exec(context.Background(), microvm.ControllerExecRequest{
			Operation: microvm.OperationExec,
			Target:    readyTarget,
		})
		assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationExec)
	})

	tests := []struct {
		name      string
		readiness *sandboxruntime.RuntimeGuestReadinessMetadata
	}{
		{name: "absent readiness"},
		{
			name: "waiting readiness",
			readiness: sandboxruntime.NewRuntimeGuestReadinessMetadata(
				sandboxruntime.RuntimeGuestReadinessStateWaiting,
				"vsock",
				[]string{"waiting"},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &phase38RecordingGuestTransport{}
			target := phase38ExecTarget(tt.readiness)
			controller := phase38ExecController(t, NewBackend(BackendOptions{
				GuestTransport: transport,
				LiveStart:      true,
			}), target)

			_, err := controller.Exec(context.Background(), microvm.ControllerExecRequest{
				Operation: microvm.OperationExec,
				Target:    target,
			})
			assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationExec)
			if transport.execCalls != 0 {
				t.Fatalf("guest transport Exec calls = %d, want none", transport.execCalls)
			}
		})
	}
}

func TestPhase38FirecrackerExecDelegatesToInjectedGuestTransportWhenReady(t *testing.T) {
	transport := &phase38RecordingGuestTransport{
		result: &sandboxruntime.ExecResult{ExitCode: 23},
	}
	target := phase38ExecTarget(sandboxruntime.NewRuntimeGuestReadinessMetadata(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"vsock",
		[]string{"ready", "probe_ok"},
	))
	controller := phase38ExecController(t, NewBackend(BackendOptions{
		GuestTransport: transport,
		LiveStart:      true,
	}), target)
	stdin := strings.NewReader("stdin payload")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	args := []string{"sh", "-lc", "printf '%s' \"$HAL_VALUE\""}
	env := map[string]string{"HAL_VALUE": "preserved"}
	workDir := "/workspace/project"

	result, err := controller.Exec(context.Background(), microvm.ControllerExecRequest{
		Operation: microvm.OperationExec,
		Target:    target,
		Args:      args,
		Env:       env,
		WorkDir:   workDir,
		Stdin:     stdin,
		Stdout:    stdout,
		Stderr:    stderr,
	})
	if err != nil {
		t.Fatalf("Exec() error = %v, want nil", err)
	}
	if result == nil || result.ExitCode != 23 {
		t.Fatalf("Exec() result = %#v, want injected transport result", result)
	}
	if transport.execCalls != 1 {
		t.Fatalf("guest transport Exec calls = %d, want 1", transport.execCalls)
	}
	got := transport.execRequest
	if !reflect.DeepEqual(got.Target, target) {
		t.Fatalf("transport Target = %#v, want %#v", got.Target, target)
	}
	if !reflect.DeepEqual(got.Args, args) {
		t.Fatalf("transport Args = %#v, want %#v", got.Args, args)
	}
	if !reflect.DeepEqual(got.Env, env) {
		t.Fatalf("transport Env = %#v, want %#v", got.Env, env)
	}
	if got.WorkDir != workDir {
		t.Fatalf("transport WorkDir = %q, want %q", got.WorkDir, workDir)
	}
	if got.Stdin != stdin || got.Stdout != stdout || got.Stderr != stderr {
		t.Fatalf("transport streams = %#v/%#v/%#v, want original streams", got.Stdin, got.Stdout, got.Stderr)
	}
}

func TestPhase38FirecrackerExecTransportFailureIsWrappedAndSanitized(t *testing.T) {
	transportErr := errors.New("exec failed args=sh -lc cat /Users/alice/private/firecracker.sock env SECRET_TOKEN=ghp_secret workdir=/Users/alice/private/project endpoint=unix:///tmp/firecracker.sock token=ghp_secret pid=4242")
	transport := &phase38RecordingGuestTransport{err: transportErr}
	target := phase38ExecTarget(sandboxruntime.NewRuntimeGuestReadinessMetadata(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"vsock",
		[]string{"ready"},
	))
	controller := phase38ExecController(t, NewBackend(BackendOptions{
		GuestTransport: transport,
		LiveStart:      true,
	}), target)

	_, err := controller.Exec(context.Background(), microvm.ControllerExecRequest{
		Operation: microvm.OperationExec,
		Target:    target,
		Args:      []string{"sh", "-lc", "cat /Users/alice/private/firecracker.sock token=ghp_secret"},
		Env:       map[string]string{"SECRET_TOKEN": "ghp_secret"},
		WorkDir:   "/Users/alice/private/project",
	})
	if err == nil {
		t.Fatal("Exec() error = nil, want wrapped transport failure")
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("errors.Is(Exec() error, transportErr) = false for %v", err)
	}
	assertFirecrackerStartOperationError(t, err, microvm.ErrorCodeBackendOperationFailed, microvm.OperationExec, "guestTransport")
	publicText := err.Error()
	if !strings.Contains(publicText, "guest transport exec failed") {
		t.Fatalf("Exec() error = %q, want sanitized guest transport failure", publicText)
	}
	assertFirecrackerErrorDoesNotLeak(t, err,
		"sh",
		"cat",
		"SECRET_TOKEN",
		"ghp_secret",
		"/Users/alice",
		"private",
		"firecracker.sock",
		"/tmp",
		"unix://",
		"4242",
	)
	encoded, marshalErr := json.Marshal(target)
	if marshalErr != nil {
		t.Fatalf("Marshal(target) error = %v", marshalErr)
	}
	for _, unsafe := range []string{"SECRET_TOKEN", "ghp_secret", "/Users/alice", "firecracker.sock", "unix://", "4242"} {
		if strings.Contains(string(encoded), unsafe) {
			t.Fatalf("runtime metadata leaked unsafe fragment %q in %s", unsafe, encoded)
		}
	}
}

func TestPhase38FirecrackerCopyInRequiresLiveGuestTransportAndReadyGuestReadiness(t *testing.T) {
	readyTarget := phase38ExecTarget(sandboxruntime.NewRuntimeGuestReadinessMetadata(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"vsock",
		[]string{"ready"},
	))

	t.Run("default backend", func(t *testing.T) {
		controller := phase38CopyInController(t, NewBackend(BackendOptions{}), readyTarget)
		err := controller.CopyIn(context.Background(), microvm.ControllerCopyRequest{
			Operation:       microvm.OperationCopyIn,
			Target:          readyTarget,
			SourcePath:      "/Users/alice/private/input-token-ghp_secret.txt",
			DestinationPath: "/workspace/input-token-ghp_secret.txt",
		})
		assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationCopyIn)
		assertFirecrackerErrorDoesNotLeak(t, err, "/Users/alice", "private", "ghp_secret", "input-token-ghp_secret.txt")
	})

	t.Run("live backend without guest transport", func(t *testing.T) {
		controller := phase38CopyInController(t, NewBackend(BackendOptions{LiveStart: true}), readyTarget)
		err := controller.CopyIn(context.Background(), microvm.ControllerCopyRequest{
			Operation:       microvm.OperationCopyIn,
			Target:          readyTarget,
			SourcePath:      "/safe/input.txt",
			DestinationPath: "/workspace/input.txt",
		})
		assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationCopyIn)
	})

	tests := []struct {
		name      string
		readiness *sandboxruntime.RuntimeGuestReadinessMetadata
	}{
		{name: "absent readiness"},
		{
			name: "waiting readiness",
			readiness: sandboxruntime.NewRuntimeGuestReadinessMetadata(
				sandboxruntime.RuntimeGuestReadinessStateWaiting,
				"vsock",
				[]string{"waiting"},
			),
		},
		{
			name: "not configured readiness",
			readiness: sandboxruntime.NewRuntimeGuestReadinessMetadata(
				sandboxruntime.RuntimeGuestReadinessStateNotConfigured,
				"vsock",
				[]string{"not_configured"},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &phase38RecordingGuestTransport{}
			target := phase38ExecTarget(tt.readiness)
			controller := phase38CopyInController(t, NewBackend(BackendOptions{
				GuestTransport: transport,
				LiveStart:      true,
			}), target)

			err := controller.CopyIn(context.Background(), microvm.ControllerCopyRequest{
				Operation:       microvm.OperationCopyIn,
				Target:          target,
				SourcePath:      "/safe/input.txt",
				DestinationPath: "/workspace/input.txt",
			})
			assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationCopyIn)
			if transport.copyInCalls != 0 {
				t.Fatalf("guest transport CopyIn calls = %d, want none", transport.copyInCalls)
			}
		})
	}
}

func TestPhase38FirecrackerCopyInDelegatesToInjectedGuestTransportWhenReady(t *testing.T) {
	transport := &phase38RecordingGuestTransport{}
	target := phase38ExecTarget(sandboxruntime.NewRuntimeGuestReadinessMetadata(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"vsock",
		[]string{"ready", "probe_ok"},
	))
	controller := phase38CopyInController(t, NewBackend(BackendOptions{
		GuestTransport: transport,
		LiveStart:      true,
	}), target)
	source := "/Users/alice/project/input.txt"
	destination := "/workspace/project/input.txt"

	err := controller.CopyIn(context.Background(), microvm.ControllerCopyRequest{
		Operation:       microvm.OperationCopyIn,
		Target:          target,
		SourcePath:      source,
		DestinationPath: destination,
	})
	if err != nil {
		t.Fatalf("CopyIn() error = %v, want nil", err)
	}
	if transport.copyInCalls != 1 {
		t.Fatalf("guest transport CopyIn calls = %d, want 1", transport.copyInCalls)
	}
	got := transport.copyInRequest
	if !reflect.DeepEqual(got.Target, target) {
		t.Fatalf("transport Target = %#v, want %#v", got.Target, target)
	}
	if got.SourcePath != source {
		t.Fatalf("transport SourcePath = %q, want %q", got.SourcePath, source)
	}
	if got.DestinationPath != destination {
		t.Fatalf("transport DestinationPath = %q, want %q", got.DestinationPath, destination)
	}
}

func TestPhase38FirecrackerCopyInTransportFailureIsWrappedAndSanitized(t *testing.T) {
	transportErr := errors.New("copy in failed source=/Users/alice/private/input-token-ghp_secret.txt destination=/workspace/private/input-token-ghp_secret.txt endpoint=unix:///tmp/firecracker.sock socket=/tmp/firecracker.sock token=ghp_secret pid=4242")
	transport := &phase38RecordingGuestTransport{copyInErr: transportErr}
	target := phase38ExecTarget(sandboxruntime.NewRuntimeGuestReadinessMetadata(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"vsock",
		[]string{"ready"},
	))
	controller := phase38CopyInController(t, NewBackend(BackendOptions{
		GuestTransport: transport,
		LiveStart:      true,
	}), target)

	err := controller.CopyIn(context.Background(), microvm.ControllerCopyRequest{
		Operation:       microvm.OperationCopyIn,
		Target:          target,
		SourcePath:      "/Users/alice/private/input-token-ghp_secret.txt",
		DestinationPath: "/workspace/private/input-token-ghp_secret.txt",
	})
	if err == nil {
		t.Fatal("CopyIn() error = nil, want wrapped transport failure")
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("errors.Is(CopyIn() error, transportErr) = false for %v", err)
	}
	assertFirecrackerStartOperationError(t, err, microvm.ErrorCodeBackendOperationFailed, microvm.OperationCopyIn, "guestTransport")
	publicText := err.Error()
	if !strings.Contains(publicText, "guest transport copy in failed") {
		t.Fatalf("CopyIn() error = %q, want sanitized guest transport failure", publicText)
	}
	assertFirecrackerErrorDoesNotLeak(t, err,
		"/Users/alice",
		"private",
		"ghp_secret",
		"input-token-ghp_secret.txt",
		"/tmp",
		"firecracker.sock",
		"unix://",
		"4242",
	)
	encoded, marshalErr := json.Marshal(target)
	if marshalErr != nil {
		t.Fatalf("Marshal(target) error = %v", marshalErr)
	}
	for _, unsafe := range []string{"ghp_secret", "/Users/alice", "firecracker.sock", "unix://", "4242"} {
		if strings.Contains(string(encoded), unsafe) {
			t.Fatalf("runtime metadata leaked unsafe fragment %q in %s", unsafe, encoded)
		}
	}
}

func TestPhase38FirecrackerCopyInPreservesPublishedDurabilityUncertainOutcome(t *testing.T) {
	transportErr := phase38CopyPublicationDurabilityError{
		cause: "fsync /Users/alice/private/input-token-ghp_secret.txt endpoint=unix:///tmp/firecracker.sock",
	}
	transport := &phase38RecordingGuestTransport{copyInErr: transportErr}
	target := phase38ExecTarget(sandboxruntime.NewRuntimeGuestReadinessMetadata(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"vsock",
		[]string{"ready"},
	))
	controller := phase38CopyInController(t, NewBackend(BackendOptions{
		GuestTransport: transport,
		LiveStart:      true,
	}), target)

	err := controller.CopyIn(context.Background(), microvm.ControllerCopyRequest{
		Operation:       microvm.OperationCopyIn,
		Target:          target,
		SourcePath:      "/Users/alice/private/input-token-ghp_secret.txt",
		DestinationPath: "/workspace/private/input-token-ghp_secret.txt",
	})
	if err == nil {
		t.Fatal("CopyIn() error = nil, want uncertain publication outcome")
	}
	var operationErr *microvm.OperationError
	if !errors.As(err, &operationErr) {
		t.Fatalf("CopyIn() error type = %T, want *microvm.OperationError", err)
	}
	if operationErr.Code != microvm.ErrorCode("durability_uncertain") {
		t.Fatalf("OperationError.Code = %q, want durability_uncertain", operationErr.Code)
	}
	if operationErr.Operation != microvm.OperationCopyIn || operationErr.Field != "guestTransport" {
		t.Fatalf("OperationError = %#v, want copy_in guestTransport classification", operationErr)
	}
	assertFirecrackerErrorDoesNotLeak(t, err,
		"/Users/alice",
		"private",
		"ghp_secret",
		"input-token-ghp_secret.txt",
		"unix://",
		"/tmp",
		"firecracker.sock",
	)
}

func TestPhase38FirecrackerCopyOutRequiresLiveGuestTransportAndReadyGuestReadiness(t *testing.T) {
	readyTarget := phase38ExecTarget(sandboxruntime.NewRuntimeGuestReadinessMetadata(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"vsock",
		[]string{"ready"},
	))

	t.Run("default backend", func(t *testing.T) {
		controller := phase38CopyOutController(t, NewBackend(BackendOptions{}), readyTarget)
		err := controller.CopyOut(context.Background(), microvm.ControllerCopyRequest{
			Operation:       microvm.OperationCopyOut,
			Target:          readyTarget,
			SourcePath:      "/workspace/output-token-ghp_secret.txt",
			DestinationPath: "/Users/alice/private/output-token-ghp_secret.txt",
		})
		assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationCopyOut)
		assertFirecrackerErrorDoesNotLeak(t, err, "/Users/alice", "private", "ghp_secret", "output-token-ghp_secret.txt")
	})

	t.Run("live backend without guest transport", func(t *testing.T) {
		controller := phase38CopyOutController(t, NewBackend(BackendOptions{LiveStart: true}), readyTarget)
		err := controller.CopyOut(context.Background(), microvm.ControllerCopyRequest{
			Operation:       microvm.OperationCopyOut,
			Target:          readyTarget,
			SourcePath:      "/workspace/output.txt",
			DestinationPath: "/safe/output.txt",
		})
		assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationCopyOut)
	})

	tests := []struct {
		name      string
		readiness *sandboxruntime.RuntimeGuestReadinessMetadata
	}{
		{name: "absent readiness"},
		{
			name: "waiting readiness",
			readiness: sandboxruntime.NewRuntimeGuestReadinessMetadata(
				sandboxruntime.RuntimeGuestReadinessStateWaiting,
				"vsock",
				[]string{"waiting"},
			),
		},
		{
			name: "not configured readiness",
			readiness: sandboxruntime.NewRuntimeGuestReadinessMetadata(
				sandboxruntime.RuntimeGuestReadinessStateNotConfigured,
				"vsock",
				[]string{"not_configured"},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &phase38RecordingGuestTransport{}
			target := phase38ExecTarget(tt.readiness)
			controller := phase38CopyOutController(t, NewBackend(BackendOptions{
				GuestTransport: transport,
				LiveStart:      true,
			}), target)

			err := controller.CopyOut(context.Background(), microvm.ControllerCopyRequest{
				Operation:       microvm.OperationCopyOut,
				Target:          target,
				SourcePath:      "/workspace/output.txt",
				DestinationPath: "/safe/output.txt",
			})
			assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationCopyOut)
			if transport.copyOutCalls != 0 {
				t.Fatalf("guest transport CopyOut calls = %d, want none", transport.copyOutCalls)
			}
		})
	}
}

func TestPhase38FirecrackerCopyOutDelegatesToInjectedGuestTransportWhenReady(t *testing.T) {
	transport := &phase38RecordingGuestTransport{}
	target := phase38ExecTarget(sandboxruntime.NewRuntimeGuestReadinessMetadata(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"vsock",
		[]string{"ready", "probe_ok"},
	))
	controller := phase38CopyOutController(t, NewBackend(BackendOptions{
		GuestTransport: transport,
		LiveStart:      true,
	}), target)
	source := "/workspace/project/output.txt"
	destination := "/Users/alice/project/output.txt"

	err := controller.CopyOut(context.Background(), microvm.ControllerCopyRequest{
		Operation:       microvm.OperationCopyOut,
		Target:          target,
		SourcePath:      source,
		DestinationPath: destination,
	})
	if err != nil {
		t.Fatalf("CopyOut() error = %v, want nil", err)
	}
	if transport.copyOutCalls != 1 {
		t.Fatalf("guest transport CopyOut calls = %d, want 1", transport.copyOutCalls)
	}
	got := transport.copyOutRequest
	if !reflect.DeepEqual(got.Target, target) {
		t.Fatalf("transport Target = %#v, want %#v", got.Target, target)
	}
	if got.SourcePath != source {
		t.Fatalf("transport SourcePath = %q, want %q", got.SourcePath, source)
	}
	if got.DestinationPath != destination {
		t.Fatalf("transport DestinationPath = %q, want %q", got.DestinationPath, destination)
	}
}

func TestPhase38FirecrackerCopyOutTransportFailureIsWrappedAndSanitized(t *testing.T) {
	transportErr := errors.New("copy out failed source=/workspace/private/output-token-ghp_secret.txt destination=/Users/alice/private/output-token-ghp_secret.txt endpoint=unix:///tmp/firecracker.sock socket=/tmp/firecracker.sock token=ghp_secret pid=4242")
	transport := &phase38RecordingGuestTransport{copyOutErr: transportErr}
	target := phase38ExecTarget(sandboxruntime.NewRuntimeGuestReadinessMetadata(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"vsock",
		[]string{"ready"},
	))
	controller := phase38CopyOutController(t, NewBackend(BackendOptions{
		GuestTransport: transport,
		LiveStart:      true,
	}), target)

	err := controller.CopyOut(context.Background(), microvm.ControllerCopyRequest{
		Operation:       microvm.OperationCopyOut,
		Target:          target,
		SourcePath:      "/workspace/private/output-token-ghp_secret.txt",
		DestinationPath: "/Users/alice/private/output-token-ghp_secret.txt",
	})
	if err == nil {
		t.Fatal("CopyOut() error = nil, want wrapped transport failure")
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("errors.Is(CopyOut() error, transportErr) = false for %v", err)
	}
	assertFirecrackerStartOperationError(t, err, microvm.ErrorCodeBackendOperationFailed, microvm.OperationCopyOut, "guestTransport")
	publicText := err.Error()
	if !strings.Contains(publicText, "guest transport copy out failed") {
		t.Fatalf("CopyOut() error = %q, want sanitized guest transport failure", publicText)
	}
	assertFirecrackerErrorDoesNotLeak(t, err,
		"/Users/alice",
		"private",
		"ghp_secret",
		"output-token-ghp_secret.txt",
		"/tmp",
		"firecracker.sock",
		"unix://",
		"4242",
	)
	encoded, marshalErr := json.Marshal(target)
	if marshalErr != nil {
		t.Fatalf("Marshal(target) error = %v", marshalErr)
	}
	for _, unsafe := range []string{"ghp_secret", "/Users/alice", "firecracker.sock", "unix://", "4242"} {
		if strings.Contains(string(encoded), unsafe) {
			t.Fatalf("runtime metadata leaked unsafe fragment %q in %s", unsafe, encoded)
		}
	}
}

type phase38RecordingGuestTransport struct {
	execCalls      int
	copyInCalls    int
	copyOutCalls   int
	execRequest    GuestExecRequest
	copyInRequest  GuestCopyRequest
	copyOutRequest GuestCopyRequest
	result         *sandboxruntime.ExecResult
	err            error
	copyInErr      error
	copyOutErr     error
}

type phase38CopyPublicationDurabilityError struct {
	cause string
}

func (err phase38CopyPublicationDurabilityError) Error() string {
	return err.cause
}

func (phase38CopyPublicationDurabilityError) CopyPublicationDurabilityUncertain() bool {
	return true
}

func (transport *phase38RecordingGuestTransport) Exec(_ context.Context, req GuestExecRequest) (*sandboxruntime.ExecResult, error) {
	transport.execCalls++
	transport.execRequest = req
	if transport.err != nil {
		return nil, transport.err
	}
	if transport.result != nil {
		return transport.result, nil
	}
	return &sandboxruntime.ExecResult{ExitCode: 0}, nil
}

func (transport *phase38RecordingGuestTransport) CopyIn(_ context.Context, req GuestCopyRequest) error {
	transport.copyInCalls++
	transport.copyInRequest = req
	return transport.copyInErr
}

func (transport *phase38RecordingGuestTransport) CopyOut(_ context.Context, req GuestCopyRequest) error {
	transport.copyOutCalls++
	transport.copyOutRequest = req
	return transport.copyOutErr
}

func phase38ExecController(t *testing.T, backend *Backend, target sandboxruntime.Target) microvm.Controller {
	t.Helper()
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationExec,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}
	return controller
}

func phase38CopyInController(t *testing.T, backend *Backend, target sandboxruntime.Target) microvm.Controller {
	t.Helper()
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationCopyIn,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}
	return controller
}

func phase38CopyOutController(t *testing.T, backend *Backend, target sandboxruntime.Target) microvm.Controller {
	t.Helper()
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationCopyOut,
		Config:    validMicroVMConfig(),
		Target:    target,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}
	return controller
}

func phase38ExecTarget(readiness *sandboxruntime.RuntimeGuestReadinessMetadata) sandboxruntime.Target {
	return sandboxruntime.Target{
		ID:       "runtime-alpha",
		Name:     "firecracker-dev",
		Provider: BackendID,
		Status:   sandbox.StatusRunning,
		Runtime: sandboxruntime.RuntimeState{
			Driver:    sandboxruntime.DriverMicroVM,
			RuntimeID: "runtime-alpha",
			Metadata: &sandboxruntime.RuntimeMetadata{
				Backend:        BackendID,
				ProcessLaunch:  NewProcessLaunchMetadata(ProcessLaunchStateAccepted, ProcessHandleMetadata{ID: "fc-process", Source: "adapter"}).RuntimeMetadata(),
				GuestReadiness: readiness,
			},
		},
	}
}
