package firecrackerhost

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestProcessLifecycleManagerStartsFakeProcessWithOpaqueHandle(t *testing.T) {
	req := firecracker.ProcessRunnerStartRequest{
		Executable:  "/Users/alice/private/bin/firecracker",
		Args:        []string{"--api-sock", "/tmp/hal/firecracker.sock", "--config-file", "/tmp/hal/firecracker-config.json"},
		Environment: []string{"OPENAI_API_KEY=sk-live-secret"},
	}
	process := &fakeHostProcess{rawPID: 424242}
	runner := &fakeHostProcessRunner{processes: []HostProcess{process}}
	manager := NewProcessLifecycleManager(runner)

	handle, err := manager.StartProcess(context.Background(), req)
	if err != nil {
		t.Fatalf("StartProcess() error = %v, want nil", err)
	}

	if handle.ID != "fc-handle-000000000001" {
		t.Fatalf("handle ID = %q, want stable opaque first handle", handle.ID)
	}
	if handle.Source != processHandleSource {
		t.Fatalf("handle source = %q, want %q", handle.Source, processHandleSource)
	}
	if rawProcessMetadataLeaked(handle.ID, "424242", "pid", "process-") {
		t.Fatalf("handle ID = %q, want no raw process identity", handle.ID)
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
	if !reflect.DeepEqual(runner.requests[0], req) {
		t.Fatalf("runner request = %#v, want %#v", runner.requests[0], req)
	}

	req.Args[1] = "/tmp/mutated.sock"
	if runner.requests[0].Args[1] == req.Args[1] {
		t.Fatal("runner request args alias caller-owned request slice")
	}

	encoded, err := json.Marshal(handle)
	if err != nil {
		t.Fatalf("Marshal(handle) error: %v", err)
	}
	assertProcessLifecyclePublicTextRedacted(t, string(encoded),
		"/Users/alice",
		"private",
		"firecracker.sock",
		"sk-live-secret",
		"OPENAI_API_KEY",
		"424242",
	)
}

func TestProcessLifecycleManagerStopSignalsAndWaitsIdempotently(t *testing.T) {
	process := &fakeHostProcess{rawPID: 424242}
	manager := NewProcessLifecycleManager(&fakeHostProcessRunner{processes: []HostProcess{process}})
	handle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{Executable: "firecracker"})
	if err != nil {
		t.Fatalf("StartProcess() error = %v, want nil", err)
	}

	unknown := firecracker.ProcessHandleMetadata{ID: "fc-handle-999999999999", Source: processHandleSource}
	if err := manager.StopLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: unknown}); err != nil {
		t.Fatalf("StopLiveProcess(unknown) error = %v, want nil", err)
	}
	if process.signalCalls != 0 || process.waitCalls != 0 || process.killCalls != 0 {
		t.Fatalf("unknown stop touched process: signal=%d wait=%d kill=%d", process.signalCalls, process.waitCalls, process.killCalls)
	}

	if err := manager.StopLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle}); err != nil {
		t.Fatalf("StopLiveProcess() error = %v, want nil", err)
	}
	if !reflect.DeepEqual(process.signals, []ProcessSignal{ProcessSignalTerminate}) {
		t.Fatalf("signals = %#v, want graceful terminate signal", process.signals)
	}
	if process.waitCalls != 1 {
		t.Fatalf("wait calls = %d, want 1", process.waitCalls)
	}
	if process.killCalls != 0 {
		t.Fatalf("kill calls = %d, want 0 for graceful stop", process.killCalls)
	}

	if err := manager.StopLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle}); err != nil {
		t.Fatalf("StopLiveProcess(already-finished) error = %v, want nil", err)
	}
	if process.signalCalls != 1 || process.waitCalls != 1 || process.killCalls != 0 {
		t.Fatalf("already-finished stop was not idempotent: signal=%d wait=%d kill=%d", process.signalCalls, process.waitCalls, process.killCalls)
	}
}

func TestProcessLifecycleManagerCleanupAndDeleteKillAndWait(t *testing.T) {
	cleanupProcess := &fakeHostProcess{rawPID: 1111}
	deleteProcess := &fakeHostProcess{rawPID: 2222}
	manager := NewProcessLifecycleManager(&fakeHostProcessRunner{
		processes: []HostProcess{cleanupProcess, deleteProcess},
	})
	cleanupHandle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{Executable: "firecracker"})
	if err != nil {
		t.Fatalf("StartProcess(cleanup) error = %v, want nil", err)
	}
	deleteHandle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{Executable: "firecracker"})
	if err != nil {
		t.Fatalf("StartProcess(delete) error = %v, want nil", err)
	}

	if err := manager.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: cleanupHandle}); err != nil {
		t.Fatalf("CleanupLiveProcess() error = %v, want nil", err)
	}
	if cleanupProcess.killCalls != 1 || cleanupProcess.waitCalls != 1 || cleanupProcess.signalCalls != 0 {
		t.Fatalf("cleanup calls = signal:%d kill:%d wait:%d, want kill+wait only", cleanupProcess.signalCalls, cleanupProcess.killCalls, cleanupProcess.waitCalls)
	}
	if err := manager.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: cleanupHandle}); err != nil {
		t.Fatalf("CleanupLiveProcess(already-finished) error = %v, want nil", err)
	}
	if cleanupProcess.killCalls != 1 || cleanupProcess.waitCalls != 1 {
		t.Fatalf("cleanup was not idempotent: kill=%d wait=%d", cleanupProcess.killCalls, cleanupProcess.waitCalls)
	}

	if err := manager.DeleteLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: deleteHandle}); err != nil {
		t.Fatalf("DeleteLiveProcess() error = %v, want nil", err)
	}
	if deleteProcess.killCalls != 1 || deleteProcess.waitCalls != 1 || deleteProcess.signalCalls != 0 {
		t.Fatalf("delete calls = signal:%d kill:%d wait:%d, want kill+wait only", deleteProcess.signalCalls, deleteProcess.killCalls, deleteProcess.waitCalls)
	}
	if err := manager.DeleteLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: deleteHandle}); err != nil {
		t.Fatalf("DeleteLiveProcess(unknown-after-delete) error = %v, want nil", err)
	}
	if deleteProcess.killCalls != 1 || deleteProcess.waitCalls != 1 {
		t.Fatalf("delete was not idempotent after handle removal: kill=%d wait=%d", deleteProcess.killCalls, deleteProcess.waitCalls)
	}
}

func TestProcessLifecycleManagerLifecycleErrorsAreSanitized(t *testing.T) {
	unsafeErr := errors.New("firecracker failed executable=/Users/alice/private/bin/firecracker argv=--api-sock /tmp/hal/firecracker.sock endpoint=https://secret.example.test:8443/api pid=424242 OPENAI_API_KEY=sk-live-secret token=ghp_secret")

	t.Run("start", func(t *testing.T) {
		runner := &fakeHostProcessRunner{err: unsafeErr}
		manager := NewProcessLifecycleManager(runner)

		_, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{Executable: "/Users/alice/private/bin/firecracker"})

		assertProcessLifecycleError(t, err, processOperationStart, unsafeErr)
	})

	t.Run("signal", func(t *testing.T) {
		process := &fakeHostProcess{signalErr: unsafeErr}
		manager, handle := startFakeManagedProcess(t, process)

		err := manager.StopLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle})

		assertProcessLifecycleError(t, err, processOperationSignal, unsafeErr)
	})

	t.Run("wait", func(t *testing.T) {
		process := &fakeHostProcess{waitErr: unsafeErr}
		manager, handle := startFakeManagedProcess(t, process)

		err := manager.StopLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle})

		assertProcessLifecycleError(t, err, processOperationWait, unsafeErr)
	})

	t.Run("kill", func(t *testing.T) {
		process := &fakeHostProcess{killErr: unsafeErr}
		manager, handle := startFakeManagedProcess(t, process)

		err := manager.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle})

		assertProcessLifecycleError(t, err, processOperationKill, unsafeErr)
	})
}

func TestProcessLifecycleManagerRejectsMissingRunnerAndNilProcess(t *testing.T) {
	manager := NewProcessLifecycleManager(nil)
	if _, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{}); !errors.Is(err, ErrDependencyNotConfigured) {
		t.Fatalf("StartProcess() error = %v, want ErrDependencyNotConfigured", err)
	}

	manager = NewProcessLifecycleManager(&fakeHostProcessRunner{})
	_, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{})
	if !errors.Is(err, ErrHostProcessRequired) {
		t.Fatalf("StartProcess(nil process) error = %v, want ErrHostProcessRequired", err)
	}
	assertProcessLifecyclePublicTextRedacted(t, err.Error(), "/Users/alice", "ghp_secret", "OPENAI_API_KEY")
}

type fakeHostProcessRunner struct {
	calls     int
	requests  []firecracker.ProcessRunnerStartRequest
	processes []HostProcess
	err       error
}

func (runner *fakeHostProcessRunner) StartHostProcess(_ context.Context, req firecracker.ProcessRunnerStartRequest) (HostProcess, error) {
	runner.calls++
	runner.requests = append(runner.requests, req)
	if runner.err != nil {
		return nil, runner.err
	}
	if len(runner.processes) == 0 {
		return nil, nil
	}
	process := runner.processes[0]
	runner.processes = runner.processes[1:]
	return process, nil
}

type fakeHostProcess struct {
	rawPID int

	signalCalls int
	waitCalls   int
	killCalls   int
	signals     []ProcessSignal

	signalErr error
	waitErr   error
	killErr   error
}

func (process *fakeHostProcess) Signal(_ context.Context, signal ProcessSignal) error {
	process.signalCalls++
	process.signals = append(process.signals, signal)
	return process.signalErr
}

func (process *fakeHostProcess) Wait(context.Context) error {
	process.waitCalls++
	return process.waitErr
}

func (process *fakeHostProcess) Kill(context.Context) error {
	process.killCalls++
	return process.killErr
}

func startFakeManagedProcess(t *testing.T, process HostProcess) (*ProcessLifecycleManager, firecracker.ProcessHandleMetadata) {
	t.Helper()
	manager := NewProcessLifecycleManager(&fakeHostProcessRunner{processes: []HostProcess{process}})
	handle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{Executable: "firecracker"})
	if err != nil {
		t.Fatalf("StartProcess() error = %v, want nil", err)
	}
	return manager, handle
}

func assertProcessLifecycleError(t *testing.T, err error, operation string, cause error) {
	t.Helper()
	if err == nil {
		t.Fatal("lifecycle error = nil, want error")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(%v, cause) = false, want true", err)
	}
	var lifecycleErr *ProcessLifecycleError
	if !errors.As(err, &lifecycleErr) {
		t.Fatalf("errors.As(%T) = false, want true", lifecycleErr)
	}
	if lifecycleErr.Operation != operation {
		t.Fatalf("operation = %q, want %q", lifecycleErr.Operation, operation)
	}
	assertProcessLifecyclePublicTextRedacted(t, err.Error(),
		"/Users/alice",
		"private",
		"/tmp/hal",
		"firecracker.sock",
		"secret.example.test",
		"8443",
		"424242",
		"OPENAI_API_KEY",
		"sk-live-secret",
		"ghp_secret",
	)
}

func assertProcessLifecyclePublicTextRedacted(t *testing.T, publicText string, unsafeFragments ...string) {
	t.Helper()
	for _, unsafe := range unsafeFragments {
		if strings.TrimSpace(unsafe) == "" {
			continue
		}
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("public text leaked unsafe fragment %q in %q", unsafe, publicText)
		}
	}
}

func rawProcessMetadataLeaked(value string, unsafeFragments ...string) bool {
	lower := strings.ToLower(value)
	for _, unsafe := range unsafeFragments {
		if strings.Contains(lower, strings.ToLower(unsafe)) {
			return true
		}
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}
