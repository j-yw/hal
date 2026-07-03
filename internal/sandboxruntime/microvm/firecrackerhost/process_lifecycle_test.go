package firecrackerhost

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

func TestProcessLifecycleManagerCleanupRemovesOnlyValidatedFirecrackerStateDir(t *testing.T) {
	paths := cleanupPathPlanForTest("fc-cleanup-safe")
	callerOwnedPath := filepath.Join(filepath.Dir(paths.StateDir), "caller-owned", firecracker.DefaultAPISocketPath)
	filesystem := newFakeCleanupFilesystem()
	filesystem.addDir(paths.StateDir)
	filesystem.addFile(paths.APISocketPath)
	filesystem.addFile(paths.ConfigPath)
	filesystem.addFile(paths.LogPath)
	filesystem.addFile(paths.MetricsPath)
	filesystem.addDir(filepath.Dir(callerOwnedPath))
	filesystem.addFile(callerOwnedPath)
	process := &fakeHostProcess{rawPID: 3333}
	manager := NewProcessLifecycleManager(
		&fakeHostProcessRunner{processes: []HostProcess{process}},
		WithProcessLifecycleCleanupFilesystem(filesystem),
	)
	handle, err := manager.StartProcess(context.Background(), processStartRequestForCleanupPaths(paths))
	if err != nil {
		t.Fatalf("StartProcess() error = %v, want nil", err)
	}

	if err := manager.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle, Paths: paths}); err != nil {
		t.Fatalf("CleanupLiveProcess() error = %v, want nil", err)
	}

	if process.killCalls != 1 || process.waitCalls != 1 || process.signalCalls != 0 {
		t.Fatalf("cleanup calls = signal:%d kill:%d wait:%d, want kill+wait only", process.signalCalls, process.killCalls, process.waitCalls)
	}
	if !reflect.DeepEqual(filesystem.removeCalls, []string{paths.StateDir}) {
		t.Fatalf("RemoveAll calls = %#v, want only validated state dir %q", filesystem.removeCalls, paths.StateDir)
	}
	for _, removed := range []string{paths.StateDir, paths.APISocketPath, paths.ConfigPath, paths.LogPath, paths.MetricsPath} {
		if filesystem.exists(removed) {
			t.Fatalf("cleanup left Firecracker-owned path %q, want removed", removed)
		}
	}
	if !filesystem.exists(callerOwnedPath) {
		t.Fatalf("cleanup removed caller-owned path %q outside state dir", callerOwnedPath)
	}

	if err := manager.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle, Paths: paths}); err != nil {
		t.Fatalf("CleanupLiveProcess(already-finished) error = %v, want nil", err)
	}
	if process.killCalls != 1 || process.waitCalls != 1 {
		t.Fatalf("already-finished cleanup was not idempotent: kill=%d wait=%d", process.killCalls, process.waitCalls)
	}
	if !reflect.DeepEqual(filesystem.removeCalls, []string{paths.StateDir}) {
		t.Fatalf("already-finished cleanup RemoveAll calls = %#v, want no second removal", filesystem.removeCalls)
	}
}

func TestProcessLifecycleManagerDeleteUnknownHandleDoesNotRemoveState(t *testing.T) {
	paths := cleanupPathPlanForTest("fc-delete-unknown")
	filesystem := newFakeCleanupFilesystem()
	filesystem.addDir(paths.StateDir)
	filesystem.addFile(paths.APISocketPath)
	filesystem.addFile(paths.ConfigPath)
	filesystem.addFile(paths.LogPath)
	filesystem.addFile(paths.MetricsPath)
	manager := NewProcessLifecycleManager(nil, WithProcessLifecycleCleanupFilesystem(filesystem))
	unknown := firecracker.ProcessHandleMetadata{ID: "fc-handle-999999999999", Source: processHandleSource}

	if err := manager.DeleteLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: unknown, Paths: paths}); err != nil {
		t.Fatalf("DeleteLiveProcess(unknown) error = %v, want nil", err)
	}
	if !filesystem.exists(paths.StateDir) {
		t.Fatalf("DeleteLiveProcess(unknown) removed state dir %q", paths.StateDir)
	}

	if err := manager.DeleteLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: unknown, Paths: paths}); err != nil {
		t.Fatalf("DeleteLiveProcess(unknown second call) error = %v, want nil", err)
	}
	if len(filesystem.removeCalls) != 0 {
		t.Fatalf("DeleteLiveProcess(unknown) RemoveAll calls = %#v, want none", filesystem.removeCalls)
	}
}

func TestProcessLifecycleManagerCleanupRequiresTrackedStartPaths(t *testing.T) {
	trackedPaths := cleanupPathPlanForTest("fc-cleanup-tracked")
	untrackedPaths := cleanupPathPlanForTest("fc-cleanup-untracked")
	filesystem := newFakeCleanupFilesystem()
	for _, paths := range []firecracker.PathPlan{trackedPaths, untrackedPaths} {
		filesystem.addDir(paths.StateDir)
		filesystem.addFile(paths.APISocketPath)
		filesystem.addFile(paths.ConfigPath)
		filesystem.addFile(paths.LogPath)
		filesystem.addFile(paths.MetricsPath)
	}
	process := &fakeHostProcess{rawPID: 4445}
	manager := NewProcessLifecycleManager(
		&fakeHostProcessRunner{processes: []HostProcess{process}},
		WithProcessLifecycleCleanupFilesystem(filesystem),
	)
	handle, err := manager.StartProcess(context.Background(), processStartRequestForCleanupPaths(trackedPaths))
	if err != nil {
		t.Fatalf("StartProcess() error = %v, want nil", err)
	}

	err = manager.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle, Paths: untrackedPaths})
	if !errors.Is(err, ErrUnsafeCleanupPath) {
		t.Fatalf("CleanupLiveProcess(untracked paths) error = %v, want ErrUnsafeCleanupPath", err)
	}
	if process.killCalls != 0 || process.waitCalls != 0 || process.signalCalls != 0 {
		t.Fatalf("untracked cleanup touched process: signal=%d kill=%d wait=%d", process.signalCalls, process.killCalls, process.waitCalls)
	}
	if len(filesystem.removeCalls) != 0 {
		t.Fatalf("untracked cleanup RemoveAll calls = %#v, want none", filesystem.removeCalls)
	}
	if !filesystem.exists(untrackedPaths.StateDir) {
		t.Fatalf("untracked cleanup removed state dir %q", untrackedPaths.StateDir)
	}

	if err := manager.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle, Paths: trackedPaths}); err != nil {
		t.Fatalf("CleanupLiveProcess(tracked paths) error = %v, want nil", err)
	}
	if !reflect.DeepEqual(filesystem.removeCalls, []string{trackedPaths.StateDir}) {
		t.Fatalf("tracked cleanup RemoveAll calls = %#v, want only %q", filesystem.removeCalls, trackedPaths.StateDir)
	}
	if filesystem.exists(trackedPaths.StateDir) {
		t.Fatalf("tracked cleanup left state dir %q", trackedPaths.StateDir)
	}
	if !filesystem.exists(untrackedPaths.StateDir) {
		t.Fatalf("tracked cleanup removed untracked state dir %q", untrackedPaths.StateDir)
	}
}

func TestProcessLifecycleManagerCleanupRefusesUnsafePathPlans(t *testing.T) {
	safePaths := cleanupPathPlanForTest("fc-refuse-unsafe")
	outsideSocket := filepath.Join(filepath.Dir(safePaths.StateDir), "caller-owned", firecracker.DefaultAPISocketPath)
	unsafeStateDir := filepath.Join(filepath.Dir(safePaths.StateDir), "caller-owned")
	unsafeStatePaths := cleanupPathPlanForStateDir(unsafeStateDir)

	tests := []struct {
		name            string
		paths           firecracker.PathPlan
		unsafeFragments []string
	}{
		{
			name: "support path outside state dir",
			paths: firecracker.PathPlan{
				StateDir:      safePaths.StateDir,
				APISocketPath: outsideSocket,
				ConfigPath:    safePaths.ConfigPath,
				LogPath:       safePaths.LogPath,
				MetricsPath:   safePaths.MetricsPath,
			},
			unsafeFragments: []string{outsideSocket, filepath.Dir(outsideSocket), firecracker.DefaultAPISocketPath},
		},
		{
			name:            "state dir without generated firecracker runtime name",
			paths:           unsafeStatePaths,
			unsafeFragments: []string{unsafeStateDir, "caller-owned"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			process := &fakeHostProcess{rawPID: 4444}
			filesystem := newFakeCleanupFilesystem()
			filesystem.addDir(safePaths.StateDir)
			filesystem.addFile(outsideSocket)
			manager := NewProcessLifecycleManager(
				&fakeHostProcessRunner{processes: []HostProcess{process}},
				WithProcessLifecycleCleanupFilesystem(filesystem),
			)
			handle, err := manager.StartProcess(context.Background(), processStartRequestForCleanupPaths(safePaths))
			if err != nil {
				t.Fatalf("StartProcess() error = %v, want nil", err)
			}

			err = manager.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle, Paths: tt.paths})

			if !errors.Is(err, ErrUnsafeCleanupPath) {
				t.Fatalf("CleanupLiveProcess() error = %v, want ErrUnsafeCleanupPath", err)
			}
			if process.killCalls != 0 || process.waitCalls != 0 || process.signalCalls != 0 {
				t.Fatalf("unsafe cleanup touched process: signal=%d kill=%d wait=%d", process.signalCalls, process.killCalls, process.waitCalls)
			}
			if len(filesystem.removeCalls) != 0 {
				t.Fatalf("unsafe cleanup RemoveAll calls = %#v, want none", filesystem.removeCalls)
			}
			if !filesystem.exists(safePaths.StateDir) {
				t.Fatalf("unsafe cleanup removed state dir %q", safePaths.StateDir)
			}
			assertProcessLifecyclePublicTextRedacted(t, err.Error(), tt.unsafeFragments...)
		})
	}
}

func TestProcessLifecycleManagerCleanupFilesystemErrorsAreSanitized(t *testing.T) {
	paths := cleanupPathPlanForTest("fc-cleanup-error")
	rawErr := errors.New("remove " + paths.StateDir + " with socket " + paths.APISocketPath + " failed OPENAI_API_KEY=sk-live-secret token=ghp_secret")
	filesystem := newFakeCleanupFilesystem()
	filesystem.addDir(paths.StateDir)
	filesystem.removeErr = rawErr
	process := &fakeHostProcess{rawPID: 5555}
	manager := NewProcessLifecycleManager(
		&fakeHostProcessRunner{processes: []HostProcess{process}},
		WithProcessLifecycleCleanupFilesystem(filesystem),
	)
	handle, err := manager.StartProcess(context.Background(), processStartRequestForCleanupPaths(paths))
	if err != nil {
		t.Fatalf("StartProcess() error = %v, want nil", err)
	}

	err = manager.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle, Paths: paths})

	if err == nil {
		t.Fatal("CleanupLiveProcess() error = nil, want filesystem error")
	}
	if !errors.Is(err, rawErr) {
		t.Fatalf("errors.Is(cleanup error, rawErr) = false for %v", err)
	}
	var lifecycleErr *ProcessLifecycleError
	if !errors.As(err, &lifecycleErr) {
		t.Fatalf("errors.As(%T) = false, want true", lifecycleErr)
	}
	if lifecycleErr.Operation != processOperationCleanup {
		t.Fatalf("cleanup operation = %q, want %q", lifecycleErr.Operation, processOperationCleanup)
	}
	assertProcessLifecyclePublicTextRedacted(t, err.Error(),
		paths.StateDir,
		paths.APISocketPath,
		filepath.Dir(paths.StateDir),
		firecracker.DefaultAPISocketPath,
		"OPENAI_API_KEY",
		"sk-live-secret",
		"ghp_secret",
	)
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

func cleanupPathPlanForTest(runtimeID string) firecracker.PathPlan {
	return cleanupPathPlanForStateDir(filepath.Join(os.TempDir(), "hal-firecrackerhost-cleanup-test", runtimeID))
}

func cleanupPathPlanForStateDir(stateDir string) firecracker.PathPlan {
	return firecracker.PathPlan{
		StateDir:      stateDir,
		APISocketPath: filepath.Join(stateDir, firecracker.DefaultAPISocketPath),
		ConfigPath:    filepath.Join(stateDir, firecracker.DefaultConfigPath),
		LogPath:       filepath.Join(stateDir, firecracker.DefaultLogPath),
		MetricsPath:   filepath.Join(stateDir, firecracker.DefaultMetricsPath),
	}
}

func processStartRequestForCleanupPaths(paths firecracker.PathPlan) firecracker.ProcessRunnerStartRequest {
	return firecracker.ProcessRunnerStartRequest{
		Executable: "firecracker",
		Args: []string{
			"--api-sock", paths.APISocketPath,
			"--config-file", paths.ConfigPath,
			"--log-path", paths.LogPath,
			"--metrics-path", paths.MetricsPath,
		},
	}
}

type fakeCleanupFilesystem struct {
	entries     map[string]fakeCleanupFileInfo
	removeCalls []string
	removeErr   error
}

func newFakeCleanupFilesystem() *fakeCleanupFilesystem {
	return &fakeCleanupFilesystem{
		entries: map[string]fakeCleanupFileInfo{},
	}
}

func (filesystem *fakeCleanupFilesystem) Lstat(path string) (os.FileInfo, error) {
	path = filepath.Clean(path)
	if filesystem == nil {
		return nil, os.ErrNotExist
	}
	info, ok := filesystem.entries[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return info, nil
}

func (filesystem *fakeCleanupFilesystem) RemoveAll(path string) error {
	path = filepath.Clean(path)
	filesystem.removeCalls = append(filesystem.removeCalls, path)
	if filesystem.removeErr != nil {
		return filesystem.removeErr
	}
	for existing := range filesystem.entries {
		if existing == path || strings.HasPrefix(existing, path+string(filepath.Separator)) {
			delete(filesystem.entries, existing)
		}
	}
	return nil
}

func (filesystem *fakeCleanupFilesystem) addDir(path string) {
	filesystem.entries[filepath.Clean(path)] = fakeCleanupFileInfo{
		name: filepath.Base(path),
		mode: os.ModeDir | 0o700,
	}
}

func (filesystem *fakeCleanupFilesystem) addFile(path string) {
	filesystem.entries[filepath.Clean(path)] = fakeCleanupFileInfo{
		name: filepath.Base(path),
		mode: 0o600,
	}
}

func (filesystem *fakeCleanupFilesystem) exists(path string) bool {
	_, ok := filesystem.entries[filepath.Clean(path)]
	return ok
}

type fakeCleanupFileInfo struct {
	name string
	mode os.FileMode
}

func (info fakeCleanupFileInfo) Name() string {
	return info.name
}

func (info fakeCleanupFileInfo) Size() int64 {
	return 0
}

func (info fakeCleanupFileInfo) Mode() os.FileMode {
	return info.mode
}

func (info fakeCleanupFileInfo) ModTime() time.Time {
	return time.Time{}
}

func (info fakeCleanupFileInfo) IsDir() bool {
	return info.mode.IsDir()
}

func (info fakeCleanupFileInfo) Sys() any {
	return nil
}
