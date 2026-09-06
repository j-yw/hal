package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestL5StopEscalatesTermToKillAndReapsWithinIndependentBound(t *testing.T) {
	process := &l5EscalationProcess{
		termWait: make(chan struct{}),
		killWait: make(chan struct{}),
	}
	manager := NewProcessLifecycleManager(
		l5SingleProcessRunner{process: process},
		WithProcessLifecycleTerminationGrace(10*time.Millisecond),
		WithProcessLifecycleCleanupTimeout(time.Second),
	)
	handle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{Executable: "firecracker"})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	if err := manager.StopLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle}); err != nil {
		t.Fatalf("StopLiveProcess() error = %v", err)
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.signalCalls != 1 || process.killCalls != 1 || process.waitCalls < 2 {
		t.Fatalf("calls signal=%d kill=%d wait=%d, want TERM, timed wait, KILL, reap", process.signalCalls, process.killCalls, process.waitCalls)
	}
}

func TestL5CanceledCallerCannotPreventOwnedCleanup(t *testing.T) {
	process := &l5EscalationProcess{
		termWait: make(chan struct{}),
		killWait: make(chan struct{}),
	}
	close(process.killWait)
	manager := NewProcessLifecycleManager(
		l5SingleProcessRunner{process: process},
		WithProcessLifecycleTerminationGrace(time.Millisecond),
		WithProcessLifecycleCleanupTimeout(time.Second),
	)
	handle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{Executable: "firecracker"})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.CleanupLiveProcess(ctx, firecracker.LiveProcessRequest{Handle: handle}); err != nil {
		t.Fatalf("CleanupLiveProcess(canceled caller) error = %v", err)
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.killCalls != 1 || process.waitCalls == 0 {
		t.Fatalf("calls kill=%d wait=%d, want independent kill and reap", process.killCalls, process.waitCalls)
	}
}

func TestL5FailedKillDoesNotMarkProcessTerminal(t *testing.T) {
	process := &l5FailedStopProcess{}
	manager := NewProcessLifecycleManager(
		l5SingleProcessRunner{process: process},
		WithProcessLifecycleTerminationGrace(time.Millisecond),
		WithProcessLifecycleCleanupTimeout(20*time.Millisecond),
	)
	handle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{Executable: "firecracker"})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	if err := manager.StopLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: handle}); err == nil {
		t.Fatal("StopLiveProcess() error = nil, want failed termination")
	}
	if _, _, active := manager.lookupActiveProcess(handle); !active {
		t.Fatal("failed kill/wait incorrectly marked the process terminal")
	}
}

func TestL5StopRejectsProcessHandleOwnedByAnotherRuntime(t *testing.T) {
	runtimeAPaths := cleanupPathPlanForTest("fc-runtime-a")
	runtimeBPaths := cleanupPathPlanForTest("fc-runtime-b")
	runtimeAProcess := &fakeHostProcess{rawPID: 1111}
	runtimeBProcess := &fakeHostProcess{rawPID: 2222}
	manager := NewProcessLifecycleManager(&fakeHostProcessRunner{
		processes: []HostProcess{runtimeAProcess, runtimeBProcess},
	})
	if _, err := manager.StartProcess(context.Background(), processStartRequestForCleanupPaths(runtimeAPaths)); err != nil {
		t.Fatalf("StartProcess(runtime A) error = %v", err)
	}
	runtimeBHandle, err := manager.StartProcess(context.Background(), processStartRequestForCleanupPaths(runtimeBPaths))
	if err != nil {
		t.Fatalf("StartProcess(runtime B) error = %v", err)
	}

	err = manager.StopLiveProcess(context.Background(), firecracker.LiveProcessRequest{
		Handle: runtimeBHandle,
		Paths:  runtimeAPaths,
	})
	if !errors.Is(err, ErrUnsafeCleanupPath) {
		t.Fatalf("StopLiveProcess(runtime A paths with runtime B handle) error = %v, want ErrUnsafeCleanupPath", err)
	}
	if runtimeAProcess.signalCalls != 0 || runtimeAProcess.waitCalls != 0 || runtimeAProcess.killCalls != 0 {
		t.Fatalf("mismatched stop touched runtime A process: signal=%d wait=%d kill=%d", runtimeAProcess.signalCalls, runtimeAProcess.waitCalls, runtimeAProcess.killCalls)
	}
	if runtimeBProcess.signalCalls != 0 || runtimeBProcess.waitCalls != 0 || runtimeBProcess.killCalls != 0 {
		t.Fatalf("mismatched stop touched runtime B process: signal=%d wait=%d kill=%d", runtimeBProcess.signalCalls, runtimeBProcess.waitCalls, runtimeBProcess.killCalls)
	}
	var lifecycleErr *ProcessLifecycleError
	if !errors.As(err, &lifecycleErr) || lifecycleErr.Operation != processOperationStop {
		t.Fatalf("mismatched stop error = %#v, want sanitized stop lifecycle error", err)
	}

	err = manager.StopLiveProcess(context.Background(), firecracker.LiveProcessRequest{Handle: runtimeBHandle})
	if !errors.Is(err, ErrUnsafeCleanupPath) {
		t.Fatalf("StopLiveProcess(runtime B handle without owned paths) error = %v, want ErrUnsafeCleanupPath", err)
	}
	if runtimeBProcess.signalCalls != 0 || runtimeBProcess.waitCalls != 0 || runtimeBProcess.killCalls != 0 {
		t.Fatalf("pathless stop touched runtime B process: signal=%d wait=%d kill=%d", runtimeBProcess.signalCalls, runtimeBProcess.waitCalls, runtimeBProcess.killCalls)
	}

	if err := manager.StopLiveProcess(context.Background(), firecracker.LiveProcessRequest{
		Handle: runtimeBHandle,
		Paths:  runtimeBPaths,
	}); err != nil {
		t.Fatalf("StopLiveProcess(runtime B matching ownership) error = %v", err)
	}
	if runtimeBProcess.signalCalls != 1 || runtimeBProcess.waitCalls != 1 || runtimeBProcess.killCalls != 0 {
		t.Fatalf("matching stop calls: signal=%d wait=%d kill=%d, want signal+wait only", runtimeBProcess.signalCalls, runtimeBProcess.waitCalls, runtimeBProcess.killCalls)
	}
}

func TestL5TerminalGenerationCannotAuthorizeCleanupWhileNewerGenerationIsActive(t *testing.T) {
	stateDir := t.TempDir()
	paths := firecracker.PathPlan{
		StateDir:        stateDir,
		APISocketPath:   filepath.Join(stateDir, firecracker.DefaultAPISocketPath),
		ConfigPath:      filepath.Join(stateDir, firecracker.DefaultConfigPath),
		LogPath:         filepath.Join(stateDir, firecracker.DefaultLogPath),
		MetricsPath:     filepath.Join(stateDir, firecracker.DefaultMetricsPath),
		VsockSocketPath: filepath.Join(stateDir, "guest.vsock"),
	}
	manager := NewProcessLifecycleManager(nil)
	manager.processes = map[string]*trackedProcess{
		"terminal": {
			paths:    paths,
			hasPaths: true,
			finished: true,
		},
		"active": {
			paths:    paths,
			hasPaths: true,
			process:  &l5FailedStopProcess{},
		},
	}
	if manager.hasTerminalProcessForPaths(paths, privateStateDirIdentity{}, false) {
		t.Fatal("terminal generation authorized cleanup while a matching generation remained active")
	}
}

func TestL5LiveProcessTerminalVerificationRequiresObservedExactGeneration(t *testing.T) {
	done := make(chan struct{})
	manager := NewProcessLifecycleManager(l5SingleProcessRunner{
		process: &l5ObservedExitedProcess{done: done},
	})
	handle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable: "firecracker",
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	request := firecracker.LiveProcessRequest{Handle: handle}
	if manager.LiveProcessTerminated(request) {
		t.Fatal("LiveProcessTerminated() = true before process exit")
	}
	if manager.LiveProcessTerminated(firecracker.LiveProcessRequest{
		Handle: firecracker.ProcessHandleMetadata{
			ID:     "fc-handle-999999999999",
			Source: handle.Source,
		},
	}) {
		t.Fatal("LiveProcessTerminated() = true for unknown process generation")
	}
	close(done)
	if !manager.LiveProcessTerminated(request) {
		t.Fatal("LiveProcessTerminated() = false after observed exact process exit")
	}
	if !manager.LiveProcessTerminated(request) {
		t.Fatal("LiveProcessTerminated() did not preserve terminal proof")
	}
}

func TestL5CleanupRejectsSubstitutedStateDirectoryIdentity(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "hal-l5-cleanup-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	paths, err := firecracker.PlanPaths(firecracker.PathPlanRequest{
		RuntimeID: "fc-cleanup-identity", BaseStateDir: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	process := &l5EscalationProcess{termWait: make(chan struct{}), killWait: make(chan struct{})}
	manager := NewProcessLifecycleManager(
		l5SingleProcessRunner{process: process},
		withProcessLifecycleProductionVsock(),
		WithProcessLifecycleCleanupTimeout(time.Second),
	)
	handle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable: "firecracker",
		Args: []string{
			"--api-sock", paths.APISocketPath,
			"--config-file", paths.ConfigPath,
			"--log-path", paths.LogPath,
			"--metrics-path", paths.MetricsPath,
		},
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	original := paths.StateDir + "-original"
	if err := os.Rename(paths.StateDir, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(paths.StateDir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = manager.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{
		Handle: handle, Paths: paths,
	})
	if err == nil {
		t.Fatal("CleanupLiveProcess() error = nil, want substituted identity rejection")
	}
	if data, readErr := os.ReadFile(sentinel); readErr != nil || string(data) != "preserve" {
		t.Fatalf("replacement state was modified: data=%q error=%v", data, readErr)
	}
}

func TestL5CleanupRemovesOnlyPinnedOwnedState(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "hal-l5-cleanup-owned-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	paths, err := firecracker.PlanPaths(firecracker.PathPlanRequest{
		RuntimeID: "fc-cleanup-owned", BaseStateDir: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	process := &l5EscalationProcess{termWait: make(chan struct{}), killWait: make(chan struct{})}
	manager := NewProcessLifecycleManager(
		l5SingleProcessRunner{process: process},
		withProcessLifecycleProductionVsock(),
		WithProcessLifecycleCleanupTimeout(time.Second),
	)
	handle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable: "firecracker",
		Args: []string{
			"--api-sock", paths.APISocketPath,
			"--config-file", paths.ConfigPath,
			"--log-path", paths.LogPath,
			"--metrics-path", paths.MetricsPath,
		},
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	for _, path := range []string{paths.ConfigPath, paths.LogPath, paths.MetricsPath} {
		if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{
		Handle: handle, Paths: paths,
	}); err != nil {
		t.Fatalf("CleanupLiveProcess() error = %v", err)
	}
	if _, err := os.Lstat(paths.StateDir); !os.IsNotExist(err) {
		t.Fatalf("state directory still exists or inspection failed: %v", err)
	}
}

func TestL5DeleteRemovesPinnedStateAfterObservedNonzeroProcessExit(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "hal-l5-cleanup-exited-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	paths, err := firecracker.PlanPaths(firecracker.PathPlanRequest{
		RuntimeID: "fc-cleanup-exited", BaseStateDir: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.ConfigPath, paths.LogPath, paths.MetricsPath} {
		if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	close(done)
	process := &l5ObservedExitedProcess{
		done:    done,
		waitErr: errors.New("process exited with status 7"),
	}
	manager := NewProcessLifecycleManager(
		l5SingleProcessRunner{process: process},
		withProcessLifecycleProductionVsock(),
		WithProcessLifecycleCleanupTimeout(time.Second),
	)
	handle, err := manager.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{
		Executable: "firecracker",
		Args: []string{
			"--api-sock", paths.APISocketPath,
			"--config-file", paths.ConfigPath,
			"--log-path", paths.LogPath,
			"--metrics-path", paths.MetricsPath,
		},
	})
	if err != nil {
		t.Fatalf("StartProcess() error = %v", err)
	}
	if err := manager.DeleteLiveProcess(context.Background(), firecracker.LiveProcessRequest{
		Handle: handle,
		Paths:  paths,
	}); err != nil {
		t.Fatalf("DeleteLiveProcess() error = %v, want observed exit to count as reaped: nil", err)
	}
	if _, err := os.Lstat(paths.StateDir); !os.IsNotExist(err) {
		t.Fatalf("state directory still exists or inspection failed: %v", err)
	}
	if _, _, active := manager.lookupActiveProcess(handle); active {
		t.Fatal("observed exited process remained active after delete")
	}
}

type l5SingleProcessRunner struct {
	process HostProcess
}

func (runner l5SingleProcessRunner) StartHostProcess(context.Context, firecracker.ProcessRunnerStartRequest) (HostProcess, error) {
	return runner.process, nil
}

type l5EscalationProcess struct {
	mu          sync.Mutex
	signalCalls int
	killCalls   int
	waitCalls   int
	termWait    chan struct{}
	killWait    chan struct{}
	killed      bool
}

type l5FailedStopProcess struct{}

type l5ObservedExitedProcess struct {
	done    <-chan struct{}
	waitErr error
}

func (*l5ObservedExitedProcess) Signal(context.Context, ProcessSignal) error { return nil }
func (*l5ObservedExitedProcess) Kill(context.Context) error                  { return nil }
func (process *l5ObservedExitedProcess) Wait(context.Context) error          { return process.waitErr }
func (*l5ObservedExitedProcess) HostPID() int                                { return 4242 }
func (process *l5ObservedExitedProcess) Done() <-chan struct{}               { return process.done }

func (*l5FailedStopProcess) Signal(context.Context, ProcessSignal) error {
	return errors.New("term failed")
}
func (*l5FailedStopProcess) Kill(context.Context) error {
	return errors.New("kill failed")
}
func (*l5FailedStopProcess) Wait(context.Context) error {
	return errors.New("wait must not prove reap")
}

func (process *l5EscalationProcess) Signal(context.Context, ProcessSignal) error {
	process.mu.Lock()
	process.signalCalls++
	process.mu.Unlock()
	return nil
}

func (process *l5EscalationProcess) Kill(context.Context) error {
	process.mu.Lock()
	process.killCalls++
	process.killed = true
	select {
	case <-process.killWait:
	default:
		close(process.killWait)
	}
	process.mu.Unlock()
	return nil
}

func (process *l5EscalationProcess) Wait(ctx context.Context) error {
	process.mu.Lock()
	process.waitCalls++
	killed := process.killed
	process.mu.Unlock()
	wait := process.termWait
	if killed {
		wait = process.killWait
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-wait:
		return nil
	}
}

var _ = errors.Is
