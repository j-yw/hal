package firecrackerhost

import (
	"context"
	"errors"
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
