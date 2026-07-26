package firecrackerhost

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"
	"unicode"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

var (
	// ErrHostProcessExecutableRequired is returned before launch when the raw
	// runner request does not identify a Firecracker executable.
	ErrHostProcessExecutableRequired = errors.New("firecracker executable is required")
	// ErrHostProcessEnvironmentUnsupported is returned before launch when a
	// request attempts host environment delivery. Environment plumbing stays
	// disabled until a later explicit whitelist phase.
	ErrHostProcessEnvironmentUnsupported = errors.New("firecracker host process environment delivery is not supported")
	// ErrHostProcessArgumentInvalid is returned before launch when executable
	// or argument data contains control characters.
	ErrHostProcessArgumentInvalid = errors.New("firecracker host process argument is invalid")
)

// OSExecProcessRunner is the real host process runner for explicitly injected
// Firecracker live starts. Default paths do not construct this runner.
type OSExecProcessRunner struct{}

var _ HostProcessRunner = OSExecProcessRunner{}

// NewOSExecProcessRunner constructs the real os/exec-backed host process
// runner for future explicit adapter injection.
func NewOSExecProcessRunner() OSExecProcessRunner {
	return OSExecProcessRunner{}
}

// StartHostProcess starts a Firecracker host process from the raw runner
// request without inheriting host environment variables.
func (OSExecProcessRunner) StartHostProcess(ctx context.Context, req firecracker.ProcessRunnerStartRequest) (HostProcess, error) {
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	executable, args, err := osExecProcessCommand(req)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(executable, args...)
	cmd.Env = []string{}
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return newOSExecHostProcess(cmd), nil
}

func osExecProcessCommand(req firecracker.ProcessRunnerStartRequest) (string, []string, error) {
	if len(req.Environment) != 0 {
		return "", nil, ErrHostProcessEnvironmentUnsupported
	}
	executable := strings.TrimSpace(req.Executable)
	if executable == "" {
		return "", nil, ErrHostProcessExecutableRequired
	}
	if hasOSExecProcessControl(executable) {
		return "", nil, ErrHostProcessArgumentInvalid
	}
	args := append([]string(nil), req.Args...)
	for _, arg := range args {
		if hasOSExecProcessControl(arg) {
			return "", nil, ErrHostProcessArgumentInvalid
		}
	}
	return executable, args, nil
}

func hasOSExecProcessControl(value string) bool {
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

type osExecHostProcess struct {
	cmd  *exec.Cmd
	done chan struct{}

	mu                   sync.Mutex
	waitErr              error
	terminationRequested bool
}

func newOSExecHostProcess(cmd *exec.Cmd) *osExecHostProcess {
	process := &osExecHostProcess{
		cmd:  cmd,
		done: make(chan struct{}),
	}
	go func() {
		process.waitErr = cmd.Wait()
		close(process.done)
	}()
	return process
}

func (process *osExecHostProcess) Wait(ctx context.Context) error {
	if process == nil || process.done == nil {
		return ErrHostProcessRequired
	}
	ctx = nonNilContext(ctx)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-process.done:
	}

	process.mu.Lock()
	defer process.mu.Unlock()
	if process.terminationRequested && process.waitErr != nil {
		return nil
	}
	return process.waitErr
}

func (process *osExecHostProcess) Signal(ctx context.Context, signal ProcessSignal) error {
	if process == nil || process.cmd == nil || process.cmd.Process == nil {
		return ErrHostProcessRequired
	}
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if signal != ProcessSignalTerminate {
		return nil
	}
	if process.completed() {
		return nil
	}
	signalValue, err := processTerminationSignal()
	if err != nil {
		return err
	}
	if err := process.cmd.Process.Signal(signalValue); err != nil && !process.completed() {
		return err
	}
	process.markTerminationRequested()
	return nil
}

func (process *osExecHostProcess) Kill(ctx context.Context) error {
	if process == nil || process.cmd == nil || process.cmd.Process == nil {
		return ErrHostProcessRequired
	}
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if process.completed() {
		return nil
	}
	if err := process.cmd.Process.Kill(); err != nil && !process.completed() {
		return err
	}
	process.markTerminationRequested()
	return nil
}

func (process *osExecHostProcess) markTerminationRequested() {
	process.mu.Lock()
	defer process.mu.Unlock()
	process.terminationRequested = true
}

func (process *osExecHostProcess) completed() bool {
	if process == nil || process.done == nil {
		return false
	}
	select {
	case <-process.done:
		return true
	default:
		return false
	}
}

func (process *osExecHostProcess) HostPID() int {
	if process == nil || process.cmd == nil || process.cmd.Process == nil {
		return 0
	}
	return process.cmd.Process.Pid
}

func (process *osExecHostProcess) Done() <-chan struct{} {
	if process == nil {
		return nil
	}
	return process.done
}
