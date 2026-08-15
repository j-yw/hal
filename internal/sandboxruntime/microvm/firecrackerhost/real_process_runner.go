package firecrackerhost

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
type OSExecProcessRunner struct {
	startCommand func(*exec.Cmd) error
}

// OSExecNamespaceProcessStarter is the production adapter for the distinct
// namespace wrapper contract. It fails closed on non-Linux platforms.
type OSExecNamespaceProcessStarter struct {
	startCommand func(*exec.Cmd) error
}

var _ HostProcessRunner = OSExecProcessRunner{}

// NewOSExecProcessRunner constructs the real os/exec-backed host process
// runner for future explicit adapter injection.
func NewOSExecProcessRunner() OSExecProcessRunner {
	return OSExecProcessRunner{}
}

func NewOSExecNamespaceProcessStarter() OSExecNamespaceProcessStarter {
	return OSExecNamespaceProcessStarter{}
}

// StartNamespaceProcess launches the explicit L7 namespace wrapper. Unlike
// StartHostProcess, this narrow contract requires exactly the fixed
// user/network/kernel/rootfs descriptor layout.
func (starter OSExecNamespaceProcessStarter) StartNamespaceProcess(ctx context.Context, request NamespaceProcessStartRequest) (HostProcess, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrNamespaceProcessUnsupported
	}
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateNamespaceProcessStartRequest(request); err != nil {
		return nil, err
	}
	command := exec.Command(request.Executable, request.Args...)
	command.Env = []string{}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = append([]*os.File(nil), request.InheritedFiles...)
	startCommand := starter.startCommand
	if startCommand == nil {
		startCommand = func(command *exec.Cmd) error {
			return startOSExecCommandWithPrivateUmask(command.Start)
		}
	}
	if err := startCommand(command); err != nil {
		return nil, ErrNamespaceProcessStartFailed
	}
	return newOSExecHostProcess(command), nil
}

func validateNamespaceProcessStartRequest(request NamespaceProcessStartRequest) error {
	if !filepathIsCleanAbsolute(request.Executable) || len(request.InheritedFiles) != 4 || len(request.Args) < 6 ||
		request.Args[0] != "--preserve-credentials" || request.Args[1] != "--keep-caps" ||
		request.Args[2] != "--user=/proc/self/fd/3" || request.Args[3] != "--net=/proc/self/fd/4" ||
		request.Args[4] != "--" || request.Args[5] == "" {
		return ErrNamespaceProcessRequestInvalid
	}
	for _, arg := range request.Args {
		if hasOSExecProcessControl(arg) {
			return ErrNamespaceProcessRequestInvalid
		}
	}
	seen := make(map[uintptr]struct{}, len(request.InheritedFiles))
	for _, file := range request.InheritedFiles {
		if file == nil || file.Fd() <= 2 {
			return ErrNamespaceProcessRequestInvalid
		}
		if _, duplicate := seen[file.Fd()]; duplicate {
			return ErrNamespaceProcessRequestInvalid
		}
		seen[file.Fd()] = struct{}{}
	}
	return nil
}

func filepathIsCleanAbsolute(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && !hasOSExecProcessControl(value)
}

// StartHostProcess starts a Firecracker host process from the raw runner
// request without inheriting host environment variables.
func (runner OSExecProcessRunner) StartHostProcess(ctx context.Context, req firecracker.ProcessRunnerStartRequest) (HostProcess, error) {
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
	cmd.ExtraFiles = append([]*os.File(nil), req.InheritedFiles...)

	startCommand := runner.startCommand
	if startCommand == nil {
		startCommand = func(command *exec.Cmd) error {
			return startOSExecCommandWithPrivateUmask(command.Start)
		}
	}
	if err := startCommand(cmd); err != nil {
		return nil, err
	}
	return newOSExecHostProcess(cmd), nil
}

func osExecProcessCommand(req firecracker.ProcessRunnerStartRequest) (string, []string, error) {
	if len(req.Environment) != 0 {
		return "", nil, ErrHostProcessEnvironmentUnsupported
	}
	if len(req.InheritedFiles) != 0 && len(req.InheritedFiles) != 2 {
		return "", nil, ErrHostProcessArgumentInvalid
	}
	for _, file := range req.InheritedFiles {
		if file == nil {
			return "", nil, ErrHostProcessArgumentInvalid
		}
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
