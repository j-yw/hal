package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

var (
	errStrictJailerNamespaceInvalidConfiguration = errors.New("strict Jailer namespace runner configuration is invalid")
	errStrictJailerNamespaceRequestInvalid       = errors.New("strict Jailer namespace request is invalid")
	errStrictJailerNamespaceInvalid              = errors.New("strict Jailer namespace descriptors are invalid")
	errStrictJailerNamespaceStartFailed          = errors.New("strict Jailer namespace start failed")
	errStrictJailerNamespaceCleanupIncomplete    = errors.New("strict Jailer namespace cleanup is incomplete")
)

type strictJailerNamespaceRunnerOptions struct {
	namespace      strictJailerNetworkNamespaceProvider
	starter        strictJailerNamespaceProcessStarter
	cleanupTimeout time.Duration
}

// strictJailerNamespaceRunner enters one existing network namespace before
// execing the foreground Jailer directly. Unlike NamespaceProcessRunner, it
// never enters a user namespace and never forwards namespace or asset
// descriptors to the child. Jailer retains initial-user-namespace root for
// its mount and device setup; staged jail paths are its only asset boundary.
type strictJailerNamespaceRunner struct {
	namespace      strictJailerNetworkNamespaceProvider
	starter        strictJailerNamespaceProcessStarter
	cleanupTimeout time.Duration

	mu       sync.Mutex
	retained HostProcess
}

var _ HostProcessRunner = (*strictJailerNamespaceRunner)(nil)

type strictJailerNamespaceProcessStartRequest struct {
	executable       string
	args             []string
	networkNamespace *os.File
}

// strictJailerNetworkNamespaceProvider exposes one independently owned
// network namespace authority. Its single-file shape cannot express the
// legacy user/network pair or duplicate descriptor ambiguity.
type strictJailerNetworkNamespaceProvider interface {
	DuplicateNetworkNamespaceForStrictJailer() (*os.File, error)
}

// strictJailerNamespaceProcessStarter is deliberately distinct from
// NamespaceProcessStarter, whose four-descriptor contract remains reserved for
// the legacy namespace+kernel+rootfs path.
type strictJailerNamespaceProcessStarter interface {
	startStrictJailerNamespaceProcess(context.Context, strictJailerNamespaceProcessStartRequest) (HostProcess, error)
}

func newStrictJailerNamespaceRunner(options strictJailerNamespaceRunnerOptions) (*strictJailerNamespaceRunner, error) {
	cleanupTimeout := options.cleanupTimeout
	if cleanupTimeout == 0 {
		cleanupTimeout = defaultNamespaceProcessCleanupTimeout
	}
	if interfaceValueIsNil(options.namespace) || interfaceValueIsNil(options.starter) || cleanupTimeout <= 0 || cleanupTimeout > time.Minute {
		return nil, errStrictJailerNamespaceInvalidConfiguration
	}
	return &strictJailerNamespaceRunner{
		namespace: options.namespace, starter: options.starter, cleanupTimeout: cleanupTimeout,
	}, nil
}

func (runner *strictJailerNamespaceRunner) configured() bool {
	return runner != nil && !interfaceValueIsNil(runner.namespace) && !interfaceValueIsNil(runner.starter) &&
		runner.cleanupTimeout > 0 && runner.cleanupTimeout <= time.Minute
}

// StartHostProcess validates the exact foreground Jailer command, duplicates
// one private network namespace descriptor, and delegates direct Jailer exec.
// The namespace descriptor is parent-side authority and is not inherited by
// Jailer. Environment must be empty and no asset descriptor can cross here.
func (runner *strictJailerNamespaceRunner) StartHostProcess(
	ctx context.Context,
	request firecracker.ProcessRunnerStartRequest,
) (HostProcess, error) {
	if !runner.configured() {
		return nil, errStrictJailerNamespaceInvalidConfiguration
	}
	command, err := parseStrictJailerCommand(request)
	if err != nil {
		return nil, errStrictJailerNamespaceRequestInvalid
	}
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	if !interfaceValueIsNil(runner.retained) {
		return nil, errStrictJailerNamespaceCleanupIncomplete
	}

	network, duplicateErr := runner.namespace.DuplicateNetworkNamespaceForStrictJailer()
	if duplicateErr != nil || !validStrictJailerNetworkNamespaceFile(network) {
		if closeErr := closeStrictJailerNetworkNamespaceFile(network); closeErr != nil {
			return nil, errors.Join(errStrictJailerNamespaceInvalid, errStrictJailerNamespaceCleanupIncomplete)
		}
		return nil, errStrictJailerNamespaceInvalid
	}

	process, startErr := runner.starter.startStrictJailerNamespaceProcess(ctx, strictJailerNamespaceProcessStartRequest{
		executable:       command.jailerPath,
		args:             append([]string(nil), command.args...),
		networkNamespace: network,
	})
	closeErr := closeStrictJailerNetworkNamespaceFile(network)
	if startErr == nil && interfaceValueIsNil(process) {
		startErr = errStrictJailerNamespaceStartFailed
	}
	if startErr == nil && closeErr == nil {
		return process, nil
	}

	primary := error(errStrictJailerNamespaceStartFailed)
	if startErr == nil {
		primary = errStrictJailerNamespaceCleanupIncomplete
	} else if closeErr != nil {
		primary = errors.Join(primary, errStrictJailerNamespaceCleanupIncomplete)
	}
	if !interfaceValueIsNil(process) {
		if cleanupErr := runner.terminateAndReap(process); cleanupErr != nil {
			runner.retained = process
			return nil, errors.Join(primary, errStrictJailerNamespaceCleanupIncomplete)
		}
	}
	return nil, primary
}

func validateStrictJailerNamespaceProcessStartRequest(request strictJailerNamespaceProcessStartRequest) error {
	if !filepathIsCleanAbsolute(request.executable) || cleanupFilesystemRoot(request.executable) ||
		!validStrictJailerNetworkNamespaceFile(request.networkNamespace) {
		return errStrictJailerNamespaceRequestInvalid
	}
	_, err := parseStrictJailerCommand(firecracker.ProcessRunnerStartRequest{
		Executable:     request.executable,
		Args:           append([]string(nil), request.args...),
		Environment:    []string{},
		InheritedFiles: []*os.File{},
	})
	return err
}

func (runner *strictJailerNamespaceRunner) retryRetainedProcessCleanup(context.Context) error {
	if runner == nil {
		return errStrictJailerNamespaceInvalidConfiguration
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if interfaceValueIsNil(runner.retained) {
		runner.retained = nil
		return nil
	}
	if err := runner.terminateAndReap(runner.retained); err != nil {
		return errStrictJailerNamespaceCleanupIncomplete
	}
	runner.retained = nil
	return nil
}

func (runner *strictJailerNamespaceRunner) terminateAndReap(process HostProcess) error {
	if runner == nil || interfaceValueIsNil(process) {
		return errStrictJailerNamespaceCleanupIncomplete
	}
	ctx, cancel := context.WithTimeout(context.Background(), runner.cleanupTimeout)
	defer cancel()
	killErr := process.Kill(ctx)
	waitErr := process.Wait(ctx)
	if hostProcessExitObserved(process) {
		return nil
	}
	if killErr != nil || waitErr != nil {
		return errStrictJailerNamespaceCleanupIncomplete
	}
	return nil
}

func validStrictJailerNetworkNamespaceFile(network *os.File) bool {
	if network == nil {
		return false
	}
	networkFD := network.Fd()
	invalidFD := ^uintptr(0)
	return networkFD > 2 && networkFD != invalidFD
}

func closeStrictJailerNetworkNamespaceFile(network *os.File) error {
	if network == nil {
		return nil
	}
	return network.Close()
}

type strictJailerCommand struct {
	jailerPath      string
	runtimeID       string
	firecrackerPath string
	chrootBaseDir   string
	args            []string
	jailPaths       firecracker.PathPlan
}

// parseStrictJailerCommand accepts only the fixed foreground command emitted
// by planStrictJailerLaunch. Jailer options cannot be injected before the
// separator, and Firecracker receives only the existing path flags plus the
// optional leading PCI flag.
func parseStrictJailerCommand(request firecracker.ProcessRunnerStartRequest) (strictJailerCommand, error) {
	if len(request.Environment) != 0 || len(request.InheritedFiles) != 0 {
		return strictJailerCommand{}, errStrictJailerNamespaceRequestInvalid
	}
	jailerPath := strings.TrimSpace(request.Executable)
	if jailerPath != request.Executable || !filepathIsCleanAbsolute(jailerPath) || cleanupFilesystemRoot(jailerPath) {
		return strictJailerCommand{}, errStrictJailerNamespaceRequestInvalid
	}
	args := append([]string(nil), request.Args...)
	if len(args) < 19 ||
		args[0] != "--id" || args[2] != "--exec-file" || args[4] != "--uid" ||
		args[6] != "--gid" || args[8] != "--chroot-base-dir" || args[10] != "--" {
		return strictJailerCommand{}, errStrictJailerNamespaceRequestInvalid
	}
	runtimeID := strings.TrimSpace(args[1])
	firecrackerPath := strings.TrimSpace(args[3])
	chrootBaseDir := strings.TrimSpace(args[9])
	if runtimeID != args[1] || firecrackerPath != args[3] || chrootBaseDir != args[9] ||
		!validStrictJailerRuntimeID(runtimeID) || !filepathIsCleanAbsolute(firecrackerPath) ||
		cleanupFilesystemRoot(firecrackerPath) || firecrackerPath == jailerPath ||
		!filepathIsCleanAbsolute(chrootBaseDir) || cleanupFilesystemRoot(chrootBaseDir) {
		return strictJailerCommand{}, errStrictJailerNamespaceRequestInvalid
	}
	uid64, uidErr := strconv.ParseUint(args[5], 10, 32)
	gid64, gidErr := strconv.ParseUint(args[7], 10, 32)
	if uidErr != nil || gidErr != nil || uid64 == 0 || gid64 == 0 ||
		strconv.FormatUint(uid64, 10) != args[5] || strconv.FormatUint(gid64, 10) != args[7] {
		return strictJailerCommand{}, errStrictJailerNamespaceRequestInvalid
	}
	jailPaths, err := strictJailerPathsFromArgs(args[11:])
	if err != nil {
		return strictJailerCommand{}, errStrictJailerNamespaceRequestInvalid
	}
	return strictJailerCommand{
		jailerPath: jailerPath, runtimeID: runtimeID, firecrackerPath: firecrackerPath,
		chrootBaseDir: chrootBaseDir, args: args, jailPaths: jailPaths,
	}, nil
}

func strictJailerPathsFromArgs(args []string) (firecracker.PathPlan, error) {
	index := 0
	enablePCI := false
	if len(args) > 0 && args[0] == "--enable-pci" {
		index++
		enablePCI = true
	}
	if len(args)-index != 8 || args[index] != "--api-sock" || args[index+2] != "--config-file" ||
		args[index+4] != "--log-path" || args[index+6] != "--metrics-path" {
		return firecracker.PathPlan{}, errStrictJailerNamespaceRequestInvalid
	}
	stateDir := filepath.Dir(args[index+3])
	paths, hasPaths, err := validatedCleanupPathPlan(firecracker.PathPlan{
		StateDir:        stateDir,
		APISocketPath:   args[index+1],
		ConfigPath:      args[index+3],
		LogPath:         args[index+5],
		MetricsPath:     args[index+7],
		VsockSocketPath: filepath.Join(stateDir, "guest.vsock"),
	})
	if err != nil || !hasPaths {
		return firecracker.PathPlan{}, errStrictJailerNamespaceRequestInvalid
	}
	if !equalJailerStrings(args, strictFirecrackerPathArgs(paths, enablePCI)) {
		return firecracker.PathPlan{}, errStrictJailerNamespaceRequestInvalid
	}
	return paths, nil
}
