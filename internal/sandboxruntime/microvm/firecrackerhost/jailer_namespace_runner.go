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
	namespace      NamespaceProcessFileProvider
	starter        strictJailerNamespaceProcessStarter
	nsenterPath    string
	cleanupTimeout time.Duration
}

// strictJailerNamespaceRunner enters one existing user/network namespace pair
// before execing the foreground Jailer. Unlike NamespaceProcessRunner, it
// never accepts or forwards kernel/rootfs descriptors: staged jail paths are
// the only future asset boundary compatible with Jailer descriptor closing.
type strictJailerNamespaceRunner struct {
	namespace      NamespaceProcessFileProvider
	starter        strictJailerNamespaceProcessStarter
	nsenterPath    string
	cleanupTimeout time.Duration

	mu       sync.Mutex
	retained HostProcess
}

var _ HostProcessRunner = (*strictJailerNamespaceRunner)(nil)

type strictJailerNamespaceProcessStartRequest struct {
	executable     string
	args           []string
	inheritedFiles []*os.File
}

// strictJailerNamespaceProcessStarter is deliberately distinct from
// NamespaceProcessStarter, whose four-descriptor contract remains reserved for
// the legacy namespace+kernel+rootfs path.
type strictJailerNamespaceProcessStarter interface {
	startStrictJailerNamespaceProcess(context.Context, strictJailerNamespaceProcessStartRequest) (HostProcess, error)
}

func newStrictJailerNamespaceRunner(options strictJailerNamespaceRunnerOptions) (*strictJailerNamespaceRunner, error) {
	nsenterPath := strings.TrimSpace(options.nsenterPath)
	cleanupTimeout := options.cleanupTimeout
	if cleanupTimeout == 0 {
		cleanupTimeout = defaultNamespaceProcessCleanupTimeout
	}
	if interfaceValueIsNil(options.namespace) || interfaceValueIsNil(options.starter) ||
		!filepathIsCleanAbsolute(nsenterPath) || cleanupFilesystemRoot(nsenterPath) ||
		cleanupTimeout <= 0 || cleanupTimeout > time.Minute {
		return nil, errStrictJailerNamespaceInvalidConfiguration
	}
	return &strictJailerNamespaceRunner{
		namespace: options.namespace, starter: options.starter, nsenterPath: nsenterPath,
		cleanupTimeout: cleanupTimeout,
	}, nil
}

func (runner *strictJailerNamespaceRunner) configured() bool {
	return runner != nil && !interfaceValueIsNil(runner.namespace) && !interfaceValueIsNil(runner.starter) &&
		filepathIsCleanAbsolute(runner.nsenterPath) && !cleanupFilesystemRoot(runner.nsenterPath) &&
		runner.cleanupTimeout > 0 && runner.cleanupTimeout <= time.Minute
}

// StartHostProcess validates the exact foreground Jailer command, duplicates
// only user/network namespace descriptors, and delegates one nsenter process.
// Environment is required to be explicitly empty and no asset descriptor can
// cross this boundary.
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

	user, network, duplicateErr := runner.namespace.DuplicateForNamespaceProcess()
	if duplicateErr != nil || !validStrictJailerNamespaceFiles(user, network) {
		if closeErr := closeStrictJailerNamespaceFiles(user, network); closeErr != nil {
			return nil, errors.Join(errStrictJailerNamespaceInvalid, errStrictJailerNamespaceCleanupIncomplete)
		}
		return nil, errStrictJailerNamespaceInvalid
	}

	wrapperArgs := []string{
		"--preserve-credentials",
		"--keep-caps",
		"--user=/proc/self/fd/3",
		"--net=/proc/self/fd/4",
		"--",
		command.jailerPath,
	}
	wrapperArgs = append(wrapperArgs, command.args...)
	process, startErr := runner.starter.startStrictJailerNamespaceProcess(ctx, strictJailerNamespaceProcessStartRequest{
		executable:     runner.nsenterPath,
		args:           wrapperArgs,
		inheritedFiles: []*os.File{user, network},
	})
	closeErr := closeStrictJailerNamespaceFiles(user, network)
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
		len(request.inheritedFiles) != 2 || !validStrictJailerNamespaceFiles(request.inheritedFiles[0], request.inheritedFiles[1]) ||
		len(request.args) < 7 || request.args[0] != "--preserve-credentials" || request.args[1] != "--keep-caps" ||
		request.args[2] != "--user=/proc/self/fd/3" || request.args[3] != "--net=/proc/self/fd/4" ||
		request.args[4] != "--" {
		return errStrictJailerNamespaceRequestInvalid
	}
	_, err := parseStrictJailerCommand(firecracker.ProcessRunnerStartRequest{
		Executable:     request.args[5],
		Args:           append([]string(nil), request.args[6:]...),
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
	if killErr != nil || waitErr != nil {
		return errStrictJailerNamespaceCleanupIncomplete
	}
	return nil
}

func validStrictJailerNamespaceFiles(user, network *os.File) bool {
	if user == nil || network == nil || user == network {
		return false
	}
	userFD, networkFD := user.Fd(), network.Fd()
	invalidFD := ^uintptr(0)
	return userFD > 2 && networkFD > 2 && userFD != invalidFD && networkFD != invalidFD && userFD != networkFD
}

func closeStrictJailerNamespaceFiles(files ...*os.File) error {
	seen := make(map[uintptr]struct{}, len(files))
	var result error
	for _, file := range files {
		if file == nil {
			continue
		}
		fd := file.Fd()
		if _, duplicate := seen[fd]; duplicate {
			continue
		}
		seen[fd] = struct{}{}
		result = errors.Join(result, file.Close())
	}
	return result
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
