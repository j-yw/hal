package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

var (
	ErrNamespaceProcessInvalidConfiguration = errors.New("Firecracker namespace process invalid configuration")
	ErrNamespaceProcessAssetsInvalid        = errors.New("Firecracker namespace process assets invalid")
	ErrNamespaceProcessNamespaceInvalid     = errors.New("Firecracker namespace process namespace invalid")
	ErrNamespaceProcessRequestInvalid       = errors.New("Firecracker namespace process request invalid")
	ErrNamespaceProcessStartFailed          = errors.New("Firecracker namespace process start failed")
	ErrNamespaceProcessCleanupIncomplete    = errors.New("Firecracker namespace process cleanup incomplete")
	ErrNamespaceProcessUnsupported          = errors.New("Firecracker namespace process unsupported")
)

const defaultNamespaceProcessCleanupTimeout = 5 * time.Second

// NamespaceProcessFileProvider creates one independently owned user/network
// namespace descriptor pair for one process launch. Implementations must not
// return their retained session descriptors directly.
type NamespaceProcessFileProvider interface {
	DuplicateForNamespaceProcess() (*os.File, *os.File, error)
}

// NamespaceProcessStartRequest is the distinct live-only launch contract for
// the namespace wrapper. Its four files always map to user, network, kernel,
// and rootfs at child descriptors 3, 4, 5, and 6 respectively.
type NamespaceProcessStartRequest struct {
	Executable     string
	Args           []string
	InheritedFiles []*os.File
}

// NamespaceProcessStarter starts the explicit namespace wrapper. It is kept
// separate from the ordinary Firecracker runner so the default 0/2 inherited
// file contract never accepts a generic four-file request.
type NamespaceProcessStarter interface {
	StartNamespaceProcess(context.Context, NamespaceProcessStartRequest) (HostProcess, error)
}

type NamespaceProcessRunnerOptions struct {
	Namespace   NamespaceProcessFileProvider
	Starter     NamespaceProcessStarter
	NSenterPath string
	// CleanupTimeout bounds exact partial-process termination and reap using an
	// independent context. Zero selects the package default.
	CleanupTimeout time.Duration
}

// NamespaceProcessRunner accepts exactly the two sealed L7 asset descriptors,
// adds exactly one owned user/network descriptor pair, and delegates one
// deterministic nsenter launch without process-global setns.
type NamespaceProcessRunner struct {
	namespace      NamespaceProcessFileProvider
	starter        NamespaceProcessStarter
	nsenterPath    string
	cleanupTimeout time.Duration
	mu             sync.Mutex
	retained       HostProcess
}

var _ HostProcessRunner = (*NamespaceProcessRunner)(nil)

func NewNamespaceProcessRunner(options NamespaceProcessRunnerOptions) (*NamespaceProcessRunner, error) {
	nsenterPath := strings.TrimSpace(options.NSenterPath)
	cleanupTimeout := options.CleanupTimeout
	if cleanupTimeout == 0 {
		cleanupTimeout = defaultNamespaceProcessCleanupTimeout
	}
	if interfaceValueIsNil(options.Namespace) || interfaceValueIsNil(options.Starter) ||
		!filepath.IsAbs(nsenterPath) || filepath.Clean(nsenterPath) != nsenterPath || hasOSExecProcessControl(nsenterPath) ||
		cleanupTimeout <= 0 || cleanupTimeout > time.Minute {
		return nil, ErrNamespaceProcessInvalidConfiguration
	}
	return &NamespaceProcessRunner{namespace: options.Namespace, starter: options.Starter, nsenterPath: nsenterPath, cleanupTimeout: cleanupTimeout}, nil
}

func (runner *NamespaceProcessRunner) StartHostProcess(ctx context.Context, request firecracker.ProcessRunnerStartRequest) (HostProcess, error) {
	if runner == nil || interfaceValueIsNil(runner.namespace) || interfaceValueIsNil(runner.starter) {
		return nil, ErrNamespaceProcessInvalidConfiguration
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if !interfaceValueIsNil(runner.retained) {
		return nil, ErrNamespaceProcessCleanupIncomplete
	}
	if len(request.InheritedFiles) != 2 {
		return nil, ErrNamespaceProcessAssetsInvalid
	}
	for _, file := range request.InheritedFiles {
		if file == nil {
			return nil, ErrNamespaceProcessAssetsInvalid
		}
	}
	executable, args, err := osExecProcessCommand(request)
	if err != nil {
		return nil, ErrNamespaceProcessRequestInvalid
	}
	user, network, err := runner.namespace.DuplicateForNamespaceProcess()
	if err != nil || !validNamespaceProcessFiles(user, network, request.InheritedFiles) {
		if closeErr := closeNamespaceProcessFiles(user, network); closeErr != nil {
			return nil, errors.Join(ErrNamespaceProcessNamespaceInvalid, ErrNamespaceProcessCleanupIncomplete)
		}
		return nil, ErrNamespaceProcessNamespaceInvalid
	}
	wrapperArgs := []string{
		"--preserve-credentials",
		"--keep-caps",
		"--user=/proc/self/fd/3",
		"--net=/proc/self/fd/4",
		"--",
		executable,
	}
	wrapperArgs = append(wrapperArgs, args...)
	process, startErr := runner.starter.StartNamespaceProcess(nonNilContext(ctx), NamespaceProcessStartRequest{
		Executable: runner.nsenterPath,
		Args:       wrapperArgs,
		InheritedFiles: []*os.File{
			user,
			network,
			request.InheritedFiles[0],
			request.InheritedFiles[1],
		},
	})
	closeErr := closeNamespaceProcessFiles(user, network)
	if startErr == nil && interfaceValueIsNil(process) {
		startErr = ErrNamespaceProcessStartFailed
	}
	if startErr == nil && closeErr == nil {
		return process, nil
	}
	primary := error(ErrNamespaceProcessStartFailed)
	if startErr == nil {
		primary = ErrNamespaceProcessCleanupIncomplete
	} else if closeErr != nil {
		primary = errors.Join(primary, ErrNamespaceProcessCleanupIncomplete)
	}
	if !interfaceValueIsNil(process) {
		if cleanupErr := runner.terminateAndReap(process); cleanupErr != nil {
			runner.retained = process
			return nil, errors.Join(primary, ErrNamespaceProcessCleanupIncomplete)
		}
	}
	return nil, primary
}

// RetryRetainedProcessCleanup retries exact termination for a partial process
// whose first bounded containment attempt was inconclusive. No new start is
// admitted until this returns nil.
func (runner *NamespaceProcessRunner) RetryRetainedProcessCleanup(context.Context) error {
	if runner == nil {
		return ErrNamespaceProcessInvalidConfiguration
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if interfaceValueIsNil(runner.retained) {
		runner.retained = nil
		return nil
	}
	if err := runner.terminateAndReap(runner.retained); err != nil {
		return ErrNamespaceProcessCleanupIncomplete
	}
	runner.retained = nil
	return nil
}

func (runner *NamespaceProcessRunner) terminateAndReap(process HostProcess) error {
	if runner == nil || interfaceValueIsNil(process) {
		return ErrNamespaceProcessCleanupIncomplete
	}
	ctx, cancel := context.WithTimeout(context.Background(), runner.cleanupTimeout)
	defer cancel()
	killErr := process.Kill(ctx)
	waitErr := process.Wait(ctx)
	if killErr != nil || waitErr != nil {
		return ErrNamespaceProcessCleanupIncomplete
	}
	return nil
}

func validNamespaceProcessFiles(user, network *os.File, assets []*os.File) bool {
	if user == nil || network == nil || user == network || user.Fd() <= 2 || network.Fd() <= 2 || user.Fd() == network.Fd() {
		return false
	}
	seen := map[uintptr]bool{user.Fd(): true, network.Fd(): true}
	for _, file := range assets {
		if file == nil || file.Fd() <= 2 || seen[file.Fd()] {
			return false
		}
		seen[file.Fd()] = true
	}
	return true
}

func closeNamespaceProcessFiles(files ...*os.File) error {
	var result error
	for _, file := range files {
		if file != nil {
			result = errors.Join(result, file.Close())
		}
	}
	return result
}

func interfaceValueIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
