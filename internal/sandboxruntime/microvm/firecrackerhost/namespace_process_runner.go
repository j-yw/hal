package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"

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

const (
	namespaceProcessUserChildFD    = 3
	namespaceProcessNetworkChildFD = 4
	namespaceProcessKernelChildFD  = 5
	namespaceProcessRootfsChildFD  = 6
)

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

// OSExecNamespaceProcessStarter is the production adapter for the distinct
// namespace wrapper contract. It fails closed on non-Linux platforms.
type OSExecNamespaceProcessStarter struct{}

func NewOSExecNamespaceProcessStarter() OSExecNamespaceProcessStarter {
	return OSExecNamespaceProcessStarter{}
}

type NamespaceProcessRunnerOptions struct {
	Namespace   NamespaceProcessFileProvider
	Starter     NamespaceProcessStarter
	NSenterPath string
}

// NamespaceProcessRunner accepts exactly the two sealed L7 asset descriptors,
// adds exactly one owned user/network descriptor pair, and delegates one
// deterministic nsenter launch without process-global setns.
type NamespaceProcessRunner struct {
	namespace   NamespaceProcessFileProvider
	starter     NamespaceProcessStarter
	nsenterPath string
}

var _ HostProcessRunner = (*NamespaceProcessRunner)(nil)

func NewNamespaceProcessRunner(options NamespaceProcessRunnerOptions) (*NamespaceProcessRunner, error) {
	nsenterPath := strings.TrimSpace(options.NSenterPath)
	if interfaceValueIsNil(options.Namespace) || interfaceValueIsNil(options.Starter) ||
		!filepath.IsAbs(nsenterPath) || filepath.Clean(nsenterPath) != nsenterPath || hasOSExecProcessControl(nsenterPath) {
		return nil, ErrNamespaceProcessInvalidConfiguration
	}
	return &NamespaceProcessRunner{namespace: options.Namespace, starter: options.Starter, nsenterPath: nsenterPath}, nil
}

func (runner *NamespaceProcessRunner) StartHostProcess(ctx context.Context, request firecracker.ProcessRunnerStartRequest) (process HostProcess, retErr error) {
	if runner == nil || interfaceValueIsNil(runner.namespace) || interfaceValueIsNil(runner.starter) {
		return nil, ErrNamespaceProcessInvalidConfiguration
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
		closeNamespaceProcessFiles(user, network)
		return nil, ErrNamespaceProcessNamespaceInvalid
	}
	defer func() {
		if closeNamespaceProcessFiles(user, network) != nil {
			retErr = errors.Join(retErr, ErrNamespaceProcessCleanupIncomplete)
		}
	}()

	wrapperArgs := []string{
		"--user=/proc/self/fd/3",
		"--net=/proc/self/fd/4",
		"--",
		executable,
	}
	wrapperArgs = append(wrapperArgs, args...)
	process, err = runner.starter.StartNamespaceProcess(nonNilContext(ctx), NamespaceProcessStartRequest{
		Executable: runner.nsenterPath,
		Args:       wrapperArgs,
		InheritedFiles: []*os.File{
			user,
			network,
			request.InheritedFiles[0],
			request.InheritedFiles[1],
		},
	})
	if err != nil || interfaceValueIsNil(process) {
		return process, ErrNamespaceProcessStartFailed
	}
	return process, nil
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
