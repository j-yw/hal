package firecrackerhost

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

// This private method does not widen the legacy exported namespace starter.
// The pair's launch duplicates are consumed only by the locked creating thread
// and never inherited by Jailer, which closes inherited descriptors itself.
func (starter OSExecNamespaceProcessStarter) startStrictJailerNamespaceProcess(
	ctx context.Context,
	request strictJailerNamespaceProcessStartRequest,
) (process HostProcess, resultErr error) {
	if runtime.GOOS != "linux" {
		return nil, errStrictJailerNamespaceInvalidConfiguration
	}
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateStrictJailerNamespaceProcessStartRequest(request); err != nil {
		return nil, errStrictJailerNamespaceRequestInvalid
	}
	parsed, err := parseStrictJailerCommand(firecracker.ProcessRunnerStartRequest{Executable: request.executable, Args: request.args})
	if err != nil {
		return nil, errStrictJailerNamespaceRequestInvalid
	}
	lease, err := request.executables.duplicateForLaunch(parsed)
	if err != nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	defer func() {
		if err := lease.close(); err != nil {
			resultErr = errors.Join(resultErr, errStrictJailerNamespaceCleanupIncomplete)
		}
	}()
	if err := prepareStrictJailerNetworkNamespaceForExec(request.networkNamespace); err != nil {
		return nil, errStrictJailerNamespaceStartFailed
	}
	command := exec.Command(request.executable, request.args...)
	command.Env = []string{}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{}
	err = request.cgroup.withLaunchFD(ctx, parsed.runtimeID, func(cgroup *os.File) error {
		if configureStrictJailerCgroup(command, cgroup) != nil {
			return errStrictJailerNamespaceStartFailed
		}
		if ctx.Err() != nil {
			return errStrictJailerNamespaceStartFailed
		}
		if starter.startCommand == nil {
			var err error
			process, err = startStrictJailerOSExecCommand(command, request.networkNamespace, lease)
			return err
		}
		if err := starter.startCommand(command); err != nil {
			return errStrictJailerNamespaceStartFailed
		}
		process = newOSExecHostProcess(command)
		return nil
	})
	if err != nil {
		return process, errStrictJailerNamespaceStartFailed
	}
	return process, nil
}
