package rootlesspodman

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

var (
	ErrCopyRunnerRequired          = errors.New("rootless Podman copy runner is required")
	ErrCopySourcePathRequired      = errors.New("rootless Podman copy source path is required")
	ErrCopyDestinationPathRequired = errors.New("rootless Podman copy destination path is required")
)

func (d *Driver) CopyIn(ctx context.Context, req sandboxruntime.CopyRequest) error {
	sourcePath := strings.TrimSpace(req.SourcePath)
	destinationPath := strings.TrimSpace(req.DestinationPath)
	if sourcePath == "" {
		return operationError(OperationCopyIn, CommandResult{}, ErrCopySourcePathRequired)
	}
	if destinationPath == "" {
		return operationError(OperationCopyIn, CommandResult{}, ErrCopyDestinationPathRequired)
	}
	ref, err := containerRef(req.Target)
	if err != nil {
		return operationError(OperationCopyIn, CommandResult{}, err)
	}
	if err := d.runCopyCommand(ctx, CommandRequest{
		Operation: OperationCopyIn,
		Args:      d.copyInPrepareParentArgs(ref, path.Dir(destinationPath)),
	}); err != nil {
		return err
	}

	return d.runCopyCommand(ctx, CommandRequest{
		Operation: OperationCopyIn,
		Args:      d.copyInArgs(ref, sourcePath, destinationPath),
	})
}

func (d *Driver) CopyOut(ctx context.Context, req sandboxruntime.CopyRequest) error {
	sourcePath := strings.TrimSpace(req.SourcePath)
	destinationPath := strings.TrimSpace(req.DestinationPath)
	if sourcePath == "" {
		return operationError(OperationCopyOut, CommandResult{}, ErrCopySourcePathRequired)
	}
	if destinationPath == "" {
		return operationError(OperationCopyOut, CommandResult{}, ErrCopyDestinationPathRequired)
	}
	ref, err := containerRef(req.Target)
	if err != nil {
		return operationError(OperationCopyOut, CommandResult{}, err)
	}

	return d.runCopyCommand(ctx, CommandRequest{
		Operation: OperationCopyOut,
		Args:      d.copyOutArgs(ref, sourcePath, destinationPath),
	})
}

func (d *Driver) runCopyCommand(ctx context.Context, req CommandRequest) error {
	runner, err := d.copyRunnerFor(req.Operation)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	result, err := runner.RunCopyCommand(ctx, req)
	if err != nil || result.ExitCode != 0 {
		return operationError(req.Operation, result, err)
	}
	return nil
}

func (d *Driver) copyRunnerFor(operation string) (CopyCommandRunner, error) {
	if d == nil || d.copyRunner == nil {
		return nil, operationError(operation, CommandResult{}, ErrCopyRunnerRequired)
	}
	return d.copyRunner, nil
}

func (d *Driver) copyInArgs(ref, sourcePath, destinationPath string) []string {
	return []string{d.podmanPath, "cp", sourcePath, containerPath(ref, destinationPath)}
}

func (d *Driver) copyInPrepareParentArgs(ref, parentPath string) []string {
	return []string{d.podmanPath, "exec", ref, "mkdir", "-p", "--", parentPath}
}

func (d *Driver) copyOutArgs(ref, sourcePath, destinationPath string) []string {
	return []string{d.podmanPath, "cp", containerPath(ref, sourcePath), destinationPath}
}

func containerPath(ref, path string) string {
	return ref + ":" + path
}
