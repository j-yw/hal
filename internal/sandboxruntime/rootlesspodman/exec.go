package rootlesspodman

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

var (
	ErrExecRunnerRequired = errors.New("rootless Podman exec runner is required")
	ErrExecArgsRequired   = errors.New("rootless Podman exec args are required")
)

func (d *Driver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	commandArgs := cloneStringSlice(req.Args)
	if len(commandArgs) == 0 {
		return nil, operationError(OperationExec, CommandResult{}, ErrExecArgsRequired)
	}
	ref, err := containerRef(req.Target)
	if err != nil {
		return nil, operationError(OperationExec, CommandResult{}, err)
	}

	result, err := d.runExecCommand(ctx, CommandRequest{
		Operation: OperationExec,
		Args:      d.execArgs(ref, commandArgs, req.Env, req.WorkDir, req.Stdin != nil),
		Env:       cloneStringMap(req.Env),
		WorkDir:   req.WorkDir,
		Stdin:     req.Stdin,
		Stdout:    req.Stdout,
		Stderr:    req.Stderr,
	})
	execResult := &sandboxruntime.ExecResult{ExitCode: result.ExitCode}
	if err != nil {
		return execResult, err
	}
	return execResult, nil
}

func (d *Driver) runExecCommand(ctx context.Context, req CommandRequest) (CommandResult, error) {
	runner, err := d.execRunnerFor(req.Operation)
	if err != nil {
		return CommandResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return CommandResult{ExitCode: -1}, operationError(req.Operation, CommandResult{ExitCode: -1}, err)
	}

	result, err := runner.RunExecCommand(ctx, req)
	if err != nil || result.ExitCode != 0 {
		return result, operationError(req.Operation, result, err)
	}
	return result, nil
}

func (d *Driver) execRunnerFor(operation string) (ExecCommandRunner, error) {
	if d == nil || d.execRunner == nil {
		return nil, operationError(operation, CommandResult{}, ErrExecRunnerRequired)
	}
	return d.execRunner, nil
}

func (d *Driver) execArgs(ref string, commandArgs []string, env map[string]string, workDir string, interactive bool) []string {
	args := []string{d.podmanPath, "exec"}
	if interactive {
		args = append(args, "--interactive")
	}
	if trimmedWorkDir := strings.TrimSpace(workDir); trimmedWorkDir != "" {
		args = append(args, "--workdir", trimmedWorkDir)
	}
	for _, key := range sortedMapKeys(env) {
		args = append(args, "--env", key+"="+env[key])
	}
	args = append(args, ref)
	args = append(args, commandArgs...)
	return args
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
