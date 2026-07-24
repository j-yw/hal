package rootlesspodman

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// DefaultCommandRunner executes the Podman argv constructed by Driver methods.
// Tests normally inject fake runners instead, so normal unit tests do not
// require Podman to be installed.
type DefaultCommandRunner struct{}

func (DefaultCommandRunner) RunLifecycleCommand(ctx context.Context, req CommandRequest) (CommandResult, error) {
	return runDefaultCommand(ctx, req)
}

func (DefaultCommandRunner) RunExecCommand(ctx context.Context, req CommandRequest) (CommandResult, error) {
	return runDefaultExecCommand(ctx, req)
}

func (DefaultCommandRunner) RunCopyCommand(ctx context.Context, req CommandRequest) (CommandResult, error) {
	return runDefaultCommand(ctx, req)
}

func runDefaultCommand(ctx context.Context, req CommandRequest) (CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(req.Args) == 0 || strings.TrimSpace(req.Args[0]) == "" {
		return CommandResult{ExitCode: -1}, fmt.Errorf("podman command args are required")
	}
	cmd := exec.CommandContext(ctx, req.Args[0], req.Args[1:]...)
	if trimmedWorkDir := strings.TrimSpace(req.WorkDir); trimmedWorkDir != "" {
		cmd.Dir = trimmedWorkDir
	}
	cmd.Env = commandEnvironment(req.Env)
	cmd.Stdin = req.Stdin

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = commandWriter(req.Stdout, &stdout)
	cmd.Stderr = commandWriter(req.Stderr, &stderr)

	err := cmd.Run()
	result := CommandResult{
		ExitCode: commandExitCode(err),
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}
	if err != nil && ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, err
}

func runDefaultExecCommand(ctx context.Context, req CommandRequest) (CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(req.Args) == 0 || strings.TrimSpace(req.Args[0]) == "" {
		return CommandResult{ExitCode: -1}, fmt.Errorf("podman command args are required")
	}
	if err := ctx.Err(); err != nil {
		return CommandResult{ExitCode: -1}, err
	}

	cmd := exec.Command(req.Args[0], req.Args[1:]...)
	configureExecProcessGroup(cmd)
	if trimmedWorkDir := strings.TrimSpace(req.WorkDir); trimmedWorkDir != "" {
		cmd.Dir = trimmedWorkDir
	}
	cmd.Env = commandEnvironment(req.Env)
	cmd.Stdin = req.Stdin

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = commandWriter(req.Stdout, &stdout)
	cmd.Stderr = commandWriter(req.Stderr, &stderr)

	if err := cmd.Start(); err != nil {
		return CommandResult{ExitCode: commandExitCode(err)}, err
	}
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	var err error
	select {
	case err = <-waitCh:
	case <-ctx.Done():
		err = terminateExecProcessGroup(cmd, waitCh)
	}
	result := CommandResult{
		ExitCode: commandExitCode(err),
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, err
}

func commandEnvironment(env map[string]string) []string {
	if len(env) == 0 {
		return os.Environ()
	}
	values := os.Environ()
	for _, key := range sortedMapKeys(env) {
		values = append(values, key+"="+env[key])
	}
	return values
}

func commandWriter(dst io.Writer, capture *bytes.Buffer) io.Writer {
	if dst == nil {
		return capture
	}
	return io.MultiWriter(dst, capture)
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
