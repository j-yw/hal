package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
)

// DaytonaProvider implements Provider by shelling out to the daytona CLI.
type DaytonaProvider struct {
	APIKey string

	// cmdContext builds an *exec.Cmd. Defaults to exec.CommandContext.
	// Override in tests to capture args without running the real CLI.
	cmdContext func(ctx context.Context, name string, args ...string) *exec.Cmd
}

// commandContext returns the configured command builder, defaulting to
// exec.CommandContext.
func (d *DaytonaProvider) commandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	if d.cmdContext != nil {
		return d.cmdContext(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...)
}

// buildCreateArgs constructs the argument list for daytona create.
// The env map keys are sorted for deterministic ordering.
func buildCreateArgs(name string, env map[string]string) []string {
	args := []string{"create", "--snapshot", "hal", "--name", name}

	// Sort env keys for deterministic flag ordering
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		args = append(args, "-e", k+"="+env[k])
	}
	return args
}

func (d *DaytonaProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*SandboxResult, error) {
	args := buildCreateArgs(name, env)
	cmd := d.commandContext(ctx, "daytona", args...)
	cmd.Stdout = out
	cmd.Stderr = out

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("daytona create failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return nil, fmt.Errorf("daytona create failed: %w", err)
	}

	return &SandboxResult{Name: name}, nil
}

func (d *DaytonaProvider) Stop(ctx context.Context, name string, out io.Writer) error {
	cmd := d.commandContext(ctx, "daytona", "stop", name)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("daytona stop failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("daytona stop failed: %w", err)
	}
	return nil
}

func (d *DaytonaProvider) Delete(ctx context.Context, name string, out io.Writer) error {
	cmd := d.commandContext(ctx, "daytona", "delete", name, "--yes")
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("daytona delete failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("daytona delete failed: %w", err)
	}
	return nil
}

func (d *DaytonaProvider) SSH(name string) (*exec.Cmd, error) {
	cmd := exec.Command("daytona", "ssh", name)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (d *DaytonaProvider) Exec(name string, args []string) (*exec.Cmd, error) {
	cmdArgs := []string{"ssh", name, "--"}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("daytona", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (d *DaytonaProvider) Status(ctx context.Context, name string, out io.Writer) error {
	cmd := d.commandContext(ctx, "daytona", "info", name)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("daytona info failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("daytona info failed: %w", err)
	}
	return nil
}
