package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var sandboxExecCmd = &cobra.Command{
	Use:   "exec [-n NAME] [--] <command...>",
	Short: "Execute a command in a sandbox",
	Long: `Execute a non-interactive command in a running Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name/-n is specified.
The sandbox must be in the running (started) state.

Use '--' when the remote command starts with flags, for example:
  hal sandbox exec -- -n foo

stdout and stderr from the remote command are streamed to the local terminal.
The exit code from the remote command is propagated as the local exit code.`,
	Example: `  hal sandbox exec -- pwd
  hal sandbox exec --name hal-dev -- go test ./...`,
	Args: minArgsValidation(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		exitCode, err := sandboxExecRunner(".", name, args, cmd.OutOrStdout(), nil)
		if err != nil {
			return err
		}
		if exitCode != 0 {
			return exitWithCode(cmd, exitCode, nil)
		}
		return nil
	},
}

var sandboxExecRunner = runSandboxExec

func init() {
	sandboxExecCmd.Flags().StringP("name", "n", "", "sandbox name (defaults to active sandbox from sandbox.json)")
	// Stop flag parsing after the remote command token so options like "-r"
	// are forwarded to the sandbox command instead of treated as local flags.
	sandboxExecCmd.Flags().SetInterspersed(false)

	sandboxCmd.AddCommand(sandboxExecCmd)
}

// sandboxExecutor is a function that executes a command in a Daytona sandbox.
// Injected in tests to avoid real SDK calls.
type sandboxExecutor func(ctx context.Context, apiKey, serverURL, nameOrID, command string) (*sandbox.ExecResult, error)

var nonZeroExitCodePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bexit\s+(?:status|code)\s*[:=]?\s*(\d+)\b`),
	regexp.MustCompile(`(?i)\bexited\s+with\s+status\s*[:=]?\s*(\d+)\b`),
}

// defaultSandboxExecutor creates a real Daytona client and calls ExecCommand.
func defaultSandboxExecutor(ctx context.Context, apiKey, serverURL, nameOrID, command string) (*sandbox.ExecResult, error) {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return nil, fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.ExecCommand(ctx, client, nameOrID, command)
}

// runSandboxExec contains the testable logic for the sandbox exec command.
// dir is the project root directory (containing .hal/).
// Returns the remote exit code and any error.
// If executor is nil, the real SDK client is used.
func runSandboxExec(dir, name string, args []string, out io.Writer, executor sandboxExecutor) (int, error) {
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return 0, fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	// Resolve sandbox name from state file before auth checks.
	if name == "" {
		state, err := sandbox.LoadState(halDir)
		if err != nil {
			return 0, err
		}
		name = state.Name
	}

	// Load config and ensure auth
	cfg, err := compound.LoadDaytonaConfig(dir)
	if err != nil {
		return 0, fmt.Errorf("loading config: %w", err)
	}

	if err := sandbox.EnsureAuth(cfg.APIKey, func() error {
		return runSandboxAutoSetup(dir, out)
	}, func() (string, error) {
		reloaded, err := compound.LoadDaytonaConfig(dir)
		if err != nil {
			return "", err
		}
		return reloaded.APIKey, nil
	}); err != nil {
		return 0, err
	}

	// Re-read config in case EnsureAuth triggered setup
	cfg, err = compound.LoadDaytonaConfig(dir)
	if err != nil {
		return 0, fmt.Errorf("reloading config: %w", err)
	}

	command := shellCommandFromArgs(args)

	if executor == nil {
		executor = defaultSandboxExecutor
	}

	ctx := context.Background()
	result, err := executor(ctx, cfg.APIKey, cfg.ServerURL, name, command)
	if err != nil {
		if exitCode, ok := nonZeroExitCodeFromError(err); ok {
			return exitCode, nil
		}
		return 0, fmt.Errorf("exec failed: %w", err)
	}
	if result == nil {
		return 0, fmt.Errorf("exec failed: missing command result")
	}

	// Stream output to terminal
	if result.Output != "" {
		fmt.Fprint(out, result.Output)
	}

	return result.ExitCode, nil
}

func nonZeroExitCodeFromError(err error) (int, bool) {
	if err == nil {
		return 0, false
	}

	msg := err.Error()
	for _, pattern := range nonZeroExitCodePatterns {
		matches := pattern.FindStringSubmatch(msg)
		if len(matches) != 2 {
			continue
		}
		exitCode, convErr := strconv.Atoi(matches[1])
		if convErr == nil && exitCode > 0 {
			return exitCode, true
		}
	}

	return 0, false
}

// shellCommandFromArgs builds a shell-safe command string that preserves original
// argument boundaries.
func shellCommandFromArgs(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = shellQuoteArg(arg)
	}
	return strings.Join(quoted, " ")
}

func shellQuoteArg(arg string) string {
	if arg == "" {
		return "''"
	}
	if isSafeShellArg(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
}

func isSafeShellArg(arg string) bool {
	const safeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"
	for _, r := range arg {
		if !strings.ContainsRune(safeChars, r) {
			return false
		}
	}
	return true
}
