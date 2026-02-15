package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var sandboxExecCmd = &cobra.Command{
	Use:   "exec [command...]",
	Short: "Execute a command in a sandbox",
	Long: `Execute a non-interactive command in a running Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name is specified.
The sandbox must be in the running (started) state.

stdout and stderr from the remote command are streamed to the local terminal.
The exit code from the remote command is propagated as the local exit code.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		exitCode, err := runSandboxExec(".", name, args, os.Stdout, nil)
		if err != nil {
			return err
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	},
}

func init() {
	sandboxExecCmd.Flags().String("name", "", "sandbox name (defaults to active sandbox from sandbox.json)")

	sandboxCmd.AddCommand(sandboxExecCmd)
}

// sandboxExecutor is a function that executes a command in a Daytona sandbox.
// Injected in tests to avoid real SDK calls.
type sandboxExecutor func(ctx context.Context, apiKey, serverURL, nameOrID, command string) (*sandbox.ExecResult, error)

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

	// Load config and ensure auth
	cfg, err := compound.LoadDaytonaConfig(dir)
	if err != nil {
		return 0, fmt.Errorf("loading config: %w", err)
	}

	if err := sandbox.EnsureAuth(cfg.APIKey, func() error {
		return runSandboxSetup(dir, os.Stdin, out, readPasswordFromTerminal)
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

	// Resolve sandbox name from state file if not provided
	if name == "" {
		state, err := sandbox.LoadState(halDir)
		if err != nil {
			return 0, err
		}
		name = state.Name
	}

	command := shellCommandFromArgs(args)

	if executor == nil {
		executor = defaultSandboxExecutor
	}

	ctx := context.Background()
	result, err := executor(ctx, cfg.APIKey, cfg.ServerURL, name, command)
	if err != nil {
		return 0, fmt.Errorf("exec failed: %w", err)
	}

	// Stream output to terminal
	if result.Output != "" {
		fmt.Fprint(out, result.Output)
	}

	return result.ExitCode, nil
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
