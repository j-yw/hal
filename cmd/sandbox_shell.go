package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var sandboxShellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Open an interactive shell in a sandbox",
	Args:  noArgsValidation(),
	Long: `Open an interactive shell session in a running Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name is specified.
The sandbox must be in the running (started) state.`,
	Example: `  hal sandbox shell
  hal sandbox shell --name hal-dev`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		return runSandboxShell(".", name, os.Stdin, os.Stdout, nil, nil)
	},
}

func init() {
	sandboxShellCmd.Flags().StringP("name", "n", "", "sandbox name (defaults to active sandbox from sandbox.json)")

	sandboxCmd.AddCommand(sandboxShellCmd)
}

// shellConnector is a function that establishes a shell connection to a sandbox.
// Injected in tests to avoid real SDK calls.
type shellConnector func(ctx context.Context, apiKey, serverURL, nameOrID string) (*sandbox.ShellConnection, error)

// shellForwarder is a function that runs bidirectional I/O forwarding.
// Injected in tests to avoid real terminal/PTY operations.
type shellForwarder func(ctx context.Context, conn *sandbox.ShellConnection, stdin io.Reader, stdout io.Writer) (*sandbox.ForwardShellIOResult, error)

// defaultShellConnector creates a real Daytona client and calls ConnectShell.
func defaultShellConnector(ctx context.Context, apiKey, serverURL, nameOrID string) (*sandbox.ShellConnection, error) {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return nil, fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.ConnectShell(ctx, client, nameOrID)
}

// runSandboxShell contains the testable logic for the sandbox shell command.
// dir is the project root directory (containing .hal/).
// If connector is nil, the real SDK client is used.
// If forwarder is nil, the real ForwardShellIO is used.
func runSandboxShell(dir, name string, stdin io.Reader, out io.Writer, connector shellConnector, forwarder shellForwarder) error {
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	// Resolve sandbox name from state file before auth checks.
	if name == "" {
		state, err := sandbox.LoadState(halDir)
		if err != nil {
			return err
		}
		name = state.Name
	}

	// Load config and ensure auth
	cfg, err := compound.LoadDaytonaConfig(dir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
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
		return err
	}

	// Re-read config in case EnsureAuth triggered setup
	cfg, err = compound.LoadDaytonaConfig(dir)
	if err != nil {
		return fmt.Errorf("reloading config: %w", err)
	}

	fmt.Fprintf(out, "Connecting to sandbox %q...\n", name)

	if connector == nil {
		connector = defaultShellConnector
	}

	ctx := context.Background()
	conn, err := connector(ctx, cfg.APIKey, cfg.ServerURL, name)
	if err != nil {
		return fmt.Errorf("shell connection failed: %w", err)
	}

	fmt.Fprintf(out, "Connected to sandbox %q.\n", conn.SandboxName)

	if forwarder == nil {
		forwarder = sandbox.ForwardShellIO
	}

	result, err := forwarder(ctx, conn, stdin, out)
	if err != nil {
		return fmt.Errorf("shell session error: %w", err)
	}
	if result == nil {
		return fmt.Errorf("shell session returned no result")
	}

	if result.ExitCode != 0 {
		if result.SessionClosed {
			fmt.Fprintln(out, "session closed")
		}
		return fmt.Errorf("exit code %d", result.ExitCode)
	}

	return nil
}
