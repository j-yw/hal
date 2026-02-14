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
	Long: `Open an interactive shell session in a running Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name is specified.
The sandbox must be in the running (started) state.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		return runSandboxShell(".", name, os.Stdout, nil)
	},
}

func init() {
	sandboxShellCmd.Flags().String("name", "", "sandbox name (defaults to active sandbox from sandbox.json)")

	sandboxCmd.AddCommand(sandboxShellCmd)
}

// shellConnector is a function that establishes a shell connection to a sandbox.
// Injected in tests to avoid real SDK calls.
type shellConnector func(ctx context.Context, apiKey, serverURL, nameOrID string) (*sandbox.ShellConnection, error)

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
func runSandboxShell(dir, name string, out io.Writer, connector shellConnector) error {
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	// Load config and ensure auth
	cfg, err := compound.LoadDaytonaConfig(dir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
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
		return err
	}

	// Re-read config in case EnsureAuth triggered setup
	cfg, err = compound.LoadDaytonaConfig(dir)
	if err != nil {
		return fmt.Errorf("reloading config: %w", err)
	}

	// Resolve sandbox name from state file if not provided
	if name == "" {
		state, err := sandbox.LoadState(halDir)
		if err != nil {
			return err
		}
		name = state.Name
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

	// Disconnect the PTY handle — US-012 will add full I/O forwarding
	if conn.PtyHandle != nil {
		conn.PtyHandle.Disconnect()
	}

	return nil
}
