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

var sandboxStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop a running sandbox",
	Long: `Stop a running Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name is specified.
The sandbox state file is updated to reflect the stopped status.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		return runSandboxStop(".", name, os.Stdout, nil)
	},
}

func init() {
	sandboxStopCmd.Flags().String("name", "", "sandbox name (defaults to active sandbox from sandbox.json)")

	sandboxCmd.AddCommand(sandboxStopCmd)
}

// sandboxStopper is a function that stops a Daytona sandbox.
// Injected in tests to avoid real SDK calls.
type sandboxStopper func(ctx context.Context, apiKey, serverURL, nameOrID string, out io.Writer) error

// defaultSandboxStopper creates a real Daytona client and calls StopSandbox.
func defaultSandboxStopper(ctx context.Context, apiKey, serverURL, nameOrID string, out io.Writer) error {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.StopSandbox(ctx, client, nameOrID, out)
}

// runSandboxStop contains the testable logic for the sandbox stop command.
// dir is the project root directory (containing .hal/).
// If stopper is nil, the real SDK client is used.
func runSandboxStop(dir, name string, out io.Writer, stopper sandboxStopper) error {
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

	fmt.Fprintf(out, "Stopping sandbox %q...\n", name)

	if stopper == nil {
		stopper = defaultSandboxStopper
	}

	ctx := context.Background()
	if err := stopper(ctx, cfg.APIKey, cfg.ServerURL, name, out); err != nil {
		return fmt.Errorf("sandbox stop failed: %w", err)
	}

	// Update state file to reflect stopped status
	state, err := sandbox.LoadState(halDir)
	if err == nil {
		state.Status = "STOPPED"
		if err := sandbox.SaveState(halDir, state); err != nil {
			return fmt.Errorf("updating sandbox state: %w", err)
		}
	}

	fmt.Fprintf(out, "Sandbox %q stopped.\n", name)
	return nil
}
