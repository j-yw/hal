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

var sandboxDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a sandbox permanently",
	Long: `Permanently delete a Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name is specified.
After successful deletion, sandbox.json is removed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		return runSandboxDelete(".", name, os.Stdout, nil)
	},
}

func init() {
	sandboxDeleteCmd.Flags().String("name", "", "sandbox name (defaults to active sandbox from sandbox.json)")

	sandboxCmd.AddCommand(sandboxDeleteCmd)
}

// sandboxDeleter is a function that deletes a Daytona sandbox.
// Injected in tests to avoid real SDK calls.
type sandboxDeleter func(ctx context.Context, apiKey, serverURL, nameOrID string, out io.Writer) error

// defaultSandboxDeleter creates a real Daytona client and calls DeleteSandbox.
func defaultSandboxDeleter(ctx context.Context, apiKey, serverURL, nameOrID string, out io.Writer) error {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.DeleteSandbox(ctx, client, nameOrID, out)
}

// runSandboxDelete contains the testable logic for the sandbox delete command.
// dir is the project root directory (containing .hal/).
// If deleter is nil, the real SDK client is used.
func runSandboxDelete(dir, name string, out io.Writer, deleter sandboxDeleter) error {
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

	fmt.Fprintf(out, "Deleting sandbox %q...\n", name)

	if deleter == nil {
		deleter = defaultSandboxDeleter
	}

	ctx := context.Background()
	if err := deleter(ctx, cfg.APIKey, cfg.ServerURL, name, out); err != nil {
		return fmt.Errorf("sandbox delete failed: %w", err)
	}

	// Remove sandbox.json after successful deletion
	if err := sandbox.RemoveState(halDir); err != nil {
		return fmt.Errorf("removing sandbox state: %w", err)
	}

	fmt.Fprintf(out, "Sandbox %q deleted.\n", name)
	return nil
}
