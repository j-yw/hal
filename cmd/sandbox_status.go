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

var sandboxStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show sandbox status",
	Args:  noArgsValidation(),
	Long: `Show the current status of a Daytona sandbox.

Reads the sandbox name from .hal/sandbox.json unless --name is specified.
Fetches live status from the Daytona API and displays Name and Status.
When local sandbox state is used, also displays SnapshotID and CreatedAt.`,
	Example: `  hal sandbox status
  hal sandbox status --name hal-dev`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		return runSandboxStatus(".", name, os.Stdout, nil)
	},
}

func init() {
	sandboxStatusCmd.Flags().StringP("name", "n", "", "sandbox name (defaults to active sandbox from sandbox.json)")

	sandboxCmd.AddCommand(sandboxStatusCmd)
}

// sandboxStatusFetcher is a function that fetches sandbox status from the Daytona API.
// Injected in tests to avoid real SDK calls.
type sandboxStatusFetcher func(ctx context.Context, apiKey, serverURL, nameOrID string) (*sandbox.SandboxStatus, error)

// defaultSandboxStatusFetcher creates a real Daytona client and calls GetSandboxStatus.
func defaultSandboxStatusFetcher(ctx context.Context, apiKey, serverURL, nameOrID string) (*sandbox.SandboxStatus, error) {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return nil, fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.GetSandboxStatus(ctx, client, nameOrID)
}

// runSandboxStatus contains the testable logic for the sandbox status command.
// dir is the project root directory (containing .hal/).
// If fetcher is nil, the real SDK client is used.
func runSandboxStatus(dir, name string, out io.Writer, fetcher sandboxStatusFetcher) error {
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	// Resolve sandbox name and local state before auth checks.
	var localState *sandbox.SandboxState
	if name == "" {
		state, err := sandbox.LoadState(halDir)
		if err != nil {
			return err
		}
		localState = state
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

	if fetcher == nil {
		fetcher = defaultSandboxStatusFetcher
	}

	ctx := context.Background()
	status, err := fetcher(ctx, cfg.APIKey, cfg.ServerURL, name)
	if err != nil {
		return fmt.Errorf("fetching sandbox status: %w", err)
	}

	// Display status info
	fmt.Fprintf(out, "Name:       %s\n", status.Name)
	fmt.Fprintf(out, "Status:     %s\n", status.Status)

	// Show SnapshotID and CreatedAt from local state if available
	if localState != nil {
		fmt.Fprintf(out, "SnapshotID: %s\n", localState.SnapshotID)
		fmt.Fprintf(out, "CreatedAt:  %s\n", localState.CreatedAt.Format("2006-01-02 15:04:05"))
	}

	return nil
}
