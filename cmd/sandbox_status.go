package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var sandboxStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show sandbox status",
	Args:  noArgsValidation(),
	Long: `Show the current status of a sandbox.

Reads the sandbox name and provider from .hal/sandbox.json.
The provider is used to determine how to fetch status (daytona CLI or hcloud CLI).`,
	Example: `  hal sandbox status`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSandboxStatusWithDeps(".", os.Stdout, nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxStatusCmd)
}

// runSandboxStatusWithDeps contains the testable logic for the sandbox status command.
// If provider is nil, it is resolved from state.Provider.
func runSandboxStatusWithDeps(dir string, out io.Writer, provider sandbox.Provider) error {
	halDir := filepath.Join(dir, template.HalDir)

	state, err := sandbox.LoadState(halDir)
	if err != nil {
		return fmt.Errorf("no active sandbox — run `hal sandbox start` first")
	}

	if provider == nil {
		provider, err = resolveProviderFromState(dir, state)
		if err != nil {
			return err
		}
	}

	// Print header with provider and name
	fmt.Fprintf(out, "Sandbox: %s (provider: %s)\n", state.Name, state.Provider)

	ctx := context.Background()
	if err := provider.Status(ctx, state.Name, out); err != nil {
		return fmt.Errorf("fetching sandbox status: %w", err)
	}

	return nil
}
