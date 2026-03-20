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

var sandboxDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a sandbox permanently",
	Args:  noArgsValidation(),
	Long: `Permanently delete a sandbox.

Reads the sandbox name and provider from .hal/sandbox.json.
After successful deletion, sandbox.json is removed.`,
	Example: `  hal sandbox delete`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSandboxDeleteWithDeps(".", os.Stdout, nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxDeleteCmd)
}

// runSandboxDeleteWithDeps contains the testable logic for the sandbox delete command.
// If provider is nil, it is resolved from state.Provider.
func runSandboxDeleteWithDeps(dir string, out io.Writer, provider sandbox.Provider) error {
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

	fmt.Fprintf(out, "Deleting sandbox %q...\n", state.Name)

	ctx := context.Background()
	if err := provider.Delete(ctx, state.Name, out); err != nil {
		return fmt.Errorf("sandbox delete failed: %w", err)
	}

	if err := sandbox.RemoveState(halDir); err != nil {
		return fmt.Errorf("removing sandbox state: %w", err)
	}

	fmt.Fprintf(out, "Sandbox %q deleted.\n", state.Name)
	return nil
}
