package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var sandboxDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a sandbox permanently",
	Args:  noArgsValidation(),
	Long: `Permanently delete a sandbox.

By default, reads the sandbox name and provider from .hal/sandbox.json.
Use --name to delete by explicit sandbox name when local state is missing.
After successful deletion, sandbox.json is removed only when it matches the deleted sandbox.`,
	Example: `  hal sandbox delete
  hal sandbox delete --name hal-feature-auth`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, err := cmd.Flags().GetString("name")
		if err != nil {
			return fmt.Errorf("reading --name flag: %w", err)
		}
		return runSandboxDeleteWithDeps(".", os.Stdout, name, nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxDeleteCmd)
	sandboxDeleteCmd.Flags().StringP("name", "n", "", "Delete sandbox by explicit name (without reading .hal/sandbox.json)")
}

// runSandboxDeleteWithDeps contains the testable logic for the sandbox delete command.
// If provider is nil, it is resolved from matching state (or sandbox config when deleting by explicit name).
func runSandboxDeleteWithDeps(dir string, out io.Writer, targetName string, provider sandbox.Provider) error {
	halDir := filepath.Join(dir, template.HalDir)

	deleteName := strings.TrimSpace(targetName)
	var state *sandbox.SandboxState
	var err error

	if deleteName == "" {
		state, err = sandbox.LoadState(halDir)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("no active sandbox — run `hal sandbox start` first")
			}
			return fmt.Errorf("loading sandbox state: %w", err)
		}
		deleteName = state.Name
	} else {
		state, err = sandbox.LoadState(halDir)
		if err != nil && !os.IsNotExist(err) {
			// Best-effort state load: delete-by-name should still work without local state.
			state = nil
		}
	}

	if provider == nil {
		provider, err = resolveDeleteProvider(dir, deleteName, state, resolveProviderFromState, resolveProviderFromName)
		if err != nil {
			return err
		}
	}

	fmt.Fprintf(out, "Deleting sandbox %q...\n", deleteName)

	ctx := context.Background()
	if err := provider.Delete(ctx, deleteName, out); err != nil {
		return fmt.Errorf("sandbox delete failed: %w", err)
	}

	if state != nil && (state.Name == deleteName || state.WorkspaceID == deleteName) {
		if err := sandbox.RemoveState(halDir); err != nil {
			return fmt.Errorf("removing sandbox state: %w", err)
		}
	}

	fmt.Fprintf(out, "Sandbox %q deleted.\n", deleteName)
	return nil
}

func resolveDeleteProvider(
	dir string,
	deleteName string,
	state *sandbox.SandboxState,
	stateResolver func(string, *sandbox.SandboxState) (sandbox.Provider, error),
	nameResolver func(string, string) (sandbox.Provider, error),
) (sandbox.Provider, error) {
	if state != nil && (state.Name == deleteName || state.WorkspaceID == deleteName) {
		return stateResolver(dir, state)
	}
	return nameResolver(dir, deleteName)
}
