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

var sandboxStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop a running sandbox",
	Args:  noArgsValidation(),
	Long: `Stop a running sandbox.

Reads the sandbox name and provider from .hal/sandbox.json.
The provider is used to determine how to stop the sandbox (daytona CLI or hcloud CLI).`,
	Example: `  hal sandbox stop`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSandboxStopWithDeps(".", os.Stdout, nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxStopCmd)
}

// runSandboxStopWithDeps contains the testable logic for the sandbox stop command.
// If provider is nil, it is resolved from state.Provider.
func runSandboxStopWithDeps(dir string, out io.Writer, provider sandbox.Provider) error {
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

	fmt.Fprintf(out, "Stopping sandbox %q...\n", state.Name)

	ctx := context.Background()
	if err := provider.Stop(ctx, state.Name, out); err != nil {
		return fmt.Errorf("sandbox stop failed: %w", err)
	}

	fmt.Fprintf(out, "Sandbox %q stopped.\n", state.Name)
	return nil
}
