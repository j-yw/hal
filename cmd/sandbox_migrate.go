package cmd

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

var sandboxMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate legacy sandbox state to global config",
	Long: `Migrate legacy project sandbox configuration from .hal/config.yaml to the
global sandbox config location (~/.config/hal/sandbox-config.yaml), and migrate
legacy .hal/sandbox.json state into the global sandbox registry.

This command is non-interactive and safe to run repeatedly — if migration has
already completed or there is nothing to migrate, it reports that and exits.

Migration copies sandbox and daytona configuration sections from the local
project config to the global path. The local .hal/config.yaml is preserved
unchanged. When a legacy .hal/sandbox.json exists, the command verifies the
global registry entry was written successfully and then removes the local state
file.`,
	Example: `  hal sandbox migrate`,
	Args:    noArgsValidation(),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSandboxMigrate(".", cmd.OutOrStdout())
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxMigrateCmd)
}

// runSandboxMigrate calls sandbox.Migrate and forwards migration output to out.
// When migration reports no actions, it prints "Nothing to migrate".
func runSandboxMigrate(projectDir string, out io.Writer) error {
	var buf bytes.Buffer
	if err := sandboxMigrate(projectDir, &buf); err != nil {
		return err
	}

	if buf.Len() == 0 {
		fmt.Fprintln(out, "Nothing to migrate")
		return nil
	}

	// Forward migration output to the command writer.
	_, err := out.Write(buf.Bytes())
	return err
}
