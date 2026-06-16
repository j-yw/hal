package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var sandboxStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Create and start a sandbox",
	Args:  noArgsValidation(),
	Long: `Create and start a sandbox using the configured provider.

Deprecated compatibility alias: use 'hal sandbox create' to provision new sandboxes.`,
	Example: `  hal sandbox start
  hal sandbox start --name hal-dev
  hal sandbox start -n worker --count 5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		count, _ := cmd.Flags().GetInt("count")
		countExplicit := cmd.Flags().Changed("count")
		force, _ := cmd.Flags().GetBool("force")
		size, _ := cmd.Flags().GetString("size")
		repo, _ := cmd.Flags().GetString("repo")
		envSlice, _ := cmd.Flags().GetStringArray("env")
		envVars := parseEnvFlags(envSlice)
		opts := autoShutdownOptsFromCommand(cmd)

		out := cmd.OutOrStdout()
		if out == nil {
			out = os.Stdout
		}
		return runSandboxCreate(".", name, count, countExplicit, force, size, repo, envVars, opts, out, nil)
	},
}

func init() {
	sandboxStartCmd.Flags().StringP("name", "n", "", "sandbox name (defaults to current git branch)")
	sandboxStartCmd.Flags().Int("count", 0, "create N sandboxes with names {name}-01..{name}-N")
	sandboxStartCmd.Flags().BoolP("force", "f", false, "replace existing sandbox with the same name")
	sandboxStartCmd.Flags().StringP("size", "s", "", "override provider instance size (e.g., cx42, s-2vcpu-4gb)")
	sandboxStartCmd.Flags().StringP("repo", "r", "", "repository label for the sandbox (informational)")
	sandboxStartCmd.Flags().StringArrayP("env", "e", nil, "extra environment variables (KEY=VALUE, repeatable)")
	sandboxStartCmd.Flags().Bool("auto-shutdown", true, "enable auto-shutdown idle timer")
	sandboxStartCmd.Flags().Bool("no-auto-shutdown", false, "disable auto-shutdown idle timer")
	sandboxStartCmd.Flags().Int("idle-hours", 0, "hours before idle shutdown (default from global config)")
	sandboxCmd.AddCommand(sandboxStartCmd)
}
