package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var verbose bool

var rootCmd = &cobra.Command{
	Use:   "goralph",
	Short: "GoRalph - Autonomous task executor using AI coding agents",
	Long: `GoRalph is a CLI tool that processes task files (PRD markdown, YAML)
and executes tasks using AI coding agents like Claude Code, OpenCode, Cursor, etc.

Usage:
  goralph run <target>       Run tasks from file or inline
  goralph init               Initialize .goralph/ config
  goralph config             Show current configuration
  goralph version            Show version info`,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
