package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "goralph",
	Short: "GoRalph - Autonomous PRD task executor using Claude Code",
	Long: `GoRalph is a CLI tool that processes PRD (Product Requirements Document) files
and executes tasks sequentially using Claude Code as the AI engine.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("GoRalph ready. Use --help for available commands.")
	},
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
