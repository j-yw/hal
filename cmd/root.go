package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "goralph",
	Short: "GoRalph - Autonomous task executor using AI coding agents",
	Long: `GoRalph is a CLI tool that autonomously executes PRD-driven tasks
using AI coding agents like Claude Code.

Workflow:
  goralph init                    Initialize project with skills
  goralph plan "feature desc"     Generate PRD interactively
  goralph validate                Validate PRD quality
  goralph run                     Execute stories autonomously

Commands:
  init        Initialize .goralph/ directory and install skills
  plan        Generate a PRD through interactive Q&A
  convert     Convert markdown PRD to JSON format
  validate    Validate PRD against quality rules
  run         Execute stories from prd.json
  config      Show current configuration
  version     Show version info

Quick Start:
  1. goralph init
  2. goralph plan "add user authentication" --format json
  3. goralph run`,
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
