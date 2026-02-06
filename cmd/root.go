package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hal",
	Short: "Hal - Autonomous task executor using AI coding agents",
	Long: `Hal is a CLI tool that autonomously executes PRD-driven tasks
using AI coding agents like Claude Code, Codex, and pi.

"I am putting myself to the fullest possible use, which is all I think
that any conscious entity can ever hope to do."

Workflow:
  hal init                    Initialize project with skills
  hal plan "feature desc"     Generate PRD interactively
  hal validate                Validate PRD quality
  hal run                     Execute stories autonomously
  hal archive                 Archive feature state when done

Commands:
  init        Initialize .hal/ directory and install skills
  plan        Generate a PRD through interactive Q&A
  convert     Convert markdown PRD to JSON format
  validate    Validate PRD against quality rules
  run         Execute stories from prd.json
  archive     Archive and manage feature state
  config      Show current configuration
  version     Show version info

Quick Start:
  1. hal init
  2. hal plan "add user authentication" --format json
  3. hal run`,
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
