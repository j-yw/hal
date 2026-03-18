package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hal",
	Short: "Hal - Autonomous task executor using AI coding agents",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	Long: `Hal is a CLI tool that autonomously executes PRD-driven tasks
using AI coding agents like Codex (default), Claude Code, and pi.

"I am putting myself to the fullest possible use, which is all I think
that any conscious entity can ever hope to do."

Workflow:
  hal init                             Initialize project with skills
  hal plan "feature desc"              Generate PRD interactively
  hal convert                          Convert markdown PRD to JSON
  hal run --base develop [iterations]  Execute stories autonomously
  hal archive create                   Archive feature state when done

Review / Reporting:
  hal report                           Generate summary report for completed work
  hal review --base <branch> [iters]  Iterative review/fix loop
  hal review against <branch> [iters] Deprecated alias

Status / Health:
  hal status [--json]                  Show workflow state
  hal doctor [--json]                  Check environment health
  hal continue [--json]                Show what to do next

Links:
  hal links status [--json]            Inspect engine skill links
  hal links refresh [engine]           Recreate skill links

Analyze:
  hal analyze --format text|json
  hal analyze --output json           Deprecated alias for --format

Quick Start:
  1. hal init
  2. hal plan "add user authentication" --format json
  3. hal run`,
	Example: `  hal init
  hal plan "add user authentication" --format json
  hal validate
  hal run`,
}

// Root returns the root cobra command for reuse by tooling.
func Root() *cobra.Command {
	return rootCmd
}

func init() {
	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return exitWithCode(cmd, ExitCodeValidation, err)
	})
}

// Execute runs the root command.
func Execute() {
	executeWithDeps(rootCmd, os.Stderr, os.Exit)
}

func executeWithDeps(root *cobra.Command, errW io.Writer, exitFn func(int)) {
	if root == nil {
		if exitFn != nil {
			exitFn(1)
		}
		return
	}

	originalSilenceUsage := root.SilenceUsage
	originalSilenceErrors := root.SilenceErrors
	defer func() {
		root.SilenceUsage = originalSilenceUsage
		root.SilenceErrors = originalSilenceErrors
	}()

	err := root.Execute()
	if err == nil {
		return
	}

	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) {
		if exitErr.Err != nil && errW != nil {
			fmt.Fprintln(errW, exitErr.Err)
		}
		if exitFn != nil {
			exitFn(exitErr.Code)
		}
		return
	}

	if exitFn != nil {
		exitFn(1)
	}
}
