package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	display "github.com/jywlabs/hal/internal/engine"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "hal",
	Short:   "Hal - Autonomous task executor using AI coding agents",
	Version: Version,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	Long: `Hal is a CLI tool that autonomously executes PRD-driven tasks
using AI coding agents like Codex (default), Claude Code, and pi.

"I am putting myself to the fullest possible use, which is all I think
that any conscious entity can ever hope to do."

Core flow:
  hal init
  hal plan "feature desc"
  hal convert
  hal run --base develop [iterations]
  hal archive create

Auto flow:
  hal auto [prd-path]
  source selection uses auto.sourcePriority (default report_first: latest report -> newest .hal/prd-*.md)

Review / reporting:
  hal report
  hal review --base <branch> [iters]

Status / health:
  hal status [--json]
  hal doctor [--json]
  hal continue [--json]
  hal repair [--dry-run] [--json]

Agent-safe examples:
  hal plan --input .hal/input/feature.md --no-questions --format json --json
  hal plan --input - --no-questions --format json --json < .hal/input/feature.md
  hal auto .hal/prd-feature.md --dry-run --json
  hal archive create --name checkout-flow

Links:
  hal links status [--json]
  hal links refresh [engine]
  hal links clean

Analyze:
  hal analyze --format text|json
  hal analyze --output json  # deprecated alias

Quick start:
  1. hal init
  2. hal plan "add user authentication" --format json
  3. hal run
  4. hal auto`,
	Example: `  hal init
  hal plan "add user authentication" --format json
  hal validate
  hal run
  hal auto`,
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
	root.SilenceUsage = true
	root.SilenceErrors = true
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

	renderRootCommandError(errW, err)
	if exitFn != nil {
		exitFn(1)
	}
}

func renderRootCommandError(errW io.Writer, err error) {
	if errW == nil || err == nil {
		return
	}
	display.NewDisplay(errW).ShowCommandError("Command failed", []display.ValidationIssue{{Message: err.Error()}}, nil)
}
