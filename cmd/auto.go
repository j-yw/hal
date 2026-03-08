package cmd

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/spf13/cobra"
)

var (
	autoDryRunFlag bool
	autoResumeFlag bool
	autoSkipPRFlag bool
	autoReportFlag string
	autoEngineFlag string
	autoBaseFlag   string
)

var autoCmd = &cobra.Command{
	Use:   "auto",
	Short: "Run the full compound engineering pipeline",
	Args:  noArgsValidation(),
	Long: `Execute the complete compound engineering automation pipeline.

The pipeline steps are:
  1. analyze  - Find and analyze the latest report to identify priority item
  2. branch   - Create and checkout a new branch for the work
  3. prd      - Generate a PRD using the autospec skill
  4. explode  - Break down the PRD into 8-15 granular tasks
  5. loop     - Execute the Hal task loop until all tasks pass
  6. pr       - Push the branch and create a draft pull request

The pipeline saves state after each step, allowing you to resume
from interruptions using the --resume flag.

Examples:
  hal auto                     # Run full pipeline with latest report
  hal auto --report report.md  # Use specific report file
  hal auto --dry-run           # Show what would happen without executing
  hal auto --resume            # Continue from last saved state
  hal auto --skip-pr           # Skip PR creation at the end
  hal auto --base develop      # Use develop as the base branch`,
	Example: `  hal auto
  hal auto --report .hal/reports/report.md
  hal auto --resume
  hal auto --engine codex --base develop`,
	RunE: runAuto,
}

func init() {
	autoCmd.Flags().BoolVar(&autoDryRunFlag, "dry-run", false, "Show steps without executing")
	autoCmd.Flags().BoolVar(&autoResumeFlag, "resume", false, "Continue from last saved state")
	autoCmd.Flags().BoolVar(&autoSkipPRFlag, "skip-pr", false, "Skip PR creation at end")
	autoCmd.Flags().StringVar(&autoReportFlag, "report", "", "Specific report file (skips find latest)")
	autoCmd.Flags().StringVarP(&autoEngineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")
	autoCmd.Flags().StringVarP(&autoBaseFlag, "base", "b", "", "Base branch for new work branch and PR target (default: current branch, or HEAD when detached)")
	rootCmd.AddCommand(autoCmd)
}

func runAuto(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	out := io.Writer(os.Stdout)
	dir := "."

	dryRun := autoDryRunFlag
	resume := autoResumeFlag
	skipPR := autoSkipPRFlag
	reportPath := autoReportFlag
	engineName := autoEngineFlag
	baseBranch := autoBaseFlag

	if cmd != nil {
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		out = cmd.OutOrStdout()

		if cmd.Flags().Lookup("dry-run") != nil {
			value, err := cmd.Flags().GetBool("dry-run")
			if err != nil {
				return err
			}
			dryRun = value
		}
		if cmd.Flags().Lookup("resume") != nil {
			value, err := cmd.Flags().GetBool("resume")
			if err != nil {
				return err
			}
			resume = value
		}
		if cmd.Flags().Lookup("skip-pr") != nil {
			value, err := cmd.Flags().GetBool("skip-pr")
			if err != nil {
				return err
			}
			skipPR = value
		}
		if cmd.Flags().Lookup("report") != nil {
			value, err := cmd.Flags().GetString("report")
			if err != nil {
				return err
			}
			reportPath = value
		}
		if cmd.Flags().Lookup("engine") != nil {
			value, err := cmd.Flags().GetString("engine")
			if err != nil {
				return err
			}
			engineName = value
		}
		if cmd.Flags().Lookup("base") != nil {
			value, err := cmd.Flags().GetString("base")
			if err != nil {
				return err
			}
			baseBranch = value
		}
	}

	// Load config
	config, err := compound.LoadConfig(dir)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	resolvedEngine, err := resolveEngine(cmd, "engine", engineName, dir)
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	// Create engine with per-engine config
	engineCfg := compound.LoadEngineConfig(dir, resolvedEngine)
	eng, err := engine.NewWithConfig(resolvedEngine, engineCfg)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	// Create display
	display := engine.NewDisplay(out)

	// Show command header
	display.ShowCommandHeader("Auto", "compound pipeline", buildHeaderCtx(resolvedEngine))

	// Create pipeline (pass same config for inner loop engine creation)
	pipeline := compound.NewPipeline(config, eng, display, dir)
	pipeline.SetEngineConfig(engineCfg)

	// Check for reports before starting (unless resuming or report specified)
	if !resume && reportPath == "" {
		_, err := compound.FindLatestReport(config.ReportsDir)
		if err != nil {
			fmt.Fprintln(out, "No reports found.")
			fmt.Fprintln(out)
			fmt.Fprintf(out, "Place your reports in %s/ and run this command again.\n", config.ReportsDir)
			fmt.Fprintln(out, "Reports can be markdown files, text files, or any format the AI can analyze.")
			return nil
		}
	}

	// Check if resuming
	if resume {
		if !pipeline.HasState() {
			return fmt.Errorf("no saved state to resume from")
		}
		display.ShowInfo("   Resuming pipeline from saved state\n")
	} else if pipeline.HasState() {
		display.ShowInfo("   Note: Previous state exists. Use --resume to continue, or delete .hal/auto-state.json to start fresh.\n")
	}

	// Run options
	opts := compound.RunOptions{
		Resume:     resume,
		DryRun:     dryRun,
		SkipPR:     skipPR,
		ReportPath: reportPath,
		BaseBranch: baseBranch,
	}

	// Run the pipeline
	if err := pipeline.Run(ctx, opts); err != nil {
		return err
	}

	// Show success message
	display.ShowCommandSuccess("Auto pipeline completed!", "")

	return nil
}
