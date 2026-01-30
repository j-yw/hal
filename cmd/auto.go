package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/jywlabs/goralph/internal/compound"
	"github.com/jywlabs/goralph/internal/engine"
	"github.com/spf13/cobra"

	// Register available engines
	_ "github.com/jywlabs/goralph/internal/engine/claude"
)

var (
	autoDryRunFlag  bool
	autoResumeFlag  bool
	autoSkipPRFlag  bool
	autoReportFlag  string
	autoEngineFlag  string
)

var autoCmd = &cobra.Command{
	Use:   "auto",
	Short: "Run the full compound engineering pipeline",
	Long: `Execute the complete compound engineering automation pipeline.

The pipeline steps are:
  1. analyze  - Find and analyze the latest report to identify priority item
  2. branch   - Create and checkout a new branch for the work
  3. prd      - Generate a PRD using the autospec skill
  4. explode  - Break down the PRD into 8-15 granular tasks
  5. loop     - Execute the Ralph task loop until all tasks pass
  6. pr       - Push the branch and create a draft pull request

The pipeline saves state after each step, allowing you to resume
from interruptions using the --resume flag.

Examples:
  goralph auto                     # Run full pipeline with latest report
  goralph auto --report report.md  # Use specific report file
  goralph auto --dry-run           # Show what would happen without executing
  goralph auto --resume            # Continue from last saved state
  goralph auto --skip-pr           # Skip PR creation at the end`,
	RunE: runAuto,
}

func init() {
	autoCmd.Flags().BoolVar(&autoDryRunFlag, "dry-run", false, "Show steps without executing")
	autoCmd.Flags().BoolVar(&autoResumeFlag, "resume", false, "Continue from last saved state")
	autoCmd.Flags().BoolVar(&autoSkipPRFlag, "skip-pr", false, "Skip PR creation at end")
	autoCmd.Flags().StringVar(&autoReportFlag, "report", "", "Specific report file (skips find latest)")
	autoCmd.Flags().StringVarP(&autoEngineFlag, "engine", "e", "claude", "Engine to use (claude)")
	rootCmd.AddCommand(autoCmd)
}

func runAuto(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	dir := "."

	// Load config
	config, err := compound.LoadConfig(dir)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create engine
	eng, err := engine.New(autoEngineFlag)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	// Create display
	display := engine.NewDisplay(os.Stdout)

	// Show command header
	display.ShowCommandHeader("Auto", "compound pipeline", eng.Name())

	// Create pipeline
	pipeline := compound.NewPipeline(config, eng, display, dir)

	// Check for reports before starting (unless resuming or report specified)
	if !autoResumeFlag && autoReportFlag == "" {
		_, err := compound.FindLatestReport(config.ReportsDir)
		if err != nil {
			fmt.Println("No reports found.")
			fmt.Println()
			fmt.Printf("Place your reports in %s/ and run this command again.\n", config.ReportsDir)
			fmt.Println("Reports can be markdown files, text files, or any format the AI can analyze.")
			return nil
		}
	}

	// Check if resuming
	if autoResumeFlag {
		if !pipeline.HasState() {
			return fmt.Errorf("no saved state to resume from")
		}
		display.ShowInfo("   Resuming pipeline from saved state\n")
	} else if pipeline.HasState() {
		display.ShowInfo("   Note: Previous state exists. Use --resume to continue, or delete .goralph/auto-state.json to start fresh.\n")
	}

	// Run options
	opts := compound.RunOptions{
		Resume:     autoResumeFlag,
		DryRun:     autoDryRunFlag,
		SkipPR:     autoSkipPRFlag,
		ReportPath: autoReportFlag,
	}

	// Run the pipeline
	if err := pipeline.Run(ctx, opts); err != nil {
		return err
	}

	// Show success message
	display.ShowCommandSuccess("Auto pipeline completed!", "")

	return nil
}
