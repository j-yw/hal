package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/spf13/cobra"

	// Register available engines
	_ "github.com/jywlabs/hal/internal/engine/claude"
	_ "github.com/jywlabs/hal/internal/engine/codex"
)

var (
	reviewDryRunFlag     bool
	reviewSkipAgentsFlag bool
	reviewEngineFlag     string
)

var reviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Review completed work and generate a report",
	Long: `Review the completed work session and generate a summary report.

The review process:
  1. Gathers context (progress log, git diff, commits, PRD)
  2. Analyzes what was built and how
  3. Identifies patterns worth documenting
  4. Updates AGENTS.md with discovered patterns
  5. Generates a report with recommendations

The generated report can be used by 'goralph auto' to identify
the next priority item to work on.

Examples:
  goralph review                  # Review with codex engine (default)
  goralph review --engine claude  # Use Claude instead
  goralph review --dry-run        # Preview what would be reviewed
  goralph review --skip-agents    # Skip AGENTS.md update`,
	RunE: runReview,
}

func init() {
	reviewCmd.Flags().BoolVar(&reviewDryRunFlag, "dry-run", false, "Preview without executing")
	reviewCmd.Flags().BoolVar(&reviewSkipAgentsFlag, "skip-agents", false, "Skip AGENTS.md update")
	reviewCmd.Flags().StringVarP(&reviewEngineFlag, "engine", "e", "codex", "Engine to use (codex, claude)")
	rootCmd.AddCommand(reviewCmd)
}

func runReview(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	dir := "."

	// Create engine (default: codex for review)
	eng, err := engine.New(reviewEngineFlag)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	// Create display
	display := engine.NewDisplay(os.Stdout)

	// Show command header
	display.ShowCommandHeader("Review", "work session", eng.Name())

	// Run review
	result, err := compound.Review(ctx, eng, display, dir, compound.ReviewOptions{
		DryRun:     reviewDryRunFlag,
		SkipAgents: reviewSkipAgentsFlag,
	})
	if err != nil {
		return err
	}

	// Show success
	if result.ReportPath != "" {
		display.ShowCommandSuccess("Review complete", result.ReportPath)

		// Show summary and recommendations
		if result.Summary != "" {
			fmt.Println()
			fmt.Println("Summary:", result.Summary)
		}

		if len(result.Recommendations) > 0 {
			fmt.Println()
			fmt.Println("Recommendations:")
			for i, rec := range result.Recommendations {
				fmt.Printf("  %d. %s\n", i+1, rec)
			}
		}
	}

	return nil
}
