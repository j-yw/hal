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
	reportDryRunFlag     bool
	reportSkipAgentsFlag bool
	reportEngineFlag     string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Run legacy session reporting for completed work",
	Args:  cobra.NoArgs,
	Long: `Run legacy session reporting for the completed work session and generate a summary report.

This command preserves the workflow that previously lived under 'hal review'.

The review process:
  1. Gathers context (progress log, git diff, commits, PRD)
  2. Analyzes what was built and how
  3. Identifies patterns worth documenting
  4. Updates AGENTS.md with discovered patterns
  5. Generates a report with recommendations

The generated report can be used by 'hal auto' to identify
the next priority item to work on.

Examples:
  hal report                  # Review with codex engine (default)
  hal report --engine claude  # Use Claude instead
  hal report --dry-run        # Preview what would be reviewed
  hal report --skip-agents    # Skip AGENTS.md update`,
	RunE: runReport,
}

type reportDeps struct {
	newEngine      func(name string) (engine.Engine, error)
	newDisplay     func(out io.Writer) *engine.Display
	buildHeaderCtx func(engineName string) engine.HeaderContext
	runReview      func(ctx context.Context, eng engine.Engine, display *engine.Display, dir string, opts compound.ReviewOptions) (*compound.ReviewResult, error)
}

var defaultReportDeps = reportDeps{
	newEngine:      newEngine,
	newDisplay:     engine.NewDisplay,
	buildHeaderCtx: buildHeaderCtx,
	runReview:      compound.Review,
}

func init() {
	reportCmd.Flags().BoolVar(&reportDryRunFlag, "dry-run", false, "Preview without executing")
	reportCmd.Flags().BoolVar(&reportSkipAgentsFlag, "skip-agents", false, "Skip AGENTS.md update")
	reportCmd.Flags().StringVarP(&reportEngineFlag, "engine", "e", "codex", "Engine to use (codex, claude, pi)")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}

	return runReportWithDeps(
		ctx,
		".",
		reportDryRunFlag,
		reportSkipAgentsFlag,
		reportEngineFlag,
		out,
		defaultReportDeps,
	)
}

func runReportWithDeps(ctx context.Context, dir string, dryRun bool, skipAgents bool, engineName string, out io.Writer, deps reportDeps) error {
	display := deps.newDisplay(out)

	var eng engine.Engine
	if !dryRun {
		var err error
		eng, err = deps.newEngine(engineName)
		if err != nil {
			return fmt.Errorf("failed to create engine: %w", err)
		}
	}

	display.ShowCommandHeader("Review", "work session", deps.buildHeaderCtx(engineName))

	result, err := deps.runReview(ctx, eng, display, dir, compound.ReviewOptions{
		DryRun:     dryRun,
		SkipAgents: skipAgents,
	})
	if err != nil {
		return err
	}

	if !dryRun && (result == nil || result.ReportPath == "") {
		return fmt.Errorf("review did not produce a report path")
	}

	showReviewResult(out, display, result)
	return nil
}

func showReviewResult(out io.Writer, display *engine.Display, result *compound.ReviewResult) {
	if result == nil {
		return
	}

	if result.ReportPath != "" {
		display.ShowCommandSuccess("Review complete", result.ReportPath)
	}

	if result.Summary != "" {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Summary:", result.Summary)
	}

	if len(result.Recommendations) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Recommendations:")
		for i, rec := range result.Recommendations {
			fmt.Fprintf(out, "  %d. %s\n", i+1, rec)
		}
	}
}
