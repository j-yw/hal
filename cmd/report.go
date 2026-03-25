package cmd

import (
	"context"
	"encoding/json"
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
	reportJSONFlag       bool
)

// ReportResult is the machine-readable output of hal report --json.
type ReportResult struct {
	ContractVersion int      `json:"contractVersion"`
	OK              bool     `json:"ok"`
	ReportPath      string   `json:"reportPath,omitempty"`
	Summary         string   `json:"summary,omitempty"`
	PatternsAdded   []string `json:"patternsAdded,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`
	Issues          []string `json:"issues,omitempty"`
	TechDebt        []string `json:"techDebt,omitempty"`
	NextAction      *struct {
		ID          string `json:"id"`
		Command     string `json:"command"`
		Description string `json:"description"`
	} `json:"nextAction,omitempty"`
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a summary report for completed work",
	Args:  noArgsValidation(),
	Long: `Generate a summary report for the completed work session.

The report process:
  1. Gathers context (progress log, git diff, commits, PRD)
  2. Analyzes what was built and how
  3. Identifies patterns worth documenting
  4. Updates AGENTS.md with discovered patterns
  5. Generates a report with recommendations

The generated report can be used by 'hal auto' to identify
the next priority item to work on.

Examples:
  hal report                  # Generate report with codex engine (default)
  hal report --engine claude  # Use Claude instead
  hal report --json           # Machine-readable JSON output
  hal report --dry-run        # Preview what would be reported
  hal report --skip-agents    # Skip AGENTS.md update`,
	Example: `  hal report
  hal report --json
  hal report --engine claude
  hal report --dry-run
  hal report --skip-agents`,
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
	reportCmd.Flags().BoolVar(&reportJSONFlag, "json", false, "Output machine-readable JSON result")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	out := io.Writer(os.Stdout)
	dryRun := reportDryRunFlag
	skipAgents := reportSkipAgentsFlag
	engineName := reportEngineFlag
	jsonMode := reportJSONFlag

	if cmd != nil {
		out = cmd.OutOrStdout()

		if cmd.Flags().Lookup("dry-run") != nil {
			value, err := cmd.Flags().GetBool("dry-run")
			if err != nil {
				return fmt.Errorf("failed to read dry-run flag: %w", err)
			}
			dryRun = value
		}
		if cmd.Flags().Lookup("skip-agents") != nil {
			value, err := cmd.Flags().GetBool("skip-agents")
			if err != nil {
				return fmt.Errorf("failed to read skip-agents flag: %w", err)
			}
			skipAgents = value
		}
		if cmd.Flags().Lookup("engine") != nil {
			value, err := cmd.Flags().GetString("engine")
			if err != nil {
				return fmt.Errorf("failed to read engine flag: %w", err)
			}
			engineName = value
		}
		if cmd.Flags().Lookup("json") != nil {
			value, err := cmd.Flags().GetBool("json")
			if err != nil {
				return fmt.Errorf("failed to read json flag: %w", err)
			}
			jsonMode = value
		}
	}

	resolvedEngine, err := resolveEngine(cmd, "engine", engineName, ".")
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	return runReportWithDeps(
		ctx,
		".",
		dryRun,
		skipAgents,
		jsonMode,
		resolvedEngine,
		out,
		defaultReportDeps,
	)
}

func runReportWithDeps(ctx context.Context, dir string, dryRun bool, skipAgents bool, jsonMode bool, engineName string, out io.Writer, deps reportDeps) error {
	if deps.newEngine == nil {
		deps.newEngine = defaultReportDeps.newEngine
	}
	if deps.newDisplay == nil {
		deps.newDisplay = defaultReportDeps.newDisplay
	}
	if deps.buildHeaderCtx == nil {
		deps.buildHeaderCtx = defaultReportDeps.buildHeaderCtx
	}
	if deps.runReview == nil {
		deps.runReview = defaultReportDeps.runReview
	}

	if deps.newDisplay == nil {
		return fmt.Errorf("missing report dependency: newDisplay")
	}
	if deps.buildHeaderCtx == nil {
		return fmt.Errorf("missing report dependency: buildHeaderCtx")
	}
	if deps.runReview == nil {
		return fmt.Errorf("missing report dependency: runReview")
	}
	if !dryRun && deps.newEngine == nil {
		return fmt.Errorf("missing report dependency: newEngine")
	}
	if out == nil {
		out = os.Stdout
	}

	display := deps.newDisplay(out)
	normalizedEngineName := normalizeReviewEngine(engineName)

	var eng engine.Engine
	if !dryRun {
		var err error
		eng, err = deps.newEngine(normalizedEngineName)
		if err != nil {
			return fmt.Errorf("failed to create engine: %w", err)
		}
	}

	display.ShowCommandHeader("Review", "work session", deps.buildHeaderCtx(normalizedEngineName))

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

	if jsonMode {
		return outputReportJSON(out, result)
	}

	showReviewResult(out, display, result)
	return nil
}

func outputReportJSON(out io.Writer, result *compound.ReviewResult) error {
	jr := ReportResult{
		ContractVersion: 1,
		OK:              true,
	}
	if result != nil {
		jr.ReportPath = result.ReportPath
		jr.Summary = result.Summary
		jr.PatternsAdded = result.PatternsAdded
		jr.Recommendations = result.Recommendations
		jr.Issues = result.Issues
		jr.TechDebt = result.TechDebt
		if result.ReportPath != "" {
			jr.NextAction = &struct {
				ID          string `json:"id"`
				Command     string `json:"command"`
				Description string `json:"description"`
			}{
				ID:          "run_auto",
				Command:     "hal auto",
				Description: "Start compound execution from the generated report.",
			}
		}
	}
	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report result: %w", err)
	}
	fmt.Fprintln(out, string(data))
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
		fmt.Fprintf(out, "%s %s\n", engine.StyleBold.Render("Summary:"), result.Summary)
	}

	if len(result.Issues) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s %d issue(s) found during session\n", engine.StyleBold.Render("Issues:"), len(result.Issues))
		for _, issue := range result.Issues {
			fmt.Fprintf(out, "  %s %s\n", engine.StyleWarning.Render("•"), issue)
		}
	}

	if len(result.PatternsAdded) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s %d pattern(s) added to AGENTS.md\n", engine.StyleBold.Render("Patterns:"), len(result.PatternsAdded))
		for _, pattern := range result.PatternsAdded {
			fmt.Fprintf(out, "  %s %s\n", engine.StyleSuccess.Render("•"), pattern)
		}
	}

	if len(result.TechDebt) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s\n", engine.StyleBold.Render("Tech Debt:"))
		for _, debt := range result.TechDebt {
			fmt.Fprintf(out, "  %s %s\n", engine.StyleMuted.Render("•"), debt)
		}
	}

	if len(result.Recommendations) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s\n", engine.StyleBold.Render("Recommendations:"))
		for i, rec := range result.Recommendations {
			fmt.Fprintf(out, "  %s %s\n", engine.StyleInfo.Render(fmt.Sprintf("%d.", i+1)), rec)
		}
	}
}
