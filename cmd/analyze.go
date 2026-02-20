package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var (
	analyzeReportsDirFlag string
	analyzeFormatFlag     string
	analyzeOutputFlag     string
	analyzeEngineFlag     string
)

type analyzeDeps struct {
	loadConfig     func(dir string) (*compound.AutoConfig, error)
	findLatest     func(reportsDir string) (string, error)
	findRecentPRDs func(dir string, days int) ([]string, error)
	newEngine      func(name string) (engine.Engine, error)
	analyzeReport  func(ctx context.Context, eng engine.Engine, reportPath string, recentPRDs []string) (*compound.AnalysisResult, error)
}

var defaultAnalyzeDeps = analyzeDeps{
	loadConfig:     compound.LoadConfig,
	findLatest:     compound.FindLatestReport,
	findRecentPRDs: compound.FindRecentPRDs,
	newEngine:      newEngine,
	analyzeReport:  compound.AnalyzeReport,
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze [report-path]",
	Short: "Analyze a report to identify the highest priority item",
	Long: `Analyze a product/engineering report to identify the highest priority item.

By default, looks for the most recently modified file in .hal/reports/.
You can specify a report file path directly as an argument.

The analysis returns:
  - Priority item title
  - Description of what needs to be built
  - Rationale for prioritization
  - Estimated number of tasks
  - Suggested branch name

Examples:
  hal analyze                           # Analyze latest report
  hal analyze report.md                 # Analyze specific file
  hal analyze --reports-dir ./reports   # Use custom reports directory
  hal analyze --format json             # Output as JSON
  hal analyze --output json             # Deprecated alias for --format`,
	Args: maxArgsValidation(1),
	RunE: runAnalyze,
}

func init() {
	analyzeCmd.Flags().StringVar(&analyzeReportsDirFlag, "reports-dir", "", "Directory containing reports (overrides config)")
	analyzeCmd.Flags().StringVarP(&analyzeFormatFlag, "format", "f", "text", "Output format: text (default) or json")
	analyzeCmd.Flags().StringVarP(&analyzeOutputFlag, "output", "o", "", "[deprecated] Alias for --format")
	analyzeCmd.Flags().StringVarP(&analyzeEngineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")
	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	return runAnalyzeWithDeps(cmd, args, defaultAnalyzeDeps)
}

func runAnalyzeWithDeps(cmd *cobra.Command, args []string, deps analyzeDeps) error {
	if deps.loadConfig == nil {
		deps.loadConfig = compound.LoadConfig
	}
	if deps.findLatest == nil {
		deps.findLatest = compound.FindLatestReport
	}
	if deps.findRecentPRDs == nil {
		deps.findRecentPRDs = compound.FindRecentPRDs
	}
	if deps.newEngine == nil {
		deps.newEngine = newEngine
	}
	if deps.analyzeReport == nil {
		deps.analyzeReport = compound.AnalyzeReport
	}

	ctx := context.Background()
	out := io.Writer(os.Stdout)
	errOut := io.Writer(os.Stderr)

	reportsDirOverride := analyzeReportsDirFlag
	formatFlagValue := analyzeFormatFlag
	outputAliasValue := analyzeOutputFlag
	engineName := analyzeEngineFlag
	formatChanged := false
	outputChanged := false

	if cmd != nil {
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		out = cmd.OutOrStdout()
		errOut = cmd.ErrOrStderr()

		flags := cmd.Flags()
		if flags.Lookup("reports-dir") != nil {
			value, err := flags.GetString("reports-dir")
			if err != nil {
				return err
			}
			reportsDirOverride = value
		}
		if flags.Lookup("format") != nil {
			value, err := flags.GetString("format")
			if err != nil {
				return err
			}
			formatFlagValue = value
			formatChanged = flags.Changed("format")
		}
		if flags.Lookup("output") != nil {
			value, err := flags.GetString("output")
			if err != nil {
				return err
			}
			outputAliasValue = value
			outputChanged = flags.Changed("output")
		}
		if flags.Lookup("engine") != nil {
			value, err := flags.GetString("engine")
			if err != nil {
				return err
			}
			engineName = value
		}
	}

	if formatChanged && outputChanged {
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("--output/-o cannot be used with --format/-f"))
	}

	formatValue := formatFlagValue
	if outputChanged {
		warnDeprecated(errOut, "--output/-o is deprecated; use --format/-f")
		formatValue = outputAliasValue
	}

	format, err := validateFormat(formatValue, "text", "json")
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	config, err := deps.loadConfig(".")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	reportsDir := config.ReportsDir
	if reportsDirOverride != "" {
		reportsDir = reportsDirOverride
	}

	reportPath := ""
	if len(args) > 0 {
		reportPath = args[0]
		if _, err := os.Stat(reportPath); os.IsNotExist(err) {
			return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("report file not found: %s", reportPath))
		}
	} else {
		reportPath, err = deps.findLatest(reportsDir)
		if err != nil {
			if errors.Is(err, compound.ErrNoReportsFound) {
				if format == "json" {
					return exitWithCode(cmd, ExitCodeAnalyzeNoReportsJSON, err)
				}
				fmt.Fprintln(out, "No reports found.")
				fmt.Fprintln(out)
				fmt.Fprintf(out, "Place your reports in %s/ and run this command again.\n", reportsDir)
				fmt.Fprintln(out, "Reports can be markdown files, text files, or any format the AI can analyze.")
				return nil
			}
			return fmt.Errorf("failed to find latest report: %w", err)
		}
	}

	resolvedEngine, err := resolveEngine(cmd, "engine", engineName, ".")
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	eng, err := deps.newEngine(resolvedEngine)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	if format != "json" {
		display := engine.NewDisplay(out)
		display.ShowCommandHeader("Analyze", filepath.Base(reportPath), buildHeaderCtx(resolvedEngine))
	}

	recentPRDs, err := deps.findRecentPRDs(".", 7)
	if err != nil {
		fmt.Fprintf(errOut, "warning: could not find recent PRDs: %v\n", err)
		recentPRDs = nil
	}

	result, err := deps.analyzeReport(ctx, eng, reportPath, recentPRDs)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	if format == "json" {
		return outputAnalysisJSON(result, out)
	}
	return outputAnalysisText(result, template.HalDir, config.BranchPrefix, out)
}

func outputAnalysisJSON(result *compound.AnalysisResult, w io.Writer) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Fprintln(w, string(data))
	return nil
}

func outputAnalysisText(result *compound.AnalysisResult, halDir string, branchPrefix string, w io.Writer) error {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "═══════════════════════════════════════════════════════════════")
	fmt.Fprintln(w, "  ANALYSIS RESULT")
	fmt.Fprintln(w, "═══════════════════════════════════════════════════════════════")
	fmt.Fprintln(w)

	fmt.Fprintf(w, "  Priority Item:    %s\n", result.PriorityItem)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "  Description:")
	fmt.Fprintf(w, "    %s\n", result.Description)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "  Rationale:")
	fmt.Fprintf(w, "    %s\n", result.Rationale)
	fmt.Fprintln(w)

	if len(result.AcceptanceCriteria) > 0 {
		fmt.Fprintln(w, "  Acceptance Criteria:")
		for _, criterion := range result.AcceptanceCriteria {
			fmt.Fprintf(w, "    - %s\n", criterion)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "  Estimated Tasks:  %d\n", result.EstimatedTasks)
	fmt.Fprintf(w, "  Suggested Branch: %s%s\n", branchPrefix, result.BranchName)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "═══════════════════════════════════════════════════════════════")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Next steps:")
	fmt.Fprintln(w, "  1. hal auto --report <path>  # Run full pipeline")
	fmt.Fprintf(w, "  2. Or manually create a PRD in %s/\n", halDir)
	fmt.Fprintln(w)

	return nil
}
