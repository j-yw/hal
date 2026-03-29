package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var (
	autoDryRunFlag bool
	autoResumeFlag bool
	autoSkipPRFlag bool
	autoReportFlag string
	autoEngineFlag string
	autoBaseFlag   string
	autoJSONFlag   bool
)

// AutoResult is the machine-readable output of hal auto --json.
type AutoResult struct {
	ContractVersion int             `json:"contractVersion"`
	OK              bool            `json:"ok"`
	Resumed         bool            `json:"resumed,omitempty"`
	Duration        string          `json:"duration,omitempty"`
	Branch          string          `json:"branch,omitempty"`
	Tasks           *AutoTasksInfo  `json:"tasks,omitempty"`
	NextAction      *AutoNextAction `json:"nextAction,omitempty"`
	Error           string          `json:"error,omitempty"`
	Summary         string          `json:"summary"`
}

// AutoTasksInfo provides task completion progress for the auto pipeline.
type AutoTasksInfo struct {
	Completed int `json:"completed"`
	Total     int `json:"total"`
}

// AutoNextAction suggests what to do after the auto pipeline.
type AutoNextAction struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	Description string `json:"description"`
}

type autoFailureKind string

const (
	autoFailureNone          autoFailureKind = ""
	autoFailureConfig        autoFailureKind = "config"
	autoFailureEngine        autoFailureKind = "engine"
	autoFailureNoReports     autoFailureKind = "no_reports"
	autoFailureNoResumeState autoFailureKind = "no_resume_state"
	autoFailurePipeline      autoFailureKind = "pipeline"
)

var autoCmd = &cobra.Command{
	Use:   "auto [prd-path]",
	Short: "Run the full compound engineering pipeline",
	Args:  maxArgsValidation(1),
	Long: `Execute the complete compound engineering automation pipeline.

The pipeline steps are:
  1. analyze  - Find and analyze the latest report to identify priority item
  2. spec     - Generate a markdown PRD using the autospec skill
  3. branch   - Create and checkout a new branch for the work
  4. convert  - Break down the PRD into 8-15 granular tasks
  5. run      - Execute the Hal task loop until all tasks pass
  6. ci       - Push the branch and create a draft pull request

If a positional markdown path is provided, auto skips analyze/spec,
uses that file as sourceMarkdown, and starts from the branch step.

The pipeline saves state after each step, allowing you to resume
from interruptions using the --resume flag.

Examples:
  hal auto                           # Run full pipeline with latest report
  hal auto .hal/prd-feature.md       # Start from a specific markdown PRD
  hal auto --report report.md        # Use specific report file
  hal auto --dry-run                 # Show what would happen without executing
  hal auto --resume                  # Continue from last saved state
  hal auto --skip-pr                 # Skip PR creation at the end
  hal auto --base develop            # Use develop as the base branch
  hal auto --json                    # Machine-readable result output`,
	Example: `  hal auto
  hal auto .hal/prd-feature.md --dry-run
  hal auto --json
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
	autoCmd.Flags().BoolVar(&autoJSONFlag, "json", false, "Output machine-readable JSON result")
	rootCmd.AddCommand(autoCmd)
}

func runAuto(cmd *cobra.Command, args []string) error {
	autoStart := time.Now()
	ctx := context.Background()
	out := io.Writer(os.Stdout)
	errOut := io.Writer(os.Stderr)
	dir := "."

	dryRun := autoDryRunFlag
	resume := autoResumeFlag
	skipPR := autoSkipPRFlag
	reportPath := autoReportFlag
	engineName := autoEngineFlag
	baseBranch := autoBaseFlag
	jsonMode := autoJSONFlag

	if cmd != nil {
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		out = cmd.OutOrStdout()
		errOut = cmd.ErrOrStderr()

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
		if cmd.Flags().Lookup("json") != nil {
			value, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = value
		}
	}

	sourceMarkdown := ""
	if len(args) > 0 {
		sourceMarkdown = strings.TrimSpace(args[0])
	}

	if err := compound.MigrateLegacyAutoPRD(dir, errOut); err != nil {
		if jsonMode {
			return outputAutoJSON(out, false, resume, "failed to migrate legacy auto-prd.json: "+err.Error(), autoFailurePipeline, false)
		}
		return fmt.Errorf("failed to migrate legacy auto-prd.json: %w", err)
	}

	// Load config
	config, err := compound.LoadConfig(dir)
	if err != nil {
		if jsonMode {
			return outputAutoJSON(out, false, resume, "failed to load config: "+err.Error(), autoFailureConfig, false)
		}
		return fmt.Errorf("failed to load config: %w", err)
	}

	resolvedEngine, err := resolveEngine(cmd, "engine", engineName, dir)
	if err != nil {
		if jsonMode {
			return outputAutoJSON(out, false, resume, err.Error(), autoFailureEngine, false)
		}
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	// Create engine with per-engine config
	engineCfg := compound.LoadEngineConfig(dir, resolvedEngine)
	eng, err := engine.NewWithConfig(resolvedEngine, engineCfg)
	if err != nil {
		if jsonMode {
			return outputAutoJSON(out, false, resume, "failed to create engine: "+err.Error(), autoFailureEngine, false)
		}
		return fmt.Errorf("failed to create engine: %w", err)
	}

	// Suppress progress/status output in JSON mode so stdout remains parseable JSON.
	displayOut := out
	if jsonMode {
		displayOut = io.Discard
	}
	display := engine.NewDisplay(displayOut)

	// Show command header in human-readable mode only.
	if !jsonMode {
		display.ShowCommandHeader("Auto", "compound pipeline", buildHeaderCtx(resolvedEngine))
	}

	// Create pipeline (pass same config for inner loop engine creation)
	pipeline := compound.NewPipeline(config, eng, display, dir)
	pipeline.SetEngineConfig(engineCfg)

	// Check for reports before starting unless resume/source markdown/report path is provided.
	if !resume && reportPath == "" && sourceMarkdown == "" {
		_, err := compound.FindLatestReport(config.ReportsDir)
		if err != nil {
			if jsonMode {
				return outputAutoJSON(out, false, resume, err.Error(), autoFailureNoReports, false)
			}
			fmt.Fprintf(out, "%s No reports found.\n", engine.StyleWarning.Render("[!]"))
			fmt.Fprintln(out)
			fmt.Fprintf(out, "Place your reports in %s and run this command again.\n", engine.StyleInfo.Render(config.ReportsDir+"/"))
			fmt.Fprintf(out, "%s\n", engine.StyleMuted.Render("Reports can be markdown files, text files, or any format the AI can analyze."))
			return nil
		}
	}

	// Check if resuming
	if resume {
		if !pipeline.HasState() {
			if jsonMode {
				return outputAutoJSON(out, false, resume, "no saved state to resume from", autoFailureNoResumeState, false)
			}
			return fmt.Errorf("no saved state to resume from")
		}
		if !jsonMode {
			display.ShowInfo("   Resuming pipeline from saved state\n")
		}
	} else if pipeline.HasState() {
		if !jsonMode {
			display.ShowInfo("   Note: Previous state exists. Use --resume to continue, or delete .hal/auto-state.json to start fresh.\n")
		}
	}

	// Run options
	opts := compound.RunOptions{
		Resume:         resume,
		DryRun:         dryRun,
		SkipPR:         skipPR,
		ReportPath:     reportPath,
		SourceMarkdown: sourceMarkdown,
		BaseBranch:     baseBranch,
	}

	// Run the pipeline
	if err := pipeline.Run(ctx, opts); err != nil {
		if jsonMode {
			return outputAutoJSON(out, false, resume, err.Error(), autoFailurePipeline, pipeline.HasState(), time.Since(autoStart))
		}
		return err
	}

	elapsed := time.Since(autoStart)

	autoBranch, _ := compound.CurrentBranchOptional()

	if jsonMode {
		summary := "Auto pipeline completed successfully."
		if autoBranch != "" {
			summary = fmt.Sprintf("Auto pipeline completed on branch %s.", autoBranch)
		}
		jr := AutoResult{
			ContractVersion: 1,
			OK:              true,
			Resumed:         resume,
			Duration:        elapsed.Round(time.Second).String(),
			Summary:         summary,
			Branch:          autoBranch,
			NextAction: &AutoNextAction{
				ID:          "run_report",
				Command:     "hal report",
				Description: "Generate a report for the completed auto pipeline work.",
			},
		}
		// Add task progress if available
		if prd, err := engine.LoadPRDFile(filepath.Join(dir, template.HalDir), template.AutoPRDFile); err == nil {
			completed, total := prd.Progress()
			if total > 0 {
				jr.Tasks = &AutoTasksInfo{Completed: completed, Total: total}
			}
		}
		data, err := json.MarshalIndent(jr, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal auto result: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	// Show pipeline summary
	summaryParts := []string{fmt.Sprintf("Duration: %s", elapsed.Round(time.Second))}
	if autoBranch != "" {
		summaryParts = append(summaryParts, fmt.Sprintf("Branch: %s", autoBranch))
	}
	// Show PRD task progress if available
	if prd, err := engine.LoadPRDFile(filepath.Join(dir, template.HalDir), template.AutoPRDFile); err == nil {
		completed, total := prd.Progress()
		if total > 0 {
			summaryParts = append(summaryParts, fmt.Sprintf("Tasks: %d/%d", completed, total))
		}
	}
	display.ShowCommandSuccess("Auto pipeline completed!", strings.Join(summaryParts, " · "))

	return nil
}

func outputAutoJSON(out io.Writer, ok bool, resumed bool, summary string, failure autoFailureKind, resumable bool, opts ...time.Duration) error {
	jr := AutoResult{
		ContractVersion: 1,
		OK:              ok,
		Resumed:         resumed,
		Summary:         summary,
	}
	if len(opts) > 0 && opts[0] > 0 {
		jr.Duration = opts[0].Round(time.Second).String()
	}
	if ok {
		jr.NextAction = &AutoNextAction{
			ID:          "run_report",
			Command:     "hal report",
			Description: "Generate a report for the completed auto pipeline work.",
		}
	} else {
		jr.Error = summary
		jr.NextAction = autoFailureNextAction(failure, resumable)
	}
	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal auto result: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func autoFailureNextAction(failure autoFailureKind, resumable bool) *AutoNextAction {
	switch failure {
	case autoFailureConfig, autoFailureEngine:
		return &AutoNextAction{
			ID:          "run_init",
			Command:     "hal init",
			Description: "Initialize or repair configuration, then retry the auto pipeline.",
		}
	case autoFailureNoReports:
		return &AutoNextAction{
			ID:          "run_auto",
			Command:     "hal auto --report <path>",
			Description: "Provide a report path and rerun the auto pipeline.",
		}
	case autoFailureNoResumeState:
		return &AutoNextAction{
			ID:          "run_auto",
			Command:     "hal auto",
			Description: "Start a fresh auto pipeline run.",
		}
	case autoFailurePipeline:
		if resumable {
			return &AutoNextAction{
				ID:          "resume_auto",
				Command:     "hal auto --resume",
				Description: "Resume the auto pipeline from the last saved state.",
			}
		}
		return &AutoNextAction{
			ID:          "run_auto",
			Command:     "hal auto",
			Description: "Retry the auto pipeline after fixing the reported failure.",
		}
	default:
		return &AutoNextAction{
			ID:          "run_auto",
			Command:     "hal auto",
			Description: "Retry the auto pipeline.",
		}
	}
}
