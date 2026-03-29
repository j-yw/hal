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
	autoSkipCIFlag bool
	autoSkipPRFlag bool
	autoReportFlag string
	autoEngineFlag string
	autoBaseFlag   string
	autoJSONFlag   bool
)

type autoEntryMode string

const (
	autoEntryModeMarkdownPath    autoEntryMode = "markdown_path"
	autoEntryModeReportDiscovery autoEntryMode = "report_discovery"
)

type autoStepStatus string

const (
	autoStepStatusCompleted autoStepStatus = "completed"
	autoStepStatusSkipped   autoStepStatus = "skipped"
	autoStepStatusFailed    autoStepStatus = "failed"
	autoStepStatusPending   autoStepStatus = "pending"
)

// AutoResult is the machine-readable output of hal auto --json.
type AutoResult struct {
	ContractVersion int             `json:"contractVersion"`
	OK              bool            `json:"ok"`
	EntryMode       string          `json:"entryMode"`
	Resumed         bool            `json:"resumed"`
	Duration        string          `json:"duration,omitempty"`
	Steps           AutoSteps       `json:"steps"`
	Error           string          `json:"error,omitempty"`
	Summary         string          `json:"summary"`
	NextAction      *AutoNextAction `json:"nextAction,omitempty"`
}

// AutoStep captures status and optional telemetry for one pipeline step.
type AutoStep struct {
	Status       autoStepStatus `json:"status"`
	Reason       string         `json:"reason,omitempty"`
	Error        string         `json:"error,omitempty"`
	Duration     string         `json:"duration,omitempty"`
	Branch       string         `json:"branch,omitempty"`
	Path         string         `json:"path,omitempty"`
	Tasks        int            `json:"tasks,omitempty"`
	Attempts     int            `json:"attempts,omitempty"`
	Iterations   int            `json:"iterations,omitempty"`
	IssuesFound  int            `json:"issuesFound,omitempty"`
	FixesApplied int            `json:"fixesApplied,omitempty"`
	PRURL        string         `json:"prUrl,omitempty"`
}

// AutoSteps contains the required fixed step map for auto-v2 JSON output.
type AutoSteps struct {
	Analyze  AutoStep `json:"analyze"`
	Spec     AutoStep `json:"spec"`
	Branch   AutoStep `json:"branch"`
	Convert  AutoStep `json:"convert"`
	Validate AutoStep `json:"validate"`
	Run      AutoStep `json:"run"`
	Review   AutoStep `json:"review"`
	Report   AutoStep `json:"report"`
	CI       AutoStep `json:"ci"`
	Archive  AutoStep `json:"archive"`
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

var autoStepOrder = []string{
	compound.StepAnalyze,
	compound.StepSpec,
	compound.StepBranch,
	compound.StepConvert,
	compound.StepValidate,
	compound.StepRun,
	compound.StepReview,
	compound.StepReport,
	compound.StepCI,
	compound.StepArchive,
}

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
  hal auto --skip-ci                 # Skip CI step at the end
  hal auto --skip-pr                 # Deprecated alias for --skip-ci
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
	autoCmd.Flags().BoolVar(&autoSkipCIFlag, "skip-ci", false, "Skip CI step at end")
	autoCmd.Flags().BoolVar(&autoSkipPRFlag, "skip-pr", false, "[deprecated] Alias for --skip-ci")
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
	skipCI := autoSkipCIFlag
	skipPRAlias := autoSkipPRFlag
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
		if cmd.Flags().Lookup("skip-ci") != nil {
			value, err := cmd.Flags().GetBool("skip-ci")
			if err != nil {
				return err
			}
			skipCI = value
		}
		if cmd.Flags().Lookup("skip-pr") != nil {
			value, err := cmd.Flags().GetBool("skip-pr")
			if err != nil {
				return err
			}
			skipPRAlias = value
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

	if skipPRAlias {
		skipCI = true
		warnDeprecated(errOut, "--skip-pr is deprecated; use --skip-ci")
	}

	if resume {
		if sourceMarkdown != "" {
			warnResumeInputIgnored(errOut, "positional prd-path")
			sourceMarkdown = ""
		}
		if strings.TrimSpace(reportPath) != "" {
			warnResumeInputIgnored(errOut, "--report")
			reportPath = ""
		}
	}

	entryMode := determineAutoEntryMode(sourceMarkdown)

	if err := compound.MigrateLegacyAutoPRD(dir, errOut); err != nil {
		if jsonMode {
			jr := autoFailureResult(entryMode, resume, "failed to migrate legacy auto-prd.json: "+err.Error(), "failed to migrate legacy auto-prd.json: "+err.Error(), autoFailurePipeline, false, "")
			return outputAutoJSON(out, jr)
		}
		return fmt.Errorf("failed to migrate legacy auto-prd.json: %w", err)
	}

	// Load config
	config, err := compound.LoadConfig(dir)
	if err != nil {
		if jsonMode {
			jr := autoFailureResult(entryMode, resume, "failed to load config: "+err.Error(), "failed to load config: "+err.Error(), autoFailureConfig, false, "")
			return outputAutoJSON(out, jr)
		}
		return fmt.Errorf("failed to load config: %w", err)
	}

	resolvedEngine, err := resolveEngine(cmd, "engine", engineName, dir)
	if err != nil {
		if jsonMode {
			jr := autoFailureResult(entryMode, resume, err.Error(), err.Error(), autoFailureEngine, false, "")
			return outputAutoJSON(out, jr)
		}
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	// Create engine with per-engine config
	engineCfg := compound.LoadEngineConfig(dir, resolvedEngine)
	eng, err := engine.NewWithConfig(resolvedEngine, engineCfg)
	if err != nil {
		if jsonMode {
			jr := autoFailureResult(entryMode, resume, "failed to create engine: "+err.Error(), "failed to create engine: "+err.Error(), autoFailureEngine, false, "")
			return outputAutoJSON(out, jr)
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
				jr := autoFailureResult(entryMode, resume, err.Error(), err.Error(), autoFailureNoReports, false, compound.StepAnalyze)
				return outputAutoJSON(out, jr)
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
				jr := autoFailureResult(entryMode, resume, "no saved state to resume from", "no saved state to resume from", autoFailureNoResumeState, false, "")
				return outputAutoJSON(out, jr)
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
		SkipCI:         skipCI,
		ReportPath:     reportPath,
		SourceMarkdown: sourceMarkdown,
		BaseBranch:     baseBranch,
	}

	// Run the pipeline
	if err := pipeline.Run(ctx, opts); err != nil {
		if jsonMode {
			failedStep := autoFailedStep(err)
			summary := err.Error()
			if failedStep != "" {
				summary = fmt.Sprintf("Auto pipeline stopped at %s.", failedStep)
			}
			jr := autoFailureResult(entryMode, resume, summary, err.Error(), autoFailurePipeline, pipeline.HasState(), failedStep, time.Since(autoStart))
			return outputAutoJSON(out, jr)
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
		jr := autoSuccessResult(entryMode, resume, skipCI, summary, elapsed)
		return outputAutoJSON(out, jr)
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

func outputAutoJSON(out io.Writer, jr AutoResult) error {
	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal auto result: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func autoSuccessResult(entryMode autoEntryMode, resumed bool, skipCI bool, summary string, duration time.Duration) AutoResult {
	jr := AutoResult{
		ContractVersion: 2,
		OK:              true,
		EntryMode:       string(entryMode),
		Resumed:         resumed,
		Steps:           autoStepsForSuccess(entryMode, skipCI),
		Summary:         summary,
		NextAction: &AutoNextAction{
			ID:          "run_report",
			Command:     "hal report",
			Description: "Generate a report for the completed auto pipeline work.",
		},
	}
	if duration > 0 {
		jr.Duration = duration.Round(time.Second).String()
	}
	return jr
}

func autoFailureResult(entryMode autoEntryMode, resumed bool, summary string, errorMsg string, failure autoFailureKind, resumable bool, failedStep string, opts ...time.Duration) AutoResult {
	jr := AutoResult{
		ContractVersion: 2,
		OK:              false,
		EntryMode:       string(entryMode),
		Resumed:         resumed,
		Steps:           autoStepsForFailure(entryMode, failedStep),
		Error:           errorMsg,
		Summary:         summary,
		NextAction:      autoFailureNextAction(failure, resumable),
	}
	if len(opts) > 0 && opts[0] > 0 {
		jr.Duration = opts[0].Round(time.Second).String()
	}
	return jr
}

func determineAutoEntryMode(sourceMarkdown string) autoEntryMode {
	if strings.TrimSpace(sourceMarkdown) != "" {
		return autoEntryModeMarkdownPath
	}
	return autoEntryModeReportDiscovery
}

func warnResumeInputIgnored(errOut io.Writer, input string) {
	if errOut == nil {
		return
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return
	}
	fmt.Fprintf(errOut, "warning: --resume ignores %s; using saved state\n", input)
}

func newPendingAutoSteps() AutoSteps {
	return AutoSteps{
		Analyze:  AutoStep{Status: autoStepStatusPending},
		Spec:     AutoStep{Status: autoStepStatusPending},
		Branch:   AutoStep{Status: autoStepStatusPending},
		Convert:  AutoStep{Status: autoStepStatusPending},
		Validate: AutoStep{Status: autoStepStatusPending},
		Run:      AutoStep{Status: autoStepStatusPending},
		Review:   AutoStep{Status: autoStepStatusPending},
		Report:   AutoStep{Status: autoStepStatusPending},
		CI:       AutoStep{Status: autoStepStatusPending},
		Archive:  AutoStep{Status: autoStepStatusPending},
	}
}

func newAutoSteps(entryMode autoEntryMode) AutoSteps {
	steps := newPendingAutoSteps()
	if entryMode == autoEntryModeMarkdownPath {
		steps.Analyze.Status = autoStepStatusSkipped
		steps.Analyze.Reason = "markdown_path_provided"
		steps.Spec.Status = autoStepStatusSkipped
		steps.Spec.Reason = "markdown_path_provided"
	}
	return steps
}

func autoStepsForSuccess(entryMode autoEntryMode, skipCI bool) AutoSteps {
	steps := newAutoSteps(entryMode)

	for _, stepName := range autoStepOrder {
		step := steps.step(stepName)
		if step == nil {
			continue
		}
		if step.Status == autoStepStatusSkipped {
			continue
		}
		step.Status = autoStepStatusCompleted
	}

	if skipCI {
		if ci := steps.step(compound.StepCI); ci != nil {
			ci.Status = autoStepStatusSkipped
			ci.Reason = "skip_ci_flag"
		}
		if archive := steps.step(compound.StepArchive); archive != nil {
			archive.Status = autoStepStatusSkipped
			archive.Reason = "skip_ci_flag"
		}
	}

	return steps
}

func autoStepsForFailure(entryMode autoEntryMode, failedStep string) AutoSteps {
	steps := newAutoSteps(entryMode)
	failureIdx := autoStepIndex(failedStep)
	if failureIdx < 0 {
		return steps
	}

	for idx, stepName := range autoStepOrder {
		step := steps.step(stepName)
		if step == nil {
			continue
		}

		switch {
		case idx < failureIdx:
			if step.Status == autoStepStatusSkipped {
				continue
			}
			step.Status = autoStepStatusCompleted
		case idx == failureIdx:
			step.Status = autoStepStatusFailed
			step.Reason = ""
		}
	}

	return steps
}

func autoStepIndex(step string) int {
	for idx, stepName := range autoStepOrder {
		if stepName == step {
			return idx
		}
	}
	return -1
}

func autoFailedStep(err error) string {
	if err == nil {
		return ""
	}

	message := strings.TrimSpace(err.Error())
	if !strings.HasPrefix(message, "step ") {
		return ""
	}

	rest := strings.TrimPrefix(message, "step ")
	idx := strings.Index(rest, " failed:")
	if idx <= 0 {
		return ""
	}

	step := strings.TrimSpace(rest[:idx])
	if autoStepIndex(step) < 0 {
		return ""
	}
	return step
}

func (steps *AutoSteps) step(step string) *AutoStep {
	switch step {
	case compound.StepAnalyze:
		return &steps.Analyze
	case compound.StepSpec:
		return &steps.Spec
	case compound.StepBranch:
		return &steps.Branch
	case compound.StepConvert:
		return &steps.Convert
	case compound.StepValidate:
		return &steps.Validate
	case compound.StepRun:
		return &steps.Run
	case compound.StepReview:
		return &steps.Review
	case compound.StepReport:
		return &steps.Report
	case compound.StepCI:
		return &steps.CI
	case compound.StepArchive:
		return &steps.Archive
	default:
		return nil
	}
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
