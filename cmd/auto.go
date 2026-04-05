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
	autoDryRunFlag       bool
	autoResumeFlag       bool
	autoNoCIFlag         bool
	autoSkipPRFlag       bool
	autoNoReviewFlag     bool
	autoModeFlag         string
	autoReviewStreakFlag int
	autoReviewMaxFlag    int
	autoReportFlag       string
	autoEngineFlag       string
	autoBaseFlag         string
	autoJSONFlag         bool
)

type autoEntryMode string

const (
	autoEntryModeMarkdownPath    autoEntryMode = "markdown_path"
	autoEntryModeReportDiscovery autoEntryMode = "report_discovery"
)

type autoStepStatus string

type autoPolicy struct {
	mode              string
	skipCI            bool
	skipReview        bool
	reviewCleanStreak int
	reviewMaxCycles   int
}

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
	CI       AutoStep `json:"ci"`
	Report   AutoStep `json:"report"`
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
	autoFailureNoSource      autoFailureKind = "no_source"
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
	compound.StepCI,
	compound.StepReport,
	compound.StepArchive,
}

var autoCmd = &cobra.Command{
	Use:   "auto [prd-path]",
	Short: "Run the single deterministic auto pipeline",
	Args:  maxArgsValidation(1),
	Long: `Execute the single deterministic auto pipeline.

Canonical runtime PRD:
- convert writes .hal/prd.json
- validate, run, review, ci, report, and archive consume that runtime state

Pipeline order:
  analyze -> spec -> branch -> convert -> validate -> run -> review -> ci -> report -> archive

Entry behavior:
- hal auto <prd-path>: skips analyze/spec and starts at branch
- --resume ignores positional prd-path and --report

Source selection (when not resuming):
  1. positional markdown path (hal auto <prd-path>)
  2. explicit report path (hal auto --report <path>)
  3. discovery order uses auto.sourcePriority
     - report_first (default): latest report in auto.reportsDir -> newest .hal/prd-*.md
     - markdown_first: newest .hal/prd-*.md -> latest report in auto.reportsDir

Convert mode policy:
  - auto.convertMode=auto (default): markdown entry -> standard, report entry -> granular
  - auto.convertMode=standard|granular overrides entry defaults for new runs
  - --resume always uses saved state convert mode

Examples:
  hal auto                           # Uses auto.sourcePriority discovery + auto.convertMode policy
  hal auto .hal/prd-feature.md       # Start from a specific markdown PRD
  hal auto --report report.md        # Force report-driven flow (skip markdown auto-discovery)
  hal auto --mode strict             # Strict gate policy (review+ci, 3 clean review cycles)
  hal auto --mode fast               # Fast policy (skip review and ci)
  hal auto --no-review               # Disable review gate for this run
  hal auto --no-ci                   # Disable CI gate for this run
  hal auto --review-streak 3         # Require 3 consecutive clean review cycles
  hal auto --review-max 15           # Cap review cycles for this run
  hal auto --dry-run                 # Show what would happen without executing
  hal auto --resume                  # Continue from last saved state
  hal auto --json                    # Machine-readable result output`,
	Example: `  hal auto
  hal auto .hal/prd-feature.md --dry-run
  hal auto --json
  hal auto --report .hal/reports/report.md
  hal auto --mode strict
  hal auto --no-ci
  hal auto --review-streak 3 --review-max 15
  hal auto --engine codex --base develop`,
	RunE: runAuto,
}

func init() {
	autoCmd.Flags().BoolVar(&autoDryRunFlag, "dry-run", false, "Show steps without executing")
	autoCmd.Flags().BoolVar(&autoResumeFlag, "resume", false, "Continue from last saved state")
	autoCmd.Flags().BoolVar(&autoNoCIFlag, "no-ci", false, "Disable CI gate for this run")
	autoCmd.Flags().BoolVar(&autoSkipPRFlag, "skip-pr", false, "Deprecated alias for --no-ci")
	_ = autoCmd.Flags().MarkHidden("skip-pr")
	_ = autoCmd.Flags().MarkDeprecated("skip-pr", "use --no-ci instead")
	autoCmd.Flags().BoolVar(&autoNoReviewFlag, "no-review", false, "Disable review gate for this run")
	autoCmd.Flags().StringVarP(&autoModeFlag, "mode", "m", "", "Policy preset: fast, balanced, strict (default from config)")
	autoCmd.Flags().IntVar(&autoReviewStreakFlag, "review-streak", 0, "Consecutive clean review cycles required (default from mode/config)")
	autoCmd.Flags().IntVar(&autoReviewMaxFlag, "review-max", 0, "Maximum review cycles before failing (default from mode/config)")
	autoCmd.Flags().StringVar(&autoReportFlag, "report", "", "Specific report file (overrides markdown auto-discovery, skips find latest)")
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
	noCI := autoNoCIFlag
	skipPR := autoSkipPRFlag
	noReview := autoNoReviewFlag
	mode := autoModeFlag
	reviewStreak := autoReviewStreakFlag
	reviewMax := autoReviewMaxFlag
	reportPath := autoReportFlag
	engineName := autoEngineFlag
	baseBranch := autoBaseFlag
	jsonMode := autoJSONFlag

	noCIChanged := false
	skipPRChanged := false
	modeChanged := false
	reviewStreakChanged := false
	reviewMaxChanged := false

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
		if cmd.Flags().Lookup("no-ci") != nil {
			value, err := cmd.Flags().GetBool("no-ci")
			if err != nil {
				return err
			}
			noCI = value
			noCIChanged = cmd.Flags().Changed("no-ci")
		}
		if cmd.Flags().Lookup("skip-pr") != nil {
			value, err := cmd.Flags().GetBool("skip-pr")
			if err != nil {
				return err
			}
			skipPR = value
			skipPRChanged = cmd.Flags().Changed("skip-pr")
		}
		if cmd.Flags().Lookup("no-review") != nil {
			value, err := cmd.Flags().GetBool("no-review")
			if err != nil {
				return err
			}
			noReview = value
		}
		if cmd.Flags().Lookup("mode") != nil {
			value, err := cmd.Flags().GetString("mode")
			if err != nil {
				return err
			}
			mode = value
			modeChanged = cmd.Flags().Changed("mode")
		}
		if cmd.Flags().Lookup("review-streak") != nil {
			value, err := cmd.Flags().GetInt("review-streak")
			if err != nil {
				return err
			}
			reviewStreak = value
			reviewStreakChanged = cmd.Flags().Changed("review-streak")
		}
		if cmd.Flags().Lookup("review-max") != nil {
			value, err := cmd.Flags().GetInt("review-max")
			if err != nil {
				return err
			}
			reviewMax = value
			reviewMaxChanged = cmd.Flags().Changed("review-max")
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
	if skipPRChanged && !noCIChanged {
		noCI = skipPR
	}

	sourceMarkdown := ""
	if len(args) > 0 {
		sourceMarkdown = strings.TrimSpace(args[0])
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

	entryMode := autoEntryModeReportDiscovery
	autoDiscoveredSource := false
	resolvedConvertMode := ""
	convertModeTelemetry := ""

	if err := compound.MigrateLegacyAutoPRD(dir, errOut); err != nil {
		if jsonMode {
			jr := autoFailureResult(entryMode, resume, "failed to migrate legacy auto-prd.json: "+err.Error(), "failed to migrate legacy auto-prd.json: "+err.Error(), autoFailurePipeline, false, "", "")
			return outputAutoJSON(out, jr)
		}
		return fmt.Errorf("failed to migrate legacy auto-prd.json: %w", err)
	}

	// Load config
	config, err := compound.LoadConfig(dir)
	if err != nil {
		if jsonMode {
			jr := autoFailureResult(entryMode, resume, "failed to load config: "+err.Error(), "failed to load config: "+err.Error(), autoFailureConfig, false, "", "")
			return outputAutoJSON(out, jr)
		}
		return fmt.Errorf("failed to load config: %w", err)
	}

	if resume {
		if resumeEntryMode, ok := determineAutoResumeEntryMode(dir); ok {
			entryMode = resumeEntryMode
		}
		resolvedConvertMode, _ = determineAutoResumeConvertMode(dir)
		if resolvedConvertMode == "" {
			resolvedConvertMode = compound.AutoConvertModeGranular
		}
		if normalizedMode, ok := normalizeAutoConvertModeTelemetry(resolvedConvertMode); ok {
			convertModeTelemetry = normalizedMode
		}
	} else {
		attemptedEntryMode := determineAutoEntryMode(sourceMarkdown)
		selection, resolveErr := resolveAutoEntrySource(dir, config, sourceMarkdown, reportPath)
		if resolveErr != nil {
			resolvedConvertMode, _ = resolveAutoConvertModeForMissingSource(config.ConvertMode)
			if normalizedMode, ok := normalizeAutoConvertModeTelemetry(resolvedConvertMode); ok {
				convertModeTelemetry = normalizedMode
			}
			if jsonMode {
				jr := autoFailureResult(attemptedEntryMode, false, resolveErr.Error(), resolveErr.Error(), autoFailureNoSource, false, "", convertModeTelemetry)
				return outputAutoJSON(out, jr)
			}
			return resolveErr
		}
		sourceMarkdown = selection.SourceMarkdown
		reportPath = selection.ReportPath
		entryMode = selection.EntryMode
		autoDiscoveredSource = selection.AutoDiscoveredMarkdown

		resolvedConvertMode, _ = resolveAutoConvertMode(config.ConvertMode, entryMode)
		if normalizedMode, ok := normalizeAutoConvertModeTelemetry(resolvedConvertMode); ok {
			convertModeTelemetry = normalizedMode
		}
	}

	if resolvedConvertMode == "" {
		resolvedConvertMode = compound.AutoConvertModeGranular
	}

	policy, err := resolveAutoPolicy(config, autoPolicyInputs{
		mode:                mode,
		modeChanged:         modeChanged,
		noCI:                noCI,
		noReview:            noReview,
		reviewStreak:        reviewStreak,
		reviewStreakChanged: reviewStreakChanged,
		reviewMax:           reviewMax,
		reviewMaxChanged:    reviewMaxChanged,
	})
	if err != nil {
		if jsonMode {
			jr := autoFailureResult(entryMode, resume, err.Error(), err.Error(), autoFailureConfig, false, "", convertModeTelemetry)
			return outputAutoJSON(out, jr)
		}
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	resolvedEngine, err := resolveEngine(cmd, "engine", engineName, dir)
	if err != nil {
		if jsonMode {
			jr := autoFailureResult(entryMode, resume, err.Error(), err.Error(), autoFailureEngine, false, "", convertModeTelemetry)
			return outputAutoJSON(out, jr)
		}
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	// Create engine with per-engine config
	engineCfg := compound.LoadEngineConfig(dir, resolvedEngine)
	eng, err := engine.NewWithConfig(resolvedEngine, engineCfg)
	if err != nil {
		if jsonMode {
			jr := autoFailureResult(entryMode, resume, "failed to create engine: "+err.Error(), "failed to create engine: "+err.Error(), autoFailureEngine, false, "", convertModeTelemetry)
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
		headerContext := buildAutoHeaderContext(resume, entryMode, autoDiscoveredSource, resolvedConvertMode)
		display.ShowCommandHeader("Auto", headerContext, buildHeaderCtx(resolvedEngine))
		display.ShowInfo("   Mode: %s\n", policy.mode)
		if policy.skipReview {
			display.ShowInfo("   Review gate: disabled\n")
		} else {
			display.ShowInfo("   Review gate: clean streak %d, max cycles %d\n", policy.reviewCleanStreak, policy.reviewMaxCycles)
		}
		if policy.skipCI {
			display.ShowInfo("   CI gate: disabled\n")
		}
		if autoDiscoveredSource {
			display.ShowInfo("   Source markdown: %s (auto-discovered)\n", sourceMarkdown)
		}
	}

	// Create pipeline (pass same config for inner loop engine creation)
	pipeline := compound.NewPipeline(config, eng, display, dir)
	pipeline.SetEngineConfig(engineCfg)

	// Check if resuming
	if resume {
		if !pipeline.HasState() {
			if jsonMode {
				jr := autoFailureResult(entryMode, resume, "no saved state to resume from", "no saved state to resume from", autoFailureNoResumeState, false, "", convertModeTelemetry)
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
		Resume:            resume,
		DryRun:            dryRun,
		SkipCI:            policy.skipCI,
		SkipReview:        policy.skipReview,
		ReviewCleanStreak: policy.reviewCleanStreak,
		ReviewMaxCycles:   policy.reviewMaxCycles,
		ReportPath:        reportPath,
		SourceMarkdown:    sourceMarkdown,
		ConvertMode:       resolvedConvertMode,
		BaseBranch:        baseBranch,
	}

	// Run the pipeline
	if err := pipeline.Run(ctx, opts); err != nil {
		if jsonMode {
			failedStep := autoFailedStep(err)
			summary := err.Error()
			if failedStep != "" {
				summary = fmt.Sprintf("Auto pipeline stopped at %s.", failedStep)
			}
			jr := autoFailureResult(entryMode, resume, summary, err.Error(), autoFailurePipeline, pipeline.HasState(), failedStep, convertModeTelemetry, time.Since(autoStart))
			applyAutoFailurePolicySkips(&jr.Steps, failedStep, policy.skipCI, policy.skipReview)
			applyAutoFailureCIState(&jr.Steps, failedStep, pipeline.LastCIState())
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
		jr := autoSuccessResult(entryMode, resume, policy.skipCI, policy.skipReview, pipeline.LastCIState(), summary, convertModeTelemetry, elapsed)
		return outputAutoJSON(out, jr)
	}

	// Show pipeline summary
	summaryParts := []string{fmt.Sprintf("Duration: %s", elapsed.Round(time.Second))}
	if autoBranch != "" {
		summaryParts = append(summaryParts, fmt.Sprintf("Branch: %s", autoBranch))
	}
	// Show PRD task progress if available
	if prd, err := engine.LoadPRDFile(filepath.Join(dir, template.HalDir), template.PRDFile); err == nil {
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

func autoSuccessResult(entryMode autoEntryMode, resumed bool, skipCI bool, skipReview bool, ciState *compound.CIState, summary string, convertMode string, duration time.Duration) AutoResult {
	steps := autoStepsForSuccess(entryMode, skipCI, skipReview, ciState)
	applyConvertModeTelemetry(&steps, convertMode)

	jr := AutoResult{
		ContractVersion: 2,
		OK:              autoStepsSucceeded(steps),
		EntryMode:       string(entryMode),
		Resumed:         resumed,
		Steps:           steps,
		Summary:         summary,
		NextAction: &AutoNextAction{
			ID:          "run_continue",
			Command:     "hal continue",
			Description: "Check workflow status and the next recommended command.",
		},
	}
	if duration > 0 {
		jr.Duration = duration.Round(time.Second).String()
	}
	return jr
}

func autoFailureResult(entryMode autoEntryMode, resumed bool, summary string, errorMsg string, failure autoFailureKind, resumable bool, failedStep string, convertMode string, opts ...time.Duration) AutoResult {
	steps := autoStepsForFailure(entryMode, failedStep)
	applyConvertModeTelemetry(&steps, convertMode)
	if failed := steps.step(failedStep); failed != nil && strings.TrimSpace(errorMsg) != "" {
		failed.Error = errorMsg
	}

	jr := AutoResult{
		ContractVersion: 2,
		OK:              false,
		EntryMode:       string(entryMode),
		Resumed:         resumed,
		Steps:           steps,
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

func buildAutoHeaderContext(resume bool, entryMode autoEntryMode, autoDiscoveredSource bool, convertMode string) string {
	headerMode := convertMode
	if normalized, ok := normalizeAutoConvertModeTelemetry(convertMode); ok {
		headerMode = normalized
	}
	if strings.TrimSpace(headerMode) == "" {
		headerMode = compound.AutoConvertModeGranular
	}

	if resume {
		return fmt.Sprintf("auto pipeline · resume from saved state · convert mode: %s", headerMode)
	}

	switch entryMode {
	case autoEntryModeMarkdownPath:
		if autoDiscoveredSource {
			return fmt.Sprintf("auto pipeline · entry: markdown PRD (auto-discovered) · convert mode: %s", headerMode)
		}
		return fmt.Sprintf("auto pipeline · entry: markdown PRD · convert mode: %s", headerMode)
	default:
		return fmt.Sprintf("auto pipeline · entry: report discovery · convert mode: %s", headerMode)
	}
}

type autoEntrySelection struct {
	SourceMarkdown         string
	ReportPath             string
	EntryMode              autoEntryMode
	AutoDiscoveredMarkdown bool
}

func resolveAutoEntrySource(dir string, config *compound.AutoConfig, sourceMarkdown, reportPath string) (autoEntrySelection, error) {
	selection := autoEntrySelection{EntryMode: autoEntryModeReportDiscovery}

	if strings.TrimSpace(sourceMarkdown) != "" {
		candidate := sourceMarkdown
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(dir, candidate)
		}
		if stat, err := os.Stat(candidate); err != nil {
			if os.IsNotExist(err) {
				return selection, fmt.Errorf("markdown PRD not found: %s", sourceMarkdown)
			}
			return selection, fmt.Errorf("failed to inspect markdown PRD %s: %w", sourceMarkdown, err)
		} else if stat.IsDir() {
			return selection, fmt.Errorf("markdown PRD path is a directory: %s", sourceMarkdown)
		}
		selection.SourceMarkdown = candidate
		selection.EntryMode = autoEntryModeMarkdownPath
		return selection, nil
	}

	if strings.TrimSpace(reportPath) != "" {
		candidate := reportPath
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(dir, candidate)
		}
		if stat, err := os.Stat(candidate); err != nil {
			if os.IsNotExist(err) {
				return selection, fmt.Errorf("report not found: %s", reportPath)
			}
			return selection, fmt.Errorf("failed to inspect report %s: %w", reportPath, err)
		} else if stat.IsDir() {
			return selection, fmt.Errorf("report path is a directory: %s", reportPath)
		}
		selection.ReportPath = candidate
		selection.EntryMode = autoEntryModeReportDiscovery
		return selection, nil
	}

	priority := compound.AutoSourcePriorityReportFirst
	reportsDir := filepath.Join(template.HalDir, "reports")
	if config != nil {
		priority = strings.TrimSpace(config.SourcePriority)
		if strings.TrimSpace(config.ReportsDir) != "" {
			reportsDir = config.ReportsDir
		}
	}

	discoverReportThenMarkdown := func() (autoEntrySelection, error) {
		reportCandidate, foundReport, reportErr := discoverLatestReportCandidate(dir, reportsDir)
		if reportErr != nil {
			return selection, reportErr
		}
		if foundReport {
			selection.ReportPath = reportCandidate
			selection.EntryMode = autoEntryModeReportDiscovery
			return selection, nil
		}

		markdownCandidate, foundMarkdown, markdownErr := discoverNewestMarkdownCandidate(dir)
		if markdownErr != nil {
			return selection, markdownErr
		}
		if foundMarkdown {
			selection.SourceMarkdown = markdownCandidate
			selection.EntryMode = autoEntryModeMarkdownPath
			selection.AutoDiscoveredMarkdown = true
			return selection, nil
		}

		return selection, noAutoSourceError(compound.AutoSourcePriorityReportFirst)
	}

	discoverMarkdownThenReport := func() (autoEntrySelection, error) {
		markdownCandidate, foundMarkdown, markdownErr := discoverNewestMarkdownCandidate(dir)
		if markdownErr != nil {
			return selection, markdownErr
		}
		if foundMarkdown {
			selection.SourceMarkdown = markdownCandidate
			selection.EntryMode = autoEntryModeMarkdownPath
			selection.AutoDiscoveredMarkdown = true
			return selection, nil
		}

		reportCandidate, foundReport, reportErr := discoverLatestReportCandidate(dir, reportsDir)
		if reportErr != nil {
			return selection, reportErr
		}
		if foundReport {
			selection.ReportPath = reportCandidate
			selection.EntryMode = autoEntryModeReportDiscovery
			return selection, nil
		}

		return selection, noAutoSourceError(compound.AutoSourcePriorityMarkdownFirst)
	}

	if priority == compound.AutoSourcePriorityMarkdownFirst {
		return discoverMarkdownThenReport()
	}
	return discoverReportThenMarkdown()
}

func discoverNewestMarkdownCandidate(dir string) (string, bool, error) {
	halDir := filepath.Join(dir, template.HalDir)
	entries, err := os.ReadDir(halDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to read %s: %w", filepath.Join(template.HalDir), err)
	}

	latestPath := ""
	latestName := ""
	var latestTime time.Time
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "prd-") || !strings.HasSuffix(name, ".md") {
			continue
		}

		info, infoErr := entry.Info()
		if infoErr != nil {
			return "", false, fmt.Errorf("failed to inspect markdown PRD candidate %s: %w", filepath.Join(template.HalDir, name), infoErr)
		}

		candidatePath := filepath.Join(halDir, name)
		if latestPath == "" || info.ModTime().After(latestTime) || (info.ModTime().Equal(latestTime) && name < latestName) {
			latestPath = candidatePath
			latestName = name
			latestTime = info.ModTime()
		}
	}

	if latestPath == "" {
		return "", false, nil
	}
	return latestPath, true, nil
}

func discoverLatestReportCandidate(dir, reportsDir string) (string, bool, error) {
	reportsPath := reportsDir
	if strings.TrimSpace(reportsPath) == "" {
		reportsPath = filepath.Join(template.HalDir, "reports")
	}
	if !filepath.IsAbs(reportsPath) {
		reportsPath = filepath.Join(dir, reportsPath)
	}

	entries, err := os.ReadDir(reportsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to read reports directory %s: %w", reportsPath, err)
	}

	latestPath := ""
	latestName := ""
	var latestTime time.Time
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isAutoReportCandidate(name) {
			continue
		}

		info, infoErr := entry.Info()
		if infoErr != nil {
			return "", false, fmt.Errorf("failed to inspect report candidate %s: %w", filepath.Join(reportsPath, name), infoErr)
		}

		candidatePath := filepath.Join(reportsPath, name)
		if latestPath == "" || info.ModTime().After(latestTime) || (info.ModTime().Equal(latestTime) && name < latestName) {
			latestPath = candidatePath
			latestName = name
			latestTime = info.ModTime()
		}
	}

	if latestPath == "" {
		return "", false, nil
	}
	return latestPath, true, nil
}

func isAutoReportCandidate(name string) bool {
	if strings.HasPrefix(name, ".") {
		return false
	}
	// Keep review-loop artifacts out of auto-report discovery.
	return !strings.HasPrefix(name, "review-loop-")
}

func noAutoSourceError(sourcePriority string) error {
	if strings.TrimSpace(sourcePriority) == compound.AutoSourcePriorityMarkdownFirst {
		return fmt.Errorf("no auto source found (sourcePriority=markdown_first): looked for newest .hal/prd-*.md, then latest report in auto.reportsDir; provide 'hal auto <prd-path>' or '--report <path>'")
	}
	return fmt.Errorf("no auto source found (sourcePriority=report_first): looked for latest report in auto.reportsDir, then newest .hal/prd-*.md; provide 'hal auto <prd-path>' or '--report <path>'")
}

func resolveAutoConvertMode(configMode string, entryMode autoEntryMode) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(configMode)) {
	case compound.AutoConvertModeStandard:
		return compound.AutoConvertModeStandard, true
	case compound.AutoConvertModeGranular:
		return compound.AutoConvertModeGranular, true
	case compound.AutoConvertModeAuto:
		switch entryMode {
		case autoEntryModeMarkdownPath:
			return compound.AutoConvertModeStandard, true
		case autoEntryModeReportDiscovery:
			return compound.AutoConvertModeGranular, true
		default:
			return "", false
		}
	default:
		return "", false
	}
}

func resolveAutoConvertModeForMissingSource(configMode string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(configMode)) {
	case compound.AutoConvertModeStandard:
		return compound.AutoConvertModeStandard, true
	case compound.AutoConvertModeGranular:
		return compound.AutoConvertModeGranular, true
	default:
		return "", false
	}
}

func normalizeAutoConvertModeTelemetry(mode string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case compound.AutoConvertModeStandard:
		return compound.AutoConvertModeStandard, true
	case compound.AutoConvertModeGranular:
		return compound.AutoConvertModeGranular, true
	default:
		return "", false
	}
}

func applyConvertModeTelemetry(steps *AutoSteps, convertMode string) {
	if steps == nil {
		return
	}
	mode, ok := normalizeAutoConvertModeTelemetry(convertMode)
	if !ok {
		return
	}
	steps.Convert.Reason = mode
}

type autoResumeStateEntry struct {
	Step           string          `json:"step"`
	SourceMarkdown string          `json:"sourceMarkdown,omitempty"`
	PRDPath        string          `json:"prdPath,omitempty"`
	ConvertMode    string          `json:"convertMode,omitempty"`
	Analysis       json.RawMessage `json:"analysis,omitempty"`
}

func loadAutoResumeState(dir string) (autoResumeStateEntry, bool) {
	statePath := filepath.Join(dir, template.HalDir, template.AutoStateFile)
	data, err := os.ReadFile(statePath)
	if err != nil {
		return autoResumeStateEntry{}, false
	}

	var state autoResumeStateEntry
	if err := json.Unmarshal(data, &state); err != nil {
		return autoResumeStateEntry{}, false
	}

	return state, true
}

func determineAutoResumeEntryMode(dir string) (autoEntryMode, bool) {
	state, ok := loadAutoResumeState(dir)
	if !ok {
		return autoEntryModeReportDiscovery, false
	}

	switch normalizeAutoResumeStep(state.Step) {
	case compound.StepAnalyze, compound.StepSpec:
		return autoEntryModeReportDiscovery, true
	}

	sourceMarkdown := strings.TrimSpace(state.SourceMarkdown)
	if sourceMarkdown == "" {
		sourceMarkdown = strings.TrimSpace(state.PRDPath)
	}
	if sourceMarkdown == "" {
		return autoEntryModeReportDiscovery, true
	}

	analysis := strings.TrimSpace(string(state.Analysis))
	if analysis != "" && analysis != "null" {
		return autoEntryModeReportDiscovery, true
	}

	return autoEntryModeMarkdownPath, true
}

func determineAutoResumeConvertMode(dir string) (string, bool) {
	state, ok := loadAutoResumeState(dir)
	if !ok {
		return compound.AutoConvertModeGranular, false
	}
	if mode, valid := normalizeAutoConvertModeTelemetry(state.ConvertMode); valid {
		return mode, true
	}
	return compound.AutoConvertModeGranular, true
}

func normalizeAutoResumeStep(step string) string {
	switch strings.TrimSpace(step) {
	case "prd":
		return compound.StepSpec
	case "explode":
		return compound.StepConvert
	case "loop":
		return compound.StepRun
	case "pr":
		return compound.StepCI
	default:
		return strings.TrimSpace(step)
	}
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

type autoPolicyInputs struct {
	mode                string
	modeChanged         bool
	noCI                bool
	noReview            bool
	reviewStreak        int
	reviewStreakChanged bool
	reviewMax           int
	reviewMaxChanged    bool
}

func resolveAutoPolicy(config *compound.AutoConfig, in autoPolicyInputs) (autoPolicy, error) {
	if config == nil {
		return autoPolicy{}, fmt.Errorf("auto config is required")
	}

	policy := autoPolicy{
		mode:              config.Mode,
		skipCI:            !config.CIEnabled,
		skipReview:        !config.ReviewEnabled,
		reviewCleanStreak: config.ReviewCleanStreak,
		reviewMaxCycles:   config.ReviewMaxIterations,
	}

	if in.modeChanged {
		settings, err := compound.ResolveAutoModeSettings(in.mode)
		if err != nil {
			return autoPolicy{}, err
		}
		policy.mode = settings.Mode
		policy.skipCI = !settings.CIEnabled
		policy.skipReview = !settings.ReviewEnabled
		policy.reviewCleanStreak = settings.ReviewCleanStreak
		policy.reviewMaxCycles = settings.ReviewMaxIterations
	}

	if in.noReview && (in.reviewStreakChanged || in.reviewMaxChanged) {
		return autoPolicy{}, fmt.Errorf("--no-review cannot be combined with --review-streak or --review-max")
	}

	if in.reviewStreakChanged {
		if in.reviewStreak <= 0 {
			return autoPolicy{}, fmt.Errorf("--review-streak must be greater than 0")
		}
		policy.reviewCleanStreak = in.reviewStreak
		policy.skipReview = false
	}
	if in.reviewMaxChanged {
		if in.reviewMax <= 0 {
			return autoPolicy{}, fmt.Errorf("--review-max must be greater than 0")
		}
		policy.reviewMaxCycles = in.reviewMax
		policy.skipReview = false
	}

	if in.noReview {
		policy.skipReview = true
	}

	if in.noCI {
		policy.skipCI = true
	}

	if policy.reviewCleanStreak <= 0 {
		return autoPolicy{}, fmt.Errorf("auto.reviewCleanStreak must be greater than 0")
	}
	if policy.reviewMaxCycles <= 0 {
		return autoPolicy{}, fmt.Errorf("auto.reviewMaxIterations must be greater than 0")
	}
	if !policy.skipReview && policy.reviewCleanStreak > policy.reviewMaxCycles {
		return autoPolicy{}, fmt.Errorf("review clean streak (%d) cannot exceed review max cycles (%d)", policy.reviewCleanStreak, policy.reviewMaxCycles)
	}

	if policy.mode == "" {
		policy.mode = compound.AutoModeBalanced
	}

	return policy, nil
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
		CI:       AutoStep{Status: autoStepStatusPending},
		Report:   AutoStep{Status: autoStepStatusPending},
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

func autoStepsForSuccess(entryMode autoEntryMode, skipCI bool, skipReview bool, ciState *compound.CIState) AutoSteps {
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

	if review := steps.step(compound.StepReview); review != nil && skipReview {
		review.Status = autoStepStatusSkipped
		review.Reason = "skip_review_flag"
	}

	if ci := steps.step(compound.StepCI); ci != nil {
		if ciSkipReason := autoCISkipReason(skipCI, ciState); ciSkipReason != "" {
			ci.Status = autoStepStatusSkipped
			ci.Reason = ciSkipReason
		} else {
			applyAutoSuccessCIState(ci, ciState)
		}
	}

	return steps
}

func autoStepsSucceeded(steps AutoSteps) bool {
	for _, stepName := range autoStepOrder {
		step := steps.step(stepName)
		if step == nil {
			continue
		}
		if step.Status != autoStepStatusCompleted && step.Status != autoStepStatusSkipped {
			return false
		}
	}
	return true
}

func applyAutoSuccessCIState(ci *AutoStep, ciState *compound.CIState) {
	if ci == nil || ciState == nil {
		return
	}

	status := strings.TrimSpace(ciState.Status)
	if status == "" || status == "passed" {
		return
	}

	ci.Status = autoStepStatusFailed
	reason := strings.TrimSpace(ciState.Reason)
	if reason == "" {
		reason = status
	}
	ci.Reason = reason
}

func autoCISkipReason(skipCI bool, ciState *compound.CIState) string {
	if ciState != nil && ciState.Status == "skipped" {
		reason := strings.TrimSpace(ciState.Reason)
		if reason != "" {
			return reason
		}
		return "skip_ci_flag"
	}

	if skipCI {
		return "skip_ci_flag"
	}

	return ""
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

func applyAutoFailurePolicySkips(steps *AutoSteps, failedStep string, skipCI bool, skipReview bool) {
	if steps == nil {
		return
	}

	failureIdx := autoStepIndex(failedStep)
	if failureIdx < 0 {
		return
	}

	reviewIdx := autoStepIndex(compound.StepReview)
	if skipReview && failureIdx > reviewIdx {
		review := steps.step(compound.StepReview)
		if review != nil {
			review.Status = autoStepStatusSkipped
			review.Reason = "skip_review_flag"
		}
	}

	ciIdx := autoStepIndex(compound.StepCI)
	if failureIdx > ciIdx {
		ci := steps.step(compound.StepCI)
		if ci != nil {
			if reason := autoCISkipReason(skipCI, nil); reason != "" {
				ci.Status = autoStepStatusSkipped
				ci.Reason = reason
			}
		}
	}
}

func applyAutoFailureCIState(steps *AutoSteps, failedStep string, ciState *compound.CIState) {
	if steps == nil || ciState == nil {
		return
	}

	failureIdx := autoStepIndex(failedStep)
	ciIdx := autoStepIndex(compound.StepCI)
	if failureIdx <= ciIdx {
		return
	}

	if strings.TrimSpace(ciState.Status) != "skipped" {
		return
	}

	ciStep := steps.step(compound.StepCI)
	if ciStep == nil {
		return
	}

	ciStep.Status = autoStepStatusSkipped
	reason := strings.TrimSpace(ciState.Reason)
	if reason == "" {
		reason = "skip_ci_flag"
	}
	ciStep.Reason = reason
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
	case compound.StepCI:
		return &steps.CI
	case compound.StepReport:
		return &steps.Report
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
	case autoFailureNoSource:
		return &AutoNextAction{
			ID:          "run_auto",
			Command:     "hal auto <prd-path> or hal auto --report <path>",
			Description: "Provide a markdown PRD path and rerun, or use hal auto --report <path>.",
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
