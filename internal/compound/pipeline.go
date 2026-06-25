package compound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/archive"
	"github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/loop"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
)

// stateFileName references the shared constant for the auto-state file.
var stateFileName = template.AutoStateFile

// convertWithEngine points to prd.ConvertWithEngine and is overridden in tests.
var convertWithEngine = prd.ConvertWithEngine

// validateWithEngine points to prd.ValidateWithEngine and is overridden in tests.
var validateWithEngine = prd.ValidateWithEngine

// repairValidationWithEngine points to prd.RepairValidationWithEngine and is overridden in tests.
var repairValidationWithEngine = prd.RepairValidationWithEngine

// runLoopWithConfig points to loop.New(...).Run and is overridden in tests.
var runLoopWithConfig = func(ctx context.Context, cfg loop.Config) (loop.Result, error) {
	runner, err := loop.New(cfg)
	if err != nil {
		return loop.Result{}, err
	}
	return runner.Run(ctx), nil
}

// runReviewLoopWithDisplay points to RunReviewLoopWithDisplay and is overridden in tests.
var runReviewLoopWithDisplay = RunReviewLoopWithDisplay

// runReviewValidationWithDisplay points to RunReviewValidationWithDisplay and is overridden in tests.
var runReviewValidationWithDisplay = RunReviewValidationWithDisplay

// runReportWithEngine points to Review and is overridden in tests.
var runReportWithEngine = Review

// checkCIDependencies verifies required CI tooling and is overridden in tests.
var checkCIDependencies = defaultCheckCIDependencies

// waitForChecksInDirFn points to ci.WaitForChecksInDir and is overridden in tests.
var waitForChecksInDirFn = ci.WaitForChecksInDir

// fixWithEngineInDirFn points to ci.FixWithEngineInDir and is overridden in tests.
var fixWithEngineInDirFn = ci.FixWithEngineInDir

// createArchiveWithOptions points to archive.CreateWithOptions and is overridden in tests.
var createArchiveWithOptions = archive.CreateWithOptions

// workingTreeChangesInDirFn points to WorkingTreeChangesInDir and is overridden in tests.
var workingTreeChangesInDirFn = WorkingTreeChangesInDir

// gitAddAllInDirFn points to defaultGitAddAllInDir and is overridden in tests.
var gitAddAllInDirFn = defaultGitAddAllInDir

// gitCommitInDirFn points to defaultGitCommitInDir and is overridden in tests.
var gitCommitInDirFn = defaultGitCommitInDir

const (
	defaultReviewIterations      = 10
	maxCIFixAttempts             = 3
	defaultValidationMaxAttempts = 25
	reviewFixCommitMessage       = "fix: address review feedback"
)

// validationRetryDelay spaces validate-loop retries so transient provider/engine
// failures don't create a tight spin loop that burns tokens and floods logs.
// It is a var (not const) so tests can set it to 0 and avoid real sleeps.
var validationRetryDelay = 2 * time.Second

// Pipeline orchestrates the compound engineering automation process.
type Pipeline struct {
	config          *AutoConfig
	engine          engine.Engine
	engineConfig    *engine.EngineConfig
	display         *engine.Display
	dir             string
	lastCIState     *CIState
	pushAndCreatePR func(context.Context, ci.PushOptions) (ci.PushResult, error)
	currentBranch   func(string) (string, error)
}

// NewPipeline creates a new pipeline instance.
func NewPipeline(config *AutoConfig, eng engine.Engine, display *engine.Display, dir string) *Pipeline {
	return &Pipeline{
		config:  config,
		engine:  eng,
		display: display,
		dir:     dir,
		pushAndCreatePR: func(ctx context.Context, opts ci.PushOptions) (ci.PushResult, error) {
			return ci.PushAndCreatePRInDir(ctx, dir, opts)
		},
		currentBranch: CurrentBranchInDir,
	}
}

// SetEngineConfig sets optional per-engine configuration for the pipeline loop.
func (p *Pipeline) SetEngineConfig(cfg *engine.EngineConfig) {
	p.engineConfig = cfg
}

// statePath returns the full path to the state file.
func (p *Pipeline) statePath() string {
	return filepath.Join(p.dir, template.HalDir, stateFileName)
}

type rawPipelineState struct {
	Step           string           `json:"step"`
	BaseBranch     string           `json:"baseBranch,omitempty"`
	BranchName     string           `json:"branchName"`
	ConvertMode    string           `json:"convertMode,omitempty"`
	SourceMarkdown string           `json:"sourceMarkdown,omitempty"`
	ReportPath     string           `json:"reportPath,omitempty"`
	StartedAt      time.Time        `json:"startedAt"`
	Validation     *ValidationState `json:"validation,omitempty"`
	Run            *RunState        `json:"run,omitempty"`
	Review         *ReviewState     `json:"review,omitempty"`
	CI             *CIState         `json:"ci,omitempty"`
	Analysis       *AnalysisResult  `json:"analysis,omitempty"`

	// Legacy fields supported for one-release compatibility.
	PRDPath           string `json:"prdPath,omitempty"`
	LoopIterations    int    `json:"loopIterations,omitempty"`
	LoopComplete      bool   `json:"loopComplete,omitempty"`
	LoopMaxIterations int    `json:"loopMaxIterations,omitempty"`
}

// loadState reads the pipeline state from .hal/auto-state.json.
// Returns nil if the state file doesn't exist.
func (p *Pipeline) loadState() *PipelineState {
	data, err := os.ReadFile(p.statePath())
	if err != nil {
		return nil
	}

	var raw rawPipelineState
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	state := &PipelineState{
		Step:           normalizePipelineStep(raw.Step),
		BaseBranch:     raw.BaseBranch,
		BranchName:     raw.BranchName,
		ConvertMode:    normalizeResolvedConvertMode(raw.ConvertMode),
		SourceMarkdown: raw.SourceMarkdown,
		ReportPath:     raw.ReportPath,
		StartedAt:      raw.StartedAt,
		Validation:     raw.Validation,
		Run:            raw.Run,
		Review:         raw.Review,
		CI:             raw.CI,
		Analysis:       raw.Analysis,
	}

	if state.SourceMarkdown == "" {
		state.SourceMarkdown = raw.PRDPath
	}

	if state.Run == nil && (raw.LoopIterations > 0 || raw.LoopComplete || raw.LoopMaxIterations > 0) {
		state.Run = &RunState{
			Iterations:    raw.LoopIterations,
			Complete:      raw.LoopComplete,
			MaxIterations: raw.LoopMaxIterations,
		}
	}

	return state
}

func normalizePipelineStep(step string) string {
	switch step {
	case "prd":
		return StepSpec
	case "explode":
		return StepConvert
	case "loop":
		return StepRun
	case "pr":
		return StepCI
	default:
		return step
	}
}

func normalizeResolvedConvertMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case AutoConvertModeStandard:
		return AutoConvertModeStandard
	case AutoConvertModeGranular:
		return AutoConvertModeGranular
	default:
		return AutoConvertModeGranular
	}
}

// saveState writes the pipeline state to .hal/auto-state.json atomically.
// It writes to a temp file first, then renames to ensure atomic operation.
func (p *Pipeline) saveState(state *PipelineState) error {
	if state == nil {
		return fmt.Errorf("pipeline state is nil")
	}

	snapshot := *state
	snapshot.ConvertMode = normalizeResolvedConvertMode(state.ConvertMode)
	state.ConvertMode = snapshot.ConvertMode

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	statePath := p.statePath()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(statePath), 0755); err != nil {
		return err
	}

	// Write to temp file first for atomic operation
	tmpPath := statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}

	// Rename temp to final (atomic on most filesystems)
	return os.Rename(tmpPath, statePath)
}

// clearState removes the state file on completion.
func (p *Pipeline) clearState() error {
	err := os.Remove(p.statePath())
	if os.IsNotExist(err) {
		return nil // Not an error if file doesn't exist
	}
	return err
}

// HasState returns true if there is a saved state to resume from.
func (p *Pipeline) HasState() bool {
	return p.loadState() != nil
}

// LastCIState returns CI telemetry from the most recent pipeline run.
func (p *Pipeline) LastCIState() *CIState {
	if p == nil || p.lastCIState == nil {
		return nil
	}
	ci := *p.lastCIState
	return &ci
}

func (p *Pipeline) recordCIState(ci *CIState) {
	if ci == nil {
		p.lastCIState = nil
		return
	}
	ciCopy := *ci
	p.lastCIState = &ciCopy
}

// RunOptions contains options for the pipeline Run method.
type RunOptions struct {
	Resume            bool   // Continue from last saved state
	DryRun            bool   // Show what would happen without executing
	SkipCI            bool   // Skip CI step (push + draft PR) at the end
	SkipReview        bool   // Skip review gate before CI
	ReviewCleanStreak int    // Consecutive clean review cycles required to pass
	ReviewMaxCycles   int    // Maximum review cycles before failing the gate
	ReportPath        string // Specific report file to use (skips find latest)
	SourceMarkdown    string // Positional markdown path (skips analyze/spec)
	ConvertMode       string // Resolved convert mode for this run (standard|granular)
	BaseBranch        string // Base branch for creating work branch / PR target

	MaxRunAttempts       int // Optional factory policy cap; 0 means no policy cap
	MaxReviewFixAttempts int // Optional factory policy cap; 0 means no policy cap
	MaxCIFixAttempts     int // Optional factory policy cap; 0 means no policy cap
}

// Run executes the compound pipeline from the current state or from the beginning.
func (p *Pipeline) Run(ctx context.Context, opts RunOptions) error {
	p.recordCIState(nil)

	// Load or create initial state
	var state *PipelineState
	var err error
	if opts.Resume {
		state = p.loadState()
		if state == nil {
			return fmt.Errorf("no saved state to resume from")
		}
		p.recordCIState(state.CI)
		p.display.ShowInfo("   Resuming from step: %s\n", state.Step)
	} else {
		state, err = p.newInitialState(opts)
		if err != nil {
			return err
		}
	}

	state.ConvertMode = normalizeResolvedConvertMode(state.ConvertMode)

	// Short-circuit if pipeline already completed (e.g. resume with step=done).
	if state.Step == StepDone {
		return nil
	}

	if err := p.initializeBaseBranch(state, opts); err != nil {
		return err
	}
	if state.BaseBranch != "" {
		p.display.ShowInfo("   Base branch: %s\n", state.BaseBranch)
	} else if !opts.DryRun {
		return fmt.Errorf("unable to determine base branch; rerun with --base <branch> (required when HEAD is detached or saved state lacks baseBranch)")
	}

	// Run steps in sequence, starting from current step
	for {
		select {
		case <-ctx.Done():
			// Save state before exiting on context cancellation
			if err := p.saveState(state); err != nil {
				return fmt.Errorf("failed to save state on cancellation: %w", err)
			}
			return ctx.Err()
		default:
		}

		var err error
		switch state.Step {
		case StepAnalyze:
			err = p.runAnalyzeStep(ctx, state, opts)
		case StepSpec:
			err = p.runPRDStep(ctx, state, opts)
		case StepBranch:
			err = p.runBranchStep(ctx, state, opts)
		case StepConvert:
			err = p.runExplodeStep(ctx, state, opts)
		case StepValidate:
			err = p.runValidateStep(ctx, state, opts)
		case StepRun:
			err = p.runLoopStep(ctx, state, opts)
		case StepReview:
			err = p.runReviewStep(ctx, state, opts)
		case StepCI:
			err = p.runPRStep(ctx, state, opts)
		case StepReport:
			err = p.runReportStep(ctx, state, opts)
		case StepArchive:
			err = p.runArchiveStep(ctx, state, opts)
		case StepDone:
			// Pipeline completed successfully
			return nil
		default:
			return fmt.Errorf("unknown pipeline step: %s", state.Step)
		}

		if err != nil {
			// Save state before returning error
			if saveErr := p.saveState(state); saveErr != nil {
				return fmt.Errorf("step %s failed: %w (also failed to save state: %v)", state.Step, err, saveErr)
			}
			return fmt.Errorf("step %s failed: %w", state.Step, err)
		}
	}
}

func (p *Pipeline) newInitialState(opts RunOptions) (*PipelineState, error) {
	state := &PipelineState{
		Step:        StepAnalyze,
		ConvertMode: normalizeResolvedConvertMode(opts.ConvertMode),
		StartedAt:   time.Now(),
	}

	sourceMarkdown := strings.TrimSpace(opts.SourceMarkdown)
	if sourceMarkdown == "" {
		return state, nil
	}

	normalizedSourceMarkdown, err := p.normalizeSourceMarkdownPath(sourceMarkdown)
	if err != nil {
		return nil, err
	}

	branchName, err := resolveSourceMarkdownBranchName(normalizedSourceMarkdown)
	if err != nil {
		return nil, err
	}

	state.Step = StepBranch
	state.SourceMarkdown = normalizedSourceMarkdown
	state.BranchName = branchName
	return state, nil
}

func (p *Pipeline) normalizeSourceMarkdownPath(mdPath string) (string, error) {
	trimmed := strings.TrimSpace(mdPath)
	if trimmed == "" {
		return "", fmt.Errorf("markdown PRD path is empty")
	}

	candidate := trimmed
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(p.dir, candidate)
	}

	resolvedPath, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("failed to resolve markdown PRD path %s: %w", mdPath, err)
	}

	return filepath.Clean(resolvedPath), nil
}

func resolveSourceMarkdownBranchName(mdPath string) (string, error) {
	mdContent, err := os.ReadFile(mdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("markdown PRD not found: %s", mdPath)
		}
		return "", fmt.Errorf("failed to read markdown PRD %s: %w", mdPath, err)
	}

	branchName := prd.ResolveMarkdownBranchName(string(mdContent), mdPath)
	if branchName == "" {
		return "", fmt.Errorf("unable to resolve branchName from markdown metadata, title, or filename; add branchName metadata or use a descriptive title/filename")
	}

	return branchName, nil
}

// initializeBaseBranch resolves and persists the base branch for this run.
// Priority:
//  1. Existing state.BaseBranch (for resumed runs)
//  2. opts.BaseBranch override
//  3. Current git branch (best-effort; empty means current HEAD)
func (p *Pipeline) initializeBaseBranch(state *PipelineState, opts RunOptions) error {
	baseOverride := strings.TrimSpace(opts.BaseBranch)

	if state.BaseBranch != "" {
		if baseOverride != "" && baseOverride != state.BaseBranch {
			p.display.ShowInfo("   Note: ignoring --base %q; resuming with saved base %q\n", baseOverride, state.BaseBranch)
		}
		return nil
	}

	if baseOverride != "" {
		state.BaseBranch = baseOverride
		return nil
	}

	if !opts.Resume || state.Step == StepAnalyze || state.Step == StepBranch {
		baseBranch, err := CurrentBranchOptionalInDir(p.dir)
		if err != nil {
			p.display.ShowInfo("   Note: could not determine current branch; defaulting to current HEAD\n")
			state.BaseBranch = ""
		} else {
			state.BaseBranch = strings.TrimSpace(baseBranch)
		}
	}

	return nil
}

// runAnalyzeStep finds and analyzes the report to identify the highest priority item.
func (p *Pipeline) runAnalyzeStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: analyze\n")

	// Determine report path
	var reportPath string
	if opts.ReportPath != "" {
		reportPath = opts.ReportPath
	} else {
		reportsDir := filepath.Join(p.dir, p.config.ReportsDir)
		var err error
		reportPath, err = FindLatestReport(reportsDir)
		if err != nil {
			return fmt.Errorf("failed to find latest report: %w", err)
		}
	}

	state.ReportPath = reportPath
	p.display.ShowInfo("   Report: %s\n", filepath.Base(reportPath))

	if opts.DryRun {
		p.display.ShowInfo("   [dry-run] Would analyze report: %s\n", reportPath)
		// Seed placeholder analysis so later dry-run steps can proceed.
		placeholder := &AnalysisResult{
			PriorityItem: "dry-run",
			BranchName:   "dry-run",
		}
		state.Analysis = placeholder
		state.BranchName = p.config.BranchPrefix + placeholder.BranchName
		state.Step = StepSpec
		return nil
	}

	// Find recent PRDs to avoid duplicating work
	recentPRDs, err := FindRecentPRDs(p.dir, 7) // Last 7 days
	if err != nil {
		return fmt.Errorf("failed to find recent PRDs: %w", err)
	}

	// Analyze the report
	p.display.StartSpinner("Analyzing report...")
	analysis, err := AnalyzeReport(ctx, p.engine, reportPath, recentPRDs)
	p.display.StopSpinner()
	if err != nil {
		return fmt.Errorf("failed to analyze report: %w", err)
	}

	state.Analysis = analysis
	state.BranchName = p.config.BranchPrefix + analysis.BranchName

	// Display analysis result
	p.display.ShowInfo("   Priority: %s\n", analysis.PriorityItem)
	p.display.ShowInfo("   Branch: %s\n", state.BranchName)
	p.display.ShowInfo("   Tasks: ~%d estimated\n", analysis.EstimatedTasks)

	// Save state and advance to next step
	state.Step = StepSpec
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

// runBranchStep ensures and checks out the target branch for the work.
func (p *Pipeline) runBranchStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: branch\n")

	if state.BranchName == "" {
		return fmt.Errorf("no branch name set in state")
	}

	nextStep := StepConvert
	if strings.TrimSpace(state.SourceMarkdown) == "" {
		nextStep = StepSpec
	}

	if opts.DryRun {
		if state.BaseBranch != "" {
			p.display.ShowInfo("   [dry-run] Would create branch: %s (from %s)\n", state.BranchName, state.BaseBranch)
		} else {
			p.display.ShowInfo("   [dry-run] Would create branch: %s (from current HEAD)\n", state.BranchName)
		}
		state.Step = nextStep
		return nil
	}

	if state.BaseBranch != "" {
		p.display.ShowInfo("   Ensuring branch: %s (from %s)\n", state.BranchName, state.BaseBranch)
	} else {
		p.display.ShowInfo("   Ensuring branch: %s (from current HEAD)\n", state.BranchName)
	}
	if err := EnsureBranchInDir(p.dir, state.BranchName, state.BaseBranch); err != nil {
		return fmt.Errorf("failed to prepare branch: %w", err)
	}

	// Save state and advance to next step
	state.Step = nextStep
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

// runPRDStep generates a PRD using the autospec skill with analysis context.
func (p *Pipeline) runPRDStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: spec\n")

	if state.Analysis == nil {
		return fmt.Errorf("no analysis result in state")
	}

	// Derive PRD path from a filesystem-safe branch slug.
	prdName := markdownPRDNameFromBranch(state.Analysis.BranchName)
	if prdName == "" {
		prdName = "feature"
	}
	prdPath := filepath.Join(p.dir, template.HalDir, fmt.Sprintf("prd-%s.md", prdName))

	if opts.DryRun {
		p.display.ShowInfo("   [dry-run] Would generate PRD: %s\n", filepath.Base(prdPath))
		state.SourceMarkdown = prdPath
		state.Step = StepBranch
		return nil
	}

	// Load autospec skill
	autospecSkill, err := skills.LoadSkill("autospec")
	if err != nil {
		return fmt.Errorf("failed to load autospec skill: %w", err)
	}

	// Build analysis context for the prompt
	analysisContext := buildAnalysisContext(state.Analysis)

	resolvedMode := normalizeResolvedConvertMode(state.ConvertMode)
	state.ConvertMode = resolvedMode

	modeFormatGuidance := "2. Use T-XXX task IDs (T-001, T-002, etc.)\n3. Each task must be completable in ONE agent iteration\n4. Include boolean acceptance criteria\n5. Every task ends with \"Typecheck passes\""
	if resolvedMode == AutoConvertModeStandard {
		modeFormatGuidance = "2. Use US-XXX user story IDs (US-001, US-002, etc.)\n3. Each story must be completable in ONE agent iteration\n4. Include boolean acceptance criteria\n5. Every story ends with \"Typecheck passes\""
	}

	// Build prompt
	prompt := fmt.Sprintf(`You are an autonomous PRD generation agent. Follow the autospec skill instructions below.

<skill>
%s
</skill>

%s

<mode_override>
Resolved convert mode for this run: %s
This mode override is authoritative for this run and overrides any conflicting generic autospec defaults.
- standard mode requires US-XXX user stories.
- granular mode requires T-XXX tasks.
</mode_override>

Generate a PRD following the skill rules:
1. Do NOT ask any questions - self-clarify from the analysis context
%s

Write the PRD directly to %s using the Write tool.`, autospecSkill, analysisContext, resolvedMode, modeFormatGuidance, prdPath)

	// Record output file modification time before (if exists)
	var preModTime time.Time
	if stat, err := os.Stat(prdPath); err == nil {
		preModTime = stat.ModTime()
	}

	// Execute prompt with streaming display
	p.display.ShowInfo("   Generating PRD...\n")
	response, err := p.engine.StreamPrompt(ctx, prompt, p.display)
	// Check if engine wrote the output file directly using tools
	fileWritten := false
	if stat, err := os.Stat(prdPath); err == nil && stat.ModTime().After(preModTime) {
		fileWritten = true
	}
	if err != nil {
		if !fileWritten || !engine.RequiresOutputFallback(err) {
			return fmt.Errorf("engine prompt failed: %w", err)
		}
	}

	if fileWritten {
		// Engine wrote the file
		state.SourceMarkdown = prdPath
		p.display.ShowInfo("   PRD generated: %s\n", filepath.Base(prdPath))
	} else {
		// Fallback: write response as PRD content
		// Extract markdown content (skip any meta-commentary)
		content := extractMarkdownContent(response)
		if content == "" {
			content = response
		}

		// Ensure output directory exists
		outDir := filepath.Dir(prdPath)
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		if err := os.WriteFile(prdPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write PRD: %w", err)
		}

		state.SourceMarkdown = prdPath
		p.display.ShowInfo("   PRD generated: %s\n", filepath.Base(prdPath))
	}

	// Save state and advance to next step
	state.Step = StepBranch
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

func markdownPRDNameFromBranch(branchName string) string {
	name := strings.Trim(archive.FeatureFromBranch(branchName), "-")
	return strings.TrimSpace(name)
}

// runExplodeStep converts the source markdown PRD to canonical .hal/prd.json.
func (p *Pipeline) runExplodeStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: convert\n")

	if state.SourceMarkdown == "" {
		return fmt.Errorf("no source markdown path in state")
	}

	normalizedSourceMarkdown, err := p.normalizeSourceMarkdownPath(state.SourceMarkdown)
	if err != nil {
		return err
	}
	state.SourceMarkdown = normalizedSourceMarkdown

	outPath := filepath.Join(p.dir, template.HalDir, template.PRDFile)
	resolvedMode := normalizeResolvedConvertMode(state.ConvertMode)
	state.ConvertMode = resolvedMode

	if opts.DryRun {
		p.display.ShowInfo("   [dry-run] Would convert PRD to: %s (mode: %s)\n", outPath, resolvedMode)
		state.Step = StepValidate
		return nil
	}

	if err := p.archivePriorCanonicalStateForConvert(normalizedSourceMarkdown, state.BranchName); err != nil {
		return err
	}

	convertOpts := prd.ConvertOptions{
		Granular:   resolvedMode == AutoConvertModeGranular,
		BranchName: state.BranchName,
	}

	if resolvedMode == AutoConvertModeStandard {
		p.display.ShowInfo("   Converting PRD in standard mode (US-XXX stories)...\n")
	} else {
		p.display.ShowInfo("   Converting PRD in granular mode (T-XXX tasks)...\n")
	}
	if err := convertWithEngine(ctx, p.engine, normalizedSourceMarkdown, outPath, convertOpts, p.display); err != nil {
		return fmt.Errorf("failed to convert PRD: %w", err)
	}

	if err := verifyConvertedBranchInvariant(p.dir, state.BranchName, resolvedMode); err != nil {
		return err
	}

	// Save state and advance to next step
	state.Step = StepValidate
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

func (p *Pipeline) archivePriorCanonicalStateForConvert(sourceMarkdown, nextBranch string) error {
	halDir := filepath.Join(p.dir, template.HalDir)

	existing, err := engine.LoadPRDFile(halDir, template.PRDFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect existing canonical PRD: %w", err)
	}

	currentBranch := strings.TrimSpace(existing.BranchName)
	nextBranch = strings.TrimSpace(nextBranch)
	if currentBranch == "" || nextBranch == "" || currentBranch == nextBranch {
		return nil
	}

	archiveName := archive.FeatureFromBranch(currentBranch)
	if archiveName == "" {
		archiveName = "auto-saved"
	}

	p.display.ShowInfo("   Branch changed from %s to %s; archiving prior feature state...\n", currentBranch, nextBranch)

	excludePaths := []string{filepath.Join(halDir, template.AutoStateFile)}
	if source := strings.TrimSpace(sourceMarkdown); source != "" {
		excludePaths = append(excludePaths, source)
	}

	if _, err := createArchiveWithOptions(halDir, archiveName, p.display.Writer(), archive.CreateOptions{
		ExcludePaths: excludePaths,
	}); err != nil {
		return fmt.Errorf("failed to archive prior feature state before convert: %w", err)
	}

	return nil
}

// runValidateStep validates the converted PRD and keeps applying targeted repairs until green.
func (p *Pipeline) runValidateStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: validate\n")

	if state.Validation == nil {
		state.Validation = &ValidationState{}
	}

	resolvedMode := normalizeResolvedConvertMode(state.ConvertMode)
	state.ConvertMode = resolvedMode

	if opts.DryRun {
		p.display.ShowInfo("   [dry-run] Would validate converted PRD at %s (mode: %s)\n", filepath.Join(template.HalDir, template.PRDFile), resolvedMode)
		state.Validation.Attempts++
		state.Validation.Status = "passed"
		state.Step = StepRun
		return nil
	}

	prdPath := filepath.Join(p.dir, template.HalDir, template.PRDFile)

	state.Validation.Attempts++
	attempt := state.Validation.Attempts

	p.display.ShowInfo("   Validating converted PRD (mode: %s, attempt %d)...\n", resolvedMode, attempt)
	result, err := validateWithEngine(ctx, p.engine, prdPath, p.display)
	if err != nil {
		if isValidationLoopTerminalError(err) {
			state.Validation.Status = "repairing"
			if saveErr := p.saveState(state); saveErr != nil {
				return fmt.Errorf("failed to validate PRD on attempt %d: %w (also failed to save state: %v)", attempt, err, saveErr)
			}
			return fmt.Errorf("failed to validate PRD on attempt %d: %w", attempt, err)
		}

		if limitErr := p.failValidationAfterMaxAttempts(state, attempt); limitErr != nil {
			return limitErr
		}

		p.display.ShowInfo("   Validation attempt %d hit an error: %v\n", attempt, err)
		return p.scheduleValidationRetry(ctx, state)
	}

	if result.Valid {
		state.Validation.Status = "passed"
		state.Step = StepRun
		if err := p.saveState(state); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
		return nil
	}

	// Allow one post-repair verification pass after the nominal max attempt.
	// If that final verification still fails, stop before scheduling another repair.
	if attempt > p.validationMaxAttempts() {
		return p.failValidationAfterMaxAttempts(state, attempt)
	}

	sourceMarkdown := strings.TrimSpace(state.SourceMarkdown)
	if sourceMarkdown != "" {
		normalizedSourceMarkdown, normErr := p.normalizeSourceMarkdownPath(sourceMarkdown)
		if normErr != nil {
			p.display.ShowInfo("   Note: could not resolve source markdown for repair (%s); repairing %s only.\n", sourceMarkdown, filepath.Join(template.HalDir, template.PRDFile))
			sourceMarkdown = ""
		} else if _, statErr := os.Stat(normalizedSourceMarkdown); statErr != nil {
			if os.IsNotExist(statErr) {
				p.display.ShowInfo("   Note: source markdown not found for repair (%s); repairing %s only.\n", normalizedSourceMarkdown, filepath.Join(template.HalDir, template.PRDFile))
			} else {
				p.display.ShowInfo("   Note: could not inspect source markdown for repair (%s): %v; repairing %s only.\n", normalizedSourceMarkdown, statErr, filepath.Join(template.HalDir, template.PRDFile))
			}
			sourceMarkdown = ""
		} else {
			sourceMarkdown = normalizedSourceMarkdown
			state.SourceMarkdown = normalizedSourceMarkdown
		}
	}

	if repairErr := repairValidationWithEngine(ctx, p.engine, sourceMarkdown, prdPath, result, p.display); repairErr != nil {
		if isValidationLoopTerminalError(repairErr) {
			state.Validation.Status = "repairing"
			if saveErr := p.saveState(state); saveErr != nil {
				return fmt.Errorf("failed to repair PRD from validation feedback on attempt %d: %w (also failed to save state: %v)", attempt, repairErr, saveErr)
			}
			return fmt.Errorf("failed to repair PRD from validation feedback on attempt %d: %w", attempt, repairErr)
		}

		if limitErr := p.failValidationAfterMaxAttempts(state, attempt); limitErr != nil {
			return limitErr
		}

		p.display.ShowInfo("   Validation repair attempt %d hit an error: %v\n", attempt, repairErr)
		return p.scheduleValidationRetry(ctx, state)
	}

	state.Validation.Status = "repairing"
	state.Step = StepValidate
	if saveErr := p.saveState(state); saveErr != nil {
		return fmt.Errorf("failed to save validation repair state: %w", saveErr)
	}
	p.display.ShowInfo("   Validation failed (attempt %d); applied validation-guided PRD edits and retrying.\n", attempt)
	return nil
}

// validationMaxAttempts bounds the autonomous validation/repair loop.
// The limit is intentionally generous, but prevents unbounded retries when
// model output oscillates and cannot converge without manual intervention.
func (p *Pipeline) validationMaxAttempts() int {
	return defaultValidationMaxAttempts
}

func (p *Pipeline) failValidationAfterMaxAttempts(state *PipelineState, attempt int) error {
	maxAttempts := p.validationMaxAttempts()
	if attempt < maxAttempts {
		return nil
	}

	state.Validation.Status = "failed"
	state.Step = StepValidate

	if saveErr := p.saveState(state); saveErr != nil {
		return fmt.Errorf("validation exceeded max attempts (%d); manual PRD intervention required (also failed to save state: %v)", maxAttempts, saveErr)
	}

	return fmt.Errorf("validation exceeded max attempts (%d); fix %s and rerun `hal auto --resume`", maxAttempts, filepath.Join(template.HalDir, template.PRDFile))
}

// scheduleValidationRetry persists validate-loop state and waits briefly before
// the next attempt to reduce pressure during transient engine/provider failures.
func (p *Pipeline) scheduleValidationRetry(ctx context.Context, state *PipelineState) error {
	state.Validation.Status = "repairing"
	state.Step = StepValidate
	if saveErr := p.saveState(state); saveErr != nil {
		return fmt.Errorf("failed to save validation retry state: %w", saveErr)
	}

	p.display.ShowInfo("   Retrying validation...\n")

	if validationRetryDelay <= 0 {
		return nil
	}

	timer := time.NewTimer(validationRetryDelay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isValidationLoopTerminalError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func verifyConvertedBranchInvariant(dir, stateBranchName, convertMode string) error {
	halDir := filepath.Join(dir, template.HalDir)
	relativePRDPath := filepath.Join(template.HalDir, template.PRDFile)

	converted, err := engine.LoadPRDFile(halDir, template.PRDFile)
	if err != nil {
		return fmt.Errorf("post-convert branch invariant failed: unable to read %s: %w", relativePRDPath, err)
	}

	expectedBranch := strings.TrimSpace(stateBranchName)
	actualBranch := strings.TrimSpace(converted.BranchName)
	fixCommand := convertBranchFixCommand(convertMode, expectedBranch)

	if actualBranch == "" {
		if expectedBranch == "" {
			return fmt.Errorf("post-convert branch invariant failed: %s is missing branchName; set branchName explicitly and rerun `hal auto --resume`", relativePRDPath)
		}
		return fmt.Errorf("post-convert branch invariant failed: %s is missing branchName; rerun `%s` or fix %s before resuming", relativePRDPath, fixCommand, relativePRDPath)
	}

	if expectedBranch == "" {
		return fmt.Errorf("post-convert branch invariant failed: pipeline state branchName is empty while %s has %q; set the pipeline branch and rerun `hal auto --resume`", relativePRDPath, actualBranch)
	}

	if actualBranch != expectedBranch {
		return fmt.Errorf("post-convert branch invariant failed: state.branchName=%q but %s branchName=%q; rerun `%s` or update %s before resuming", expectedBranch, relativePRDPath, actualBranch, fixCommand, relativePRDPath)
	}

	return nil
}

func convertBranchFixCommand(convertMode, branchName string) string {
	branchName = strings.TrimSpace(branchName)
	if normalizeResolvedConvertMode(convertMode) == AutoConvertModeStandard {
		return fmt.Sprintf("hal convert --branch %s", branchName)
	}
	return fmt.Sprintf("hal convert --granular --branch %s", branchName)
}

// runLoopStep executes the Hal loop as a completion gate against .hal/prd.json.
func (p *Pipeline) runLoopStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: run\n")

	previousRunIterations := incompleteRunIterations(state)
	maxRunIterations := p.runStepMaxIterations(state, opts)
	if opts.MaxRunAttempts > 0 && previousRunIterations >= opts.MaxRunAttempts {
		return &PolicyLimitError{
			PolicyField: "factory.policy.maxRunAttempts",
			Step:        StepRun,
			Attempts:    previousRunIterations,
			Limit:       opts.MaxRunAttempts,
		}
	}

	if opts.DryRun {
		p.display.ShowInfo("   [dry-run] Would run task loop with max %d iterations\n", maxRunIterations)
		state.Step = StepReview
		return nil
	}

	// Migrate legacy auto-progress.txt to unified progress.txt
	if err := p.migrateAutoProgress(); err != nil {
		return fmt.Errorf("failed to migrate auto-progress.txt: %w", err)
	}

	progressPath := filepath.Join(p.dir, template.HalDir, template.ProgressFile)
	if _, err := os.Stat(progressPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(progressPath), 0755); err != nil {
			return fmt.Errorf("failed to create progress directory: %w", err)
		}
		if err := os.WriteFile(progressPath, []byte(template.DefaultProgress), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", template.ProgressFile, err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat %s: %w", template.ProgressFile, err)
	}

	loopConfig := loop.Config{
		Dir:           filepath.Join(p.dir, template.HalDir),
		PRDFile:       template.PRDFile,
		ProgressFile:  template.ProgressFile,
		BaseBranch:    state.BaseBranch,
		MaxIterations: maxRunIterations,
		Engine:        p.engine.Name(),
		EngineConfig:  p.engineConfig,
		Logger:        p.display.Writer(),
		MaxRetries:    3,
	}

	p.display.ShowInfo("   Running task loop...\n")
	result, err := runLoopWithConfig(ctx, loopConfig)
	if err != nil {
		return fmt.Errorf("failed to create loop runner: %w", err)
	}

	totalRunIterations := previousRunIterations + result.Iterations
	state.Run = &RunState{
		Iterations:    totalRunIterations,
		Complete:      result.Complete,
		MaxIterations: maxRunIterations,
	}

	if result.Error != nil {
		if saveErr := p.saveState(state); saveErr != nil {
			return fmt.Errorf("loop execution failed: %w (also failed to save run telemetry: %v)", result.Error, saveErr)
		}
		return fmt.Errorf("loop execution failed: %w", result.Error)
	}

	if !result.Complete {
		p.display.ShowInfo("   Loop stopped after %d iterations (tasks remaining)\n", result.Iterations)
		if saveErr := p.saveState(state); saveErr != nil {
			return fmt.Errorf("run gate blocked: PRD completion incomplete (also failed to save run telemetry: %v)", saveErr)
		}
		if opts.MaxRunAttempts > 0 && totalRunIterations >= opts.MaxRunAttempts {
			return &PolicyLimitError{
				PolicyField: "factory.policy.maxRunAttempts",
				Step:        StepRun,
				Attempts:    totalRunIterations,
				Limit:       opts.MaxRunAttempts,
			}
		}
		if result.TotalStories > 0 {
			return fmt.Errorf("run gate blocked: PRD completion incomplete (%d/%d complete); rerun `hal auto --resume` to continue remaining tasks", result.CompletedStories, result.TotalStories)
		}
		return fmt.Errorf("run gate blocked: PRD completion incomplete; rerun `hal auto --resume` to continue remaining tasks")
	}

	p.display.ShowInfo("   All tasks completed in %d iterations\n", result.Iterations)
	state.Step = StepReview
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

func (p *Pipeline) runStepMaxIterations(state *PipelineState, opts RunOptions) int {
	maxIterations := p.config.MaxIterations
	if opts.MaxRunAttempts > 0 {
		remainingAttempts := opts.MaxRunAttempts - incompleteRunIterations(state)
		if remainingAttempts < maxIterations {
			return remainingAttempts
		}
	}
	return maxIterations
}

func incompleteRunIterations(state *PipelineState) int {
	if state == nil || state.Run == nil || state.Run.Complete || state.Run.Iterations <= 0 {
		return 0
	}
	return state.Run.Iterations
}

// runReviewStep executes bounded review cycles before CI.
func (p *Pipeline) runReviewStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: review\n")

	if state.Review == nil {
		state.Review = &ReviewState{}
	}

	maxCycles := opts.ReviewMaxCycles
	if maxCycles <= 0 {
		maxCycles = defaultReviewIterations
	}

	cleanStreakRequired := opts.ReviewCleanStreak
	if cleanStreakRequired <= 0 {
		cleanStreakRequired = 1
	}

	if opts.SkipReview {
		state.Review.Status = "skipped"
		p.display.ShowInfo("   Skipping review step (review gate disabled by policy)\n")
		state.Step = StepCI
		if opts.DryRun {
			return nil
		}
		if err := p.saveState(state); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
		return nil
	}

	if opts.DryRun {
		if strings.TrimSpace(state.BaseBranch) != "" {
			p.display.ShowInfo("   [dry-run] Would run up to %d review cycles against base branch %s (clean streak required: %d)\n", maxCycles, state.BaseBranch, cleanStreakRequired)
		} else {
			p.display.ShowInfo("   [dry-run] Would run up to %d review cycles (clean streak required: %d)\n", maxCycles, cleanStreakRequired)
		}
		state.Review.Status = "passed"
		state.Step = StepCI
		return nil
	}

	baseBranch := strings.TrimSpace(state.BaseBranch)
	if baseBranch == "" {
		state.Review.Status = "failed"
		return fmt.Errorf("review step requires baseBranch in state")
	}

	cleanStreak := 0
	lastValidIssues := 0
	fixesAppliedDuringReview := false
	for cycle := 1; cycle <= maxCycles; cycle++ {
		atReviewFixLimit := opts.MaxReviewFixAttempts > 0 && state.Review.FixAttempts >= opts.MaxReviewFixAttempts
		fixAttemptsBeforeCycle := state.Review.FixAttempts
		p.display.ShowInfo("   Running review cycle %d/%d against %s...\n", cycle, maxCycles, baseBranch)
		var result *ReviewLoopResult
		var err error
		if atReviewFixLimit {
			result, err = runReviewValidationWithDisplay(ctx, p.engine, p.display, baseBranch)
		} else {
			if opts.MaxReviewFixAttempts > 0 {
				state.Review.FixAttempts++
				state.Step = StepReview
				if saveErr := p.saveState(state); saveErr != nil {
					return fmt.Errorf("failed to reserve review fix attempt: %w", saveErr)
				}
			}
			result, err = runReviewLoopWithDisplay(ctx, p.engine, p.display, baseBranch, 1)
		}
		if err != nil {
			state.Review.Status = "failed"
			return fmt.Errorf("failed to run review cycle %d: %w", cycle, err)
		}
		if result == nil || len(result.Iterations) == 0 {
			state.Review.Status = "failed"
			return fmt.Errorf("failed to run review cycle %d: no iteration result returned", cycle)
		}

		iteration := result.Iterations[len(result.Iterations)-1]
		lastValidIssues = iteration.ValidIssues
		countsAsFixAttempt := iteration.ValidIssues > 0 || iteration.FixesApplied > 0
		if atReviewFixLimit && countsAsFixAttempt {
			state.Review.Status = "failed"
			state.Step = StepReview
			limitErr := reviewFixPolicyLimitError(fixAttemptsBeforeCycle, opts.MaxReviewFixAttempts)
			if saveErr := p.saveState(state); saveErr != nil {
				return fmt.Errorf("%w (also failed to save state: %v)", limitErr, saveErr)
			}
			return limitErr
		}
		if countsAsFixAttempt {
			if opts.MaxReviewFixAttempts <= 0 {
				state.Review.FixAttempts++
			}
		} else if opts.MaxReviewFixAttempts > 0 && !atReviewFixLimit {
			state.Review.FixAttempts = fixAttemptsBeforeCycle
		}
		if iteration.FixesApplied > 0 {
			fixesAppliedDuringReview = true
		}

		if iteration.ValidIssues == 0 {
			cleanStreak++
			p.display.ShowInfo("   Review cycle %d clean (%d/%d required)\n", cycle, cleanStreak, cleanStreakRequired)
			if cleanStreak >= cleanStreakRequired {
				if fixesAppliedDuringReview {
					if err := p.finalizeReviewFixes(ctx); err != nil {
						state.Review.Status = "failed"
						if saveErr := p.saveState(state); saveErr != nil {
							return fmt.Errorf("review gate blocked: finalize review fixes failed: %w (also failed to save state: %v)", err, saveErr)
						}
						return fmt.Errorf("review gate blocked: finalize review fixes failed: %w", err)
					}
				}
				if err := p.runFinalVerification(ctx, state); err != nil {
					state.Review.Status = "failed"
					if saveErr := p.saveState(state); saveErr != nil {
						return fmt.Errorf("review gate blocked: final verification failed: %w (also failed to save state: %v)", err, saveErr)
					}
					return fmt.Errorf("review gate blocked: final verification failed: %w", err)
				}
				state.Review.Status = "passed"
				p.display.ShowInfo("   Review gate passed after %d cycle(s)\n", cycle)
				state.Step = StepCI
				if err := p.saveState(state); err != nil {
					return fmt.Errorf("failed to save state: %w", err)
				}
				return nil
			}
			continue
		}

		cleanStreak = 0
		p.display.ShowInfo("   Review cycle %d found %d valid issue(s); clean streak reset\n", cycle, iteration.ValidIssues)
	}

	state.Review.Status = "failed"
	if saveErr := p.saveState(state); saveErr != nil {
		return fmt.Errorf("review gate blocked: clean streak %d/%d not reached within %d cycle(s); rerun `hal auto --resume` to continue review fixes (last valid issues: %d) (also failed to save state: %v)", cleanStreak, cleanStreakRequired, maxCycles, lastValidIssues, saveErr)
	}
	return fmt.Errorf("review gate blocked: clean streak %d/%d not reached within %d cycle(s); rerun `hal auto --resume` to continue review fixes (last valid issues: %d)", cleanStreak, cleanStreakRequired, maxCycles, lastValidIssues)
}

func reviewFixPolicyLimitError(attempts, limit int) *PolicyLimitError {
	return &PolicyLimitError{
		PolicyField: "factory.policy.maxReviewFixAttempts",
		Step:        StepReview,
		Attempts:    attempts,
		Limit:       limit,
	}
}

// runReportStep generates a report artifact after CI passes/skips.
func (p *Pipeline) runReportStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: report\n")

	if opts.DryRun {
		p.display.ShowInfo("   [dry-run] Would generate a report artifact\n")
		state.Step = StepArchive
		return nil
	}

	result, err := runReportWithEngine(ctx, p.engine, p.display, p.dir, ReviewOptions{
		DryRun:       false,
		SkipAgents:   true,
		Verification: p.reviewVerificationChecks(state),
	})
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}
	if result == nil || strings.TrimSpace(result.ReportPath) == "" {
		return fmt.Errorf("report gate failed: report generation did not produce a report path")
	}

	state.ReportPath = strings.TrimSpace(result.ReportPath)
	p.display.ShowInfo("   Report: %s\n", filepath.Base(state.ReportPath))

	state.Step = StepArchive
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

func (p *Pipeline) ensureCleanWorkingTree() error {
	paths, err := workingTreeChangesInDirFn(p.dir)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return nil
	}
	return fmt.Errorf("working tree is dirty: %s", strings.Join(paths, ", "))
}

func (p *Pipeline) finalizeReviewFixes(ctx context.Context) error {
	paths, err := workingTreeChangesInDirFn(p.dir)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return nil
	}
	if err := gitAddAllInDirFn(ctx, p.dir); err != nil {
		return err
	}
	if err := gitCommitInDirFn(ctx, p.dir, reviewFixCommitMessage); err != nil {
		return err
	}
	return nil
}

func (p *Pipeline) runFinalVerification(ctx context.Context, state *PipelineState) error {
	if err := p.ensureCleanWorkingTree(); err != nil {
		return err
	}
	if state == nil || strings.TrimSpace(state.BranchName) == "" {
		return nil
	}
	currentBranch := p.currentBranch
	if currentBranch == nil {
		currentBranch = CurrentBranchInDir
	}
	activeBranch, err := currentBranch(p.dir)
	if err != nil {
		return fmt.Errorf("determine current branch: %w", err)
	}
	if strings.TrimSpace(activeBranch) != strings.TrimSpace(state.BranchName) {
		return fmt.Errorf("current branch %q does not match pipeline state branch %q", strings.TrimSpace(activeBranch), strings.TrimSpace(state.BranchName))
	}
	return nil
}

func (p *Pipeline) reviewVerificationChecks(state *PipelineState) []VerificationCheck {
	checks := make([]VerificationCheck, 0, 5)
	if state != nil && state.Validation != nil {
		status := strings.TrimSpace(state.Validation.Status)
		output := fmt.Sprintf("status=%s attempts=%d", status, state.Validation.Attempts)
		checks = append(checks, VerificationCheck{Name: "validate", OK: status == "passed", Output: output})
	}
	if state != nil && state.Run != nil {
		output := fmt.Sprintf("complete=%t iterations=%d maxIterations=%d", state.Run.Complete, state.Run.Iterations, state.Run.MaxIterations)
		checks = append(checks, VerificationCheck{Name: "run", OK: state.Run.Complete, Output: output})
	}
	if state != nil && state.Review != nil {
		status := strings.TrimSpace(state.Review.Status)
		checks = append(checks, VerificationCheck{Name: "review", OK: status == "passed" || status == "skipped", Output: fmt.Sprintf("status=%s", status)})
	}
	if state != nil && state.CI != nil {
		status := strings.TrimSpace(state.CI.Status)
		output := fmt.Sprintf("status=%s", status)
		if reason := strings.TrimSpace(state.CI.Reason); reason != "" {
			output += fmt.Sprintf(" reason=%s", reason)
		}
		checks = append(checks, VerificationCheck{Name: "ci", OK: status == "passed" || status == "skipped", Output: output})
	}
	paths, err := workingTreeChangesInDirFn(p.dir)
	if err != nil {
		checks = append(checks, VerificationCheck{Name: "working_tree", OK: false, Output: fmt.Sprintf("inspect failed: %v", err)})
		return checks
	}
	if len(paths) == 0 {
		checks = append(checks, VerificationCheck{Name: "working_tree", OK: true, Output: "clean"})
		return checks
	}
	checks = append(checks, VerificationCheck{Name: "working_tree", OK: false, Output: fmt.Sprintf("dirty: %s", strings.Join(paths, ", "))})
	return checks
}

// migrateAutoProgress migrates content from legacy auto-progress.txt to unified progress.txt.
// If auto-progress.txt exists, its content is appended to progress.txt and the legacy file is deleted.
func (p *Pipeline) migrateAutoProgress() error {
	return MigrateAutoProgress(p.dir, p.display)
}

// runPRStep pushes the branch, creates a draft pull request, waits for CI
// checks, and attempts engine-driven fixes when checks fail.
func (p *Pipeline) runPRStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: ci\n")

	if opts.SkipCI {
		state.CI = &CIState{Status: "skipped", Reason: "skip_ci_flag"}
		p.recordCIState(state.CI)
		p.display.ShowInfo("   Skipping CI step (--no-ci)\n")
		state.Step = StepReport
		if opts.DryRun {
			return nil
		}
		if err := p.saveState(state); err != nil {
			return fmt.Errorf("failed to save state: %w", err)
		}
		return nil
	}

	if state.BranchName == "" {
		return fmt.Errorf("no branch name in state")
	}

	if opts.DryRun {
		if state.BaseBranch != "" {
			p.display.ShowInfo("   [dry-run] Would push branch %s, create draft PR against %s, wait for CI, and auto-fix if failing\n", state.BranchName, state.BaseBranch)
		} else {
			p.display.ShowInfo("   [dry-run] Would push branch %s, create draft PR, wait for CI, and auto-fix if failing\n", state.BranchName)
		}
		state.Step = StepReport
		return nil
	}

	if err := checkCIDependencies(); err != nil {
		state.CI = &CIState{Status: "failed", Reason: "ci_unavailable"}
		p.recordCIState(state.CI)
		p.display.ShowInfo("   CI dependencies unavailable (%v); stopping at CI step\n", err)
		state.Step = StepCI
		if saveErr := p.saveState(state); saveErr != nil {
			return fmt.Errorf("ci gate blocked: CI dependencies unavailable (%v); install required tooling and rerun with --resume, or rerun with --no-ci (also failed to save state: %v)", err, saveErr)
		}
		return fmt.Errorf("ci gate blocked: CI dependencies unavailable (%v); install required tooling and rerun with --resume, or rerun with --no-ci", err)
	}

	currentBranch := p.currentBranch
	if currentBranch == nil {
		currentBranch = CurrentBranchInDir
	}
	activeBranch, err := currentBranch(p.dir)
	if err != nil {
		return fmt.Errorf("failed to determine current branch before PR step: %w", err)
	}
	if strings.TrimSpace(activeBranch) != state.BranchName {
		return fmt.Errorf("current branch %q does not match pipeline state branch %q", strings.TrimSpace(activeBranch), state.BranchName)
	}

	pushAndCreatePR := p.pushAndCreatePR
	if pushAndCreatePR == nil {
		pushAndCreatePR = func(ctx context.Context, opts ci.PushOptions) (ci.PushResult, error) {
			return ci.PushAndCreatePRInDir(ctx, p.dir, opts)
		}
	}

	// 1. Push the branch and create/reuse PR through shared CI core.
	p.display.ShowInfo("   Pushing branch: %s\n", state.BranchName)

	taskStatus := ""
	if prd, err := engine.LoadPRDFile(filepath.Join(p.dir, template.HalDir), template.PRDFile); err == nil {
		taskStatus = buildTaskStatusSection(prd, state, p.config.MaxIterations)
	}

	prBody := buildPRBody(state, taskStatus)

	prTitle := "Compound: " + state.BranchName
	if state.Analysis != nil {
		if priority := strings.TrimSpace(state.Analysis.PriorityItem); priority != "" {
			prTitle = priority
		}
	}

	draft := true
	p.display.ShowInfo("   Creating draft PR...\n")
	pushResult, err := pushAndCreatePR(ctx, ci.PushOptions{
		BaseRef: state.BaseBranch,
		Title:   prTitle,
		Body:    prBody,
		Draft:   &draft,
	})
	if err != nil {
		state.CI = &CIState{Status: "failed"}
		p.recordCIState(state.CI)
		if saveErr := p.saveState(state); saveErr != nil {
			return fmt.Errorf("failed to create PR: %w (also failed to save state: %v)", err, saveErr)
		}
		return fmt.Errorf("failed to create PR: %w", err)
	}

	prURL := strings.TrimSpace(pushResult.PullRequest.URL)
	if prURL == "" {
		state.CI = &CIState{Status: "failed", Reason: "empty_pr_url"}
		p.recordCIState(state.CI)
		state.Step = StepCI
		if saveErr := p.saveState(state); saveErr != nil {
			return fmt.Errorf("failed to create PR: empty pull request URL (also failed to save state: %v)", saveErr)
		}
		return fmt.Errorf("failed to create PR: empty pull request URL")
	}
	p.display.ShowInfo("   PR created: %s\n", prURL)

	// Initialize CI telemetry.
	if state.CI == nil {
		state.CI = &CIState{}
	}
	state.CI.PRURL = prURL
	state.CI.PRNumber = pushResult.PullRequest.Number
	state.CI.PRTitle = strings.TrimSpace(pushResult.PullRequest.Title)
	state.CI.PRHeadRef = strings.TrimSpace(pushResult.PullRequest.HeadRef)
	state.CI.PRBaseRef = strings.TrimSpace(pushResult.PullRequest.BaseRef)
	state.CI.PRReused = pushResult.PullRequest.Existing
	p.recordCIState(state.CI)
	if saveErr := p.saveState(state); saveErr != nil {
		return fmt.Errorf("failed to save PR metadata before waiting for CI checks: %w", saveErr)
	}

	// 2. Wait for CI checks.
	p.display.ShowInfo("   Waiting for CI checks...\n")
	status, err := p.waitForChecksInDir(ctx, ci.WaitOptions{})
	if err != nil {
		state.CI.Status = "failed"
		state.CI.Reason = "wait_error"
		p.recordCIState(state.CI)
		if saveErr := p.saveState(state); saveErr != nil {
			return fmt.Errorf("failed to wait for CI checks: %w (also failed to save state: %v)", err, saveErr)
		}
		return fmt.Errorf("failed to wait for CI checks: %w", err)
	}

	if !status.ChecksDiscovered {
		p.display.ShowInfo("   No CI checks discovered; stopping at CI step\n")
		state.CI.Status = ci.StatusPending
		state.CI.Reason = ci.WaitTerminalReasonNoChecksDetected
		p.recordCIState(state.CI)
		state.Step = StepCI
		if saveErr := p.saveState(state); saveErr != nil {
			return fmt.Errorf("ci gate blocked: no CI checks detected yet; wait for checks to start and rerun with --resume, or rerun with --no-ci (also failed to save state: %v)", saveErr)
		}
		return fmt.Errorf("ci gate blocked: no CI checks detected yet; wait for checks to start and rerun with --resume, or rerun with --no-ci")
	}

	// 3. If passing, advance to report.
	if status.Status == ci.StatusPassing {
		p.display.ShowInfo("   CI checks passing\n")
		state.CI.Status = "passed"
		state.CI.Reason = ""
		p.recordCIState(state.CI)
		state.Step = StepReport
		if saveErr := p.saveState(state); saveErr != nil {
			return fmt.Errorf("failed to save state: %w", saveErr)
		}
		return nil
	}

	// 4. If failing, attempt engine-driven fixes.
	if status.Status == ci.StatusFailing {
		maxFixAttempts := ciFixMaxAttemptsForRun(state, opts)
		p.display.ShowInfo("   CI checks failing; attempting auto-fix (up to %d attempts)\n", maxFixAttempts)

		firstFixAttempt := 1
		if opts.MaxCIFixAttempts > 0 {
			firstFixAttempt = state.CI.FixAttempts + 1
		}
		for attempt := firstFixAttempt; attempt <= maxFixAttempts; attempt++ {
			if opts.MaxCIFixAttempts > 0 && state.CI.FixAttempts >= opts.MaxCIFixAttempts {
				state.CI.Status = "policy_blocked"
				state.CI.Reason = "max_ci_fix_attempts"
				p.recordCIState(state.CI)
				state.Step = StepCI
				if saveErr := p.saveState(state); saveErr != nil {
					return fmt.Errorf("%w (also failed to save state: %v)", ciFixPolicyLimitError(state.CI.FixAttempts, opts.MaxCIFixAttempts), saveErr)
				}
				return ciFixPolicyLimitError(state.CI.FixAttempts, opts.MaxCIFixAttempts)
			}

			p.display.ShowInfo("   Fix attempt %d/%d...\n", attempt, maxFixAttempts)
			state.CI.FixAttempts = attempt
			p.recordCIState(state.CI)
			state.Step = StepCI
			if saveErr := p.saveState(state); saveErr != nil {
				return fmt.Errorf("failed to reserve CI fix attempt %d: %w", attempt, saveErr)
			}

			fixResult, fixErr := p.fixWithEngineInDir(ctx, status, ci.FixOptions{
				Engine:      p.engine,
				Display:     p.display,
				Attempt:     attempt,
				MaxAttempts: maxFixAttempts,
			})

			if fixErr != nil {
				p.display.ShowInfo("   Fix attempt %d failed: %v\n", attempt, fixErr)
				// Save progress and continue to next attempt if retries remain.
				if saveErr := p.saveState(state); saveErr != nil {
					return fmt.Errorf("ci fix attempt %d failed: %w (also failed to save state: %v)", attempt, fixErr, saveErr)
				}
				continue
			}

			if fixResult.Applied {
				state.CI.FixesApplied++
				p.display.ShowInfo("   Fix applied, pushed %d file(s)\n", len(fixResult.FilesChanged))
			}

			// Wait for fresh CI status after the fix.
			p.display.ShowInfo("   Waiting for CI checks after fix...\n")
			verified, waitErr := p.waitForChecksInDir(ctx, ci.WaitOptions{})
			if waitErr != nil {
				p.display.ShowInfo("   Post-fix CI wait failed: %v\n", waitErr)
				if saveErr := p.saveState(state); saveErr != nil {
					return fmt.Errorf("post-fix CI wait failed: %w (also failed to save state: %v)", waitErr, saveErr)
				}
				continue
			}

			if verified.Status == ci.StatusPassing {
				p.display.ShowInfo("   CI checks passing after fix attempt %d\n", attempt)
				state.CI.Status = "passed"
				state.CI.Reason = ""
				p.recordCIState(state.CI)
				state.Step = StepReport
				if saveErr := p.saveState(state); saveErr != nil {
					return fmt.Errorf("failed to save state: %w", saveErr)
				}
				return nil
			}

			if verified.Status != ci.StatusFailing {
				p.display.ShowInfo("   CI status is %s after fix attempt %d; stopping at CI step\n", verified.Status, attempt)
				state.CI.Status = verified.Status
				p.recordCIState(state.CI)
				state.Step = StepCI
				if saveErr := p.saveState(state); saveErr != nil {
					return fmt.Errorf("ci gate blocked: CI status is %s; wait for checks to complete and rerun with --resume, or rerun with --no-ci (also failed to save state: %v)", verified.Status, saveErr)
				}
				return fmt.Errorf("ci gate blocked: CI status is %s; wait for checks to complete and rerun with --resume, or rerun with --no-ci", verified.Status)
			}

			// Still failing — update status for next iteration.
			status = verified
		}

		// Exhausted all fix attempts.
		p.display.ShowInfo("   CI still failing after %d fix attempt(s); stopping at CI step\n", maxFixAttempts)
		if opts.MaxCIFixAttempts > 0 && state.CI.FixAttempts >= opts.MaxCIFixAttempts {
			state.CI.Status = "policy_blocked"
			state.CI.Reason = "max_ci_fix_attempts"
			p.recordCIState(state.CI)
			state.Step = StepCI
			limitErr := ciFixPolicyLimitError(state.CI.FixAttempts, opts.MaxCIFixAttempts)
			if saveErr := p.saveState(state); saveErr != nil {
				return fmt.Errorf("%w (also failed to save state: %v)", limitErr, saveErr)
			}
			return limitErr
		}

		state.CI.Status = "fix_exhausted"
		p.recordCIState(state.CI)
		state.Step = StepCI
		if saveErr := p.saveState(state); saveErr != nil {
			return fmt.Errorf("ci gate blocked: CI still failing after %d fix attempt(s); resolve failures and rerun with --resume, or rerun with --no-ci (also failed to save state: %v)", maxFixAttempts, saveErr)
		}
		return fmt.Errorf("ci gate blocked: CI still failing after %d fix attempt(s); resolve failures and rerun with --resume, or rerun with --no-ci", maxFixAttempts)
	}

	// Pending/timeout/unknown — keep pipeline at CI until checks reach a terminal passing state.
	p.display.ShowInfo("   CI status is %s; stopping at CI step\n", status.Status)
	state.CI.Status = status.Status
	p.recordCIState(state.CI)
	state.Step = StepCI
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("ci gate blocked: CI status is %s; wait for checks to complete and rerun with --resume, or rerun with --no-ci (also failed to save state: %v)", status.Status, err)
	}

	return fmt.Errorf("ci gate blocked: CI status is %s; wait for checks to complete and rerun with --resume, or rerun with --no-ci", status.Status)
}

func ciFixMaxAttemptsForRun(state *PipelineState, opts RunOptions) int {
	if opts.MaxCIFixAttempts > 0 {
		previousAttempts := 0
		if state != nil && state.CI != nil {
			previousAttempts = state.CI.FixAttempts
		}
		maxAttempts := previousAttempts + maxCIFixAttempts
		if maxAttempts > opts.MaxCIFixAttempts {
			return opts.MaxCIFixAttempts
		}
		return maxAttempts
	}
	return maxCIFixAttempts
}

func ciFixPolicyLimitError(attempts, limit int) *PolicyLimitError {
	return &PolicyLimitError{
		PolicyField: "factory.policy.maxCiFixAttempts",
		Step:        StepCI,
		Attempts:    attempts,
		Limit:       limit,
	}
}

func (p *Pipeline) waitForChecksInDir(ctx context.Context, opts ci.WaitOptions) (ci.StatusResult, error) {
	return waitForChecksInDirFn(ctx, p.dir, opts)
}

func (p *Pipeline) fixWithEngineInDir(ctx context.Context, status ci.StatusResult, opts ci.FixOptions) (ci.FixResult, error) {
	return fixWithEngineInDirFn(ctx, p.dir, status, opts)
}

// runArchiveStep archives feature state while preserving the latest generated report.
func (p *Pipeline) runArchiveStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: archive\n")

	if opts.DryRun {
		if reportPath := strings.TrimSpace(state.ReportPath); reportPath != "" {
			p.display.ShowInfo("   [dry-run] Would archive feature state while preserving %s\n", filepath.Base(reportPath))
		} else {
			p.display.ShowInfo("   [dry-run] Would archive feature state\n")
		}
		state.Step = StepDone
		return nil
	}

	if err := p.ensureCleanWorkingTree(); err != nil {
		return fmt.Errorf("archive gate blocked: %w", err)
	}

	halDir := filepath.Join(p.dir, template.HalDir)
	archiveName := archive.FeatureFromBranch(state.BranchName)
	if strings.TrimSpace(archiveName) == "" {
		archiveName = "archive"
	}

	createOpts := archive.CreateOptions{}
	if reportPath := strings.TrimSpace(state.ReportPath); reportPath != "" {
		reportExclude := reportPath
		if !filepath.IsAbs(reportExclude) {
			reportExclude = filepath.Join(p.dir, reportExclude)
		}
		createOpts.ExcludePaths = []string{reportExclude}
	}

	archiveDir, err := createArchiveWithOptions(halDir, archiveName, p.display.Writer(), createOpts)
	if err != nil {
		return fmt.Errorf("failed to archive feature state: %w", err)
	}
	p.display.ShowInfo("   Archived state to %s\n", filepath.Base(archiveDir))

	if err := p.clearState(); err != nil {
		return fmt.Errorf("failed to clear state: %w", err)
	}

	state.Step = StepDone
	return nil
}

func defaultCheckCIDependencies() error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git CLI not found in PATH")
	}
	if _, err := ci.SelectGitHubClient(context.Background()); err != nil {
		return fmt.Errorf("GitHub auth unavailable: %w", err)
	}
	return nil
}

// buildPRBody constructs the PR description from pipeline state.
func buildPRBody(state *PipelineState, taskStatus string) string {
	var sb strings.Builder

	sb.WriteString("## Summary\n\n")

	if state.Analysis != nil {
		sb.WriteString(state.Analysis.Description)
		sb.WriteString("\n\n")

		if state.Analysis.Rationale != "" {
			sb.WriteString("### Rationale\n\n")
			sb.WriteString(state.Analysis.Rationale)
			sb.WriteString("\n\n")
		}

		if len(state.Analysis.AcceptanceCriteria) > 0 {
			sb.WriteString("### Acceptance Criteria\n\n")
			for _, ac := range state.Analysis.AcceptanceCriteria {
				sb.WriteString("- ")
				sb.WriteString(ac)
				sb.WriteString("\n")
			}
			sb.WriteString("\n")
		}
	}

	if taskStatus != "" {
		sb.WriteString(taskStatus)
	}

	sb.WriteString("---\n\n")
	sb.WriteString("🤖 Generated by [hal](https://github.com/jywlabs/hal) compound pipeline\n")

	return sb.String()
}

func buildTaskStatusSection(prd *engine.PRD, state *PipelineState, maxIterations int) string {
	completed, total := prd.Progress()
	if total == 0 {
		return ""
	}

	remaining := remainingStoryIDs(prd)

	var sb strings.Builder
	sb.WriteString("### Task Status\n\n")
	sb.WriteString(fmt.Sprintf("- Completed: %d/%d\n", completed, total))
	if len(remaining) > 0 {
		sb.WriteString("- Remaining: ")
		sb.WriteString(strings.Join(remaining, ", "))
		sb.WriteString("\n")
	}
	if completed < total {
		iterations := 0
		maxIters := maxIterations
		if state != nil && state.Run != nil {
			iterations = state.Run.Iterations
			if state.Run.MaxIterations > 0 {
				maxIters = state.Run.MaxIterations
			}
		}
		if iterations > 0 && maxIters > 0 {
			sb.WriteString(fmt.Sprintf("- Note: Loop stopped after %d iterations (max %d) with tasks remaining.\n", iterations, maxIters))
		} else if iterations > 0 {
			sb.WriteString(fmt.Sprintf("- Note: Loop stopped after %d iterations with tasks remaining.\n", iterations))
		} else {
			sb.WriteString("- Note: Loop stopped with tasks remaining.\n")
		}
	}
	sb.WriteString("\n")

	return sb.String()
}

func remainingStoryIDs(prd *engine.PRD) []string {
	remaining := make([]string, 0)
	for _, story := range prd.UserStories {
		if story.Passes {
			continue
		}
		id := story.ID
		if id == "" {
			id = story.Title
		}
		if id != "" {
			remaining = append(remaining, id)
		}
	}
	for _, task := range prd.Tasks {
		if task.Passes {
			continue
		}
		id := task.ID
		if id == "" {
			id = task.Title
		}
		if id != "" {
			remaining = append(remaining, id)
		}
	}
	return remaining
}

// buildAnalysisContext formats the analysis result for the autospec skill prompt.
func buildAnalysisContext(analysis *AnalysisResult) string {
	criteria := strings.Join(analysis.AcceptanceCriteria, "\n  - ")
	if criteria != "" {
		criteria = "  - " + criteria
	}

	return fmt.Sprintf(`ANALYSIS CONTEXT:
- Priority Item: %s
- Description: %s
- Rationale: %s
- Acceptance Criteria Hints:
%s
- Estimated Tasks: %d
- Branch Name: %s`, analysis.PriorityItem, analysis.Description, analysis.Rationale, criteria, analysis.EstimatedTasks, analysis.BranchName)
}

// extractMarkdownContent extracts markdown content from a response, handling cases
// where the response might include meta-commentary before/after the actual content.
func extractMarkdownContent(response string) string {
	// If response starts with a markdown header, use it as-is
	trimmed := strings.TrimSpace(response)
	if strings.HasPrefix(trimmed, "#") {
		return trimmed
	}

	// Look for markdown content starting with # header
	idx := strings.Index(response, "\n# ")
	if idx != -1 {
		return strings.TrimSpace(response[idx+1:])
	}

	// Return empty to signal using the full response
	return ""
}
