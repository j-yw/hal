package compound

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/loop"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
)

// stateFileName references the shared constant for the auto-state file.
var stateFileName = template.AutoStateFile

// Pipeline orchestrates the compound engineering automation process.
type Pipeline struct {
	config       *AutoConfig
	engine       engine.Engine
	engineConfig *engine.EngineConfig
	display      *engine.Display
	dir          string
}

// NewPipeline creates a new pipeline instance.
func NewPipeline(config *AutoConfig, eng engine.Engine, display *engine.Display, dir string) *Pipeline {
	return &Pipeline{
		config:  config,
		engine:  eng,
		display: display,
		dir:     dir,
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

// saveState writes the pipeline state to .hal/auto-state.json atomically.
// It writes to a temp file first, then renames to ensure atomic operation.
func (p *Pipeline) saveState(state *PipelineState) error {
	data, err := json.MarshalIndent(state, "", "  ")
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

// RunOptions contains options for the pipeline Run method.
type RunOptions struct {
	Resume         bool   // Continue from last saved state
	DryRun         bool   // Show what would happen without executing
	SkipPR         bool   // Skip PR creation at the end
	ReportPath     string // Specific report file to use (skips find latest)
	SourceMarkdown string // Positional markdown path (skips analyze/spec)
	BaseBranch     string // Base branch for creating work branch / PR target
}

// Run executes the compound pipeline from the current state or from the beginning.
func (p *Pipeline) Run(ctx context.Context, opts RunOptions) error {
	// Load or create initial state
	var state *PipelineState
	var err error
	if opts.Resume {
		state = p.loadState()
		if state == nil {
			return fmt.Errorf("no saved state to resume from")
		}
		p.display.ShowInfo("   Resuming from step: %s\n", state.Step)
	} else {
		state, err = p.newInitialState(opts)
		if err != nil {
			return err
		}
	}

	if err := p.initializeBaseBranch(state, opts); err != nil {
		return err
	}
	if state.BaseBranch != "" {
		p.display.ShowInfo("   Base branch: %s\n", state.BaseBranch)
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
		case StepRun:
			err = p.runLoopStep(ctx, state, opts)
		case StepCI:
			err = p.runPRStep(ctx, state, opts)
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
		Step:      StepAnalyze,
		StartedAt: time.Now(),
	}

	sourceMarkdown := strings.TrimSpace(opts.SourceMarkdown)
	if sourceMarkdown == "" {
		return state, nil
	}

	branchName, err := resolveSourceMarkdownBranchName(sourceMarkdown)
	if err != nil {
		return nil, err
	}

	state.Step = StepBranch
	state.SourceMarkdown = sourceMarkdown
	state.BranchName = branchName
	return state, nil
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
		return "", fmt.Errorf("unable to resolve branchName from markdown metadata, title, or filename; pass --branch")
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

	// Derive PRD path from branch name
	prdName := state.Analysis.BranchName
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

	// Build prompt
	prompt := fmt.Sprintf(`You are an autonomous PRD generation agent. Follow the autospec skill instructions below.

<skill>
%s
</skill>

%s

Generate a PRD following the skill rules:
1. Do NOT ask any questions - self-clarify from the analysis context
2. Use T-XXX task IDs (T-001, T-002, etc.)
3. Each task must be completable in ONE agent iteration
4. Include boolean acceptance criteria
5. Every task ends with "Typecheck passes"

Write the PRD directly to %s using the Write tool.`, autospecSkill, analysisContext, prdPath)

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

// runExplodeStep breaks down the PRD into granular tasks.
func (p *Pipeline) runExplodeStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: convert\n")

	if state.SourceMarkdown == "" {
		return fmt.Errorf("no source markdown path in state")
	}

	outPath := filepath.Join(p.dir, template.HalDir, template.AutoPRDFile)

	if opts.DryRun {
		p.display.ShowInfo("   [dry-run] Would explode PRD to: %s\n", outPath)
		state.Step = StepLoop
		return nil
	}

	// Read PRD content
	prdContent, err := os.ReadFile(state.SourceMarkdown)
	if err != nil {
		return fmt.Errorf("failed to read PRD: %w", err)
	}

	// Load explode skill
	explodeSkill, err := skills.LoadSkill("explode")
	if err != nil {
		return fmt.Errorf("failed to load explode skill: %w", err)
	}

	// Build prompt
	prompt := fmt.Sprintf(`You are a PRD task breakdown agent. Follow the explode skill instructions below.

<skill>
%s
</skill>

<prd>
%s
</prd>

Branch name to use: %s

Break down this PRD into 8-15 granular tasks following the skill rules:
1. Each task completable in ONE agent iteration
2. Tasks ordered by dependency (types → logic → integration → verification)
3. Every task has boolean acceptance criteria
4. Every task ends with "Typecheck passes"
5. Use T-XXX IDs (T-001, T-002, etc.)
6. All tasks have passes: false and empty notes

Write the JSON directly to %s using the Write tool.`, explodeSkill, string(prdContent), state.BranchName, outPath)

	// Record output file modification time before (if exists)
	var preModTime time.Time
	if stat, err := os.Stat(outPath); err == nil {
		preModTime = stat.ModTime()
	}

	// Execute prompt with streaming display
	p.display.ShowInfo("   Exploding PRD into tasks...\n")
	response, err := p.engine.StreamPrompt(ctx, prompt, p.display)
	// Check if engine wrote the output file directly using tools
	fileWritten := false
	if stat, err := os.Stat(outPath); err == nil && stat.ModTime().After(preModTime) {
		fileWritten = true
	}
	if err != nil {
		if !fileWritten || !engine.RequiresOutputFallback(err) {
			return fmt.Errorf("engine prompt failed: %w", err)
		}
	}

	if fileWritten {
		// Engine wrote the file - validate and format it
		content, err := os.ReadFile(outPath)
		if err != nil {
			return fmt.Errorf("failed to read engine-written %s: %w", template.AutoPRDFile, err)
		}

		// Validate JSON structure
		var prd engine.PRD
		if err := json.Unmarshal(content, &prd); err != nil {
			return fmt.Errorf("engine wrote invalid JSON: %w", err)
		}

		// Re-marshal with proper formatting
		formatted, err := json.MarshalIndent(prd, "", "  ")
		if err != nil {
			return err
		}

		// Write formatted version back
		if err := os.WriteFile(outPath, formatted, 0644); err != nil {
			return fmt.Errorf("failed to write formatted %s: %w", template.AutoPRDFile, err)
		}

		taskCount := countExplodeTasks(&prd)
		p.display.ShowInfo("   Tasks generated: %d • Path: %s\n", taskCount, outPath)
	} else {
		// Fallback: Parse JSON from text response
		prdJSON, err := extractJSONFromResponse(response)
		if err != nil {
			return fmt.Errorf("failed to extract JSON from response: %w", err)
		}

		// Ensure output directory exists
		outDir := filepath.Dir(outPath)
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		// Write auto-prd.json
		if err := os.WriteFile(outPath, []byte(prdJSON), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", template.AutoPRDFile, err)
		}

		// Parse to get task count
		taskCount := 0
		var prd engine.PRD
		if err := json.Unmarshal([]byte(prdJSON), &prd); err == nil {
			taskCount = countExplodeTasks(&prd)
		}
		p.display.ShowInfo("   Tasks generated: %d • Path: %s\n", taskCount, outPath)
	}

	// Save state and advance to next step
	state.Step = StepLoop
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

// runLoopStep executes the Hal loop to complete all tasks in the PRD.
func (p *Pipeline) runLoopStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: run\n")

	if opts.DryRun {
		p.display.ShowInfo("   [dry-run] Would run task loop with max %d iterations\n", p.config.MaxIterations)
		state.Step = StepPR
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

	// Create loop runner with config from auto settings
	loopConfig := loop.Config{
		Dir:           filepath.Join(p.dir, template.HalDir),
		PRDFile:       template.AutoPRDFile,
		ProgressFile:  template.ProgressFile,
		BaseBranch:    state.BaseBranch,
		MaxIterations: p.config.MaxIterations,
		Engine:        p.engine.Name(),
		EngineConfig:  p.engineConfig,
		Logger:        p.display.Writer(),
		MaxRetries:    3, // Use default retry count
	}

	runner, err := loop.New(loopConfig)
	if err != nil {
		return fmt.Errorf("failed to create loop runner: %w", err)
	}

	// Run the loop
	p.display.ShowInfo("   Running task loop...\n")
	result := runner.Run(ctx)

	if result.Error != nil {
		return fmt.Errorf("loop execution failed: %w", result.Error)
	}

	// Report result
	if result.Complete {
		p.display.ShowInfo("   All tasks completed in %d iterations\n", result.Iterations)
	} else {
		p.display.ShowInfo("   Loop stopped after %d iterations (tasks remaining)\n", result.Iterations)
	}

	state.Run = &RunState{
		Iterations:    result.Iterations,
		Complete:      result.Complete,
		MaxIterations: p.config.MaxIterations,
	}

	// Save state and advance to next step
	state.Step = StepPR
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

// migrateAutoProgress migrates content from legacy auto-progress.txt to unified progress.txt.
// If auto-progress.txt exists, its content is appended to progress.txt and the legacy file is deleted.
func (p *Pipeline) migrateAutoProgress() error {
	return MigrateAutoProgress(p.dir, p.display)
}

// runPRStep pushes the branch and creates a draft pull request.
func (p *Pipeline) runPRStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: ci\n")

	if opts.SkipPR {
		p.display.ShowInfo("   Skipping PR creation (--skip-pr)\n")
		if err := p.clearState(); err != nil {
			return fmt.Errorf("failed to clear state: %w", err)
		}
		state.Step = StepDone
		return nil
	}

	if state.BranchName == "" {
		return fmt.Errorf("no branch name in state")
	}

	if opts.DryRun {
		if state.BaseBranch != "" {
			p.display.ShowInfo("   [dry-run] Would push branch %s and create draft PR against %s\n", state.BranchName, state.BaseBranch)
		} else {
			p.display.ShowInfo("   [dry-run] Would push branch %s and create draft PR\n", state.BranchName)
		}
		state.Step = StepDone
		return nil
	}

	// Push the branch
	p.display.ShowInfo("   Pushing branch: %s\n", state.BranchName)
	if err := PushBranch(state.BranchName); err != nil {
		return fmt.Errorf("failed to push branch: %w", err)
	}

	taskStatus := ""
	if prd, err := engine.LoadPRDFile(filepath.Join(p.dir, template.HalDir), template.AutoPRDFile); err == nil {
		taskStatus = buildTaskStatusSection(prd, state, p.config.MaxIterations)
	}

	// Build PR body from analysis
	prBody := buildPRBody(state, taskStatus)

	// Create PR title from analysis
	prTitle := state.Analysis.PriorityItem
	if prTitle == "" {
		prTitle = "Compound: " + state.BranchName
	}

	// Create draft PR
	p.display.ShowInfo("   Creating draft PR...\n")
	prURL, err := CreatePR(prTitle, prBody, state.BaseBranch, state.BranchName)
	if err != nil {
		return fmt.Errorf("failed to create PR: %w", err)
	}

	p.display.ShowInfo("   PR created: %s\n", prURL)

	// Clear state on successful completion
	if err := p.clearState(); err != nil {
		return fmt.Errorf("failed to clear state: %w", err)
	}

	state.Step = StepDone
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

// extractJSONFromResponse extracts JSON object from a response that may contain
// markdown code blocks or other text.
func extractJSONFromResponse(response string) (string, error) {
	response = strings.TrimSpace(response)

	// Handle markdown code blocks
	if strings.Contains(response, "```") {
		response = extractFromCodeBlock(response)
	}

	// Find JSON object
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end < start {
		return "", fmt.Errorf("no JSON found in response")
	}
	response = response[start : end+1]

	// Validate JSON by parsing it
	var prd engine.PRD
	if err := json.Unmarshal([]byte(response), &prd); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	// Re-marshal with proper formatting
	formatted, err := json.MarshalIndent(prd, "", "  ")
	if err != nil {
		return "", err
	}

	return string(formatted), nil
}

// extractFromCodeBlock extracts content from markdown code blocks.
func extractFromCodeBlock(response string) string {
	var result strings.Builder
	inBlock := false
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "```") {
			inBlock = !inBlock
			continue
		}
		if inBlock {
			result.WriteString(line)
			result.WriteString("\n")
		}
	}
	return result.String()
}

// countExplodeTasks returns the number of tasks in a PRD.
func countExplodeTasks(prd *engine.PRD) int {
	if len(prd.UserStories) > 0 {
		return len(prd.UserStories)
	}
	return len(prd.Tasks)
}
