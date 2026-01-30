package compound

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/goralph/internal/engine"
	"github.com/jywlabs/goralph/internal/skills"
	"github.com/jywlabs/goralph/internal/template"
)

const stateFileName = "auto-state.json"

// Pipeline orchestrates the compound engineering automation process.
type Pipeline struct {
	config  *AutoConfig
	engine  engine.Engine
	display *engine.Display
	dir     string
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

// statePath returns the full path to the state file.
func (p *Pipeline) statePath() string {
	return filepath.Join(p.dir, ".goralph", stateFileName)
}

// loadState reads the pipeline state from .goralph/auto-state.json.
// Returns nil if the state file doesn't exist.
func (p *Pipeline) loadState() *PipelineState {
	data, err := os.ReadFile(p.statePath())
	if err != nil {
		return nil
	}

	var state PipelineState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}

	return &state
}

// saveState writes the pipeline state to .goralph/auto-state.json atomically.
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
	Resume     bool   // Continue from last saved state
	DryRun     bool   // Show what would happen without executing
	SkipPR     bool   // Skip PR creation at the end
	ReportPath string // Specific report file to use (skips find latest)
}

// Run executes the compound pipeline from the current state or from the beginning.
func (p *Pipeline) Run(ctx context.Context, opts RunOptions) error {
	// Load or create initial state
	var state *PipelineState
	if opts.Resume {
		state = p.loadState()
		if state == nil {
			return fmt.Errorf("no saved state to resume from")
		}
		p.display.ShowInfo("   Resuming from step: %s\n", state.Step)
	} else {
		state = &PipelineState{
			Step:      StepAnalyze,
			StartedAt: time.Now(),
		}
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
		case StepBranch:
			err = p.runBranchStep(ctx, state, opts)
		case StepPRD:
			err = p.runPRDStep(ctx, state, opts)
		case StepExplode:
			err = p.runExplodeStep(ctx, state, opts)
		case StepLoop:
			// T-016 will implement this
			return nil
		case StepPR:
			// T-016 will implement this
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
		state.Step = StepBranch
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
	state.Step = StepBranch
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

// runBranchStep creates and checks out a new branch for the work.
func (p *Pipeline) runBranchStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: branch\n")

	if state.BranchName == "" {
		return fmt.Errorf("no branch name set in state")
	}

	if opts.DryRun {
		p.display.ShowInfo("   [dry-run] Would create branch: %s\n", state.BranchName)
		state.Step = StepPRD
		return nil
	}

	// Create and checkout the branch
	p.display.ShowInfo("   Creating branch: %s\n", state.BranchName)
	if err := CreateBranch(state.BranchName); err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}

	// Save state and advance to next step
	state.Step = StepPRD
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

// runPRDStep generates a PRD using the autospec skill with analysis context.
func (p *Pipeline) runPRDStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: prd\n")

	if state.Analysis == nil {
		return fmt.Errorf("no analysis result in state")
	}

	// Derive PRD path from branch name
	prdName := state.Analysis.BranchName
	if prdName == "" {
		prdName = "feature"
	}
	prdPath := filepath.Join(p.dir, template.GoralphDir, fmt.Sprintf("prd-%s.md", prdName))

	if opts.DryRun {
		p.display.ShowInfo("   [dry-run] Would generate PRD: %s\n", filepath.Base(prdPath))
		state.PRDPath = prdPath
		state.Step = StepExplode
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
	if err != nil {
		return fmt.Errorf("engine prompt failed: %w", err)
	}

	// Check if engine wrote the output file directly using tools
	if stat, err := os.Stat(prdPath); err == nil && stat.ModTime().After(preModTime) {
		// Engine wrote the file
		state.PRDPath = prdPath
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

		state.PRDPath = prdPath
		p.display.ShowInfo("   PRD generated: %s\n", filepath.Base(prdPath))
	}

	// Save state and advance to next step
	state.Step = StepExplode
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

// runExplodeStep breaks down the PRD into granular tasks.
func (p *Pipeline) runExplodeStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
	p.display.ShowInfo("   Step: explode\n")

	if state.PRDPath == "" {
		return fmt.Errorf("no PRD path in state")
	}

	outPath := filepath.Join(p.dir, template.GoralphDir, "prd.json")

	if opts.DryRun {
		p.display.ShowInfo("   [dry-run] Would explode PRD to: %s\n", outPath)
		state.Step = StepLoop
		return nil
	}

	// Read PRD content
	prdContent, err := os.ReadFile(state.PRDPath)
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
	if err != nil {
		return fmt.Errorf("engine prompt failed: %w", err)
	}

	// Check if engine wrote the output file directly using tools
	if stat, err := os.Stat(outPath); err == nil && stat.ModTime().After(preModTime) {
		// Engine wrote the file - validate and format it
		content, err := os.ReadFile(outPath)
		if err != nil {
			return fmt.Errorf("failed to read engine-written prd.json: %w", err)
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
			return fmt.Errorf("failed to write formatted prd.json: %w", err)
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

		// Write prd.json
		if err := os.WriteFile(outPath, []byte(prdJSON), 0644); err != nil {
			return fmt.Errorf("failed to write prd.json: %w", err)
		}

		// Parse to get task count
		var prd engine.PRD
		json.Unmarshal([]byte(prdJSON), &prd)
		taskCount := countExplodeTasks(&prd)
		p.display.ShowInfo("   Tasks generated: %d • Path: %s\n", taskCount, outPath)
	}

	// Save state and advance to next step
	state.Step = StepLoop
	if err := p.saveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
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
