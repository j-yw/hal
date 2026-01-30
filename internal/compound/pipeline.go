package compound

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jywlabs/goralph/internal/engine"
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
			// T-015 will implement this
			return nil
		case StepExplode:
			// T-015 will implement this
			return nil
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
