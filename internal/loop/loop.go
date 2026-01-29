package loop

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jywlabs/goralph/internal/engine"
	"github.com/jywlabs/goralph/internal/template"
)

// Result represents the outcome of the loop execution.
type Result struct {
	Iterations int   // Number of iterations run
	Complete   bool  // Whether all tasks were completed
	Success    bool  // Whether the loop finished successfully
	Error      error // Any error that occurred
}

// Config holds configuration for the loop.
type Config struct {
	Dir           string        // Path to .goralph directory
	MaxIterations int           // Maximum iterations (0 = unlimited)
	Engine        string        // Engine name (claude)
	Logger        io.Writer     // Where to write logs
	RetryDelay    time.Duration // Delay between retries on failure
	MaxRetries    int           // Max retries per iteration on failure
	DryRun        bool          // Show what would execute without running
	StoryID       string        // Run specific story by ID (e.g., US-001)
}

// Runner orchestrates the Ralph loop.
type Runner struct {
	config  Config
	engine  engine.Engine
	display *engine.Display
}

// New creates a new loop Runner.
func New(cfg Config) (*Runner, error) {
	if cfg.Dir == "" {
		cfg.Dir = template.GoralphDir
	}
	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 10
	}
	if cfg.Engine == "" {
		cfg.Engine = "claude"
	}
	if cfg.Logger == nil {
		cfg.Logger = os.Stdout
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = 5 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}

	eng, err := engine.New(cfg.Engine)
	if err != nil {
		return nil, err
	}

	return &Runner{
		config:  cfg,
		engine:  eng,
		display: engine.NewDisplay(cfg.Logger),
	}, nil
}

// Run executes the Ralph loop.
func (r *Runner) Run(ctx context.Context) Result {
	// Load prompt
	prompt, err := r.loadPrompt()
	if err != nil {
		return Result{
			Success: false,
			Error:   fmt.Errorf("failed to load prompt: %w", err),
		}
	}

	// Verify prd.json exists
	prdPath := filepath.Join(r.config.Dir, "prd.json")
	if _, err := os.Stat(prdPath); os.IsNotExist(err) {
		return Result{
			Success: false,
			Error:   fmt.Errorf("prd.json not found at %s", prdPath),
		}
	}

	// Load PRD
	prd, err := engine.LoadPRD(r.config.Dir)
	if err != nil {
		return Result{
			Success: false,
			Error:   fmt.Errorf("failed to load PRD: %w", err),
		}
	}

	// Determine which story to run
	var targetStory *engine.UserStory
	if r.config.StoryID != "" {
		// Find specific story by ID
		targetStory = prd.FindStoryByID(r.config.StoryID)
		if targetStory == nil {
			return Result{
				Success: false,
				Error:   fmt.Errorf("story not found: %s", r.config.StoryID),
			}
		}
	} else {
		// Get next pending story
		targetStory = prd.CurrentStory()
	}

	// Handle dry-run mode
	if r.config.DryRun {
		r.display.ShowInfo("Dry-run mode: showing what would execute\n\n")
		if targetStory == nil {
			r.display.ShowSuccess("All stories are complete!")
			return Result{Success: true, Complete: true}
		}
		r.display.ShowInfo("Next story to execute:\n")
		r.display.ShowInfo("  ID:    %s\n", targetStory.ID)
		r.display.ShowInfo("  Title: %s\n", targetStory.Title)
		r.display.ShowInfo("  Description: %s\n", targetStory.Description)
		r.display.ShowInfo("\nAcceptance Criteria:\n")
		for _, ac := range targetStory.AcceptanceCriteria {
			r.display.ShowInfo("  - %s\n", ac)
		}
		r.display.ShowInfo("\nPrompt file: %s/prompt.md\n", r.config.Dir)
		return Result{Success: true}
	}

	r.display.ShowLoopHeader(r.engine.Name(), r.config.MaxIterations)

	result := Result{}

	for i := 1; i <= r.config.MaxIterations; i++ {
		// Load PRD to get current story info
		var storyInfo *engine.StoryInfo
		if r.config.StoryID != "" {
			// Running specific story
			storyInfo = &engine.StoryInfo{
				ID:    targetStory.ID,
				Title: targetStory.Title,
			}
		} else if prd, err := engine.LoadPRD(r.config.Dir); err == nil {
			if story := prd.CurrentStory(); story != nil {
				storyInfo = &engine.StoryInfo{
					ID:    story.ID,
					Title: story.Title,
				}
			}
		}

		r.display.ShowIterationHeader(i, r.config.MaxIterations, storyInfo)

		// Execute with retry
		execResult := r.executeWithRetry(ctx, prompt)
		result.Iterations = i

		if execResult.Error != nil {
			r.display.ShowError(fmt.Sprintf("%v", execResult.Error))
			result.Error = execResult.Error
			result.Success = false
			return result
		}

		if execResult.Complete {
			// Verify that all stories actually have passes: true before accepting COMPLETE
			// This guards against LLM reasoning errors where it says COMPLETE prematurely
			if prd, err := engine.LoadPRD(r.config.Dir); err == nil {
				if story := prd.CurrentStory(); story != nil {
					// There are still pending stories - LLM said COMPLETE incorrectly
					r.display.ShowInfo("   ⚠ Agent signaled COMPLETE but %s is still pending\n", story.ID)
					r.display.ShowIterationComplete(i)
					// Continue to next iteration
					select {
					case <-ctx.Done():
						result.Error = ctx.Err()
						return result
					case <-time.After(2 * time.Second):
					}
					continue
				}
			}
			r.display.ShowSuccess("All tasks complete!")
			result.Complete = true
			result.Success = true
			return result
		}

		r.display.ShowIterationComplete(i)

		// Small delay between iterations
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result
		case <-time.After(2 * time.Second):
		}
	}

	// Max iterations reached - this is not an error, just a stopping point
	r.display.ShowMaxIterations()
	result.Success = true
	result.Complete = false
	return result
}

// loadPrompt reads the prompt file.
func (r *Runner) loadPrompt() (string, error) {
	promptPath := filepath.Join(r.config.Dir, "prompt.md")
	data, err := os.ReadFile(promptPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// executeWithRetry runs a single iteration with retry on failure.
func (r *Runner) executeWithRetry(ctx context.Context, prompt string) engine.Result {
	var lastResult engine.Result

	for attempt := 0; attempt <= r.config.MaxRetries; attempt++ {
		if attempt > 0 {
			r.display.ShowInfo("   Retrying... (attempt %d/%d)\n", attempt+1, r.config.MaxRetries+1)
			select {
			case <-ctx.Done():
				return engine.Result{Error: ctx.Err()}
			case <-time.After(r.retryDelay(attempt)):
			}
		}

		lastResult = r.engine.Execute(ctx, prompt, r.display)

		if lastResult.Success || lastResult.Complete {
			return lastResult
		}

		// Check if error is retryable
		if lastResult.Error != nil && !r.isRetryable(lastResult.Error) {
			return lastResult
		}
	}

	return lastResult
}

// retryDelay calculates exponential backoff delay.
func (r *Runner) retryDelay(attempt int) time.Duration {
	delay := r.config.RetryDelay * time.Duration(1<<attempt)
	if delay > 2*time.Minute {
		delay = 2 * time.Minute
	}
	return delay
}

// isRetryable checks if an error is retryable.
func (r *Runner) isRetryable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	retryablePatterns := []string{
		"rate limit",
		"timeout",
		"timed out",
		"connection",
		"503",
		"429",
		"overloaded",
	}
	for _, pattern := range retryablePatterns {
		if containsIgnoreCase(msg, pattern) {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c1, c2 := s[i+j], substr[j]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 'a' - 'A'
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 'a' - 'A'
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
