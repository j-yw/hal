package executor

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/jywlabs/goralph/internal/claude"
	"github.com/jywlabs/goralph/internal/git"
	"github.com/jywlabs/goralph/internal/marker"
	"github.com/jywlabs/goralph/internal/parser"
	"github.com/jywlabs/goralph/internal/prompt"
	"github.com/jywlabs/goralph/internal/retry"
)

// Result represents the outcome of the execution loop.
type Result struct {
	TotalTasks     int  // Total number of pending tasks found
	CompletedTasks int  // Number of successfully completed tasks
	Success        bool // Whether all tasks completed successfully
	Error          error
}

// Config holds configuration for the executor.
type Config struct {
	PRDFile    string    // Path to the PRD file
	RepoPath   string    // Path to the git repository (defaults to current directory)
	MaxRetries int       // Maximum retry attempts per task (defaults to 3)
	Logger     io.Writer // Where to write logs (nil for no logging)
}

// claudeEngine defines the interface for executing prompts.
// This allows for mocking in tests.
type claudeEngine interface {
	Execute(prompt string) claude.Result
}

// Executor orchestrates the sequential execution of PRD tasks.
type Executor struct {
	config Config
	engine claudeEngine
}

// New creates a new Executor with the given configuration.
func New(cfg Config) *Executor {
	if cfg.RepoPath == "" {
		cfg.RepoPath = "."
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = retry.DefaultMaxRetries
	}
	return &Executor{
		config: cfg,
		engine: claude.NewEngine(),
	}
}

// NewWithEngine creates an Executor with a custom engine (for testing).
func NewWithEngine(cfg Config, engine claudeEngine) *Executor {
	if cfg.RepoPath == "" {
		cfg.RepoPath = "."
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = retry.DefaultMaxRetries
	}
	return &Executor{
		config: cfg,
		engine: engine,
	}
}

// Run executes all pending tasks from the PRD file sequentially.
// For each task: build prompt, execute Claude, check result.
// On success: mark task complete, auto-commit, continue to next.
// On failure: retry up to MaxRetries times, then stop with error.
func (e *Executor) Run(ctx context.Context) Result {
	// Load pending tasks from PRD file
	tasks, err := e.loadTasks()
	if err != nil {
		return Result{
			Success: false,
			Error:   fmt.Errorf("failed to load tasks: %w", err),
		}
	}

	result := Result{
		TotalTasks: len(tasks),
	}

	if len(tasks) == 0 {
		result.Success = true
		return result
	}

	// Process each task sequentially
	for i, task := range tasks {
		e.log("Processing task %d/%d: %s\n", i+1, len(tasks), truncate(task.Description, 60))

		// Execute task with retry logic
		execResult := e.executeTaskWithRetry(ctx, task)

		if !execResult.Success {
			result.Error = execResult.Error
			return result
		}

		// Mark task as complete in PRD file
		if err := marker.MarkComplete(e.config.PRDFile, task.LineNumber); err != nil {
			result.Error = fmt.Errorf("failed to mark task complete: %w", err)
			return result
		}

		// Auto-commit changes
		commitResult, err := git.AutoCommit(e.config.RepoPath, task.Description)
		if err != nil {
			result.Error = fmt.Errorf("failed to commit: %w", err)
			return result
		}

		if commitResult.Committed {
			e.log("Committed: %s (%s)\n", commitResult.Message, commitResult.Hash[:7])
		}

		result.CompletedTasks++
	}

	result.Success = true
	return result
}

// loadTasks reads the PRD file and parses pending tasks.
func (e *Executor) loadTasks() ([]parser.Task, error) {
	file, err := os.Open(e.config.PRDFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return parser.Parse(file)
}

// executeTaskWithRetry executes a single task with retry logic.
func (e *Executor) executeTaskWithRetry(ctx context.Context, task parser.Task) retry.Result {
	cfg := retry.Config{
		MaxRetries: e.config.MaxRetries,
		Logger:     e.config.Logger,
	}

	op := func() retry.Result {
		taskPrompt := prompt.Build(task.Description)
		result := e.engine.Execute(taskPrompt)
		return retry.Result{
			Success: result.Success,
			Output:  result.Output,
			Error:   result.Error,
		}
	}

	return retry.Execute(ctx, cfg, op)
}

// log writes a formatted message to the logger if configured.
func (e *Executor) log(format string, args ...interface{}) {
	if e.config.Logger != nil {
		fmt.Fprintf(e.config.Logger, format, args...)
	}
}

// truncate shortens a string to the given length, adding "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
