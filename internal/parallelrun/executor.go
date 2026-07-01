package parallelrun

import (
	"context"
	"fmt"
	"time"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/loop"
)

// EngineWorkerExecutor runs worker prompts through a configured Hal engine.
type EngineWorkerExecutor struct {
	MaxRetries int
	RetryDelay time.Duration
	NewEngine  func(string, *engine.EngineConfig) (engine.Engine, error)
}

// NewEngineWorkerExecutor creates the default worker executor.
func NewEngineWorkerExecutor(maxRetries int, retryDelay time.Duration) *EngineWorkerExecutor {
	return &EngineWorkerExecutor{
		MaxRetries: maxRetries,
		RetryDelay: retryDelay,
		NewEngine:  engine.NewWithConfig,
	}
}

// ExecuteWorker executes one assignment and reads its manifest.
func (e *EngineWorkerExecutor) ExecuteWorker(ctx context.Context, req WorkerExecutionRequest) WorkerExecutionResult {
	newEngine := e.NewEngine
	if newEngine == nil {
		newEngine = engine.NewWithConfig
	}

	cfg := cloneEngineConfig(req.EngineConfig)
	cfg.WorkDir = req.WorktreePath
	eng, err := newEngine(req.Engine, cfg)
	if err != nil {
		return WorkerExecutionResult{Error: err}
	}

	prompt := loop.BuildWorkerAssignmentPrompt(req.Assignment)
	display := engine.NewDisplay(req.Logger)
	var result engine.Result
	attempts := e.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 && e.RetryDelay > 0 {
			select {
			case <-ctx.Done():
				return WorkerExecutionResult{Error: ctx.Err()}
			case <-time.After(e.RetryDelay):
			}
		}
		result = eng.Execute(ctx, prompt, display)
		if result.Error == nil && (result.Success || result.Complete) {
			break
		}
		if result.Error == nil {
			break
		}
	}
	if result.Error != nil {
		return WorkerExecutionResult{EngineResult: result}
	}

	manifest, manifestErr := loop.ReadWorkerManifest(req.ManifestPath)
	if manifestErr == nil {
		return WorkerExecutionResult{EngineResult: result, Manifest: manifest}
	}
	if !result.Success && !result.Complete {
		return WorkerExecutionResult{
			EngineResult: result,
			Error:        fmt.Errorf("worker %s did not report success and manifest is unavailable: %w", req.Assignment.TaskID, manifestErr),
		}
	}

	return WorkerExecutionResult{EngineResult: result, Error: manifestErr}
}

func cloneEngineConfig(cfg *engine.EngineConfig) *engine.EngineConfig {
	if cfg == nil {
		return &engine.EngineConfig{}
	}
	next := *cfg
	return &next
}
