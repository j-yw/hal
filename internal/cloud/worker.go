package cloud

import (
	"context"
	"fmt"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// ErrNoWork is returned by ProcessOne when the claim queue has no eligible
// runs. Callers should treat this as a normal "nothing to do" signal, not
// an operational error.
var ErrNoWork = fmt.Errorf("no eligible runs in queue")

// IsNoWork reports whether err is the no-work sentinel.
func IsNoWork(err error) bool {
	return err == ErrNoWork
}

// WorkerPipelineConfig holds the dependencies and settings for WorkerPipeline.
type WorkerPipelineConfig struct {
	// Store is the persistence backend (required).
	Store Store
	// Runner is the sandbox lifecycle backend (required).
	Runner runner.Runner
	// WorkerID identifies this worker instance (required, non-empty).
	WorkerID string
	// Claim is the service used to atomically claim queued runs (required).
	Claim *ClaimService
}

// WorkerPipeline orchestrates the lifecycle of a single claimed run:
// claim → setup → execute → finalize → cleanup. Each ProcessOne call
// handles exactly one run from the queue.
type WorkerPipeline struct {
	store    Store
	runner   runner.Runner
	workerID string
	claim    *ClaimService
}

// NewWorkerPipeline validates required dependencies and returns a ready
// pipeline. Returns an error if any required dependency is missing.
func NewWorkerPipeline(cfg WorkerPipelineConfig) (*WorkerPipeline, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("store must not be nil")
	}
	if cfg.Runner == nil {
		return nil, fmt.Errorf("runner must not be nil")
	}
	if cfg.WorkerID == "" {
		return nil, fmt.Errorf("workerID must not be empty")
	}
	if cfg.Claim == nil {
		return nil, fmt.Errorf("claim must not be nil")
	}
	return &WorkerPipeline{
		store:    cfg.Store,
		runner:   cfg.Runner,
		workerID: cfg.WorkerID,
		claim:    cfg.Claim,
	}, nil
}

// ProcessOne claims one eligible run and executes the full attempt lifecycle.
// Returns ErrNoWork when the queue is empty (no eligible runs). Other errors
// indicate operational failures during the attempt.
func (p *WorkerPipeline) ProcessOne(ctx context.Context) error {
	result, err := p.claim.ClaimAndLock(ctx, p.workerID)
	if err != nil {
		if IsNotFound(err) {
			return ErrNoWork
		}
		return fmt.Errorf("claiming run: %w", err)
	}

	// Future stories will add: setup, execution, finalization, cleanup.
	_ = result
	return nil
}
