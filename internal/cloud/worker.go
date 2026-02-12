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
	// Provision is the service used to create sandboxes (required).
	Provision *ProvisionService
	// Bootstrap is the service used to clone repos and run init (required).
	Bootstrap *BootstrapService
	// AuthMaterialization is the service used to materialize auth artifacts (required).
	AuthMaterialization *AuthMaterializationService
	// Preflight is the service used to run provider-specific validation (required).
	Preflight *PreflightService
}

// WorkerPipeline orchestrates the lifecycle of a single claimed run:
// claim → setup → execute → finalize → cleanup. Each ProcessOne call
// handles exactly one run from the queue.
type WorkerPipeline struct {
	store               Store
	runner              runner.Runner
	workerID            string
	claim               *ClaimService
	provision           *ProvisionService
	bootstrap           *BootstrapService
	authMaterialization *AuthMaterializationService
	preflight           *PreflightService
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
	if cfg.Provision == nil {
		return nil, fmt.Errorf("provision must not be nil")
	}
	if cfg.Bootstrap == nil {
		return nil, fmt.Errorf("bootstrap must not be nil")
	}
	if cfg.AuthMaterialization == nil {
		return nil, fmt.Errorf("authMaterialization must not be nil")
	}
	if cfg.Preflight == nil {
		return nil, fmt.Errorf("preflight must not be nil")
	}
	return &WorkerPipeline{
		store:               cfg.Store,
		runner:              cfg.Runner,
		workerID:            cfg.WorkerID,
		claim:               cfg.Claim,
		provision:           cfg.Provision,
		bootstrap:           cfg.Bootstrap,
		authMaterialization: cfg.AuthMaterialization,
		preflight:           cfg.Preflight,
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

	return p.executeAttempt(ctx, result)
}

// executeAttempt runs the full attempt lifecycle for a claimed run.
// It transitions the run from claimed to running, then executes setup
// services in a deterministic order: provision → bootstrap →
// auth materialization → preflight.
func (p *WorkerPipeline) executeAttempt(ctx context.Context, claim *ClaimResult) error {
	run := claim.Run
	attempt := claim.Attempt

	// Step 1: Transition run from claimed to running before any setup work.
	if err := p.store.TransitionRun(ctx, run.ID, RunStatusClaimed, RunStatusRunning); err != nil {
		return fmt.Errorf("transitioning run to running: %w", err)
	}

	// Step 2: Provision — create sandbox.
	provResult, err := p.provision.Provision(ctx, attempt.ID, run.ID)
	if err != nil {
		return fmt.Errorf("provision failed: %w", err)
	}

	// Step 3: Bootstrap — clone repo, checkout branch, run hal init.
	if err := p.bootstrap.Bootstrap(ctx, &BootstrapRequest{
		Repo:      run.Repo,
		Branch:    run.BaseBranch,
		SandboxID: provResult.SandboxID,
		AttemptID: attempt.ID,
		RunID:     run.ID,
	}); err != nil {
		return fmt.Errorf("bootstrap failed: %w", err)
	}

	// Step 4: Auth materialization — write auth artifacts into sandbox.
	if err := p.authMaterialization.Materialize(ctx, &MaterializeRequest{
		AuthProfileID: run.AuthProfileID,
		SandboxID:     provResult.SandboxID,
		AttemptID:     attempt.ID,
		RunID:         run.ID,
	}); err != nil {
		return fmt.Errorf("auth materialization failed: %w", err)
	}

	// Step 5: Preflight — validate provider-specific requirements.
	if err := p.preflight.Preflight(ctx, &PreflightRequest{
		AuthProfileID: run.AuthProfileID,
		SandboxID:     provResult.SandboxID,
		AttemptID:     attempt.ID,
		RunID:         run.ID,
	}); err != nil {
		return fmt.Errorf("preflight failed: %w", err)
	}

	// Future stories will add: execution, finalization, cleanup.
	return nil
}
