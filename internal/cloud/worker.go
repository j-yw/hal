package cloud

import (
	"context"
	"fmt"
	"time"

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
	// Checkpoint is the service used to commit and push sandbox changes (required).
	Checkpoint *CheckpointService
	// Cancel is the service used to check and propagate cancel intent (required).
	Cancel *CancellationService
	// Heartbeat is the service used to renew attempt leases (required).
	Heartbeat *HeartbeatService
	// HeartbeatInterval is the interval between heartbeat ticks. Defaults to
	// 10 seconds if zero.
	HeartbeatInterval time.Duration
	// GitUsername is the HTTPS auth username for clone/push (optional).
	GitUsername string
	// GitPassword is the HTTPS auth password/token for clone/push (optional).
	GitPassword string
}

// WorkerPipeline orchestrates the lifecycle of a single claimed run:
// claim -> setup -> execute -> finalize -> cleanup. Each ProcessOne call
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
	checkpoint          *CheckpointService
	cancel              *CancellationService
	heartbeat           *HeartbeatService
	heartbeatInterval   time.Duration
	gitUsername         string
	gitPassword         string
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
	if cfg.Checkpoint == nil {
		return nil, fmt.Errorf("checkpoint must not be nil")
	}
	if cfg.Cancel == nil {
		return nil, fmt.Errorf("cancel must not be nil")
	}
	if cfg.Heartbeat == nil {
		return nil, fmt.Errorf("heartbeat must not be nil")
	}
	hbInterval := cfg.HeartbeatInterval
	if hbInterval == 0 {
		hbInterval = 10 * time.Second
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
		checkpoint:          cfg.Checkpoint,
		cancel:              cfg.Cancel,
		heartbeat:           cfg.Heartbeat,
		heartbeatInterval:   hbInterval,
		gitUsername:         cfg.GitUsername,
		gitPassword:         cfg.GitPassword,
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

// heartbeatResult communicates why the heartbeat goroutine exited.
type heartbeatResult struct {
	// LeaseLost is true when the heartbeat detected ErrLeaseExpired from Renew.
	// The HeartbeatService already transitioned the attempt to failed with
	// error_code "lease_lost" -- the worker must NOT emit a duplicate
	// TransitionAttempt.
	LeaseLost bool

	// ProfileRevoked is true when the heartbeat detected ErrProfileRevoked
	// from Renew. The HeartbeatService already transitioned the attempt to
	// failed with error_code "profile_revoked" and released the auth lock --
	// the worker must NOT emit a duplicate TransitionAttempt or release the
	// auth lock again.
	ProfileRevoked bool
}

// executeAttempt runs the full attempt lifecycle for a claimed run.
// It transitions the run from claimed to running, then executes setup
// services in a deterministic order: provision -> bootstrap ->
// auth materialization -> preflight. A heartbeat goroutine runs
// throughout setup and execution until terminal routing begins.
func (p *WorkerPipeline) executeAttempt(ctx context.Context, claim *ClaimResult) error {
	run := claim.Run
	attempt := claim.Attempt

	// Compute the deterministic working branch for this run.
	workingBranch := WorkingBranch(run.ID)

	// Track current run status for status-aware failure transitions.
	currentStatus := RunStatusClaimed

	// Step 1: Transition run from claimed to running before any setup work.
	if err := p.store.TransitionRun(ctx, run.ID, RunStatusClaimed, RunStatusRunning); err != nil {
		p.handleSetupFailure(ctx, run.ID, attempt.ID, currentStatus, "transitioning run to running", err)
		return fmt.Errorf("transitioning run to running: %w", err)
	}
	currentStatus = RunStatusRunning

	// Start heartbeat loop after transitioning to running. The heartbeat
	// remains active through setup and execution until stopHeartbeat is called.
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	hbResult, heartbeatDone := p.startHeartbeat(heartbeatCtx, attempt.ID, run.AuthProfileID, run.ID)
	defer func() {
		stopHeartbeat()
		<-heartbeatDone
	}()

	// Step 2: Provision -- create sandbox.
	provResult, err := p.provision.Provision(ctx, attempt.ID, run.ID)
	if err != nil {
		p.handleSetupFailure(ctx, run.ID, attempt.ID, currentStatus, "provision", err)
		return fmt.Errorf("provision failed: %w", err)
	}

	// Step 3: Bootstrap -- clone repo, checkout branch, run hal init.
	if err := p.bootstrap.Bootstrap(ctx, &BootstrapRequest{
		Repo:          run.Repo,
		Branch:        run.BaseBranch,
		SandboxID:     provResult.SandboxID,
		AttemptID:     attempt.ID,
		RunID:         run.ID,
		WorkingBranch: workingBranch,
		AttemptNumber: attempt.AttemptNumber,
		GitUsername:   p.gitUsername,
		GitPassword:   p.gitPassword,
	}); err != nil {
		p.handleSetupFailure(ctx, run.ID, attempt.ID, currentStatus, "bootstrap", err)
		return fmt.Errorf("bootstrap failed: %w", err)
	}

	// Step 4: Auth materialization -- write auth artifacts into sandbox.
	if err := p.authMaterialization.Materialize(ctx, &MaterializeRequest{
		AuthProfileID: run.AuthProfileID,
		SandboxID:     provResult.SandboxID,
		AttemptID:     attempt.ID,
		RunID:         run.ID,
	}); err != nil {
		p.handleSetupFailure(ctx, run.ID, attempt.ID, currentStatus, "auth materialization", err)
		return fmt.Errorf("auth materialization failed: %w", err)
	}

	// Step 5: Preflight -- validate provider-specific requirements.
	if err := p.preflight.Preflight(ctx, &PreflightRequest{
		AuthProfileID: run.AuthProfileID,
		SandboxID:     provResult.SandboxID,
		AttemptID:     attempt.ID,
		RunID:         run.ID,
	}); err != nil {
		p.handleSetupFailure(ctx, run.ID, attempt.ID, currentStatus, "preflight", err)
		return fmt.Errorf("preflight failed: %w", err)
	}

	// Check if heartbeat detected lease_lost or profile_revoked during
	// setup/execution. Stop the heartbeat first so we can safely read
	// the result.
	stopHeartbeat()
	<-heartbeatDone

	if hbResult.LeaseLost {
		p.handleLeaseLost(ctx, run.ID, run.AuthProfileID, provResult.SandboxID)
		return fmt.Errorf("lease lost during execution")
	}

	if hbResult.ProfileRevoked {
		p.handleProfileRevoked(ctx, run.ID, provResult.SandboxID)
		return fmt.Errorf("profile revoked during execution")
	}

	// Future stories will add: execution, finalization, cleanup.
	return nil
}

// startHeartbeat launches a goroutine that ticks at p.heartbeatInterval.
// On each tick it calls cancel.CheckAndCancel before heartbeat.Renew.
// When cancellation is detected, the tick skips Renew and cancels ctx
// via the provided cancelFunc so the main pipeline observes the signal.
// The goroutine runs until ctx is canceled. The returned result is populated
// before the done channel is closed; callers should stop the heartbeat and
// drain the done channel before reading the result.
func (p *WorkerPipeline) startHeartbeat(ctx context.Context, attemptID, authProfileID, runID string) (*heartbeatResult, <-chan struct{}) {
	done := make(chan struct{})
	result := &heartbeatResult{}
	go func() {
		defer close(done)
		ticker := time.NewTicker(p.heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Check cancellation before renewing the lease.
				cancelResult, err := p.cancel.CheckAndCancel(ctx, runID, attemptID, authProfileID)
				if err == nil && cancelResult.Canceled {
					// Cancellation detected -- do not renew, just return.
					return
				}
				err = p.heartbeat.Renew(ctx, attemptID, authProfileID, runID)
				if err != nil {
					if IsLeaseExpired(err) {
						// Lease lost -- heartbeat service already marked the
						// attempt as failed with error_code "lease_lost".
						// Signal the main goroutine so it can route through
						// lease-lost handling without duplicate transitions.
						result.LeaseLost = true
						return
					}
					if IsProfileRevoked(err) {
						// Profile revoked -- heartbeat service already marked
						// the attempt as failed with error_code "profile_revoked"
						// and released the auth lock. Signal the main goroutine
						// so it can route through profile-revoked handling
						// without duplicate transitions or auth lock releases.
						result.ProfileRevoked = true
						return
					}
				}
			}
		}
	}()
	return result, done
}

// handleLeaseLost handles the lease_lost terminal path. The HeartbeatService
// has already transitioned the attempt to failed (with error_code "lease_lost"),
// so this method must NOT emit a duplicate TransitionAttempt. It transitions
// the run to failed and performs cleanup (auth lock release, sandbox teardown).
func (p *WorkerPipeline) handleLeaseLost(ctx context.Context, runID, authProfileID, sandboxID string) {
	// Transition run from running to failed. Best-effort -- the run may have
	// already been transitioned by a concurrent reconciler.
	_ = p.store.TransitionRun(ctx, runID, RunStatusRunning, RunStatusFailed)

	// Release auth lock -- tolerate ErrNotFound (lock may have expired or been released).
	now := time.Now().UTC()
	_ = p.store.ReleaseAuthLock(ctx, authProfileID, runID, now)

	// Destroy sandbox -- best-effort cleanup.
	if sandboxID != "" {
		_ = p.runner.DestroySandbox(ctx, sandboxID)
	}
}

// handleProfileRevoked handles the profile_revoked terminal path. The
// HeartbeatService has already transitioned the attempt to failed (with
// error_code "profile_revoked") and released the auth lock, so this method
// must NOT emit a duplicate TransitionAttempt or release the auth lock.
// It transitions the run to failed and performs sandbox cleanup.
func (p *WorkerPipeline) handleProfileRevoked(ctx context.Context, runID, sandboxID string) {
	// Transition run from running to failed. Best-effort -- the run may have
	// already been transitioned by a concurrent reconciler.
	_ = p.store.TransitionRun(ctx, runID, RunStatusRunning, RunStatusFailed)

	// Destroy sandbox -- best-effort cleanup.
	// Note: Auth lock is NOT released here because emitProfileRevokedAndTerminate
	// in HeartbeatService already released it.
	if sandboxID != "" {
		_ = p.runner.DestroySandbox(ctx, sandboxID)
	}
}

// handleSetupFailure transitions both the run and attempt to failed status
// using the provided fromRunStatus. This ensures failure transitions use the
// correct source status regardless of how far setup progressed.
func (p *WorkerPipeline) handleSetupFailure(ctx context.Context, runID, attemptID string, fromRunStatus RunStatus, stage string, cause error) {
	now := time.Now().UTC()
	errCode := "setup_failure"
	errMsg := fmt.Sprintf("%s failed: %s", stage, cause.Error())

	// Transition attempt to failed.
	_ = p.store.TransitionAttempt(ctx, attemptID, AttemptStatusFailed, now, &errCode, &errMsg)

	// Transition run from its current status to failed.
	_ = p.store.TransitionRun(ctx, runID, fromRunStatus, RunStatusFailed)
}
