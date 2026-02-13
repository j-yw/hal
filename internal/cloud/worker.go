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

// ErrorFunc is an optional callback for reporting operational errors from
// the worker loop. When non-nil, RunLoop invokes it for each non-nil,
// non-ErrNoWork error from ProcessOne, Reconcile, or EnforceTimeouts.
type ErrorFunc func(err error)

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
	// Execution is the service used to run Hal inside the sandbox (required).
	Execution *ExecutionService
	// Snapshot is the service used to persist final state snapshots (required).
	Snapshot *SnapshotService
	// Cancel is the service used to check and propagate cancel intent (required).
	Cancel *CancellationService
	// Heartbeat is the service used to renew attempt leases (required).
	Heartbeat *HeartbeatService
	// HeartbeatInterval is the interval between heartbeat ticks. Defaults to
	// 10 seconds if zero.
	HeartbeatInterval time.Duration
	// PRCreate is the service used to create pull requests (optional).
	// When nil, PR creation is skipped regardless of PREnabled.
	PRCreate *PRCreateService
	// PREnabled gates whether PR creation runs on successful execution.
	// PR creation only runs when PREnabled is true, PRCreate is non-nil,
	// and workflowKind is auto or review.
	PREnabled bool
	// PRCreatorFunc builds a PRCreator for a given sandbox and auth directory.
	// When nil, PR creation is skipped. Typically set to GitHubPRCreator.
	PRCreatorFunc func(sandboxID, authDir string) PRCreator
	// Reconciler is the service used to detect and close stale attempts (optional).
	// When nil, reconciliation ticks are skipped in RunLoop.
	Reconciler *ReconcilerService
	// Timeout is the service used to detect and fail overdue runs (optional).
	// When nil, timeout enforcement ticks are skipped in RunLoop.
	Timeout *TimeoutService
	// OnError is called for each operational error in the worker loop (optional).
	// When nil, errors are silently discarded.
	OnError ErrorFunc
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
	execution           *ExecutionService
	snapshot            *SnapshotService
	cancel              *CancellationService
	heartbeat           *HeartbeatService
	heartbeatInterval   time.Duration
	prCreate            *PRCreateService
	prEnabled           bool
	prCreatorFunc       func(sandboxID, authDir string) PRCreator
	reconciler          *ReconcilerService
	timeout             *TimeoutService
	onError             ErrorFunc
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
	if cfg.Execution == nil {
		return nil, fmt.Errorf("execution must not be nil")
	}
	if cfg.Snapshot == nil {
		return nil, fmt.Errorf("snapshot must not be nil")
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
		execution:           cfg.Execution,
		snapshot:            cfg.Snapshot,
		cancel:              cfg.Cancel,
		heartbeat:           cfg.Heartbeat,
		heartbeatInterval:   hbInterval,
		prCreate:            cfg.PRCreate,
		prEnabled:           cfg.PREnabled,
		prCreatorFunc:       cfg.PRCreatorFunc,
		reconciler:          cfg.Reconciler,
		timeout:             cfg.Timeout,
		onError:             cfg.OnError,
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
//
// Sandbox cleanup is guaranteed via a deferred destroySandboxBestEffort call
// that fires whenever provisioning succeeded, regardless of the exit path.
func (p *WorkerPipeline) executeAttempt(ctx context.Context, claim *ClaimResult) error {
	run := claim.Run
	attempt := claim.Attempt

	// Compute the deterministic working branch for this run.
	workingBranch := WorkingBranch(run.ID)

	// Track current run status for status-aware failure transitions.
	currentStatus := RunStatusClaimed

	// sandboxID is set after successful provisioning. The deferred cleanup
	// uses this value to destroy the sandbox on all exit paths.
	var sandboxID string
	defer func() {
		p.destroySandboxBestEffort(sandboxID)
	}()

	// Step 1: Transition run from claimed to running before any setup work.
	if err := p.store.TransitionRun(ctx, run.ID, RunStatusClaimed, RunStatusRunning); err != nil {
		p.handleSetupFailure(ctx, run.ID, attempt.ID, run.AuthProfileID, currentStatus, "transitioning run to running", err)
		return fmt.Errorf("transitioning run to running: %w", err)
	}
	currentStatus = RunStatusRunning

	// Start heartbeat loop after transitioning to running. The heartbeat
	// remains active through setup and execution until terminal routing
	// stops it.
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	hbResult, heartbeatDone := p.startHeartbeat(heartbeatCtx, attempt.ID, run.AuthProfileID, run.ID)
	defer func() {
		stopHeartbeat()
		<-heartbeatDone
	}()

	// Step 2: Provision -- create sandbox.
	provResult, err := p.provision.Provision(ctx, attempt.ID, run.ID)
	if err != nil {
		p.handleSetupFailure(ctx, run.ID, attempt.ID, run.AuthProfileID, currentStatus, "provision", err)
		return fmt.Errorf("provision failed: %w", err)
	}
	sandboxID = provResult.SandboxID

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
		p.handleSetupFailure(ctx, run.ID, attempt.ID, run.AuthProfileID, currentStatus, "bootstrap", err)
		return fmt.Errorf("bootstrap failed: %w", err)
	}

	// Step 4: Auth materialization -- write auth artifacts into sandbox.
	if err := p.authMaterialization.Materialize(ctx, &MaterializeRequest{
		AuthProfileID: run.AuthProfileID,
		SandboxID:     provResult.SandboxID,
		AttemptID:     attempt.ID,
		RunID:         run.ID,
	}); err != nil {
		p.handleSetupFailure(ctx, run.ID, attempt.ID, run.AuthProfileID, currentStatus, "auth materialization", err)
		return fmt.Errorf("auth materialization failed: %w", err)
	}

	// Step 5: Preflight -- validate provider-specific requirements.
	if err := p.preflight.Preflight(ctx, &PreflightRequest{
		AuthProfileID: run.AuthProfileID,
		SandboxID:     provResult.SandboxID,
		AttemptID:     attempt.ID,
		RunID:         run.ID,
	}); err != nil {
		p.handleSetupFailure(ctx, run.ID, attempt.ID, run.AuthProfileID, currentStatus, "preflight", err)
		return fmt.Errorf("preflight failed: %w", err)
	}

	// Step 6: Execute -- run Hal in the sandbox. The heartbeat continues
	// running throughout execution to keep the lease alive.
	execResult, err := p.execution.Execute(ctx, &ExecutionRequest{
		SandboxID:    provResult.SandboxID,
		AttemptID:    attempt.ID,
		RunID:        run.ID,
		WorkflowKind: run.WorkflowKind,
		Mode:         ExecutionModeUntilComplete,
	})

	// Stop heartbeat and check for async terminal signals before routing
	// the execution result.
	stopHeartbeat()
	<-heartbeatDone

	if hbResult.LeaseLost {
		p.handleLeaseLost(ctx, run.ID, run.AuthProfileID)
		return fmt.Errorf("lease lost during execution")
	}

	if hbResult.ProfileRevoked {
		p.handleProfileRevoked(ctx, run.ID)
		return fmt.Errorf("profile revoked during execution")
	}

	prCtx := &prContext{
		repo:          run.Repo,
		baseBranch:    run.BaseBranch,
		workingBranch: workingBranch,
		sandboxID:     provResult.SandboxID,
		authDir:       p.authMaterialization.AuthDir(),
	}

	if err != nil {
		// Runner API error -- treat as non-retryable failure.
		p.handleExecutionResult(ctx, run.ID, attempt.ID, run.AuthProfileID, run.WorkflowKind, -1, prCtx)
		return fmt.Errorf("execution failed: %w", err)
	}

	p.handleExecutionResult(ctx, run.ID, attempt.ID, run.AuthProfileID, run.WorkflowKind, execResult.ExitCode, prCtx)

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

// cleanupTimeout is the maximum duration allowed for terminal cleanup
// operations (transitions, lock release, sandbox teardown). Cleanup uses
// context.Background() so it can proceed even when the parent context is
// already canceled (e.g., during graceful shutdown).
const cleanupTimeout = 30 * time.Second

// handleLeaseLost handles the lease_lost terminal path. The HeartbeatService
// has already transitioned the attempt to failed (with error_code "lease_lost"),
// so this method must NOT emit a duplicate TransitionAttempt. It transitions
// the run to failed and releases the auth lock.
//
// Sandbox teardown is handled by the deferred destroySandboxBestEffort in
// executeAttempt, so this method does not need to destroy the sandbox.
//
// Cleanup uses context.Background() with a timeout so it can complete even
// when the parent context is already canceled (e.g., during graceful shutdown).
func (p *WorkerPipeline) handleLeaseLost(_ context.Context, runID, authProfileID string) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()

	// Transition run from running to failed. Best-effort -- the run may have
	// already been transitioned by a concurrent reconciler.
	_ = p.store.TransitionRun(ctx, runID, RunStatusRunning, RunStatusFailed)

	// Release auth lock -- tolerate ErrNotFound (lock may have expired or been released).
	_ = p.releaseAuthLockBestEffort(ctx, authProfileID, runID)
}

// handleProfileRevoked handles the profile_revoked terminal path. The
// HeartbeatService has already transitioned the attempt to failed (with
// error_code "profile_revoked") and released the auth lock, so this method
// must NOT emit a duplicate TransitionAttempt or release the auth lock.
// It transitions the run to failed.
//
// Sandbox teardown is handled by the deferred destroySandboxBestEffort in
// executeAttempt, so this method does not need to destroy the sandbox.
//
// Cleanup uses context.Background() with a timeout so it can complete even
// when the parent context is already canceled (e.g., during graceful shutdown).
func (p *WorkerPipeline) handleProfileRevoked(_ context.Context, runID string) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()

	// Transition run from running to failed. Best-effort -- the run may have
	// already been transitioned by a concurrent reconciler.
	_ = p.store.TransitionRun(ctx, runID, RunStatusRunning, RunStatusFailed)

	// Note: Auth lock is NOT released here because emitProfileRevokedAndTerminate
	// in HeartbeatService already released it.
}

// handleSetupFailure transitions both the run and attempt to failed status
// using the provided fromRunStatus. This ensures failure transitions use the
// correct source status regardless of how far setup progressed. After
// terminal transitions, the auth lock is released.
//
// Sandbox teardown is handled by the deferred destroySandboxBestEffort in
// executeAttempt, so this method does not need to destroy the sandbox.
//
// Cleanup uses context.Background() with a timeout so it can complete even
// when the parent context is already canceled (e.g., during graceful shutdown).
func (p *WorkerPipeline) handleSetupFailure(_ context.Context, runID, attemptID, authProfileID string, fromRunStatus RunStatus, stage string, cause error) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()

	now := time.Now().UTC()
	errCode := "setup_failure"
	errMsg := fmt.Sprintf("%s failed: %s", stage, cause.Error())

	// Transition attempt to failed.
	_ = p.store.TransitionAttempt(ctx, attemptID, AttemptStatusFailed, now, &errCode, &errMsg)

	// Transition run from its current status to failed.
	_ = p.store.TransitionRun(ctx, runID, fromRunStatus, RunStatusFailed)

	// Release auth lock -- tolerate ErrNotFound (lock may have expired or been released).
	_ = p.releaseAuthLockBestEffort(ctx, authProfileID, runID)
}

// prContext carries PR-related metadata from executeAttempt to
// handleExecutionResult so that maybeCreatePR can build the PR request.
type prContext struct {
	repo          string
	baseBranch    string
	workingBranch string
	sandboxID     string
	authDir       string
}

// handleExecutionResult maps an execution exit code to deterministic terminal
// transitions. Each outcome emits exactly one attempt transition and exactly
// one run transition:
//
//   - Exit code 0: attempt succeeded + run succeeded + final snapshot persisted + optional PR
//   - Non-zero exit: attempt failed (reason non_retryable) + run failed
//
// On success (exit code 0), finalization collects sandbox artifacts, compresses
// the bundle, computes a deterministic SHA via ComputeSandboxBundleHash, and
// persists the snapshot via SnapshotService before terminal transitions.
// PR creation is gated by workflow kind (auto/review only) and PREnabled.
//
// After terminal transitions, the auth lock is released. Sandbox teardown is
// handled by the deferred destroySandboxBestEffort in executeAttempt.
//
// Cleanup uses context.Background() with a timeout so it can complete even
// when the parent context is already canceled (e.g., during graceful shutdown).
func (p *WorkerPipeline) handleExecutionResult(_ context.Context, runID, attemptID, authProfileID string, workflowKind WorkflowKind, exitCode int, prc *prContext) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()

	now := time.Now().UTC()

	if exitCode == 0 {
		// Finalize: collect, compress, hash, and persist final snapshot.
		// The sandboxID is carried inside prContext for snapshot collection.
		if prc != nil {
			_ = p.finalizeSnapshot(ctx, runID, attemptID, prc.sandboxID, workflowKind)
		}

		// PR creation: only for auto/review workflows when enabled.
		_ = p.maybeCreatePR(ctx, runID, attemptID, workflowKind, prc)

		// Success: attempt succeeded, run succeeded.
		_ = p.store.TransitionAttempt(ctx, attemptID, AttemptStatusSucceeded, now, nil, nil)
		_ = p.store.TransitionRun(ctx, runID, RunStatusRunning, RunStatusSucceeded)
	} else {
		// Non-zero exit: attempt failed with reason non_retryable, run failed.
		errCode := string(FailureNonRetryable)
		errMsg := fmt.Sprintf("execution exited with code %d", exitCode)
		_ = p.store.TransitionAttempt(ctx, attemptID, AttemptStatusFailed, now, &errCode, &errMsg)
		_ = p.store.TransitionRun(ctx, runID, RunStatusRunning, RunStatusFailed)
	}

	// Release auth lock -- tolerate ErrNotFound (lock may have expired or been released).
	_ = p.releaseAuthLockBestEffort(ctx, authProfileID, runID)
}

// maybeCreatePR invokes PR creation when the workflow kind is auto or review
// and PREnabled is true. For workflowKind run, PR creation is always skipped.
// Returns nil when PR creation is skipped or when it succeeds. Errors from
// PR creation are best-effort and returned for logging but do not block
// terminal transitions.
func (p *WorkerPipeline) maybeCreatePR(ctx context.Context, runID, attemptID string, workflowKind WorkflowKind, prc *prContext) error {
	// Gate 1: PR creation must be enabled.
	if !p.prEnabled {
		return nil
	}

	// Gate 2: PRCreate service must be available.
	if p.prCreate == nil {
		return nil
	}

	// Gate 3: PRCreatorFunc must be available to build the creator.
	if p.prCreatorFunc == nil {
		return nil
	}

	// Gate 4: Only auto and review workflows create PRs.
	if workflowKind != WorkflowKindAuto && workflowKind != WorkflowKindReview {
		return nil
	}

	// Gate 5: PR context must be available.
	if prc == nil {
		return nil
	}

	creator := p.prCreatorFunc(prc.sandboxID, prc.authDir)

	_, err := p.prCreate.CreatePR(ctx, &PRCreateRequest{
		RunID:     runID,
		AttemptID: attemptID,
		Title:     fmt.Sprintf("hal: %s workflow for %s", workflowKind, prc.repo),
		Head:      prc.workingBranch,
		Base:      prc.baseBranch,
		Repo:      prc.repo,
	}, creator)
	if err != nil {
		return fmt.Errorf("creating PR: %w", err)
	}

	return nil
}

// finalizeSnapshot collects sandbox artifacts, compresses them into a bundle,
// computes a deterministic SHA via ComputeSandboxBundleHash(records), and
// persists the result via SnapshotService.StoreSnapshot. The persisted snapshot
// SHA equals ComputeBundleHash(records), not the hash of the compressed payload
// bytes. Errors are best-effort — finalization failures do not block terminal
// transitions.
func (p *WorkerPipeline) finalizeSnapshot(ctx context.Context, runID, attemptID, sandboxID string, workflowKind WorkflowKind) error {
	// Step 1: Collect sandbox files filtered by workflow artifact patterns.
	records, err := CollectSandboxBundle(ctx, p.runner, sandboxID, workflowKind)
	if err != nil {
		return fmt.Errorf("collecting sandbox bundle: %w", err)
	}
	if len(records) == 0 {
		return nil
	}

	// Step 2: Compress collected records into gzipped bundle.
	compressed, err := CompressBundle(records)
	if err != nil {
		return fmt.Errorf("compressing bundle: %w", err)
	}

	// Step 3: Compute deterministic SHA from records (not from compressed bytes).
	sha := ComputeSandboxBundleHash(records)

	// Step 4: Persist final snapshot via SnapshotService.
	_, err = p.snapshot.StoreSnapshot(ctx, &SnapshotRequest{
		RunID:           runID,
		AttemptID:       attemptID,
		Kind:            SnapshotKindFinal,
		Content:         compressed,
		SHA256:          sha,
		ContentEncoding: "application/gzip",
	})
	if err != nil {
		return fmt.Errorf("storing final snapshot: %w", err)
	}

	return nil
}

// destroySandboxBestEffort destroys a sandbox if the ID is non-empty. It uses
// a background context with timeout so it can complete even after the parent
// context is canceled (e.g., during graceful shutdown). Errors are ignored —
// the sandbox may have already been destroyed or may not exist.
func (p *WorkerPipeline) destroySandboxBestEffort(sandboxID string) {
	if sandboxID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	_ = p.runner.DestroySandbox(ctx, sandboxID)
}

// releaseAuthLockBestEffort releases the auth lock for a run, treating
// ErrNotFound as non-fatal (the lock may have already been released or
// expired). Non-ErrNotFound errors are returned with wrapped context.
func (p *WorkerPipeline) releaseAuthLockBestEffort(ctx context.Context, authProfileID, runID string) error {
	now := time.Now().UTC()
	err := p.store.ReleaseAuthLock(ctx, authProfileID, runID, now)
	if err != nil && !IsNotFound(err) {
		return fmt.Errorf("releasing auth lock for profile %s run %s: %w", authProfileID, runID, err)
	}
	return nil
}

// reportError invokes the configured OnError callback if non-nil.
func (p *WorkerPipeline) reportError(err error) {
	if p.onError != nil {
		p.onError(err)
	}
}

// RunLoopConfig holds the interval settings for the worker loop.
type RunLoopConfig struct {
	// PollInterval is the interval between ProcessOne claim polls.
	PollInterval time.Duration
	// ReconcileInterval is the interval between reconciliation sweeps.
	ReconcileInterval time.Duration
	// TimeoutInterval is the interval between timeout enforcement checks.
	TimeoutInterval time.Duration
}

// RunLoop runs the worker loop until ctx is canceled. On each poll tick it
// calls ProcessOne to claim and execute one eligible run. On each reconcile
// tick it calls the reconciler to close stale attempts. On each timeout tick
// it calls the timeout service to fail overdue runs.
//
// V1 behavior note: ProcessOne runs synchronously on the poll ticker goroutine,
// so a long-running ProcessOne call can delay subsequent poll and maintenance
// ticks. This is an accepted simplification for the initial implementation —
// future versions may process claims in a separate goroutine to decouple poll
// latency from execution duration.
func (p *WorkerPipeline) RunLoop(ctx context.Context, cfg RunLoopConfig) {
	pollTicker := time.NewTicker(cfg.PollInterval)
	defer pollTicker.Stop()

	reconcileTicker := time.NewTicker(cfg.ReconcileInterval)
	defer reconcileTicker.Stop()

	timeoutTicker := time.NewTicker(cfg.TimeoutInterval)
	defer timeoutTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pollTicker.C:
			if err := p.ProcessOne(ctx); err != nil && !IsNoWork(err) {
				p.reportError(fmt.Errorf("ProcessOne: %w", err))
			}
		case <-reconcileTicker.C:
			if p.reconciler != nil {
				if _, err := p.reconciler.Reconcile(ctx, time.Now().UTC()); err != nil {
					p.reportError(fmt.Errorf("Reconcile: %w", err))
				}
			}
		case <-timeoutTicker.C:
			if p.timeout != nil {
				if _, err := p.timeout.EnforceTimeouts(ctx, time.Now().UTC()); err != nil {
					p.reportError(fmt.Errorf("EnforceTimeouts: %w", err))
				}
			}
		}
	}
}
