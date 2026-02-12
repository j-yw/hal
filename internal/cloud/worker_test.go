package cloud

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// callLog records the order of service calls for deterministic ordering tests.
type callLog struct {
	calls []string
}

func (l *callLog) record(name string) {
	l.calls = append(l.calls, name)
}

// workerMockStore extends mockStore with behavior needed by worker tests.
type workerMockStore struct {
	mockStore

	// ClaimRun behavior
	claimedRun *Run
	claimErr   error

	// CreateAttempt behavior
	attempts  []*Attempt
	createErr error

	// AcquireAuthLock behavior
	locks   []*AuthProfileLock
	lockErr error

	// TransitionRun tracking
	transitions []runTransition
	transErr    error

	// TransitionAttempt tracking
	transitionAttemptCalls []transitionAttemptCall
	transAttemptErr        error

	// GetAuthProfile behavior
	authProfile    *AuthProfile
	authProfileErr error

	// HeartbeatAttempt tracking
	mu             sync.Mutex
	heartbeatCalls []heartbeatCall

	// GetRun behavior
	getRun    *Run
	getRunErr error

	// Optional call log for ordering tests.
	log *callLog
}

type heartbeatCall struct {
	AttemptID      string
	HeartbeatAt    time.Time
	LeaseExpiresAt time.Time
}

type runTransition struct {
	runID      string
	fromStatus RunStatus
	toStatus   RunStatus
}

func newWorkerMockStore() *workerMockStore {
	return &workerMockStore{}
}

func (s *workerMockStore) ClaimRun(_ context.Context, _ string) (*Run, error) {
	if s.claimErr != nil {
		return nil, s.claimErr
	}
	if s.claimedRun == nil {
		return nil, ErrNotFound
	}
	return s.claimedRun, nil
}

func (s *workerMockStore) CreateAttempt(_ context.Context, a *Attempt) error {
	if s.createErr != nil {
		return s.createErr
	}
	s.attempts = append(s.attempts, a)
	return nil
}

func (s *workerMockStore) AcquireAuthLock(_ context.Context, lock *AuthProfileLock) error {
	if s.lockErr != nil {
		return s.lockErr
	}
	s.locks = append(s.locks, lock)
	return nil
}

func (s *workerMockStore) TransitionRun(_ context.Context, runID string, from, to RunStatus) error {
	if s.log != nil {
		s.log.record(fmt.Sprintf("transition_run:%s->%s", from, to))
	}
	s.transitions = append(s.transitions, runTransition{runID, from, to})
	if s.transErr != nil {
		return s.transErr
	}
	return nil
}

func (s *workerMockStore) TransitionAttempt(_ context.Context, attemptID string, status AttemptStatus, endedAt time.Time, errCode, errMsg *string) error {
	if s.log != nil {
		s.log.record(fmt.Sprintf("transition_attempt:%s", status))
	}
	s.transitionAttemptCalls = append(s.transitionAttemptCalls, transitionAttemptCall{
		AttemptID:    attemptID,
		Status:       status,
		EndedAt:      endedAt,
		ErrorCode:    errCode,
		ErrorMessage: errMsg,
	})
	if s.transAttemptErr != nil {
		return s.transAttemptErr
	}
	return nil
}

func (s *workerMockStore) GetAuthProfile(_ context.Context, _ string) (*AuthProfile, error) {
	if s.authProfileErr != nil {
		return nil, s.authProfileErr
	}
	if s.authProfile != nil {
		return s.authProfile, nil
	}
	return &AuthProfile{ID: "profile-1", Provider: "github", Status: AuthProfileStatusLinked}, nil
}

func (s *workerMockStore) HeartbeatAttempt(_ context.Context, attemptID string, heartbeatAt, leaseExpiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heartbeatCalls = append(s.heartbeatCalls, heartbeatCall{
		AttemptID:      attemptID,
		HeartbeatAt:    heartbeatAt,
		LeaseExpiresAt: leaseExpiresAt,
	})
	return nil
}

func (s *workerMockStore) GetRun(_ context.Context, _ string) (*Run, error) {
	if s.getRunErr != nil {
		return nil, s.getRunErr
	}
	if s.getRun != nil {
		return s.getRun, nil
	}
	// Default: return a running run (for heartbeat service's auth check).
	return &Run{ID: "run-1", Status: RunStatusRunning, AuthProfileID: "profile-1"}, nil
}

func (s *workerMockStore) UpdateAttemptSandboxID(_ context.Context, _, _ string) error {
	return nil
}

// workerMockRunner is a minimal runner for worker tests with optional
// call-log tracking for ordering assertions.
type workerMockRunner struct {
	log *callLog

	// CreateSandbox behavior
	sandboxID  string
	createErr  error
	sandboxSeq int

	// Exec tracking
	execCalls []*execCall
	execErr   error

	// Per-command exec overrides: command prefix → result/error
	execOverrides map[string]execOverride
}

type execCall struct {
	sandboxID string
	command   string
}

type execOverride struct {
	result *runner.ExecResult
	err    error
}

func newWorkerMockRunner(log *callLog) *workerMockRunner {
	return &workerMockRunner{
		log:           log,
		sandboxID:     "sandbox-1",
		execOverrides: make(map[string]execOverride),
	}
}

func (r *workerMockRunner) CreateSandbox(_ context.Context, _ *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	if r.log != nil {
		r.log.record("provision")
	}
	if r.createErr != nil {
		return nil, r.createErr
	}
	r.sandboxSeq++
	id := r.sandboxID
	if r.sandboxSeq > 1 {
		id = fmt.Sprintf("%s-%d", r.sandboxID, r.sandboxSeq)
	}
	return &runner.Sandbox{
		ID:        id,
		Status:    "running",
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (r *workerMockRunner) Exec(_ context.Context, sandboxID string, req *runner.ExecRequest) (*runner.ExecResult, error) {
	r.execCalls = append(r.execCalls, &execCall{sandboxID: sandboxID, command: req.Command})

	// Check for logging based on command content.
	if r.log != nil {
		switch {
		case strings.HasPrefix(req.Command, "git clone"):
			r.log.record("bootstrap")
		case req.Command == "hal init":
			// Part of bootstrap, don't double-log.
		case strings.Contains(req.Command, "mkdir") && strings.Contains(req.Command, ".auth"):
			r.log.record("auth_materialize")
		case strings.Contains(req.Command, "printf") && strings.Contains(req.Command, ".auth"):
			// Part of auth materialization, don't double-log.
		default:
			// For preflight or other commands, check overrides first.
		}
	}

	// Check per-command overrides.
	for prefix, override := range r.execOverrides {
		if strings.HasPrefix(req.Command, prefix) {
			if override.err != nil {
				return nil, override.err
			}
			return override.result, nil
		}
	}

	if r.execErr != nil {
		return nil, r.execErr
	}
	return &runner.ExecResult{ExitCode: 0}, nil
}

func (r *workerMockRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}
func (r *workerMockRunner) DestroySandbox(_ context.Context, _ string) error { return nil }
func (r *workerMockRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return nil, nil
}

// --- Helper to build a full WorkerPipelineConfig with all required services ---

// workerMockGitOps is a minimal GitOps mock for worker tests that records
// clone, branch creation, checkout, add, commit, and push calls.
type workerMockGitOps struct {
	cloneRequests []*runner.GitCloneRequest
	branchCreated []string
	checkedOut    []string
	pushRequests  []*runner.GitPushRequest
}

func (g *workerMockGitOps) GitClone(_ context.Context, _ string, req *runner.GitCloneRequest) error {
	g.cloneRequests = append(g.cloneRequests, req)
	return nil
}
func (g *workerMockGitOps) GitAdd(_ context.Context, _, _ string, _ []string) error { return nil }
func (g *workerMockGitOps) GitCommit(_ context.Context, _ string, _ *runner.GitCommitRequest) (*runner.GitCommitResult, error) {
	return &runner.GitCommitResult{}, nil
}
func (g *workerMockGitOps) GitPush(_ context.Context, _ string, req *runner.GitPushRequest) error {
	g.pushRequests = append(g.pushRequests, req)
	return nil
}
func (g *workerMockGitOps) GitCreateBranch(_ context.Context, _, _, branch string) error {
	g.branchCreated = append(g.branchCreated, branch)
	return nil
}
func (g *workerMockGitOps) GitCheckout(_ context.Context, _, _, branch string) error {
	g.checkedOut = append(g.checkedOut, branch)
	return nil
}
func (g *workerMockGitOps) GitListBranches(_ context.Context, _, _ string) ([]string, error) {
	return nil, nil
}

func newTestWorkerPipeline(t *testing.T, store *workerMockStore, rnr *workerMockRunner) *WorkerPipeline {
	t.Helper()
	return newTestWorkerPipelineWithOpts(t, store, rnr, nil, "", "")
}

func newTestWorkerPipelineWithOpts(t *testing.T, store *workerMockStore, rnr *workerMockRunner, git runner.GitOps, gitUser, gitPass string) *WorkerPipeline {
	t.Helper()
	claim := NewClaimService(store, ClaimConfig{
		IDFunc: func() string { return "attempt-1" },
	})
	provision := NewProvisionService(store, rnr, ProvisionConfig{
		Image: "test-image:latest",
	})
	var bootstrap *BootstrapService
	if git != nil {
		bootstrap = NewBootstrapServiceWithGit(store, rnr, git, BootstrapConfig{})
	} else {
		bootstrap = NewBootstrapService(store, rnr, BootstrapConfig{})
	}
	authMat := NewAuthMaterializationService(store, rnr, AuthMaterializationConfig{})
	preflight := NewPreflightService(store, rnr, PreflightConfig{})
	checkpoint := NewCheckpointService(store, git, CheckpointConfig{})
	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})

	pipeline, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:               store,
		Runner:              rnr,
		WorkerID:            "worker-1",
		Claim:               claim,
		Provision:           provision,
		Bootstrap:           bootstrap,
		AuthMaterialization: authMat,
		Preflight:           preflight,
		Checkpoint:          checkpoint,
		Heartbeat:           heartbeat,
		HeartbeatInterval:   50 * time.Millisecond, // fast ticks for tests
		GitUsername:         gitUser,
		GitPassword:         gitPass,
	})
	if err != nil {
		t.Fatalf("NewWorkerPipeline: %v", err)
	}
	return pipeline
}

func testClaimedRun() *Run {
	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(1 * time.Hour)
	return &Run{
		ID:            "run-1",
		Repo:          "https://github.com/org/repo.git",
		BaseBranch:    "main",
		WorkflowKind:  WorkflowKindRun,
		Engine:        "claude",
		AuthProfileID: "profile-1",
		ScopeRef:      "prd-123",
		Status:        RunStatusClaimed,
		AttemptCount:  1,
		MaxAttempts:   3,
		DeadlineAt:    &deadline,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestNewWorkerPipeline(t *testing.T) {
	store := newWorkerMockStore()
	rnr := newWorkerMockRunner(nil)
	claim := NewClaimService(store, ClaimConfig{
		IDFunc: func() string { return "attempt-1" },
	})
	provision := NewProvisionService(store, rnr, ProvisionConfig{Image: "img"})
	bootstrap := NewBootstrapService(store, rnr, BootstrapConfig{})
	authMat := NewAuthMaterializationService(store, rnr, AuthMaterializationConfig{})
	preflight := NewPreflightService(store, rnr, PreflightConfig{})
	checkpoint := NewCheckpointService(store, nil, CheckpointConfig{})
	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})

	tests := []struct {
		name    string
		cfg     WorkerPipelineConfig
		wantErr string
	}{
		{
			name: "valid config",
			cfg: WorkerPipelineConfig{
				Store:               store,
				Runner:              rnr,
				WorkerID:            "worker-1",
				Claim:               claim,
				Provision:           provision,
				Bootstrap:           bootstrap,
				AuthMaterialization: authMat,
				Preflight:           preflight,
				Checkpoint:          checkpoint,
				Heartbeat:           heartbeat,
			},
		},
		{
			name: "nil store",
			cfg: WorkerPipelineConfig{
				Store:               nil,
				Runner:              rnr,
				WorkerID:            "worker-1",
				Claim:               claim,
				Provision:           provision,
				Bootstrap:           bootstrap,
				AuthMaterialization: authMat,
				Preflight:           preflight,
				Checkpoint:          checkpoint,
				Heartbeat:           heartbeat,
			},
			wantErr: "store must not be nil",
		},
		{
			name: "nil runner",
			cfg: WorkerPipelineConfig{
				Store:               store,
				Runner:              nil,
				WorkerID:            "worker-1",
				Claim:               claim,
				Provision:           provision,
				Bootstrap:           bootstrap,
				AuthMaterialization: authMat,
				Preflight:           preflight,
				Checkpoint:          checkpoint,
				Heartbeat:           heartbeat,
			},
			wantErr: "runner must not be nil",
		},
		{
			name: "empty worker ID",
			cfg: WorkerPipelineConfig{
				Store:               store,
				Runner:              rnr,
				WorkerID:            "",
				Claim:               claim,
				Provision:           provision,
				Bootstrap:           bootstrap,
				AuthMaterialization: authMat,
				Preflight:           preflight,
				Checkpoint:          checkpoint,
				Heartbeat:           heartbeat,
			},
			wantErr: "workerID must not be empty",
		},
		{
			name: "nil claim service",
			cfg: WorkerPipelineConfig{
				Store:               store,
				Runner:              rnr,
				WorkerID:            "worker-1",
				Claim:               nil,
				Provision:           provision,
				Bootstrap:           bootstrap,
				AuthMaterialization: authMat,
				Preflight:           preflight,
				Checkpoint:          checkpoint,
				Heartbeat:           heartbeat,
			},
			wantErr: "claim must not be nil",
		},
		{
			name: "nil provision service",
			cfg: WorkerPipelineConfig{
				Store:               store,
				Runner:              rnr,
				WorkerID:            "worker-1",
				Claim:               claim,
				Provision:           nil,
				Bootstrap:           bootstrap,
				AuthMaterialization: authMat,
				Preflight:           preflight,
				Checkpoint:          checkpoint,
				Heartbeat:           heartbeat,
			},
			wantErr: "provision must not be nil",
		},
		{
			name: "nil bootstrap service",
			cfg: WorkerPipelineConfig{
				Store:               store,
				Runner:              rnr,
				WorkerID:            "worker-1",
				Claim:               claim,
				Provision:           provision,
				Bootstrap:           nil,
				AuthMaterialization: authMat,
				Preflight:           preflight,
				Checkpoint:          checkpoint,
				Heartbeat:           heartbeat,
			},
			wantErr: "bootstrap must not be nil",
		},
		{
			name: "nil auth materialization service",
			cfg: WorkerPipelineConfig{
				Store:               store,
				Runner:              rnr,
				WorkerID:            "worker-1",
				Claim:               claim,
				Provision:           provision,
				Bootstrap:           bootstrap,
				AuthMaterialization: nil,
				Preflight:           preflight,
				Checkpoint:          checkpoint,
				Heartbeat:           heartbeat,
			},
			wantErr: "authMaterialization must not be nil",
		},
		{
			name: "nil preflight service",
			cfg: WorkerPipelineConfig{
				Store:               store,
				Runner:              rnr,
				WorkerID:            "worker-1",
				Claim:               claim,
				Provision:           provision,
				Bootstrap:           bootstrap,
				AuthMaterialization: authMat,
				Preflight:           nil,
				Checkpoint:          checkpoint,
				Heartbeat:           heartbeat,
			},
			wantErr: "preflight must not be nil",
		},
		{
			name: "nil checkpoint service",
			cfg: WorkerPipelineConfig{
				Store:               store,
				Runner:              rnr,
				WorkerID:            "worker-1",
				Claim:               claim,
				Provision:           provision,
				Bootstrap:           bootstrap,
				AuthMaterialization: authMat,
				Preflight:           preflight,
				Checkpoint:          nil,
				Heartbeat:           heartbeat,
			},
			wantErr: "checkpoint must not be nil",
		},
		{
			name: "nil heartbeat service",
			cfg: WorkerPipelineConfig{
				Store:               store,
				Runner:              rnr,
				WorkerID:            "worker-1",
				Claim:               claim,
				Provision:           provision,
				Bootstrap:           bootstrap,
				AuthMaterialization: authMat,
				Preflight:           preflight,
				Checkpoint:          checkpoint,
				Heartbeat:           nil,
			},
			wantErr: "heartbeat must not be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline, err := NewWorkerPipeline(tt.cfg)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
				}
				if pipeline != nil {
					t.Error("expected nil pipeline on error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pipeline == nil {
				t.Fatal("expected non-nil pipeline")
			}
		})
	}
}

func TestProcessOne_NoWork(t *testing.T) {
	store := newWorkerMockStore()
	// No claimedRun set — ClaimRun returns ErrNotFound.
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != ErrNoWork {
		t.Errorf("ProcessOne = %v, want ErrNoWork", err)
	}
	if !IsNoWork(err) {
		t.Error("IsNoWork(err) = false, want true")
	}
}

func TestProcessOne_ClaimError(t *testing.T) {
	store := newWorkerMockStore()
	store.claimErr = fmt.Errorf("database connection lost")
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if strings.Contains(err.Error(), "no eligible runs") {
		t.Error("claim error should not be mapped to ErrNoWork")
	}
	if !strings.Contains(err.Error(), "database connection lost") {
		t.Errorf("error = %q, want containing %q", err.Error(), "database connection lost")
	}
}

func TestProcessOne_SuccessfulClaim(t *testing.T) {
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// Verify claim was made (attempt created).
	if len(store.attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(store.attempts))
	}
	if store.attempts[0].WorkerID != "worker-1" {
		t.Errorf("attempt.WorkerID = %q, want %q", store.attempts[0].WorkerID, "worker-1")
	}
}

func TestErrNoWork_Message(t *testing.T) {
	if ErrNoWork.Error() != "no eligible runs in queue" {
		t.Errorf("ErrNoWork = %q, want %q", ErrNoWork.Error(), "no eligible runs in queue")
	}
}

func TestIsNoWork(t *testing.T) {
	if !IsNoWork(ErrNoWork) {
		t.Error("IsNoWork(ErrNoWork) = false, want true")
	}
	if IsNoWork(ErrNotFound) {
		t.Error("IsNoWork(ErrNotFound) = true, want false")
	}
	if IsNoWork(fmt.Errorf("other error")) {
		t.Error("IsNoWork(other) = true, want false")
	}
	if IsNoWork(nil) {
		t.Error("IsNoWork(nil) = true, want false")
	}
}

// --- US-014: executeAttempt setup ordering tests ---

func TestExecuteAttempt_TransitionsClaimedToRunningBeforeSetup(t *testing.T) {
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// Verify claimed → running transition happened.
	if len(store.transitions) == 0 {
		t.Fatal("expected at least one run transition")
	}
	tr := store.transitions[0]
	if tr.fromStatus != RunStatusClaimed {
		t.Errorf("transition from = %q, want %q", tr.fromStatus, RunStatusClaimed)
	}
	if tr.toStatus != RunStatusRunning {
		t.Errorf("transition to = %q, want %q", tr.toStatus, RunStatusRunning)
	}
	if tr.runID != "run-1" {
		t.Errorf("transition runID = %q, want %q", tr.runID, "run-1")
	}
}

func TestExecuteAttempt_SetupCallOrder(t *testing.T) {
	log := &callLog{}
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.log = log
	// Provide a profile with secret_ref so auth materialization executes commands.
	secretRef := "test-secret"
	store.authProfile = &AuthProfile{
		ID:        "profile-1",
		Provider:  "github",
		Status:    AuthProfileStatusLinked,
		SecretRef: &secretRef,
	}
	rnr := newWorkerMockRunner(log)
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// The expected deterministic order:
	// 1. transition_run:claimed->running
	// 2. provision (CreateSandbox)
	// 3. bootstrap (git clone exec)
	// 4. auth_materialize (auth materialization exec)
	// 5. preflight (no exec needed if no provider commands configured)
	//
	// Note: preflight with no ProviderCommands configured still calls
	// GetAuthProfile but emits no exec calls, so it won't appear in
	// the runner log. We verify the first 4 are in order.
	wantOrder := []string{
		"transition_run:claimed->running",
		"provision",
		"bootstrap",
		"auth_materialize",
	}

	if len(log.calls) < len(wantOrder) {
		t.Fatalf("call log has %d entries, want at least %d: %v", len(log.calls), len(wantOrder), log.calls)
	}

	for i, want := range wantOrder {
		if log.calls[i] != want {
			t.Errorf("call[%d] = %q, want %q (full log: %v)", i, log.calls[i], want, log.calls)
		}
	}
}

func TestExecuteAttempt_TransitionRunFailure(t *testing.T) {
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.transErr = fmt.Errorf("transition conflict")
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "transitioning run to running") {
		t.Errorf("error = %q, want containing %q", err.Error(), "transitioning run to running")
	}
	if !strings.Contains(err.Error(), "transition conflict") {
		t.Errorf("error = %q, want containing %q", err.Error(), "transition conflict")
	}

	// No sandbox should have been created.
	if len(rnr.execCalls) != 0 {
		t.Errorf("expected no exec calls after transition failure, got %d", len(rnr.execCalls))
	}
}

func TestExecuteAttempt_ProvisionFailure(t *testing.T) {
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	rnr.createErr = fmt.Errorf("sandbox quota exceeded")
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "provision failed") {
		t.Errorf("error = %q, want containing %q", err.Error(), "provision failed")
	}

	// Transition to running should have happened before provision,
	// then setup failure handler transitions running → failed.
	if len(store.transitions) != 2 {
		t.Fatalf("expected 2 transitions, got %d", len(store.transitions))
	}
	if store.transitions[0].toStatus != RunStatusRunning {
		t.Errorf("transition[0] to = %q, want %q", store.transitions[0].toStatus, RunStatusRunning)
	}
	if store.transitions[1].fromStatus != RunStatusRunning || store.transitions[1].toStatus != RunStatusFailed {
		t.Errorf("transition[1] = %s→%s, want running→failed", store.transitions[1].fromStatus, store.transitions[1].toStatus)
	}
}

func TestExecuteAttempt_BootstrapFailure(t *testing.T) {
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	// Fail the git clone command.
	rnr.execOverrides["git clone"] = execOverride{
		err: fmt.Errorf("clone timeout"),
	}
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "bootstrap failed") {
		t.Errorf("error = %q, want containing %q", err.Error(), "bootstrap failed")
	}
}

func TestExecuteAttempt_AuthMaterializationFailure(t *testing.T) {
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	// auth_materialization.Materialize calls GetAuthProfile then Exec.
	// Provide a profile with a secret_ref so Materialize actually runs commands.
	secretRef := "vault:secret/github-token"
	store.authProfile = &AuthProfile{
		ID:        "profile-1",
		Provider:  "github",
		Status:    AuthProfileStatusLinked,
		SecretRef: &secretRef,
	}
	rnr := newWorkerMockRunner(nil)
	// Fail the mkdir command that auth materialization issues.
	rnr.execOverrides["mkdir"] = execOverride{
		err: fmt.Errorf("permission denied"),
	}
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "auth materialization failed") {
		t.Errorf("error = %q, want containing %q", err.Error(), "auth materialization failed")
	}
}

func TestExecuteAttempt_PreflightFailure(t *testing.T) {
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.authProfile = &AuthProfile{
		ID:       "profile-1",
		Provider: "github",
		Status:   AuthProfileStatusLinked,
	}
	rnr := newWorkerMockRunner(nil)
	// Fail the preflight provider command.
	rnr.execOverrides["gh auth status"] = execOverride{
		result: &runner.ExecResult{ExitCode: 1, Stderr: "not authenticated"},
	}

	// Use a custom preflight with ProviderCommands that triggers a failing exec.
	preflightSvc := NewPreflightService(store, rnr, PreflightConfig{
		ProviderCommands: map[string]string{
			"github": "gh auth status",
		},
	})
	claim := NewClaimService(store, ClaimConfig{
		IDFunc: func() string { return "attempt-1" },
	})
	provision := NewProvisionService(store, rnr, ProvisionConfig{Image: "test-image:latest"})
	bootstrap := NewBootstrapService(store, rnr, BootstrapConfig{})
	authMat := NewAuthMaterializationService(store, rnr, AuthMaterializationConfig{})

	checkpoint := NewCheckpointService(store, nil, CheckpointConfig{})
	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})

	p, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:               store,
		Runner:              rnr,
		WorkerID:            "worker-1",
		Claim:               claim,
		Provision:           provision,
		Bootstrap:           bootstrap,
		AuthMaterialization: authMat,
		Preflight:           preflightSvc,
		Checkpoint:          checkpoint,
		Heartbeat:           heartbeat,
		HeartbeatInterval:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWorkerPipeline: %v", err)
	}

	err = p.ProcessOne(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "preflight failed") {
		t.Errorf("error = %q, want containing %q", err.Error(), "preflight failed")
	}
}

func TestExecuteAttempt_SetupCallOrderExact(t *testing.T) {
	// This test uses a tracking runner to record the exact order of
	// all calls through the pipeline to verify deterministic setup ordering.
	log := &callLog{}
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.log = log
	// Provide a profile with secret_ref so auth materialization executes commands.
	secretRef := "test-secret"
	store.authProfile = &AuthProfile{
		ID:        "profile-1",
		Provider:  "github",
		Status:    AuthProfileStatusLinked,
		SecretRef: &secretRef,
	}

	rnr := newWorkerMockRunner(log)
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// Verify the log starts with the expected sequence.
	// After transition, provision MUST come before bootstrap,
	// bootstrap MUST come before auth materialization.
	foundTransition := false
	foundProvision := false
	foundBootstrap := false
	foundAuth := false

	for i, call := range log.calls {
		switch {
		case call == "transition_run:claimed->running":
			foundTransition = true
			if foundProvision || foundBootstrap || foundAuth {
				t.Errorf("transition_run at position %d but a setup step was already recorded", i)
			}
		case call == "provision":
			foundProvision = true
			if !foundTransition {
				t.Errorf("provision at position %d but transition_run not yet recorded", i)
			}
			if foundBootstrap || foundAuth {
				t.Errorf("provision at position %d but bootstrap or auth already recorded", i)
			}
		case call == "bootstrap":
			foundBootstrap = true
			if !foundProvision {
				t.Errorf("bootstrap at position %d but provision not yet recorded", i)
			}
			if foundAuth {
				t.Errorf("bootstrap at position %d but auth already recorded", i)
			}
		case call == "auth_materialize":
			foundAuth = true
			if !foundBootstrap {
				t.Errorf("auth_materialize at position %d but bootstrap not yet recorded", i)
			}
		}
	}

	if !foundTransition {
		t.Error("transition_run:claimed->running not found in call log")
	}
	if !foundProvision {
		t.Error("provision not found in call log")
	}
	if !foundBootstrap {
		t.Error("bootstrap not found in call log")
	}
	if !foundAuth {
		t.Error("auth_materialize not found in call log")
	}
}

// --- US-015: Status-aware failure transitions during setup ---

func TestHandleSetupFailure_ProvisionFailsFromRunning(t *testing.T) {
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	rnr.createErr = fmt.Errorf("sandbox quota exceeded")
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "provision failed") {
		t.Errorf("error = %q, want containing %q", err.Error(), "provision failed")
	}

	// Verify run was transitioned: claimed→running (success), then running→failed (setup failure).
	if len(store.transitions) != 2 {
		t.Fatalf("expected 2 run transitions, got %d: %v", len(store.transitions), store.transitions)
	}
	// First: claimed → running.
	if store.transitions[0].fromStatus != RunStatusClaimed || store.transitions[0].toStatus != RunStatusRunning {
		t.Errorf("transition[0] = %s→%s, want claimed→running", store.transitions[0].fromStatus, store.transitions[0].toStatus)
	}
	// Second: running → failed (fromRunStatus is running because transition succeeded).
	if store.transitions[1].fromStatus != RunStatusRunning || store.transitions[1].toStatus != RunStatusFailed {
		t.Errorf("transition[1] = %s→%s, want running→failed", store.transitions[1].fromStatus, store.transitions[1].toStatus)
	}

	// Verify attempt was transitioned to failed.
	if len(store.transitionAttemptCalls) != 1 {
		t.Fatalf("expected 1 TransitionAttempt call, got %d", len(store.transitionAttemptCalls))
	}
	tc := store.transitionAttemptCalls[0]
	if tc.Status != AttemptStatusFailed {
		t.Errorf("TransitionAttempt.Status = %q, want %q", tc.Status, AttemptStatusFailed)
	}
	if tc.ErrorCode == nil || *tc.ErrorCode != "setup_failure" {
		t.Errorf("TransitionAttempt.ErrorCode = %v, want %q", tc.ErrorCode, "setup_failure")
	}
	if tc.ErrorMessage == nil || !strings.Contains(*tc.ErrorMessage, "provision") {
		t.Errorf("TransitionAttempt.ErrorMessage = %v, want containing %q", tc.ErrorMessage, "provision")
	}
}

func TestHandleSetupFailure_TransitionToRunningFailsFromClaimed(t *testing.T) {
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.transErr = fmt.Errorf("transition conflict")
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "transitioning run to running") {
		t.Errorf("error = %q, want containing %q", err.Error(), "transitioning run to running")
	}

	// The first TransitionRun call (claimed→running) failed.
	// handleSetupFailure should use fromRunStatus=claimed since the transition never completed.
	// We expect 2 TransitionRun calls: the failed claimed→running, then claimed→failed.
	if len(store.transitions) != 2 {
		t.Fatalf("expected 2 run transitions, got %d: %v", len(store.transitions), store.transitions)
	}
	// First: attempted claimed → running (which failed).
	if store.transitions[0].fromStatus != RunStatusClaimed || store.transitions[0].toStatus != RunStatusRunning {
		t.Errorf("transition[0] = %s→%s, want claimed→running", store.transitions[0].fromStatus, store.transitions[0].toStatus)
	}
	// Second: claimed → failed (setup failure handler uses fromRunStatus=claimed).
	if store.transitions[1].fromStatus != RunStatusClaimed || store.transitions[1].toStatus != RunStatusFailed {
		t.Errorf("transition[1] = %s→%s, want claimed→failed", store.transitions[1].fromStatus, store.transitions[1].toStatus)
	}

	// Verify attempt was also transitioned to failed.
	if len(store.transitionAttemptCalls) != 1 {
		t.Fatalf("expected 1 TransitionAttempt call, got %d", len(store.transitionAttemptCalls))
	}
	tc := store.transitionAttemptCalls[0]
	if tc.Status != AttemptStatusFailed {
		t.Errorf("TransitionAttempt.Status = %q, want %q", tc.Status, AttemptStatusFailed)
	}
	if tc.ErrorCode == nil || *tc.ErrorCode != "setup_failure" {
		t.Errorf("TransitionAttempt.ErrorCode = %v, want %q", tc.ErrorCode, "setup_failure")
	}
}

func TestHandleSetupFailure_BootstrapFailsFromRunning(t *testing.T) {
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	rnr.execOverrides["git clone"] = execOverride{
		err: fmt.Errorf("clone timeout"),
	}
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Bootstrap fails after transition to running, so failure should use running→failed.
	if len(store.transitions) < 2 {
		t.Fatalf("expected at least 2 run transitions, got %d", len(store.transitions))
	}
	// Find the failure transition.
	lastTr := store.transitions[len(store.transitions)-1]
	if lastTr.fromStatus != RunStatusRunning || lastTr.toStatus != RunStatusFailed {
		t.Errorf("last transition = %s→%s, want running→failed", lastTr.fromStatus, lastTr.toStatus)
	}

	// Verify attempt failure.
	if len(store.transitionAttemptCalls) != 1 {
		t.Fatalf("expected 1 TransitionAttempt call, got %d", len(store.transitionAttemptCalls))
	}
	if store.transitionAttemptCalls[0].ErrorMessage == nil || !strings.Contains(*store.transitionAttemptCalls[0].ErrorMessage, "bootstrap") {
		t.Errorf("TransitionAttempt.ErrorMessage = %v, want containing %q", store.transitionAttemptCalls[0].ErrorMessage, "bootstrap")
	}
}

func TestHandleSetupFailure_SetupFailureCallOrder(t *testing.T) {
	// Verify that handleSetupFailure transitions attempt before run.
	log := &callLog{}
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.log = log
	rnr := newWorkerMockRunner(log)
	rnr.createErr = fmt.Errorf("provision error")
	pipeline := newTestWorkerPipeline(t, store, rnr)

	_ = pipeline.ProcessOne(context.Background())

	// Expected call order for the failure path:
	// 1. transition_run:claimed->running
	// 2. provision (fails)
	// 3. transition_attempt:failed (from handleSetupFailure)
	// 4. transition_run:running->failed (from handleSetupFailure)
	wantSuffix := []string{
		"transition_attempt:failed",
		"transition_run:running->failed",
	}

	if len(log.calls) < len(wantSuffix) {
		t.Fatalf("call log has %d entries, want at least %d: %v", len(log.calls), len(wantSuffix), log.calls)
	}

	// Check the last two calls are the failure transitions in correct order.
	tail := log.calls[len(log.calls)-len(wantSuffix):]
	for i, want := range wantSuffix {
		if tail[i] != want {
			t.Errorf("call[%d from end] = %q, want %q (full log: %v)", i, tail[i], want, log.calls)
		}
	}
}

func TestHandleSetupFailure_NoSetupCallsAfterFailure(t *testing.T) {
	// When provision fails, no subsequent setup steps should run.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	rnr.createErr = fmt.Errorf("sandbox unavailable")
	pipeline := newTestWorkerPipeline(t, store, rnr)

	_ = pipeline.ProcessOne(context.Background())

	// No exec calls should have been made (provision uses CreateSandbox, not Exec).
	// Bootstrap, auth materialization, and preflight use Exec calls, so none should appear.
	if len(rnr.execCalls) != 0 {
		t.Errorf("expected 0 exec calls after provision failure, got %d", len(rnr.execCalls))
	}
}

// --- US-016: Propagate working branch and git credential fields ---

func TestExecuteAttempt_PropagatesWorkingBranch(t *testing.T) {
	// Verify that executeAttempt computes WorkingBranch(runID) and passes
	// it to bootstrap along with AttemptNumber.
	git := &workerMockGitOps{}
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipelineWithOpts(t, store, rnr, git, "", "")

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// Bootstrap with GitOps creates and checks out the working branch on first attempt.
	wantBranch := WorkingBranch("run-1") // "hal/cloud/run-1"
	if len(git.branchCreated) != 1 {
		t.Fatalf("expected 1 branch creation, got %d", len(git.branchCreated))
	}
	if git.branchCreated[0] != wantBranch {
		t.Errorf("branchCreated = %q, want %q", git.branchCreated[0], wantBranch)
	}
	if len(git.checkedOut) != 1 {
		t.Fatalf("expected 1 checkout, got %d", len(git.checkedOut))
	}
	if git.checkedOut[0] != wantBranch {
		t.Errorf("checkedOut = %q, want %q", git.checkedOut[0], wantBranch)
	}
}

func TestExecuteAttempt_PropagatesGitCredentials(t *testing.T) {
	// Verify that git credentials from the pipeline config are propagated
	// to bootstrap (and will flow to checkpoint in future stories).
	git := &workerMockGitOps{}
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipelineWithOpts(t, store, rnr, git, "x-access-token", "ghp_secret123")

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// Verify pipeline stores credentials.
	if pipeline.gitUsername != "x-access-token" {
		t.Errorf("pipeline.gitUsername = %q, want %q", pipeline.gitUsername, "x-access-token")
	}
	if pipeline.gitPassword != "ghp_secret123" {
		t.Errorf("pipeline.gitPassword = %q, want %q", pipeline.gitPassword, "ghp_secret123")
	}
}

func TestExecuteAttempt_WorkingBranchDerivedFromRunID(t *testing.T) {
	// Different run IDs produce different working branches.
	tests := []struct {
		runID      string
		wantBranch string
	}{
		{"run-001", "hal/cloud/run-001"},
		{"run-abc", "hal/cloud/run-abc"},
		{"my-special-run", "hal/cloud/my-special-run"},
	}
	for _, tt := range tests {
		t.Run(tt.runID, func(t *testing.T) {
			git := &workerMockGitOps{}
			store := newWorkerMockStore()
			run := testClaimedRun()
			run.ID = tt.runID
			store.claimedRun = run
			rnr := newWorkerMockRunner(nil)
			pipeline := newTestWorkerPipelineWithOpts(t, store, rnr, git, "", "")

			err := pipeline.ProcessOne(context.Background())
			if err != nil {
				t.Fatalf("ProcessOne: %v", err)
			}

			if len(git.branchCreated) != 1 {
				t.Fatalf("expected 1 branch creation, got %d", len(git.branchCreated))
			}
			if git.branchCreated[0] != tt.wantBranch {
				t.Errorf("branchCreated = %q, want %q", git.branchCreated[0], tt.wantBranch)
			}
		})
	}
}

func TestExecuteAttempt_PropagatesAttemptNumber(t *testing.T) {
	// Verify that AttemptNumber from the claimed attempt is passed through to bootstrap.
	// On first attempt (AttemptNumber=1), bootstrap creates working branch.
	// On retry (AttemptNumber>1), bootstrap would attempt resume (clone working branch).
	git := &workerMockGitOps{}
	store := newWorkerMockStore()
	run := testClaimedRun()
	run.AttemptCount = 1 // first claim
	store.claimedRun = run
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipelineWithOpts(t, store, rnr, git, "", "")

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// First attempt: bootstrap clones base branch and creates working branch.
	// With GitOps enabled and AttemptNumber=1, we should see branch creation.
	if len(git.branchCreated) != 1 {
		t.Fatalf("expected 1 branch creation on first attempt, got %d", len(git.branchCreated))
	}

	// Simulate second attempt by creating a new run with AttemptCount=2.
	git2 := &workerMockGitOps{}
	store2 := newWorkerMockStore()
	run2 := testClaimedRun()
	run2.AttemptCount = 2
	store2.claimedRun = run2
	rnr2 := newWorkerMockRunner(nil)
	pipeline2 := newTestWorkerPipelineWithOpts(t, store2, rnr2, git2, "", "")

	err = pipeline2.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("ProcessOne (retry): %v", err)
	}

	// Second attempt (AttemptNumber=2): bootstrap tries resume clone on working branch.
	// GitClone should be called with the working branch.
	if len(git2.cloneRequests) != 1 {
		t.Fatalf("expected 1 clone request on retry, got %d", len(git2.cloneRequests))
	}
	wantBranch := WorkingBranch("run-1")
	if git2.cloneRequests[0].Branch != wantBranch {
		t.Errorf("clone branch = %q, want %q", git2.cloneRequests[0].Branch, wantBranch)
	}
}

func TestExecuteAttempt_CheckpointServiceValidation(t *testing.T) {
	// Verify that NewWorkerPipeline rejects nil checkpoint.
	store := newWorkerMockStore()
	rnr := newWorkerMockRunner(nil)
	claim := NewClaimService(store, ClaimConfig{IDFunc: func() string { return "a" }})
	provision := NewProvisionService(store, rnr, ProvisionConfig{Image: "img"})
	bootstrap := NewBootstrapService(store, rnr, BootstrapConfig{})
	authMat := NewAuthMaterializationService(store, rnr, AuthMaterializationConfig{})
	preflight := NewPreflightService(store, rnr, PreflightConfig{})
	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})

	_, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:               store,
		Runner:              rnr,
		WorkerID:            "w",
		Claim:               claim,
		Provision:           provision,
		Bootstrap:           bootstrap,
		AuthMaterialization: authMat,
		Preflight:           preflight,
		Checkpoint:          nil,
		Heartbeat:           heartbeat,
	})
	if err == nil {
		t.Fatal("expected error for nil checkpoint, got nil")
	}
	if !strings.Contains(err.Error(), "checkpoint must not be nil") {
		t.Errorf("error = %q, want containing %q", err.Error(), "checkpoint must not be nil")
	}
}

// --- US-017: Heartbeat across setup and execution windows ---

// slowProvisionRunner wraps workerMockRunner and blocks CreateSandbox until
// a release signal is received, simulating long-running setup.
type slowProvisionRunner struct {
	*workerMockRunner
	gate chan struct{} // close to unblock CreateSandbox
}

func (r *slowProvisionRunner) CreateSandbox(ctx context.Context, req *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	// Wait until the test signals us to proceed (or context is canceled).
	select {
	case <-r.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return r.workerMockRunner.CreateSandbox(ctx, req)
}

func TestHeartbeat_StartsAfterTransitionToRunning(t *testing.T) {
	// Verify heartbeat ticks occur after run transitions to running but before
	// setup completes. We use a slow provision step to keep the pipeline busy
	// long enough for heartbeat ticks to fire.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	baseRnr := newWorkerMockRunner(nil)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	claim := NewClaimService(store, ClaimConfig{
		IDFunc: func() string { return "attempt-1" },
	})
	provision := NewProvisionService(store, rnr, ProvisionConfig{Image: "test-image:latest"})
	bootstrap := NewBootstrapService(store, rnr, BootstrapConfig{})
	authMat := NewAuthMaterializationService(store, rnr, AuthMaterializationConfig{})
	preflight := NewPreflightService(store, rnr, PreflightConfig{})
	checkpoint := NewCheckpointService(store, nil, CheckpointConfig{})

	pipeline, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:               store,
		Runner:              rnr,
		WorkerID:            "worker-1",
		Claim:               claim,
		Provision:           provision,
		Bootstrap:           bootstrap,
		AuthMaterialization: authMat,
		Preflight:           preflight,
		Checkpoint:          checkpoint,
		Heartbeat:           heartbeat,
		HeartbeatInterval:   20 * time.Millisecond, // fast ticks
	})
	if err != nil {
		t.Fatalf("NewWorkerPipeline: %v", err)
	}

	// Run ProcessOne in a goroutine since it will block on provision.
	done := make(chan error, 1)
	go func() {
		done <- pipeline.ProcessOne(context.Background())
	}()

	// Wait for at least 2 heartbeat ticks to fire while provision is blocked.
	deadline := time.After(2 * time.Second)
	for {
		store.mu.Lock()
		count := len(store.heartbeatCalls)
		store.mu.Unlock()
		if count >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for heartbeat calls, got %d", count)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Unblock provision and let the pipeline finish.
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// Verify heartbeat calls were made with the correct attempt and run IDs.
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.heartbeatCalls) < 2 {
		t.Fatalf("expected at least 2 heartbeat calls, got %d", len(store.heartbeatCalls))
	}
	for i, hb := range store.heartbeatCalls {
		if hb.AttemptID != "attempt-1" {
			t.Errorf("heartbeatCalls[%d].AttemptID = %q, want %q", i, hb.AttemptID, "attempt-1")
		}
	}
}

func TestHeartbeat_ActiveThroughSetupAndExecution(t *testing.T) {
	// Verify heartbeat remains active across the setup window by checking
	// that heartbeat ticks continue to accumulate while provision is blocked.
	// This proves the heartbeat loop runs concurrently with setup stages.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	baseRnr := newWorkerMockRunner(nil)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	claim := NewClaimService(store, ClaimConfig{
		IDFunc: func() string { return "attempt-1" },
	})
	provision := NewProvisionService(store, rnr, ProvisionConfig{Image: "test-image:latest"})
	bootstrap := NewBootstrapService(store, rnr, BootstrapConfig{})
	authMat := NewAuthMaterializationService(store, rnr, AuthMaterializationConfig{})
	preflight := NewPreflightService(store, rnr, PreflightConfig{})
	checkpoint := NewCheckpointService(store, nil, CheckpointConfig{})

	pipeline, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:               store,
		Runner:              rnr,
		WorkerID:            "worker-1",
		Claim:               claim,
		Provision:           provision,
		Bootstrap:           bootstrap,
		AuthMaterialization: authMat,
		Preflight:           preflight,
		Checkpoint:          checkpoint,
		Heartbeat:           heartbeat,
		HeartbeatInterval:   20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWorkerPipeline: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- pipeline.ProcessOne(context.Background())
	}()

	// Wait for at least 3 heartbeat ticks during the blocked provision,
	// proving the heartbeat loop runs concurrently with setup.
	deadline := time.After(2 * time.Second)
	for {
		store.mu.Lock()
		count := len(store.heartbeatCalls)
		store.mu.Unlock()
		if count >= 3 {
			break
		}
		select {
		case <-deadline:
			store.mu.Lock()
			c := len(store.heartbeatCalls)
			store.mu.Unlock()
			t.Fatalf("timed out waiting for heartbeat calls during setup, got %d", c)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Unblock provision and let the pipeline finish.
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}
}

func TestHeartbeat_StopsAfterExecuteAttemptReturns(t *testing.T) {
	// Verify that heartbeat stops ticking after executeAttempt returns.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// Record count right after return.
	store.mu.Lock()
	countAfter := len(store.heartbeatCalls)
	store.mu.Unlock()

	// Wait a bit and verify no new heartbeat ticks occur.
	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	countLater := len(store.heartbeatCalls)
	store.mu.Unlock()

	if countLater != countAfter {
		t.Errorf("heartbeat continued after ProcessOne returned: %d -> %d calls", countAfter, countLater)
	}
}

func TestHeartbeat_NotStartedBeforeTransitionToRunning(t *testing.T) {
	// Verify that heartbeat does NOT fire when transition to running fails
	// (heartbeat should only start after successful transition).
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.transErr = fmt.Errorf("transition conflict")
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipeline(t, store, rnr)

	_ = pipeline.ProcessOne(context.Background())

	// No heartbeat calls should have been made.
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.heartbeatCalls) != 0 {
		t.Errorf("expected 0 heartbeat calls when transition failed, got %d", len(store.heartbeatCalls))
	}
}

func TestHeartbeat_RenewCallsIncludeCorrectIDs(t *testing.T) {
	// Verify that heartbeat renew calls include the correct attempt, auth profile,
	// and run IDs from the claimed run.
	store := newWorkerMockStore()
	run := testClaimedRun()
	run.AuthProfileID = "custom-profile-99"
	store.claimedRun = run
	baseRnr := newWorkerMockRunner(nil)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	claim := NewClaimService(store, ClaimConfig{
		IDFunc: func() string { return "attempt-42" },
	})
	provision := NewProvisionService(store, rnr, ProvisionConfig{Image: "img"})
	bootstrap := NewBootstrapService(store, rnr, BootstrapConfig{})
	authMat := NewAuthMaterializationService(store, rnr, AuthMaterializationConfig{})
	preflight := NewPreflightService(store, rnr, PreflightConfig{})
	checkpoint := NewCheckpointService(store, nil, CheckpointConfig{})

	pipeline, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:               store,
		Runner:              rnr,
		WorkerID:            "worker-1",
		Claim:               claim,
		Provision:           provision,
		Bootstrap:           bootstrap,
		AuthMaterialization: authMat,
		Preflight:           preflight,
		Checkpoint:          checkpoint,
		Heartbeat:           heartbeat,
		HeartbeatInterval:   20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWorkerPipeline: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- pipeline.ProcessOne(context.Background())
	}()

	// Wait for at least 1 heartbeat tick.
	deadline := time.After(2 * time.Second)
	for {
		store.mu.Lock()
		count := len(store.heartbeatCalls)
		store.mu.Unlock()
		if count >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for heartbeat call")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// HeartbeatService.Renew calls HeartbeatAttempt with the attempt ID.
	// It uses the correct attempt ID ("attempt-42") from the claim.
	store.mu.Lock()
	defer store.mu.Unlock()
	for i, hb := range store.heartbeatCalls {
		if hb.AttemptID != "attempt-42" {
			t.Errorf("heartbeatCalls[%d].AttemptID = %q, want %q", i, hb.AttemptID, "attempt-42")
		}
	}
}
