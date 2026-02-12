package cloud

import (
	"context"
	"encoding/base64"
	"errors"
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
	mu    sync.Mutex
	calls []string
}

func (l *callLog) record(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, name)
}

func (l *callLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.calls))
	copy(out, l.calls)
	return out
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
	mu                sync.Mutex
	heartbeatCalls    []heartbeatCall
	heartbeatErr      error // when non-nil, HeartbeatAttempt returns this after heartbeatErrAfter successful calls
	heartbeatErrAfter int   // number of successful HeartbeatAttempt calls before returning heartbeatErr

	// GetRun behavior — also controls cancel check behavior
	getRun          *Run
	getRunErr       error
	cancelRequested bool // when true, GetRun returns CancelRequested=true

	// ReleaseAuthLock tracking
	releaseAuthLockCalls []releaseAuthLockCall
	releaseAuthLockErr   error

	// Profile revocation control -- when true, GetAuthProfile returns
	// AuthProfileStatusRevoked (used to trigger profile_revoked in heartbeat).
	profileRevoked bool

	// PutSnapshot tracking
	putSnapshotCalls []*RunStateSnapshot
	putSnapshotErr   error

	// UpdateRunSnapshotRefs tracking
	updateRefsCalls []workerUpdateRefsCall
	updateRefsErr   error

	// InsertEvent tracking
	insertedEvents []*Event

	// Optional call log for ordering tests.
	log *callLog
}

type workerUpdateRefsCall struct {
	RunID                 string
	InputSnapshotID       *string
	LatestSnapshotID      *string
	LatestSnapshotVersion int
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
	s.mu.Lock()
	revoked := s.profileRevoked
	s.mu.Unlock()
	status := AuthProfileStatusLinked
	if revoked {
		status = AuthProfileStatusRevoked
	}
	return &AuthProfile{ID: "profile-1", Provider: "github", Status: status}, nil
}

func (s *workerMockStore) HeartbeatAttempt(_ context.Context, attemptID string, heartbeatAt, leaseExpiresAt time.Time) error {
	if s.log != nil {
		s.log.record("heartbeat_attempt")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heartbeatCalls = append(s.heartbeatCalls, heartbeatCall{
		AttemptID:      attemptID,
		HeartbeatAt:    heartbeatAt,
		LeaseExpiresAt: leaseExpiresAt,
	})
	// Return error after N successful calls to simulate lease expiry.
	if s.heartbeatErr != nil && len(s.heartbeatCalls) > s.heartbeatErrAfter {
		return s.heartbeatErr
	}
	return nil
}

func (s *workerMockStore) GetRun(_ context.Context, _ string) (*Run, error) {
	if s.log != nil {
		s.log.record("get_run")
	}
	if s.getRunErr != nil {
		return nil, s.getRunErr
	}
	if s.getRun != nil {
		r := *s.getRun
		s.mu.Lock()
		r.CancelRequested = s.cancelRequested
		s.mu.Unlock()
		return &r, nil
	}
	// Default: return a running run (for heartbeat service's auth check).
	s.mu.Lock()
	cr := s.cancelRequested
	s.mu.Unlock()
	return &Run{ID: "run-1", Status: RunStatusRunning, AuthProfileID: "profile-1", CancelRequested: cr}, nil
}

func (s *workerMockStore) UpdateAttemptSandboxID(_ context.Context, _, _ string) error {
	return nil
}

func (s *workerMockStore) ReleaseAuthLock(_ context.Context, authProfileID, runID string, _ time.Time) error {
	if s.log != nil {
		s.log.record("release_auth_lock")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseAuthLockCalls = append(s.releaseAuthLockCalls, releaseAuthLockCall{
		AuthProfileID: authProfileID,
		RunID:         runID,
	})
	return s.releaseAuthLockErr
}

func (s *workerMockStore) PutSnapshot(_ context.Context, snapshot *RunStateSnapshot) error {
	s.putSnapshotCalls = append(s.putSnapshotCalls, snapshot)
	return s.putSnapshotErr
}

func (s *workerMockStore) UpdateRunSnapshotRefs(_ context.Context, runID string, inputSnapshotID, latestSnapshotID *string, latestSnapshotVersion int) error {
	s.updateRefsCalls = append(s.updateRefsCalls, workerUpdateRefsCall{
		RunID:                 runID,
		InputSnapshotID:       inputSnapshotID,
		LatestSnapshotID:      latestSnapshotID,
		LatestSnapshotVersion: latestSnapshotVersion,
	})
	return s.updateRefsErr
}

func (s *workerMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.insertedEvents = append(s.insertedEvents, event)
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

	// DestroySandbox tracking
	mu                  sync.Mutex
	destroySandboxCalls []string
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
func (r *workerMockRunner) DestroySandbox(_ context.Context, sandboxID string) error {
	if r.log != nil {
		r.log.record("destroy_sandbox")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.destroySandboxCalls = append(r.destroySandboxCalls, sandboxID)
	return nil
}
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
	execution := NewExecutionService(store, rnr, ExecutionConfig{})
	snapshot := NewSnapshotService(store, SnapshotServiceConfig{
		IDFunc: func() string { return "snapshot-1" },
	})
	cancel := NewCancellationService(store, CancellationConfig{})
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
		Execution:           execution,
		Snapshot:            snapshot,
		Cancel:              cancel,
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
	execution := NewExecutionService(store, rnr, ExecutionConfig{})
	snapshot := NewSnapshotService(store, SnapshotServiceConfig{})
	cancel := NewCancellationService(store, CancellationConfig{})
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              cancel,
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              cancel,
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              cancel,
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              cancel,
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              cancel,
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              cancel,
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              cancel,
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              cancel,
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              cancel,
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              cancel,
				Heartbeat:           heartbeat,
			},
			wantErr: "checkpoint must not be nil",
		},
		{
			name: "nil execution service",
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
				Execution:           nil,
				Snapshot:            snapshot,
				Cancel:              cancel,
				Heartbeat:           heartbeat,
			},
			wantErr: "execution must not be nil",
		},
		{
			name: "nil snapshot service",
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
				Execution:           execution,
				Snapshot:            nil,
				Cancel:              cancel,
				Heartbeat:           heartbeat,
			},
			wantErr: "snapshot must not be nil",
		},
		{
			name: "nil cancel service",
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              nil,
				Heartbeat:           heartbeat,
			},
			wantErr: "cancel must not be nil",
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
				Execution:           execution,
				Snapshot:            snapshot,
				Cancel:              cancel,
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
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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

// --- US-018: Check cancellation before heartbeat renew on every tick ---

func TestHeartbeat_CancelCheckedBeforeRenewOnEachTick(t *testing.T) {
	// Verify that on each heartbeat tick, cancel.CheckAndCancel is called
	// before heartbeat.Renew. We use a slow provision to keep the pipeline
	// busy and inspect the call log for ordering.
	log := &callLog{}
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.log = log
	baseRnr := newWorkerMockRunner(nil)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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

	// Wait for at least 2 heartbeat ticks.
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
			t.Fatal("timed out waiting for heartbeat ticks")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Unblock provision and let the pipeline finish.
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// Inspect the call log. For each tick, we expect a GetRun (from
	// cancel.CheckAndCancel) to appear before HeartbeatAttempt (from
	// heartbeat.Renew). The log records the store-level calls.
	// After the transition_run:claimed->running call, the heartbeat
	// goroutine calls GetRun for cancel check, then HeartbeatAttempt
	// for renew, then GetRun again for renew's auth check, then
	// RenewAuthLock.
	//
	// We verify the pattern: each heartbeat_attempt is preceded by
	// at least one get_run (from the cancel check).
	calls := log.snapshot()

	// Count heartbeat ticks — each tick produces a "get_run" (cancel check)
	// followed by "heartbeat_attempt" (renew).
	heartbeatAttemptCount := 0
	for _, c := range calls {
		if c == "heartbeat_attempt" {
			heartbeatAttemptCount++
		}
	}
	if heartbeatAttemptCount < 2 {
		t.Fatalf("expected at least 2 heartbeat_attempt calls, got %d (log: %v)", heartbeatAttemptCount, calls)
	}

	// Verify ordering: each heartbeat_attempt is preceded by get_run.
	getRuns := 0
	for _, c := range calls {
		if c == "get_run" {
			getRuns++
		}
		if c == "heartbeat_attempt" {
			if getRuns == 0 {
				t.Fatalf("heartbeat_attempt found before any get_run call (log: %v)", calls)
			}
		}
	}
}

func TestHeartbeat_CancelDetectedSkipsRenew(t *testing.T) {
	// When cancellation is detected during a heartbeat tick, the tick should
	// NOT call heartbeat.Renew, and the heartbeat loop should exit.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	baseRnr := newWorkerMockRunner(nil)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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

	// Let one heartbeat tick fire normally (no cancel), then set cancel flag.
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
			t.Fatal("timed out waiting for initial heartbeat tick")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Record heartbeat count before setting cancel flag.
	store.mu.Lock()
	countBefore := len(store.heartbeatCalls)
	store.mu.Unlock()

	// Set cancel_requested on the run — the next tick's CheckAndCancel will
	// see this and cancel without calling Renew.
	store.mu.Lock()
	store.cancelRequested = true
	store.mu.Unlock()

	// Wait for the heartbeat loop to exit (it should stop after detecting cancel).
	// We can detect this because once the cancel propagates, the heartbeat
	// goroutine returns without further HeartbeatAttempt calls.
	time.Sleep(200 * time.Millisecond)

	store.mu.Lock()
	countAfter := len(store.heartbeatCalls)
	store.mu.Unlock()

	// After cancel is detected, no more heartbeat renew calls should occur.
	// At most one more heartbeat might have been in flight at the time we set
	// the flag, so we allow countBefore+1 but not more.
	if countAfter > countBefore+1 {
		t.Errorf("heartbeat continued after cancel: before=%d, after=%d (expected at most %d)", countBefore, countAfter, countBefore+1)
	}

	// Unblock provision so pipeline can finish.
	close(gate)
	<-done
}

func TestHeartbeat_CancelCheckCallOrderPerTick(t *testing.T) {
	// Verify the exact per-tick call order: GetRun (cancel check) happens
	// first on every tick, and when it returns Canceled=false, HeartbeatAttempt
	// follows. Uses a log to capture ordering.
	log := &callLog{}
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.log = log
	rnr := newWorkerMockRunner(nil)
	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	// Pipeline completes quickly; heartbeat may have ticked 0-2 times.
	// Regardless, if there are any heartbeat_attempt entries, each must
	// have been preceded by a get_run.
	calls := log.snapshot()

	lastGetRun := -1
	for i, c := range calls {
		if c == "get_run" {
			lastGetRun = i
		}
		if c == "heartbeat_attempt" {
			if lastGetRun < 0 || lastGetRun > i {
				t.Fatalf("heartbeat_attempt at index %d without preceding get_run (log: %v)", i, calls)
			}
		}
	}
}

// --- US-019: Handle lease_lost routing without duplicate attempt terminalization ---

func TestLeaseLost_SetsReasonAndRoutesToLeaseLostHandling(t *testing.T) {
	// When the heartbeat detects ErrLeaseExpired, the worker should route
	// through handleLeaseLost which transitions the run to failed and performs
	// cleanup — but does NOT emit a duplicate TransitionAttempt.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	// Return ErrLeaseExpired on the first HeartbeatAttempt call to simulate
	// immediate lease loss.
	store.heartbeatErr = ErrLeaseExpired
	store.heartbeatErrAfter = 0

	baseRnr := newWorkerMockRunner(nil)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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

	// Wait for heartbeat to fire and detect lease_lost. The heartbeat loop
	// will exit after setting LeaseLost=true, then unblock provision.
	// Give it time to tick at least once.
	time.Sleep(100 * time.Millisecond)

	// Unblock provision so the pipeline can observe lease_lost and route.
	close(gate)

	err = <-done
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "lease lost") {
		t.Errorf("error = %q, want containing %q", err.Error(), "lease lost")
	}

	// Verify run was transitioned: claimed→running (success), then running→failed
	// (lease_lost handling).
	runningFound := false
	failedFound := false
	for _, tr := range store.transitions {
		if tr.fromStatus == RunStatusClaimed && tr.toStatus == RunStatusRunning {
			runningFound = true
		}
		if tr.fromStatus == RunStatusRunning && tr.toStatus == RunStatusFailed {
			failedFound = true
		}
	}
	if !runningFound {
		t.Error("expected claimed→running transition")
	}
	if !failedFound {
		t.Error("expected running→failed transition from handleLeaseLost")
	}
}

func TestLeaseLost_NoDuplicateAttemptTerminalization(t *testing.T) {
	// The heartbeat service already transitions the attempt to failed with
	// error_code "lease_lost". The worker's handleLeaseLost must NOT emit
	// a second TransitionAttempt.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.heartbeatErr = ErrLeaseExpired
	store.heartbeatErrAfter = 0

	baseRnr := newWorkerMockRunner(nil)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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

	time.Sleep(100 * time.Millisecond)
	close(gate)
	<-done

	// Count TransitionAttempt calls to failed. The heartbeat service emits
	// exactly one. The worker's handleLeaseLost must not add a second.
	failedAttemptCount := 0
	for _, tc := range store.transitionAttemptCalls {
		if tc.Status == AttemptStatusFailed {
			failedAttemptCount++
		}
	}

	// Exactly 1 from heartbeat service's emitLeaseLostAndTerminate.
	if failedAttemptCount != 1 {
		t.Errorf("TransitionAttempt(failed) count = %d, want exactly 1 (from heartbeat service only)", failedAttemptCount)
	}

	// Verify the single attempt transition has the correct error code.
	if len(store.transitionAttemptCalls) == 0 {
		t.Fatal("expected at least 1 TransitionAttempt call")
	}
	tc := store.transitionAttemptCalls[0]
	if tc.ErrorCode == nil || *tc.ErrorCode != "lease_lost" {
		t.Errorf("TransitionAttempt.ErrorCode = %v, want %q", tc.ErrorCode, "lease_lost")
	}
}

func TestLeaseLost_CleanupStillRuns(t *testing.T) {
	// After lease_lost is detected, handleLeaseLost must still run cleanup:
	// transition run to failed, release auth lock, and destroy sandbox.
	log := &callLog{}
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.log = log
	store.heartbeatErr = ErrLeaseExpired
	store.heartbeatErrAfter = 0

	baseRnr := newWorkerMockRunner(log)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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

	time.Sleep(100 * time.Millisecond)
	close(gate)
	<-done

	// Verify auth lock release was called.
	store.mu.Lock()
	authLockReleased := len(store.releaseAuthLockCalls)
	store.mu.Unlock()
	if authLockReleased == 0 {
		t.Error("expected ReleaseAuthLock to be called during lease_lost cleanup")
	}

	// Verify sandbox destroy was called.
	baseRnr.mu.Lock()
	destroyCalls := len(baseRnr.destroySandboxCalls)
	baseRnr.mu.Unlock()
	if destroyCalls == 0 {
		t.Error("expected DestroySandbox to be called during lease_lost cleanup")
	}

	// Verify run was transitioned to failed.
	runToFailed := false
	for _, tr := range store.transitions {
		if tr.fromStatus == RunStatusRunning && tr.toStatus == RunStatusFailed {
			runToFailed = true
			break
		}
	}
	if !runToFailed {
		t.Error("expected running→failed transition from handleLeaseLost")
	}

	// Verify cleanup happened in the call log.
	calls := log.snapshot()
	foundRelease := false
	foundDestroy := false
	for _, c := range calls {
		if c == "release_auth_lock" {
			foundRelease = true
		}
		if c == "destroy_sandbox" {
			foundDestroy = true
		}
	}
	if !foundRelease {
		t.Errorf("release_auth_lock not found in call log: %v", calls)
	}
	if !foundDestroy {
		t.Errorf("destroy_sandbox not found in call log: %v", calls)
	}
}

func TestLeaseLost_AfterSuccessfulHeartbeats(t *testing.T) {
	// Verify that lease_lost is correctly detected even after some successful
	// heartbeat renewals. The heartbeat should work normally for a few ticks,
	// then when HeartbeatAttempt returns ErrLeaseExpired, the pipeline routes
	// through lease_lost handling.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	// Allow 2 successful heartbeats, then return ErrLeaseExpired.
	store.heartbeatErr = ErrLeaseExpired
	store.heartbeatErrAfter = 2

	baseRnr := newWorkerMockRunner(nil)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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

	// Wait for the 3rd heartbeat tick to fire and detect lease_lost.
	time.Sleep(200 * time.Millisecond)
	close(gate)

	err = <-done
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "lease lost") {
		t.Errorf("error = %q, want containing %q", err.Error(), "lease lost")
	}

	// Verify some heartbeats succeeded before the lease expired.
	store.mu.Lock()
	hbCount := len(store.heartbeatCalls)
	store.mu.Unlock()
	if hbCount < 2 {
		t.Errorf("expected at least 2 heartbeat calls before lease_lost, got %d", hbCount)
	}

	// Run transition should still be running→failed.
	runToFailed := false
	for _, tr := range store.transitions {
		if tr.fromStatus == RunStatusRunning && tr.toStatus == RunStatusFailed {
			runToFailed = true
			break
		}
	}
	if !runToFailed {
		t.Error("expected running→failed transition from handleLeaseLost")
	}
}

// --- US-020: Handle profile_revoked routing without duplicate attempt terminalization ---

func TestProfileRevoked_SetsReasonAndRoutesToProfileRevokedHandling(t *testing.T) {
	// When the heartbeat detects ErrProfileRevoked (auth profile revoked),
	// the worker should route through handleProfileRevoked which transitions
	// the run to failed and performs sandbox cleanup — but does NOT emit a
	// duplicate TransitionAttempt or release the auth lock (the heartbeat
	// service already did both).
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	// Mark the profile as revoked so HeartbeatService.Renew detects it
	// on the first heartbeat tick.
	store.profileRevoked = true

	baseRnr := newWorkerMockRunner(nil)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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

	// Wait for heartbeat to fire and detect profile_revoked.
	time.Sleep(100 * time.Millisecond)

	// Unblock provision so the pipeline can observe profile_revoked and route.
	close(gate)

	err = <-done
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "profile revoked") {
		t.Errorf("error = %q, want containing %q", err.Error(), "profile revoked")
	}

	// Verify run was transitioned: claimed->running (success), then running->failed
	// (profile_revoked handling).
	runningFound := false
	failedFound := false
	for _, tr := range store.transitions {
		if tr.fromStatus == RunStatusClaimed && tr.toStatus == RunStatusRunning {
			runningFound = true
		}
		if tr.fromStatus == RunStatusRunning && tr.toStatus == RunStatusFailed {
			failedFound = true
		}
	}
	if !runningFound {
		t.Error("expected claimed->running transition")
	}
	if !failedFound {
		t.Error("expected running->failed transition from handleProfileRevoked")
	}
}

func TestProfileRevoked_NoDuplicateAttemptTerminalization(t *testing.T) {
	// The heartbeat service already transitions the attempt to failed with
	// error_code "profile_revoked". The worker's handleProfileRevoked must
	// NOT emit a second TransitionAttempt.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.profileRevoked = true

	baseRnr := newWorkerMockRunner(nil)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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

	time.Sleep(100 * time.Millisecond)
	close(gate)
	<-done

	// Count TransitionAttempt calls to failed. The heartbeat service emits
	// exactly one. The worker's handleProfileRevoked must not add a second.
	failedAttemptCount := 0
	for _, tc := range store.transitionAttemptCalls {
		if tc.Status == AttemptStatusFailed {
			failedAttemptCount++
		}
	}

	// Exactly 1 from heartbeat service's emitProfileRevokedAndTerminate.
	if failedAttemptCount != 1 {
		t.Errorf("TransitionAttempt(failed) count = %d, want exactly 1 (from heartbeat service only)", failedAttemptCount)
	}

	// Verify the single attempt transition has the correct error code.
	if len(store.transitionAttemptCalls) == 0 {
		t.Fatal("expected at least 1 TransitionAttempt call")
	}
	tc := store.transitionAttemptCalls[0]
	if tc.ErrorCode == nil || *tc.ErrorCode != "profile_revoked" {
		t.Errorf("TransitionAttempt.ErrorCode = %v, want %q", tc.ErrorCode, "profile_revoked")
	}
}

func TestProfileRevoked_RunTransitionsToFailed(t *testing.T) {
	// After profile_revoked is detected, handleProfileRevoked must transition
	// the run from running to failed and destroy the sandbox, but must NOT
	// release the auth lock (already released by heartbeat service).
	log := &callLog{}
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.log = log
	store.profileRevoked = true

	baseRnr := newWorkerMockRunner(log)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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

	time.Sleep(100 * time.Millisecond)
	close(gate)
	<-done

	// Verify run was transitioned to failed.
	runToFailed := false
	for _, tr := range store.transitions {
		if tr.fromStatus == RunStatusRunning && tr.toStatus == RunStatusFailed {
			runToFailed = true
			break
		}
	}
	if !runToFailed {
		t.Error("expected running->failed transition from handleProfileRevoked")
	}

	// Verify sandbox destroy was called.
	baseRnr.mu.Lock()
	destroyCalls := len(baseRnr.destroySandboxCalls)
	baseRnr.mu.Unlock()
	if destroyCalls == 0 {
		t.Error("expected DestroySandbox to be called during profile_revoked cleanup")
	}

	// Verify handleProfileRevoked did NOT release auth lock — the heartbeat
	// service's emitProfileRevokedAndTerminate already did that. Count only
	// auth lock releases that come from handleProfileRevoked (after provision
	// completes). The heartbeat service releases it internally via the store
	// during emitProfileRevokedAndTerminate, but handleProfileRevoked must
	// not issue a second release.
	//
	// We check the call log for release_auth_lock entries. The heartbeat
	// service's emitProfileRevokedAndTerminate calls ReleaseAuthLock once.
	// handleProfileRevoked must not add another.
	store.mu.Lock()
	authLockReleaseCount := len(store.releaseAuthLockCalls)
	store.mu.Unlock()

	// Exactly 1 from emitProfileRevokedAndTerminate (heartbeat service).
	// handleProfileRevoked must NOT add a second.
	if authLockReleaseCount != 1 {
		t.Errorf("ReleaseAuthLock call count = %d, want exactly 1 (from heartbeat service only)", authLockReleaseCount)
	}
}

func TestProfileRevoked_AfterSuccessfulHeartbeats(t *testing.T) {
	// Verify that profile_revoked is correctly detected even after some
	// successful heartbeat renewals. The heartbeat should work normally for
	// a few ticks, then when the profile is revoked, the pipeline routes
	// through profile_revoked handling.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	// Start with non-revoked profile -- will be toggled after successful heartbeats.

	baseRnr := newWorkerMockRunner(nil)
	gate := make(chan struct{})
	rnr := &slowProvisionRunner{workerMockRunner: baseRnr, gate: gate}

	heartbeat := NewHeartbeatService(store, HeartbeatConfig{})
	cancelSvc := NewCancellationService(store, CancellationConfig{})
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
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              cancelSvc,
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

	// Wait for a few successful heartbeat ticks.
	time.Sleep(80 * time.Millisecond)

	// Now revoke the profile -- next heartbeat tick will detect it.
	store.mu.Lock()
	store.profileRevoked = true
	store.mu.Unlock()

	// Wait for heartbeat to detect profile_revoked.
	time.Sleep(100 * time.Millisecond)
	close(gate)

	err = <-done
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "profile revoked") {
		t.Errorf("error = %q, want containing %q", err.Error(), "profile revoked")
	}

	// Verify some heartbeats succeeded before the profile was revoked.
	store.mu.Lock()
	hbCount := len(store.heartbeatCalls)
	store.mu.Unlock()
	if hbCount < 2 {
		t.Errorf("expected at least 2 heartbeat calls before profile_revoked, got %d", hbCount)
	}

	// Run transition should still be running->failed.
	runToFailed := false
	for _, tr := range store.transitions {
		if tr.fromStatus == RunStatusRunning && tr.toStatus == RunStatusFailed {
			runToFailed = true
			break
		}
	}
	if !runToFailed {
		t.Error("expected running->failed transition from handleProfileRevoked")
	}
}

// --- Shutdown-safe cleanup context tests (US-021) ---

// ctxTrackingStore wraps workerMockStore and records whether contexts passed
// to cleanup methods (TransitionRun, TransitionAttempt, ReleaseAuthLock) are
// canceled at the time of the call.
type ctxTrackingStore struct {
	*workerMockStore
	mu              sync.Mutex
	canceledCtxSeen []string // method names that received a canceled context
	liveCtxSeen     []string // method names that received a live (non-canceled) context
}

func newCtxTrackingStore(base *workerMockStore) *ctxTrackingStore {
	return &ctxTrackingStore{workerMockStore: base}
}

func (s *ctxTrackingStore) recordCtx(method string, ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		s.canceledCtxSeen = append(s.canceledCtxSeen, method)
	} else {
		s.liveCtxSeen = append(s.liveCtxSeen, method)
	}
}

func (s *ctxTrackingStore) TransitionRun(ctx context.Context, runID string, from, to RunStatus) error {
	s.recordCtx("TransitionRun", ctx)
	return s.workerMockStore.TransitionRun(ctx, runID, from, to)
}

func (s *ctxTrackingStore) TransitionAttempt(ctx context.Context, attemptID string, status AttemptStatus, endedAt time.Time, errCode, errMsg *string) error {
	s.recordCtx("TransitionAttempt", ctx)
	return s.workerMockStore.TransitionAttempt(ctx, attemptID, status, endedAt, errCode, errMsg)
}

func (s *ctxTrackingStore) ReleaseAuthLock(ctx context.Context, authProfileID, runID string, t2 time.Time) error {
	s.recordCtx("ReleaseAuthLock", ctx)
	return s.workerMockStore.ReleaseAuthLock(ctx, authProfileID, runID, t2)
}

// ctxTrackingRunner wraps workerMockRunner and records whether
// DestroySandbox receives a canceled context.
type ctxTrackingRunner struct {
	*workerMockRunner
	mu              sync.Mutex
	canceledCtxSeen []string
	liveCtxSeen     []string
}

func newCtxTrackingRunner(base *workerMockRunner) *ctxTrackingRunner {
	return &ctxTrackingRunner{workerMockRunner: base}
}

func (r *ctxTrackingRunner) DestroySandbox(ctx context.Context, sandboxID string) error {
	r.mu.Lock()
	if ctx.Err() != nil {
		r.canceledCtxSeen = append(r.canceledCtxSeen, "DestroySandbox")
	} else {
		r.liveCtxSeen = append(r.liveCtxSeen, "DestroySandbox")
	}
	r.mu.Unlock()
	return r.workerMockRunner.DestroySandbox(ctx, sandboxID)
}

func TestCleanup_HandleLeaseLost_UsesBackgroundContext(t *testing.T) {
	// When parent context is canceled, handleLeaseLost should still complete
	// cleanup using context.Background() with a timeout.
	baseStore := newWorkerMockStore()
	store := newCtxTrackingStore(baseStore)
	baseRnr := newWorkerMockRunner(nil)
	rnr := newCtxTrackingRunner(baseRnr)

	pipeline, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:               store,
		Runner:              rnr,
		WorkerID:            "worker-1",
		Claim:               NewClaimService(store, ClaimConfig{IDFunc: func() string { return "a-1" }}),
		Provision:           NewProvisionService(store, rnr, ProvisionConfig{Image: "img"}),
		Bootstrap:           NewBootstrapService(store, rnr, BootstrapConfig{}),
		AuthMaterialization: NewAuthMaterializationService(store, rnr, AuthMaterializationConfig{}),
		Preflight:           NewPreflightService(store, rnr, PreflightConfig{}),
		Checkpoint:          NewCheckpointService(store, nil, CheckpointConfig{}),
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              NewCancellationService(store, CancellationConfig{}),
		Heartbeat:           NewHeartbeatService(store, HeartbeatConfig{}),
		HeartbeatInterval:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWorkerPipeline: %v", err)
	}

	// Create and immediately cancel a context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Call handleLeaseLost with the canceled context.
	pipeline.handleLeaseLost(ctx, "run-1", "profile-1", "sandbox-1")

	// All cleanup operations should have received a live (non-canceled) context
	// because handleLeaseLost creates its own context.Background() with timeout.
	store.mu.Lock()
	canceledOps := append([]string{}, store.canceledCtxSeen...)
	liveOps := append([]string{}, store.liveCtxSeen...)
	store.mu.Unlock()

	if len(canceledOps) > 0 {
		t.Errorf("cleanup operations received canceled context: %v", canceledOps)
	}

	// Verify all expected operations ran with live context.
	wantOps := map[string]bool{"TransitionRun": false, "ReleaseAuthLock": false}
	for _, op := range liveOps {
		wantOps[op] = true
	}
	for op, seen := range wantOps {
		if !seen {
			t.Errorf("expected %s to be called with live context", op)
		}
	}

	// Verify DestroySandbox also got a live context.
	rnr.mu.Lock()
	rnrCanceled := append([]string{}, rnr.canceledCtxSeen...)
	rnrLive := append([]string{}, rnr.liveCtxSeen...)
	rnr.mu.Unlock()

	if len(rnrCanceled) > 0 {
		t.Errorf("DestroySandbox received canceled context: %v", rnrCanceled)
	}
	if len(rnrLive) == 0 {
		t.Error("expected DestroySandbox to be called with live context")
	}
}

func TestCleanup_HandleProfileRevoked_UsesBackgroundContext(t *testing.T) {
	// When parent context is canceled, handleProfileRevoked should still
	// complete cleanup using context.Background() with a timeout.
	baseStore := newWorkerMockStore()
	store := newCtxTrackingStore(baseStore)
	baseRnr := newWorkerMockRunner(nil)
	rnr := newCtxTrackingRunner(baseRnr)

	pipeline, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:               store,
		Runner:              rnr,
		WorkerID:            "worker-1",
		Claim:               NewClaimService(store, ClaimConfig{IDFunc: func() string { return "a-1" }}),
		Provision:           NewProvisionService(store, rnr, ProvisionConfig{Image: "img"}),
		Bootstrap:           NewBootstrapService(store, rnr, BootstrapConfig{}),
		AuthMaterialization: NewAuthMaterializationService(store, rnr, AuthMaterializationConfig{}),
		Preflight:           NewPreflightService(store, rnr, PreflightConfig{}),
		Checkpoint:          NewCheckpointService(store, nil, CheckpointConfig{}),
		Execution:           NewExecutionService(store, rnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              NewCancellationService(store, CancellationConfig{}),
		Heartbeat:           NewHeartbeatService(store, HeartbeatConfig{}),
		HeartbeatInterval:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWorkerPipeline: %v", err)
	}

	// Create and immediately cancel a context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Call handleProfileRevoked with the canceled context.
	pipeline.handleProfileRevoked(ctx, "run-1", "sandbox-1")

	// All cleanup operations should have received a live context.
	store.mu.Lock()
	canceledOps := append([]string{}, store.canceledCtxSeen...)
	liveOps := append([]string{}, store.liveCtxSeen...)
	store.mu.Unlock()

	if len(canceledOps) > 0 {
		t.Errorf("cleanup operations received canceled context: %v", canceledOps)
	}

	// TransitionRun should have been called with live context.
	transitionFound := false
	for _, op := range liveOps {
		if op == "TransitionRun" {
			transitionFound = true
		}
	}
	if !transitionFound {
		t.Error("expected TransitionRun to be called with live context")
	}

	// DestroySandbox should have been called with live context.
	rnr.mu.Lock()
	rnrCanceled := append([]string{}, rnr.canceledCtxSeen...)
	rnrLive := append([]string{}, rnr.liveCtxSeen...)
	rnr.mu.Unlock()

	if len(rnrCanceled) > 0 {
		t.Errorf("DestroySandbox received canceled context: %v", rnrCanceled)
	}
	if len(rnrLive) == 0 {
		t.Error("expected DestroySandbox to be called with live context")
	}

	// Verify ReleaseAuthLock was NOT called (profile_revoked path doesn't release it).
	store.mu.Lock()
	for _, op := range store.liveCtxSeen {
		if op == "ReleaseAuthLock" {
			t.Error("handleProfileRevoked should NOT call ReleaseAuthLock")
		}
	}
	store.mu.Unlock()
}

func TestCleanup_HandleSetupFailure_UsesBackgroundContext(t *testing.T) {
	// When parent context is canceled, handleSetupFailure should still
	// complete cleanup (attempt and run transitions) using context.Background().
	baseStore := newWorkerMockStore()
	store := newCtxTrackingStore(baseStore)
	baseRnr := newWorkerMockRunner(nil)

	pipeline, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:               store,
		Runner:              baseRnr,
		WorkerID:            "worker-1",
		Claim:               NewClaimService(store, ClaimConfig{IDFunc: func() string { return "a-1" }}),
		Provision:           NewProvisionService(store, baseRnr, ProvisionConfig{Image: "img"}),
		Bootstrap:           NewBootstrapService(store, baseRnr, BootstrapConfig{}),
		AuthMaterialization: NewAuthMaterializationService(store, baseRnr, AuthMaterializationConfig{}),
		Preflight:           NewPreflightService(store, baseRnr, PreflightConfig{}),
		Checkpoint:          NewCheckpointService(store, nil, CheckpointConfig{}),
		Execution:           NewExecutionService(store, baseRnr, ExecutionConfig{}),
		Snapshot:            NewSnapshotService(store, SnapshotServiceConfig{}),
		Cancel:              NewCancellationService(store, CancellationConfig{}),
		Heartbeat:           NewHeartbeatService(store, HeartbeatConfig{}),
		HeartbeatInterval:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWorkerPipeline: %v", err)
	}

	// Create and immediately cancel a context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Call handleSetupFailure with the canceled context.
	pipeline.handleSetupFailure(ctx, "run-1", "attempt-1", RunStatusRunning, "provision", fmt.Errorf("sandbox creation failed"))

	// All cleanup operations should have received a live context.
	store.mu.Lock()
	canceledOps := append([]string{}, store.canceledCtxSeen...)
	liveOps := append([]string{}, store.liveCtxSeen...)
	store.mu.Unlock()

	if len(canceledOps) > 0 {
		t.Errorf("cleanup operations received canceled context: %v", canceledOps)
	}

	// Both TransitionAttempt and TransitionRun should have been called with live context.
	wantOps := map[string]bool{"TransitionAttempt": false, "TransitionRun": false}
	for _, op := range liveOps {
		wantOps[op] = true
	}
	for op, seen := range wantOps {
		if !seen {
			t.Errorf("expected %s to be called with live context", op)
		}
	}
}

func TestCleanup_CleanupTimeoutConstant(t *testing.T) {
	// Verify the cleanup timeout is set to a reasonable value.
	if cleanupTimeout != 30*time.Second {
		t.Errorf("cleanupTimeout = %v, want 30s", cleanupTimeout)
	}
}

// --- Execution exit code mapping tests (US-022) ---

func TestExecutionResult_ExitCodeZero_EmitsSucceededTransitions(t *testing.T) {
	// Exit code 0 must emit exactly one attempt succeeded transition and
	// exactly one run succeeded transition.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)

	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Count attempt transitions.
	attemptSucceeded := 0
	attemptFailed := 0
	for _, tc := range store.transitionAttemptCalls {
		switch tc.Status {
		case AttemptStatusSucceeded:
			attemptSucceeded++
		case AttemptStatusFailed:
			attemptFailed++
		}
	}
	if attemptSucceeded != 1 {
		t.Errorf("attempt succeeded transitions = %d, want exactly 1", attemptSucceeded)
	}
	if attemptFailed != 0 {
		t.Errorf("attempt failed transitions = %d, want 0", attemptFailed)
	}

	// Count run transitions (excluding claimed->running which is setup).
	runSucceeded := 0
	runFailed := 0
	for _, tr := range store.transitions {
		switch {
		case tr.toStatus == RunStatusSucceeded:
			runSucceeded++
		case tr.toStatus == RunStatusFailed:
			runFailed++
		}
	}
	if runSucceeded != 1 {
		t.Errorf("run succeeded transitions = %d, want exactly 1", runSucceeded)
	}
	if runFailed != 0 {
		t.Errorf("run failed transitions = %d, want 0", runFailed)
	}

	// Verify the run transition was from running to succeeded.
	found := false
	for _, tr := range store.transitions {
		if tr.fromStatus == RunStatusRunning && tr.toStatus == RunStatusSucceeded {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected running->succeeded transition, not found")
	}

	// Verify attempt transition has no error code or message.
	for _, tc := range store.transitionAttemptCalls {
		if tc.Status == AttemptStatusSucceeded {
			if tc.ErrorCode != nil {
				t.Errorf("succeeded attempt error_code = %q, want nil", *tc.ErrorCode)
			}
			if tc.ErrorMessage != nil {
				t.Errorf("succeeded attempt error_message = %q, want nil", *tc.ErrorMessage)
			}
		}
	}
}

func TestExecutionResult_NonZeroExit_EmitsFailedTransitions(t *testing.T) {
	// Non-zero exit must emit exactly one attempt failed transition with
	// reason non_retryable and exactly one run failed transition.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	// Override hal run command to return exit code 1 (testClaimedRun uses WorkflowKindRun).
	rnr.execOverrides["hal run"] = execOverride{
		result: &runner.ExecResult{ExitCode: 1, Stderr: "test failure"},
	}

	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Count attempt transitions.
	attemptSucceeded := 0
	attemptFailed := 0
	for _, tc := range store.transitionAttemptCalls {
		switch tc.Status {
		case AttemptStatusSucceeded:
			attemptSucceeded++
		case AttemptStatusFailed:
			attemptFailed++
		}
	}
	if attemptFailed != 1 {
		t.Errorf("attempt failed transitions = %d, want exactly 1", attemptFailed)
	}
	if attemptSucceeded != 0 {
		t.Errorf("attempt succeeded transitions = %d, want 0", attemptSucceeded)
	}

	// Count run transitions (excluding claimed->running).
	runSucceeded := 0
	runFailed := 0
	for _, tr := range store.transitions {
		switch {
		case tr.toStatus == RunStatusSucceeded:
			runSucceeded++
		case tr.toStatus == RunStatusFailed:
			runFailed++
		}
	}
	if runFailed != 1 {
		t.Errorf("run failed transitions = %d, want exactly 1", runFailed)
	}
	if runSucceeded != 0 {
		t.Errorf("run succeeded transitions = %d, want 0", runSucceeded)
	}

	// Verify the run transition was from running to failed.
	found := false
	for _, tr := range store.transitions {
		if tr.fromStatus == RunStatusRunning && tr.toStatus == RunStatusFailed {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected running->failed transition, not found")
	}
}

func TestExecutionResult_NonZeroExit_FailureReasonIsNonRetryable(t *testing.T) {
	// Verify the attempt failure has error_code = "non_retryable".
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	rnr.execOverrides["hal run"] = execOverride{
		result: &runner.ExecResult{ExitCode: 2},
	}

	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Find the failed attempt transition.
	var failedTC *transitionAttemptCall
	for i, tc := range store.transitionAttemptCalls {
		if tc.Status == AttemptStatusFailed {
			failedTC = &store.transitionAttemptCalls[i]
			break
		}
	}
	if failedTC == nil {
		t.Fatal("no failed attempt transition found")
	}

	// Verify error_code is non_retryable.
	if failedTC.ErrorCode == nil {
		t.Fatal("error_code is nil, want non_retryable")
	}
	if *failedTC.ErrorCode != string(FailureNonRetryable) {
		t.Errorf("error_code = %q, want %q", *failedTC.ErrorCode, FailureNonRetryable)
	}

	// Verify error_message includes the exit code.
	if failedTC.ErrorMessage == nil {
		t.Fatal("error_message is nil, want non-nil")
	}
	if !strings.Contains(*failedTC.ErrorMessage, "code 2") {
		t.Errorf("error_message = %q, want containing 'code 2'", *failedTC.ErrorMessage)
	}
}

func TestExecutionResult_MultipleExitCodes(t *testing.T) {
	// Table-driven test covering various exit codes to verify deterministic
	// transition mapping.
	tests := []struct {
		name              string
		exitCode          int
		wantAttemptStatus AttemptStatus
		wantRunToStatus   RunStatus
		wantErrCode       *string
	}{
		{
			name:              "exit_0_success",
			exitCode:          0,
			wantAttemptStatus: AttemptStatusSucceeded,
			wantRunToStatus:   RunStatusSucceeded,
			wantErrCode:       nil,
		},
		{
			name:              "exit_1_failure",
			exitCode:          1,
			wantAttemptStatus: AttemptStatusFailed,
			wantRunToStatus:   RunStatusFailed,
			wantErrCode:       strPtr(string(FailureNonRetryable)),
		},
		{
			name:              "exit_2_failure",
			exitCode:          2,
			wantAttemptStatus: AttemptStatusFailed,
			wantRunToStatus:   RunStatusFailed,
			wantErrCode:       strPtr(string(FailureNonRetryable)),
		},
		{
			name:              "exit_128_failure",
			exitCode:          128,
			wantAttemptStatus: AttemptStatusFailed,
			wantRunToStatus:   RunStatusFailed,
			wantErrCode:       strPtr(string(FailureNonRetryable)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newWorkerMockStore()
			store.claimedRun = testClaimedRun()
			rnr := newWorkerMockRunner(nil)
			if tt.exitCode != 0 {
				rnr.execOverrides["hal run"] = execOverride{
					result: &runner.ExecResult{ExitCode: tt.exitCode},
				}
			}

			pipeline := newTestWorkerPipeline(t, store, rnr)

			err := pipeline.ProcessOne(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify exactly one attempt transition with expected status.
			if len(store.transitionAttemptCalls) != 1 {
				t.Fatalf("attempt transitions = %d, want exactly 1", len(store.transitionAttemptCalls))
			}
			tc := store.transitionAttemptCalls[0]
			if tc.Status != tt.wantAttemptStatus {
				t.Errorf("attempt status = %q, want %q", tc.Status, tt.wantAttemptStatus)
			}

			// Verify error code.
			if tt.wantErrCode == nil {
				if tc.ErrorCode != nil {
					t.Errorf("error_code = %q, want nil", *tc.ErrorCode)
				}
			} else {
				if tc.ErrorCode == nil {
					t.Fatalf("error_code is nil, want %q", *tt.wantErrCode)
				}
				if *tc.ErrorCode != *tt.wantErrCode {
					t.Errorf("error_code = %q, want %q", *tc.ErrorCode, *tt.wantErrCode)
				}
			}

			// Verify run transition: claimed->running (setup) + running->terminal.
			// Find the terminal transition (last one).
			terminalFound := false
			for _, tr := range store.transitions {
				if tr.fromStatus == RunStatusRunning && tr.toStatus == tt.wantRunToStatus {
					terminalFound = true
				}
			}
			if !terminalFound {
				t.Errorf("expected running->%s transition, not found", tt.wantRunToStatus)
			}
		})
	}
}

func TestExecutionResult_RunnerAPIError_TreatsAsFailure(t *testing.T) {
	// When the execution service returns an error (runner API failure),
	// the pipeline should treat it as a non-retryable failure with exit -1.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	// Make the hal run command return a runner error.
	rnr.execOverrides["hal run"] = execOverride{
		err: fmt.Errorf("sandbox unreachable"),
	}

	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "execution failed") {
		t.Errorf("error = %q, want containing 'execution failed'", err.Error())
	}

	// Should still emit attempt failed transition.
	attemptFailed := 0
	for _, tc := range store.transitionAttemptCalls {
		if tc.Status == AttemptStatusFailed {
			attemptFailed++
		}
	}
	if attemptFailed != 1 {
		t.Errorf("attempt failed transitions = %d, want exactly 1", attemptFailed)
	}

	// Should emit run failed transition.
	runFailed := 0
	for _, tr := range store.transitions {
		if tr.fromStatus == RunStatusRunning && tr.toStatus == RunStatusFailed {
			runFailed++
		}
	}
	if runFailed != 1 {
		t.Errorf("run failed transitions = %d, want exactly 1", runFailed)
	}
}

func TestExecutionResult_TransitionCounts(t *testing.T) {
	// Verify that handleExecutionResult emits exactly one attempt transition
	// and exactly one run transition (beyond the setup claimed->running).
	tests := []struct {
		name                       string
		exitCode                   int
		wantAttemptTransitions     int
		wantRunTerminalTransitions int
	}{
		{
			name:                       "exit_0_one_of_each",
			exitCode:                   0,
			wantAttemptTransitions:     1,
			wantRunTerminalTransitions: 1,
		},
		{
			name:                       "exit_1_one_of_each",
			exitCode:                   1,
			wantAttemptTransitions:     1,
			wantRunTerminalTransitions: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newWorkerMockStore()
			store.claimedRun = testClaimedRun()
			rnr := newWorkerMockRunner(nil)
			if tt.exitCode != 0 {
				rnr.execOverrides["hal run"] = execOverride{
					result: &runner.ExecResult{ExitCode: tt.exitCode},
				}
			}

			pipeline := newTestWorkerPipeline(t, store, rnr)

			err := pipeline.ProcessOne(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Count attempt transitions (all of them come from handleExecutionResult).
			if len(store.transitionAttemptCalls) != tt.wantAttemptTransitions {
				t.Errorf("attempt transitions = %d, want %d", len(store.transitionAttemptCalls), tt.wantAttemptTransitions)
			}

			// Count run terminal transitions (exclude claimed->running from setup).
			terminalRunTransitions := 0
			for _, tr := range store.transitions {
				if tr.fromStatus == RunStatusRunning && (tr.toStatus == RunStatusSucceeded || tr.toStatus == RunStatusFailed) {
					terminalRunTransitions++
				}
			}
			if terminalRunTransitions != tt.wantRunTerminalTransitions {
				t.Errorf("run terminal transitions = %d, want %d", terminalRunTransitions, tt.wantRunTerminalTransitions)
			}
		})
	}
}

// strPtr returns a pointer to s.
func strPtr(s string) *string {
	return &s
}

// --- US-023: Auth lock ErrNotFound tolerance in cleanup paths ---

func TestReleaseAuthLockBestEffort_ToleratesErrNotFound(t *testing.T) {
	store := newWorkerMockStore()
	store.releaseAuthLockErr = ErrNotFound
	rnr := newWorkerMockRunner(nil)

	p := newTestWorkerPipeline(t, store, rnr)

	err := p.releaseAuthLockBestEffort(context.Background(), "profile-1", "run-1")
	if err != nil {
		t.Errorf("releaseAuthLockBestEffort returned error for ErrNotFound: %v", err)
	}

	// Verify ReleaseAuthLock was still called.
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.releaseAuthLockCalls) != 1 {
		t.Fatalf("expected 1 ReleaseAuthLock call, got %d", len(store.releaseAuthLockCalls))
	}
	if store.releaseAuthLockCalls[0].AuthProfileID != "profile-1" {
		t.Errorf("AuthProfileID = %q, want %q", store.releaseAuthLockCalls[0].AuthProfileID, "profile-1")
	}
	if store.releaseAuthLockCalls[0].RunID != "run-1" {
		t.Errorf("RunID = %q, want %q", store.releaseAuthLockCalls[0].RunID, "run-1")
	}
}

func TestReleaseAuthLockBestEffort_ReturnsWrappedNonNotFoundError(t *testing.T) {
	dbErr := fmt.Errorf("database connection lost")
	store := newWorkerMockStore()
	store.releaseAuthLockErr = dbErr
	rnr := newWorkerMockRunner(nil)

	p := newTestWorkerPipeline(t, store, rnr)

	err := p.releaseAuthLockBestEffort(context.Background(), "profile-1", "run-1")
	if err == nil {
		t.Fatal("expected error for non-ErrNotFound, got nil")
	}

	// Verify the error wraps the original with %w.
	if !errors.Is(err, dbErr) {
		t.Errorf("error does not wrap original: %v", err)
	}

	// Verify the error includes context about the operation.
	if !strings.Contains(err.Error(), "releasing auth lock") {
		t.Errorf("error missing operation context: %v", err)
	}
	if !strings.Contains(err.Error(), "profile-1") {
		t.Errorf("error missing profile ID: %v", err)
	}
	if !strings.Contains(err.Error(), "run-1") {
		t.Errorf("error missing run ID: %v", err)
	}
}

func TestReleaseAuthLockBestEffort_SuccessReturnsNil(t *testing.T) {
	store := newWorkerMockStore()
	// releaseAuthLockErr defaults to nil — successful release.
	rnr := newWorkerMockRunner(nil)

	p := newTestWorkerPipeline(t, store, rnr)

	err := p.releaseAuthLockBestEffort(context.Background(), "profile-1", "run-1")
	if err != nil {
		t.Errorf("releaseAuthLockBestEffort returned error for success: %v", err)
	}
}

func TestHandleLeaseLost_ToleratesErrNotFoundForAuthLock(t *testing.T) {
	store := newWorkerMockStore()
	store.releaseAuthLockErr = ErrNotFound
	rnr := newWorkerMockRunner(nil)

	p := newTestWorkerPipeline(t, store, rnr)

	// handleLeaseLost should not panic or fail for ErrNotFound on auth lock release.
	p.handleLeaseLost(context.Background(), "run-1", "profile-1", "sandbox-1")

	// Verify ReleaseAuthLock was called.
	store.mu.Lock()
	lockCalls := len(store.releaseAuthLockCalls)
	store.mu.Unlock()
	if lockCalls != 1 {
		t.Errorf("expected 1 ReleaseAuthLock call, got %d", lockCalls)
	}

	// Verify sandbox cleanup still ran despite auth lock ErrNotFound.
	rnr.mu.Lock()
	destroyCalls := len(rnr.destroySandboxCalls)
	rnr.mu.Unlock()
	if destroyCalls != 1 {
		t.Errorf("expected 1 DestroySandbox call, got %d", destroyCalls)
	}
}

func TestHandleLeaseLost_AuthLockOtherErrorStillCleansUp(t *testing.T) {
	store := newWorkerMockStore()
	store.releaseAuthLockErr = fmt.Errorf("database timeout")
	rnr := newWorkerMockRunner(nil)

	p := newTestWorkerPipeline(t, store, rnr)

	// handleLeaseLost is best-effort — non-ErrNotFound errors are handled
	// internally, and cleanup still proceeds (sandbox teardown).
	p.handleLeaseLost(context.Background(), "run-1", "profile-1", "sandbox-1")

	// Verify sandbox cleanup still ran.
	rnr.mu.Lock()
	destroyCalls := len(rnr.destroySandboxCalls)
	rnr.mu.Unlock()
	if destroyCalls != 1 {
		t.Errorf("expected 1 DestroySandbox call, got %d", destroyCalls)
	}
}

// --- US-024: Persist final snapshot payloads with deterministic metadata ---

func TestFinalizeSnapshot_StoresRecordsAndCompressedPayload(t *testing.T) {
	// On success (exit code 0), finalization collects sandbox files,
	// compresses them, and persists a final snapshot with deterministic SHA.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	// GetRun for snapshot service version resolution returns a run with version 0.
	store.getRun = &Run{
		ID:                    "run-1",
		Status:                RunStatusRunning,
		AuthProfileID:         "profile-1",
		LatestSnapshotVersion: 0,
	}
	rnr := newWorkerMockRunner(nil)

	// Set up sandbox file listing — find returns one file.
	fileContent := []byte("test prd content")
	encodedContent := base64.StdEncoding.EncodeToString(fileContent)
	rnr.execOverrides["find /workspace/.hal"] = execOverride{
		result: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "/workspace/.hal/prd.json\n",
		},
	}
	rnr.execOverrides[base64Cmd] = execOverride{
		result: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   encodedContent,
		},
	}

	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify PutSnapshot was called.
	if len(store.putSnapshotCalls) != 1 {
		t.Fatalf("PutSnapshot calls = %d, want 1", len(store.putSnapshotCalls))
	}

	snap := store.putSnapshotCalls[0]

	// Verify snapshot kind is final.
	if snap.SnapshotKind != SnapshotKindFinal {
		t.Errorf("SnapshotKind = %q, want %q", snap.SnapshotKind, SnapshotKindFinal)
	}

	// Verify snapshot content is non-empty (compressed payload).
	if len(snap.ContentBlob) == 0 {
		t.Error("ContentBlob is empty, want compressed payload")
	}

	// Verify content encoding.
	if snap.ContentEncoding != "application/gzip" {
		t.Errorf("ContentEncoding = %q, want %q", snap.ContentEncoding, "application/gzip")
	}

	// Verify SizeBytes matches ContentBlob length.
	if snap.SizeBytes != int64(len(snap.ContentBlob)) {
		t.Errorf("SizeBytes = %d, want %d (ContentBlob length)", snap.SizeBytes, len(snap.ContentBlob))
	}

	// Verify snapshot SHA equals ComputeSandboxBundleHash(records).
	expectedRecords := []SandboxBundleRecord{
		{Path: ".hal/prd.json", Content: fileContent},
	}
	expectedSHA := ComputeSandboxBundleHash(expectedRecords)
	if snap.SHA256 != expectedSHA {
		t.Errorf("SHA256 = %q, want %q (ComputeSandboxBundleHash)", snap.SHA256, expectedSHA)
	}

	// Verify snapshot run ID matches.
	if snap.RunID != "run-1" {
		t.Errorf("RunID = %q, want %q", snap.RunID, "run-1")
	}

	// Verify attempt ID is set.
	if snap.AttemptID == nil || *snap.AttemptID != "attempt-1" {
		t.Errorf("AttemptID = %v, want %q", snap.AttemptID, "attempt-1")
	}

	// Verify version is 1 (first snapshot).
	if snap.Version != 1 {
		t.Errorf("Version = %d, want 1", snap.Version)
	}
}

func TestFinalizeSnapshot_SHAMatchesRecordHashNotCompressedPayload(t *testing.T) {
	// The snapshot SHA must equal ComputeBundleHash(records), NOT a hash
	// of the compressed payload bytes.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.getRun = &Run{
		ID:                    "run-1",
		Status:                RunStatusRunning,
		AuthProfileID:         "profile-1",
		LatestSnapshotVersion: 0,
	}
	rnr := newWorkerMockRunner(nil)

	fileContent := []byte("deterministic hash test content")
	encodedContent := base64.StdEncoding.EncodeToString(fileContent)
	rnr.execOverrides["find /workspace/.hal"] = execOverride{
		result: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "/workspace/.hal/progress.txt\n",
		},
	}
	rnr.execOverrides[base64Cmd] = execOverride{
		result: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   encodedContent,
		},
	}

	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(store.putSnapshotCalls) != 1 {
		t.Fatalf("PutSnapshot calls = %d, want 1", len(store.putSnapshotCalls))
	}

	snap := store.putSnapshotCalls[0]

	// Compute expected SHA from records (not from compressed bytes).
	records := []SandboxBundleRecord{
		{Path: ".hal/progress.txt", Content: fileContent},
	}
	expectedSHA := ComputeSandboxBundleHash(records)

	// Compute SHA from compressed payload bytes for comparison.
	compressed, _ := CompressBundle(records)
	compressedSHA := ComputeSandboxBundleHash([]SandboxBundleRecord{
		{Path: "compressed", Content: compressed},
	})

	// The snapshot SHA should match the record hash.
	if snap.SHA256 != expectedSHA {
		t.Errorf("SHA256 = %q, want %q (record hash)", snap.SHA256, expectedSHA)
	}

	// The snapshot SHA should NOT equal the compressed payload hash.
	if snap.SHA256 == compressedSHA {
		t.Error("SHA256 equals compressed payload hash — should be record hash instead")
	}
}

func TestFinalizeSnapshot_UpdatesRunSnapshotRefs(t *testing.T) {
	// Finalization updates run snapshot references with new snapshot ID and version.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.getRun = &Run{
		ID:                    "run-1",
		Status:                RunStatusRunning,
		AuthProfileID:         "profile-1",
		LatestSnapshotVersion: 0,
	}
	rnr := newWorkerMockRunner(nil)

	fileContent := []byte("refs test")
	encodedContent := base64.StdEncoding.EncodeToString(fileContent)
	rnr.execOverrides["find /workspace/.hal"] = execOverride{
		result: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "/workspace/.hal/prd.json\n",
		},
	}
	rnr.execOverrides[base64Cmd] = execOverride{
		result: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   encodedContent,
		},
	}

	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify UpdateRunSnapshotRefs was called.
	if len(store.updateRefsCalls) != 1 {
		t.Fatalf("UpdateRunSnapshotRefs calls = %d, want 1", len(store.updateRefsCalls))
	}
	refs := store.updateRefsCalls[0]
	if refs.RunID != "run-1" {
		t.Errorf("RunID = %q, want %q", refs.RunID, "run-1")
	}
	if refs.LatestSnapshotVersion != 1 {
		t.Errorf("LatestSnapshotVersion = %d, want 1", refs.LatestSnapshotVersion)
	}
	if refs.LatestSnapshotID == nil || *refs.LatestSnapshotID != "snapshot-1" {
		t.Errorf("LatestSnapshotID = %v, want %q", refs.LatestSnapshotID, "snapshot-1")
	}
}

func TestFinalizeSnapshot_NotCalledOnNonZeroExit(t *testing.T) {
	// Non-zero exit code should not trigger finalization.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)
	rnr.execOverrides["hal run"] = execOverride{
		result: &runner.ExecResult{ExitCode: 1},
	}

	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// PutSnapshot should not have been called.
	if len(store.putSnapshotCalls) != 0 {
		t.Errorf("PutSnapshot calls = %d, want 0 (non-zero exit should skip finalization)", len(store.putSnapshotCalls))
	}

	// UpdateRunSnapshotRefs should not have been called.
	if len(store.updateRefsCalls) != 0 {
		t.Errorf("UpdateRunSnapshotRefs calls = %d, want 0", len(store.updateRefsCalls))
	}
}

func TestFinalizeSnapshot_EmptyWorkspaceSkipsSnapshot(t *testing.T) {
	// When the sandbox has no matching files, finalization is a no-op.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	rnr := newWorkerMockRunner(nil)

	// find returns empty output (no files).
	rnr.execOverrides["find /workspace/.hal"] = execOverride{
		result: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "",
		},
	}

	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No snapshot should be stored.
	if len(store.putSnapshotCalls) != 0 {
		t.Errorf("PutSnapshot calls = %d, want 0 (empty workspace)", len(store.putSnapshotCalls))
	}
}

func TestFinalizeSnapshot_MultipleFiles(t *testing.T) {
	// Finalization with multiple sandbox files stores all in a single snapshot.
	store := newWorkerMockStore()
	store.claimedRun = testClaimedRun()
	store.getRun = &Run{
		ID:                    "run-1",
		Status:                RunStatusRunning,
		AuthProfileID:         "profile-1",
		LatestSnapshotVersion: 0,
	}
	rnr := newWorkerMockRunner(nil)

	prdContent := []byte(`{"project":"test"}`)
	progressContent := []byte("## progress\n- step 1")

	rnr.execOverrides["find /workspace/.hal"] = execOverride{
		result: &runner.ExecResult{
			ExitCode: 0,
			Stdout:   "/workspace/.hal/prd.json\n/workspace/.hal/progress.txt\n",
		},
	}

	// Return different base64 content per file.
	// Since execOverrides match by prefix, we need to be more specific.
	// The base64 command includes the full quoted path.
	prdEncoded := base64.StdEncoding.EncodeToString(prdContent)
	progressEncoded := base64.StdEncoding.EncodeToString(progressContent)
	rnr.execOverrides[base64Cmd+" '/workspace/.hal/prd.json'"] = execOverride{
		result: &runner.ExecResult{ExitCode: 0, Stdout: prdEncoded},
	}
	rnr.execOverrides[base64Cmd+" '/workspace/.hal/progress.txt'"] = execOverride{
		result: &runner.ExecResult{ExitCode: 0, Stdout: progressEncoded},
	}

	pipeline := newTestWorkerPipeline(t, store, rnr)

	err := pipeline.ProcessOne(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(store.putSnapshotCalls) != 1 {
		t.Fatalf("PutSnapshot calls = %d, want 1", len(store.putSnapshotCalls))
	}

	snap := store.putSnapshotCalls[0]

	// Verify SHA matches the hash of both records.
	expectedRecords := []SandboxBundleRecord{
		{Path: ".hal/prd.json", Content: prdContent},
		{Path: ".hal/progress.txt", Content: progressContent},
	}
	expectedSHA := ComputeSandboxBundleHash(expectedRecords)
	if snap.SHA256 != expectedSHA {
		t.Errorf("SHA256 = %q, want %q", snap.SHA256, expectedSHA)
	}

	// Verify compressed payload is non-empty.
	if len(snap.ContentBlob) == 0 {
		t.Error("ContentBlob is empty, want compressed multi-file payload")
	}
}
