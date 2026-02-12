package cloud

import (
	"context"
	"fmt"
	"io"
	"strings"
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

	// GetAuthProfile behavior
	authProfile    *AuthProfile
	authProfileErr error

	// Optional call log for ordering tests.
	log *callLog
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

func (s *workerMockStore) GetAuthProfile(_ context.Context, _ string) (*AuthProfile, error) {
	if s.authProfileErr != nil {
		return nil, s.authProfileErr
	}
	if s.authProfile != nil {
		return s.authProfile, nil
	}
	return &AuthProfile{ID: "profile-1", Provider: "github", Status: AuthProfileStatusLinked}, nil
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

func newTestWorkerPipeline(t *testing.T, store *workerMockStore, rnr *workerMockRunner) *WorkerPipeline {
	t.Helper()
	claim := NewClaimService(store, ClaimConfig{
		IDFunc: func() string { return "attempt-1" },
	})
	provision := NewProvisionService(store, rnr, ProvisionConfig{
		Image: "test-image:latest",
	})
	bootstrap := NewBootstrapService(store, rnr, BootstrapConfig{})
	authMat := NewAuthMaterializationService(store, rnr, AuthMaterializationConfig{})
	preflight := NewPreflightService(store, rnr, PreflightConfig{})

	pipeline, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:               store,
		Runner:              rnr,
		WorkerID:            "worker-1",
		Claim:               claim,
		Provision:           provision,
		Bootstrap:           bootstrap,
		AuthMaterialization: authMat,
		Preflight:           preflight,
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
			},
			wantErr: "preflight must not be nil",
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

	// Transition should still have happened before provision.
	if len(store.transitions) != 1 {
		t.Fatalf("expected 1 transition, got %d", len(store.transitions))
	}
	if store.transitions[0].toStatus != RunStatusRunning {
		t.Errorf("transition to = %q, want %q", store.transitions[0].toStatus, RunStatusRunning)
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

	p, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:               store,
		Runner:              rnr,
		WorkerID:            "worker-1",
		Claim:               claim,
		Provision:           provision,
		Bootstrap:           bootstrap,
		AuthMaterialization: authMat,
		Preflight:           preflightSvc,
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
