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

// workerMockRunner is a minimal runner for worker tests.
type workerMockRunner struct{}

func (r *workerMockRunner) CreateSandbox(_ context.Context, _ *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	return nil, nil
}
func (r *workerMockRunner) Exec(_ context.Context, _ string, _ *runner.ExecRequest) (*runner.ExecResult, error) {
	return nil, nil
}
func (r *workerMockRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}
func (r *workerMockRunner) DestroySandbox(_ context.Context, _ string) error { return nil }
func (r *workerMockRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return nil, nil
}

func TestNewWorkerPipeline(t *testing.T) {
	store := newWorkerMockStore()
	rnr := &workerMockRunner{}
	claim := NewClaimService(store, ClaimConfig{
		IDFunc: func() string { return "attempt-1" },
	})

	tests := []struct {
		name    string
		cfg     WorkerPipelineConfig
		wantErr string
	}{
		{
			name: "valid config",
			cfg: WorkerPipelineConfig{
				Store:    store,
				Runner:   rnr,
				WorkerID: "worker-1",
				Claim:    claim,
			},
		},
		{
			name: "nil store",
			cfg: WorkerPipelineConfig{
				Store:    nil,
				Runner:   rnr,
				WorkerID: "worker-1",
				Claim:    claim,
			},
			wantErr: "store must not be nil",
		},
		{
			name: "nil runner",
			cfg: WorkerPipelineConfig{
				Store:    store,
				Runner:   nil,
				WorkerID: "worker-1",
				Claim:    claim,
			},
			wantErr: "runner must not be nil",
		},
		{
			name: "empty worker ID",
			cfg: WorkerPipelineConfig{
				Store:    store,
				Runner:   rnr,
				WorkerID: "",
				Claim:    claim,
			},
			wantErr: "workerID must not be empty",
		},
		{
			name: "nil claim service",
			cfg: WorkerPipelineConfig{
				Store:    store,
				Runner:   rnr,
				WorkerID: "worker-1",
				Claim:    nil,
			},
			wantErr: "claim must not be nil",
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
	rnr := &workerMockRunner{}
	claim := NewClaimService(store, ClaimConfig{
		IDFunc: func() string { return "attempt-1" },
	})

	pipeline, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:    store,
		Runner:   rnr,
		WorkerID: "worker-1",
		Claim:    claim,
	})
	if err != nil {
		t.Fatalf("NewWorkerPipeline: %v", err)
	}

	err = pipeline.ProcessOne(context.Background())
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
	rnr := &workerMockRunner{}
	claim := NewClaimService(store, ClaimConfig{
		IDFunc: func() string { return "attempt-1" },
	})

	pipeline, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:    store,
		Runner:   rnr,
		WorkerID: "worker-1",
		Claim:    claim,
	})
	if err != nil {
		t.Fatalf("NewWorkerPipeline: %v", err)
	}

	err = pipeline.ProcessOne(context.Background())
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
	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(1 * time.Hour)
	store.claimedRun = &Run{
		ID:            "run-1",
		Repo:          "org/repo",
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
	rnr := &workerMockRunner{}
	claim := NewClaimService(store, ClaimConfig{
		IDFunc: func() string { return "attempt-1" },
	})

	pipeline, err := NewWorkerPipeline(WorkerPipelineConfig{
		Store:    store,
		Runner:   rnr,
		WorkerID: "worker-1",
		Claim:    claim,
	})
	if err != nil {
		t.Fatalf("NewWorkerPipeline: %v", err)
	}

	err = pipeline.ProcessOne(context.Background())
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
