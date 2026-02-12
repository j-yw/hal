package cloud

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// claimMockStore is a test store for claim service tests.
type claimMockStore struct {
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
	transitionRunCalls []transitionRunCall

	// TransitionAttempt tracking
	transitionAttemptCalls []transitionAttemptCall
}

type transitionRunCall struct {
	RunID      string
	FromStatus RunStatus
	ToStatus   RunStatus
}

type transitionAttemptCall struct {
	AttemptID    string
	Status       AttemptStatus
	EndedAt      time.Time
	ErrorCode    *string
	ErrorMessage *string
}

func newClaimMockStore() *claimMockStore {
	return &claimMockStore{}
}

func (s *claimMockStore) ClaimRun(_ context.Context, _ string) (*Run, error) {
	if s.claimErr != nil {
		return nil, s.claimErr
	}
	if s.claimedRun == nil {
		return nil, ErrNotFound
	}
	return s.claimedRun, nil
}

func (s *claimMockStore) CreateAttempt(_ context.Context, a *Attempt) error {
	if s.createErr != nil {
		return s.createErr
	}
	s.attempts = append(s.attempts, a)
	return nil
}

func (s *claimMockStore) AcquireAuthLock(_ context.Context, lock *AuthProfileLock) error {
	if s.lockErr != nil {
		return s.lockErr
	}
	s.locks = append(s.locks, lock)
	return nil
}

func (s *claimMockStore) TransitionRun(_ context.Context, runID string, from, to RunStatus) error {
	s.transitionRunCalls = append(s.transitionRunCalls, transitionRunCall{
		RunID:      runID,
		FromStatus: from,
		ToStatus:   to,
	})
	return nil
}

func (s *claimMockStore) TransitionAttempt(_ context.Context, attemptID string, status AttemptStatus, endedAt time.Time, errCode, errMsg *string) error {
	s.transitionAttemptCalls = append(s.transitionAttemptCalls, transitionAttemptCall{
		AttemptID:    attemptID,
		Status:       status,
		EndedAt:      endedAt,
		ErrorCode:    errCode,
		ErrorMessage: errMsg,
	})
	return nil
}

func claimedRun() *Run {
	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(1 * time.Hour)
	return &Run{
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
}

func TestClaimAndLock(t *testing.T) {
	idSeq := 0
	idFunc := func() string {
		idSeq++
		return fmt.Sprintf("attempt-%d", idSeq)
	}

	tests := []struct {
		name     string
		workerID string
		setup    func(s *claimMockStore)
		wantErr  string
		check    func(t *testing.T, result *ClaimResult, s *claimMockStore)
	}{
		{
			name:     "successful claim and lock",
			workerID: "worker-1",
			setup: func(s *claimMockStore) {
				s.claimedRun = claimedRun()
			},
			check: func(t *testing.T, result *ClaimResult, s *claimMockStore) {
				t.Helper()
				if result.Run.ID != "run-1" {
					t.Errorf("run.ID = %q, want %q", result.Run.ID, "run-1")
				}
				if result.Attempt.RunID != "run-1" {
					t.Errorf("attempt.RunID = %q, want %q", result.Attempt.RunID, "run-1")
				}
				if result.Attempt.WorkerID != "worker-1" {
					t.Errorf("attempt.WorkerID = %q, want %q", result.Attempt.WorkerID, "worker-1")
				}
				if result.Attempt.AttemptNumber != 1 {
					t.Errorf("attempt.AttemptNumber = %d, want 1", result.Attempt.AttemptNumber)
				}
				if result.Attempt.Status != AttemptStatusActive {
					t.Errorf("attempt.Status = %q, want %q", result.Attempt.Status, AttemptStatusActive)
				}
				if result.Lock.AuthProfileID != "profile-1" {
					t.Errorf("lock.AuthProfileID = %q, want %q", result.Lock.AuthProfileID, "profile-1")
				}
				if result.Lock.RunID != "run-1" {
					t.Errorf("lock.RunID = %q, want %q", result.Lock.RunID, "run-1")
				}
				if result.Lock.WorkerID != "worker-1" {
					t.Errorf("lock.WorkerID = %q, want %q", result.Lock.WorkerID, "worker-1")
				}
				// Verify no rollback calls were made.
				if len(s.transitionRunCalls) != 0 {
					t.Errorf("unexpected TransitionRun calls: %d", len(s.transitionRunCalls))
				}
				if len(s.transitionAttemptCalls) != 0 {
					t.Errorf("unexpected TransitionAttempt calls: %d", len(s.transitionAttemptCalls))
				}
			},
		},
		{
			name:     "empty worker ID",
			workerID: "",
			setup:    func(s *claimMockStore) {},
			wantErr:  "workerID must not be empty",
		},
		{
			name:     "no eligible run",
			workerID: "worker-1",
			setup: func(s *claimMockStore) {
				s.claimErr = ErrNotFound
			},
			wantErr: "not_found",
		},
		{
			name:     "claim store error",
			workerID: "worker-1",
			setup: func(s *claimMockStore) {
				s.claimErr = fmt.Errorf("database connection lost")
			},
			wantErr: "database connection lost",
		},
		{
			name:     "create attempt fails rolls back claim",
			workerID: "worker-1",
			setup: func(s *claimMockStore) {
				s.claimedRun = claimedRun()
				s.createErr = fmt.Errorf("attempt insert failed")
			},
			wantErr: "failed to create attempt: attempt insert failed",
			check: func(t *testing.T, _ *ClaimResult, s *claimMockStore) {
				t.Helper()
				// Verify run was rolled back to queued.
				if len(s.transitionRunCalls) != 1 {
					t.Fatalf("expected 1 TransitionRun call, got %d", len(s.transitionRunCalls))
				}
				call := s.transitionRunCalls[0]
				if call.RunID != "run-1" {
					t.Errorf("rollback RunID = %q, want %q", call.RunID, "run-1")
				}
				if call.FromStatus != RunStatusClaimed {
					t.Errorf("rollback FromStatus = %q, want %q", call.FromStatus, RunStatusClaimed)
				}
				if call.ToStatus != RunStatusQueued {
					t.Errorf("rollback ToStatus = %q, want %q", call.ToStatus, RunStatusQueued)
				}
			},
		},
		{
			name:     "lock acquisition fails rolls back claim and attempt",
			workerID: "worker-1",
			setup: func(s *claimMockStore) {
				s.claimedRun = claimedRun()
				s.lockErr = ErrConflict
			},
			wantErr: "failed to acquire auth lock",
			check: func(t *testing.T, _ *ClaimResult, s *claimMockStore) {
				t.Helper()
				// Verify attempt was marked as failed.
				if len(s.transitionAttemptCalls) != 1 {
					t.Fatalf("expected 1 TransitionAttempt call, got %d", len(s.transitionAttemptCalls))
				}
				aC := s.transitionAttemptCalls[0]
				if aC.Status != AttemptStatusFailed {
					t.Errorf("rollback attempt Status = %q, want %q", aC.Status, AttemptStatusFailed)
				}
				if aC.ErrorCode == nil || *aC.ErrorCode != "lock_acquisition_failed" {
					t.Errorf("rollback attempt ErrorCode = %v, want %q", aC.ErrorCode, "lock_acquisition_failed")
				}

				// Verify run was rolled back to queued.
				if len(s.transitionRunCalls) != 1 {
					t.Fatalf("expected 1 TransitionRun call, got %d", len(s.transitionRunCalls))
				}
				rC := s.transitionRunCalls[0]
				if rC.FromStatus != RunStatusClaimed {
					t.Errorf("rollback FromStatus = %q, want %q", rC.FromStatus, RunStatusClaimed)
				}
				if rC.ToStatus != RunStatusQueued {
					t.Errorf("rollback ToStatus = %q, want %q", rC.ToStatus, RunStatusQueued)
				}
			},
		},
		{
			name:     "attempt number equals claimed run attempt count",
			workerID: "worker-1",
			setup: func(s *claimMockStore) {
				r := claimedRun()
				r.AttemptCount = 2
				s.claimedRun = r
			},
			check: func(t *testing.T, result *ClaimResult, _ *claimMockStore) {
				t.Helper()
				if result.Attempt.AttemptNumber != 2 {
					t.Errorf("attempt.AttemptNumber = %d, want 2", result.Attempt.AttemptNumber)
				}
				if result.Attempt.AttemptNumber != result.Run.AttemptCount {
					t.Errorf("attempt.AttemptNumber (%d) != run.AttemptCount (%d), want equal",
						result.Attempt.AttemptNumber, result.Run.AttemptCount)
				}
			},
		},
		{
			name:     "attempt and lock share lease expiry",
			workerID: "worker-1",
			setup: func(s *claimMockStore) {
				s.claimedRun = claimedRun()
			},
			check: func(t *testing.T, result *ClaimResult, _ *claimMockStore) {
				t.Helper()
				if !result.Attempt.LeaseExpiresAt.Equal(result.Lock.LeaseExpiresAt) {
					t.Errorf("attempt.LeaseExpiresAt = %v, lock.LeaseExpiresAt = %v, want equal",
						result.Attempt.LeaseExpiresAt, result.Lock.LeaseExpiresAt)
				}
			},
		},
		{
			name:     "attempt ID set by IDFunc",
			workerID: "worker-1",
			setup: func(s *claimMockStore) {
				s.claimedRun = claimedRun()
			},
			check: func(t *testing.T, result *ClaimResult, _ *claimMockStore) {
				t.Helper()
				if result.Attempt.ID == "" {
					t.Error("attempt.ID should be set by IDFunc")
				}
				if !strings.HasPrefix(result.Attempt.ID, "attempt-") {
					t.Errorf("attempt.ID = %q, want prefix %q", result.Attempt.ID, "attempt-")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idSeq = 0
			store := newClaimMockStore()
			if tt.setup != nil {
				tt.setup(store)
			}

			svc := NewClaimService(store, ClaimConfig{
				LeaseDuration: 30 * time.Second,
				IDFunc:        idFunc,
			})

			result, err := svc.ClaimAndLock(context.Background(), tt.workerID)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
				}
				if tt.check != nil {
					tt.check(t, nil, store)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if tt.check != nil {
				tt.check(t, result, store)
			}
		})
	}
}

func TestNewClaimServiceDefaults(t *testing.T) {
	store := newClaimMockStore()

	svc := NewClaimService(store, ClaimConfig{})
	if svc.config.LeaseDuration != 30*time.Second {
		t.Errorf("LeaseDuration = %v, want 30s", svc.config.LeaseDuration)
	}
}

func TestClaimAttemptNumberAlignment(t *testing.T) {
	idSeq := 0
	idFunc := func() string {
		idSeq++
		return fmt.Sprintf("attempt-%d", idSeq)
	}

	t.Run("first claim returns attempt number 1", func(t *testing.T) {
		idSeq = 0
		store := newClaimMockStore()
		// Store atomically increments attempt_count from 0 to 1 during ClaimRun.
		r := claimedRun() // AttemptCount: 1
		store.claimedRun = r

		svc := NewClaimService(store, ClaimConfig{
			LeaseDuration: 30 * time.Second,
			IDFunc:        idFunc,
		})

		result, err := svc.ClaimAndLock(context.Background(), "worker-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Attempt.AttemptNumber != 1 {
			t.Errorf("attempt.AttemptNumber = %d, want 1", result.Attempt.AttemptNumber)
		}
		if result.Attempt.AttemptNumber != result.Run.AttemptCount {
			t.Errorf("attempt.AttemptNumber (%d) != run.AttemptCount (%d), want equal",
				result.Attempt.AttemptNumber, result.Run.AttemptCount)
		}
	})

	t.Run("second claim after requeue returns attempt number 2", func(t *testing.T) {
		idSeq = 0
		store := newClaimMockStore()
		// Simulate second claim: store atomically increments attempt_count
		// from 1 to 2 during ClaimRun after a requeue.
		r := claimedRun()
		r.AttemptCount = 2
		store.claimedRun = r

		svc := NewClaimService(store, ClaimConfig{
			LeaseDuration: 30 * time.Second,
			IDFunc:        idFunc,
		})

		result, err := svc.ClaimAndLock(context.Background(), "worker-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Attempt.AttemptNumber != 2 {
			t.Errorf("attempt.AttemptNumber = %d, want 2", result.Attempt.AttemptNumber)
		}
		if result.Attempt.AttemptNumber != result.Run.AttemptCount {
			t.Errorf("attempt.AttemptNumber (%d) != run.AttemptCount (%d), want equal",
				result.Attempt.AttemptNumber, result.Run.AttemptCount)
		}
	})
}

func TestClaimAndLockCustomLeaseDuration(t *testing.T) {
	store := newClaimMockStore()
	store.claimedRun = claimedRun()

	svc := NewClaimService(store, ClaimConfig{
		LeaseDuration: 2 * time.Minute,
		IDFunc:        func() string { return "attempt-custom" },
	})

	result, err := svc.ClaimAndLock(context.Background(), "worker-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify lease duration is respected.
	delta := result.Attempt.LeaseExpiresAt.Sub(result.Attempt.StartedAt)
	if delta != 2*time.Minute {
		t.Errorf("lease duration = %v, want 2m", delta)
	}
}
