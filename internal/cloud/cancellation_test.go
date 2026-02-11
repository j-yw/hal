package cloud

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// cancelMockStore is a test store for cancellation service tests.
type cancelMockStore struct {
	mockStore

	// GetRun behavior
	runs      map[string]*Run
	getRunErr error

	// SetCancelIntent behavior
	setCancelIntentCalls []string
	setCancelIntentErr   error

	// TransitionRun tracking
	transitionRunCalls []transitionRunCall

	// TransitionAttempt tracking
	transitionAttemptCalls []transitionAttemptCall

	// InsertEvent tracking
	events []Event

	// ReleaseAuthLock tracking
	releaseAuthLockCalls []releaseAuthLockCall
	releaseAuthLockErr   error
}

func newCancelMockStore() *cancelMockStore {
	return &cancelMockStore{
		runs: make(map[string]*Run),
	}
}

func (s *cancelMockStore) GetRun(_ context.Context, runID string) (*Run, error) {
	if s.getRunErr != nil {
		return nil, s.getRunErr
	}
	r, ok := s.runs[runID]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

func (s *cancelMockStore) SetCancelIntent(_ context.Context, runID string) error {
	s.setCancelIntentCalls = append(s.setCancelIntentCalls, runID)
	if s.setCancelIntentErr != nil {
		return s.setCancelIntentErr
	}
	return nil
}

func (s *cancelMockStore) TransitionRun(_ context.Context, runID string, from, to RunStatus) error {
	s.transitionRunCalls = append(s.transitionRunCalls, transitionRunCall{
		RunID:      runID,
		FromStatus: from,
		ToStatus:   to,
	})
	return nil
}

func (s *cancelMockStore) TransitionAttempt(_ context.Context, attemptID string, status AttemptStatus, endedAt time.Time, errCode, errMsg *string) error {
	s.transitionAttemptCalls = append(s.transitionAttemptCalls, transitionAttemptCall{
		AttemptID:    attemptID,
		Status:       status,
		EndedAt:      endedAt,
		ErrorCode:    errCode,
		ErrorMessage: errMsg,
	})
	return nil
}

func (s *cancelMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.events = append(s.events, *event)
	return nil
}

func (s *cancelMockStore) ReleaseAuthLock(_ context.Context, authProfileID, runID string, releasedAt time.Time) error {
	s.releaseAuthLockCalls = append(s.releaseAuthLockCalls, releaseAuthLockCall{
		AuthProfileID: authProfileID,
		RunID:         runID,
		ReleasedAt:    releasedAt,
	})
	if s.releaseAuthLockErr != nil {
		return s.releaseAuthLockErr
	}
	return nil
}

func runningRun(id string) *Run {
	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(1 * time.Hour)
	return &Run{
		ID:            id,
		Repo:          "org/repo",
		BaseBranch:    "main",
		WorkflowKind:  WorkflowKindRun,
		Engine:        "claude",
		AuthProfileID: "profile-1",
		ScopeRef:      "prd-123",
		Status:        RunStatusRunning,
		AttemptCount:  1,
		MaxAttempts:   3,
		DeadlineAt:    &deadline,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestRequestCancel(t *testing.T) {
	tests := []struct {
		name    string
		runID   string
		setup   func(s *cancelMockStore)
		wantErr string
		check   func(t *testing.T, s *cancelMockStore)
	}{
		{
			name:  "successful cancel request",
			runID: "run-1",
			setup: func(s *cancelMockStore) {},
			check: func(t *testing.T, s *cancelMockStore) {
				t.Helper()
				if len(s.setCancelIntentCalls) != 1 {
					t.Fatalf("expected 1 SetCancelIntent call, got %d", len(s.setCancelIntentCalls))
				}
				if s.setCancelIntentCalls[0] != "run-1" {
					t.Errorf("SetCancelIntent runID = %q, want %q", s.setCancelIntentCalls[0], "run-1")
				}
			},
		},
		{
			name:    "empty runID",
			runID:   "",
			setup:   func(s *cancelMockStore) {},
			wantErr: "runID must not be empty",
		},
		{
			name:  "run not found",
			runID: "run-missing",
			setup: func(s *cancelMockStore) {
				s.setCancelIntentErr = ErrNotFound
			},
			wantErr: "not_found",
		},
		{
			name:  "store error propagates",
			runID: "run-1",
			setup: func(s *cancelMockStore) {
				s.setCancelIntentErr = fmt.Errorf("database unavailable")
			},
			wantErr: "database unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newCancelMockStore()
			if tt.setup != nil {
				tt.setup(store)
			}

			svc := NewCancellationService(store, CancellationConfig{})
			err := svc.RequestCancel(context.Background(), tt.runID)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
				}
				if tt.check != nil {
					tt.check(t, store)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, store)
			}
		})
	}
}

func TestCheckAndCancel(t *testing.T) {
	evtSeq := 0
	idFunc := func() string {
		evtSeq++
		return fmt.Sprintf("evt-%d", evtSeq)
	}

	tests := []struct {
		name          string
		runID         string
		attemptID     string
		authProfileID string
		setup         func(s *cancelMockStore)
		wantErr       string
		check         func(t *testing.T, result *CheckAndCancelResult, s *cancelMockStore)
	}{
		{
			name:          "cancel requested propagates to attempt and run",
			runID:         "run-1",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			setup: func(s *cancelMockStore) {
				r := runningRun("run-1")
				r.CancelRequested = true
				s.runs["run-1"] = r
			},
			check: func(t *testing.T, result *CheckAndCancelResult, s *cancelMockStore) {
				t.Helper()
				if !result.Canceled {
					t.Error("expected Canceled = true")
				}

				// Verify attempt was marked canceled.
				if len(s.transitionAttemptCalls) != 1 {
					t.Fatalf("expected 1 TransitionAttempt call, got %d", len(s.transitionAttemptCalls))
				}
				ac := s.transitionAttemptCalls[0]
				if ac.AttemptID != "attempt-1" {
					t.Errorf("attempt.ID = %q, want %q", ac.AttemptID, "attempt-1")
				}
				if ac.Status != AttemptStatusCanceled {
					t.Errorf("attempt.Status = %q, want %q", ac.Status, AttemptStatusCanceled)
				}
				if ac.ErrorCode == nil || *ac.ErrorCode != "canceled" {
					t.Errorf("attempt.ErrorCode = %v, want %q", ac.ErrorCode, "canceled")
				}

				// Verify run was transitioned to canceled.
				if len(s.transitionRunCalls) != 1 {
					t.Fatalf("expected 1 TransitionRun call, got %d", len(s.transitionRunCalls))
				}
				rc := s.transitionRunCalls[0]
				if rc.RunID != "run-1" {
					t.Errorf("run.ID = %q, want %q", rc.RunID, "run-1")
				}
				if rc.FromStatus != RunStatusRunning {
					t.Errorf("from = %q, want %q", rc.FromStatus, RunStatusRunning)
				}
				if rc.ToStatus != RunStatusCanceled {
					t.Errorf("to = %q, want %q", rc.ToStatus, RunStatusCanceled)
				}

				// Verify cancel_propagated event.
				if len(s.events) != 1 {
					t.Fatalf("expected 1 event, got %d", len(s.events))
				}
				ev := s.events[0]
				if ev.EventType != "cancel_propagated" {
					t.Errorf("event.EventType = %q, want %q", ev.EventType, "cancel_propagated")
				}
				if ev.RunID != "run-1" {
					t.Errorf("event.RunID = %q, want %q", ev.RunID, "run-1")
				}
				if ev.AttemptID == nil || *ev.AttemptID != "attempt-1" {
					t.Errorf("event.AttemptID = %v, want %q", ev.AttemptID, "attempt-1")
				}

				// Verify auth lock was released.
				if len(s.releaseAuthLockCalls) != 1 {
					t.Fatalf("expected 1 ReleaseAuthLock call, got %d", len(s.releaseAuthLockCalls))
				}
				rl := s.releaseAuthLockCalls[0]
				if rl.AuthProfileID != "profile-1" {
					t.Errorf("lock.AuthProfileID = %q, want %q", rl.AuthProfileID, "profile-1")
				}
				if rl.RunID != "run-1" {
					t.Errorf("lock.RunID = %q, want %q", rl.RunID, "run-1")
				}
			},
		},
		{
			name:          "no cancel requested is a no-op",
			runID:         "run-1",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			setup: func(s *cancelMockStore) {
				r := runningRun("run-1")
				r.CancelRequested = false
				s.runs["run-1"] = r
			},
			check: func(t *testing.T, result *CheckAndCancelResult, s *cancelMockStore) {
				t.Helper()
				if result.Canceled {
					t.Error("expected Canceled = false")
				}
				if len(s.transitionAttemptCalls) != 0 {
					t.Errorf("unexpected TransitionAttempt calls: %d", len(s.transitionAttemptCalls))
				}
				if len(s.transitionRunCalls) != 0 {
					t.Errorf("unexpected TransitionRun calls: %d", len(s.transitionRunCalls))
				}
				if len(s.events) != 0 {
					t.Errorf("unexpected events: %d", len(s.events))
				}
				if len(s.releaseAuthLockCalls) != 0 {
					t.Errorf("unexpected ReleaseAuthLock calls: %d", len(s.releaseAuthLockCalls))
				}
			},
		},
		{
			name:          "empty runID",
			runID:         "",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			setup:         func(s *cancelMockStore) {},
			wantErr:       "runID must not be empty",
		},
		{
			name:          "empty attemptID",
			runID:         "run-1",
			attemptID:     "",
			authProfileID: "profile-1",
			setup:         func(s *cancelMockStore) {},
			wantErr:       "attemptID must not be empty",
		},
		{
			name:          "empty authProfileID",
			runID:         "run-1",
			attemptID:     "attempt-1",
			authProfileID: "",
			setup:         func(s *cancelMockStore) {},
			wantErr:       "authProfileID must not be empty",
		},
		{
			name:          "run not found",
			runID:         "run-missing",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			setup:         func(s *cancelMockStore) {},
			wantErr:       "failed to get run",
		},
		{
			name:          "get run store error",
			runID:         "run-1",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			setup: func(s *cancelMockStore) {
				s.getRunErr = fmt.Errorf("database unavailable")
			},
			wantErr: "failed to get run: database unavailable",
		},
		{
			name:          "release auth lock tolerates ErrNotFound",
			runID:         "run-1",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			setup: func(s *cancelMockStore) {
				r := runningRun("run-1")
				r.CancelRequested = true
				s.runs["run-1"] = r
				s.releaseAuthLockErr = ErrNotFound
			},
			check: func(t *testing.T, result *CheckAndCancelResult, s *cancelMockStore) {
				t.Helper()
				if !result.Canceled {
					t.Error("expected Canceled = true even when lock was already released")
				}
			},
		},
		{
			name:          "release auth lock non-NotFound error propagates",
			runID:         "run-1",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			setup: func(s *cancelMockStore) {
				r := runningRun("run-1")
				r.CancelRequested = true
				s.runs["run-1"] = r
				s.releaseAuthLockErr = fmt.Errorf("lock table corrupted")
			},
			wantErr: "failed to release auth lock: lock table corrupted",
		},
		{
			name:          "event ID set by IDFunc",
			runID:         "run-1",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			setup: func(s *cancelMockStore) {
				r := runningRun("run-1")
				r.CancelRequested = true
				s.runs["run-1"] = r
			},
			check: func(t *testing.T, result *CheckAndCancelResult, s *cancelMockStore) {
				t.Helper()
				if len(s.events) != 1 {
					t.Fatalf("expected 1 event, got %d", len(s.events))
				}
				if s.events[0].ID != "evt-1" {
					t.Errorf("event.ID = %q, want %q", s.events[0].ID, "evt-1")
				}
			},
		},
		{
			name:          "cancel from claimed status",
			runID:         "run-1",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			setup: func(s *cancelMockStore) {
				r := runningRun("run-1")
				r.Status = RunStatusClaimed
				r.CancelRequested = true
				s.runs["run-1"] = r
			},
			check: func(t *testing.T, result *CheckAndCancelResult, s *cancelMockStore) {
				t.Helper()
				if !result.Canceled {
					t.Error("expected Canceled = true")
				}
				if len(s.transitionRunCalls) != 1 {
					t.Fatalf("expected 1 TransitionRun call, got %d", len(s.transitionRunCalls))
				}
				rc := s.transitionRunCalls[0]
				if rc.FromStatus != RunStatusClaimed {
					t.Errorf("from = %q, want %q", rc.FromStatus, RunStatusClaimed)
				}
				if rc.ToStatus != RunStatusCanceled {
					t.Errorf("to = %q, want %q", rc.ToStatus, RunStatusCanceled)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evtSeq = 0
			store := newCancelMockStore()
			if tt.setup != nil {
				tt.setup(store)
			}

			svc := NewCancellationService(store, CancellationConfig{
				IDFunc: idFunc,
			})

			result, err := svc.CheckAndCancel(context.Background(), tt.runID, tt.attemptID, tt.authProfileID)

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
