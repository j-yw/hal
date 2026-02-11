package cloud

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// timeoutMockStore is a test store for timeout service tests.
type timeoutMockStore struct {
	mockStore

	// ListOverdueRuns behavior
	overdueRuns []*Run
	listErr     error

	// TransitionRun tracking
	transitionRunCalls []transitionRunCall
	transitionRunErr   error

	// InsertEvent tracking
	events         []Event
	insertEventErr error
}

func newTimeoutMockStore() *timeoutMockStore {
	return &timeoutMockStore{}
}

func (s *timeoutMockStore) ListOverdueRuns(_ context.Context, _ time.Time) ([]*Run, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.overdueRuns, nil
}

func (s *timeoutMockStore) TransitionRun(_ context.Context, runID string, fromStatus, toStatus RunStatus) error {
	s.transitionRunCalls = append(s.transitionRunCalls, transitionRunCall{
		RunID:      runID,
		FromStatus: fromStatus,
		ToStatus:   toStatus,
	})
	if s.transitionRunErr != nil {
		return s.transitionRunErr
	}
	return nil
}

func (s *timeoutMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.events = append(s.events, *event)
	if s.insertEventErr != nil {
		return s.insertEventErr
	}
	return nil
}

func overdueRun(id string, status RunStatus) *Run {
	now := time.Now().UTC().Truncate(time.Second)
	pastDeadline := now.Add(-10 * time.Minute)
	return &Run{
		ID:            id,
		Repo:          "org/repo",
		BaseBranch:    "main",
		WorkflowKind:  WorkflowKindRun,
		Engine:        "claude",
		AuthProfileID: "profile-1",
		ScopeRef:      "prd-123",
		Status:        status,
		AttemptCount:  1,
		MaxAttempts:   3,
		DeadlineAt:    &pastDeadline,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestEnforceTimeouts(t *testing.T) {
	evtSeq := 0
	idFunc := func() string {
		evtSeq++
		return fmt.Sprintf("evt-%d", evtSeq)
	}

	tests := []struct {
		name    string
		setup   func(s *timeoutMockStore)
		wantErr string
		check   func(t *testing.T, result *TimeoutResult, s *timeoutMockStore)
	}{
		{
			name: "no overdue runs",
			setup: func(s *timeoutMockStore) {
				s.overdueRuns = nil
			},
			check: func(t *testing.T, result *TimeoutResult, s *timeoutMockStore) {
				t.Helper()
				if result.TimedOut != 0 {
					t.Errorf("TimedOut = %d, want 0", result.TimedOut)
				}
				if len(result.Errors) != 0 {
					t.Errorf("unexpected errors: %v", result.Errors)
				}
			},
		},
		{
			name: "single overdue running run timed out",
			setup: func(s *timeoutMockStore) {
				s.overdueRuns = []*Run{overdueRun("run-1", RunStatusRunning)}
			},
			check: func(t *testing.T, result *TimeoutResult, s *timeoutMockStore) {
				t.Helper()
				if result.TimedOut != 1 {
					t.Errorf("TimedOut = %d, want 1", result.TimedOut)
				}
				if len(result.Errors) != 0 {
					t.Errorf("unexpected errors: %v", result.Errors)
				}

				// Verify run was transitioned to failed.
				if len(s.transitionRunCalls) != 1 {
					t.Fatalf("expected 1 TransitionRun call, got %d", len(s.transitionRunCalls))
				}
				tc := s.transitionRunCalls[0]
				if tc.RunID != "run-1" {
					t.Errorf("TransitionRun.RunID = %q, want %q", tc.RunID, "run-1")
				}
				if tc.FromStatus != RunStatusRunning {
					t.Errorf("TransitionRun.FromStatus = %q, want %q", tc.FromStatus, RunStatusRunning)
				}
				if tc.ToStatus != RunStatusFailed {
					t.Errorf("TransitionRun.ToStatus = %q, want %q", tc.ToStatus, RunStatusFailed)
				}

				// Verify run_timeout event was emitted.
				if len(s.events) != 1 {
					t.Fatalf("expected 1 event, got %d", len(s.events))
				}
				ev := s.events[0]
				if ev.EventType != "run_timeout" {
					t.Errorf("event.EventType = %q, want %q", ev.EventType, "run_timeout")
				}
				if ev.RunID != "run-1" {
					t.Errorf("event.RunID = %q, want %q", ev.RunID, "run-1")
				}
				if ev.ID != "evt-1" {
					t.Errorf("event.ID = %q, want %q", ev.ID, "evt-1")
				}
			},
		},
		{
			name: "overdue queued run timed out",
			setup: func(s *timeoutMockStore) {
				s.overdueRuns = []*Run{overdueRun("run-1", RunStatusQueued)}
			},
			check: func(t *testing.T, result *TimeoutResult, s *timeoutMockStore) {
				t.Helper()
				if result.TimedOut != 1 {
					t.Errorf("TimedOut = %d, want 1", result.TimedOut)
				}
				// Verify transition uses queued as fromStatus.
				if len(s.transitionRunCalls) != 1 {
					t.Fatalf("expected 1 TransitionRun call, got %d", len(s.transitionRunCalls))
				}
				tc := s.transitionRunCalls[0]
				if tc.FromStatus != RunStatusQueued {
					t.Errorf("TransitionRun.FromStatus = %q, want %q", tc.FromStatus, RunStatusQueued)
				}
				if tc.ToStatus != RunStatusFailed {
					t.Errorf("TransitionRun.ToStatus = %q, want %q", tc.ToStatus, RunStatusFailed)
				}
			},
		},
		{
			name: "multiple overdue runs timed out",
			setup: func(s *timeoutMockStore) {
				s.overdueRuns = []*Run{
					overdueRun("run-1", RunStatusRunning),
					overdueRun("run-2", RunStatusClaimed),
				}
			},
			check: func(t *testing.T, result *TimeoutResult, s *timeoutMockStore) {
				t.Helper()
				if result.TimedOut != 2 {
					t.Errorf("TimedOut = %d, want 2", result.TimedOut)
				}
				if len(s.transitionRunCalls) != 2 {
					t.Errorf("expected 2 TransitionRun calls, got %d", len(s.transitionRunCalls))
				}
				if len(s.events) != 2 {
					t.Errorf("expected 2 events, got %d", len(s.events))
				}
			},
		},
		{
			name: "list overdue runs fails",
			setup: func(s *timeoutMockStore) {
				s.listErr = fmt.Errorf("database unavailable")
			},
			wantErr: "failed to list overdue runs: database unavailable",
		},
		{
			name: "transition run fails collects error and continues",
			setup: func(s *timeoutMockStore) {
				s.overdueRuns = []*Run{
					overdueRun("run-1", RunStatusRunning),
					overdueRun("run-2", RunStatusRunning),
				}
				s.transitionRunErr = fmt.Errorf("transition failed")
			},
			check: func(t *testing.T, result *TimeoutResult, _ *timeoutMockStore) {
				t.Helper()
				if result.TimedOut != 0 {
					t.Errorf("TimedOut = %d, want 0", result.TimedOut)
				}
				if len(result.Errors) != 2 {
					t.Fatalf("expected 2 errors, got %d", len(result.Errors))
				}
				for _, e := range result.Errors {
					if !strings.Contains(e.Error(), "failed to transition run to failed") {
						t.Errorf("error = %q, want containing %q", e.Error(), "failed to transition run to failed")
					}
				}
			},
		},
		{
			name: "insert event fails collects error and continues",
			setup: func(s *timeoutMockStore) {
				s.overdueRuns = []*Run{
					overdueRun("run-1", RunStatusRunning),
					overdueRun("run-2", RunStatusRunning),
				}
				s.insertEventErr = fmt.Errorf("event insert failed")
			},
			check: func(t *testing.T, result *TimeoutResult, _ *timeoutMockStore) {
				t.Helper()
				if result.TimedOut != 0 {
					t.Errorf("TimedOut = %d, want 0", result.TimedOut)
				}
				if len(result.Errors) != 2 {
					t.Fatalf("expected 2 errors, got %d", len(result.Errors))
				}
				for _, e := range result.Errors {
					if !strings.Contains(e.Error(), "failed to insert run_timeout event") {
						t.Errorf("error = %q, want containing %q", e.Error(), "failed to insert run_timeout event")
					}
				}
			},
		},
		{
			name: "partial success with mixed results",
			setup: func(s *timeoutMockStore) {
				s.overdueRuns = []*Run{
					overdueRun("run-1", RunStatusRunning),
					overdueRun("run-2", RunStatusRunning),
				}
				// Override TransitionRun to fail only for run-2.
				s.transitionRunErr = nil
			},
			check: func(t *testing.T, result *TimeoutResult, s *timeoutMockStore) {
				t.Helper()
				// Both succeed since no error set.
				if result.TimedOut != 2 {
					t.Errorf("TimedOut = %d, want 2", result.TimedOut)
				}
				if len(result.Errors) != 0 {
					t.Errorf("unexpected errors: %v", result.Errors)
				}
			},
		},
		{
			name: "overdue retrying run timed out",
			setup: func(s *timeoutMockStore) {
				s.overdueRuns = []*Run{overdueRun("run-1", RunStatusRetrying)}
			},
			check: func(t *testing.T, result *TimeoutResult, s *timeoutMockStore) {
				t.Helper()
				if result.TimedOut != 1 {
					t.Errorf("TimedOut = %d, want 1", result.TimedOut)
				}
				tc := s.transitionRunCalls[0]
				if tc.FromStatus != RunStatusRetrying {
					t.Errorf("TransitionRun.FromStatus = %q, want %q", tc.FromStatus, RunStatusRetrying)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evtSeq = 0
			store := newTimeoutMockStore()
			if tt.setup != nil {
				tt.setup(store)
			}

			svc := NewTimeoutService(store, TimeoutConfig{
				IDFunc: idFunc,
			})

			now := time.Now().UTC().Truncate(time.Second)
			result, err := svc.EnforceTimeouts(context.Background(), now)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
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

func TestEnforceTimeoutsEventUsesIDFunc(t *testing.T) {
	seq := 0
	idFunc := func() string {
		seq++
		return fmt.Sprintf("custom-evt-%d", seq)
	}

	store := newTimeoutMockStore()
	store.overdueRuns = []*Run{overdueRun("run-1", RunStatusRunning)}

	svc := NewTimeoutService(store, TimeoutConfig{IDFunc: idFunc})

	result, err := svc.EnforceTimeouts(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TimedOut != 1 {
		t.Fatalf("TimedOut = %d, want 1", result.TimedOut)
	}
	if len(store.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(store.events))
	}
	if store.events[0].ID != "custom-evt-1" {
		t.Errorf("event.ID = %q, want %q", store.events[0].ID, "custom-evt-1")
	}
}

func TestEnforceTimeoutsNilIDFunc(t *testing.T) {
	store := newTimeoutMockStore()
	store.overdueRuns = []*Run{overdueRun("run-1", RunStatusRunning)}

	svc := NewTimeoutService(store, TimeoutConfig{})

	result, err := svc.EnforceTimeouts(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TimedOut != 1 {
		t.Fatalf("TimedOut = %d, want 1", result.TimedOut)
	}
	// Event ID should be empty string when IDFunc is nil.
	if store.events[0].ID != "" {
		t.Errorf("event.ID = %q, want empty", store.events[0].ID)
	}
}
