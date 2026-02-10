package cloud

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// reconcilerMockStore is a test store for reconciler service tests.
type reconcilerMockStore struct {
	mockStore

	// ListStaleAttempts behavior
	staleAttempts []*Attempt
	listErr       error

	// TransitionAttempt behavior
	transitionAttemptCalls []transitionAttemptCall
	transitionAttemptErr   error

	// InsertEvent tracking
	events         []Event
	insertEventErr error

	// GetRun behavior
	runs      map[string]*Run
	getRunErr error

	// ReleaseAuthLock tracking
	releaseAuthLockCalls []releaseAuthLockCall
	releaseAuthLockErr   error
}

type releaseAuthLockCall struct {
	AuthProfileID string
	RunID         string
	ReleasedAt    time.Time
}

func newReconcilerMockStore() *reconcilerMockStore {
	return &reconcilerMockStore{
		runs: make(map[string]*Run),
	}
}

func (s *reconcilerMockStore) ListStaleAttempts(_ context.Context, _ time.Time) ([]*Attempt, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.staleAttempts, nil
}

func (s *reconcilerMockStore) TransitionAttempt(_ context.Context, attemptID string, status AttemptStatus, endedAt time.Time, errCode, errMsg *string) error {
	s.transitionAttemptCalls = append(s.transitionAttemptCalls, transitionAttemptCall{
		AttemptID:    attemptID,
		Status:       status,
		EndedAt:      endedAt,
		ErrorCode:    errCode,
		ErrorMessage: errMsg,
	})
	if s.transitionAttemptErr != nil {
		return s.transitionAttemptErr
	}
	return nil
}

func (s *reconcilerMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.events = append(s.events, *event)
	if s.insertEventErr != nil {
		return s.insertEventErr
	}
	return nil
}

func (s *reconcilerMockStore) GetRun(_ context.Context, runID string) (*Run, error) {
	if s.getRunErr != nil {
		return nil, s.getRunErr
	}
	r, ok := s.runs[runID]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

func (s *reconcilerMockStore) ReleaseAuthLock(_ context.Context, authProfileID, runID string, releasedAt time.Time) error {
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

func staleAttempt(id, runID string) *Attempt {
	past := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second)
	return &Attempt{
		ID:             id,
		RunID:          runID,
		AttemptNumber:  1,
		WorkerID:       "worker-1",
		Status:         AttemptStatusActive,
		StartedAt:      past,
		HeartbeatAt:    past,
		LeaseExpiresAt: past.Add(30 * time.Second),
	}
}

func runForAttempt(runID, authProfileID string) *Run {
	now := time.Now().UTC().Truncate(time.Second)
	return &Run{
		ID:            runID,
		Repo:          "org/repo",
		BaseBranch:    "main",
		Engine:        "claude",
		AuthProfileID: authProfileID,
		ScopeRef:      "prd-123",
		Status:        RunStatusRunning,
		AttemptCount:  1,
		MaxAttempts:   3,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestReconcile(t *testing.T) {
	evtSeq := 0
	idFunc := func() string {
		evtSeq++
		return fmt.Sprintf("evt-%d", evtSeq)
	}

	tests := []struct {
		name    string
		setup   func(s *reconcilerMockStore)
		wantErr string
		check   func(t *testing.T, result *ReconcileResult, s *reconcilerMockStore)
	}{
		{
			name: "no stale attempts",
			setup: func(s *reconcilerMockStore) {
				s.staleAttempts = nil
			},
			check: func(t *testing.T, result *ReconcileResult, s *reconcilerMockStore) {
				t.Helper()
				if result.Reconciled != 0 {
					t.Errorf("Reconciled = %d, want 0", result.Reconciled)
				}
				if len(result.Errors) != 0 {
					t.Errorf("unexpected errors: %v", result.Errors)
				}
			},
		},
		{
			name: "single stale attempt reconciled",
			setup: func(s *reconcilerMockStore) {
				s.staleAttempts = []*Attempt{staleAttempt("attempt-1", "run-1")}
				s.runs["run-1"] = runForAttempt("run-1", "profile-1")
			},
			check: func(t *testing.T, result *ReconcileResult, s *reconcilerMockStore) {
				t.Helper()
				if result.Reconciled != 1 {
					t.Errorf("Reconciled = %d, want 1", result.Reconciled)
				}
				if len(result.Errors) != 0 {
					t.Errorf("unexpected errors: %v", result.Errors)
				}

				// Verify attempt was marked failed with stale_attempt error code.
				if len(s.transitionAttemptCalls) != 1 {
					t.Fatalf("expected 1 TransitionAttempt call, got %d", len(s.transitionAttemptCalls))
				}
				tc := s.transitionAttemptCalls[0]
				if tc.AttemptID != "attempt-1" {
					t.Errorf("TransitionAttempt.AttemptID = %q, want %q", tc.AttemptID, "attempt-1")
				}
				if tc.Status != AttemptStatusFailed {
					t.Errorf("TransitionAttempt.Status = %q, want %q", tc.Status, AttemptStatusFailed)
				}
				if tc.ErrorCode == nil || *tc.ErrorCode != "stale_attempt" {
					t.Errorf("TransitionAttempt.ErrorCode = %v, want %q", tc.ErrorCode, "stale_attempt")
				}

				// Verify stale_attempt event was emitted.
				if len(s.events) != 1 {
					t.Fatalf("expected 1 event, got %d", len(s.events))
				}
				ev := s.events[0]
				if ev.EventType != "stale_attempt" {
					t.Errorf("event.EventType = %q, want %q", ev.EventType, "stale_attempt")
				}
				if ev.RunID != "run-1" {
					t.Errorf("event.RunID = %q, want %q", ev.RunID, "run-1")
				}
				if ev.AttemptID == nil || *ev.AttemptID != "attempt-1" {
					t.Errorf("event.AttemptID = %v, want %q", ev.AttemptID, "attempt-1")
				}
				if ev.ID != "evt-1" {
					t.Errorf("event.ID = %q, want %q", ev.ID, "evt-1")
				}

				// Verify auth lock was released.
				if len(s.releaseAuthLockCalls) != 1 {
					t.Fatalf("expected 1 ReleaseAuthLock call, got %d", len(s.releaseAuthLockCalls))
				}
				rc := s.releaseAuthLockCalls[0]
				if rc.AuthProfileID != "profile-1" {
					t.Errorf("ReleaseAuthLock.AuthProfileID = %q, want %q", rc.AuthProfileID, "profile-1")
				}
				if rc.RunID != "run-1" {
					t.Errorf("ReleaseAuthLock.RunID = %q, want %q", rc.RunID, "run-1")
				}
			},
		},
		{
			name: "multiple stale attempts reconciled",
			setup: func(s *reconcilerMockStore) {
				s.staleAttempts = []*Attempt{
					staleAttempt("attempt-1", "run-1"),
					staleAttempt("attempt-2", "run-2"),
				}
				s.runs["run-1"] = runForAttempt("run-1", "profile-1")
				s.runs["run-2"] = runForAttempt("run-2", "profile-2")
			},
			check: func(t *testing.T, result *ReconcileResult, s *reconcilerMockStore) {
				t.Helper()
				if result.Reconciled != 2 {
					t.Errorf("Reconciled = %d, want 2", result.Reconciled)
				}
				if len(s.transitionAttemptCalls) != 2 {
					t.Errorf("expected 2 TransitionAttempt calls, got %d", len(s.transitionAttemptCalls))
				}
				if len(s.events) != 2 {
					t.Errorf("expected 2 events, got %d", len(s.events))
				}
				if len(s.releaseAuthLockCalls) != 2 {
					t.Errorf("expected 2 ReleaseAuthLock calls, got %d", len(s.releaseAuthLockCalls))
				}
			},
		},
		{
			name: "list stale attempts fails",
			setup: func(s *reconcilerMockStore) {
				s.listErr = fmt.Errorf("database unavailable")
			},
			wantErr: "failed to list stale attempts: database unavailable",
		},
		{
			name: "transition attempt fails collects error and continues",
			setup: func(s *reconcilerMockStore) {
				s.staleAttempts = []*Attempt{
					staleAttempt("attempt-1", "run-1"),
					staleAttempt("attempt-2", "run-2"),
				}
				s.runs["run-1"] = runForAttempt("run-1", "profile-1")
				s.runs["run-2"] = runForAttempt("run-2", "profile-2")
				s.transitionAttemptErr = fmt.Errorf("transition failed")
			},
			check: func(t *testing.T, result *ReconcileResult, _ *reconcilerMockStore) {
				t.Helper()
				if result.Reconciled != 0 {
					t.Errorf("Reconciled = %d, want 0", result.Reconciled)
				}
				if len(result.Errors) != 2 {
					t.Fatalf("expected 2 errors, got %d", len(result.Errors))
				}
				for _, e := range result.Errors {
					if !strings.Contains(e.Error(), "failed to transition attempt") {
						t.Errorf("error = %q, want containing %q", e.Error(), "failed to transition attempt")
					}
				}
			},
		},
		{
			name: "insert event fails collects error and continues",
			setup: func(s *reconcilerMockStore) {
				s.staleAttempts = []*Attempt{
					staleAttempt("attempt-1", "run-1"),
					staleAttempt("attempt-2", "run-2"),
				}
				s.runs["run-1"] = runForAttempt("run-1", "profile-1")
				s.runs["run-2"] = runForAttempt("run-2", "profile-2")
				s.insertEventErr = fmt.Errorf("event insert failed")
			},
			check: func(t *testing.T, result *ReconcileResult, _ *reconcilerMockStore) {
				t.Helper()
				if result.Reconciled != 0 {
					t.Errorf("Reconciled = %d, want 0", result.Reconciled)
				}
				if len(result.Errors) != 2 {
					t.Fatalf("expected 2 errors, got %d", len(result.Errors))
				}
				for _, e := range result.Errors {
					if !strings.Contains(e.Error(), "failed to insert stale_attempt event") {
						t.Errorf("error = %q, want containing %q", e.Error(), "failed to insert stale_attempt event")
					}
				}
			},
		},
		{
			name: "get run fails collects error",
			setup: func(s *reconcilerMockStore) {
				s.staleAttempts = []*Attempt{staleAttempt("attempt-1", "run-1")}
				// Don't add run to map — will return ErrNotFound.
			},
			check: func(t *testing.T, result *ReconcileResult, _ *reconcilerMockStore) {
				t.Helper()
				if result.Reconciled != 0 {
					t.Errorf("Reconciled = %d, want 0", result.Reconciled)
				}
				if len(result.Errors) != 1 {
					t.Fatalf("expected 1 error, got %d", len(result.Errors))
				}
				if !strings.Contains(result.Errors[0].Error(), "failed to get run for lock release") {
					t.Errorf("error = %q, want containing %q", result.Errors[0].Error(), "failed to get run for lock release")
				}
			},
		},
		{
			name: "release auth lock not found is tolerated",
			setup: func(s *reconcilerMockStore) {
				s.staleAttempts = []*Attempt{staleAttempt("attempt-1", "run-1")}
				s.runs["run-1"] = runForAttempt("run-1", "profile-1")
				s.releaseAuthLockErr = ErrNotFound
			},
			check: func(t *testing.T, result *ReconcileResult, s *reconcilerMockStore) {
				t.Helper()
				// ErrNotFound on lock release is tolerated — lock may have already been released.
				if result.Reconciled != 1 {
					t.Errorf("Reconciled = %d, want 1", result.Reconciled)
				}
				if len(result.Errors) != 0 {
					t.Errorf("unexpected errors: %v", result.Errors)
				}
				if len(s.releaseAuthLockCalls) != 1 {
					t.Errorf("expected 1 ReleaseAuthLock call, got %d", len(s.releaseAuthLockCalls))
				}
			},
		},
		{
			name: "release auth lock non-not-found error collects error",
			setup: func(s *reconcilerMockStore) {
				s.staleAttempts = []*Attempt{staleAttempt("attempt-1", "run-1")}
				s.runs["run-1"] = runForAttempt("run-1", "profile-1")
				s.releaseAuthLockErr = fmt.Errorf("lock table corrupted")
			},
			check: func(t *testing.T, result *ReconcileResult, _ *reconcilerMockStore) {
				t.Helper()
				if result.Reconciled != 0 {
					t.Errorf("Reconciled = %d, want 0", result.Reconciled)
				}
				if len(result.Errors) != 1 {
					t.Fatalf("expected 1 error, got %d", len(result.Errors))
				}
				if !strings.Contains(result.Errors[0].Error(), "failed to release auth lock") {
					t.Errorf("error = %q, want containing %q", result.Errors[0].Error(), "failed to release auth lock")
				}
			},
		},
		{
			name: "partial success with mixed results",
			setup: func(s *reconcilerMockStore) {
				s.staleAttempts = []*Attempt{
					staleAttempt("attempt-1", "run-1"),
					staleAttempt("attempt-2", "run-2"),
				}
				s.runs["run-1"] = runForAttempt("run-1", "profile-1")
				// run-2 is missing — will fail on GetRun.
			},
			check: func(t *testing.T, result *ReconcileResult, _ *reconcilerMockStore) {
				t.Helper()
				if result.Reconciled != 1 {
					t.Errorf("Reconciled = %d, want 1", result.Reconciled)
				}
				if len(result.Errors) != 1 {
					t.Fatalf("expected 1 error, got %d", len(result.Errors))
				}
				if !strings.Contains(result.Errors[0].Error(), "attempt-2") {
					t.Errorf("error = %q, want containing %q", result.Errors[0].Error(), "attempt-2")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evtSeq = 0
			store := newReconcilerMockStore()
			if tt.setup != nil {
				tt.setup(store)
			}

			svc := NewReconcilerService(store, ReconcilerConfig{
				IDFunc: idFunc,
			})

			cutoff := time.Now().UTC().Truncate(time.Second)
			result, err := svc.Reconcile(context.Background(), cutoff)

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

func TestReconcileEventUsesIDFunc(t *testing.T) {
	seq := 0
	idFunc := func() string {
		seq++
		return fmt.Sprintf("custom-evt-%d", seq)
	}

	store := newReconcilerMockStore()
	store.staleAttempts = []*Attempt{staleAttempt("attempt-1", "run-1")}
	store.runs["run-1"] = runForAttempt("run-1", "profile-1")

	svc := NewReconcilerService(store, ReconcilerConfig{IDFunc: idFunc})

	result, err := svc.Reconcile(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reconciled != 1 {
		t.Fatalf("Reconciled = %d, want 1", result.Reconciled)
	}
	if len(store.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(store.events))
	}
	if store.events[0].ID != "custom-evt-1" {
		t.Errorf("event.ID = %q, want %q", store.events[0].ID, "custom-evt-1")
	}
}
