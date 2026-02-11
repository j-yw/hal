package cloud

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// retryMockStore is a test store for retry service tests.
type retryMockStore struct {
	mockStore

	// GetRun behavior
	runs      map[string]*Run
	getRunErr error

	// TransitionRun tracking
	transitionRunCalls []transitionRunCall
	transitionRunErr   error

	// InsertEvent tracking
	events         []Event
	insertEventErr error
}

func newRetryMockStore() *retryMockStore {
	return &retryMockStore{
		runs: make(map[string]*Run),
	}
}

func (s *retryMockStore) GetRun(_ context.Context, runID string) (*Run, error) {
	if s.getRunErr != nil {
		return nil, s.getRunErr
	}
	r, ok := s.runs[runID]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

func (s *retryMockStore) TransitionRun(_ context.Context, runID string, from, to RunStatus) error {
	s.transitionRunCalls = append(s.transitionRunCalls, transitionRunCall{
		RunID:      runID,
		FromStatus: from,
		ToStatus:   to,
	})
	if s.transitionRunErr != nil {
		return s.transitionRunErr
	}
	return nil
}

func (s *retryMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.events = append(s.events, *event)
	if s.insertEventErr != nil {
		return s.insertEventErr
	}
	return nil
}

func failedRun(id string, attemptCount, maxAttempts int) *Run {
	now := time.Now().UTC().Truncate(time.Second)
	return &Run{
		ID:            id,
		Repo:          "org/repo",
		BaseBranch:    "main",
		WorkflowKind:  WorkflowKindRun,
		Engine:        "claude",
		AuthProfileID: "profile-1",
		ScopeRef:      "prd-123",
		Status:        RunStatusFailed,
		AttemptCount:  attemptCount,
		MaxAttempts:   maxAttempts,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestEvaluateRetry(t *testing.T) {
	evtSeq := 0
	idFunc := func() string {
		evtSeq++
		return fmt.Sprintf("evt-%d", evtSeq)
	}

	tests := []struct {
		name        string
		runID       string
		failureCode FailureCode
		setup       func(s *retryMockStore)
		wantErr     string
		check       func(t *testing.T, result *RetryResult, s *retryMockStore)
	}{
		{
			name:        "retryable failure with budget remaining",
			runID:       "run-1",
			failureCode: FailureBootstrapFailed,
			setup: func(s *retryMockStore) {
				s.runs["run-1"] = failedRun("run-1", 1, 3)
			},
			check: func(t *testing.T, result *RetryResult, s *retryMockStore) {
				t.Helper()
				if !result.Retried {
					t.Error("expected Retried=true")
				}
				if result.BackoffDelay != 30*time.Second {
					t.Errorf("BackoffDelay = %v, want 30s", result.BackoffDelay)
				}
				// Should have two TransitionRun calls: failed→retrying, retrying→queued.
				if len(s.transitionRunCalls) != 2 {
					t.Fatalf("expected 2 TransitionRun calls, got %d", len(s.transitionRunCalls))
				}
				tc1 := s.transitionRunCalls[0]
				if tc1.FromStatus != RunStatusFailed || tc1.ToStatus != RunStatusRetrying {
					t.Errorf("transition 1: %s→%s, want failed→retrying", tc1.FromStatus, tc1.ToStatus)
				}
				tc2 := s.transitionRunCalls[1]
				if tc2.FromStatus != RunStatusRetrying || tc2.ToStatus != RunStatusQueued {
					t.Errorf("transition 2: %s→%s, want retrying→queued", tc2.FromStatus, tc2.ToStatus)
				}
				// Should emit retry_scheduled event.
				if len(s.events) != 1 {
					t.Fatalf("expected 1 event, got %d", len(s.events))
				}
				if s.events[0].EventType != "retry_scheduled" {
					t.Errorf("event.EventType = %q, want %q", s.events[0].EventType, "retry_scheduled")
				}
				if s.events[0].RunID != "run-1" {
					t.Errorf("event.RunID = %q, want %q", s.events[0].RunID, "run-1")
				}
			},
		},
		{
			name:        "stale_attempt is retryable",
			runID:       "run-1",
			failureCode: FailureStaleAttempt,
			setup: func(s *retryMockStore) {
				s.runs["run-1"] = failedRun("run-1", 1, 3)
			},
			check: func(t *testing.T, result *RetryResult, _ *retryMockStore) {
				t.Helper()
				if !result.Retried {
					t.Error("expected Retried=true for stale_attempt")
				}
			},
		},
		{
			name:        "non-retryable failure code",
			runID:       "run-1",
			failureCode: FailureAuthInvalid,
			setup: func(s *retryMockStore) {
				s.runs["run-1"] = failedRun("run-1", 1, 3)
			},
			check: func(t *testing.T, result *RetryResult, s *retryMockStore) {
				t.Helper()
				if result.Retried {
					t.Error("expected Retried=false for auth_invalid")
				}
				if len(s.transitionRunCalls) != 0 {
					t.Errorf("expected no TransitionRun calls, got %d", len(s.transitionRunCalls))
				}
			},
		},
		{
			name:        "policy_blocked is non-retryable",
			runID:       "run-1",
			failureCode: FailurePolicyBlocked,
			setup: func(s *retryMockStore) {
				s.runs["run-1"] = failedRun("run-1", 1, 3)
			},
			check: func(t *testing.T, result *RetryResult, _ *retryMockStore) {
				t.Helper()
				if result.Retried {
					t.Error("expected Retried=false for policy_blocked")
				}
			},
		},
		{
			name:        "run_timeout is non-retryable",
			runID:       "run-1",
			failureCode: FailureRunTimeout,
			setup: func(s *retryMockStore) {
				s.runs["run-1"] = failedRun("run-1", 1, 3)
			},
			check: func(t *testing.T, result *RetryResult, _ *retryMockStore) {
				t.Helper()
				if result.Retried {
					t.Error("expected Retried=false for run_timeout")
				}
			},
		},
		{
			name:        "max attempts exhausted",
			runID:       "run-1",
			failureCode: FailureBootstrapFailed,
			setup: func(s *retryMockStore) {
				s.runs["run-1"] = failedRun("run-1", 3, 3) // 3 of 3 used
			},
			check: func(t *testing.T, result *RetryResult, s *retryMockStore) {
				t.Helper()
				if result.Retried {
					t.Error("expected Retried=false when max_attempts exhausted")
				}
				if len(s.transitionRunCalls) != 0 {
					t.Errorf("expected no TransitionRun calls, got %d", len(s.transitionRunCalls))
				}
			},
		},
		{
			name:        "run not in failed status",
			runID:       "run-1",
			failureCode: FailureBootstrapFailed,
			setup: func(s *retryMockStore) {
				r := failedRun("run-1", 1, 3)
				r.Status = RunStatusRunning
				s.runs["run-1"] = r
			},
			check: func(t *testing.T, result *RetryResult, s *retryMockStore) {
				t.Helper()
				if result.Retried {
					t.Error("expected Retried=false for non-failed run")
				}
				if len(s.transitionRunCalls) != 0 {
					t.Errorf("expected no TransitionRun calls, got %d", len(s.transitionRunCalls))
				}
			},
		},
		{
			name:        "canceled run is skipped by retry scheduler",
			runID:       "run-1",
			failureCode: FailureBootstrapFailed,
			setup: func(s *retryMockStore) {
				r := failedRun("run-1", 1, 3)
				r.Status = RunStatusCanceled
				s.runs["run-1"] = r
			},
			check: func(t *testing.T, result *RetryResult, s *retryMockStore) {
				t.Helper()
				if result.Retried {
					t.Error("expected Retried=false for canceled run")
				}
				if len(s.transitionRunCalls) != 0 {
					t.Errorf("expected no TransitionRun calls, got %d", len(s.transitionRunCalls))
				}
			},
		},
		{
			name:        "empty runID returns error",
			runID:       "",
			failureCode: FailureBootstrapFailed,
			wantErr:     "runID must not be empty",
		},
		{
			name:        "run not found returns error",
			runID:       "run-missing",
			failureCode: FailureBootstrapFailed,
			wantErr:     "failed to get run",
		},
		{
			name:        "transition to retrying fails returns error",
			runID:       "run-1",
			failureCode: FailureBootstrapFailed,
			setup: func(s *retryMockStore) {
				s.runs["run-1"] = failedRun("run-1", 1, 3)
				s.transitionRunErr = fmt.Errorf("database unavailable")
			},
			wantErr: "failed to transition run to retrying",
		},
		{
			name:        "event insert failure does not block retry",
			runID:       "run-1",
			failureCode: FailureBootstrapFailed,
			setup: func(s *retryMockStore) {
				s.runs["run-1"] = failedRun("run-1", 1, 3)
				s.insertEventErr = fmt.Errorf("event table full")
			},
			check: func(t *testing.T, result *RetryResult, s *retryMockStore) {
				t.Helper()
				if !result.Retried {
					t.Error("expected Retried=true despite event failure")
				}
				// Both transitions should still occur.
				if len(s.transitionRunCalls) != 2 {
					t.Fatalf("expected 2 TransitionRun calls, got %d", len(s.transitionRunCalls))
				}
			},
		},
		{
			name:        "unknown failure code is non-retryable",
			runID:       "run-1",
			failureCode: FailureCode("unknown_code"),
			setup: func(s *retryMockStore) {
				s.runs["run-1"] = failedRun("run-1", 1, 3)
			},
			check: func(t *testing.T, result *RetryResult, _ *retryMockStore) {
				t.Helper()
				if result.Retried {
					t.Error("expected Retried=false for unknown failure code")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evtSeq = 0
			store := newRetryMockStore()
			if tt.setup != nil {
				tt.setup(store)
			}

			svc := NewRetryService(store, RetryConfig{
				BaseDelay: 30 * time.Second,
				MaxDelay:  30 * time.Minute,
				IDFunc:    idFunc,
			})

			result, err := svc.EvaluateRetry(context.Background(), tt.runID, tt.failureCode)

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

func TestRetryEventUsesIDFunc(t *testing.T) {
	seq := 0
	idFunc := func() string {
		seq++
		return fmt.Sprintf("custom-evt-%d", seq)
	}

	store := newRetryMockStore()
	store.runs["run-1"] = failedRun("run-1", 1, 3)

	svc := NewRetryService(store, RetryConfig{IDFunc: idFunc})

	result, err := svc.EvaluateRetry(context.Background(), "run-1", FailureBootstrapFailed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Retried {
		t.Fatal("expected Retried=true")
	}
	if len(store.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(store.events))
	}
	if store.events[0].ID != "custom-evt-1" {
		t.Errorf("event.ID = %q, want %q", store.events[0].ID, "custom-evt-1")
	}
}

func TestRetryExponentialBackoff(t *testing.T) {
	tests := []struct {
		name         string
		attemptCount int
		baseDelay    time.Duration
		maxDelay     time.Duration
		wantDelay    time.Duration
	}{
		{
			name:         "first attempt: base delay",
			attemptCount: 1,
			baseDelay:    30 * time.Second,
			maxDelay:     30 * time.Minute,
			wantDelay:    30 * time.Second,
		},
		{
			name:         "second attempt: 2x base",
			attemptCount: 2,
			baseDelay:    30 * time.Second,
			maxDelay:     30 * time.Minute,
			wantDelay:    60 * time.Second,
		},
		{
			name:         "third attempt: 4x base",
			attemptCount: 3,
			baseDelay:    30 * time.Second,
			maxDelay:     30 * time.Minute,
			wantDelay:    120 * time.Second,
		},
		{
			name:         "capped at max delay",
			attemptCount: 20,
			baseDelay:    30 * time.Second,
			maxDelay:     30 * time.Minute,
			wantDelay:    30 * time.Minute,
		},
		{
			name:         "zero attempt count returns base",
			attemptCount: 0,
			baseDelay:    10 * time.Second,
			maxDelay:     5 * time.Minute,
			wantDelay:    10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newRetryMockStore()
			store.runs["run-1"] = failedRun("run-1", tt.attemptCount, 100)

			svc := NewRetryService(store, RetryConfig{
				BaseDelay: tt.baseDelay,
				MaxDelay:  tt.maxDelay,
			})

			result, err := svc.EvaluateRetry(context.Background(), "run-1", FailureBootstrapFailed)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Retried {
				t.Fatal("expected Retried=true")
			}
			if result.BackoffDelay != tt.wantDelay {
				t.Errorf("BackoffDelay = %v, want %v", result.BackoffDelay, tt.wantDelay)
			}
		})
	}
}

func TestRetryDefaults(t *testing.T) {
	store := newRetryMockStore()
	svc := NewRetryService(store, RetryConfig{})

	if svc.config.BaseDelay != 30*time.Second {
		t.Errorf("default BaseDelay = %v, want 30s", svc.config.BaseDelay)
	}
	if svc.config.MaxDelay != 30*time.Minute {
		t.Errorf("default MaxDelay = %v, want 30m", svc.config.MaxDelay)
	}
}

func TestRetryCustomConfig(t *testing.T) {
	store := newRetryMockStore()
	svc := NewRetryService(store, RetryConfig{
		BaseDelay: 10 * time.Second,
		MaxDelay:  5 * time.Minute,
	})

	if svc.config.BaseDelay != 10*time.Second {
		t.Errorf("BaseDelay = %v, want 10s", svc.config.BaseDelay)
	}
	if svc.config.MaxDelay != 5*time.Minute {
		t.Errorf("MaxDelay = %v, want 5m", svc.config.MaxDelay)
	}
}

func TestRetrySecondTransitionFails(t *testing.T) {
	// When the second transition (retrying→queued) fails, the error is returned.
	// The run is left in retrying state — a separate reconciliation pass would
	// handle it.
	store := newRetryMockStore()
	store.runs["run-1"] = failedRun("run-1", 1, 3)

	customStore := &retryMockStoreWithCallCount{
		retryMockStore: *store,
		failOnCall:     2,
		failErr:        fmt.Errorf("database timeout"),
	}
	customStore.runs = store.runs

	svc := NewRetryService(customStore, RetryConfig{})

	_, err := svc.EvaluateRetry(context.Background(), "run-1", FailureBootstrapFailed)
	if err == nil {
		t.Fatal("expected error when second transition fails")
	}
	if !strings.Contains(err.Error(), "failed to transition run to queued") {
		t.Errorf("error = %q, want containing %q", err.Error(), "failed to transition run to queued")
	}

	// First transition (failed→retrying) should have succeeded.
	if len(customStore.transitionRunCalls) != 2 {
		t.Fatalf("expected 2 TransitionRun calls, got %d", len(customStore.transitionRunCalls))
	}
	tc1 := customStore.transitionRunCalls[0]
	if tc1.FromStatus != RunStatusFailed || tc1.ToStatus != RunStatusRetrying {
		t.Errorf("transition 1: %s→%s, want failed→retrying", tc1.FromStatus, tc1.ToStatus)
	}
}

// retryMockStoreWithCallCount extends retryMockStore to fail on a specific call number.
type retryMockStoreWithCallCount struct {
	retryMockStore
	failOnCall int
	failErr    error
	callCount  int
}

func (s *retryMockStoreWithCallCount) TransitionRun(_ context.Context, runID string, from, to RunStatus) error {
	s.callCount++
	s.transitionRunCalls = append(s.transitionRunCalls, transitionRunCall{
		RunID:      runID,
		FromStatus: from,
		ToStatus:   to,
	})
	if s.callCount >= s.failOnCall {
		return s.failErr
	}
	return nil
}
