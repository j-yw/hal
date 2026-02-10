package cloud

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// heartbeatMockStore is a test store for heartbeat service tests.
type heartbeatMockStore struct {
	mockStore

	// HeartbeatAttempt behavior
	heartbeatAttemptErr   error
	heartbeatAttemptCalls []heartbeatAttemptCall

	// RenewAuthLock behavior
	renewAuthLockErr   error
	renewAuthLockCalls []renewAuthLockCall

	// InsertEvent tracking
	events []Event

	// TransitionAttempt tracking
	transitionAttemptCalls []transitionAttemptCall
}

type heartbeatAttemptCall struct {
	AttemptID      string
	HeartbeatAt    time.Time
	LeaseExpiresAt time.Time
}

type renewAuthLockCall struct {
	AuthProfileID  string
	RunID          string
	HeartbeatAt    time.Time
	LeaseExpiresAt time.Time
}

func newHeartbeatMockStore() *heartbeatMockStore {
	return &heartbeatMockStore{}
}

func (s *heartbeatMockStore) HeartbeatAttempt(_ context.Context, attemptID string, heartbeatAt, leaseExpiresAt time.Time) error {
	s.heartbeatAttemptCalls = append(s.heartbeatAttemptCalls, heartbeatAttemptCall{
		AttemptID:      attemptID,
		HeartbeatAt:    heartbeatAt,
		LeaseExpiresAt: leaseExpiresAt,
	})
	if s.heartbeatAttemptErr != nil {
		return s.heartbeatAttemptErr
	}
	return nil
}

func (s *heartbeatMockStore) RenewAuthLock(_ context.Context, authProfileID, runID string, heartbeatAt, leaseExpiresAt time.Time) error {
	s.renewAuthLockCalls = append(s.renewAuthLockCalls, renewAuthLockCall{
		AuthProfileID:  authProfileID,
		RunID:          runID,
		HeartbeatAt:    heartbeatAt,
		LeaseExpiresAt: leaseExpiresAt,
	})
	if s.renewAuthLockErr != nil {
		return s.renewAuthLockErr
	}
	return nil
}

func (s *heartbeatMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.events = append(s.events, *event)
	return nil
}

func (s *heartbeatMockStore) TransitionAttempt(_ context.Context, attemptID string, status AttemptStatus, endedAt time.Time, errCode, errMsg *string) error {
	s.transitionAttemptCalls = append(s.transitionAttemptCalls, transitionAttemptCall{
		AttemptID:    attemptID,
		Status:       status,
		EndedAt:      endedAt,
		ErrorCode:    errCode,
		ErrorMessage: errMsg,
	})
	return nil
}

func TestHeartbeatRenew(t *testing.T) {
	tests := []struct {
		name          string
		attemptID     string
		authProfileID string
		runID         string
		setup         func(s *heartbeatMockStore)
		wantErr       string
		check         func(t *testing.T, s *heartbeatMockStore)
	}{
		{
			name:          "successful renewal of attempt and auth lock",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			runID:         "run-1",
			setup:         func(s *heartbeatMockStore) {},
			check: func(t *testing.T, s *heartbeatMockStore) {
				t.Helper()
				// Verify attempt heartbeat was called.
				if len(s.heartbeatAttemptCalls) != 1 {
					t.Fatalf("expected 1 HeartbeatAttempt call, got %d", len(s.heartbeatAttemptCalls))
				}
				hc := s.heartbeatAttemptCalls[0]
				if hc.AttemptID != "attempt-1" {
					t.Errorf("HeartbeatAttempt.AttemptID = %q, want %q", hc.AttemptID, "attempt-1")
				}
				// Lease extends by 30s default.
				delta := hc.LeaseExpiresAt.Sub(hc.HeartbeatAt)
				if delta != 30*time.Second {
					t.Errorf("attempt lease delta = %v, want 30s", delta)
				}

				// Verify auth lock renewal was called.
				if len(s.renewAuthLockCalls) != 1 {
					t.Fatalf("expected 1 RenewAuthLock call, got %d", len(s.renewAuthLockCalls))
				}
				rc := s.renewAuthLockCalls[0]
				if rc.AuthProfileID != "profile-1" {
					t.Errorf("RenewAuthLock.AuthProfileID = %q, want %q", rc.AuthProfileID, "profile-1")
				}
				if rc.RunID != "run-1" {
					t.Errorf("RenewAuthLock.RunID = %q, want %q", rc.RunID, "run-1")
				}
				// Lock expiry matches attempt expiry.
				if !hc.LeaseExpiresAt.Equal(rc.LeaseExpiresAt) {
					t.Errorf("attempt and lock lease expiry differ: %v vs %v", hc.LeaseExpiresAt, rc.LeaseExpiresAt)
				}

				// No events or transitions on success.
				if len(s.events) != 0 {
					t.Errorf("unexpected events: %d", len(s.events))
				}
				if len(s.transitionAttemptCalls) != 0 {
					t.Errorf("unexpected TransitionAttempt calls: %d", len(s.transitionAttemptCalls))
				}
			},
		},
		{
			name:          "empty attemptID",
			attemptID:     "",
			authProfileID: "profile-1",
			runID:         "run-1",
			setup:         func(s *heartbeatMockStore) {},
			wantErr:       "attemptID must not be empty",
		},
		{
			name:          "empty authProfileID",
			attemptID:     "attempt-1",
			authProfileID: "",
			runID:         "run-1",
			setup:         func(s *heartbeatMockStore) {},
			wantErr:       "authProfileID must not be empty",
		},
		{
			name:          "empty runID",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			runID:         "",
			setup:         func(s *heartbeatMockStore) {},
			wantErr:       "runID must not be empty",
		},
		{
			name:          "attempt lease expired emits lease_lost and terminates",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			runID:         "run-1",
			setup: func(s *heartbeatMockStore) {
				s.heartbeatAttemptErr = ErrLeaseExpired
			},
			wantErr: "lease_expired",
			check: func(t *testing.T, s *heartbeatMockStore) {
				t.Helper()
				// Verify lease_lost event was emitted.
				if len(s.events) != 1 {
					t.Fatalf("expected 1 event, got %d", len(s.events))
				}
				ev := s.events[0]
				if ev.EventType != "lease_lost" {
					t.Errorf("event.EventType = %q, want %q", ev.EventType, "lease_lost")
				}
				if ev.RunID != "run-1" {
					t.Errorf("event.RunID = %q, want %q", ev.RunID, "run-1")
				}
				if ev.AttemptID == nil || *ev.AttemptID != "attempt-1" {
					t.Errorf("event.AttemptID = %v, want %q", ev.AttemptID, "attempt-1")
				}

				// Verify attempt was marked as failed.
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
				if tc.ErrorCode == nil || *tc.ErrorCode != "lease_lost" {
					t.Errorf("TransitionAttempt.ErrorCode = %v, want %q", tc.ErrorCode, "lease_lost")
				}

				// Auth lock renewal should NOT be called when attempt heartbeat fails.
				if len(s.renewAuthLockCalls) != 0 {
					t.Errorf("unexpected RenewAuthLock calls: %d", len(s.renewAuthLockCalls))
				}
			},
		},
		{
			name:          "auth lock lease expired emits lease_lost and terminates",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			runID:         "run-1",
			setup: func(s *heartbeatMockStore) {
				s.renewAuthLockErr = ErrLeaseExpired
			},
			wantErr: "lease_expired",
			check: func(t *testing.T, s *heartbeatMockStore) {
				t.Helper()
				// Attempt heartbeat succeeded.
				if len(s.heartbeatAttemptCalls) != 1 {
					t.Fatalf("expected 1 HeartbeatAttempt call, got %d", len(s.heartbeatAttemptCalls))
				}

				// Verify lease_lost event was emitted.
				if len(s.events) != 1 {
					t.Fatalf("expected 1 event, got %d", len(s.events))
				}
				ev := s.events[0]
				if ev.EventType != "lease_lost" {
					t.Errorf("event.EventType = %q, want %q", ev.EventType, "lease_lost")
				}

				// Verify attempt was marked as failed.
				if len(s.transitionAttemptCalls) != 1 {
					t.Fatalf("expected 1 TransitionAttempt call, got %d", len(s.transitionAttemptCalls))
				}
				tc := s.transitionAttemptCalls[0]
				if tc.Status != AttemptStatusFailed {
					t.Errorf("TransitionAttempt.Status = %q, want %q", tc.Status, AttemptStatusFailed)
				}
				if tc.ErrorCode == nil || *tc.ErrorCode != "lease_lost" {
					t.Errorf("TransitionAttempt.ErrorCode = %v, want %q", tc.ErrorCode, "lease_lost")
				}
			},
		},
		{
			name:          "attempt heartbeat non-lease error propagates",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			runID:         "run-1",
			setup: func(s *heartbeatMockStore) {
				s.heartbeatAttemptErr = fmt.Errorf("database unavailable")
			},
			wantErr: "failed to heartbeat attempt: database unavailable",
			check: func(t *testing.T, s *heartbeatMockStore) {
				t.Helper()
				// No lease_lost event or transition on non-lease errors.
				if len(s.events) != 0 {
					t.Errorf("unexpected events: %d", len(s.events))
				}
				if len(s.transitionAttemptCalls) != 0 {
					t.Errorf("unexpected TransitionAttempt calls: %d", len(s.transitionAttemptCalls))
				}
			},
		},
		{
			name:          "auth lock renewal non-lease error propagates",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			runID:         "run-1",
			setup: func(s *heartbeatMockStore) {
				s.renewAuthLockErr = fmt.Errorf("lock table corrupted")
			},
			wantErr: "failed to renew auth lock: lock table corrupted",
			check: func(t *testing.T, s *heartbeatMockStore) {
				t.Helper()
				// No lease_lost event or transition on non-lease errors.
				if len(s.events) != 0 {
					t.Errorf("unexpected events: %d", len(s.events))
				}
				if len(s.transitionAttemptCalls) != 0 {
					t.Errorf("unexpected TransitionAttempt calls: %d", len(s.transitionAttemptCalls))
				}
			},
		},
		{
			name:          "lease_lost event uses IDFunc",
			attemptID:     "attempt-1",
			authProfileID: "profile-1",
			runID:         "run-1",
			setup: func(s *heartbeatMockStore) {
				s.heartbeatAttemptErr = ErrLeaseExpired
			},
			wantErr: "lease_expired",
			check: func(t *testing.T, s *heartbeatMockStore) {
				t.Helper()
				if len(s.events) != 1 {
					t.Fatalf("expected 1 event, got %d", len(s.events))
				}
				if s.events[0].ID != "evt-1" {
					t.Errorf("event.ID = %q, want %q", s.events[0].ID, "evt-1")
				}
			},
		},
	}

	evtSeq := 0
	idFunc := func() string {
		evtSeq++
		return fmt.Sprintf("evt-%d", evtSeq)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evtSeq = 0
			store := newHeartbeatMockStore()
			if tt.setup != nil {
				tt.setup(store)
			}

			svc := NewHeartbeatService(store, HeartbeatConfig{
				LeaseDuration: 30 * time.Second,
				IDFunc:        idFunc,
			})

			err := svc.Renew(context.Background(), tt.attemptID, tt.authProfileID, tt.runID)

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

func TestNewHeartbeatServiceDefaults(t *testing.T) {
	store := newHeartbeatMockStore()
	svc := NewHeartbeatService(store, HeartbeatConfig{})
	if svc.config.LeaseDuration != 30*time.Second {
		t.Errorf("LeaseDuration = %v, want 30s", svc.config.LeaseDuration)
	}
}

func TestHeartbeatCustomLeaseDuration(t *testing.T) {
	store := newHeartbeatMockStore()
	svc := NewHeartbeatService(store, HeartbeatConfig{
		LeaseDuration: 2 * time.Minute,
		IDFunc:        func() string { return "evt-custom" },
	})

	err := svc.Renew(context.Background(), "attempt-1", "profile-1", "run-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify lease duration is respected.
	if len(store.heartbeatAttemptCalls) != 1 {
		t.Fatalf("expected 1 HeartbeatAttempt call, got %d", len(store.heartbeatAttemptCalls))
	}
	hc := store.heartbeatAttemptCalls[0]
	delta := hc.LeaseExpiresAt.Sub(hc.HeartbeatAt)
	if delta != 2*time.Minute {
		t.Errorf("lease duration = %v, want 2m", delta)
	}
}
