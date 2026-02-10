package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// writebackMockRunner implements runner.Runner for writeback tests.
type writebackMockRunner struct {
	execResults map[string]*runner.ExecResult
	execErrs    map[string]error
	execCalls   []writebackExecCall
}

type writebackExecCall struct {
	SandboxID string
	Command   string
}

func (r *writebackMockRunner) Exec(_ context.Context, sandboxID string, req *runner.ExecRequest) (*runner.ExecResult, error) {
	r.execCalls = append(r.execCalls, writebackExecCall{
		SandboxID: sandboxID,
		Command:   req.Command,
	})

	for substr, err := range r.execErrs {
		if strings.Contains(req.Command, substr) {
			return nil, err
		}
	}
	for substr, result := range r.execResults {
		if strings.Contains(req.Command, substr) {
			return result, nil
		}
	}
	return &runner.ExecResult{ExitCode: 0}, nil
}

func (r *writebackMockRunner) CreateSandbox(_ context.Context, _ *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	return nil, nil
}

func (r *writebackMockRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}

func (r *writebackMockRunner) DestroySandbox(_ context.Context, _ string) error {
	return nil
}

func (r *writebackMockRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return nil, nil
}

// writebackMockStore extends mockStore for writeback tests.
type writebackMockStore struct {
	mockStore
	insertedEvents     []*Event
	insertEventErr     error
	authProfile        *AuthProfile
	getProfileErr      error
	updateProfileErr   error
	updatedProfile     *AuthProfile
	updateProfileCalls int
}

func (s *writebackMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.insertedEvents = append(s.insertedEvents, event)
	return s.insertEventErr
}

func (s *writebackMockStore) GetAuthProfile(_ context.Context, _ string) (*AuthProfile, error) {
	if s.getProfileErr != nil {
		return nil, s.getProfileErr
	}
	return s.authProfile, nil
}

func (s *writebackMockStore) UpdateAuthProfile(_ context.Context, profile *AuthProfile) error {
	s.updateProfileCalls++
	// Deep copy to capture the profile state at call time.
	cp := *profile
	s.updatedProfile = &cp
	return s.updateProfileErr
}

func validWritebackRequest() *WritebackRequest {
	return &WritebackRequest{
		AuthProfileID: "profile-001",
		SandboxID:     "sandbox-001",
		AttemptID:     "att-001",
		RunID:         "run-001",
	}
}

func linkedProfileWithSecretForWriteback(secretRef string) *AuthProfile {
	ref := secretRef
	return &AuthProfile{
		ID:                "profile-001",
		OwnerID:           "owner-001",
		Provider:          "claude",
		Mode:              "session",
		SecretRef:         &ref,
		Status:            AuthProfileStatusLinked,
		MaxConcurrentRuns: 1,
		Version:           1,
		CreatedAt:         time.Now().UTC().Truncate(time.Second),
		UpdatedAt:         time.Now().UTC().Truncate(time.Second),
	}
}

func TestWriteback(t *testing.T) {
	t.Run("successful writeback with changed credentials", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile: linkedProfileWithSecretForWriteback("old-secret"),
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "new-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{
			IDFunc: func() string { return "evt-001" },
		})

		result, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Changed {
			t.Error("expected Changed=true")
		}
		if !result.Written {
			t.Error("expected Written=true")
		}

		// Verify profile was updated.
		if store.updateProfileCalls != 1 {
			t.Errorf("expected 1 UpdateAuthProfile call, got %d", store.updateProfileCalls)
		}
		if store.updatedProfile == nil {
			t.Fatal("expected updatedProfile to be set")
		}
		if store.updatedProfile.SecretRef == nil || *store.updatedProfile.SecretRef != "new-secret" {
			t.Errorf("expected SecretRef='new-secret', got %v", store.updatedProfile.SecretRef)
		}
		if store.updatedProfile.LastValidatedAt == nil {
			t.Error("expected LastValidatedAt to be set")
		}
		if store.updatedProfile.ExpiresAt == nil {
			t.Error("expected ExpiresAt to be set")
		}
		if store.updatedProfile.LastErrorCode != nil {
			t.Errorf("expected LastErrorCode=nil, got %v", store.updatedProfile.LastErrorCode)
		}

		// Verify events: writeback_started, writeback_completed.
		events := filterWritebackEventsByType(store.insertedEvents, "writeback_started")
		if len(events) != 1 {
			t.Errorf("expected 1 writeback_started event, got %d", len(events))
		}
		events = filterWritebackEventsByType(store.insertedEvents, "writeback_completed")
		if len(events) != 1 {
			t.Errorf("expected 1 writeback_completed event, got %d", len(events))
		}
		// Verify completed event payload has changed=true, written=true.
		if len(events) > 0 && events[0].PayloadJSON != nil {
			var payload writebackEventPayload
			if err := json.Unmarshal([]byte(*events[0].PayloadJSON), &payload); err == nil {
				if !payload.Changed {
					t.Error("expected completed event Changed=true")
				}
				if !payload.Written {
					t.Error("expected completed event Written=true")
				}
			}
		}
	})

	t.Run("no change in credentials", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile: linkedProfileWithSecretForWriteback("same-secret"),
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "same-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		result, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Changed {
			t.Error("expected Changed=false")
		}
		if result.Written {
			t.Error("expected Written=false")
		}

		// Verify no UpdateAuthProfile call.
		if store.updateProfileCalls != 0 {
			t.Errorf("expected 0 UpdateAuthProfile calls, got %d", store.updateProfileCalls)
		}

		// Verify writeback_completed event with changed=false.
		events := filterWritebackEventsByType(store.insertedEvents, "writeback_completed")
		if len(events) != 1 {
			t.Errorf("expected 1 writeback_completed event, got %d", len(events))
		}
	})

	t.Run("no-op when secret_ref is nil", func(t *testing.T) {
		profile := linkedProfileWithSecretForWriteback("")
		profile.SecretRef = nil
		store := &writebackMockStore{
			authProfile: profile,
		}
		mockRunner := &writebackMockRunner{}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		result, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Changed {
			t.Error("expected Changed=false")
		}
		if result.Written {
			t.Error("expected Written=false")
		}
		if len(mockRunner.execCalls) != 0 {
			t.Errorf("expected no exec calls, got %d", len(mockRunner.execCalls))
		}
	})

	t.Run("no-op when secret_ref is empty string", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile: linkedProfileWithSecretForWriteback(""),
		}
		mockRunner := &writebackMockRunner{}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		result, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Changed {
			t.Error("expected Changed=false")
		}
		if len(mockRunner.execCalls) != 0 {
			t.Errorf("expected no exec calls, got %d", len(mockRunner.execCalls))
		}
	})

	t.Run("get auth profile error", func(t *testing.T) {
		store := &writebackMockStore{
			getProfileErr: fmt.Errorf("db unavailable"),
		}
		mockRunner := &writebackMockRunner{}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "failed to get auth profile") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("read exec error", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile: linkedProfileWithSecretForWriteback("old-secret"),
		}
		mockRunner := &writebackMockRunner{
			execErrs: map[string]error{
				"cat": fmt.Errorf("sandbox unreachable"),
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "writeback read failed") {
			t.Errorf("unexpected error: %v", err)
		}

		// Verify writeback_failed event emitted.
		events := filterWritebackEventsByType(store.insertedEvents, "writeback_failed")
		if len(events) != 1 {
			t.Errorf("expected 1 writeback_failed event, got %d", len(events))
		}
	})

	t.Run("read non-zero exit code", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile: linkedProfileWithSecretForWriteback("old-secret"),
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 1, Stderr: "no such file"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "exit code 1") {
			t.Errorf("unexpected error: %v", err)
		}

		events := filterWritebackEventsByType(store.insertedEvents, "writeback_failed")
		if len(events) != 1 {
			t.Errorf("expected 1 writeback_failed event, got %d", len(events))
		}
	})

	t.Run("read non-zero exit stderr fallback to stdout", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile: linkedProfileWithSecretForWriteback("old-secret"),
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 1, Stdout: "stdout error"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "stdout error") {
			t.Errorf("expected error to contain 'stdout error', got: %v", err)
		}
	})

	t.Run("version conflict on update", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile:      linkedProfileWithSecretForWriteback("old-secret"),
			updateProfileErr: ErrConflict,
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "new-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "version conflict") {
			t.Errorf("unexpected error: %v", err)
		}

		// Verify writeback_failed event with error_code=version_conflict.
		events := filterWritebackEventsByType(store.insertedEvents, "writeback_failed")
		if len(events) != 1 {
			t.Fatalf("expected 1 writeback_failed event, got %d", len(events))
		}
		if events[0].PayloadJSON != nil {
			var payload writebackEventPayload
			if err := json.Unmarshal([]byte(*events[0].PayloadJSON), &payload); err == nil {
				if payload.ErrorCode != "version_conflict" {
					t.Errorf("expected error_code=version_conflict, got %q", payload.ErrorCode)
				}
			}
		}
	})

	t.Run("profile not found on update", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile:      linkedProfileWithSecretForWriteback("old-secret"),
			updateProfileErr: ErrNotFound,
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "new-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("unexpected error: %v", err)
		}

		events := filterWritebackEventsByType(store.insertedEvents, "writeback_failed")
		if len(events) != 1 {
			t.Errorf("expected 1 writeback_failed event, got %d", len(events))
		}
	})

	t.Run("generic update error", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile:      linkedProfileWithSecretForWriteback("old-secret"),
			updateProfileErr: fmt.Errorf("db timeout"),
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "new-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "writeback update failed") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("event failure tolerance", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile:    linkedProfileWithSecretForWriteback("old-secret"),
			insertEventErr: fmt.Errorf("event storage failed"),
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "new-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		result, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Changed || !result.Written {
			t.Error("expected Changed=true, Written=true despite event failures")
		}
	})

	t.Run("nil IDFunc uses empty event IDs", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile: linkedProfileWithSecretForWriteback("old-secret"),
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "new-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, evt := range store.insertedEvents {
			if evt.ID != "" {
				t.Errorf("expected empty event ID with nil IDFunc, got %q", evt.ID)
			}
		}
	})

	t.Run("custom IDFunc", func(t *testing.T) {
		callCount := 0
		store := &writebackMockStore{
			authProfile: linkedProfileWithSecretForWriteback("old-secret"),
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "new-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{
			IDFunc: func() string {
				callCount++
				return fmt.Sprintf("evt-%03d", callCount)
			},
		})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have 2 events: writeback_started, writeback_completed.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("expected 2 events, got %d", len(store.insertedEvents))
		}
		if store.insertedEvents[0].ID != "evt-001" {
			t.Errorf("expected first event ID='evt-001', got %q", store.insertedEvents[0].ID)
		}
		if store.insertedEvents[1].ID != "evt-002" {
			t.Errorf("expected second event ID='evt-002', got %q", store.insertedEvents[1].ID)
		}
	})

	t.Run("custom auth dir", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile: linkedProfileWithSecretForWriteback("old-secret"),
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "old-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{
			AuthDir: "/custom/auth",
		})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify the cat command uses the custom auth dir.
		if len(mockRunner.execCalls) != 1 {
			t.Fatalf("expected 1 exec call, got %d", len(mockRunner.execCalls))
		}
		if !strings.Contains(mockRunner.execCalls[0].Command, "/custom/auth/credentials") {
			t.Errorf("expected command to reference /custom/auth/credentials, got %q", mockRunner.execCalls[0].Command)
		}
	})

	t.Run("custom credentials TTL", func(t *testing.T) {
		store := &writebackMockStore{
			authProfile: linkedProfileWithSecretForWriteback("old-secret"),
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "new-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{
			CredentialsTTL: 48 * time.Hour,
		})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if store.updatedProfile == nil {
			t.Fatal("expected updatedProfile to be set")
		}
		if store.updatedProfile.ExpiresAt == nil {
			t.Fatal("expected ExpiresAt to be set")
		}
		// ExpiresAt should be approximately 48 hours from now.
		expectedMin := time.Now().UTC().Add(47 * time.Hour)
		if store.updatedProfile.ExpiresAt.Before(expectedMin) {
			t.Errorf("expected ExpiresAt >= 47h from now, got %v", store.updatedProfile.ExpiresAt)
		}
	})

	t.Run("successful writeback clears last_error_code", func(t *testing.T) {
		errCode := "auth_invalid"
		profile := linkedProfileWithSecretForWriteback("old-secret")
		profile.LastErrorCode = &errCode
		store := &writebackMockStore{
			authProfile: profile,
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "new-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if store.updatedProfile == nil {
			t.Fatal("expected updatedProfile to be set")
		}
		if store.updatedProfile.LastErrorCode != nil {
			t.Errorf("expected LastErrorCode=nil (cleared), got %v", *store.updatedProfile.LastErrorCode)
		}
	})

	t.Run("defaults", func(t *testing.T) {
		svc := NewWritebackService(&writebackMockStore{}, &writebackMockRunner{}, WritebackConfig{})
		if svc.config.AuthDir != DefaultAuthDir {
			t.Errorf("expected AuthDir=%q, got %q", DefaultAuthDir, svc.config.AuthDir)
		}
		if svc.config.CredentialsTTL != DefaultCredentialsTTL {
			t.Errorf("expected CredentialsTTL=%v, got %v", DefaultCredentialsTTL, svc.config.CredentialsTTL)
		}
	})

	t.Run("optimistic version check passes profile version", func(t *testing.T) {
		profile := linkedProfileWithSecretForWriteback("old-secret")
		profile.Version = 5
		store := &writebackMockStore{
			authProfile: profile,
		}
		mockRunner := &writebackMockRunner{
			execResults: map[string]*runner.ExecResult{
				"cat": {ExitCode: 0, Stdout: "new-secret"},
			},
		}
		svc := NewWritebackService(store, mockRunner, WritebackConfig{})

		_, err := svc.Writeback(context.Background(), validWritebackRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if store.updatedProfile == nil {
			t.Fatal("expected updatedProfile to be set")
		}
		// The profile passed to UpdateAuthProfile should have version=5
		// (the adapter checks WHERE version = 5 and sets version = version + 1).
		if store.updatedProfile.Version != 5 {
			t.Errorf("expected profile version=5 passed to UpdateAuthProfile, got %d", store.updatedProfile.Version)
		}
	})
}

func TestWritebackRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *WritebackRequest)
		wantErr string
	}{
		{
			name:    "valid request",
			modify:  func(r *WritebackRequest) {},
			wantErr: "",
		},
		{
			name:    "empty authProfileID",
			modify:  func(r *WritebackRequest) { r.AuthProfileID = "" },
			wantErr: "authProfileID must not be empty",
		},
		{
			name:    "empty sandboxID",
			modify:  func(r *WritebackRequest) { r.SandboxID = "" },
			wantErr: "sandboxID must not be empty",
		},
		{
			name:    "empty attemptID",
			modify:  func(r *WritebackRequest) { r.AttemptID = "" },
			wantErr: "attemptID must not be empty",
		},
		{
			name:    "empty runID",
			modify:  func(r *WritebackRequest) { r.RunID = "" },
			wantErr: "runID must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validWritebackRequest()
			tt.modify(req)
			err := req.Validate()

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// filterWritebackEventsByType returns events matching the given event type.
func filterWritebackEventsByType(events []*Event, eventType string) []*Event {
	var result []*Event
	for _, e := range events {
		if e.EventType == eventType {
			result = append(result, e)
		}
	}
	return result
}
