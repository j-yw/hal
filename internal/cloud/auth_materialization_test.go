package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// authMatMockRunner implements runner.Runner for auth materialization tests.
type authMatMockRunner struct {
	// execResults maps command substrings to results for flexible matching.
	execResults map[string]*runner.ExecResult
	execErrs    map[string]error
	// execCalls records all Exec calls for verification.
	execCalls []authMatExecCall
	// destroyErr is the error returned by DestroySandbox.
	destroyErr error
}

type authMatExecCall struct {
	SandboxID string
	Command   string
	WorkDir   string
}

func (r *authMatMockRunner) Exec(_ context.Context, sandboxID string, req *runner.ExecRequest) (*runner.ExecResult, error) {
	r.execCalls = append(r.execCalls, authMatExecCall{
		SandboxID: sandboxID,
		Command:   req.Command,
		WorkDir:   req.WorkDir,
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
	// Default: success with exit code 0.
	return &runner.ExecResult{ExitCode: 0}, nil
}

func (r *authMatMockRunner) CreateSandbox(_ context.Context, _ *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	return nil, nil
}

func (r *authMatMockRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}

func (r *authMatMockRunner) DestroySandbox(_ context.Context, _ string) error {
	return r.destroyErr
}

func (r *authMatMockRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return nil, nil
}

// authMatMockStore extends mockStore for auth materialization tests.
type authMatMockStore struct {
	mockStore
	insertedEvents []*Event
	insertEventErr error
	authProfile    *AuthProfile
	getProfileErr  error
}

func (s *authMatMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.insertedEvents = append(s.insertedEvents, event)
	return s.insertEventErr
}

func (s *authMatMockStore) GetAuthProfile(_ context.Context, _ string) (*AuthProfile, error) {
	if s.getProfileErr != nil {
		return nil, s.getProfileErr
	}
	return s.authProfile, nil
}

func validMaterializeRequest() *MaterializeRequest {
	return &MaterializeRequest{
		AuthProfileID: "profile-001",
		SandboxID:     "sandbox-001",
		AttemptID:     "att-001",
		RunID:         "run-001",
	}
}

func linkedProfileWithSecret(secretRef string) *AuthProfile {
	ref := secretRef
	return &AuthProfile{
		ID:                "profile-001",
		OwnerID:           "owner-001",
		Provider:          "anthropic",
		Mode:              "api_key",
		SecretRef:         &ref,
		Status:            AuthProfileStatusLinked,
		MaxConcurrentRuns: 1,
		Version:           1,
	}
}

func linkedProfileNoSecret() *AuthProfile {
	return &AuthProfile{
		ID:                "profile-001",
		OwnerID:           "owner-001",
		Provider:          "anthropic",
		Mode:              "api_key",
		SecretRef:         nil,
		Status:            AuthProfileStatusLinked,
		MaxConcurrentRuns: 1,
		Version:           1,
	}
}

func TestMaterialize(t *testing.T) {
	t.Run("successful_materialization", func(t *testing.T) {
		store := &authMatMockStore{
			authProfile: linkedProfileWithSecret("sk-secret-key-123"),
		}
		mockRunner := &authMatMockRunner{}

		idCounter := 0
		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("evt-%d", idCounter)
			},
		})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify two Exec calls: mkdir + write.
		if len(mockRunner.execCalls) != 2 {
			t.Fatalf("execCalls = %d, want 2", len(mockRunner.execCalls))
		}

		// mkdir call.
		mkdirCall := mockRunner.execCalls[0]
		if mkdirCall.SandboxID != "sandbox-001" {
			t.Errorf("mkdir sandboxID = %q, want %q", mkdirCall.SandboxID, "sandbox-001")
		}
		if !strings.Contains(mkdirCall.Command, "mkdir") {
			t.Errorf("mkdir command = %q, want to contain 'mkdir'", mkdirCall.Command)
		}
		if !strings.Contains(mkdirCall.Command, "0700") {
			t.Errorf("mkdir command = %q, want to contain '0700'", mkdirCall.Command)
		}
		if !strings.Contains(mkdirCall.Command, DefaultAuthDir) {
			t.Errorf("mkdir command = %q, want to contain %q", mkdirCall.Command, DefaultAuthDir)
		}

		// write call.
		writeCall := mockRunner.execCalls[1]
		if writeCall.SandboxID != "sandbox-001" {
			t.Errorf("write sandboxID = %q, want %q", writeCall.SandboxID, "sandbox-001")
		}
		if !strings.Contains(writeCall.Command, "sk-secret-key-123") {
			t.Errorf("write command = %q, want to contain secret content", writeCall.Command)
		}
		if !strings.Contains(writeCall.Command, "0600") {
			t.Errorf("write command = %q, want to contain '0600'", writeCall.Command)
		}
		if !strings.Contains(writeCall.Command, DefaultAuthDir+"/credentials") {
			t.Errorf("write command = %q, want to contain credentials path", writeCall.Command)
		}

		// Verify events: auth_materialize_started + auth_materialize_completed.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
		}

		evt0 := store.insertedEvents[0]
		if evt0.EventType != "auth_materialize_started" {
			t.Errorf("event[0] type = %q, want %q", evt0.EventType, "auth_materialize_started")
		}
		if evt0.ID != "evt-1" {
			t.Errorf("event[0] id = %q, want %q", evt0.ID, "evt-1")
		}
		if evt0.RunID != "run-001" {
			t.Errorf("event[0] run_id = %q, want %q", evt0.RunID, "run-001")
		}
		if evt0.AttemptID == nil || *evt0.AttemptID != "att-001" {
			t.Errorf("event[0] attempt_id = %v, want %q", evt0.AttemptID, "att-001")
		}

		evt1 := store.insertedEvents[1]
		if evt1.EventType != "auth_materialize_completed" {
			t.Errorf("event[1] type = %q, want %q", evt1.EventType, "auth_materialize_completed")
		}
		if evt1.ID != "evt-2" {
			t.Errorf("event[1] id = %q, want %q", evt1.ID, "evt-2")
		}

		// Verify started payload.
		if evt0.PayloadJSON != nil {
			var payload authMaterializationEventPayload
			if err := json.Unmarshal([]byte(*evt0.PayloadJSON), &payload); err != nil {
				t.Fatalf("event[0] payload unmarshal: %v", err)
			}
			if payload.SandboxID != "sandbox-001" {
				t.Errorf("event[0] payload sandbox_id = %q, want %q", payload.SandboxID, "sandbox-001")
			}
			if payload.AuthProfileID != "profile-001" {
				t.Errorf("event[0] payload auth_profile_id = %q, want %q", payload.AuthProfileID, "profile-001")
			}
			if payload.AuthDir != DefaultAuthDir {
				t.Errorf("event[0] payload auth_dir = %q, want %q", payload.AuthDir, DefaultAuthDir)
			}
		} else {
			t.Error("event[0] payload_json is nil, want non-nil")
		}
	})

	t.Run("no_secret_ref_is_noop", func(t *testing.T) {
		store := &authMatMockStore{
			authProfile: linkedProfileNoSecret(),
		}
		mockRunner := &authMatMockRunner{}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// No Exec calls should have been made.
		if len(mockRunner.execCalls) != 0 {
			t.Errorf("execCalls = %d, want 0 (no-op for nil secret_ref)", len(mockRunner.execCalls))
		}

		// No events should have been emitted.
		if len(store.insertedEvents) != 0 {
			t.Errorf("insertedEvents = %d, want 0 (no-op for nil secret_ref)", len(store.insertedEvents))
		}
	})

	t.Run("empty_secret_ref_is_noop", func(t *testing.T) {
		empty := ""
		profile := linkedProfileNoSecret()
		profile.SecretRef = &empty
		store := &authMatMockStore{
			authProfile: profile,
		}
		mockRunner := &authMatMockRunner{}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(mockRunner.execCalls) != 0 {
			t.Errorf("execCalls = %d, want 0 (no-op for empty secret_ref)", len(mockRunner.execCalls))
		}
	})

	t.Run("get_profile_error", func(t *testing.T) {
		store := &authMatMockStore{
			getProfileErr: fmt.Errorf("database unavailable"),
		}
		mockRunner := &authMatMockRunner{}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to get auth profile") {
			t.Errorf("error = %q, want to contain 'failed to get auth profile'", err.Error())
		}
		if !strings.Contains(err.Error(), "database unavailable") {
			t.Errorf("error = %q, want to contain wrapped cause", err.Error())
		}
	})

	t.Run("mkdir_exec_error", func(t *testing.T) {
		store := &authMatMockStore{
			authProfile: linkedProfileWithSecret("secret"),
		}
		mockRunner := &authMatMockRunner{
			execErrs: map[string]error{
				"mkdir": fmt.Errorf("sandbox unreachable"),
			},
		}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "auth materialization mkdir failed") {
			t.Errorf("error = %q, want to contain 'auth materialization mkdir failed'", err.Error())
		}

		// Verify failed event emitted.
		failedEvents := filterEventsByType(store.insertedEvents, "auth_materialize_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("auth_materialize_failed events = %d, want 1", len(failedEvents))
		}
		var payload authMaterializationEventPayload
		if err := json.Unmarshal([]byte(*failedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if !strings.Contains(payload.Error, "sandbox unreachable") {
			t.Errorf("payload error = %q, want to contain 'sandbox unreachable'", payload.Error)
		}
	})

	t.Run("mkdir_nonzero_exit_code", func(t *testing.T) {
		store := &authMatMockStore{
			authProfile: linkedProfileWithSecret("secret"),
		}
		mockRunner := &authMatMockRunner{
			execResults: map[string]*runner.ExecResult{
				"mkdir": {ExitCode: 1, Stderr: "permission denied"},
			},
		}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "auth materialization mkdir failed") {
			t.Errorf("error = %q, want to contain 'auth materialization mkdir failed'", err.Error())
		}
		if !strings.Contains(err.Error(), "exit code 1") {
			t.Errorf("error = %q, want to contain 'exit code 1'", err.Error())
		}

		failedEvents := filterEventsByType(store.insertedEvents, "auth_materialize_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("auth_materialize_failed events = %d, want 1", len(failedEvents))
		}
		var payload authMaterializationEventPayload
		if err := json.Unmarshal([]byte(*failedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.ExitCode == nil || *payload.ExitCode != 1 {
			t.Errorf("payload exit_code = %v, want 1", payload.ExitCode)
		}
	})

	t.Run("write_exec_error", func(t *testing.T) {
		store := &authMatMockStore{
			authProfile: linkedProfileWithSecret("secret"),
		}
		mockRunner := &authMatMockRunner{
			execErrs: map[string]error{
				"printf": fmt.Errorf("write timeout"),
			},
		}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "auth materialization write failed") {
			t.Errorf("error = %q, want to contain 'auth materialization write failed'", err.Error())
		}

		// Verify mkdir happened first.
		if len(mockRunner.execCalls) < 1 {
			t.Fatal("expected at least 1 exec call for mkdir")
		}
		if !strings.Contains(mockRunner.execCalls[0].Command, "mkdir") {
			t.Errorf("first exec call = %q, want mkdir", mockRunner.execCalls[0].Command)
		}
	})

	t.Run("write_nonzero_exit_code", func(t *testing.T) {
		store := &authMatMockStore{
			authProfile: linkedProfileWithSecret("secret"),
		}
		mockRunner := &authMatMockRunner{
			execResults: map[string]*runner.ExecResult{
				"printf": {ExitCode: 1, Stderr: "disk full"},
			},
		}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "auth materialization write failed") {
			t.Errorf("error = %q, want to contain 'auth materialization write failed'", err.Error())
		}
		if !strings.Contains(err.Error(), "exit code 1") {
			t.Errorf("error = %q, want to contain 'exit code 1'", err.Error())
		}
	})

	t.Run("event_failure_does_not_block", func(t *testing.T) {
		store := &authMatMockStore{
			authProfile:    linkedProfileWithSecret("secret"),
			insertEventErr: fmt.Errorf("event insert failed"),
		}
		mockRunner := &authMatMockRunner{}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Both Exec calls should still have happened.
		if len(mockRunner.execCalls) != 2 {
			t.Errorf("execCalls = %d, want 2", len(mockRunner.execCalls))
		}
	})

	t.Run("nil_IDFunc_uses_empty_event_id", func(t *testing.T) {
		store := &authMatMockStore{
			authProfile: linkedProfileWithSecret("secret"),
		}
		mockRunner := &authMatMockRunner{}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i, evt := range store.insertedEvents {
			if evt.ID != "" {
				t.Errorf("event[%d] id = %q, want empty (nil IDFunc)", i, evt.ID)
			}
		}
	})

	t.Run("custom_auth_dir", func(t *testing.T) {
		store := &authMatMockStore{
			authProfile: linkedProfileWithSecret("secret"),
		}
		mockRunner := &authMatMockRunner{}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{
			AuthDir: "/workspace/.secrets",
		})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify mkdir uses custom dir.
		if !strings.Contains(mockRunner.execCalls[0].Command, "/workspace/.secrets") {
			t.Errorf("mkdir command = %q, want to contain custom auth dir", mockRunner.execCalls[0].Command)
		}

		// Verify write uses custom dir.
		if !strings.Contains(mockRunner.execCalls[1].Command, "/workspace/.secrets/credentials") {
			t.Errorf("write command = %q, want to contain custom credentials path", mockRunner.execCalls[1].Command)
		}
	})

	t.Run("secret_with_single_quotes_escaped", func(t *testing.T) {
		store := &authMatMockStore{
			authProfile: linkedProfileWithSecret("it's a secret"),
		}
		mockRunner := &authMatMockRunner{}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Materialize(context.Background(), validMaterializeRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// The write command should contain escaped single quotes.
		writeCmd := mockRunner.execCalls[1].Command
		if strings.Contains(writeCmd, "it's") {
			t.Errorf("write command contains unescaped single quote: %q", writeCmd)
		}
		if !strings.Contains(writeCmd, "it") {
			t.Errorf("write command = %q, want to contain secret content", writeCmd)
		}
	})

	t.Run("defaults", func(t *testing.T) {
		svc := NewAuthMaterializationService(&authMatMockStore{}, &authMatMockRunner{}, AuthMaterializationConfig{})
		if svc.store == nil {
			t.Error("store is nil")
		}
		if svc.runner == nil {
			t.Error("runner is nil")
		}
		if svc.config.AuthDir != DefaultAuthDir {
			t.Errorf("authDir = %q, want %q", svc.config.AuthDir, DefaultAuthDir)
		}
	})
}

func TestMaterializeRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *MaterializeRequest)
		wantErr string
	}{
		{
			name:    "valid_request",
			modify:  func(r *MaterializeRequest) {},
			wantErr: "",
		},
		{
			name:    "empty_authProfileID",
			modify:  func(r *MaterializeRequest) { r.AuthProfileID = "" },
			wantErr: "authProfileID must not be empty",
		},
		{
			name:    "empty_sandboxID",
			modify:  func(r *MaterializeRequest) { r.SandboxID = "" },
			wantErr: "sandboxID must not be empty",
		},
		{
			name:    "empty_attemptID",
			modify:  func(r *MaterializeRequest) { r.AttemptID = "" },
			wantErr: "attemptID must not be empty",
		},
		{
			name:    "empty_runID",
			modify:  func(r *MaterializeRequest) { r.RunID = "" },
			wantErr: "runID must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validMaterializeRequest()
			tt.modify(req)
			err := req.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestCleanup(t *testing.T) {
	t.Run("successful_cleanup", func(t *testing.T) {
		store := &authMatMockStore{}
		mockRunner := &authMatMockRunner{}

		idCounter := 0
		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("evt-%d", idCounter)
			},
		})

		err := svc.Cleanup(context.Background(), "sandbox-001", "att-001", "run-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify one Exec call: rm -rf.
		if len(mockRunner.execCalls) != 1 {
			t.Fatalf("execCalls = %d, want 1", len(mockRunner.execCalls))
		}

		rmCall := mockRunner.execCalls[0]
		if rmCall.SandboxID != "sandbox-001" {
			t.Errorf("rm sandboxID = %q, want %q", rmCall.SandboxID, "sandbox-001")
		}
		if !strings.Contains(rmCall.Command, "rm -rf") {
			t.Errorf("rm command = %q, want to contain 'rm -rf'", rmCall.Command)
		}
		if !strings.Contains(rmCall.Command, DefaultAuthDir) {
			t.Errorf("rm command = %q, want to contain %q", rmCall.Command, DefaultAuthDir)
		}

		// Verify events: auth_cleanup_started + auth_cleanup_done.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
		}

		evt0 := store.insertedEvents[0]
		if evt0.EventType != "auth_cleanup_started" {
			t.Errorf("event[0] type = %q, want %q", evt0.EventType, "auth_cleanup_started")
		}
		if evt0.ID != "evt-1" {
			t.Errorf("event[0] id = %q, want %q", evt0.ID, "evt-1")
		}

		evt1 := store.insertedEvents[1]
		if evt1.EventType != "auth_cleanup_done" {
			t.Errorf("event[1] type = %q, want %q", evt1.EventType, "auth_cleanup_done")
		}
		if evt1.ID != "evt-2" {
			t.Errorf("event[1] id = %q, want %q", evt1.ID, "evt-2")
		}

		// Verify done payload has no error.
		if evt1.PayloadJSON != nil {
			var payload authMaterializationEventPayload
			if err := json.Unmarshal([]byte(*evt1.PayloadJSON), &payload); err != nil {
				t.Fatalf("event[1] payload unmarshal: %v", err)
			}
			if payload.Error != "" {
				t.Errorf("event[1] payload error = %q, want empty", payload.Error)
			}
			if payload.SandboxID != "sandbox-001" {
				t.Errorf("event[1] payload sandbox_id = %q, want %q", payload.SandboxID, "sandbox-001")
			}
		}
	})

	t.Run("cleanup_exec_error", func(t *testing.T) {
		store := &authMatMockStore{}
		mockRunner := &authMatMockRunner{
			execErrs: map[string]error{
				"rm": fmt.Errorf("sandbox unreachable"),
			},
		}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Cleanup(context.Background(), "sandbox-001", "att-001", "run-001")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "auth cleanup failed") {
			t.Errorf("error = %q, want to contain 'auth cleanup failed'", err.Error())
		}

		// Verify done event has error.
		doneEvents := filterEventsByType(store.insertedEvents, "auth_cleanup_done")
		if len(doneEvents) != 1 {
			t.Fatalf("auth_cleanup_done events = %d, want 1", len(doneEvents))
		}
		var payload authMaterializationEventPayload
		if err := json.Unmarshal([]byte(*doneEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if !strings.Contains(payload.Error, "sandbox unreachable") {
			t.Errorf("payload error = %q, want to contain 'sandbox unreachable'", payload.Error)
		}
	})

	t.Run("cleanup_nonzero_exit_code", func(t *testing.T) {
		store := &authMatMockStore{}
		mockRunner := &authMatMockRunner{
			execResults: map[string]*runner.ExecResult{
				"rm": {ExitCode: 1, Stderr: "operation not permitted"},
			},
		}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Cleanup(context.Background(), "sandbox-001", "att-001", "run-001")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "auth cleanup failed") {
			t.Errorf("error = %q, want to contain 'auth cleanup failed'", err.Error())
		}
		if !strings.Contains(err.Error(), "exit code 1") {
			t.Errorf("error = %q, want to contain 'exit code 1'", err.Error())
		}

		// Verify done event has error and exit_code.
		doneEvents := filterEventsByType(store.insertedEvents, "auth_cleanup_done")
		if len(doneEvents) != 1 {
			t.Fatalf("auth_cleanup_done events = %d, want 1", len(doneEvents))
		}
		var payload authMaterializationEventPayload
		if err := json.Unmarshal([]byte(*doneEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.ExitCode == nil || *payload.ExitCode != 1 {
			t.Errorf("payload exit_code = %v, want 1", payload.ExitCode)
		}
	})

	t.Run("empty_sandboxID", func(t *testing.T) {
		svc := NewAuthMaterializationService(&authMatMockStore{}, &authMatMockRunner{}, AuthMaterializationConfig{})

		err := svc.Cleanup(context.Background(), "", "att-001", "run-001")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "sandboxID must not be empty") {
			t.Errorf("error = %q, want to contain validation message", err.Error())
		}
	})

	t.Run("empty_attemptID", func(t *testing.T) {
		svc := NewAuthMaterializationService(&authMatMockStore{}, &authMatMockRunner{}, AuthMaterializationConfig{})

		err := svc.Cleanup(context.Background(), "sandbox-001", "", "run-001")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "attemptID must not be empty") {
			t.Errorf("error = %q, want to contain validation message", err.Error())
		}
	})

	t.Run("empty_runID", func(t *testing.T) {
		svc := NewAuthMaterializationService(&authMatMockStore{}, &authMatMockRunner{}, AuthMaterializationConfig{})

		err := svc.Cleanup(context.Background(), "sandbox-001", "att-001", "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "runID must not be empty") {
			t.Errorf("error = %q, want to contain validation message", err.Error())
		}
	})

	t.Run("cleanup_event_failure_does_not_block", func(t *testing.T) {
		store := &authMatMockStore{
			insertEventErr: fmt.Errorf("event insert failed"),
		}
		mockRunner := &authMatMockRunner{}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Cleanup(context.Background(), "sandbox-001", "att-001", "run-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Exec call should still have happened.
		if len(mockRunner.execCalls) != 1 {
			t.Errorf("execCalls = %d, want 1", len(mockRunner.execCalls))
		}
	})

	t.Run("nil_IDFunc_uses_empty_event_id", func(t *testing.T) {
		store := &authMatMockStore{}
		mockRunner := &authMatMockRunner{}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{})

		err := svc.Cleanup(context.Background(), "sandbox-001", "att-001", "run-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i, evt := range store.insertedEvents {
			if evt.ID != "" {
				t.Errorf("event[%d] id = %q, want empty (nil IDFunc)", i, evt.ID)
			}
		}
	})

	t.Run("custom_auth_dir_cleanup", func(t *testing.T) {
		store := &authMatMockStore{}
		mockRunner := &authMatMockRunner{}

		svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{
			AuthDir: "/workspace/.secrets",
		})

		err := svc.Cleanup(context.Background(), "sandbox-001", "att-001", "run-001")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !strings.Contains(mockRunner.execCalls[0].Command, "/workspace/.secrets") {
			t.Errorf("rm command = %q, want to contain custom auth dir", mockRunner.execCalls[0].Command)
		}
	})
}

func TestEscapeShellSingleQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no_quotes",
			input: "hello world",
			want:  "hello world",
		},
		{
			name:  "single_quote",
			input: "it's",
			want:  "it'\\''s",
		},
		{
			name:  "multiple_quotes",
			input: "it's a 'test'",
			want:  "it'\\''s a '\\''test'\\''",
		},
		{
			name:  "empty_string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeShellSingleQuote(tt.input)
			if got != tt.want {
				t.Errorf("escapeShellSingleQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMaterializeIDFunc(t *testing.T) {
	store := &authMatMockStore{
		authProfile: linkedProfileWithSecret("secret"),
	}
	mockRunner := &authMatMockRunner{}

	idCounter := 0
	svc := NewAuthMaterializationService(store, mockRunner, AuthMaterializationConfig{
		IDFunc: func() string {
			idCounter++
			return fmt.Sprintf("custom-%d", idCounter)
		},
	})

	err := svc.Materialize(context.Background(), validMaterializeRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// auth_materialize_started + auth_materialize_completed = 2 events.
	if len(store.insertedEvents) != 2 {
		t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
	}
	if store.insertedEvents[0].ID != "custom-1" {
		t.Errorf("event[0] id = %q, want %q", store.insertedEvents[0].ID, "custom-1")
	}
	if store.insertedEvents[1].ID != "custom-2" {
		t.Errorf("event[1] id = %q, want %q", store.insertedEvents[1].ID, "custom-2")
	}
}
