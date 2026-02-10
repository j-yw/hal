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

// preflightMockRunner implements runner.Runner for preflight tests.
type preflightMockRunner struct {
	execResults map[string]*runner.ExecResult
	execErrs    map[string]error
	execCalls   []preflightExecCall
}

type preflightExecCall struct {
	SandboxID string
	Command   string
	WorkDir   string
}

func (r *preflightMockRunner) Exec(_ context.Context, sandboxID string, req *runner.ExecRequest) (*runner.ExecResult, error) {
	r.execCalls = append(r.execCalls, preflightExecCall{
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
	return &runner.ExecResult{ExitCode: 0}, nil
}

func (r *preflightMockRunner) CreateSandbox(_ context.Context, _ *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	return nil, nil
}

func (r *preflightMockRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}

func (r *preflightMockRunner) DestroySandbox(_ context.Context, _ string) error {
	return nil
}

func (r *preflightMockRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return nil, nil
}

// preflightMockStore extends mockStore for preflight tests.
type preflightMockStore struct {
	mockStore
	insertedEvents []*Event
	insertEventErr error
	authProfile    *AuthProfile
	getProfileErr  error
}

func (s *preflightMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.insertedEvents = append(s.insertedEvents, event)
	return s.insertEventErr
}

func (s *preflightMockStore) GetAuthProfile(_ context.Context, _ string) (*AuthProfile, error) {
	if s.getProfileErr != nil {
		return nil, s.getProfileErr
	}
	return s.authProfile, nil
}

func validPreflightRequest() *PreflightRequest {
	return &PreflightRequest{
		AuthProfileID:     "profile-001",
		SandboxID:         "sandbox-001",
		AttemptID:         "att-001",
		RunID:             "run-001",
		SandboxOS:         "linux",
		SandboxArch:       "amd64",
		SandboxCLIVersion: "1.2",
	}
}

func linkedProfileWithMetadata(metadataJSON string) *AuthProfile {
	meta := metadataJSON
	return &AuthProfile{
		ID:                  "profile-001",
		OwnerID:             "owner-001",
		Provider:            "anthropic",
		Mode:                "api_key",
		Status:              AuthProfileStatusLinked,
		MaxConcurrentRuns:   1,
		RuntimeMetadataJSON: &meta,
		Version:             1,
	}
}

func linkedProfileNoMetadata() *AuthProfile {
	return &AuthProfile{
		ID:                "profile-001",
		OwnerID:           "owner-001",
		Provider:          "anthropic",
		Mode:              "api_key",
		Status:            AuthProfileStatusLinked,
		MaxConcurrentRuns: 1,
		Version:           1,
	}
}

func TestPreflight(t *testing.T) {
	t.Run("successful_preflight_with_command", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"linux","arch":"amd64","cli_version":"1.2"}`),
		}
		mockRunner := &preflightMockRunner{}

		idCounter := 0
		svc := NewPreflightService(store, mockRunner, PreflightConfig{
			ProviderCommands: map[string]string{
				"anthropic": "claude --version",
			},
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("evt-%d", idCounter)
			},
		})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify one Exec call for the preflight command.
		if len(mockRunner.execCalls) != 1 {
			t.Fatalf("execCalls = %d, want 1", len(mockRunner.execCalls))
		}
		if mockRunner.execCalls[0].Command != "claude --version" {
			t.Errorf("exec command = %q, want %q", mockRunner.execCalls[0].Command, "claude --version")
		}
		if mockRunner.execCalls[0].SandboxID != "sandbox-001" {
			t.Errorf("exec sandboxID = %q, want %q", mockRunner.execCalls[0].SandboxID, "sandbox-001")
		}
		if mockRunner.execCalls[0].WorkDir != "/workspace" {
			t.Errorf("exec workDir = %q, want %q", mockRunner.execCalls[0].WorkDir, "/workspace")
		}

		// Verify events: preflight_started + preflight_completed.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
		}

		evt0 := store.insertedEvents[0]
		if evt0.EventType != "preflight_started" {
			t.Errorf("event[0] type = %q, want %q", evt0.EventType, "preflight_started")
		}
		if evt0.ID != "evt-1" {
			t.Errorf("event[0] id = %q, want %q", evt0.ID, "evt-1")
		}

		evt1 := store.insertedEvents[1]
		if evt1.EventType != "preflight_completed" {
			t.Errorf("event[1] type = %q, want %q", evt1.EventType, "preflight_completed")
		}
		if evt1.ID != "evt-2" {
			t.Errorf("event[1] id = %q, want %q", evt1.ID, "evt-2")
		}

		// Verify started payload has provider.
		if evt0.PayloadJSON != nil {
			var payload preflightEventPayload
			if err := json.Unmarshal([]byte(*evt0.PayloadJSON), &payload); err != nil {
				t.Fatalf("event[0] payload unmarshal: %v", err)
			}
			if payload.Provider != "anthropic" {
				t.Errorf("event[0] payload provider = %q, want %q", payload.Provider, "anthropic")
			}
			if payload.SandboxID != "sandbox-001" {
				t.Errorf("event[0] payload sandbox_id = %q, want %q", payload.SandboxID, "sandbox-001")
			}
			if payload.AuthProfileID != "profile-001" {
				t.Errorf("event[0] payload auth_profile_id = %q, want %q", payload.AuthProfileID, "profile-001")
			}
		} else {
			t.Error("event[0] payload_json is nil, want non-nil")
		}
	})

	t.Run("successful_preflight_no_command", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"linux","arch":"amd64","cli_version":"1.2"}`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// No Exec calls — no provider command configured.
		if len(mockRunner.execCalls) != 0 {
			t.Errorf("execCalls = %d, want 0 (no provider command)", len(mockRunner.execCalls))
		}

		// Events: preflight_started + preflight_completed.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
		}
		if store.insertedEvents[0].EventType != "preflight_started" {
			t.Errorf("event[0] type = %q, want %q", store.insertedEvents[0].EventType, "preflight_started")
		}
		if store.insertedEvents[1].EventType != "preflight_completed" {
			t.Errorf("event[1] type = %q, want %q", store.insertedEvents[1].EventType, "preflight_completed")
		}
	})

	t.Run("no_metadata_skips_compatibility_check", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileNoMetadata(),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Events: preflight_started + preflight_completed.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
		}
	})

	t.Run("os_mismatch_fails_with_incompatible", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"darwin","arch":"amd64","cli_version":"1.2"}`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "auth_profile_incompatible") {
			t.Errorf("error = %q, want to contain 'auth_profile_incompatible'", err.Error())
		}
		if !strings.Contains(err.Error(), "OS mismatch") {
			t.Errorf("error = %q, want to contain 'OS mismatch'", err.Error())
		}

		// Verify preflight_failed event emitted with error_code.
		failedEvents := filterEventsByType(store.insertedEvents, "preflight_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("preflight_failed events = %d, want 1", len(failedEvents))
		}
		var payload preflightEventPayload
		if err := json.Unmarshal([]byte(*failedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.ErrorCode != string(FailureAuthProfileIncompatible) {
			t.Errorf("payload error_code = %q, want %q", payload.ErrorCode, FailureAuthProfileIncompatible)
		}
		if payload.Step != "compatibility_check" {
			t.Errorf("payload step = %q, want %q", payload.Step, "compatibility_check")
		}

		// No Exec calls — compatibility check fails before command execution.
		if len(mockRunner.execCalls) != 0 {
			t.Errorf("execCalls = %d, want 0 (stopped at compatibility check)", len(mockRunner.execCalls))
		}
	})

	t.Run("arch_mismatch_fails_with_incompatible", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"linux","arch":"arm64","cli_version":"1.2"}`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "architecture mismatch") {
			t.Errorf("error = %q, want to contain 'architecture mismatch'", err.Error())
		}
		if !strings.Contains(err.Error(), "auth_profile_incompatible") {
			t.Errorf("error = %q, want to contain 'auth_profile_incompatible'", err.Error())
		}
	})

	t.Run("cli_major_version_mismatch", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"linux","arch":"amd64","cli_version":"2.0"}`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "CLI major version mismatch") {
			t.Errorf("error = %q, want to contain 'CLI major version mismatch'", err.Error())
		}
		if !strings.Contains(err.Error(), "auth_profile_incompatible") {
			t.Errorf("error = %q, want to contain 'auth_profile_incompatible'", err.Error())
		}
	})

	t.Run("cli_minor_version_mismatch", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"linux","arch":"amd64","cli_version":"1.5"}`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "CLI minor version mismatch") {
			t.Errorf("error = %q, want to contain 'CLI minor version mismatch'", err.Error())
		}
	})

	t.Run("multiple_mismatches_reported", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"darwin","arch":"arm64","cli_version":"2.0"}`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "OS mismatch") {
			t.Errorf("error = %q, want to contain 'OS mismatch'", err.Error())
		}
		if !strings.Contains(err.Error(), "architecture mismatch") {
			t.Errorf("error = %q, want to contain 'architecture mismatch'", err.Error())
		}
		if !strings.Contains(err.Error(), "CLI major version mismatch") {
			t.Errorf("error = %q, want to contain 'CLI major version mismatch'", err.Error())
		}
	})

	t.Run("case_insensitive_os_match", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"Linux","arch":"amd64","cli_version":"1.2"}`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v (case-insensitive OS should match)", err)
		}
	})

	t.Run("case_insensitive_arch_match", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"linux","arch":"AMD64","cli_version":"1.2"}`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v (case-insensitive arch should match)", err)
		}
	})

	t.Run("empty_metadata_fields_skip_check", func(t *testing.T) {
		// Metadata with only OS set — arch and cli_version checks are skipped.
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"linux"}`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		req := validPreflightRequest()
		req.SandboxArch = "arm64"       // Different arch, but metadata doesn't specify arch.
		req.SandboxCLIVersion = "99.99" // Different version, but metadata doesn't specify version.

		err := svc.Preflight(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v (empty metadata fields should skip check)", err)
		}
	})

	t.Run("empty_sandbox_fields_skip_check", func(t *testing.T) {
		// Sandbox doesn't report OS/arch/version — checks are skipped.
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"darwin","arch":"arm64","cli_version":"2.0"}`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		req := validPreflightRequest()
		req.SandboxOS = ""
		req.SandboxArch = ""
		req.SandboxCLIVersion = ""

		err := svc.Preflight(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v (empty sandbox fields should skip check)", err)
		}
	})

	t.Run("malformed_metadata_json", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{invalid json`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to parse runtime metadata") {
			t.Errorf("error = %q, want to contain 'failed to parse runtime metadata'", err.Error())
		}

		// Verify preflight_failed event with error_code.
		failedEvents := filterEventsByType(store.insertedEvents, "preflight_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("preflight_failed events = %d, want 1", len(failedEvents))
		}
		var payload preflightEventPayload
		if err := json.Unmarshal([]byte(*failedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.ErrorCode != string(FailureAuthProfileIncompatible) {
			t.Errorf("payload error_code = %q, want %q", payload.ErrorCode, FailureAuthProfileIncompatible)
		}
		if payload.Step != "metadata_parse" {
			t.Errorf("payload step = %q, want %q", payload.Step, "metadata_parse")
		}
	})

	t.Run("get_profile_error", func(t *testing.T) {
		store := &preflightMockStore{
			getProfileErr: fmt.Errorf("database unavailable"),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to get auth profile") {
			t.Errorf("error = %q, want to contain 'failed to get auth profile'", err.Error())
		}
	})

	t.Run("preflight_command_exec_error", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileNoMetadata(),
		}
		mockRunner := &preflightMockRunner{
			execErrs: map[string]error{
				"claude": fmt.Errorf("sandbox unreachable"),
			},
		}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{
			ProviderCommands: map[string]string{
				"anthropic": "claude --version",
			},
		})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "command execution failed") {
			t.Errorf("error = %q, want to contain 'command execution failed'", err.Error())
		}

		// Verify preflight_failed event.
		failedEvents := filterEventsByType(store.insertedEvents, "preflight_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("preflight_failed events = %d, want 1", len(failedEvents))
		}
		var payload preflightEventPayload
		if err := json.Unmarshal([]byte(*failedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.Step != "preflight_command" {
			t.Errorf("payload step = %q, want %q", payload.Step, "preflight_command")
		}
		if !strings.Contains(payload.Error, "sandbox unreachable") {
			t.Errorf("payload error = %q, want to contain 'sandbox unreachable'", payload.Error)
		}
	})

	t.Run("preflight_command_nonzero_exit", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileNoMetadata(),
		}
		mockRunner := &preflightMockRunner{
			execResults: map[string]*runner.ExecResult{
				"claude": {ExitCode: 1, Stderr: "authentication failed"},
			},
		}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{
			ProviderCommands: map[string]string{
				"anthropic": "claude --version",
			},
		})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "command failed") {
			t.Errorf("error = %q, want to contain 'command failed'", err.Error())
		}
		if !strings.Contains(err.Error(), "exit code 1") {
			t.Errorf("error = %q, want to contain 'exit code 1'", err.Error())
		}

		// Verify preflight_failed event with exit_code.
		failedEvents := filterEventsByType(store.insertedEvents, "preflight_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("preflight_failed events = %d, want 1", len(failedEvents))
		}
		var payload preflightEventPayload
		if err := json.Unmarshal([]byte(*failedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.ExitCode == nil || *payload.ExitCode != 1 {
			t.Errorf("payload exit_code = %v, want 1", payload.ExitCode)
		}
		if !strings.Contains(payload.Error, "authentication failed") {
			t.Errorf("payload error = %q, want to contain 'authentication failed'", payload.Error)
		}
	})

	t.Run("preflight_command_stderr_fallback_to_stdout", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileNoMetadata(),
		}
		mockRunner := &preflightMockRunner{
			execResults: map[string]*runner.ExecResult{
				"claude": {ExitCode: 1, Stdout: "stdout error output"},
			},
		}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{
			ProviderCommands: map[string]string{
				"anthropic": "claude --version",
			},
		})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "stdout error output") {
			t.Errorf("error = %q, want to contain 'stdout error output'", err.Error())
		}
	})

	t.Run("event_failure_does_not_block", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile:    linkedProfileNoMetadata(),
			insertEventErr: fmt.Errorf("event insert failed"),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{
			ProviderCommands: map[string]string{
				"anthropic": "claude --version",
			},
		})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Exec call should still have happened.
		if len(mockRunner.execCalls) != 1 {
			t.Errorf("execCalls = %d, want 1", len(mockRunner.execCalls))
		}
	})

	t.Run("nil_IDFunc_uses_empty_event_id", func(t *testing.T) {
		store := &preflightMockStore{
			authProfile: linkedProfileNoMetadata(),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i, evt := range store.insertedEvents {
			if evt.ID != "" {
				t.Errorf("event[%d] id = %q, want empty (nil IDFunc)", i, evt.ID)
			}
		}
	})

	t.Run("compatibility_check_before_command_execution", func(t *testing.T) {
		// Incompatible metadata should fail before provider command runs.
		store := &preflightMockStore{
			authProfile: linkedProfileWithMetadata(`{"os":"darwin"}`),
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{
			ProviderCommands: map[string]string{
				"anthropic": "claude --version",
			},
		})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		// Command should NOT have been executed.
		if len(mockRunner.execCalls) != 0 {
			t.Errorf("execCalls = %d, want 0 (compatibility check fails first)", len(mockRunner.execCalls))
		}
	})

	t.Run("empty_metadata_json_string", func(t *testing.T) {
		empty := ""
		profile := linkedProfileNoMetadata()
		profile.RuntimeMetadataJSON = &empty
		store := &preflightMockStore{
			authProfile: profile,
		}
		mockRunner := &preflightMockRunner{}

		svc := NewPreflightService(store, mockRunner, PreflightConfig{})

		err := svc.Preflight(context.Background(), validPreflightRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v (empty metadata string should be skipped)", err)
		}
	})

	t.Run("defaults", func(t *testing.T) {
		svc := NewPreflightService(&preflightMockStore{}, &preflightMockRunner{}, PreflightConfig{})
		if svc.store == nil {
			t.Error("store is nil")
		}
		if svc.runner == nil {
			t.Error("runner is nil")
		}
		if svc.config.ProviderCommands == nil {
			t.Error("ProviderCommands is nil, want initialized empty map")
		}
	})
}

func TestPreflightRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *PreflightRequest)
		wantErr string
	}{
		{
			name:    "valid_request",
			modify:  func(r *PreflightRequest) {},
			wantErr: "",
		},
		{
			name:    "empty_authProfileID",
			modify:  func(r *PreflightRequest) { r.AuthProfileID = "" },
			wantErr: "authProfileID must not be empty",
		},
		{
			name:    "empty_sandboxID",
			modify:  func(r *PreflightRequest) { r.SandboxID = "" },
			wantErr: "sandboxID must not be empty",
		},
		{
			name:    "empty_attemptID",
			modify:  func(r *PreflightRequest) { r.AttemptID = "" },
			wantErr: "attemptID must not be empty",
		},
		{
			name:    "empty_runID",
			modify:  func(r *PreflightRequest) { r.RunID = "" },
			wantErr: "runID must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validPreflightRequest()
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

func TestCheckCompatibility(t *testing.T) {
	tests := []struct {
		name     string
		metadata RuntimeMetadata
		req      *PreflightRequest
		wantErr  string
	}{
		{
			name:     "fully_compatible",
			metadata: RuntimeMetadata{OS: "linux", Arch: "amd64", CLIVersion: "1.2"},
			req:      &PreflightRequest{SandboxOS: "linux", SandboxArch: "amd64", SandboxCLIVersion: "1.2"},
			wantErr:  "",
		},
		{
			name:     "os_mismatch",
			metadata: RuntimeMetadata{OS: "darwin"},
			req:      &PreflightRequest{SandboxOS: "linux"},
			wantErr:  "OS mismatch",
		},
		{
			name:     "arch_mismatch",
			metadata: RuntimeMetadata{Arch: "arm64"},
			req:      &PreflightRequest{SandboxArch: "amd64"},
			wantErr:  "architecture mismatch",
		},
		{
			name:     "cli_major_mismatch",
			metadata: RuntimeMetadata{CLIVersion: "2.0"},
			req:      &PreflightRequest{SandboxCLIVersion: "1.0"},
			wantErr:  "CLI major version mismatch",
		},
		{
			name:     "cli_minor_mismatch",
			metadata: RuntimeMetadata{CLIVersion: "1.3"},
			req:      &PreflightRequest{SandboxCLIVersion: "1.2"},
			wantErr:  "CLI minor version mismatch",
		},
		{
			name:     "same_major_different_patch_compatible",
			metadata: RuntimeMetadata{CLIVersion: "1.2"},
			req:      &PreflightRequest{SandboxCLIVersion: "1.2.5"},
			wantErr:  "",
		},
		{
			name:     "empty_metadata_os_skips",
			metadata: RuntimeMetadata{OS: ""},
			req:      &PreflightRequest{SandboxOS: "linux"},
			wantErr:  "",
		},
		{
			name:     "empty_sandbox_os_skips",
			metadata: RuntimeMetadata{OS: "darwin"},
			req:      &PreflightRequest{SandboxOS: ""},
			wantErr:  "",
		},
		{
			name:     "case_insensitive_os",
			metadata: RuntimeMetadata{OS: "Linux"},
			req:      &PreflightRequest{SandboxOS: "linux"},
			wantErr:  "",
		},
		{
			name:     "case_insensitive_arch",
			metadata: RuntimeMetadata{Arch: "AMD64"},
			req:      &PreflightRequest{SandboxArch: "amd64"},
			wantErr:  "",
		},
		{
			name:     "cli_version_only_major",
			metadata: RuntimeMetadata{CLIVersion: "2"},
			req:      &PreflightRequest{SandboxCLIVersion: "1"},
			wantErr:  "CLI major version mismatch",
		},
		{
			name:     "cli_version_same_major_no_minor",
			metadata: RuntimeMetadata{CLIVersion: "1"},
			req:      &PreflightRequest{SandboxCLIVersion: "1"},
			wantErr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkCompatibility(tt.metadata, tt.req)
			if tt.wantErr == "" {
				if result != "" {
					t.Errorf("checkCompatibility() = %q, want empty (compatible)", result)
				}
				return
			}
			if result == "" {
				t.Fatalf("expected incompatibility containing %q, got empty", tt.wantErr)
			}
			if !strings.Contains(result, tt.wantErr) {
				t.Errorf("checkCompatibility() = %q, want to contain %q", result, tt.wantErr)
			}
		})
	}
}

func TestParseMajorMinor(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		wantMajor string
		wantMinor string
	}{
		{name: "major.minor", version: "1.2", wantMajor: "1", wantMinor: "2"},
		{name: "major.minor.patch", version: "1.2.3", wantMajor: "1", wantMinor: "2"},
		{name: "major_only", version: "1", wantMajor: "1", wantMinor: ""},
		{name: "empty", version: "", wantMajor: "", wantMinor: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, minor := parseMajorMinor(tt.version)
			if major != tt.wantMajor {
				t.Errorf("major = %q, want %q", major, tt.wantMajor)
			}
			if minor != tt.wantMinor {
				t.Errorf("minor = %q, want %q", minor, tt.wantMinor)
			}
		})
	}
}

func TestPreflightIDFunc(t *testing.T) {
	store := &preflightMockStore{
		authProfile: linkedProfileNoMetadata(),
	}
	mockRunner := &preflightMockRunner{}

	idCounter := 0
	svc := NewPreflightService(store, mockRunner, PreflightConfig{
		IDFunc: func() string {
			idCounter++
			return fmt.Sprintf("custom-%d", idCounter)
		},
	})

	err := svc.Preflight(context.Background(), validPreflightRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// preflight_started + preflight_completed = 2 events.
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
