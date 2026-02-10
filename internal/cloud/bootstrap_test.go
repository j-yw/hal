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

// bootstrapMockRunner implements runner.Runner for bootstrap service tests.
type bootstrapMockRunner struct {
	// execResults maps command substrings to results for flexible matching.
	execResults map[string]*runner.ExecResult
	execErrs    map[string]error
	// execCalls records all Exec calls for verification.
	execCalls []bootstrapExecCall
}

type bootstrapExecCall struct {
	SandboxID string
	Command   string
	WorkDir   string
}

func (r *bootstrapMockRunner) Exec(_ context.Context, sandboxID string, req *runner.ExecRequest) (*runner.ExecResult, error) {
	r.execCalls = append(r.execCalls, bootstrapExecCall{
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

func (r *bootstrapMockRunner) CreateSandbox(_ context.Context, _ *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	return nil, nil
}

func (r *bootstrapMockRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}

func (r *bootstrapMockRunner) DestroySandbox(_ context.Context, _ string) error {
	return nil
}

func (r *bootstrapMockRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return nil, nil
}

// bootstrapMockStore extends mockStore for bootstrap service tests.
type bootstrapMockStore struct {
	mockStore
	insertedEvents []*Event
	insertEventErr error
}

func (s *bootstrapMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.insertedEvents = append(s.insertedEvents, event)
	return s.insertEventErr
}

func validBootstrapRequest() *BootstrapRequest {
	return &BootstrapRequest{
		Repo:      "https://github.com/org/repo.git",
		Branch:    "main",
		SandboxID: "sandbox-001",
		AttemptID: "att-001",
		RunID:     "run-001",
	}
}

func TestBootstrap(t *testing.T) {
	t.Run("successful_bootstrap", func(t *testing.T) {
		store := &bootstrapMockStore{}
		mockRunner := &bootstrapMockRunner{
			execResults: map[string]*runner.ExecResult{
				"git clone": {ExitCode: 0, Stdout: "Cloning into '/workspace'..."},
				"hal init":  {ExitCode: 0, Stdout: "Initialized .hal directory"},
			},
		}

		idCounter := 0
		svc := NewBootstrapService(store, mockRunner, BootstrapConfig{
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("evt-%d", idCounter)
			},
		})

		err := svc.Bootstrap(context.Background(), validBootstrapRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify two Exec calls: clone + init.
		if len(mockRunner.execCalls) != 2 {
			t.Fatalf("execCalls = %d, want 2", len(mockRunner.execCalls))
		}

		// Clone call.
		clone := mockRunner.execCalls[0]
		if clone.SandboxID != "sandbox-001" {
			t.Errorf("clone sandboxID = %q, want %q", clone.SandboxID, "sandbox-001")
		}
		if !strings.Contains(clone.Command, "git clone") {
			t.Errorf("clone command = %q, want to contain 'git clone'", clone.Command)
		}
		if !strings.Contains(clone.Command, "--branch main") {
			t.Errorf("clone command = %q, want to contain '--branch main'", clone.Command)
		}
		if !strings.Contains(clone.Command, "https://github.com/org/repo.git") {
			t.Errorf("clone command = %q, want to contain repo URL", clone.Command)
		}

		// Init call.
		init := mockRunner.execCalls[1]
		if init.SandboxID != "sandbox-001" {
			t.Errorf("init sandboxID = %q, want %q", init.SandboxID, "sandbox-001")
		}
		if init.Command != "hal init" {
			t.Errorf("init command = %q, want %q", init.Command, "hal init")
		}
		if init.WorkDir != "/workspace" {
			t.Errorf("init workDir = %q, want %q", init.WorkDir, "/workspace")
		}

		// Verify events: bootstrap_started + bootstrap_completed.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
		}

		evt0 := store.insertedEvents[0]
		if evt0.EventType != "bootstrap_started" {
			t.Errorf("event[0] type = %q, want %q", evt0.EventType, "bootstrap_started")
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
		// Verify started payload.
		if evt0.PayloadJSON != nil {
			var payload bootstrapEventPayload
			if err := json.Unmarshal([]byte(*evt0.PayloadJSON), &payload); err != nil {
				t.Fatalf("event[0] payload unmarshal: %v", err)
			}
			if payload.SandboxID != "sandbox-001" {
				t.Errorf("event[0] payload sandbox_id = %q, want %q", payload.SandboxID, "sandbox-001")
			}
			if payload.Repo != "https://github.com/org/repo.git" {
				t.Errorf("event[0] payload repo = %q, want repo URL", payload.Repo)
			}
			if payload.Branch != "main" {
				t.Errorf("event[0] payload branch = %q, want %q", payload.Branch, "main")
			}
		} else {
			t.Error("event[0] payload_json is nil, want non-nil")
		}

		evt1 := store.insertedEvents[1]
		if evt1.EventType != "bootstrap_completed" {
			t.Errorf("event[1] type = %q, want %q", evt1.EventType, "bootstrap_completed")
		}
		if evt1.ID != "evt-2" {
			t.Errorf("event[1] id = %q, want %q", evt1.ID, "evt-2")
		}
	})

	t.Run("clone_exec_error", func(t *testing.T) {
		store := &bootstrapMockStore{}
		mockRunner := &bootstrapMockRunner{
			execErrs: map[string]error{
				"git clone": fmt.Errorf("connection refused"),
			},
		}

		svc := NewBootstrapService(store, mockRunner, BootstrapConfig{})

		err := svc.Bootstrap(context.Background(), validBootstrapRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "bootstrap clone failed") {
			t.Errorf("error = %q, want to contain 'bootstrap clone failed'", err.Error())
		}
		if !strings.Contains(err.Error(), "connection refused") {
			t.Errorf("error = %q, want to contain wrapped cause", err.Error())
		}

		// Verify bootstrap_failed event was emitted with step=clone.
		failedEvents := filterEventsByType(store.insertedEvents, "bootstrap_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("bootstrap_failed events = %d, want 1", len(failedEvents))
		}
		var payload bootstrapEventPayload
		if err := json.Unmarshal([]byte(*failedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.Step != "clone" {
			t.Errorf("payload step = %q, want %q", payload.Step, "clone")
		}
		if !strings.Contains(payload.Error, "connection refused") {
			t.Errorf("payload error = %q, want to contain 'connection refused'", payload.Error)
		}

		// Init should not have been called.
		for _, call := range mockRunner.execCalls {
			if strings.Contains(call.Command, "hal init") {
				t.Error("hal init should not be called when clone fails")
			}
		}
	})

	t.Run("clone_nonzero_exit_code", func(t *testing.T) {
		store := &bootstrapMockStore{}
		mockRunner := &bootstrapMockRunner{
			execResults: map[string]*runner.ExecResult{
				"git clone": {ExitCode: 128, Stderr: "fatal: repository not found"},
			},
		}

		svc := NewBootstrapService(store, mockRunner, BootstrapConfig{})

		err := svc.Bootstrap(context.Background(), validBootstrapRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "bootstrap clone failed") {
			t.Errorf("error = %q, want to contain 'bootstrap clone failed'", err.Error())
		}
		if !strings.Contains(err.Error(), "exit code 128") {
			t.Errorf("error = %q, want to contain 'exit code 128'", err.Error())
		}

		// Verify bootstrap_failed payload has exit_code.
		failedEvents := filterEventsByType(store.insertedEvents, "bootstrap_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("bootstrap_failed events = %d, want 1", len(failedEvents))
		}
		var payload bootstrapEventPayload
		if err := json.Unmarshal([]byte(*failedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.ExitCode == nil || *payload.ExitCode != 128 {
			t.Errorf("payload exit_code = %v, want 128", payload.ExitCode)
		}
		if payload.Step != "clone" {
			t.Errorf("payload step = %q, want %q", payload.Step, "clone")
		}
	})

	t.Run("init_exec_error", func(t *testing.T) {
		store := &bootstrapMockStore{}
		mockRunner := &bootstrapMockRunner{
			execResults: map[string]*runner.ExecResult{
				"git clone": {ExitCode: 0},
			},
			execErrs: map[string]error{
				"hal init": fmt.Errorf("sandbox process crashed"),
			},
		}

		svc := NewBootstrapService(store, mockRunner, BootstrapConfig{})

		err := svc.Bootstrap(context.Background(), validBootstrapRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "bootstrap init failed") {
			t.Errorf("error = %q, want to contain 'bootstrap init failed'", err.Error())
		}

		// Verify bootstrap_failed event with step=init.
		failedEvents := filterEventsByType(store.insertedEvents, "bootstrap_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("bootstrap_failed events = %d, want 1", len(failedEvents))
		}
		var payload bootstrapEventPayload
		if err := json.Unmarshal([]byte(*failedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.Step != "init" {
			t.Errorf("payload step = %q, want %q", payload.Step, "init")
		}
	})

	t.Run("init_nonzero_exit_code", func(t *testing.T) {
		store := &bootstrapMockStore{}
		mockRunner := &bootstrapMockRunner{
			execResults: map[string]*runner.ExecResult{
				"git clone": {ExitCode: 0},
				"hal init":  {ExitCode: 1, Stderr: "permission denied"},
			},
		}

		svc := NewBootstrapService(store, mockRunner, BootstrapConfig{})

		err := svc.Bootstrap(context.Background(), validBootstrapRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "bootstrap init failed") {
			t.Errorf("error = %q, want to contain 'bootstrap init failed'", err.Error())
		}
		if !strings.Contains(err.Error(), "exit code 1") {
			t.Errorf("error = %q, want to contain 'exit code 1'", err.Error())
		}

		failedEvents := filterEventsByType(store.insertedEvents, "bootstrap_failed")
		if len(failedEvents) != 1 {
			t.Fatalf("bootstrap_failed events = %d, want 1", len(failedEvents))
		}
		var payload bootstrapEventPayload
		if err := json.Unmarshal([]byte(*failedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.Step != "init" {
			t.Errorf("payload step = %q, want %q", payload.Step, "init")
		}
		if payload.ExitCode == nil || *payload.ExitCode != 1 {
			t.Errorf("payload exit_code = %v, want 1", payload.ExitCode)
		}
	})

	t.Run("clone_uses_stderr_over_stdout_for_error", func(t *testing.T) {
		store := &bootstrapMockStore{}
		mockRunner := &bootstrapMockRunner{
			execResults: map[string]*runner.ExecResult{
				"git clone": {ExitCode: 1, Stderr: "stderr message", Stdout: "stdout message"},
			},
		}

		svc := NewBootstrapService(store, mockRunner, BootstrapConfig{})

		err := svc.Bootstrap(context.Background(), validBootstrapRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		// Should prefer stderr when available.
		if !strings.Contains(err.Error(), "stderr message") {
			t.Errorf("error = %q, want to contain stderr message", err.Error())
		}
	})

	t.Run("clone_falls_back_to_stdout_when_no_stderr", func(t *testing.T) {
		store := &bootstrapMockStore{}
		mockRunner := &bootstrapMockRunner{
			execResults: map[string]*runner.ExecResult{
				"git clone": {ExitCode: 1, Stderr: "", Stdout: "stdout only"},
			},
		}

		svc := NewBootstrapService(store, mockRunner, BootstrapConfig{})

		err := svc.Bootstrap(context.Background(), validBootstrapRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "stdout only") {
			t.Errorf("error = %q, want to contain stdout fallback", err.Error())
		}
	})

	t.Run("event_emission_failure_does_not_block", func(t *testing.T) {
		store := &bootstrapMockStore{
			insertEventErr: fmt.Errorf("event insert failed"),
		}
		mockRunner := &bootstrapMockRunner{
			execResults: map[string]*runner.ExecResult{
				"git clone": {ExitCode: 0},
				"hal init":  {ExitCode: 0},
			},
		}

		svc := NewBootstrapService(store, mockRunner, BootstrapConfig{})

		err := svc.Bootstrap(context.Background(), validBootstrapRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Both Exec calls should still have happened.
		if len(mockRunner.execCalls) != 2 {
			t.Errorf("execCalls = %d, want 2", len(mockRunner.execCalls))
		}
	})

	t.Run("nil_IDFunc_uses_empty_event_id", func(t *testing.T) {
		store := &bootstrapMockStore{}
		mockRunner := &bootstrapMockRunner{
			execResults: map[string]*runner.ExecResult{
				"git clone": {ExitCode: 0},
				"hal init":  {ExitCode: 0},
			},
		}

		svc := NewBootstrapService(store, mockRunner, BootstrapConfig{})

		err := svc.Bootstrap(context.Background(), validBootstrapRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for i, evt := range store.insertedEvents {
			if evt.ID != "" {
				t.Errorf("event[%d] id = %q, want empty (nil IDFunc)", i, evt.ID)
			}
		}
	})

	t.Run("defaults", func(t *testing.T) {
		svc := NewBootstrapService(&bootstrapMockStore{}, &bootstrapMockRunner{}, BootstrapConfig{})
		if svc.store == nil {
			t.Error("store is nil")
		}
		if svc.runner == nil {
			t.Error("runner is nil")
		}
	})
}

func TestBootstrapRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *BootstrapRequest)
		wantErr string
	}{
		{
			name:    "valid_request",
			modify:  func(r *BootstrapRequest) {},
			wantErr: "",
		},
		{
			name:    "empty_repo",
			modify:  func(r *BootstrapRequest) { r.Repo = "" },
			wantErr: "repo must not be empty",
		},
		{
			name:    "empty_branch",
			modify:  func(r *BootstrapRequest) { r.Branch = "" },
			wantErr: "branch must not be empty",
		},
		{
			name:    "empty_sandboxID",
			modify:  func(r *BootstrapRequest) { r.SandboxID = "" },
			wantErr: "sandboxID must not be empty",
		},
		{
			name:    "empty_attemptID",
			modify:  func(r *BootstrapRequest) { r.AttemptID = "" },
			wantErr: "attemptID must not be empty",
		},
		{
			name:    "empty_runID",
			modify:  func(r *BootstrapRequest) { r.RunID = "" },
			wantErr: "runID must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validBootstrapRequest()
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

func TestBootstrapIDFunc(t *testing.T) {
	store := &bootstrapMockStore{}
	mockRunner := &bootstrapMockRunner{
		execResults: map[string]*runner.ExecResult{
			"git clone": {ExitCode: 0},
			"hal init":  {ExitCode: 0},
		},
	}

	idCounter := 0
	svc := NewBootstrapService(store, mockRunner, BootstrapConfig{
		IDFunc: func() string {
			idCounter++
			return fmt.Sprintf("custom-%d", idCounter)
		},
	})

	err := svc.Bootstrap(context.Background(), validBootstrapRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// bootstrap_started + bootstrap_completed = 2 events.
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

func TestBootstrapFailedEventOnCloneStopsAttempt(t *testing.T) {
	// Verifies that clone failure emits bootstrap_failed and no further
	// commands are executed (init is never called).
	store := &bootstrapMockStore{}
	mockRunner := &bootstrapMockRunner{
		execResults: map[string]*runner.ExecResult{
			"git clone": {ExitCode: 128, Stderr: "remote: Repository not found"},
		},
	}

	svc := NewBootstrapService(store, mockRunner, BootstrapConfig{})

	err := svc.Bootstrap(context.Background(), validBootstrapRequest())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Only 1 Exec call (clone), init should not have been called.
	if len(mockRunner.execCalls) != 1 {
		t.Fatalf("execCalls = %d, want 1 (clone only)", len(mockRunner.execCalls))
	}

	// Events: bootstrap_started + bootstrap_failed.
	if len(store.insertedEvents) != 2 {
		t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
	}
	if store.insertedEvents[0].EventType != "bootstrap_started" {
		t.Errorf("event[0] type = %q, want %q", store.insertedEvents[0].EventType, "bootstrap_started")
	}
	if store.insertedEvents[1].EventType != "bootstrap_failed" {
		t.Errorf("event[1] type = %q, want %q", store.insertedEvents[1].EventType, "bootstrap_failed")
	}
}

// filterEventsByType returns events matching the given event type.
func filterEventsByType(events []*Event, eventType string) []*Event {
	var result []*Event
	for _, e := range events {
		if e.EventType == eventType {
			result = append(result, e)
		}
	}
	return result
}
