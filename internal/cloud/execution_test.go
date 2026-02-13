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

// executionMockRunner implements runner.Runner for execution service tests.
type executionMockRunner struct {
	execResult *runner.ExecResult
	execErr    error
	execCalls  []executionExecCall
}

type executionExecCall struct {
	SandboxID string
	Command   string
	WorkDir   string
}

func (r *executionMockRunner) Exec(_ context.Context, sandboxID string, req *runner.ExecRequest) (*runner.ExecResult, error) {
	r.execCalls = append(r.execCalls, executionExecCall{
		SandboxID: sandboxID,
		Command:   req.Command,
		WorkDir:   req.WorkDir,
	})
	if r.execErr != nil {
		return nil, r.execErr
	}
	if r.execResult != nil {
		return r.execResult, nil
	}
	return &runner.ExecResult{ExitCode: 0}, nil
}

func (r *executionMockRunner) CreateSandbox(_ context.Context, _ *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	return nil, nil
}

func (r *executionMockRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, nil
}

func (r *executionMockRunner) DestroySandbox(_ context.Context, _ string) error { return nil }

func (r *executionMockRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return nil, nil
}

// executionMockStore extends mockStore for execution service tests.
type executionMockStore struct {
	mockStore
	insertedEvents []*Event
	insertEventErr error
}

func (s *executionMockStore) InsertEvent(_ context.Context, event *Event) error {
	s.insertedEvents = append(s.insertedEvents, event)
	return s.insertEventErr
}

func validExecutionRequest() *ExecutionRequest {
	return &ExecutionRequest{
		SandboxID:    "sandbox-001",
		AttemptID:    "att-001",
		RunID:        "run-001",
		WorkflowKind: WorkflowKindAuto,
		Mode:         ExecutionModeUntilComplete,
	}
}

func TestExecute(t *testing.T) {
	t.Run("successful_until_complete", func(t *testing.T) {
		store := &executionMockStore{}
		mockRunner := &executionMockRunner{
			execResult: &runner.ExecResult{
				ExitCode: 0,
				Stdout:   "All stories complete.",
			},
		}

		idCounter := 0
		svc := NewExecutionService(store, mockRunner, ExecutionConfig{
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("evt-%d", idCounter)
			},
		})

		result, err := svc.Execute(context.Background(), validExecutionRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify result.
		if result.ExitCode != 0 {
			t.Errorf("exit_code = %d, want 0", result.ExitCode)
		}
		if result.Output != "All stories complete." {
			t.Errorf("output = %q, want %q", result.Output, "All stories complete.")
		}

		// Verify Exec call.
		if len(mockRunner.execCalls) != 1 {
			t.Fatalf("execCalls = %d, want 1", len(mockRunner.execCalls))
		}
		call := mockRunner.execCalls[0]
		if call.SandboxID != "sandbox-001" {
			t.Errorf("sandboxID = %q, want %q", call.SandboxID, "sandbox-001")
		}
		if call.Command != "hal auto" {
			t.Errorf("command = %q, want %q", call.Command, "hal auto")
		}
		if call.WorkDir != "/workspace" {
			t.Errorf("workDir = %q, want %q", call.WorkDir, "/workspace")
		}

		// Verify events: execution_started + execution_finished.
		if len(store.insertedEvents) != 2 {
			t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
		}

		evt0 := store.insertedEvents[0]
		if evt0.EventType != "execution_started" {
			t.Errorf("event[0] type = %q, want %q", evt0.EventType, "execution_started")
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

		// Verify started payload includes mode and workflow_kind.
		if evt0.PayloadJSON != nil {
			var payload executionEventPayload
			if err := json.Unmarshal([]byte(*evt0.PayloadJSON), &payload); err != nil {
				t.Fatalf("event[0] payload unmarshal: %v", err)
			}
			if payload.Mode != "until_complete" {
				t.Errorf("event[0] payload mode = %q, want %q", payload.Mode, "until_complete")
			}
			if payload.WorkflowKind != "auto" {
				t.Errorf("event[0] payload workflow_kind = %q, want %q", payload.WorkflowKind, "auto")
			}
			if payload.SandboxID != "sandbox-001" {
				t.Errorf("event[0] payload sandbox_id = %q, want %q", payload.SandboxID, "sandbox-001")
			}
			if payload.Command == "" {
				t.Error("event[0] payload command should not be empty")
			}
		} else {
			t.Error("event[0] payload_json is nil, want non-nil")
		}

		evt1 := store.insertedEvents[1]
		if evt1.EventType != "execution_finished" {
			t.Errorf("event[1] type = %q, want %q", evt1.EventType, "execution_finished")
		}
		if evt1.ID != "evt-2" {
			t.Errorf("event[1] id = %q, want %q", evt1.ID, "evt-2")
		}

		// Verify finished payload includes exit_code.
		if evt1.PayloadJSON != nil {
			var payload executionEventPayload
			if err := json.Unmarshal([]byte(*evt1.PayloadJSON), &payload); err != nil {
				t.Fatalf("event[1] payload unmarshal: %v", err)
			}
			if payload.ExitCode == nil || *payload.ExitCode != 0 {
				t.Errorf("event[1] payload exit_code = %v, want 0", payload.ExitCode)
			}
			if payload.Error != "" {
				t.Errorf("event[1] payload error = %q, want empty", payload.Error)
			}
		} else {
			t.Error("event[1] payload_json is nil, want non-nil")
		}
	})

	t.Run("successful_bounded_batch", func(t *testing.T) {
		store := &executionMockStore{}
		mockRunner := &executionMockRunner{
			execResult: &runner.ExecResult{
				ExitCode: 0,
				Stdout:   "Batch complete.",
			},
		}

		svc := NewExecutionService(store, mockRunner, ExecutionConfig{})

		req := validExecutionRequest()
		req.Mode = ExecutionModeBoundedBatch
		result, err := svc.Execute(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.ExitCode != 0 {
			t.Errorf("exit_code = %d, want 0", result.ExitCode)
		}

		// Verify command uses bounded-batch mode.
		if len(mockRunner.execCalls) != 1 {
			t.Fatalf("execCalls = %d, want 1", len(mockRunner.execCalls))
		}
		if mockRunner.execCalls[0].Command != "hal auto" {
			t.Errorf("command = %q, want %q", mockRunner.execCalls[0].Command, "hal auto")
		}

		// Verify started event payload has bounded_batch mode (cloud scheduling metadata).
		if len(store.insertedEvents) < 1 {
			t.Fatal("expected at least 1 event")
		}
		var payload executionEventPayload
		if err := json.Unmarshal([]byte(*store.insertedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.Mode != "bounded_batch" {
			t.Errorf("payload mode = %q, want %q", payload.Mode, "bounded_batch")
		}
	})

	t.Run("nonzero_exit_code", func(t *testing.T) {
		store := &executionMockStore{}
		mockRunner := &executionMockRunner{
			execResult: &runner.ExecResult{
				ExitCode: 1,
				Stdout:   "partial output",
				Stderr:   "error: test failed",
			},
		}

		svc := NewExecutionService(store, mockRunner, ExecutionConfig{})

		result, err := svc.Execute(context.Background(), validExecutionRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Non-zero exit is data, not error.
		if result.ExitCode != 1 {
			t.Errorf("exit_code = %d, want 1", result.ExitCode)
		}
		if result.Output != "partial output" {
			t.Errorf("output = %q, want %q", result.Output, "partial output")
		}
		if result.ErrorOutput != "error: test failed" {
			t.Errorf("error_output = %q, want %q", result.ErrorOutput, "error: test failed")
		}

		// Verify execution_finished event has exit_code and error.
		finishedEvents := filterEventsByType(store.insertedEvents, "execution_finished")
		if len(finishedEvents) != 1 {
			t.Fatalf("execution_finished events = %d, want 1", len(finishedEvents))
		}
		var payload executionEventPayload
		if err := json.Unmarshal([]byte(*finishedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.ExitCode == nil || *payload.ExitCode != 1 {
			t.Errorf("payload exit_code = %v, want 1", payload.ExitCode)
		}
		if !strings.Contains(payload.Error, "error: test failed") {
			t.Errorf("payload error = %q, want to contain stderr", payload.Error)
		}
	})

	t.Run("nonzero_exit_stderr_fallback_to_stdout", func(t *testing.T) {
		store := &executionMockStore{}
		mockRunner := &executionMockRunner{
			execResult: &runner.ExecResult{
				ExitCode: 2,
				Stdout:   "stdout only",
				Stderr:   "",
			},
		}

		svc := NewExecutionService(store, mockRunner, ExecutionConfig{})

		result, err := svc.Execute(context.Background(), validExecutionRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.ExitCode != 2 {
			t.Errorf("exit_code = %d, want 2", result.ExitCode)
		}

		// Verify finished event uses stdout when stderr is empty.
		finishedEvents := filterEventsByType(store.insertedEvents, "execution_finished")
		if len(finishedEvents) != 1 {
			t.Fatalf("execution_finished events = %d, want 1", len(finishedEvents))
		}
		var payload executionEventPayload
		if err := json.Unmarshal([]byte(*finishedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if payload.Error != "stdout only" {
			t.Errorf("payload error = %q, want %q", payload.Error, "stdout only")
		}
	})

	t.Run("runner_exec_error", func(t *testing.T) {
		store := &executionMockStore{}
		mockRunner := &executionMockRunner{
			execErr: fmt.Errorf("sandbox unreachable"),
		}

		svc := NewExecutionService(store, mockRunner, ExecutionConfig{})

		result, err := svc.Execute(context.Background(), validExecutionRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if result != nil {
			t.Errorf("result = %v, want nil", result)
		}
		if !strings.Contains(err.Error(), "execution failed") {
			t.Errorf("error = %q, want to contain 'execution failed'", err.Error())
		}
		if !strings.Contains(err.Error(), "sandbox unreachable") {
			t.Errorf("error = %q, want to contain wrapped cause", err.Error())
		}

		// Verify execution_finished event with error.
		finishedEvents := filterEventsByType(store.insertedEvents, "execution_finished")
		if len(finishedEvents) != 1 {
			t.Fatalf("execution_finished events = %d, want 1", len(finishedEvents))
		}
		var payload executionEventPayload
		if err := json.Unmarshal([]byte(*finishedEvents[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if !strings.Contains(payload.Error, "sandbox unreachable") {
			t.Errorf("payload error = %q, want to contain 'sandbox unreachable'", payload.Error)
		}
	})

	t.Run("event_emission_failure_does_not_block", func(t *testing.T) {
		store := &executionMockStore{
			insertEventErr: fmt.Errorf("event insert failed"),
		}
		mockRunner := &executionMockRunner{
			execResult: &runner.ExecResult{ExitCode: 0},
		}

		svc := NewExecutionService(store, mockRunner, ExecutionConfig{})

		result, err := svc.Execute(context.Background(), validExecutionRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ExitCode != 0 {
			t.Errorf("exit_code = %d, want 0", result.ExitCode)
		}

		// Exec should still have been called.
		if len(mockRunner.execCalls) != 1 {
			t.Errorf("execCalls = %d, want 1", len(mockRunner.execCalls))
		}
	})

	t.Run("nil_IDFunc_uses_empty_event_id", func(t *testing.T) {
		store := &executionMockStore{}
		mockRunner := &executionMockRunner{
			execResult: &runner.ExecResult{ExitCode: 0},
		}

		svc := NewExecutionService(store, mockRunner, ExecutionConfig{})

		_, err := svc.Execute(context.Background(), validExecutionRequest())
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
		svc := NewExecutionService(&executionMockStore{}, &executionMockRunner{}, ExecutionConfig{})
		if svc.store == nil {
			t.Error("store is nil")
		}
		if svc.runner == nil {
			t.Error("runner is nil")
		}
	})
}

func TestExecutionRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(r *ExecutionRequest)
		wantErr string
	}{
		{
			name:    "valid_request",
			modify:  func(r *ExecutionRequest) {},
			wantErr: "",
		},
		{
			name:    "empty_sandboxID",
			modify:  func(r *ExecutionRequest) { r.SandboxID = "" },
			wantErr: "sandboxID must not be empty",
		},
		{
			name:    "empty_attemptID",
			modify:  func(r *ExecutionRequest) { r.AttemptID = "" },
			wantErr: "attemptID must not be empty",
		},
		{
			name:    "empty_runID",
			modify:  func(r *ExecutionRequest) { r.RunID = "" },
			wantErr: "runID must not be empty",
		},
		{
			name:    "invalid_workflowKind",
			modify:  func(r *ExecutionRequest) { r.WorkflowKind = "bad_kind" },
			wantErr: `workflowKind "bad_kind" is not valid`,
		},
		{
			name:    "empty_workflowKind",
			modify:  func(r *ExecutionRequest) { r.WorkflowKind = "" },
			wantErr: `workflowKind "" is not valid`,
		},
		{
			name:    "invalid_mode",
			modify:  func(r *ExecutionRequest) { r.Mode = "bad_mode" },
			wantErr: `mode "bad_mode" is not valid`,
		},
		{
			name:    "empty_mode",
			modify:  func(r *ExecutionRequest) { r.Mode = "" },
			wantErr: `mode "" is not valid`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validExecutionRequest()
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

func TestExecutionModeIsValid(t *testing.T) {
	tests := []struct {
		mode ExecutionMode
		want bool
	}{
		{ExecutionModeUntilComplete, true},
		{ExecutionModeBoundedBatch, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := tt.mode.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExecutionIDFunc(t *testing.T) {
	store := &executionMockStore{}
	mockRunner := &executionMockRunner{
		execResult: &runner.ExecResult{ExitCode: 0},
	}

	idCounter := 0
	svc := NewExecutionService(store, mockRunner, ExecutionConfig{
		IDFunc: func() string {
			idCounter++
			return fmt.Sprintf("custom-%d", idCounter)
		},
	})

	_, err := svc.Execute(context.Background(), validExecutionRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// execution_started + execution_finished = 2 events.
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

func TestBuildHalCommand(t *testing.T) {
	tests := []struct {
		name    string
		kind    WorkflowKind
		wantCmd string
	}{
		{
			name:    "run_dispatches_hal_run",
			kind:    WorkflowKindRun,
			wantCmd: "hal run",
		},
		{
			name:    "auto_dispatches_hal_auto",
			kind:    WorkflowKindAuto,
			wantCmd: "hal auto",
		},
		{
			name:    "review_dispatches_hal_review",
			kind:    WorkflowKindReview,
			wantCmd: "hal review",
		},
		{
			name:    "unknown_defaults_to_hal_auto",
			kind:    WorkflowKind("unknown"),
			wantCmd: "hal auto",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildHalCommand(tt.kind)
			if got != tt.wantCmd {
				t.Errorf("buildHalCommand(%q) = %q, want %q", tt.kind, got, tt.wantCmd)
			}
		})
	}
}

// TestWorkflowKindDispatchExactArgv verifies the exact argv mapping required
// by the acceptance criteria: run→"hal run", auto→"hal auto", review→"hal review".
// Mode flags do not alter the dispatch base command.
func TestWorkflowKindDispatchExactArgv(t *testing.T) {
	tests := []struct {
		kind       WorkflowKind
		wantPrefix string
	}{
		{WorkflowKindRun, "hal run"},
		{WorkflowKindAuto, "hal auto"},
		{WorkflowKindReview, "hal review"},
	}

	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			store := &executionMockStore{}
			mockRunner := &executionMockRunner{
				execResult: &runner.ExecResult{ExitCode: 0},
			}
			svc := NewExecutionService(store, mockRunner, ExecutionConfig{})

			req := validExecutionRequest()
			req.WorkflowKind = tt.kind
			_, err := svc.Execute(context.Background(), req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(mockRunner.execCalls) != 1 {
				t.Fatalf("execCalls = %d, want 1", len(mockRunner.execCalls))
			}
			cmd := mockRunner.execCalls[0].Command
			if !strings.HasPrefix(cmd, tt.wantPrefix) {
				t.Errorf("command = %q, want prefix %q", cmd, tt.wantPrefix)
			}

			// Verify events include workflow_kind for observability.
			for i, evt := range store.insertedEvents {
				if evt.PayloadJSON == nil {
					t.Errorf("event[%d] payload is nil", i)
					continue
				}
				var payload executionEventPayload
				if err := json.Unmarshal([]byte(*evt.PayloadJSON), &payload); err != nil {
					t.Fatalf("event[%d] payload unmarshal: %v", i, err)
				}
				if payload.WorkflowKind != string(tt.kind) {
					t.Errorf("event[%d] workflow_kind = %q, want %q", i, payload.WorkflowKind, tt.kind)
				}
			}
		})
	}
}

// TestBuildHalCommand_AllKinds verifies every WorkflowKind produces the
// expected command string.
func TestBuildHalCommand_AllKinds(t *testing.T) {
	kinds := []struct {
		kind WorkflowKind
		want string
	}{
		{WorkflowKindRun, "hal run"},
		{WorkflowKindAuto, "hal auto"},
		{WorkflowKindReview, "hal review"},
	}
	for _, tt := range kinds {
		got := buildHalCommand(tt.kind)
		if got != tt.want {
			t.Errorf("buildHalCommand(%q) = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

// --- Async execution tests ---

// asyncMockSession implements runner.SessionExec for ExecuteAsync tests.
type asyncMockSession struct {
	createSessionErr error
	execAsyncResult  *runner.SessionCommandStatus
	execAsyncErr     error
	statusResults    []*runner.SessionCommandStatus // returned in order per poll
	statusIdx        int
	statusErr        error
	streamErr        error
	streamStdout     []string // chunks to send
	streamStderr     []string // chunks to send
	commandLogs      string
	commandLogsErr   error
	deleteSessionErr error
	neverComplete    bool // when true, GetCommandStatus always returns nil exit code

	createdSessions []string
	execAsyncCalls  []executionExecCall
	deletedSessions []string
}

func (s *asyncMockSession) CreateSession(_ context.Context, _, sessionID string) error {
	s.createdSessions = append(s.createdSessions, sessionID)
	return s.createSessionErr
}

func (s *asyncMockSession) ExecAsync(_ context.Context, sandboxID, _ string, req *runner.ExecRequest) (*runner.SessionCommandStatus, error) {
	s.execAsyncCalls = append(s.execAsyncCalls, executionExecCall{
		SandboxID: sandboxID,
		Command:   req.Command,
		WorkDir:   req.WorkDir,
	})
	if s.execAsyncErr != nil {
		return nil, s.execAsyncErr
	}
	if s.execAsyncResult != nil {
		return s.execAsyncResult, nil
	}
	return &runner.SessionCommandStatus{CommandID: "cmd-001"}, nil
}

func (s *asyncMockSession) GetCommandStatus(_ context.Context, _, _, _ string) (*runner.SessionCommandStatus, error) {
	if s.statusErr != nil {
		return nil, s.statusErr
	}
	if s.statusIdx < len(s.statusResults) {
		r := s.statusResults[s.statusIdx]
		s.statusIdx++
		return r, nil
	}
	if s.neverComplete {
		return &runner.SessionCommandStatus{CommandID: "cmd-001", ExitCode: nil}, nil
	}
	// Default: completed with exit 0.
	code := 0
	return &runner.SessionCommandStatus{CommandID: "cmd-001", ExitCode: &code}, nil
}

func (s *asyncMockSession) StreamCommandLogs(_ context.Context, _, _, _ string, stdout, stderr chan<- string) error {
	defer close(stdout)
	defer close(stderr)
	if s.streamErr != nil {
		return s.streamErr
	}
	for _, chunk := range s.streamStdout {
		stdout <- chunk
	}
	for _, chunk := range s.streamStderr {
		stderr <- chunk
	}
	return nil
}

func (s *asyncMockSession) GetCommandLogs(_ context.Context, _, _, _ string) (string, error) {
	return s.commandLogs, s.commandLogsErr
}

func (s *asyncMockSession) DeleteSession(_ context.Context, _, sessionID string) error {
	s.deletedSessions = append(s.deletedSessions, sessionID)
	return s.deleteSessionErr
}

func validAsyncExecutionRequest() *ExecutionRequest {
	return &ExecutionRequest{
		SandboxID:    "sandbox-001",
		AttemptID:    "att-001",
		RunID:        "run-001",
		WorkflowKind: WorkflowKindAuto,
		Mode:         ExecutionModeUntilComplete,
		SessionID:    "session-att-001",
	}
}

func TestExecuteAsync(t *testing.T) {
	t.Run("successful_async_execution", func(t *testing.T) {
		store := &executionMockStore{}
		mockRunner := &executionMockRunner{}
		code := 0
		session := &asyncMockSession{
			execAsyncResult: &runner.SessionCommandStatus{CommandID: "cmd-001"},
			statusResults: []*runner.SessionCommandStatus{
				{CommandID: "cmd-001", ExitCode: nil},   // still running
				{CommandID: "cmd-001", ExitCode: nil},   // still running
				{CommandID: "cmd-001", ExitCode: &code}, // done
			},
			streamStdout: []string{"output line 1\n", "output line 2\n"},
			commandLogs:  "output line 1\noutput line 2\n",
		}

		idCounter := 0
		svc := NewExecutionServiceWithSession(store, mockRunner, session, ExecutionConfig{
			PollInterval: 1 * time.Millisecond, // fast polling for test
			IDFunc: func() string {
				idCounter++
				return fmt.Sprintf("evt-%d", idCounter)
			},
		})

		result, err := svc.ExecuteAsync(context.Background(), validAsyncExecutionRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.ExitCode != 0 {
			t.Errorf("exit_code = %d, want 0", result.ExitCode)
		}
		if result.CommandID != "cmd-001" {
			t.Errorf("command_id = %q, want %q", result.CommandID, "cmd-001")
		}
		if result.Output == "" {
			t.Error("output should not be empty")
		}

		// Verify session lifecycle.
		if len(session.createdSessions) != 1 || session.createdSessions[0] != "session-att-001" {
			t.Errorf("createdSessions = %v, want [session-att-001]", session.createdSessions)
		}
		if len(session.deletedSessions) != 1 || session.deletedSessions[0] != "session-att-001" {
			t.Errorf("deletedSessions = %v, want [session-att-001]", session.deletedSessions)
		}

		// Verify events.
		startedEvts := filterEventsByType(store.insertedEvents, "execution_started")
		finishedEvts := filterEventsByType(store.insertedEvents, "execution_finished")
		if len(startedEvts) != 1 {
			t.Errorf("execution_started events = %d, want 1", len(startedEvts))
		}
		if len(finishedEvts) != 1 {
			t.Errorf("execution_finished events = %d, want 1", len(finishedEvts))
		}
	})

	t.Run("nonzero_exit_code", func(t *testing.T) {
		store := &executionMockStore{}
		code := 1
		session := &asyncMockSession{
			statusResults: []*runner.SessionCommandStatus{
				{CommandID: "cmd-001", ExitCode: &code},
			},
			streamStderr: []string{"error: something failed\n"},
			commandLogs:  "partial output",
		}

		svc := NewExecutionServiceWithSession(store, &executionMockRunner{}, session, ExecutionConfig{
			PollInterval: 1 * time.Millisecond,
		})

		result, err := svc.ExecuteAsync(context.Background(), validAsyncExecutionRequest())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ExitCode != 1 {
			t.Errorf("exit_code = %d, want 1", result.ExitCode)
		}

		// Verify finished event has error.
		finishedEvts := filterEventsByType(store.insertedEvents, "execution_finished")
		if len(finishedEvts) != 1 {
			t.Fatalf("execution_finished events = %d, want 1", len(finishedEvts))
		}
		var payload executionEventPayload
		if err := json.Unmarshal([]byte(*finishedEvts[0].PayloadJSON), &payload); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if payload.ExitCode == nil || *payload.ExitCode != 1 {
			t.Errorf("payload exit_code = %v, want 1", payload.ExitCode)
		}
	})

	t.Run("create_session_failure", func(t *testing.T) {
		store := &executionMockStore{}
		session := &asyncMockSession{
			createSessionErr: fmt.Errorf("session limit exceeded"),
		}

		svc := NewExecutionServiceWithSession(store, &executionMockRunner{}, session, ExecutionConfig{
			PollInterval: 1 * time.Millisecond,
		})

		_, err := svc.ExecuteAsync(context.Background(), validAsyncExecutionRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "create session failed") {
			t.Errorf("error = %q, want to contain 'create session failed'", err.Error())
		}

		// Should have emitted execution_finished with error.
		finishedEvts := filterEventsByType(store.insertedEvents, "execution_finished")
		if len(finishedEvts) != 1 {
			t.Fatalf("execution_finished events = %d, want 1", len(finishedEvts))
		}
	})

	t.Run("exec_async_launch_failure", func(t *testing.T) {
		store := &executionMockStore{}
		session := &asyncMockSession{
			execAsyncErr: fmt.Errorf("command rejected"),
		}

		svc := NewExecutionServiceWithSession(store, &executionMockRunner{}, session, ExecutionConfig{
			PollInterval: 1 * time.Millisecond,
		})

		_, err := svc.ExecuteAsync(context.Background(), validAsyncExecutionRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "execution launch failed") {
			t.Errorf("error = %q, want to contain 'execution launch failed'", err.Error())
		}

		// Session should have been cleaned up.
		if len(session.deletedSessions) != 1 {
			t.Errorf("deletedSessions = %d, want 1 (cleanup)", len(session.deletedSessions))
		}
	})

	t.Run("context_cancellation", func(t *testing.T) {
		store := &executionMockStore{}
		session := &asyncMockSession{
			neverComplete: true, // never returns a completed status
		}

		svc := NewExecutionServiceWithSession(store, &executionMockRunner{}, session, ExecutionConfig{
			PollInterval: 1 * time.Millisecond,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := svc.ExecuteAsync(ctx, validAsyncExecutionRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "execution cancelled") {
			t.Errorf("error = %q, want to contain 'execution cancelled'", err.Error())
		}
	})

	t.Run("no_session_returns_error", func(t *testing.T) {
		svc := NewExecutionService(&executionMockStore{}, &executionMockRunner{}, ExecutionConfig{})

		_, err := svc.ExecuteAsync(context.Background(), validAsyncExecutionRequest())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "requires NewExecutionServiceWithSession") {
			t.Errorf("error = %q, want session required error", err.Error())
		}
	})

	t.Run("missing_session_id_validation", func(t *testing.T) {
		session := &asyncMockSession{}
		svc := NewExecutionServiceWithSession(&executionMockStore{}, &executionMockRunner{}, session, ExecutionConfig{})

		req := validAsyncExecutionRequest()
		req.SessionID = ""

		_, err := svc.ExecuteAsync(context.Background(), req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "sessionID must not be empty") {
			t.Errorf("error = %q, want session validation error", err.Error())
		}
	})

	t.Run("log_chunks_callback", func(t *testing.T) {
		store := &executionMockStore{}
		code := 0
		session := &asyncMockSession{
			statusResults: []*runner.SessionCommandStatus{
				{CommandID: "cmd-001", ExitCode: &code},
			},
			streamStdout: []string{"hello\n", "world\n"},
			streamStderr: []string{"warn\n"},
			commandLogs:  "hello\nworld\n",
		}

		svc := NewExecutionServiceWithSession(store, &executionMockRunner{}, session, ExecutionConfig{
			PollInterval: 1 * time.Millisecond,
		})

		var chunks []string
		req := validAsyncExecutionRequest()
		req.OnLogChunk = func(stream, chunk string) {
			chunks = append(chunks, fmt.Sprintf("[%s] %s", stream, chunk))
		}

		_, err := svc.ExecuteAsync(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should have received log chunks via callback.
		if len(chunks) == 0 {
			t.Error("expected log chunks via OnLogChunk callback")
		}
	})
}

func TestExecutionRequestValidateAsync(t *testing.T) {
	t.Run("valid_async", func(t *testing.T) {
		req := validAsyncExecutionRequest()
		if err := req.ValidateAsync(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing_session_id", func(t *testing.T) {
		req := validAsyncExecutionRequest()
		req.SessionID = ""
		err := req.ValidateAsync()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "sessionID") {
			t.Errorf("error = %q, want sessionID error", err.Error())
		}
	})

	t.Run("inherits_base_validation", func(t *testing.T) {
		req := validAsyncExecutionRequest()
		req.SandboxID = ""
		err := req.ValidateAsync()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "sandboxID") {
			t.Errorf("error = %q, want sandboxID error", err.Error())
		}
	})
}

func TestExecutionRunnerExecErrorEmitsFinishedEvent(t *testing.T) {
	// Verifies that even on runner API failure, execution_finished event
	// is emitted with the error context.
	store := &executionMockStore{}
	mockRunner := &executionMockRunner{
		execErr: fmt.Errorf("timeout"),
	}

	idCounter := 0
	svc := NewExecutionService(store, mockRunner, ExecutionConfig{
		IDFunc: func() string {
			idCounter++
			return fmt.Sprintf("evt-%d", idCounter)
		},
	})

	_, err := svc.Execute(context.Background(), validExecutionRequest())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Events: execution_started + execution_finished.
	if len(store.insertedEvents) != 2 {
		t.Fatalf("insertedEvents = %d, want 2", len(store.insertedEvents))
	}
	if store.insertedEvents[0].EventType != "execution_started" {
		t.Errorf("event[0] type = %q, want %q", store.insertedEvents[0].EventType, "execution_started")
	}
	if store.insertedEvents[1].EventType != "execution_finished" {
		t.Errorf("event[1] type = %q, want %q", store.insertedEvents[1].EventType, "execution_finished")
	}

	// Verify finished event has error but no exit_code (runner error, not exit code).
	var payload executionEventPayload
	if err := json.Unmarshal([]byte(*store.insertedEvents[1].PayloadJSON), &payload); err != nil {
		t.Fatalf("payload unmarshal: %v", err)
	}
	if payload.ExitCode != nil {
		t.Errorf("payload exit_code = %v, want nil (runner error, not exit code)", *payload.ExitCode)
	}
	if !strings.Contains(payload.Error, "timeout") {
		t.Errorf("payload error = %q, want to contain 'timeout'", payload.Error)
	}
}
