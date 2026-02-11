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
		if call.Command != "hal auto --mode until-complete" {
			t.Errorf("command = %q, want %q", call.Command, "hal auto --mode until-complete")
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
		if mockRunner.execCalls[0].Command != "hal auto --mode bounded-batch" {
			t.Errorf("command = %q, want %q", mockRunner.execCalls[0].Command, "hal auto --mode bounded-batch")
		}

		// Verify started event payload has bounded_batch mode.
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
		mode    ExecutionMode
		wantCmd string
	}{
		{
			name:    "run_dispatches_hal_run",
			kind:    WorkflowKindRun,
			mode:    ExecutionModeUntilComplete,
			wantCmd: "hal run",
		},
		{
			name:    "run_ignores_mode",
			kind:    WorkflowKindRun,
			mode:    ExecutionModeBoundedBatch,
			wantCmd: "hal run",
		},
		{
			name:    "auto_until_complete",
			kind:    WorkflowKindAuto,
			mode:    ExecutionModeUntilComplete,
			wantCmd: "hal auto --mode until-complete",
		},
		{
			name:    "auto_bounded_batch",
			kind:    WorkflowKindAuto,
			mode:    ExecutionModeBoundedBatch,
			wantCmd: "hal auto --mode bounded-batch",
		},
		{
			name:    "review_dispatches_hal_review",
			kind:    WorkflowKindReview,
			mode:    ExecutionModeUntilComplete,
			wantCmd: "hal review",
		},
		{
			name:    "review_ignores_mode",
			kind:    WorkflowKindReview,
			mode:    ExecutionModeBoundedBatch,
			wantCmd: "hal review",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildHalCommand(tt.kind, tt.mode)
			if got != tt.wantCmd {
				t.Errorf("buildHalCommand(%q, %q) = %q, want %q", tt.kind, tt.mode, got, tt.wantCmd)
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

// TestModeDoesNotAlterDispatch verifies that mode flags only affect auto
// workflow commands, not run or review.
func TestModeDoesNotAlterDispatch(t *testing.T) {
	modes := []ExecutionMode{ExecutionModeUntilComplete, ExecutionModeBoundedBatch}

	for _, mode := range modes {
		t.Run("run_mode_"+string(mode), func(t *testing.T) {
			cmd := buildHalCommand(WorkflowKindRun, mode)
			if cmd != "hal run" {
				t.Errorf("buildHalCommand(run, %q) = %q, want %q", mode, cmd, "hal run")
			}
		})
		t.Run("review_mode_"+string(mode), func(t *testing.T) {
			cmd := buildHalCommand(WorkflowKindReview, mode)
			if cmd != "hal review" {
				t.Errorf("buildHalCommand(review, %q) = %q, want %q", mode, cmd, "hal review")
			}
		})
	}
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
