package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// ExecutionMode represents the mode used for Hal execution in a sandbox.
type ExecutionMode string

const (
	// ExecutionModeUntilComplete runs Hal in a loop until all stories
	// are marked complete or the process exits.
	ExecutionModeUntilComplete ExecutionMode = "until_complete"
	// ExecutionModeBoundedBatch runs Hal for a single bounded batch of
	// stories then exits regardless of overall completion.
	ExecutionModeBoundedBatch ExecutionMode = "bounded_batch"
)

// validExecutionModes is the exhaustive set of allowed execution modes.
var validExecutionModes = map[ExecutionMode]bool{
	ExecutionModeUntilComplete: true,
	ExecutionModeBoundedBatch:  true,
}

// IsValid reports whether m is one of the allowed execution modes.
func (m ExecutionMode) IsValid() bool {
	return validExecutionModes[m]
}

// ExecutionConfig holds configuration for the execution service.
type ExecutionConfig struct {
	// IDFunc generates unique IDs for events. If nil, event IDs will be empty.
	IDFunc func() string
}

// ExecutionService manages controlled Hal execution inside a sandbox. It
// runs the Hal CLI with the selected execution mode, persists start and
// finish events, and captures command exit status for failure classification.
type ExecutionService struct {
	store  Store
	runner runner.Runner
	config ExecutionConfig
}

// NewExecutionService creates a new ExecutionService with the given store,
// runner, and config.
func NewExecutionService(store Store, r runner.Runner, config ExecutionConfig) *ExecutionService {
	return &ExecutionService{
		store:  store,
		runner: r,
		config: config,
	}
}

// ExecutionRequest contains the parameters for a Hal execution step.
type ExecutionRequest struct {
	// SandboxID is the sandbox where Hal is executed.
	SandboxID string
	// AttemptID is the current attempt (for event correlation).
	AttemptID string
	// RunID is the current run (for event correlation).
	RunID string
	// Mode is the execution mode (until_complete or bounded_batch).
	Mode ExecutionMode
}

// Validate checks required fields on ExecutionRequest.
func (r *ExecutionRequest) Validate() error {
	if r.SandboxID == "" {
		return fmt.Errorf("sandboxID must not be empty")
	}
	if r.AttemptID == "" {
		return fmt.Errorf("attemptID must not be empty")
	}
	if r.RunID == "" {
		return fmt.Errorf("runID must not be empty")
	}
	if !r.Mode.IsValid() {
		return fmt.Errorf("mode %q is not valid", r.Mode)
	}
	return nil
}

// ExecutionResult holds the outcome of a Hal execution step.
type ExecutionResult struct {
	// ExitCode is the command exit status from the Hal process.
	ExitCode int
	// Output is the captured stdout from the Hal process.
	Output string
	// ErrorOutput is the captured stderr from the Hal process.
	ErrorOutput string
}

// executionEventPayload is the JSON payload for execution lifecycle events.
type executionEventPayload struct {
	SandboxID   string `json:"sandbox_id"`
	Mode        string `json:"mode"`
	ExitCode    *int   `json:"exit_code,omitempty"`
	Error       string `json:"error,omitempty"`
	Command     string `json:"command,omitempty"`
}

// Execute runs Hal inside the sandbox with the selected execution mode. It
// emits execution_started before the command, and execution_finished after
// completion (including on failure). The exit code is captured for downstream
// failure classification.
func (s *ExecutionService) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Build the Hal command based on execution mode.
	cmd := buildHalCommand(req.Mode)

	// Step 1: Emit execution_started event.
	startPayload := &executionEventPayload{
		SandboxID: req.SandboxID,
		Mode:      string(req.Mode),
		Command:   cmd,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "execution_started", startPayload, now)

	// Step 2: Execute the Hal command in the sandbox.
	execResult, err := s.runner.Exec(ctx, req.SandboxID, &runner.ExecRequest{
		Command: cmd,
		WorkDir: "/workspace",
	})
	if err != nil {
		// Runner API error (not a non-zero exit code).
		errPayload := &executionEventPayload{
			SandboxID: req.SandboxID,
			Mode:      string(req.Mode),
			Error:     err.Error(),
		}
		s.emitEvent(ctx, req.RunID, req.AttemptID, "execution_finished", errPayload, now)
		return nil, fmt.Errorf("execution failed: %w", err)
	}

	// Step 3: Emit execution_finished event with exit code.
	finishPayload := &executionEventPayload{
		SandboxID: req.SandboxID,
		Mode:      string(req.Mode),
		ExitCode:  &execResult.ExitCode,
	}
	if execResult.ExitCode != 0 {
		output := execResult.Stderr
		if output == "" {
			output = execResult.Stdout
		}
		finishPayload.Error = output
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "execution_finished", finishPayload, now)

	return &ExecutionResult{
		ExitCode:    execResult.ExitCode,
		Output:      execResult.Stdout,
		ErrorOutput: execResult.Stderr,
	}, nil
}

// buildHalCommand constructs the Hal CLI command for the given execution mode.
func buildHalCommand(mode ExecutionMode) string {
	switch mode {
	case ExecutionModeUntilComplete:
		return "hal auto --mode until-complete"
	case ExecutionModeBoundedBatch:
		return "hal auto --mode bounded-batch"
	default:
		return "hal auto"
	}
}

// emitEvent inserts an event with the given type and payload. Errors are
// best-effort — event emission failures do not block execution.
func (s *ExecutionService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *executionEventPayload, now time.Time) {
	eventID := ""
	if s.config.IDFunc != nil {
		eventID = s.config.IDFunc()
	}

	var payloadJSON *string
	if payload != nil {
		data, err := json.Marshal(payload)
		if err == nil {
			str := string(data)
			payloadJSON = &str
		}
	}

	event := &Event{
		ID:          eventID,
		RunID:       runID,
		AttemptID:   &attemptID,
		EventType:   eventType,
		PayloadJSON: payloadJSON,
		CreatedAt:   now,
	}
	_ = s.store.InsertEvent(ctx, event)
}
