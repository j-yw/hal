package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// concurrentBuffer is a goroutine-safe string builder used to accumulate
// log output from the background streaming goroutine.
type concurrentBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *concurrentBuffer) Write(s string) {
	b.mu.Lock()
	b.buf.WriteString(s)
	b.mu.Unlock()
}

func (b *concurrentBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

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
	// PollInterval is the interval for polling command status during async
	// execution. Defaults to 5 seconds.
	PollInterval time.Duration
}

// ExecutionService manages controlled Hal execution inside a sandbox. It
// runs the Hal CLI with the selected execution mode, persists start and
// finish events, and captures command exit status for failure classification.
//
// Two execution modes are supported:
//
//   - Execute (blocking): uses Runner.Exec for short commands (< 60s).
//     Suitable for hal init, hal review, and other quick commands.
//
//   - ExecuteAsync (session-based): uses SessionExec for long-running commands.
//     Creates a Daytona session, launches the command asynchronously, and polls
//     for completion. Required for hal auto and hal run which can take hours.
//     The Daytona SDK's ExecuteCommand has a 60s HTTP client timeout, making
//     blocking execution unsuitable for long-running commands.
type ExecutionService struct {
	store   Store
	runner  runner.Runner
	session runner.SessionExec // optional; enables async execution
	config  ExecutionConfig
}

// NewExecutionService creates a new ExecutionService with blocking execution
// only. Use NewExecutionServiceWithSession for long-running commands.
func NewExecutionService(store Store, r runner.Runner, config ExecutionConfig) *ExecutionService {
	return &ExecutionService{
		store:  store,
		runner: r,
		config: config,
	}
}

// NewExecutionServiceWithSession creates an ExecutionService with session-based
// async execution support for long-running commands.
func NewExecutionServiceWithSession(store Store, r runner.Runner, session runner.SessionExec, config ExecutionConfig) *ExecutionService {
	if config.PollInterval == 0 {
		config.PollInterval = 5 * time.Second
	}
	return &ExecutionService{
		store:   store,
		runner:  r,
		session: session,
		config:  config,
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
	// WorkflowKind determines the command dispatched: run→"hal run",
	// auto→"hal auto", review→"hal review".
	WorkflowKind WorkflowKind
	// Mode is the execution mode (until_complete or bounded_batch).
	Mode ExecutionMode

	// --- Async fields (used by ExecuteAsync only, zero values ignored by Execute) ---

	// SessionID is the Daytona session ID for async execution.
	// Should be deterministic from the attempt ID so the worker can
	// reconnect after a restart.
	SessionID string
	// OnLogChunk is called for each log chunk received during async
	// execution. If nil, logs are silently accumulated.
	OnLogChunk func(stream string, chunk string)
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
	if !r.WorkflowKind.IsValid() {
		return fmt.Errorf("workflowKind %q is not valid", r.WorkflowKind)
	}
	if !r.Mode.IsValid() {
		return fmt.Errorf("mode %q is not valid", r.Mode)
	}
	return nil
}

// ValidateAsync checks fields required for async execution in addition to
// the base validation.
func (r *ExecutionRequest) ValidateAsync() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.SessionID == "" {
		return fmt.Errorf("sessionID must not be empty for async execution")
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
	// CommandID is the session command ID (only set for async execution).
	CommandID string
}

// executionEventPayload is the JSON payload for execution lifecycle events.
type executionEventPayload struct {
	SandboxID    string `json:"sandbox_id"`
	WorkflowKind string `json:"workflow_kind"`
	Mode         string `json:"mode"`
	ExitCode     *int   `json:"exit_code,omitempty"`
	Error        string `json:"error,omitempty"`
	Command      string `json:"command,omitempty"`
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

	// Build the Hal command based on workflow kind.
	cmd := buildHalCommand(req.WorkflowKind)

	// Step 1: Emit execution_started event.
	startPayload := &executionEventPayload{
		SandboxID:    req.SandboxID,
		WorkflowKind: string(req.WorkflowKind),
		Mode:         string(req.Mode),
		Command:      cmd,
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
			SandboxID:    req.SandboxID,
			WorkflowKind: string(req.WorkflowKind),
			Mode:         string(req.Mode),
			Error:        err.Error(),
		}
		s.emitEvent(ctx, req.RunID, req.AttemptID, "execution_finished", errPayload, now)
		return nil, fmt.Errorf("execution failed: %w", err)
	}

	// Step 3: Emit execution_finished event with exit code.
	finishPayload := &executionEventPayload{
		SandboxID:    req.SandboxID,
		WorkflowKind: string(req.WorkflowKind),
		Mode:         string(req.Mode),
		ExitCode:     &execResult.ExitCode,
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

// ExecuteAsync runs Hal inside a sandbox using session-based async execution.
// Unlike Execute (which blocks on a single HTTP call), ExecuteAsync:
//
//  1. Creates a Daytona session in the sandbox
//  2. Launches the hal command asynchronously (returns immediately from the API)
//  3. Streams logs via WebSocket in a background goroutine
//  4. Polls command status until completion or context cancellation
//  5. Fetches final logs after completion
//
// This is required for hal auto and hal run which can run for hours.
// The Daytona SDK's ExecuteCommand has a hardcoded 60s HTTP client timeout.
//
// Requires NewExecutionServiceWithSession; returns an error if session is nil.
func (s *ExecutionService) ExecuteAsync(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	if s.session == nil {
		return nil, fmt.Errorf("async execution requires NewExecutionServiceWithSession")
	}
	if err := req.ValidateAsync(); err != nil {
		return nil, err
	}

	now := time.Now().UTC().Truncate(time.Second)
	cmd := buildHalCommand(req.WorkflowKind)

	// Step 1: Emit execution_started event.
	startPayload := &executionEventPayload{
		SandboxID:    req.SandboxID,
		WorkflowKind: string(req.WorkflowKind),
		Mode:         string(req.Mode),
		Command:      cmd,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "execution_started", startPayload, now)

	// Step 2: Create session.
	if err := s.session.CreateSession(ctx, req.SandboxID, req.SessionID); err != nil {
		errPayload := &executionEventPayload{
			SandboxID:    req.SandboxID,
			WorkflowKind: string(req.WorkflowKind),
			Mode:         string(req.Mode),
			Error:        err.Error(),
		}
		s.emitEvent(ctx, req.RunID, req.AttemptID, "execution_finished", errPayload, now)
		return nil, fmt.Errorf("execution create session failed: %w", err)
	}

	// Step 3: Launch command asynchronously.
	cmdStatus, err := s.session.ExecAsync(ctx, req.SandboxID, req.SessionID, &runner.ExecRequest{
		Command: cmd,
		WorkDir: "/workspace",
	})
	if err != nil {
		errPayload := &executionEventPayload{
			SandboxID:    req.SandboxID,
			WorkflowKind: string(req.WorkflowKind),
			Mode:         string(req.Mode),
			Error:        err.Error(),
		}
		s.emitEvent(ctx, req.RunID, req.AttemptID, "execution_finished", errPayload, now)
		// Best-effort cleanup.
		_ = s.session.DeleteSession(ctx, req.SandboxID, req.SessionID)
		return nil, fmt.Errorf("execution launch failed: %w", err)
	}

	// Step 4: Stream logs in background.
	var stdoutBuf, stderrBuf concurrentBuffer
	logCtx, logCancel := context.WithCancel(ctx)
	logsDone := make(chan error, 1)

	go func() {
		stdout := make(chan string, 64)
		stderr := make(chan string, 64)

		go func() {
			logsDone <- s.session.StreamCommandLogs(logCtx, req.SandboxID, req.SessionID, cmdStatus.CommandID, stdout, stderr)
		}()

		for stdout != nil || stderr != nil {
			select {
			case chunk, ok := <-stdout:
				if !ok {
					stdout = nil
					continue
				}
				stdoutBuf.Write(chunk)
				if req.OnLogChunk != nil {
					req.OnLogChunk("stdout", chunk)
				}
			case chunk, ok := <-stderr:
				if !ok {
					stderr = nil
					continue
				}
				stderrBuf.Write(chunk)
				if req.OnLogChunk != nil {
					req.OnLogChunk("stderr", chunk)
				}
			}
		}
	}()

	// Step 5: Poll for completion.
	var finalExitCode int
	pollInterval := s.config.PollInterval
	if pollInterval == 0 {
		pollInterval = 5 * time.Second
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logCancel()
			<-logsDone
			errPayload := &executionEventPayload{
				SandboxID:    req.SandboxID,
				WorkflowKind: string(req.WorkflowKind),
				Mode:         string(req.Mode),
				Error:        ctx.Err().Error(),
			}
			s.emitEvent(ctx, req.RunID, req.AttemptID, "execution_finished", errPayload, now)
			return nil, fmt.Errorf("execution cancelled: %w", ctx.Err())

		case <-ticker.C:
			status, pollErr := s.session.GetCommandStatus(ctx, req.SandboxID, req.SessionID, cmdStatus.CommandID)
			if pollErr != nil {
				// Transient poll failure — keep trying.
				continue
			}
			if status.ExitCode == nil {
				// Still running.
				continue
			}

			// Command completed.
			finalExitCode = *status.ExitCode

			// Give log stream a moment to flush, then cancel it.
			flushCtx, flushCancel := context.WithTimeout(ctx, 2*time.Second)
			select {
			case <-logsDone:
			case <-flushCtx.Done():
			}
			flushCancel()
			logCancel()

			goto done
		}
	}

done:
	// Step 6: Fetch final logs (log stream may have missed tail).
	finalLogs, _ := s.session.GetCommandLogs(ctx, req.SandboxID, req.SessionID, cmdStatus.CommandID)
	stdout := stdoutBuf.String()
	if finalLogs != "" && len(finalLogs) > len(stdout) {
		stdout = finalLogs
	}

	// Step 7: Clean up session (best-effort).
	_ = s.session.DeleteSession(ctx, req.SandboxID, req.SessionID)

	// Step 8: Emit execution_finished event.
	finishPayload := &executionEventPayload{
		SandboxID:    req.SandboxID,
		WorkflowKind: string(req.WorkflowKind),
		Mode:         string(req.Mode),
		ExitCode:     &finalExitCode,
	}
	if finalExitCode != 0 {
		errOut := stderrBuf.String()
		if errOut == "" {
			errOut = stdout
		}
		finishPayload.Error = errOut
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "execution_finished", finishPayload, now)

	return &ExecutionResult{
		ExitCode:    finalExitCode,
		Output:      stdout,
		ErrorOutput: stderrBuf.String(),
		CommandID:   cmdStatus.CommandID,
	}, nil
}

// buildHalCommand constructs the Hal CLI command based on workflow kind.
// Dispatch maps workflow kinds to their exact CLI command:
//
//	run    → "hal run"
//	auto   → "hal auto"
//	review → "hal review"
func buildHalCommand(kind WorkflowKind) string {
	switch kind {
	case WorkflowKindRun:
		return "hal run"
	case WorkflowKindReview:
		return "hal review"
	case WorkflowKindAuto:
		return "hal auto"
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

	redacted, wasRedacted := redactPayload(payloadJSON)

	event := &Event{
		ID:          eventID,
		RunID:       runID,
		AttemptID:   &attemptID,
		EventType:   eventType,
		PayloadJSON: redacted,
		Redacted:    wasRedacted,
		CreatedAt:   now,
	}
	_ = s.store.InsertEvent(ctx, event)
}
