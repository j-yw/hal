package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// BootstrapConfig holds configuration for the bootstrap service.
type BootstrapConfig struct {
	// IDFunc generates unique IDs for events. If nil, event IDs will be empty.
	IDFunc func() string
}

// BootstrapService manages deterministic environment setup before Hal
// execution. It clones or fetches the repository, checks out the target
// branch, and runs hal init inside the sandbox.
type BootstrapService struct {
	store  Store
	runner runner.Runner
	config BootstrapConfig
}

// NewBootstrapService creates a new BootstrapService with the given store,
// runner, and config.
func NewBootstrapService(store Store, r runner.Runner, config BootstrapConfig) *BootstrapService {
	return &BootstrapService{
		store:  store,
		runner: r,
		config: config,
	}
}

// BootstrapRequest contains the parameters for bootstrapping a sandbox.
type BootstrapRequest struct {
	// Repo is the repository URL to clone (e.g., "https://github.com/org/repo.git").
	Repo string
	// Branch is the target branch to checkout after cloning.
	Branch string
	// SandboxID is the sandbox to bootstrap.
	SandboxID string
	// AttemptID is the current attempt (for event correlation).
	AttemptID string
	// RunID is the current run (for event correlation).
	RunID string
}

// Validate checks required fields on BootstrapRequest.
func (r *BootstrapRequest) Validate() error {
	if r.Repo == "" {
		return fmt.Errorf("repo must not be empty")
	}
	if r.Branch == "" {
		return fmt.Errorf("branch must not be empty")
	}
	if r.SandboxID == "" {
		return fmt.Errorf("sandboxID must not be empty")
	}
	if r.AttemptID == "" {
		return fmt.Errorf("attemptID must not be empty")
	}
	if r.RunID == "" {
		return fmt.Errorf("runID must not be empty")
	}
	return nil
}

// bootstrapEventPayload is the JSON payload for bootstrap lifecycle events.
type bootstrapEventPayload struct {
	SandboxID string `json:"sandbox_id"`
	Repo      string `json:"repo,omitempty"`
	Branch    string `json:"branch,omitempty"`
	Step      string `json:"step,omitempty"`
	Error     string `json:"error,omitempty"`
	ExitCode  *int   `json:"exit_code,omitempty"`
}

// Bootstrap clones or fetches the repository, checks out the target branch,
// and runs hal init inside the sandbox. On failure, a bootstrap_failed event
// is emitted and the error is returned. On success, bootstrap_completed is
// emitted.
func (s *BootstrapService) Bootstrap(ctx context.Context, req *BootstrapRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Step 1: Emit bootstrap_started event.
	startPayload := &bootstrapEventPayload{
		SandboxID: req.SandboxID,
		Repo:      req.Repo,
		Branch:    req.Branch,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "bootstrap_started", startPayload, now)

	// Step 2: Clone repository.
	cloneCmd := fmt.Sprintf("git clone --branch %s --single-branch %s /workspace", req.Branch, req.Repo)
	cloneResult, err := s.runner.Exec(ctx, req.SandboxID, &runner.ExecRequest{
		Command: cloneCmd,
	})
	if err != nil {
		s.emitBootstrapFailed(ctx, req, "clone", err.Error(), nil, now)
		return fmt.Errorf("bootstrap clone failed: %w", err)
	}
	if cloneResult.ExitCode != 0 {
		output := cloneResult.Stderr
		if output == "" {
			output = cloneResult.Stdout
		}
		s.emitBootstrapFailed(ctx, req, "clone", output, &cloneResult.ExitCode, now)
		return fmt.Errorf("bootstrap clone failed: exit code %d: %s", cloneResult.ExitCode, output)
	}

	// Step 3: Run hal init.
	initResult, err := s.runner.Exec(ctx, req.SandboxID, &runner.ExecRequest{
		Command: "hal init",
		WorkDir: "/workspace",
	})
	if err != nil {
		s.emitBootstrapFailed(ctx, req, "init", err.Error(), nil, now)
		return fmt.Errorf("bootstrap init failed: %w", err)
	}
	if initResult.ExitCode != 0 {
		output := initResult.Stderr
		if output == "" {
			output = initResult.Stdout
		}
		s.emitBootstrapFailed(ctx, req, "init", output, &initResult.ExitCode, now)
		return fmt.Errorf("bootstrap init failed: exit code %d: %s", initResult.ExitCode, output)
	}

	// Step 4: Emit bootstrap_completed event.
	completePayload := &bootstrapEventPayload{
		SandboxID: req.SandboxID,
		Repo:      req.Repo,
		Branch:    req.Branch,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "bootstrap_completed", completePayload, now)

	return nil
}

// emitBootstrapFailed emits a bootstrap_failed event with error context.
func (s *BootstrapService) emitBootstrapFailed(ctx context.Context, req *BootstrapRequest, step, errMsg string, exitCode *int, now time.Time) {
	payload := &bootstrapEventPayload{
		SandboxID: req.SandboxID,
		Repo:      req.Repo,
		Branch:    req.Branch,
		Step:      step,
		Error:     errMsg,
		ExitCode:  exitCode,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "bootstrap_failed", payload, now)
}

// emitEvent inserts an event with the given type and payload. Errors are
// best-effort — event emission failures do not block bootstrap.
func (s *BootstrapService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *bootstrapEventPayload, now time.Time) {
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
