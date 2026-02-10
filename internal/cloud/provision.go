package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// ProvisionConfig holds configuration for the provision service.
type ProvisionConfig struct {
	// Image is the container image or Daytona template to use for sandbox creation.
	Image string
	// EnvVars are environment variables to inject into the sandbox.
	EnvVars map[string]string
	// IDFunc generates unique IDs for events. If nil, callers must provide
	// an alternative.
	IDFunc func() string
}

// ProvisionService manages sandbox provisioning for worker attempts. It calls
// the runner API to create a sandbox, persists the sandbox_id on the attempt
// row, and emits sandbox_created and sandbox_ready events.
type ProvisionService struct {
	store  Store
	runner runner.Runner
	config ProvisionConfig
}

// NewProvisionService creates a new ProvisionService with the given store,
// runner, and config.
func NewProvisionService(store Store, r runner.Runner, config ProvisionConfig) *ProvisionService {
	return &ProvisionService{
		store:  store,
		runner: r,
		config: config,
	}
}

// ProvisionResult holds the outcome of a successful sandbox provisioning.
type ProvisionResult struct {
	SandboxID string
	Status    string
}

// Provision creates a Daytona sandbox for the given attempt and run, persists
// the sandbox_id on the attempt row, and emits sandbox_created and
// sandbox_ready events. If sandbox creation fails, the error is returned
// without emitting events.
func (s *ProvisionService) Provision(ctx context.Context, attemptID, runID string) (*ProvisionResult, error) {
	if attemptID == "" {
		return nil, fmt.Errorf("attemptID must not be empty")
	}
	if runID == "" {
		return nil, fmt.Errorf("runID must not be empty")
	}

	// Step 1: Create sandbox via runner API.
	req := &runner.CreateSandboxRequest{
		Image:   s.config.Image,
		EnvVars: s.config.EnvVars,
	}

	sandbox, err := s.runner.CreateSandbox(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox: %w", err)
	}

	// Step 2: Persist sandbox_id on the attempt row.
	if err := s.store.UpdateAttemptSandboxID(ctx, attemptID, sandbox.ID); err != nil {
		return nil, fmt.Errorf("failed to persist sandbox_id: %w", err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Step 3: Emit sandbox_created event.
	createdPayload := sandboxEventPayload{
		SandboxID: sandbox.ID,
		Image:     s.config.Image,
	}
	s.emitEvent(ctx, runID, attemptID, "sandbox_created", &createdPayload, now)

	// Step 4: Emit sandbox_ready event.
	readyPayload := sandboxEventPayload{
		SandboxID: sandbox.ID,
		Status:    sandbox.Status,
	}
	s.emitEvent(ctx, runID, attemptID, "sandbox_ready", &readyPayload, now)

	return &ProvisionResult{
		SandboxID: sandbox.ID,
		Status:    sandbox.Status,
	}, nil
}

// sandboxEventPayload is the JSON payload for sandbox lifecycle events.
type sandboxEventPayload struct {
	SandboxID string `json:"sandbox_id"`
	Image     string `json:"image,omitempty"`
	Status    string `json:"status,omitempty"`
}

// emitEvent inserts an event with the given type and payload. Errors are
// best-effort — event emission failures do not block provisioning.
func (s *ProvisionService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *sandboxEventPayload, now time.Time) {
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
