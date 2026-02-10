package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// TeardownConfig holds configuration for the teardown service.
type TeardownConfig struct {
	// IDFunc generates unique IDs for events. If nil, event IDs will be empty.
	IDFunc func() string
}

// TeardownService manages sandbox teardown for worker attempts. It calls the
// runner API to destroy a sandbox on both success and failure terminal paths,
// and emits teardown_started and teardown_done events.
type TeardownService struct {
	store  Store
	runner runner.Runner
	config TeardownConfig
}

// NewTeardownService creates a new TeardownService with the given store,
// runner, and config.
func NewTeardownService(store Store, r runner.Runner, config TeardownConfig) *TeardownService {
	return &TeardownService{
		store:  store,
		runner: r,
		config: config,
	}
}

// teardownEventPayload is the JSON payload for teardown lifecycle events.
type teardownEventPayload struct {
	SandboxID string `json:"sandbox_id"`
	Error     string `json:"error,omitempty"`
}

// Teardown destroys the sandbox associated with the given attempt. It emits
// teardown_started before the runner API call and teardown_done after
// completion. This method runs on both success and failure terminal paths.
// Teardown errors do not prevent the caller from completing the terminal
// transition — the method always returns nil unless the sandboxID is empty
// or the runner API call fails.
func (s *TeardownService) Teardown(ctx context.Context, sandboxID, attemptID, runID string) error {
	if sandboxID == "" {
		return fmt.Errorf("sandboxID must not be empty")
	}
	if attemptID == "" {
		return fmt.Errorf("attemptID must not be empty")
	}
	if runID == "" {
		return fmt.Errorf("runID must not be empty")
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Step 1: Emit teardown_started event.
	startedPayload := &teardownEventPayload{
		SandboxID: sandboxID,
	}
	s.emitEvent(ctx, runID, attemptID, "teardown_started", startedPayload, now)

	// Step 2: Destroy sandbox via runner API.
	destroyErr := s.runner.DestroySandbox(ctx, sandboxID)

	// Step 3: Emit teardown_done event (with error if destroy failed).
	donePayload := &teardownEventPayload{
		SandboxID: sandboxID,
	}
	if destroyErr != nil {
		donePayload.Error = destroyErr.Error()
	}
	s.emitEvent(ctx, runID, attemptID, "teardown_done", donePayload, now)

	if destroyErr != nil {
		return fmt.Errorf("failed to destroy sandbox %s: %w", sandboxID, destroyErr)
	}

	return nil
}

// emitEvent inserts an event with the given type and payload. Errors are
// best-effort — event emission failures do not block teardown.
func (s *TeardownService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *teardownEventPayload, now time.Time) {
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
