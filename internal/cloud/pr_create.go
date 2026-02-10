package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// PRCreateConfig holds configuration for the PR create service.
type PRCreateConfig struct {
	// IDFunc generates unique IDs for events and idempotency keys. If nil,
	// IDs will be empty.
	IDFunc func() string
}

// PRCreateService manages idempotent PR creation for cloud runs. It uses
// deterministic idempotency keys so retries cannot create duplicate PRs.
type PRCreateService struct {
	store  Store
	config PRCreateConfig
}

// NewPRCreateService creates a new PRCreateService with the given store and config.
func NewPRCreateService(store Store, config PRCreateConfig) *PRCreateService {
	return &PRCreateService{
		store:  store,
		config: config,
	}
}

// PRCreateRequest contains the parameters for creating a pull request.
type PRCreateRequest struct {
	// RunID is the run this PR is associated with.
	RunID string
	// AttemptID is the current attempt (for event correlation).
	AttemptID string
	// Title is the PR title.
	Title string
	// Body is the PR description body.
	Body string
	// Head is the head branch name.
	Head string
	// Base is the base branch name.
	Base string
	// Repo is the repository (owner/repo).
	Repo string
}

// Validate checks required fields on PRCreateRequest.
func (r *PRCreateRequest) Validate() error {
	if r.RunID == "" {
		return fmt.Errorf("runID must not be empty")
	}
	if r.AttemptID == "" {
		return fmt.Errorf("attemptID must not be empty")
	}
	if r.Title == "" {
		return fmt.Errorf("title must not be empty")
	}
	if r.Head == "" {
		return fmt.Errorf("head must not be empty")
	}
	if r.Base == "" {
		return fmt.Errorf("base must not be empty")
	}
	if r.Repo == "" {
		return fmt.Errorf("repo must not be empty")
	}
	return nil
}

// PRCreateResult holds the outcome of a PR creation attempt.
type PRCreateResult struct {
	// PRRef is the reference to the created (or existing) PR (e.g., URL or number).
	PRRef string
	// Created is true if a new PR was created, false if reused from a prior attempt.
	Created bool
}

// PRCreator is the function signature for the external PR creation call.
// It receives the request and returns the PR reference string (e.g., a URL)
// or an error.
type PRCreator func(ctx context.Context, req *PRCreateRequest) (string, error)

// prCreateEventPayload is the JSON payload for PR creation lifecycle events.
type prCreateEventPayload struct {
	RunID    string `json:"run_id"`
	PRRef    string `json:"pr_ref,omitempty"`
	Reused   bool   `json:"reused,omitempty"`
	Error    string `json:"error,omitempty"`
	IdempKey string `json:"idempotency_key,omitempty"`
}

// sideEffectPRCreate is the side effect type for PR creation idempotency keys.
const sideEffectPRCreate = "pr_create"

// prCreateIdempotencyKey builds a deterministic idempotency key for PR creation.
// Format: pr_create:<run_id>
func prCreateIdempotencyKey(runID string) string {
	return fmt.Sprintf("%s:%s", sideEffectPRCreate, runID)
}

// CreatePR creates a pull request idempotently. If a prior attempt already
// created a PR for this run (matching idempotency key), the stored PR
// reference is returned without making an external create call.
func (s *PRCreateService) CreatePR(ctx context.Context, req *PRCreateRequest, creator PRCreator) (*PRCreateResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if creator == nil {
		return nil, fmt.Errorf("creator must not be nil")
	}

	now := time.Now().UTC().Truncate(time.Second)
	idempKey := prCreateIdempotencyKey(req.RunID)

	// Step 1: Check for existing idempotency key.
	existing, err := s.store.GetIdempotencyKey(ctx, idempKey)
	if err == nil && existing != nil {
		// PR was already created in a prior attempt — return stored reference.
		prRef := ""
		if existing.ResultRef != nil {
			prRef = *existing.ResultRef
		}
		s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_create_reused", &prCreateEventPayload{
			RunID:    req.RunID,
			PRRef:    prRef,
			Reused:   true,
			IdempKey: idempKey,
		}, now)
		return &PRCreateResult{
			PRRef:   prRef,
			Created: false,
		}, nil
	}
	if err != nil && !IsNotFound(err) {
		return nil, fmt.Errorf("checking idempotency key: %w", err)
	}

	// Step 2: Emit pr_create_started event.
	s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_create_started", &prCreateEventPayload{
		RunID:    req.RunID,
		IdempKey: idempKey,
	}, now)

	// Step 3: Call the external PR creator.
	prRef, err := creator(ctx, req)
	if err != nil {
		s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_create_failed", &prCreateEventPayload{
			RunID:    req.RunID,
			Error:    err.Error(),
			IdempKey: idempKey,
		}, now)
		return nil, fmt.Errorf("creating PR: %w", err)
	}

	// Step 4: Store the idempotency key with the PR reference.
	iKey := &IdempotencyKey{
		Key:            idempKey,
		RunID:          req.RunID,
		SideEffectType: sideEffectPRCreate,
		ResultRef:      &prRef,
		CreatedAt:      now,
	}
	if putErr := s.store.PutIdempotencyKey(ctx, iKey); putErr != nil {
		if IsDuplicateKey(putErr) {
			// Race condition: another attempt stored the key concurrently.
			// Retrieve the stored result and return it.
			raced, getErr := s.store.GetIdempotencyKey(ctx, idempKey)
			if getErr != nil {
				return nil, fmt.Errorf("retrieving raced idempotency key: %w", getErr)
			}
			racedRef := ""
			if raced.ResultRef != nil {
				racedRef = *raced.ResultRef
			}
			return &PRCreateResult{
				PRRef:   racedRef,
				Created: false,
			}, nil
		}
		return nil, fmt.Errorf("storing idempotency key: %w", putErr)
	}

	// Step 5: Emit pr_create_completed event.
	s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_create_completed", &prCreateEventPayload{
		RunID:    req.RunID,
		PRRef:    prRef,
		IdempKey: idempKey,
	}, now)

	return &PRCreateResult{
		PRRef:   prRef,
		Created: true,
	}, nil
}

// emitEvent inserts an event with the given type and payload. Errors are
// best-effort — event emission failures do not block PR creation.
func (s *PRCreateService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *prCreateEventPayload, now time.Time) {
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
