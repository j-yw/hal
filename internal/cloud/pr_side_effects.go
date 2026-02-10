package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// --- PR Update ---

// PRUpdateConfig holds configuration for the PR update service.
type PRUpdateConfig struct {
	IDFunc func() string
}

// PRUpdateService manages idempotent PR updates for cloud runs.
type PRUpdateService struct {
	store  Store
	config PRUpdateConfig
}

// NewPRUpdateService creates a new PRUpdateService with the given store and config.
func NewPRUpdateService(store Store, config PRUpdateConfig) *PRUpdateService {
	return &PRUpdateService{
		store:  store,
		config: config,
	}
}

// PRUpdateRequest contains the parameters for updating a pull request.
type PRUpdateRequest struct {
	RunID     string
	AttemptID string
	PRRef     string
	Title     string
	Body      string
	Repo      string
}

// Validate checks required fields on PRUpdateRequest.
func (r *PRUpdateRequest) Validate() error {
	if r.RunID == "" {
		return fmt.Errorf("runID must not be empty")
	}
	if r.AttemptID == "" {
		return fmt.Errorf("attemptID must not be empty")
	}
	if r.PRRef == "" {
		return fmt.Errorf("prRef must not be empty")
	}
	if r.Repo == "" {
		return fmt.Errorf("repo must not be empty")
	}
	return nil
}

// PRUpdateResult holds the outcome of a PR update attempt.
type PRUpdateResult struct {
	Updated bool
}

// PRUpdater is the function signature for the external PR update call.
type PRUpdater func(ctx context.Context, req *PRUpdateRequest) error

const sideEffectPRUpdate = "pr_update"

func prUpdateIdempotencyKey(runID string) string {
	return fmt.Sprintf("%s:%s", sideEffectPRUpdate, runID)
}

// UpdatePR updates a pull request idempotently. If a prior attempt already
// updated the PR for this run (matching idempotency key), the operation
// returns without making an external update call.
func (s *PRUpdateService) UpdatePR(ctx context.Context, req *PRUpdateRequest, updater PRUpdater) (*PRUpdateResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if updater == nil {
		return nil, fmt.Errorf("updater must not be nil")
	}

	now := time.Now().UTC().Truncate(time.Second)
	idempKey := prUpdateIdempotencyKey(req.RunID)

	// Check for existing idempotency key.
	existing, err := s.store.GetIdempotencyKey(ctx, idempKey)
	if err == nil && existing != nil {
		s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_update_reused", &prSideEffectEventPayload{
			RunID:    req.RunID,
			PRRef:    req.PRRef,
			Reused:   true,
			IdempKey: idempKey,
		}, now)
		return &PRUpdateResult{Updated: false}, nil
	}
	if err != nil && !IsNotFound(err) {
		return nil, fmt.Errorf("checking idempotency key: %w", err)
	}

	// Emit pr_update_started event.
	s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_update_started", &prSideEffectEventPayload{
		RunID:    req.RunID,
		PRRef:    req.PRRef,
		IdempKey: idempKey,
	}, now)

	// Call the external PR updater.
	if err := updater(ctx, req); err != nil {
		s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_update_failed", &prSideEffectEventPayload{
			RunID:    req.RunID,
			PRRef:    req.PRRef,
			Error:    err.Error(),
			IdempKey: idempKey,
		}, now)
		return nil, fmt.Errorf("updating PR: %w", err)
	}

	// Store the idempotency key.
	iKey := &IdempotencyKey{
		Key:            idempKey,
		RunID:          req.RunID,
		SideEffectType: sideEffectPRUpdate,
		ResultRef:      &req.PRRef,
		CreatedAt:      now,
	}
	if putErr := s.store.PutIdempotencyKey(ctx, iKey); putErr != nil {
		if IsDuplicateKey(putErr) {
			return &PRUpdateResult{Updated: false}, nil
		}
		return nil, fmt.Errorf("storing idempotency key: %w", putErr)
	}

	// Emit pr_update_completed event.
	s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_update_completed", &prSideEffectEventPayload{
		RunID:    req.RunID,
		PRRef:    req.PRRef,
		IdempKey: idempKey,
	}, now)

	return &PRUpdateResult{Updated: true}, nil
}

func (s *PRUpdateService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *prSideEffectEventPayload, now time.Time) {
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

// --- PR Comment ---

// PRCommentConfig holds configuration for the PR comment service.
type PRCommentConfig struct {
	IDFunc func() string
}

// PRCommentService manages idempotent PR comments for cloud runs.
type PRCommentService struct {
	store  Store
	config PRCommentConfig
}

// NewPRCommentService creates a new PRCommentService with the given store and config.
func NewPRCommentService(store Store, config PRCommentConfig) *PRCommentService {
	return &PRCommentService{
		store:  store,
		config: config,
	}
}

// PRCommentRequest contains the parameters for adding a comment to a pull request.
type PRCommentRequest struct {
	RunID     string
	AttemptID string
	PRRef     string
	Body      string
	Repo      string
}

// Validate checks required fields on PRCommentRequest.
func (r *PRCommentRequest) Validate() error {
	if r.RunID == "" {
		return fmt.Errorf("runID must not be empty")
	}
	if r.AttemptID == "" {
		return fmt.Errorf("attemptID must not be empty")
	}
	if r.PRRef == "" {
		return fmt.Errorf("prRef must not be empty")
	}
	if r.Body == "" {
		return fmt.Errorf("body must not be empty")
	}
	if r.Repo == "" {
		return fmt.Errorf("repo must not be empty")
	}
	return nil
}

// PRCommentResult holds the outcome of a PR comment attempt.
type PRCommentResult struct {
	CommentRef string
	Created    bool
}

// PRCommenter is the function signature for the external PR comment call.
// It returns the comment reference (e.g., URL or ID) or an error.
type PRCommenter func(ctx context.Context, req *PRCommentRequest) (string, error)

const sideEffectPRComment = "pr_comment"

func prCommentIdempotencyKey(runID string) string {
	return fmt.Sprintf("%s:%s", sideEffectPRComment, runID)
}

// CommentPR adds a comment to a pull request idempotently. If a prior attempt
// already commented on the PR for this run (matching idempotency key), the
// stored comment reference is returned without making an external call.
func (s *PRCommentService) CommentPR(ctx context.Context, req *PRCommentRequest, commenter PRCommenter) (*PRCommentResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if commenter == nil {
		return nil, fmt.Errorf("commenter must not be nil")
	}

	now := time.Now().UTC().Truncate(time.Second)
	idempKey := prCommentIdempotencyKey(req.RunID)

	// Check for existing idempotency key.
	existing, err := s.store.GetIdempotencyKey(ctx, idempKey)
	if err == nil && existing != nil {
		commentRef := ""
		if existing.ResultRef != nil {
			commentRef = *existing.ResultRef
		}
		s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_comment_reused", &prSideEffectEventPayload{
			RunID:      req.RunID,
			PRRef:      req.PRRef,
			CommentRef: commentRef,
			Reused:     true,
			IdempKey:   idempKey,
		}, now)
		return &PRCommentResult{
			CommentRef: commentRef,
			Created:    false,
		}, nil
	}
	if err != nil && !IsNotFound(err) {
		return nil, fmt.Errorf("checking idempotency key: %w", err)
	}

	// Emit pr_comment_started event.
	s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_comment_started", &prSideEffectEventPayload{
		RunID:    req.RunID,
		PRRef:    req.PRRef,
		IdempKey: idempKey,
	}, now)

	// Call the external PR commenter.
	commentRef, err := commenter(ctx, req)
	if err != nil {
		s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_comment_failed", &prSideEffectEventPayload{
			RunID:    req.RunID,
			PRRef:    req.PRRef,
			Error:    err.Error(),
			IdempKey: idempKey,
		}, now)
		return nil, fmt.Errorf("commenting on PR: %w", err)
	}

	// Store the idempotency key with the comment reference.
	iKey := &IdempotencyKey{
		Key:            idempKey,
		RunID:          req.RunID,
		SideEffectType: sideEffectPRComment,
		ResultRef:      &commentRef,
		CreatedAt:      now,
	}
	if putErr := s.store.PutIdempotencyKey(ctx, iKey); putErr != nil {
		if IsDuplicateKey(putErr) {
			raced, getErr := s.store.GetIdempotencyKey(ctx, idempKey)
			if getErr != nil {
				return nil, fmt.Errorf("retrieving raced idempotency key: %w", getErr)
			}
			racedRef := ""
			if raced.ResultRef != nil {
				racedRef = *raced.ResultRef
			}
			return &PRCommentResult{
				CommentRef: racedRef,
				Created:    false,
			}, nil
		}
		return nil, fmt.Errorf("storing idempotency key: %w", putErr)
	}

	// Emit pr_comment_completed event.
	s.emitEvent(ctx, req.RunID, req.AttemptID, "pr_comment_completed", &prSideEffectEventPayload{
		RunID:      req.RunID,
		PRRef:      req.PRRef,
		CommentRef: commentRef,
		IdempKey:   idempKey,
	}, now)

	return &PRCommentResult{
		CommentRef: commentRef,
		Created:    true,
	}, nil
}

func (s *PRCommentService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *prSideEffectEventPayload, now time.Time) {
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

// --- Shared event payload ---

// prSideEffectEventPayload is the JSON payload for PR update and comment lifecycle events.
type prSideEffectEventPayload struct {
	RunID      string `json:"run_id"`
	PRRef      string `json:"pr_ref,omitempty"`
	CommentRef string `json:"comment_ref,omitempty"`
	Reused     bool   `json:"reused,omitempty"`
	Error      string `json:"error,omitempty"`
	IdempKey   string `json:"idempotency_key,omitempty"`
}
