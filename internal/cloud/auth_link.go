package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AuthLinkRequest contains the fields required to link an auth profile.
type AuthLinkRequest struct {
	Provider  string `json:"provider"`
	ProfileID string `json:"profile_id"`
	OwnerID   string `json:"owner_id"`
	Mode      string `json:"mode"`
	SecretRef string `json:"secret_ref"`
}

// Validate checks that all required fields are set.
func (r *AuthLinkRequest) Validate() error {
	if r.Provider == "" {
		return fmt.Errorf("provider must not be empty")
	}
	if r.ProfileID == "" {
		return fmt.Errorf("profile must not be empty")
	}
	return nil
}

// AuthLinkConfig holds configuration for the AuthLinkService.
type AuthLinkConfig struct {
	// IDFunc generates unique IDs. If nil, a default is used.
	IDFunc func() string
}

// AuthLinkService handles interactive profile linking from an operator environment.
type AuthLinkService struct {
	store  Store
	config AuthLinkConfig
}

// NewAuthLinkService creates a new AuthLinkService.
func NewAuthLinkService(store Store, config AuthLinkConfig) *AuthLinkService {
	return &AuthLinkService{store: store, config: config}
}

// AuthLinkResult contains the result of a successful link operation.
type AuthLinkResult struct {
	ProfileID string    `json:"profile_id"`
	Provider  string    `json:"provider"`
	Status    string    `json:"status"`
	LinkedAt  time.Time `json:"linked_at"`
}

// authLinkAuditPayload is the event payload for auth link audit events.
type authLinkAuditPayload struct {
	Provider  string `json:"provider"`
	ProfileID string `json:"profile_id"`
	Action    string `json:"action"`
}

// Link initiates a provider flow and stores the encrypted secret reference.
// It creates a new auth profile with linked status and emits an audit event.
func (s *AuthLinkService) Link(ctx context.Context, req *AuthLinkRequest) (*AuthLinkResult, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	now := time.Now().UTC()

	// Build the secret reference from the request.
	var secretRef *string
	if req.SecretRef != "" {
		secretRef = &req.SecretRef
	}

	// Determine owner ID — default to "operator" if not provided.
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "operator"
	}

	// Determine mode — default to "session" if not provided.
	mode := req.Mode
	if mode == "" {
		mode = "session"
	}

	profile := &AuthProfile{
		ID:                req.ProfileID,
		OwnerID:           ownerID,
		Provider:          req.Provider,
		Mode:              mode,
		SecretRef:         secretRef,
		Status:            AuthProfileStatusLinked,
		MaxConcurrentRuns: 1,
		Version:           1,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := s.store.CreateAuthProfile(ctx, profile); err != nil {
		if IsDuplicateKey(err) {
			return nil, fmt.Errorf("auth profile %q already exists", req.ProfileID)
		}
		return nil, fmt.Errorf("failed to create auth profile: %w", err)
	}

	// Emit audit event. Best-effort — errors are ignored.
	s.emitAuditEvent(ctx, req.ProfileID, req.Provider)

	return &AuthLinkResult{
		ProfileID: req.ProfileID,
		Provider:  req.Provider,
		Status:    string(AuthProfileStatusLinked),
		LinkedAt:  now,
	}, nil
}

// emitAuditEvent emits an auth_profile_linked audit event. Best-effort.
func (s *AuthLinkService) emitAuditEvent(ctx context.Context, profileID, provider string) {
	payload := authLinkAuditPayload{
		Provider:  provider,
		ProfileID: profileID,
		Action:    "link",
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return
	}
	payloadStr := string(payloadJSON)

	id := "evt-" + profileID + "-link"
	if s.config.IDFunc != nil {
		id = s.config.IDFunc()
	}

	event := &Event{
		ID:          id,
		RunID:       profileID, // Use profile ID as run_id for audit events
		EventType:   "auth_profile_linked",
		PayloadJSON: &payloadStr,
		CreatedAt:   time.Now().UTC(),
	}
	// Best-effort: ignore insertion errors (e.g., if events table has FK constraints
	// requiring a valid run_id, the audit event is skipped gracefully).
	_ = s.store.InsertEvent(ctx, event)
}
