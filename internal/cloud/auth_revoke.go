package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AuthRevokeRequest contains the fields required to revoke an auth profile.
type AuthRevokeRequest struct {
	ProfileID string `json:"profile_id"`
}

// Validate checks that all required fields are set.
func (r *AuthRevokeRequest) Validate() error {
	if r.ProfileID == "" {
		return fmt.Errorf("profile must not be empty")
	}
	return nil
}

// AuthRevokeConfig holds configuration for the AuthRevokeService.
type AuthRevokeConfig struct {
	// IDFunc generates unique IDs. If nil, a default is used.
	IDFunc func() string
}

// AuthRevokeService handles fast profile revocation for compromised credentials.
type AuthRevokeService struct {
	store  Store
	config AuthRevokeConfig
}

// NewAuthRevokeService creates a new AuthRevokeService.
func NewAuthRevokeService(store Store, config AuthRevokeConfig) *AuthRevokeService {
	return &AuthRevokeService{store: store, config: config}
}

// AuthRevokeResult contains the result of a successful revocation.
type AuthRevokeResult struct {
	ProfileID string    `json:"profile_id"`
	Provider  string    `json:"provider"`
	Status    string    `json:"status"`
	RevokedAt time.Time `json:"revoked_at"`
}

// authRevokeAuditPayload is the event payload for auth revoke audit events.
type authRevokeAuditPayload struct {
	Provider  string `json:"provider"`
	ProfileID string `json:"profile_id"`
	Action    string `json:"action"`
}

// Revoke transitions the given auth profile status to revoked.
// Emits an audit event including profile ID and provider.
func (s *AuthRevokeService) Revoke(ctx context.Context, req *AuthRevokeRequest) (*AuthRevokeResult, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	now := time.Now().UTC()

	// Step 1: Fetch auth profile.
	profile, err := s.store.GetAuthProfile(ctx, req.ProfileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth profile: %w", err)
	}

	// Step 2: Transition status to revoked.
	profile.Status = AuthProfileStatusRevoked
	profile.UpdatedAt = now
	if err := s.store.UpdateAuthProfile(ctx, profile); err != nil {
		return nil, fmt.Errorf("failed to update auth profile: %w", err)
	}

	// Emit audit event. Best-effort — errors are ignored.
	s.emitAuditEvent(ctx, req.ProfileID, profile.Provider)

	return &AuthRevokeResult{
		ProfileID: profile.ID,
		Provider:  profile.Provider,
		Status:    string(AuthProfileStatusRevoked),
		RevokedAt: now,
	}, nil
}

// emitAuditEvent emits an auth_profile_revoked audit event. Best-effort.
func (s *AuthRevokeService) emitAuditEvent(ctx context.Context, profileID, provider string) {
	payload := authRevokeAuditPayload{
		Provider:  provider,
		ProfileID: profileID,
		Action:    "revoke",
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return
	}
	payloadStr := string(payloadJSON)

	id := "evt-" + profileID + "-revoke"
	if s.config.IDFunc != nil {
		id = s.config.IDFunc()
	}

	event := &Event{
		ID:          id,
		RunID:       profileID, // Use profile ID as run_id for audit events
		EventType:   "auth_profile_revoked",
		PayloadJSON: &payloadStr,
		CreatedAt:   time.Now().UTC(),
	}
	// Best-effort: ignore insertion errors.
	_ = s.store.InsertEvent(ctx, event)
}
