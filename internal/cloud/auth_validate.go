package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AuthValidateRequest contains the fields required to validate an auth profile.
type AuthValidateRequest struct {
	ProfileID string `json:"profile_id"`
}

// Validate checks that all required fields are set.
func (r *AuthValidateRequest) Validate() error {
	if r.ProfileID == "" {
		return fmt.Errorf("profile must not be empty")
	}
	return nil
}

// AuthValidateConfig holds configuration for the AuthValidateService.
type AuthValidateConfig struct {
	// IDFunc generates unique IDs. If nil, a default is used.
	IDFunc func() string
}

// AuthValidateService handles explicit provider validation for auth profiles.
type AuthValidateService struct {
	store  Store
	config AuthValidateConfig
}

// NewAuthValidateService creates a new AuthValidateService.
func NewAuthValidateService(store Store, config AuthValidateConfig) *AuthValidateService {
	return &AuthValidateService{store: store, config: config}
}

// AuthValidateResult contains the result of a successful validation.
type AuthValidateResult struct {
	ProfileID   string    `json:"profile_id"`
	Provider    string    `json:"provider"`
	Status      string    `json:"status"`
	ValidatedAt time.Time `json:"validated_at"`
}

// authValidateAuditPayload is the event payload for auth validate audit events.
type authValidateAuditPayload struct {
	Provider  string `json:"provider"`
	ProfileID string `json:"profile_id"`
	Action    string `json:"action"`
	ErrorCode string `json:"error_code,omitempty"`
}

// Validate runs provider validation checks on the given auth profile.
// On success, it updates last_validated_at to now.
// On failure, it sets last_error_code and returns an error.
func (s *AuthValidateService) Validate(ctx context.Context, req *AuthValidateRequest) (*AuthValidateResult, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	now := time.Now().UTC()

	// Step 1: Fetch auth profile.
	profile, err := s.store.GetAuthProfile(ctx, req.ProfileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth profile: %w", err)
	}

	// Step 2: Check profile status is not terminal/revoked.
	if profile.Status == AuthProfileStatusRevoked {
		errCode := string(FailureAuthInvalid)
		profile.LastErrorCode = &errCode
		profile.UpdatedAt = now
		_ = s.store.UpdateAuthProfile(ctx, profile)
		s.emitAuditEvent(ctx, req.ProfileID, profile.Provider, errCode)
		return nil, fmt.Errorf("auth profile %q is revoked", req.ProfileID)
	}

	// Step 3: Validate runtime metadata if present.
	if profile.RuntimeMetadataJSON != nil && *profile.RuntimeMetadataJSON != "" {
		var metadata RuntimeMetadata
		if err := json.Unmarshal([]byte(*profile.RuntimeMetadataJSON), &metadata); err != nil {
			errCode := string(FailureAuthProfileIncompatible)
			profile.LastErrorCode = &errCode
			profile.UpdatedAt = now
			_ = s.store.UpdateAuthProfile(ctx, profile)
			s.emitAuditEvent(ctx, req.ProfileID, profile.Provider, errCode)
			return nil, fmt.Errorf("failed to parse runtime metadata: %w", err)
		}
	}

	// Step 4: Check profile has a secret_ref (credential linkage).
	if profile.SecretRef == nil || *profile.SecretRef == "" {
		errCode := string(FailureAuthInvalid)
		profile.LastErrorCode = &errCode
		profile.UpdatedAt = now
		_ = s.store.UpdateAuthProfile(ctx, profile)
		s.emitAuditEvent(ctx, req.ProfileID, profile.Provider, errCode)
		return nil, fmt.Errorf("auth profile %q has no linked credentials", req.ProfileID)
	}

	// Step 5: Validation passed — update last_validated_at and clear error.
	profile.LastValidatedAt = &now
	profile.LastErrorCode = nil
	profile.UpdatedAt = now
	if err := s.store.UpdateAuthProfile(ctx, profile); err != nil {
		return nil, fmt.Errorf("failed to update auth profile: %w", err)
	}

	// Emit success audit event.
	s.emitAuditEvent(ctx, req.ProfileID, profile.Provider, "")

	return &AuthValidateResult{
		ProfileID:   profile.ID,
		Provider:    profile.Provider,
		Status:      string(profile.Status),
		ValidatedAt: now,
	}, nil
}

// emitAuditEvent emits an auth_profile_validated audit event. Best-effort.
func (s *AuthValidateService) emitAuditEvent(ctx context.Context, profileID, provider, errCode string) {
	payload := authValidateAuditPayload{
		Provider:  provider,
		ProfileID: profileID,
		Action:    "validate",
		ErrorCode: errCode,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return
	}
	payloadStr := string(payloadJSON)

	id := "evt-" + profileID + "-validate"
	if s.config.IDFunc != nil {
		id = s.config.IDFunc()
	}

	event := &Event{
		ID:          id,
		RunID:       profileID, // Use profile ID as run_id for audit events
		EventType:   "auth_profile_validated",
		PayloadJSON: &payloadStr,
		CreatedAt:   time.Now().UTC(),
	}
	// Best-effort: ignore insertion errors.
	_ = s.store.InsertEvent(ctx, event)
}
