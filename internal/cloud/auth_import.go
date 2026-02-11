package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AuthImportRequest contains the fields required to import auth artifacts.
type AuthImportRequest struct {
	Provider  string `json:"provider"`
	ProfileID string `json:"profile_id"`
	Source    string `json:"source"`
	OwnerID   string `json:"owner_id"`
	Mode      string `json:"mode"`
}

// Validate checks that all required fields are set.
func (r *AuthImportRequest) Validate() error {
	if r.Provider == "" {
		return fmt.Errorf("provider must not be empty")
	}
	if r.ProfileID == "" {
		return fmt.Errorf("profile must not be empty")
	}
	if r.Source == "" {
		return fmt.Errorf("source must not be empty")
	}
	return nil
}

// AuthImportConfig holds configuration for the AuthImportService.
type AuthImportConfig struct {
	// IDFunc generates unique IDs. If nil, a default is used.
	IDFunc func() string

	// CredentialValidator validates supplied credentials with the configured backend.
	// If nil, no backend validation is performed.
	// Returns nil on success, or an error if credentials are invalid.
	CredentialValidator func(ctx context.Context, provider, source string) error
}

// AuthImportService handles importing local auth artifacts into a profile.
type AuthImportService struct {
	store  Store
	config AuthImportConfig
}

// NewAuthImportService creates a new AuthImportService.
func NewAuthImportService(store Store, config AuthImportConfig) *AuthImportService {
	return &AuthImportService{store: store, config: config}
}

// AuthImportResult contains the result of a successful import operation.
type AuthImportResult struct {
	ProfileID  string    `json:"profile_id"`
	Provider   string    `json:"provider"`
	Status     string    `json:"status"`
	ImportedAt time.Time `json:"imported_at"`
}

// authImportAuditPayload is the event payload for auth import audit events.
type authImportAuditPayload struct {
	Provider  string `json:"provider"`
	ProfileID string `json:"profile_id"`
	Action    string `json:"action"`
}

// Import reads local auth artifacts and creates an auth profile with an encrypted secret reference.
func (s *AuthImportService) Import(ctx context.Context, req *AuthImportRequest) (*AuthImportResult, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Validate credentials with the configured backend before persisting.
	if s.config.CredentialValidator != nil {
		if err := s.config.CredentialValidator(ctx, req.Provider, req.Source); err != nil {
			return nil, fmt.Errorf("invalid credentials: %w", err)
		}
	}

	now := time.Now().UTC()

	// Encrypt the source path as the secret reference.
	// In production, this would involve reading the source file and encrypting its contents.
	// For now, the source is stored as the encrypted secret reference.
	secretRef := "encrypted:" + req.Source

	// Determine owner ID — default to "operator" if not provided.
	ownerID := req.OwnerID
	if ownerID == "" {
		ownerID = "operator"
	}

	// Determine mode — default to "imported" if not provided.
	mode := req.Mode
	if mode == "" {
		mode = "imported"
	}

	profile := &AuthProfile{
		ID:                req.ProfileID,
		OwnerID:           ownerID,
		Provider:          req.Provider,
		Mode:              mode,
		SecretRef:         &secretRef,
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

	return &AuthImportResult{
		ProfileID:  req.ProfileID,
		Provider:   req.Provider,
		Status:     string(AuthProfileStatusLinked),
		ImportedAt: now,
	}, nil
}

// emitAuditEvent emits an auth_profile_imported audit event. Best-effort.
func (s *AuthImportService) emitAuditEvent(ctx context.Context, profileID, provider string) {
	payload := authImportAuditPayload{
		Provider:  provider,
		ProfileID: profileID,
		Action:    "import",
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return
	}
	payloadStr := string(payloadJSON)

	id := "evt-" + profileID + "-import"
	if s.config.IDFunc != nil {
		id = s.config.IDFunc()
	}

	event := &Event{
		ID:          id,
		RunID:       profileID, // Use profile ID as run_id for audit events
		EventType:   "auth_profile_imported",
		PayloadJSON: &payloadStr,
		CreatedAt:   time.Now().UTC(),
	}
	// Best-effort: ignore insertion errors.
	_ = s.store.InsertEvent(ctx, event)
}
