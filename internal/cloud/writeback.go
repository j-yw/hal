package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// WritebackConfig holds configuration for the credential writeback service.
type WritebackConfig struct {
	// AuthDir is the directory path inside the sandbox where auth artifacts
	// are materialized. Defaults to "/home/user/.auth".
	AuthDir string
	// CredentialsTTL is the duration to extend expires_at on successful
	// writeback. Defaults to 24 hours.
	CredentialsTTL time.Duration
	// IDFunc generates unique IDs for events. If nil, event IDs will be empty.
	IDFunc func() string
}

// DefaultCredentialsTTL is the default TTL for refreshed credentials.
const DefaultCredentialsTTL = 24 * time.Hour

// WritebackService detects changed auth artifacts in a sandbox after execution
// and persists the refreshed credentials back to the auth profile using
// optimistic version checks. On success, it updates last_validated_at and
// expires_at and clears last_error_code.
type WritebackService struct {
	store  Store
	runner runner.Runner
	config WritebackConfig
}

// NewWritebackService creates a new WritebackService with the given store,
// runner, and config.
func NewWritebackService(store Store, r runner.Runner, config WritebackConfig) *WritebackService {
	if config.AuthDir == "" {
		config.AuthDir = DefaultAuthDir
	}
	if config.CredentialsTTL == 0 {
		config.CredentialsTTL = DefaultCredentialsTTL
	}
	return &WritebackService{
		store:  store,
		runner: r,
		config: config,
	}
}

// WritebackRequest contains the parameters for credential writeback.
type WritebackRequest struct {
	// AuthProfileID is the auth profile whose credentials may have been refreshed.
	AuthProfileID string
	// SandboxID is the sandbox containing the potentially updated artifacts.
	SandboxID string
	// AttemptID is the current attempt (for event correlation).
	AttemptID string
	// RunID is the current run (for event correlation).
	RunID string
}

// Validate checks required fields on WritebackRequest.
func (r *WritebackRequest) Validate() error {
	if r.AuthProfileID == "" {
		return fmt.Errorf("authProfileID must not be empty")
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

// WritebackResult contains the outcome of a credential writeback.
type WritebackResult struct {
	// Changed indicates whether the auth artifacts were different from the
	// original secret_ref.
	Changed bool
	// Written indicates whether the updated credentials were persisted.
	Written bool
}

// writebackEventPayload is the JSON payload for writeback lifecycle events.
type writebackEventPayload struct {
	SandboxID     string `json:"sandbox_id"`
	AuthProfileID string `json:"auth_profile_id"`
	Changed       bool   `json:"changed,omitempty"`
	Written       bool   `json:"written,omitempty"`
	Error         string `json:"error,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
}

// Writeback reads auth artifacts from the sandbox, compares them with the
// original secret_ref, and persists any changes using an optimistic version
// check on auth_profiles.version. On success, it updates last_validated_at
// and expires_at and clears last_error_code.
func (s *WritebackService) Writeback(ctx context.Context, req *WritebackRequest) (*WritebackResult, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Step 1: Fetch auth profile.
	profile, err := s.store.GetAuthProfile(ctx, req.AuthProfileID)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth profile: %w", err)
	}

	// Step 2: Skip if no secret_ref (nothing was materialized).
	if profile.SecretRef == nil || *profile.SecretRef == "" {
		return &WritebackResult{Changed: false, Written: false}, nil
	}

	// Step 3: Emit writeback_started event.
	startPayload := &writebackEventPayload{
		SandboxID:     req.SandboxID,
		AuthProfileID: req.AuthProfileID,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "writeback_started", startPayload, now)

	// Step 4: Read current auth artifacts from sandbox.
	credFile := s.config.AuthDir + "/credentials"
	readCmd := fmt.Sprintf("cat %s", credFile)
	readResult, err := s.runner.Exec(ctx, req.SandboxID, &runner.ExecRequest{
		Command: readCmd,
	})
	if err != nil {
		s.emitWritebackFailed(ctx, req, "read failed: "+err.Error(), "", now)
		return nil, fmt.Errorf("writeback read failed: %w", err)
	}
	if readResult.ExitCode != 0 {
		output := readResult.Stderr
		if output == "" {
			output = readResult.Stdout
		}
		s.emitWritebackFailed(ctx, req, "read failed: exit code "+fmt.Sprintf("%d", readResult.ExitCode)+": "+output, "", now)
		return nil, fmt.Errorf("writeback read failed: exit code %d: %s", readResult.ExitCode, output)
	}

	currentSecret := readResult.Stdout

	// Step 5: Compare with original secret_ref.
	if currentSecret == *profile.SecretRef {
		// No change — emit completed event and return.
		completePayload := &writebackEventPayload{
			SandboxID:     req.SandboxID,
			AuthProfileID: req.AuthProfileID,
			Changed:       false,
			Written:       false,
		}
		s.emitEvent(ctx, req.RunID, req.AttemptID, "writeback_completed", completePayload, now)
		return &WritebackResult{Changed: false, Written: false}, nil
	}

	// Step 6: Credentials changed — update auth profile with optimistic version check.
	newExpiresAt := now.Add(s.config.CredentialsTTL)
	profile.SecretRef = &currentSecret
	profile.LastValidatedAt = &now
	profile.ExpiresAt = &newExpiresAt
	profile.LastErrorCode = nil

	err = s.store.UpdateAuthProfile(ctx, profile)
	if err != nil {
		if IsConflict(err) {
			s.emitWritebackFailed(ctx, req, "version conflict: another process updated the profile", "version_conflict", now)
			return nil, fmt.Errorf("writeback version conflict: %w", err)
		}
		if IsNotFound(err) {
			s.emitWritebackFailed(ctx, req, "auth profile not found during writeback", "not_found", now)
			return nil, fmt.Errorf("writeback auth profile not found: %w", err)
		}
		s.emitWritebackFailed(ctx, req, "update failed: "+err.Error(), "", now)
		return nil, fmt.Errorf("writeback update failed: %w", err)
	}

	// Step 7: Emit writeback_completed event.
	completePayload := &writebackEventPayload{
		SandboxID:     req.SandboxID,
		AuthProfileID: req.AuthProfileID,
		Changed:       true,
		Written:       true,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "writeback_completed", completePayload, now)

	return &WritebackResult{Changed: true, Written: true}, nil
}

// emitWritebackFailed emits a writeback_failed event.
func (s *WritebackService) emitWritebackFailed(ctx context.Context, req *WritebackRequest, errMsg, errorCode string, now time.Time) {
	payload := &writebackEventPayload{
		SandboxID:     req.SandboxID,
		AuthProfileID: req.AuthProfileID,
		Error:         errMsg,
		ErrorCode:     errorCode,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "writeback_failed", payload, now)
}

// emitEvent inserts an event with the given type and payload. Errors are
// best-effort — event emission failures do not block writeback.
func (s *WritebackService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *writebackEventPayload, now time.Time) {
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

	event := &Event{
		ID:          eventID,
		RunID:       runID,
		AttemptID:   &attemptID,
		EventType:   eventType,
		PayloadJSON: payloadJSON,
		CreatedAt:   now,
	}
	_ = s.store.InsertEvent(ctx, event)
}
