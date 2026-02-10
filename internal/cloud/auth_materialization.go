package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// AuthMaterializationConfig holds configuration for the auth materialization service.
type AuthMaterializationConfig struct {
	// AuthDir is the directory path inside the sandbox where auth artifacts are
	// materialized. Defaults to "/home/user/.auth".
	AuthDir string
	// IDFunc generates unique IDs for events. If nil, event IDs will be empty.
	IDFunc func() string
}

// DefaultAuthDir is the default directory for materialized auth artifacts.
const DefaultAuthDir = "/home/user/.auth"

// AuthMaterializationService manages the materialization of auth artifacts
// from secret_ref into a sandbox at runtime and their removal during teardown.
type AuthMaterializationService struct {
	store  Store
	runner runner.Runner
	config AuthMaterializationConfig
}

// NewAuthMaterializationService creates a new AuthMaterializationService with
// the given store, runner, and config.
func NewAuthMaterializationService(store Store, r runner.Runner, config AuthMaterializationConfig) *AuthMaterializationService {
	if config.AuthDir == "" {
		config.AuthDir = DefaultAuthDir
	}
	return &AuthMaterializationService{
		store:  store,
		runner: r,
		config: config,
	}
}

// MaterializeRequest contains the parameters for materializing auth artifacts.
type MaterializeRequest struct {
	// AuthProfileID is the auth profile whose secret_ref should be materialized.
	AuthProfileID string
	// SandboxID is the sandbox where artifacts will be written.
	SandboxID string
	// AttemptID is the current attempt (for event correlation).
	AttemptID string
	// RunID is the current run (for event correlation).
	RunID string
}

// Validate checks required fields on MaterializeRequest.
func (r *MaterializeRequest) Validate() error {
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

// authMaterializationEventPayload is the JSON payload for auth materialization
// lifecycle events.
type authMaterializationEventPayload struct {
	SandboxID     string `json:"sandbox_id"`
	AuthProfileID string `json:"auth_profile_id"`
	AuthDir       string `json:"auth_dir,omitempty"`
	Error         string `json:"error,omitempty"`
	ExitCode      *int   `json:"exit_code,omitempty"`
}

// Materialize retrieves the auth profile's secret_ref from the store and
// writes it into the sandbox filesystem with least-privilege permissions.
// The auth directory is created with mode 0700 and secret files with mode 0600.
// If the profile has no secret_ref, materialization is skipped (no-op).
func (s *AuthMaterializationService) Materialize(ctx context.Context, req *MaterializeRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Step 1: Fetch auth profile.
	profile, err := s.store.GetAuthProfile(ctx, req.AuthProfileID)
	if err != nil {
		return fmt.Errorf("failed to get auth profile: %w", err)
	}

	// Step 2: Skip if no secret_ref.
	if profile.SecretRef == nil || *profile.SecretRef == "" {
		return nil
	}

	// Step 3: Emit auth_materialize_started event.
	startPayload := &authMaterializationEventPayload{
		SandboxID:     req.SandboxID,
		AuthProfileID: req.AuthProfileID,
		AuthDir:       s.config.AuthDir,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "auth_materialize_started", startPayload, now)

	// Step 4: Create auth directory with mode 0700.
	mkdirCmd := fmt.Sprintf("mkdir -p -m 0700 %s", s.config.AuthDir)
	mkdirResult, err := s.runner.Exec(ctx, req.SandboxID, &runner.ExecRequest{
		Command: mkdirCmd,
	})
	if err != nil {
		s.emitMaterializeFailed(ctx, req, "mkdir failed: "+err.Error(), nil, now)
		return fmt.Errorf("auth materialization mkdir failed: %w", err)
	}
	if mkdirResult.ExitCode != 0 {
		output := mkdirResult.Stderr
		if output == "" {
			output = mkdirResult.Stdout
		}
		s.emitMaterializeFailed(ctx, req, output, &mkdirResult.ExitCode, now)
		return fmt.Errorf("auth materialization mkdir failed: exit code %d: %s", mkdirResult.ExitCode, output)
	}

	// Step 5: Write secret_ref content to credentials file with mode 0600.
	// Use printf to write the secret content and chmod to set permissions.
	credFile := s.config.AuthDir + "/credentials"
	writeCmd := fmt.Sprintf("printf '%%s' '%s' > %s && chmod 0600 %s",
		escapeShellSingleQuote(*profile.SecretRef), credFile, credFile)
	writeResult, err := s.runner.Exec(ctx, req.SandboxID, &runner.ExecRequest{
		Command: writeCmd,
	})
	if err != nil {
		s.emitMaterializeFailed(ctx, req, "write failed: "+err.Error(), nil, now)
		return fmt.Errorf("auth materialization write failed: %w", err)
	}
	if writeResult.ExitCode != 0 {
		output := writeResult.Stderr
		if output == "" {
			output = writeResult.Stdout
		}
		s.emitMaterializeFailed(ctx, req, output, &writeResult.ExitCode, now)
		return fmt.Errorf("auth materialization write failed: exit code %d: %s", writeResult.ExitCode, output)
	}

	// Step 6: Emit auth_materialize_completed event.
	completePayload := &authMaterializationEventPayload{
		SandboxID:     req.SandboxID,
		AuthProfileID: req.AuthProfileID,
		AuthDir:       s.config.AuthDir,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "auth_materialize_completed", completePayload, now)

	return nil
}

// Cleanup removes materialized auth artifacts from the sandbox. This should
// be called during the teardown path. Cleanup errors are returned but do not
// prevent the caller from completing the teardown.
func (s *AuthMaterializationService) Cleanup(ctx context.Context, sandboxID, attemptID, runID string) error {
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

	// Step 1: Emit auth_cleanup_started event.
	startPayload := &authMaterializationEventPayload{
		SandboxID: sandboxID,
		AuthDir:   s.config.AuthDir,
	}
	s.emitEvent(ctx, runID, attemptID, "auth_cleanup_started", startPayload, now)

	// Step 2: Remove auth directory.
	rmCmd := fmt.Sprintf("rm -rf %s", s.config.AuthDir)
	rmResult, err := s.runner.Exec(ctx, sandboxID, &runner.ExecRequest{
		Command: rmCmd,
	})

	// Step 3: Emit auth_cleanup_done event (with error if removal failed).
	donePayload := &authMaterializationEventPayload{
		SandboxID: sandboxID,
		AuthDir:   s.config.AuthDir,
	}
	if err != nil {
		donePayload.Error = err.Error()
	} else if rmResult.ExitCode != 0 {
		output := rmResult.Stderr
		if output == "" {
			output = rmResult.Stdout
		}
		donePayload.Error = output
		donePayload.ExitCode = &rmResult.ExitCode
	}
	s.emitEvent(ctx, runID, attemptID, "auth_cleanup_done", donePayload, now)

	if err != nil {
		return fmt.Errorf("auth cleanup failed: %w", err)
	}
	if rmResult.ExitCode != 0 {
		output := rmResult.Stderr
		if output == "" {
			output = rmResult.Stdout
		}
		return fmt.Errorf("auth cleanup failed: exit code %d: %s", rmResult.ExitCode, output)
	}

	return nil
}

// emitMaterializeFailed emits an auth_materialize_failed event.
func (s *AuthMaterializationService) emitMaterializeFailed(ctx context.Context, req *MaterializeRequest, errMsg string, exitCode *int, now time.Time) {
	payload := &authMaterializationEventPayload{
		SandboxID:     req.SandboxID,
		AuthProfileID: req.AuthProfileID,
		AuthDir:       s.config.AuthDir,
		Error:         errMsg,
		ExitCode:      exitCode,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "auth_materialize_failed", payload, now)
}

// emitEvent inserts an event with the given type and payload. Errors are
// best-effort — event emission failures do not block materialization.
func (s *AuthMaterializationService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *authMaterializationEventPayload, now time.Time) {
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

// escapeShellSingleQuote escapes single quotes for safe use in shell
// single-quoted strings by replacing ' with '\”.
func escapeShellSingleQuote(s string) string {
	result := ""
	for _, c := range s {
		if c == '\'' {
			result += "'\\''"
		} else {
			result += string(c)
		}
	}
	return result
}
