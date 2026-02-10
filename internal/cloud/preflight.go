package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/cloud/runner"
)

// PreflightConfig holds configuration for the preflight service.
type PreflightConfig struct {
	// ProviderCommands maps provider names to their non-interactive preflight
	// shell commands. If empty, preflight execution is skipped for unknown
	// providers.
	ProviderCommands map[string]string
	// IDFunc generates unique IDs for events. If nil, event IDs will be empty.
	IDFunc func() string
}

// PreflightService executes provider-specific preflight validation and
// runtime metadata compatibility checks before Hal execution begins.
type PreflightService struct {
	store  Store
	runner runner.Runner
	config PreflightConfig
}

// NewPreflightService creates a new PreflightService with the given store,
// runner, and config.
func NewPreflightService(store Store, r runner.Runner, config PreflightConfig) *PreflightService {
	if config.ProviderCommands == nil {
		config.ProviderCommands = make(map[string]string)
	}
	return &PreflightService{
		store:  store,
		runner: r,
		config: config,
	}
}

// PreflightRequest contains the parameters for a preflight check.
type PreflightRequest struct {
	// AuthProfileID is the auth profile to validate.
	AuthProfileID string
	// SandboxID is the sandbox where preflight commands are executed.
	SandboxID string
	// AttemptID is the current attempt (for event correlation).
	AttemptID string
	// RunID is the current run (for event correlation).
	RunID string
	// SandboxOS is the operating system of the sandbox runtime (e.g., "linux").
	SandboxOS string
	// SandboxArch is the architecture of the sandbox runtime (e.g., "amd64").
	SandboxArch string
	// SandboxCLIVersion is the CLI major.minor version in the sandbox (e.g., "1.2").
	SandboxCLIVersion string
}

// Validate checks required fields on PreflightRequest.
func (r *PreflightRequest) Validate() error {
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

// RuntimeMetadata is the expected runtime metadata stored on an auth profile.
type RuntimeMetadata struct {
	OS         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
	CLIVersion string `json:"cli_version,omitempty"`
}

// preflightEventPayload is the JSON payload for preflight lifecycle events.
type preflightEventPayload struct {
	SandboxID     string `json:"sandbox_id"`
	AuthProfileID string `json:"auth_profile_id"`
	Provider      string `json:"provider,omitempty"`
	Command       string `json:"command,omitempty"`
	Step          string `json:"step,omitempty"`
	Error         string `json:"error,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
	ExitCode      *int   `json:"exit_code,omitempty"`
}

// Preflight executes provider-specific non-interactive preflight validation
// and checks runtime metadata compatibility. If the auth profile has
// runtime_metadata_json, the sandbox runtime attributes are validated against
// it. Metadata incompatibility fails with error code auth_profile_incompatible.
func (s *PreflightService) Preflight(ctx context.Context, req *PreflightRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Step 1: Fetch auth profile.
	profile, err := s.store.GetAuthProfile(ctx, req.AuthProfileID)
	if err != nil {
		return fmt.Errorf("preflight: failed to get auth profile: %w", err)
	}

	// Step 2: Emit preflight_started event.
	startPayload := &preflightEventPayload{
		SandboxID:     req.SandboxID,
		AuthProfileID: req.AuthProfileID,
		Provider:      profile.Provider,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "preflight_started", startPayload, now)

	// Step 3: Validate runtime metadata compatibility.
	if profile.RuntimeMetadataJSON != nil && *profile.RuntimeMetadataJSON != "" {
		var metadata RuntimeMetadata
		if err := json.Unmarshal([]byte(*profile.RuntimeMetadataJSON), &metadata); err != nil {
			s.emitPreflightFailed(ctx, req, profile.Provider, "metadata_parse",
				fmt.Sprintf("failed to parse runtime_metadata_json: %s", err.Error()),
				string(FailureAuthProfileIncompatible), nil, now)
			return fmt.Errorf("preflight: failed to parse runtime metadata: %w", err)
		}

		if incompatibility := checkCompatibility(metadata, req); incompatibility != "" {
			s.emitPreflightFailed(ctx, req, profile.Provider, "compatibility_check",
				incompatibility, string(FailureAuthProfileIncompatible), nil, now)
			return fmt.Errorf("preflight: %s", incompatibility)
		}
	}

	// Step 4: Execute provider-specific preflight command.
	cmd, hasCommand := s.config.ProviderCommands[profile.Provider]
	if hasCommand && cmd != "" {
		startPayload.Command = cmd
		execResult, err := s.runner.Exec(ctx, req.SandboxID, &runner.ExecRequest{
			Command: cmd,
			WorkDir: "/workspace",
		})
		if err != nil {
			s.emitPreflightFailed(ctx, req, profile.Provider, "preflight_command",
				"preflight command failed: "+err.Error(), "", nil, now)
			return fmt.Errorf("preflight: command execution failed: %w", err)
		}
		if execResult.ExitCode != 0 {
			output := execResult.Stderr
			if output == "" {
				output = execResult.Stdout
			}
			s.emitPreflightFailed(ctx, req, profile.Provider, "preflight_command",
				output, "", &execResult.ExitCode, now)
			return fmt.Errorf("preflight: command failed: exit code %d: %s", execResult.ExitCode, output)
		}
	}

	// Step 5: Emit preflight_completed event.
	completePayload := &preflightEventPayload{
		SandboxID:     req.SandboxID,
		AuthProfileID: req.AuthProfileID,
		Provider:      profile.Provider,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "preflight_completed", completePayload, now)

	return nil
}

// checkCompatibility validates sandbox runtime attributes against profile
// metadata. Returns a human-readable incompatibility description or empty
// string if compatible.
func checkCompatibility(metadata RuntimeMetadata, req *PreflightRequest) string {
	var mismatches []string

	if metadata.OS != "" && req.SandboxOS != "" && !strings.EqualFold(metadata.OS, req.SandboxOS) {
		mismatches = append(mismatches, fmt.Sprintf("OS mismatch: profile requires %q, sandbox has %q", metadata.OS, req.SandboxOS))
	}

	if metadata.Arch != "" && req.SandboxArch != "" && !strings.EqualFold(metadata.Arch, req.SandboxArch) {
		mismatches = append(mismatches, fmt.Sprintf("architecture mismatch: profile requires %q, sandbox has %q", metadata.Arch, req.SandboxArch))
	}

	if metadata.CLIVersion != "" && req.SandboxCLIVersion != "" {
		profileMajor, profileMinor := parseMajorMinor(metadata.CLIVersion)
		sandboxMajor, sandboxMinor := parseMajorMinor(req.SandboxCLIVersion)

		if profileMajor != "" && sandboxMajor != "" {
			if profileMajor != sandboxMajor {
				mismatches = append(mismatches, fmt.Sprintf("CLI major version mismatch: profile requires %q, sandbox has %q", metadata.CLIVersion, req.SandboxCLIVersion))
			} else if profileMinor != "" && sandboxMinor != "" && profileMinor != sandboxMinor {
				mismatches = append(mismatches, fmt.Sprintf("CLI minor version mismatch: profile requires %q, sandbox has %q", metadata.CLIVersion, req.SandboxCLIVersion))
			}
		}
	}

	if len(mismatches) == 0 {
		return ""
	}
	return "auth_profile_incompatible: " + strings.Join(mismatches, "; ")
}

// parseMajorMinor extracts major and minor components from a "major.minor"
// version string. Returns empty strings for unparseable input.
func parseMajorMinor(version string) (major, minor string) {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) >= 1 {
		major = parts[0]
	}
	if len(parts) >= 2 {
		minor = parts[1]
	}
	return major, minor
}

// emitPreflightFailed emits a preflight_failed event with error context.
func (s *PreflightService) emitPreflightFailed(ctx context.Context, req *PreflightRequest, provider, step, errMsg, errorCode string, exitCode *int, now time.Time) {
	payload := &preflightEventPayload{
		SandboxID:     req.SandboxID,
		AuthProfileID: req.AuthProfileID,
		Provider:      provider,
		Step:          step,
		Error:         errMsg,
		ErrorCode:     errorCode,
		ExitCode:      exitCode,
	}
	s.emitEvent(ctx, req.RunID, req.AttemptID, "preflight_failed", payload, now)
}

// emitEvent inserts an event with the given type and payload. Errors are
// best-effort — event emission failures do not block preflight.
func (s *PreflightService) emitEvent(ctx context.Context, runID, attemptID, eventType string, payload *preflightEventPayload, now time.Time) {
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
