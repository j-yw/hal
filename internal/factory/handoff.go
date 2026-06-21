package factory

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	handoffInspectActionID         = "inspect_factory_run"
	handoffSandboxTakeoverActionID = "takeover_sandbox"
	handoffResumeActionID          = "resume_auto"
)

// HandoffSummary is durable, redaction-safe takeover context derived from the
// factory store. It intentionally avoids live provider, git, shell, or network
// lookups so callers can render guidance from persisted run state only.
type HandoffSummary struct {
	RunID             string               `json:"runId"`
	Status            string               `json:"status"`
	ExecutorMode      string               `json:"executorMode"`
	HandoffRequired   bool                 `json:"handoffRequired"`
	NextAction        *NextAction          `json:"nextAction,omitempty"`
	InspectCommand    string               `json:"inspectCommand,omitempty"`
	ResumeCommand     string               `json:"resumeCommand,omitempty"`
	SSHCommand        string               `json:"sshCommand,omitempty"`
	RepoPath          string               `json:"repoPath,omitempty"`
	BranchName        string               `json:"branchName,omitempty"`
	SandboxName       string               `json:"sandboxName,omitempty"`
	PullRequestURL    string               `json:"pullRequestUrl,omitempty"`
	CurrentStep       string               `json:"currentStep,omitempty"`
	FailureReason     string               `json:"failureReason,omitempty"`
	ArtifactLocations []NextActionLocation `json:"artifactLocations,omitempty"`
	LogLocations      []NextActionLocation `json:"logLocations,omitempty"`
}

// LoadHandoffSummary resolves a stored run ID into handoff guidance using only
// the factory store and store-backed artifact payloads.
func LoadHandoffSummary(store Store, runID string) (*HandoffSummary, error) {
	record, err := store.LoadRun(runID)
	if err != nil {
		return nil, fmt.Errorf("load factory run for handoff: %w", err)
	}
	summary := NewHandoffSummary(store, *record)
	return &summary, nil
}

// NewHandoffSummary builds handoff guidance for an already-loaded run record.
// Store-backed artifact payloads are used when available for resumability and
// pull request outcome metadata; missing or unreadable optional artifacts are
// treated as unavailable.
func NewHandoffSummary(store Store, record RunRecord) HandoffSummary {
	summary := HandoffSummary{
		RunID:             strings.TrimSpace(record.RunID),
		Status:            strings.TrimSpace(record.Status),
		ExecutorMode:      strings.TrimSpace(record.ExecutorMode),
		InspectCommand:    HandoffInspectCommand(record.RunID),
		RepoPath:          strings.TrimSpace(record.RepoPath),
		BranchName:        strings.TrimSpace(record.BranchName),
		SandboxName:       handoffSandboxName(record),
		PullRequestURL:    handoffPullRequestURL(store, record),
		CurrentStep:       handoffCurrentStep(record),
		FailureReason:     handoffFailureReason(record),
		ArtifactLocations: handoffArtifactLocations(record.Artifacts, false),
		LogLocations:      handoffArtifactLocations(record.Artifacts, true),
	}

	if record.Status != RunStatusFailed {
		return summary
	}

	summary.HandoffRequired = true
	if record.ExecutorMode == ExecutorModeSandbox {
		if summary.SandboxName != "" {
			summary.SSHCommand = "hal sandbox ssh " + summary.SandboxName
			summary.NextAction = handoffNextAction(summary, handoffSandboxTakeoverActionID, NextActionTypeTakeover, summary.SSHCommand, "Open an interactive shell in the sandbox for manual takeover.")
			return summary
		}
		summary.NextAction = handoffNextAction(summary, handoffInspectActionID, NextActionTypeInspect, summary.InspectCommand, "Inspect the durable run record and timeline.")
		return summary
	}

	if handoffHasResumableAutoState(store, record) {
		summary.ResumeCommand = "hal auto --resume"
		summary.NextAction = handoffNextAction(summary, handoffResumeActionID, NextActionTypeContinue, summary.ResumeCommand, "Resume the saved auto pipeline state.")
		return summary
	}

	summary.NextAction = handoffNextAction(summary, handoffInspectActionID, NextActionTypeInspect, summary.InspectCommand, "Inspect the durable run record and timeline.")
	return summary
}

// HandoffInspectCommand returns the local, shell-safe command for inspecting a
// durable factory run record.
func HandoffInspectCommand(runID string) string {
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return ""
	}
	return fmt.Sprintf("hal factory status %s --json", runID)
}

func handoffNextAction(summary HandoffSummary, id, actionType, command, description string) *NextAction {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}
	return &NextAction{
		ID:                id,
		Type:              actionType,
		Command:           command,
		Description:       description,
		RunID:             summary.RunID,
		SandboxName:       summary.SandboxName,
		RepoPath:          summary.RepoPath,
		BranchName:        summary.BranchName,
		PullRequestURL:    summary.PullRequestURL,
		CurrentStep:       summary.CurrentStep,
		FailureReason:     summary.FailureReason,
		ArtifactLocations: summary.ArtifactLocations,
		LogLocations:      summary.LogLocations,
	}
}

func handoffSandboxName(record RunRecord) string {
	if record.Sandbox != nil {
		if name := strings.TrimSpace(record.Sandbox.Name); name != "" {
			return name
		}
	}
	return strings.TrimSpace(record.SandboxName)
}

func handoffCurrentStep(record RunRecord) string {
	if record.Failure != nil {
		if step := strings.TrimSpace(record.Failure.Step); step != "" {
			return step
		}
	}
	return strings.TrimSpace(record.CurrentStep)
}

func handoffFailureReason(record RunRecord) string {
	if record.Failure == nil {
		return ""
	}
	return strings.TrimSpace(record.Failure.Message)
}

func handoffPullRequestURL(store Store, record RunRecord) string {
	for _, artifact := range record.Artifacts {
		if pullRequestURL := handoffSafeURL(handoffArtifactSummaryString(artifact, "pullRequestUrl")); pullRequestURL != "" {
			return pullRequestURL
		}
		if pullRequestURL := handoffSafeURL(artifact.URL); pullRequestURL != "" && handoffArtifactLooksLikePR(artifact) {
			return pullRequestURL
		}
		if pullRequestURL := handoffStoredPullRequestURL(store, record.RunID, artifact); pullRequestURL != "" {
			return pullRequestURL
		}
	}
	return ""
}

func handoffStoredPullRequestURL(store Store, runID string, artifact ArtifactReference) string {
	if !handoffArtifactLooksLikePR(artifact) {
		return ""
	}
	data, ok := handoffReadStoredArtifact(store, runID, artifact)
	if !ok {
		return ""
	}
	var payload struct {
		PullRequestURL string `json:"pullRequestUrl"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return ""
	}
	return handoffSafeURL(payload.PullRequestURL)
}

func handoffArtifactSummaryString(artifact ArtifactReference, key string) string {
	if len(artifact.Summary) == 0 {
		return ""
	}
	value, ok := artifact.Summary[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func handoffHasResumableAutoState(store Store, record RunRecord) bool {
	if record.ExecutorMode != ExecutorModeLocal || record.Status != RunStatusFailed {
		return false
	}
	if record.Failure == nil || !record.Failure.Recoverable {
		return false
	}
	for _, artifact := range record.Artifacts {
		if !handoffArtifactLooksLikeAutoState(artifact) {
			continue
		}
		data, ok := handoffReadStoredArtifact(store, record.RunID, artifact)
		if !ok {
			continue
		}
		var payload struct {
			Step string `json:"step"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			continue
		}
		step := strings.TrimSpace(payload.Step)
		if step != "" && step != "done" {
			return true
		}
	}
	return false
}

func handoffReadStoredArtifact(store Store, runID string, artifact ArtifactReference) ([]byte, bool) {
	storedPath := strings.TrimSpace(artifact.StoredPath)
	if storedPath == "" {
		return nil, false
	}
	path, err := store.ResolveArtifactPath(runID, storedPath)
	if err != nil {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

func handoffArtifactLocations(artifacts []ArtifactReference, logsOnly bool) []NextActionLocation {
	locations := make([]NextActionLocation, 0, len(artifacts))
	for _, artifact := range artifacts {
		if logsOnly != handoffArtifactLooksLikeLog(artifact) {
			continue
		}
		location := NextActionLocation{
			Name:       strings.TrimSpace(artifact.Name),
			Path:       strings.TrimSpace(artifact.Path),
			StoredPath: strings.TrimSpace(artifact.StoredPath),
		}
		if location.Path == "" && location.StoredPath == "" {
			continue
		}
		locations = append(locations, location)
	}
	if len(locations) == 0 {
		return nil
	}
	return locations
}

func handoffArtifactLooksLikeLog(artifact ArtifactReference) bool {
	search := strings.ToLower(strings.Join([]string{
		artifact.Name,
		artifact.Type,
		artifact.Path,
		artifact.StoredPath,
	}, " "))
	return strings.Contains(search, "log") ||
		strings.Contains(search, "stdout") ||
		strings.Contains(search, "stderr")
}

func handoffArtifactLooksLikePR(artifact ArtifactReference) bool {
	search := strings.ToLower(strings.Join([]string{
		artifact.Name,
		artifact.Type,
		artifact.Path,
		artifact.StoredPath,
	}, " "))
	return strings.Contains(search, "pull") ||
		strings.Contains(search, "pr-outcome") ||
		strings.Contains(search, "pullrequest")
}

func handoffArtifactLooksLikeAutoState(artifact ArtifactReference) bool {
	path := filepath.ToSlash(strings.TrimSpace(artifact.Path))
	storedPath := filepath.ToSlash(strings.TrimSpace(artifact.StoredPath))
	name := strings.ToLower(strings.TrimSpace(artifact.Name))
	return path == ".hal/auto-state.json" ||
		strings.HasSuffix(path, "/.hal/auto-state.json") ||
		strings.HasSuffix(storedPath, "/auto-state.json") ||
		strings.Contains(name, "auto-state")
}

func handoffSafeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.User != nil {
		return ""
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return ""
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	return parsed.String()
}
