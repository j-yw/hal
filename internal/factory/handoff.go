package factory

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
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

// HasActionableData reports whether the summary should be emitted on optional
// machine-readable handoff surfaces.
func (summary HandoffSummary) HasActionableData() bool {
	return summary.HandoffRequired ||
		summary.NextAction != nil ||
		strings.TrimSpace(summary.ResumeCommand) != "" ||
		strings.TrimSpace(summary.SSHCommand) != ""
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
		if summary.SandboxName != "" && handoffSandboxIsRunning(record) {
			summary.SSHCommand = "hal sandbox ssh " + summary.SandboxName
			summary.NextAction = handoffNextAction(summary, handoffSandboxTakeoverActionID, NextActionTypeTakeover, summary.SSHCommand, "Open an interactive shell in the sandbox for manual takeover.")
			return summary
		}
		summary.NextAction = handoffNextAction(summary, handoffInspectActionID, NextActionTypeInspect, summary.InspectCommand, "Inspect the durable run record and timeline.")
		return summary
	}

	if handoffHasResumableAutoState(store, record) && summary.RepoPath != "" {
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
	if _, err := validateRunID(runID); err != nil {
		return ""
	}
	if !handoffSafeCommandToken(runID) {
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
		if name := handoffSafeSandboxName(record.Sandbox.Name); name != "" {
			return name
		}
	}
	return handoffSafeSandboxName(record.SandboxName)
}

func handoffSandboxIsRunning(record RunRecord) bool {
	return record.Sandbox != nil && strings.TrimSpace(record.Sandbox.Status) == sandbox.StatusRunning
}

func handoffSafeSandboxName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if err := sandbox.ValidateName(name); err != nil {
		return ""
	}
	return name
}

func handoffSafeCommandToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		isSafePunctuation := c == '-' || c == '_' || c == '.'
		if !isAlpha && !isDigit && !isSafePunctuation {
			return false
		}
	}
	return true
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
	return SanitizeHandoffFailureReason(record.Failure.Message)
}

// SanitizeHandoffFailureReason returns failure text that is safe to include in
// durable handoff and next-action surfaces.
func SanitizeHandoffFailureReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ""
	}
	if handoffStringNeedsRedaction(reason) {
		return handoffRedactedLocation
	}
	return reason
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
			Path:       handoffSafeArtifactPath(artifact.Path),
			StoredPath: strings.TrimSpace(artifact.StoredPath),
		}
		if location.Path == handoffRedactedLocation && location.StoredPath != "" {
			location.Path = ""
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
	for key := range parsed.Query() {
		if handoffSecretKey(key) {
			return ""
		}
	}
	return parsed.String()
}

const handoffRedactedLocation = "[redacted]"

func handoffSafeArtifactPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if handoffArtifactPathLooksLikeURL(path) {
		return handoffRedactedLocation
	}
	cleanPath := filepath.Clean(path)
	if handoffArtifactLooksLikeWindowsAbsolutePath(path) || handoffArtifactLooksLikeWindowsAbsolutePath(cleanPath) {
		return handoffRedactedLocation
	}
	if filepath.IsAbs(cleanPath) {
		base := filepath.Base(cleanPath)
		if base == "" || base == "." || base == string(os.PathSeparator) {
			return handoffRedactedLocation
		}
		return filepath.ToSlash(base)
	}
	if handoffArtifactPathIsParentRelative(cleanPath) {
		return handoffRedactedLocation
	}
	return filepath.ToSlash(cleanPath)
}

func handoffArtifactPathLooksLikeURL(path string) bool {
	parsed, err := url.Parse(path)
	if err != nil {
		return true
	}
	return parsed.Scheme != "" || parsed.Host != ""
}

func handoffArtifactPathIsParentRelative(path string) bool {
	path = filepath.ToSlash(path)
	if path == ".." || strings.HasPrefix(path, "../") {
		return true
	}
	windowsPath := strings.ReplaceAll(path, `\`, "/")
	return windowsPath == ".." || strings.HasPrefix(windowsPath, "../")
}

func handoffArtifactLooksLikeWindowsAbsolutePath(value string) bool {
	if len(value) >= 3 {
		drive := value[0]
		if ((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) && value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
			return true
		}
	}
	return strings.HasPrefix(value, `\\`) || strings.HasPrefix(value, `//`)
}

func handoffStringNeedsRedaction(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if net.ParseIP(strings.Trim(value, "[]")) != nil {
		return true
	}
	if host, _, err := net.SplitHostPort(value); err == nil && net.ParseIP(strings.Trim(host, "[]")) != nil {
		return true
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err == nil {
			if parsed.User != nil {
				return true
			}
			if host := strings.TrimSpace(parsed.Hostname()); host != "" && net.ParseIP(host) != nil {
				return true
			}
			for key := range parsed.Query() {
				if handoffSecretKey(key) {
					return true
				}
			}
		}
	}
	if handoffStringContainsAbsolutePath(value) {
		return true
	}
	if handoffStringContainsSecretAssignment(value) {
		return true
	}
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '/' || r == ',' || r == ';' || r == '=' || r == '(' || r == ')' || r == '[' || r == ']'
	})
	for _, field := range fields {
		if handoffFieldContainsIP(field) {
			return true
		}
	}
	return false
}

func handoffFieldContainsIP(field string) bool {
	field = strings.TrimSpace(field)
	field = strings.Trim(field, "\"'<>[](){}.,;")
	if field == "" {
		return false
	}
	if net.ParseIP(strings.Trim(field, "[]")) != nil {
		return true
	}
	if host, _, err := net.SplitHostPort(field); err == nil && net.ParseIP(strings.Trim(host, "[]")) != nil {
		return true
	}
	if idx := strings.LastIndex(field, ":"); idx > 0 {
		host := field[:idx]
		if strings.Count(host, ":") == 0 && net.ParseIP(strings.Trim(host, "[]")) != nil {
			return true
		}
	}
	return false
}

func handoffStringContainsAbsolutePath(value string) bool {
	for _, field := range handoffRedactionFields(value) {
		if handoffFieldIsAbsolutePath(field) {
			return true
		}
		if strings.Contains(field, "://") {
			continue
		}
		for _, sep := range []string{"=", ":"} {
			if idx := strings.Index(field, sep); idx >= 0 && idx+1 < len(field) {
				if handoffFieldIsAbsolutePath(field[idx+1:]) {
					return true
				}
			}
		}
	}
	return false
}

func handoffFieldIsAbsolutePath(value string) bool {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "\"'<>[](){}.,;")
	if value == "" {
		return false
	}
	if filepath.IsAbs(value) {
		return true
	}
	return handoffArtifactLooksLikeWindowsAbsolutePath(value)
}

func handoffStringContainsSecretAssignment(value string) bool {
	fields := handoffRedactionFields(value)
	for i, field := range fields {
		field = strings.TrimSpace(field)
		field = strings.Trim(field, "\"'<>[](){}.,;")
		if field == "" {
			continue
		}
		if idx := strings.IndexAny(field, "=:"); idx > 0 && handoffSecretKey(field[:idx]) {
			return true
		}
		if !handoffSecretKey(field) || i+1 >= len(fields) {
			continue
		}
		next := strings.TrimSpace(fields[i+1])
		if next == "=" || next == ":" || strings.HasPrefix(next, "=") || strings.HasPrefix(next, ":") {
			return true
		}
	}
	return false
}

func handoffRedactionFields(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ',', ';', '"', '\'', '<', '>', '(', ')', '[', ']', '{', '}', '?', '&':
			return true
		default:
			return false
		}
	})
}

func handoffSecretKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return false
	}
	secretFragments := []string{
		"token",
		"secret",
		"password",
		"passwd",
		"credential",
		"private_key",
		"private-key",
		"api_key",
		"api-key",
		"access_key",
		"access-key",
		"auth",
	}
	for _, fragment := range secretFragments {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return key == "key" || strings.HasSuffix(key, "_key") || strings.HasSuffix(key, "-key")
}
