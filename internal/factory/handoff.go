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
		ArtifactLocations: handoffArtifactLocations(record.RunID, record.Artifacts, false),
		LogLocations:      handoffArtifactLocations(record.RunID, record.Artifacts, true),
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
	if handoffStringContainsBareSecretValue(reason) || handoffStringNeedsRedaction(handoffNormalizeDocPlaceholders(reason)) {
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

func handoffArtifactLocations(runID string, artifacts []ArtifactReference, logsOnly bool) []NextActionLocation {
	locations := make([]NextActionLocation, 0, len(artifacts))
	for _, artifact := range artifacts {
		if logsOnly != handoffArtifactLooksLikeLog(artifact) {
			continue
		}
		location := NextActionLocation{
			Name:       strings.TrimSpace(artifact.Name),
			Path:       handoffSafeArtifactPath(artifact.Path),
			StoredPath: handoffSafeStoredArtifactPath(runID, artifact.StoredPath),
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
	if handoffURLQueryContainsSecret(parsed.Query()) {
		return ""
	}
	if handoffURLFragmentContainsSecret(parsed.Fragment) {
		return ""
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

func handoffSafeStoredArtifactPath(runID, storedPath string) string {
	runID = strings.TrimSpace(runID)
	if _, err := validateRunID(runID); err != nil {
		return ""
	}
	storedPath = strings.TrimSpace(storedPath)
	if storedPath == "" {
		return ""
	}
	if filepath.IsAbs(storedPath) || strings.ContainsAny(storedPath, `\`) || handoffArtifactPathLooksLikeURL(storedPath) {
		return ""
	}
	cleanStoredPath := filepath.Clean(filepath.FromSlash(storedPath))
	runPrefix := filepath.Join(artifactsDirName, runID)
	if cleanStoredPath == "." || cleanStoredPath == runPrefix || !strings.HasPrefix(cleanStoredPath, runPrefix+string(filepath.Separator)) {
		return ""
	}
	safePath := filepath.ToSlash(cleanStoredPath)
	if handoffStoredPathContainsSecret(safePath) {
		return ""
	}
	return safePath
}

func handoffStoredPathContainsSecret(storedPath string) bool {
	for _, segment := range strings.Split(storedPath, "/") {
		if handoffStringContainsSecretAssignment(segment) ||
			handoffStringContainsSecretValueAssignment(segment) ||
			handoffURLQueryValueLooksLikeSecret(segment) {
			return true
		}
	}
	return false
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
			if handoffURLQueryContainsSecret(parsed.Query()) {
				return true
			}
			if handoffURLFragmentContainsSecret(parsed.Fragment) {
				return true
			}
		}
	}
	if handoffStringContainsSSHHost(value) {
		return true
	}
	if handoffStringContainsAbsolutePath(value) {
		return true
	}
	if handoffStringContainsSecretAssignment(value) {
		return true
	}
	if handoffStringContainsSecretValueAssignment(value) {
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

func handoffNormalizeDocPlaceholders(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '<' {
			out.WriteByte(value[i])
			i++
			continue
		}
		end := strings.IndexByte(value[i+1:], '>')
		if end < 0 {
			out.WriteByte(value[i])
			i++
			continue
		}
		token := value[i+1 : i+1+end]
		if handoffDocPlaceholderToken(token) {
			out.WriteString("placeholder")
			i += end + 2
			continue
		}
		out.WriteString(value[i : i+end+2])
		i += end + 2
	}
	return out.String()
}

func handoffDocPlaceholderToken(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	for _, r := range token {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func handoffFieldContainsIP(field string) bool {
	field = strings.TrimSpace(field)
	field = strings.Trim(field, "\"'<>[](){}.,;:")
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

func handoffStringContainsSSHHost(value string) bool {
	fields := handoffRedactionFields(value)
	for i, field := range fields {
		field = handoffTrimRedactionField(field)
		if field == "" {
			continue
		}
		if handoffSSHURLContainsHost(field) || handoffFieldIsSSHUserHost(field) {
			return true
		}
		if !strings.EqualFold(field, "ssh") {
			continue
		}
		for _, next := range fields[i+1:] {
			next = handoffTrimRedactionField(next)
			if next == "" {
				continue
			}
			if strings.HasPrefix(next, "-") {
				continue
			}
			return handoffSSHURLContainsHost(next) ||
				handoffFieldIsSSHUserHost(next) ||
				handoffFieldIsSSHBareHost(next)
		}
	}
	return false
}

func handoffSSHURLContainsHost(field string) bool {
	if !strings.Contains(field, "://") {
		return false
	}
	parsed, err := url.Parse(field)
	if err != nil || !strings.EqualFold(parsed.Scheme, "ssh") {
		return false
	}
	return handoffSSHHostLooksSensitive(parsed.Hostname())
}

func handoffFieldIsSSHUserHost(field string) bool {
	if strings.Contains(field, "://") {
		return false
	}
	at := strings.LastIndex(field, "@")
	if at <= 0 || at+1 >= len(field) {
		return false
	}
	host, ok := handoffSplitSSHHostPort(field[at+1:])
	return ok && handoffSSHHostLooksSensitive(host)
}

func handoffFieldIsSSHBareHost(field string) bool {
	host, ok := handoffSplitSSHHostPort(field)
	return ok && handoffSSHHostLooksSensitive(host)
}

func handoffSplitSSHHostPort(value string) (string, bool) {
	value = handoffTrimRedactionField(value)
	value = strings.TrimSuffix(value, ":")
	if value == "" || strings.ContainsAny(value, `/\`) {
		return "", false
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		return host, port != ""
	}
	if idx := strings.LastIndex(value, ":"); idx > 0 {
		host := value[:idx]
		port := value[idx+1:]
		if strings.Contains(host, ":") || port == "" {
			return "", false
		}
		for _, r := range port {
			if r < '0' || r > '9' {
				return "", false
			}
		}
		return host, true
	}
	return value, true
}

func handoffSSHHostLooksSensitive(host string) bool {
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	hasHostnameMarker := len(labels) > 1
	for _, label := range labels {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			isAlpha := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			isDigit := r >= '0' && r <= '9'
			if isDigit || r == '-' {
				hasHostnameMarker = true
			}
			if !isAlpha && !isDigit && r != '-' {
				return false
			}
		}
	}
	return hasHostnameMarker
}

func handoffTrimRedactionField(field string) string {
	field = strings.TrimSpace(field)
	return strings.Trim(field, "\"'<>[](){}.,;")
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

func handoffStringContainsSecretValueAssignment(value string) bool {
	for _, field := range handoffRedactionFields(value) {
		field = strings.TrimSpace(field)
		field = strings.Trim(field, "\"'<>[](){}.,;")
		if field == "" {
			continue
		}
		for _, sep := range []string{"=", ":"} {
			if idx := strings.Index(field, sep); idx > 0 && idx+1 < len(field) {
				if handoffURLQueryValueLooksLikeSecret(field[idx+1:]) {
					return true
				}
			}
		}
	}
	return false
}

func handoffStringContainsBareSecretValue(value string) bool {
	fields := handoffRedactionFields(value)
	for i, field := range fields {
		field = strings.TrimSpace(field)
		field = strings.Trim(field, "\"'<>[](){}.,;")
		if !handoffStandaloneSecretKey(field) || i+1 >= len(fields) {
			continue
		}
		if handoffFieldLooksLikeSecretValue(fields[i+1]) {
			return true
		}
	}
	return false
}

func handoffStandaloneSecretKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.Trim(key, "\"'<>[](){}.,;")
	switch key {
	case "token", "secret", "password", "passwd", "credential", "credentials", "auth", "authorization", "key",
		"api_key", "api-key", "apikey", "access_key", "access-key", "accesskey", "private_key", "private-key", "privatekey":
		return true
	default:
		return false
	}
}

func handoffFieldLooksLikeSecretValue(value string) bool {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "\"'<>[](){}.,;")
	if value == "" {
		return false
	}
	if handoffFieldHasSecretPrefix(value) {
		return true
	}
	if len(value) >= 6 && strings.ContainsAny(value, "_-./+=") {
		return true
	}
	if len(value) >= 6 {
		for _, r := range value {
			if r >= '0' && r <= '9' {
				return true
			}
		}
	}
	return len(value) >= 16 && handoffFieldLooksLikeTokenChars(value)
}

func handoffURLQueryContainsSecret(query url.Values) bool {
	for key, values := range query {
		if handoffSecretKey(key) {
			return true
		}
		for _, value := range values {
			if handoffURLQueryValueLooksLikeSecret(value) {
				return true
			}
		}
	}
	return false
}

func handoffURLFragmentContainsSecret(fragment string) bool {
	fragment = strings.TrimSpace(fragment)
	if fragment == "" {
		return false
	}
	if query, err := url.ParseQuery(fragment); err == nil && handoffURLQueryContainsSecret(query) {
		return true
	}
	if unescaped, err := url.QueryUnescape(fragment); err == nil {
		fragment = unescaped
	}
	return handoffStringContainsSecretAssignment(fragment) ||
		handoffStringContainsSecretValueAssignment(fragment) ||
		handoffStringContainsBareSecretValue(fragment) ||
		handoffURLQueryValueLooksLikeSecret(fragment)
}

func handoffURLQueryValueLooksLikeSecret(value string) bool {
	for _, field := range handoffRedactionFields(value) {
		field = strings.TrimSpace(field)
		field = strings.Trim(field, "\"'<>[](){}.,;")
		if field == "" {
			continue
		}
		if handoffFieldHasSecretPrefix(field) {
			return true
		}
		if len(field) >= 20 && handoffFieldLooksLikeTokenChars(field) {
			return true
		}
	}
	return false
}

func handoffFieldHasSecretPrefix(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	knownPrefixes := []string{
		"ghp_",
		"github_pat_",
		"gho_",
		"ghu_",
		"ghs_",
		"ghr_",
		"sk-",
		"xoxb-",
		"xoxp-",
	}
	for _, prefix := range knownPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func handoffFieldLooksLikeTokenChars(value string) bool {
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
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
