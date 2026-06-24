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
		RepoPath:          handoffSafeRepoPath(record.RepoPath),
		BranchName:        handoffSafeDisplayValue(record.BranchName),
		SandboxName:       handoffSandboxName(record),
		PullRequestURL:    handoffPullRequestURL(store, record),
		CurrentStep:       handoffSafeDisplayValue(handoffCurrentStep(record)),
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

func handoffSafeRepoPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || strings.ContainsAny(path, "\r\n") {
		return ""
	}
	if handoffRepoPathLooksLikeURL(path) || strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
		return ""
	}
	cleanPath := filepath.Clean(path)
	if handoffRepoPathNeedsRedaction(cleanPath) {
		return ""
	}
	return cleanPath
}

func handoffRepoPathLooksLikeURL(path string) bool {
	parsed, err := url.Parse(path)
	if err != nil {
		return true
	}
	if parsed.Host != "" {
		return true
	}
	if parsed.Scheme == "" {
		return false
	}
	return !handoffRepoPathLooksLikeWindowsDrive(path)
}

func handoffRepoPathLooksLikeWindowsDrive(path string) bool {
	if len(path) < 3 || path[1] != ':' {
		return false
	}
	drive := path[0]
	isDrive := (drive >= 'a' && drive <= 'z') || (drive >= 'A' && drive <= 'Z')
	return isDrive && (path[2] == '\\' || path[2] == '/')
}

func handoffRepoPathNeedsRedaction(path string) bool {
	safePath := filepath.ToSlash(strings.ReplaceAll(path, `\`, "/"))
	if handoffArtifactDisplayPathNeedsRedaction(safePath) {
		return true
	}
	segments := strings.FieldsFunc(safePath, func(r rune) bool {
		return r == '/'
	})
	for i, segment := range segments {
		segment = handoffTrimRedactionField(segment)
		if segment == "" || segment == "." {
			continue
		}
		if handoffFieldHasSecretPrefix(segment) || handoffURLQueryValueLooksLikeSecret(segment) {
			return true
		}
		if handoffStandaloneSecretKey(segment) && i+1 < len(segments) && handoffFieldLooksLikeSecretValue(segments[i+1]) {
			return true
		}
	}
	return false
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

func handoffSafeDisplayValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	normalizedValue := handoffNormalizeDocPlaceholders(value)
	if strings.ContainsAny(value, "\r\n") ||
		handoffStringContainsBareSecretValue(value) ||
		handoffStringNeedsRedaction(normalizedValue) ||
		handoffDisplayValueContainsBareDNSHost(normalizedValue) {
		return handoffRedactedLocation
	}
	return value
}

func handoffDisplayValueContainsBareDNSHost(value string) bool {
	if handoffStringContainsBareDNSHost(value) {
		return true
	}
	for _, field := range handoffRedactionFields(value) {
		for _, segment := range strings.FieldsFunc(field, func(r rune) bool {
			return r == '/' || r == '\\'
		}) {
			if handoffFieldContainsBareDNSHost(segment) {
				return true
			}
		}
	}
	return false
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
	normalizedReason := handoffNormalizeDocPlaceholders(reason)
	if strings.ContainsAny(reason, "\r\n") ||
		handoffStringContainsBareSecretValue(reason) ||
		handoffStringNeedsRedaction(normalizedReason) ||
		handoffStringContainsBareDNSHost(normalizedReason) {
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
			Name:       handoffSafeLocationName(artifact.Name, logsOnly),
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

func handoffSafeLocationName(name string, logLocation bool) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if handoffLocationNameNeedsRedaction(name) {
		if logLocation {
			return "log"
		}
		return "artifact"
	}
	return name
}

func handoffLocationNameNeedsRedaction(name string) bool {
	if strings.ContainsAny(name, "\r\n") {
		return true
	}
	if handoffStringContainsURLHost(name) {
		return true
	}
	return handoffStringContainsBareSecretValue(name) ||
		handoffStringNeedsRedaction(handoffNormalizeDocPlaceholders(name))
}

func handoffStringContainsURLHost(value string) bool {
	for _, field := range handoffRedactionFields(value) {
		parsed, err := url.Parse(handoffTrimRedactionField(field))
		if err != nil {
			continue
		}
		if parsed.Scheme != "" && parsed.Host != "" {
			if handoffURLIsDocumentationPlaceholder(parsed) {
				continue
			}
			return true
		}
	}
	return false
}

func handoffURLIsDocumentationPlaceholder(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	if !strings.EqualFold(parsed.Hostname(), "github.com") {
		return false
	}
	path := strings.Trim(filepath.ToSlash(parsed.EscapedPath()), "/")
	return path == "placeholder/placeholder" || path == "placeholder/placeholder.git"
}

func handoffArtifactLooksLikeLog(artifact ArtifactReference) bool {
	for _, value := range []string{
		artifact.Name,
		artifact.Type,
		artifact.Path,
		artifact.StoredPath,
	} {
		if handoffArtifactHasLogToken(value) {
			return true
		}
	}
	return false
}

func handoffArtifactHasLogToken(value string) bool {
	for _, token := range strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		switch token {
		case "log", "logs", "stdout", "stderr":
			return true
		}
	}
	return false
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
	path := filepath.ToSlash(filepath.Clean(strings.TrimSpace(artifact.Path)))
	return path == ".hal/auto-state.json"
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
	if handoffBareDNSHostLooksSensitive(host, parsed.Port() != "") {
		return ""
	}
	if handoffURLRawQueryContainsSecret(parsed.RawQuery) {
		return ""
	}
	if handoffURLFragmentContainsSecret(parsed.Fragment) {
		return ""
	}
	if handoffURLPathContainsSecret(parsed) {
		return ""
	}
	return parsed.String()
}

func handoffURLPathContainsSecret(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	for _, candidate := range []string{parsed.EscapedPath(), parsed.RawPath, parsed.Path} {
		if handoffURLPathStringContainsSecret(candidate) {
			return true
		}
		if unescaped, err := url.PathUnescape(candidate); err == nil && unescaped != candidate {
			if handoffURLPathStringContainsSecret(unescaped) {
				return true
			}
		}
	}
	return false
}

func handoffURLPathStringContainsSecret(path string) bool {
	path = strings.TrimSpace(strings.ReplaceAll(path, "\\", "/"))
	if path == "" {
		return false
	}
	if handoffStringContainsSecretAssignment(path) ||
		handoffStringContainsSecretValueAssignment(path) ||
		handoffStringContainsBareSecretValue(path) ||
		handoffPathStringNeedsRedaction(path) {
		return true
	}
	segments := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/'
	})
	for i, segment := range segments {
		segment = handoffTrimRedactionField(segment)
		if segment == "" {
			continue
		}
		if handoffStringContainsSecretAssignment(segment) ||
			handoffStringContainsSecretValueAssignment(segment) ||
			handoffPathStringNeedsRedaction(segment) {
			return true
		}
		if handoffStandaloneSecretKey(segment) && i+1 < len(segments) && handoffFieldLooksLikeSecretValue(segments[i+1]) {
			return true
		}
	}
	return false
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
		safePath := filepath.ToSlash(base)
		if handoffArtifactDisplayPathNeedsRedaction(safePath) {
			return handoffRedactedLocation
		}
		return safePath
	}
	if handoffArtifactPathIsParentRelative(cleanPath) {
		return handoffRedactedLocation
	}
	safePath := filepath.ToSlash(cleanPath)
	if handoffArtifactDisplayPathNeedsRedaction(safePath) {
		return handoffRedactedLocation
	}
	return safePath
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

func handoffArtifactDisplayPathNeedsRedaction(path string) bool {
	path = strings.TrimSpace(filepath.ToSlash(path))
	if path == "" {
		return false
	}
	if handoffStoredPathContainsSecret(path) {
		return true
	}
	for _, segment := range strings.Split(path, "/") {
		segment = strings.TrimSpace(segment)
		if segment == "" || segment == "." {
			continue
		}
		if handoffStringNeedsRedaction(segment) {
			return true
		}
	}
	return false
}

func handoffStoredPathContainsSecret(storedPath string) bool {
	for _, segment := range strings.Split(storedPath, "/") {
		if handoffStringContainsSecretAssignment(segment) ||
			handoffStringContainsSecretValueAssignment(segment) ||
			handoffPathStringNeedsRedaction(segment) {
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
	if handoffURLQueryValueLooksLikeSecret(value) {
		return true
	}
	if host, _, err := net.SplitHostPort(value); err == nil && net.ParseIP(strings.Trim(host, "[]")) != nil {
		return true
	}
	if handoffStringContainsURLHost(value) {
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
			if handoffURLRawQueryContainsSecret(parsed.RawQuery) {
				return true
			}
			if handoffURLFragmentContainsSecret(parsed.Fragment) {
				return true
			}
			if handoffURLContainsAbsoluteLocalPath(parsed) {
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
	if handoffStringContainsIP(value) {
		return true
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
	if at := strings.LastIndexByte(field, '@'); at >= 0 && at+1 < len(field) {
		if handoffFieldContainsIP(field[at+1:]) {
			return true
		}
	}
	candidates := []string{field}
	if base := handoffStripFilenameSuffix(field); base != field {
		candidates = append(candidates, base)
	}
	for _, candidate := range candidates {
		if net.ParseIP(strings.Trim(candidate, "[]")) != nil {
			return true
		}
		if host, _, err := net.SplitHostPort(candidate); err == nil && net.ParseIP(strings.Trim(host, "[]")) != nil {
			return true
		}
		if idx := strings.LastIndex(candidate, ":"); idx > 0 {
			host := candidate[:idx]
			if strings.Count(host, ":") == 0 && net.ParseIP(strings.Trim(host, "[]")) != nil {
				return true
			}
		}
	}
	return false
}

func handoffStripFilenameSuffix(value string) string {
	idx := strings.LastIndexByte(value, '.')
	if idx <= 0 || idx+1 >= len(value) {
		return value
	}
	suffix := value[idx+1:]
	for _, r := range suffix {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			continue
		}
		return value
	}
	return value[:idx]
}

func handoffStringContainsIP(value string) bool {
	for _, field := range handoffRedactionFields(value) {
		field = handoffTrimRedactionField(field)
		if field == "" {
			continue
		}
		if handoffFieldContainsIP(field) {
			return true
		}
		for _, segment := range strings.FieldsFunc(field, func(r rune) bool {
			return r == '/' || r == '\\' || r == '#' || r == '='
		}) {
			if handoffFieldContainsIP(segment) {
				return true
			}
		}
	}
	return false
}

func handoffStringContainsBareDNSHost(value string) bool {
	for _, field := range handoffRedactionFields(value) {
		field = handoffTrimRedactionField(field)
		if field == "" || strings.Contains(field, "://") {
			continue
		}
		if handoffFieldContainsBareDNSHost(field) {
			return true
		}
		for _, segment := range strings.FieldsFunc(field, func(r rune) bool {
			return r == '/' || r == '\\'
		}) {
			if handoffFieldContainsBareDNSHost(segment) {
				return true
			}
		}
	}
	return false
}

func handoffFieldContainsBareDNSHost(field string) bool {
	field = strings.TrimSpace(field)
	field = strings.Trim(field, "\"'<>[](){}.,;:")
	if field == "" || strings.ContainsAny(field, `/\@`) {
		return false
	}
	if idx := strings.LastIndexByte(field, '='); idx >= 0 && idx+1 < len(field) {
		field = strings.TrimSpace(field[idx+1:])
	}
	if host, _, err := net.SplitHostPort(field); err == nil {
		return handoffBareDNSHostLooksSensitive(host, true)
	}
	if idx := strings.LastIndexByte(field, ':'); idx > 0 {
		host := field[:idx]
		port := field[idx+1:]
		if strings.Contains(host, ":") || !handoffStringIsDecimalPort(port) {
			return false
		}
		return handoffBareDNSHostLooksSensitive(host, true)
	}
	return handoffBareDNSHostLooksSensitive(field, false)
}

func handoffStringIsDecimalPort(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func handoffBareDNSHostLooksSensitive(host string, hasPort bool) bool {
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil || strings.ContainsAny(host, `:/\@_`) {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			isAlpha := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			isDigit := r >= '0' && r <= '9'
			if !isAlpha && !isDigit && r != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 || !handoffStringContainsAlpha(tld) {
		return false
	}
	if hasPort || len(labels) >= 3 {
		return true
	}
	for _, label := range labels {
		switch strings.ToLower(label) {
		case "internal", "intranet", "corp", "corporate", "local", "localhost", "lan", "tailnet":
			return true
		}
	}
	return false
}

func handoffStringContainsAlpha(value string) bool {
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
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
			if handoffURLFieldContainsAbsoluteLocalPath(field) {
				return true
			}
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

func handoffURLFieldContainsAbsoluteLocalPath(field string) bool {
	parsed, err := url.Parse(handoffTrimRedactionField(field))
	if err != nil {
		return false
	}
	return handoffURLContainsAbsoluteLocalPath(parsed)
}

func handoffURLContainsAbsoluteLocalPath(parsed *url.URL) bool {
	if parsed == nil || strings.ToLower(parsed.Scheme) != "file" {
		return false
	}
	return handoffFieldIsAbsolutePath(parsed.Path) || handoffFieldIsAbsolutePath(parsed.Opaque)
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
			if handoffSSHURLContainsHost(next) ||
				handoffFieldIsSSHUserHost(next) ||
				handoffFieldIsSSHBareHost(next) {
				return true
			}
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
	target := field[at+1:]
	if host, path, ok := handoffSplitSCPStyleSSHHost(target); ok {
		if handoffSCPStyleDocumentationPlaceholder(host, path) {
			return false
		}
		return handoffSSHHostLooksSensitive(host)
	}
	host, ok := handoffSplitSSHHostPort(target)
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

func handoffSplitSCPStyleSSHHost(value string) (string, string, bool) {
	value = handoffTrimRedactionField(value)
	idx := strings.IndexByte(value, ':')
	if idx <= 0 || idx+1 >= len(value) {
		return "", "", false
	}
	host := value[:idx]
	path := value[idx+1:]
	if strings.Contains(host, ":") || strings.ContainsAny(host, `/\`) || handoffStringIsDecimalPort(path) {
		return "", "", false
	}
	return host, path, true
}

func handoffSCPStyleDocumentationPlaceholder(host, path string) bool {
	if !strings.EqualFold(strings.TrimSpace(host), "github.com") {
		return false
	}
	path = strings.Trim(strings.TrimSpace(filepath.ToSlash(path)), "/")
	return path == "placeholder/placeholder" || path == "placeholder/placeholder.git"
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
	for _, label := range labels {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			isAlpha := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			isDigit := r >= '0' && r <= '9'
			if !isAlpha && !isDigit && r != '-' {
				return false
			}
		}
	}
	return true
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
		next := i + 1
		if handoffFieldIsAuthScheme(fields[next]) && next+1 < len(fields) {
			next++
		}
		if handoffFieldLooksLikeSecretValue(fields[next]) {
			return true
		}
	}
	return false
}

func handoffFieldIsAuthScheme(value string) bool {
	value = strings.ToLower(handoffTrimRedactionField(value))
	switch value {
	case "bearer", "basic":
		return true
	default:
		return false
	}
}

func handoffStandaloneSecretKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.Trim(key, "\"'<>[](){}.,;")
	key = strings.TrimLeft(key, "-")
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

func handoffURLRawQueryContainsSecret(rawQuery string) bool {
	rawQuery = strings.TrimSpace(rawQuery)
	if rawQuery == "" {
		return false
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return true
	}
	return handoffURLQueryContainsSecret(query)
}

func handoffURLQueryContainsSecret(query url.Values) bool {
	for key, values := range query {
		if handoffSecretKey(key) {
			return true
		}
		for _, value := range values {
			if handoffURLQueryValueNeedsRedaction(value) {
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
	if query, err := url.ParseQuery(fragment); err == nil {
		if handoffURLQueryContainsSecret(query) {
			return true
		}
	} else {
		return true
	}
	if unescaped, err := url.QueryUnescape(fragment); err == nil {
		fragment = unescaped
	}
	return handoffStringContainsSecretAssignment(fragment) ||
		handoffStringContainsSecretValueAssignment(fragment) ||
		handoffStringContainsBareSecretValue(fragment) ||
		handoffURLQueryValueNeedsRedaction(fragment)
}

func handoffPathStringNeedsRedaction(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	normalizedValue := handoffNormalizeDocPlaceholders(value)
	return handoffURLQueryValueLooksLikeSecret(value) ||
		handoffStringContainsSecretAssignment(value) ||
		handoffStringContainsSecretValueAssignment(value) ||
		handoffStringContainsBareSecretValue(value) ||
		handoffStringContainsIP(normalizedValue) ||
		handoffStringContainsSSHHost(normalizedValue) ||
		handoffDisplayValueContainsBareDNSHost(normalizedValue)
}

func handoffURLQueryValueNeedsRedaction(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	normalizedValue := handoffNormalizeDocPlaceholders(value)
	return handoffURLQueryValueLooksLikeSecret(value) ||
		handoffStringContainsSecretAssignment(value) ||
		handoffStringContainsSecretValueAssignment(value) ||
		handoffStringContainsBareSecretValue(value) ||
		handoffStringContainsIP(normalizedValue) ||
		handoffStringContainsSSHHost(normalizedValue) ||
		handoffStringContainsAbsolutePath(normalizedValue) ||
		handoffStringContainsURLHost(normalizedValue) ||
		handoffDisplayValueContainsBareDNSHost(normalizedValue)
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
