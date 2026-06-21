// Package factory defines durable factory run records, timeline events, and bootstrap contracts.
package factory

import (
	"fmt"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/verify"
)

// Run status values.
const (
	RunStatusPending   = "pending"
	RunStatusRunning   = "running"
	RunStatusSucceeded = "succeeded"
	RunStatusFailed    = "failed"
	RunStatusCanceled  = "canceled"
)

// Executor mode values.
const (
	ExecutorModeLocal   = "local"
	ExecutorModeSandbox = "sandbox"
)

// SupportedExecutorModes returns the executor modes implemented by the factory
// executor layer.
func SupportedExecutorModes() []string {
	return []string{ExecutorModeLocal, ExecutorModeSandbox}
}

// ValidateExecutorMode normalizes and validates a factory executor mode.
func ValidateExecutorMode(executorMode string) (string, error) {
	trimmedExecutorMode := strings.TrimSpace(executorMode)
	if trimmedExecutorMode == "" {
		return "", fmt.Errorf("factory executor mode is required")
	}
	if executorMode != trimmedExecutorMode {
		return "", fmt.Errorf("factory executor mode %q is invalid", executorMode)
	}

	for _, supported := range SupportedExecutorModes() {
		if trimmedExecutorMode == supported {
			return trimmedExecutorMode, nil
		}
	}

	return "", fmt.Errorf("unsupported factory executor mode %q (supported: %s)", trimmedExecutorMode, strings.Join(SupportedExecutorModes(), ", "))
}

// Queue status values.
const (
	QueueStatusQueued    = "queued"
	QueueStatusClaimed   = "claimed"
	QueueStatusSucceeded = "succeeded"
	QueueStatusFailed    = "failed"
)

// Run source kind values.
const (
	SourceKindAutoDiscovery = "auto_discovery"
	SourceKindMarkdown      = "markdown"
	SourceKindReport        = "report"
	SourceKindPRD           = "prd"
)

// Failure category values.
const (
	FailureCategorySetup        = "setup"
	FailureCategoryEngine       = "engine"
	FailureCategoryPRD          = "PRD"
	FailureCategoryRun          = "run"
	FailureCategoryReview       = "review"
	FailureCategoryVerification = "verification"
	FailureCategoryCI           = "CI"
	FailureCategorySandbox      = "sandbox"
	FailureCategoryQueue        = "queue"
	FailureCategoryUnknown      = "unknown"
)

// SupportedFailureCategories returns the stable failure category contract in
// display order.
func SupportedFailureCategories() []string {
	return []string{
		FailureCategorySetup,
		FailureCategoryEngine,
		FailureCategoryPRD,
		FailureCategoryRun,
		FailureCategoryReview,
		FailureCategoryVerification,
		FailureCategoryCI,
		FailureCategorySandbox,
		FailureCategoryQueue,
		FailureCategoryUnknown,
	}
}

// NormalizeFailureCategory resolves missing or unsupported categories to the
// stable unknown category.
func NormalizeFailureCategory(category string) string {
	trimmedCategory := strings.TrimSpace(category)
	for _, supportedCategory := range SupportedFailureCategories() {
		if trimmedCategory == supportedCategory {
			return trimmedCategory
		}
	}
	return FailureCategoryUnknown
}

// Timeline event type values.
const (
	EventTypeRunCreated            = "run_created"
	EventTypeStepStarted           = "step_started"
	EventTypeStepEnded             = "step_ended"
	EventTypeCommandOutputSummary  = "command_output_summary"
	EventTypeVerificationResult    = "verification_result"
	EventTypeCIState               = "ci_state"
	EventTypeArtifactSync          = "artifact_sync"
	EventTypeFailureClassification = "failure_classification"
)

// Log stream values.
const (
	LogStreamStdout  = "stdout"
	LogStreamStderr  = "stderr"
	LogStreamSummary = "summary"
)

// Log source values.
const (
	LogSourceLocalFactory  = "local_factory"
	LogSourceRemoteSandbox = "remote_sandbox"
	LogSourceEngine        = "engine"
)

// Run duration step values. These are the only lifecycle step names used for
// derived per-step duration telemetry.
const (
	RunDurationStepSetup            = "setup"
	RunDurationStepQueueClaim       = "queue_claim"
	RunDurationStepSandboxProvision = "sandbox_provision"
	RunDurationStepSandboxStart     = "sandbox_start"
	RunDurationStepEngineRun        = "engine_run"
	RunDurationStepReview           = "review"
	RunDurationStepVerification     = "verification"
	RunDurationStepCI               = "ci"
	RunDurationStepArtifactCollect  = "artifact_collection"
	RunDurationStepFinalization     = "finalization"
)

// SupportedRunDurationSteps returns the stable step names that can produce
// derived per-step duration telemetry.
func SupportedRunDurationSteps() []string {
	return []string{
		RunDurationStepSetup,
		RunDurationStepQueueClaim,
		RunDurationStepSandboxProvision,
		RunDurationStepSandboxStart,
		RunDurationStepEngineRun,
		RunDurationStepReview,
		RunDurationStepVerification,
		RunDurationStepCI,
		RunDurationStepArtifactCollect,
		RunDurationStepFinalization,
	}
}

// RunRecord captures persisted state for one factory run.
type RunRecord struct {
	RunID        string              `json:"runId"`
	Status       string              `json:"status"`
	ExecutorMode string              `json:"executorMode"`
	Source       SourceMetadata      `json:"source"`
	RepoPath     string              `json:"repoPath"`
	RepoRemote   string              `json:"repoRemote"`
	BranchName   string              `json:"branchName"`
	BaseBranch   string              `json:"baseBranch"`
	SandboxName  string              `json:"sandboxName,omitempty"`
	Sandbox      *SandboxMetadata    `json:"sandbox,omitempty"`
	CurrentStep  string              `json:"currentStep"`
	CreatedAt    time.Time           `json:"createdAt"`
	UpdatedAt    time.Time           `json:"updatedAt"`
	FinishedAt   *time.Time          `json:"finishedAt,omitempty"`
	Artifacts    []ArtifactReference `json:"artifacts,omitempty"`
	Verification *VerificationRecord `json:"verification,omitempty"`
	Telemetry    *RunTelemetry       `json:"telemetry,omitempty"`
	Failure      *FailureSummary     `json:"failure,omitempty"`
}

// SandboxMetadata captures redaction-safe remote execution details for a
// sandbox-backed factory run.
type SandboxMetadata struct {
	Name           string                     `json:"name"`
	Provider       string                     `json:"provider"`
	Size           string                     `json:"size,omitempty"`
	Status         string                     `json:"status"`
	Connection     *SandboxConnectionMetadata `json:"connection,omitempty"`
	SSHCommand     string                     `json:"sshCommand,omitempty"`
	CleanupCommand string                     `json:"cleanupCommand,omitempty"`
	Handoff        string                     `json:"handoff,omitempty"`
}

// SandboxConnectionMetadata contains safe connection display fields. It must
// not grow credentials, private keys, tokens, or raw environment values.
type SandboxConnectionMetadata struct {
	Address           string `json:"address,omitempty"`
	PublicIP          string `json:"publicIp,omitempty"`
	TailscaleIP       string `json:"tailscaleIp,omitempty"`
	TailscaleHostname string `json:"tailscaleHostname,omitempty"`
	TailscaleLockdown bool   `json:"tailscaleLockdown,omitempty"`
}

// SourceMetadata identifies the input that started a factory run.
type SourceMetadata struct {
	Kind       string `json:"kind"`
	Path       string `json:"path,omitempty"`
	ReportPath string `json:"reportPath,omitempty"`
	Title      string `json:"title,omitempty"`
}

// ArtifactReference references an artifact produced or consumed by a factory run.
type ArtifactReference struct {
	ID         string         `json:"id,omitempty"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	SourcePath string         `json:"sourcePath,omitempty"`
	StoredPath string         `json:"storedPath,omitempty"`
	Path       string         `json:"path,omitempty"`
	URL        string         `json:"url,omitempty"`
	SizeBytes  *int64         `json:"sizeBytes,omitempty"`
	CreatedAt  *time.Time     `json:"createdAt,omitempty"`
	Summary    map[string]any `json:"summary,omitempty"`
	Warnings   []string       `json:"warnings,omitempty"`
	Partial    bool           `json:"partial,omitempty"`
}

// VerificationRecord captures verification metadata associated with a run.
type VerificationRecord struct {
	Summary   verify.Summary             `json:"summary"`
	Artifacts []verify.ArtifactReference `json:"artifacts,omitempty"`
}

// RunTelemetry captures optional observability fields for factory run summaries.
// Population is best-effort and additive so older records can omit it entirely.
type RunTelemetry struct {
	TotalDurationMs      *int64               `json:"totalDurationMs,omitempty"`
	StepDurations        []RunStepDuration    `json:"stepDurations,omitempty"`
	Engine               *EngineTelemetry     `json:"engine,omitempty"`
	Sandbox              *RunSandboxTelemetry `json:"sandbox,omitempty"`
	EstimatedSandboxCost *SandboxCostEstimate `json:"estimatedSandboxCost,omitempty"`
	CIOutcome            string               `json:"ciOutcome,omitempty"`
	VerificationOutcome  string               `json:"verificationOutcome,omitempty"`
	ArtifactCount        *int                 `json:"artifactCount,omitempty"`
	FailureCategory      string               `json:"failureCategory,omitempty"`
}

// RunStepDuration captures derived timing for one factory lifecycle step.
type RunStepDuration struct {
	Step       string    `json:"step"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	DurationMs int64     `json:"durationMs"`
}

// EngineTelemetry captures the engine execution context when known.
type EngineTelemetry struct {
	Name  string `json:"name,omitempty"`
	Model string `json:"model,omitempty"`
}

// RunSandboxTelemetry captures sandbox execution resources when known.
type RunSandboxTelemetry struct {
	Provider string `json:"provider,omitempty"`
	Size     string `json:"size,omitempty"`
}

// SandboxCostEstimate captures an estimated sandbox cost when pricing is known.
type SandboxCostEstimate struct {
	AmountUSD float64 `json:"amountUsd"`
	Estimated bool    `json:"estimated"`
}

// FailureSummary records the terminal failure context for a run.
type FailureSummary struct {
	Step             string `json:"step"`
	Category         string `json:"category,omitempty"`
	Message          string `json:"message"`
	Recoverable      bool   `json:"recoverable"`
	SuggestedCommand string `json:"suggestedCommand,omitempty"`
	ExitCode         int    `json:"exitCode,omitempty"`
}

// QueueEntry captures one durable factory queue item.
type QueueEntry struct {
	QueueID      string      `json:"queueId"`
	RunID        string      `json:"runId"`
	ExecutorMode string      `json:"executorMode"`
	Status       string      `json:"status"`
	CreatedAt    time.Time   `json:"createdAt"`
	ClaimedAt    *time.Time  `json:"claimedAt,omitempty"`
	CompletedAt  *time.Time  `json:"completedAt,omitempty"`
	Claim        *QueueClaim `json:"claim,omitempty"`
	AttemptCount int         `json:"attemptCount"`
	LastError    string      `json:"lastError,omitempty"`
}

// QueueClaim identifies the local worker process that claimed a queue entry.
type QueueClaim struct {
	WorkerID string `json:"workerId,omitempty"`
	PID      int    `json:"pid,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// EventRecord captures one append-only timeline entry for a factory run.
type EventRecord struct {
	Sequence  int64          `json:"sequence"`
	RunID     string         `json:"runId"`
	EventType string         `json:"eventType"`
	Timestamp time.Time      `json:"timestamp"`
	Message   string         `json:"message,omitempty"`
	Summary   string         `json:"summary,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// LogChunk captures one durable factory log chunk or summarized output line.
type LogChunk struct {
	Sequence  int64     `json:"sequence"`
	RunID     string    `json:"runId"`
	Stream    string    `json:"stream,omitempty"`
	Source    string    `json:"source,omitempty"`
	Text      string    `json:"text,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
}

// DeriveRunTelemetry returns a copy of the record telemetry enriched with
// timing fields derivable from the durable run record and timeline.
func DeriveRunTelemetry(record RunRecord, events []EventRecord) *RunTelemetry {
	telemetry := cloneRunTelemetry(record.Telemetry)

	if totalDurationMs, ok := deriveRunTotalDuration(record); ok {
		if telemetry == nil {
			telemetry = &RunTelemetry{}
		}
		if telemetry.TotalDurationMs == nil {
			telemetry.TotalDurationMs = &totalDurationMs
		}
	}

	stepDurations := DeriveRunStepDurations(events)
	if len(stepDurations) > 0 {
		if telemetry == nil {
			telemetry = &RunTelemetry{}
		}
		if len(telemetry.StepDurations) == 0 {
			telemetry.StepDurations = stepDurations
		}
	}

	if sandboxTelemetry := deriveSandboxTelemetry(record); sandboxTelemetry != nil {
		if telemetry == nil {
			telemetry = &RunTelemetry{}
		}
		if telemetry.Sandbox == nil {
			telemetry.Sandbox = sandboxTelemetry
		}
	}

	if costEstimate := deriveSandboxCostEstimate(record, telemetry); costEstimate != nil {
		if telemetry == nil {
			telemetry = &RunTelemetry{}
		}
		if telemetry.EstimatedSandboxCost == nil {
			telemetry.EstimatedSandboxCost = costEstimate
		}
	}

	if ciOutcome := deriveOutcome(record, events, "ci"); ciOutcome != "" {
		if telemetry == nil {
			telemetry = &RunTelemetry{}
		}
		if strings.TrimSpace(telemetry.CIOutcome) == "" {
			telemetry.CIOutcome = ciOutcome
		}
	}

	if verificationOutcome := deriveOutcome(record, events, "verification"); verificationOutcome != "" {
		if telemetry == nil {
			telemetry = &RunTelemetry{}
		}
		if strings.TrimSpace(telemetry.VerificationOutcome) == "" {
			telemetry.VerificationOutcome = verificationOutcome
		}
	}

	if len(record.Artifacts) > 0 {
		if telemetry == nil {
			telemetry = &RunTelemetry{}
		}
		if telemetry.ArtifactCount == nil {
			artifactCount := len(record.Artifacts)
			telemetry.ArtifactCount = &artifactCount
		}
	}

	if record.Failure != nil {
		if telemetry == nil {
			telemetry = &RunTelemetry{}
		}
		if strings.TrimSpace(telemetry.FailureCategory) == "" {
			telemetry.FailureCategory = NormalizeFailureCategory(record.Failure.Category)
		}
	}

	return telemetry
}

// DeriveRunStepDurations derives valid step duration pairs from timeline
// events. Partial, unsupported, or out-of-order pairs are skipped.
func DeriveRunStepDurations(events []EventRecord) []RunStepDuration {
	startedAtByStep := map[string]time.Time{}
	durations := []RunStepDuration{}

	for _, event := range events {
		step := eventDurationStep(event)
		if step == "" || event.Timestamp.IsZero() {
			continue
		}

		switch event.EventType {
		case EventTypeStepStarted:
			startedAtByStep[step] = event.Timestamp
		case EventTypeStepEnded:
			startedAt, ok := startedAtByStep[step]
			if !ok || startedAt.IsZero() || event.Timestamp.Before(startedAt) {
				continue
			}
			durations = append(durations, RunStepDuration{
				Step:       step,
				StartedAt:  startedAt,
				FinishedAt: event.Timestamp,
				DurationMs: event.Timestamp.Sub(startedAt).Milliseconds(),
			})
			delete(startedAtByStep, step)
		}
	}

	return durations
}

func deriveRunTotalDuration(record RunRecord) (int64, bool) {
	if record.CreatedAt.IsZero() || record.FinishedAt == nil || record.FinishedAt.IsZero() {
		return 0, false
	}
	if record.FinishedAt.Before(record.CreatedAt) {
		return 0, false
	}
	return record.FinishedAt.Sub(record.CreatedAt).Milliseconds(), true
}

func deriveSandboxTelemetry(record RunRecord) *RunSandboxTelemetry {
	if record.Sandbox == nil {
		return nil
	}
	telemetry := &RunSandboxTelemetry{
		Provider: strings.TrimSpace(record.Sandbox.Provider),
		Size:     strings.TrimSpace(record.Sandbox.Size),
	}
	if telemetry.Provider == "" && telemetry.Size == "" {
		return nil
	}
	return telemetry
}

func deriveSandboxCostEstimate(record RunRecord, telemetry *RunTelemetry) *SandboxCostEstimate {
	if telemetry == nil || telemetry.Sandbox == nil || record.CreatedAt.IsZero() {
		return nil
	}
	if telemetry.TotalDurationMs == nil {
		return nil
	}
	provider := strings.TrimSpace(telemetry.Sandbox.Provider)
	size := strings.TrimSpace(telemetry.Sandbox.Size)
	if provider == "" || size == "" {
		return nil
	}
	finishedAt := record.CreatedAt.Add(time.Duration(*telemetry.TotalDurationMs) * time.Millisecond)
	instance := &sandbox.SandboxState{
		Provider:  provider,
		Size:      size,
		CreatedAt: record.CreatedAt,
	}
	cost := sandbox.EstimatedCost(instance, func() time.Time { return finishedAt })
	if cost < 0 {
		return nil
	}
	return &SandboxCostEstimate{
		AmountUSD: cost,
		Estimated: true,
	}
}

func deriveOutcome(record RunRecord, events []EventRecord, kind string) string {
	if record.Telemetry != nil {
		switch kind {
		case "ci":
			if outcome := strings.TrimSpace(record.Telemetry.CIOutcome); outcome != "" {
				return outcome
			}
		case "verification":
			if outcome := strings.TrimSpace(record.Telemetry.VerificationOutcome); outcome != "" {
				return outcome
			}
		}
	}
	if outcome := deriveOutcomeFromArtifacts(record.Artifacts, kind); outcome != "" {
		return outcome
	}
	return deriveOutcomeFromEvents(events, kind)
}

func deriveOutcomeFromArtifacts(artifacts []ArtifactReference, kind string) string {
	for _, artifact := range artifacts {
		if artifact.Summary == nil {
			continue
		}
		outcomeKind, _ := artifact.Summary["outcomeKind"].(string)
		if strings.TrimSpace(outcomeKind) != kind {
			continue
		}
		if status, _ := artifact.Summary["status"].(string); strings.TrimSpace(status) != "" {
			return strings.TrimSpace(status)
		}
	}
	return ""
}

func deriveOutcomeFromEvents(events []EventRecord, kind string) string {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Metadata == nil {
			continue
		}
		if kind == "verification" && event.EventType == EventTypeVerificationResult {
			if status, _ := event.Metadata["status"].(string); strings.TrimSpace(status) != "" {
				return strings.TrimSpace(status)
			}
		}
		step, _ := event.Metadata["step"].(string)
		if strings.TrimSpace(step) != kind {
			continue
		}
		status, _ := event.Metadata["status"].(string)
		status = strings.TrimSpace(status)
		switch status {
		case RunStatusSucceeded:
			return "passed"
		case RunStatusFailed:
			return "failed"
		case "skipped":
			return "skipped"
		}
	}
	return ""
}

func eventDurationStep(event EventRecord) string {
	if event.Metadata == nil {
		return ""
	}
	step, ok := event.Metadata["step"].(string)
	if !ok {
		return ""
	}
	step = strings.TrimSpace(step)
	if !isSupportedRunDurationStep(step) {
		return ""
	}
	return step
}

func isSupportedRunDurationStep(step string) bool {
	switch step {
	case RunDurationStepSetup,
		RunDurationStepQueueClaim,
		RunDurationStepSandboxProvision,
		RunDurationStepSandboxStart,
		RunDurationStepEngineRun,
		RunDurationStepReview,
		RunDurationStepVerification,
		RunDurationStepCI,
		RunDurationStepArtifactCollect,
		RunDurationStepFinalization:
		return true
	default:
		return false
	}
}

func cloneRunTelemetry(src *RunTelemetry) *RunTelemetry {
	if src == nil {
		return nil
	}

	dst := *src
	if src.TotalDurationMs != nil {
		totalDurationMs := *src.TotalDurationMs
		dst.TotalDurationMs = &totalDurationMs
	}
	if len(src.StepDurations) > 0 {
		dst.StepDurations = append([]RunStepDuration(nil), src.StepDurations...)
	}
	if src.Engine != nil {
		engine := *src.Engine
		dst.Engine = &engine
	}
	if src.Sandbox != nil {
		sandbox := *src.Sandbox
		dst.Sandbox = &sandbox
	}
	if src.EstimatedSandboxCost != nil {
		estimatedSandboxCost := *src.EstimatedSandboxCost
		dst.EstimatedSandboxCost = &estimatedSandboxCost
	}
	if src.ArtifactCount != nil {
		artifactCount := *src.ArtifactCount
		dst.ArtifactCount = &artifactCount
	}
	return &dst
}
