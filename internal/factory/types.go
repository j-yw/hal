// Package factory defines durable factory run records and timeline events.
package factory

import (
	"time"

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
	ExecutorModeLocal = "local"
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
	FailureCategoryValidation = "validation"
	FailureCategoryPipeline   = "pipeline"
	FailureCategoryEngine     = "engine"
	FailureCategoryGit        = "git"
	FailureCategoryCI         = "ci"
	FailureCategoryUnknown    = "unknown"
)

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

// RunRecord captures persisted state for one factory run.
type RunRecord struct {
	RunID        string              `json:"runId"`
	Status       string              `json:"status"`
	ExecutorMode string              `json:"executorMode,omitempty"`
	Source       SourceMetadata      `json:"source"`
	RepoPath     string              `json:"repoPath"`
	RepoRemote   string              `json:"repoRemote"`
	BranchName   string              `json:"branchName"`
	BaseBranch   string              `json:"baseBranch"`
	SandboxName  string              `json:"sandboxName,omitempty"`
	CurrentStep  string              `json:"currentStep"`
	CreatedAt    time.Time           `json:"createdAt"`
	UpdatedAt    time.Time           `json:"updatedAt"`
	FinishedAt   *time.Time          `json:"finishedAt,omitempty"`
	Artifacts    []ArtifactReference `json:"artifacts,omitempty"`
	Verification *VerificationRecord `json:"verification,omitempty"`
	Failure      *FailureSummary     `json:"failure,omitempty"`
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
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
	URL  string `json:"url,omitempty"`
}

// VerificationRecord captures verification metadata associated with a run.
type VerificationRecord struct {
	Summary   verify.Summary             `json:"summary"`
	Artifacts []verify.ArtifactReference `json:"artifacts,omitempty"`
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
