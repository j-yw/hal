package sandboxexecution

import (
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

// Purpose identifies which non-factory command created an execution record.
type Purpose string

const (
	PurposeRun  Purpose = "run"
	PurposeAuto Purpose = "auto"
)

// Status identifies the durable lifecycle state for an execution.
type Status string

const (
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCanceled  Status = "canceled"
)

// Artifact describes a persisted execution payload without recording unsafe
// local source paths.
type Artifact struct {
	ID         string     `json:"id,omitempty"`
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	Path       string     `json:"path,omitempty"`
	StoredPath string     `json:"storedPath,omitempty"`
	SizeBytes  *int64     `json:"sizeBytes,omitempty"`
	CreatedAt  *time.Time `json:"createdAt,omitempty"`
}

// ArtifactMetadata groups additive collection metadata for execution payloads.
// It intentionally stays separate from the legacy Artifacts array so existing
// manifest readers keep seeing the same JSON shape.
type ArtifactMetadata struct {
	Collected []ArtifactMetadataEntry `json:"collected,omitempty"`
	Partial   []ArtifactMetadataEntry `json:"partial,omitempty"`
	Warnings  []ArtifactWarning       `json:"warnings,omitempty"`
}

// ArtifactMetadataEntry describes a collected or partial artifact without any
// host-local source path.
type ArtifactMetadataEntry struct {
	ID         string     `json:"id,omitempty"`
	Name       string     `json:"name,omitempty"`
	Type       string     `json:"type,omitempty"`
	Path       string     `json:"path,omitempty"`
	StoredPath string     `json:"storedPath,omitempty"`
	SizeBytes  *int64     `json:"sizeBytes,omitempty"`
	CreatedAt  *time.Time `json:"createdAt,omitempty"`
}

// ArtifactWarning records a non-fatal artifact collection issue with the
// artifact affected by that phase.
type ArtifactWarning struct {
	Phase    string                `json:"phase"`
	Message  string                `json:"message"`
	Artifact ArtifactMetadataEntry `json:"artifact"`
}

// Manifest is the durable state record for one non-factory sandbox execution.
type Manifest struct {
	ID               string                            `json:"id"`
	Purpose          Purpose                           `json:"purpose"`
	SandboxName      string                            `json:"sandboxName,omitempty"`
	ProjectDir       string                            `json:"projectDir,omitempty"`
	Command          []string                          `json:"command,omitempty"`
	WorkDir          string                            `json:"workDir,omitempty"`
	Status           Status                            `json:"status"`
	StartedAt        time.Time                         `json:"startedAt"`
	FinishedAt       *time.Time                        `json:"finishedAt,omitempty"`
	Workspace        *sandbox.SandboxWorkspace         `json:"workspace,omitempty"`
	Host             *sandbox.SandboxHost              `json:"host,omitempty"`
	Runtime          *sandbox.SandboxRuntimeState      `json:"runtime,omitempty"`
	Security         *sandbox.SandboxSecurity          `json:"security,omitempty"`
	Lease            *sandbox.SandboxLeaseRef          `json:"lease,omitempty"`
	WorkerRouting    *sandbox.WorkerRoutingMetadata    `json:"workerRouting,omitempty"`
	Artifacts        []Artifact                        `json:"artifacts,omitempty"`
	ArtifactMetadata *ArtifactMetadata                 `json:"artifactMetadata,omitempty"`
	SyncOut          *sandboxworkspace.SyncOutSummary  `json:"syncOut,omitempty"`
	SyncOutApply     *sandboxworkspace.SafeApplyResult `json:"syncOutApply,omitempty"`
}

func validPurpose(purpose Purpose) bool {
	switch purpose {
	case PurposeRun, PurposeAuto:
		return true
	default:
		return false
	}
}

func validStatus(status Status) bool {
	switch status {
	case StatusRunning, StatusSucceeded, StatusFailed, StatusCanceled:
		return true
	default:
		return false
	}
}
