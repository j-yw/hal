package sandboxexecution

import (
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
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

// Manifest is the durable state record for one non-factory sandbox execution.
type Manifest struct {
	ID          string                       `json:"id"`
	Purpose     Purpose                      `json:"purpose"`
	SandboxName string                       `json:"sandboxName"`
	ProjectDir  string                       `json:"projectDir"`
	Command     []string                     `json:"command"`
	WorkDir     string                       `json:"workDir"`
	Status      Status                       `json:"status"`
	StartedAt   time.Time                    `json:"startedAt"`
	FinishedAt  *time.Time                   `json:"finishedAt"`
	Workspace   *sandbox.SandboxWorkspace    `json:"workspace"`
	Host        *sandbox.SandboxHost         `json:"host"`
	Runtime     *sandbox.SandboxRuntimeState `json:"runtime"`
	Security    *sandbox.SandboxSecurity     `json:"security"`
	Lease       *sandbox.SandboxLeaseRef     `json:"lease"`
	Artifacts   []Artifact                   `json:"artifacts"`
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
