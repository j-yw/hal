package cloud

import (
	"fmt"
	"time"
)

// RunStatus represents the lifecycle state of a cloud run.
type RunStatus string

const (
	RunStatusQueued    RunStatus = "queued"
	RunStatusClaimed   RunStatus = "claimed"
	RunStatusRunning   RunStatus = "running"
	RunStatusRetrying  RunStatus = "retrying"
	RunStatusSucceeded RunStatus = "succeeded"
	RunStatusFailed    RunStatus = "failed"
	RunStatusCanceled  RunStatus = "canceled"
)

// validRunStatuses is the exhaustive set of allowed run statuses.
var validRunStatuses = map[RunStatus]bool{
	RunStatusQueued:    true,
	RunStatusClaimed:   true,
	RunStatusRunning:   true,
	RunStatusRetrying:  true,
	RunStatusSucceeded: true,
	RunStatusFailed:    true,
	RunStatusCanceled:  true,
}

// IsValid reports whether s is one of the allowed run statuses.
func (s RunStatus) IsValid() bool {
	return validRunStatuses[s]
}

// IsTerminal reports whether s is a terminal (final) run status.
func (s RunStatus) IsTerminal() bool {
	switch s {
	case RunStatusSucceeded, RunStatusFailed, RunStatusCanceled:
		return true
	default:
		return false
	}
}

// Run represents a durable cloud run record.
type Run struct {
	ID                    string     `json:"id"`
	Repo                  string     `json:"repo"`
	BaseBranch            string     `json:"base_branch"`
	Engine                string     `json:"engine"`
	AuthProfileID         string     `json:"auth_profile_id"`
	ScopeRef              string     `json:"scope_ref"`
	Status                RunStatus  `json:"status"`
	AttemptCount          int        `json:"attempt_count"`
	MaxAttempts           int        `json:"max_attempts"`
	DeadlineAt            *time.Time `json:"deadline_at,omitempty"`
	InputSnapshotID       *string    `json:"input_snapshot_id,omitempty"`
	LatestSnapshotID      *string    `json:"latest_snapshot_id,omitempty"`
	LatestSnapshotVersion int        `json:"latest_snapshot_version"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// Validate checks that all required fields are set and the status is valid.
func (r *Run) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("run.id must not be empty")
	}
	if r.Repo == "" {
		return fmt.Errorf("run.repo must not be empty")
	}
	if r.BaseBranch == "" {
		return fmt.Errorf("run.base_branch must not be empty")
	}
	if r.Engine == "" {
		return fmt.Errorf("run.engine must not be empty")
	}
	if r.AuthProfileID == "" {
		return fmt.Errorf("run.auth_profile_id must not be empty")
	}
	if r.ScopeRef == "" {
		return fmt.Errorf("run.scope_ref must not be empty")
	}
	if !r.Status.IsValid() {
		return fmt.Errorf("run.status %q is not a valid status", r.Status)
	}
	if r.MaxAttempts < 1 {
		return fmt.Errorf("run.max_attempts must be >= 1, got %d", r.MaxAttempts)
	}
	return nil
}

// RunsSchema is the SQL DDL for the runs table.
const RunsSchema = `CREATE TABLE IF NOT EXISTS runs (
    id                      TEXT PRIMARY KEY,
    repo                    TEXT NOT NULL,
    base_branch             TEXT NOT NULL,
    engine                  TEXT NOT NULL,
    auth_profile_id         TEXT NOT NULL,
    scope_ref               TEXT NOT NULL,
    status                  TEXT NOT NULL CHECK (status IN ('queued','claimed','running','retrying','succeeded','failed','canceled')),
    attempt_count           INTEGER NOT NULL DEFAULT 0,
    max_attempts            INTEGER NOT NULL DEFAULT 3,
    deadline_at             TIMESTAMP,
    input_snapshot_id       TEXT,
    latest_snapshot_id      TEXT,
    latest_snapshot_version INTEGER NOT NULL DEFAULT 0,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

// RunsQueueIndex is the SQL DDL for the queue index on (status, created_at).
const RunsQueueIndex = `CREATE INDEX IF NOT EXISTS idx_runs_queue ON runs (status, created_at);`
