package cloud

import (
	"fmt"
	"time"
)

// SnapshotKind represents the type of a run state snapshot.
type SnapshotKind string

const (
	SnapshotKindInput      SnapshotKind = "input"
	SnapshotKindCheckpoint SnapshotKind = "checkpoint"
	SnapshotKindFinal      SnapshotKind = "final"
)

// validSnapshotKinds is the exhaustive set of allowed snapshot kinds.
var validSnapshotKinds = map[SnapshotKind]bool{
	SnapshotKindInput:      true,
	SnapshotKindCheckpoint: true,
	SnapshotKindFinal:      true,
}

// IsValid reports whether k is one of the allowed snapshot kinds.
func (k SnapshotKind) IsValid() bool {
	return validSnapshotKinds[k]
}

// RunStateSnapshot represents a durable .hal state snapshot for a run.
type RunStateSnapshot struct {
	ID              string       `json:"id"`
	RunID           string       `json:"run_id"`
	AttemptID       *string      `json:"attempt_id,omitempty"`
	SnapshotKind    SnapshotKind `json:"snapshot_kind"`
	Version         int          `json:"version"`
	SHA256          string       `json:"sha256"`
	SizeBytes       int64        `json:"size_bytes"`
	ContentEncoding string       `json:"content_encoding"`
	ContentBlob     []byte       `json:"content_blob"`
	CreatedAt       time.Time    `json:"created_at"`
}

// Validate checks that all required fields are set and the snapshot kind is valid.
func (s *RunStateSnapshot) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("run_state_snapshot.id must not be empty")
	}
	if s.RunID == "" {
		return fmt.Errorf("run_state_snapshot.run_id must not be empty")
	}
	if !s.SnapshotKind.IsValid() {
		return fmt.Errorf("run_state_snapshot.snapshot_kind %q is not a valid kind", s.SnapshotKind)
	}
	if s.Version < 1 {
		return fmt.Errorf("run_state_snapshot.version must be >= 1, got %d", s.Version)
	}
	if s.SHA256 == "" {
		return fmt.Errorf("run_state_snapshot.sha256 must not be empty")
	}
	if s.SizeBytes < 0 {
		return fmt.Errorf("run_state_snapshot.size_bytes must be >= 0, got %d", s.SizeBytes)
	}
	if s.ContentEncoding == "" {
		return fmt.Errorf("run_state_snapshot.content_encoding must not be empty")
	}
	return nil
}

// RunStateSnapshotsSchema is the SQL DDL for the run_state_snapshots table.
const RunStateSnapshotsSchema = `CREATE TABLE IF NOT EXISTS run_state_snapshots (
    id               TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs(id),
    attempt_id       TEXT REFERENCES attempts(id),
    snapshot_kind    TEXT NOT NULL CHECK (snapshot_kind IN ('input','checkpoint','final')),
    version          INTEGER NOT NULL CHECK (version >= 1),
    sha256           TEXT NOT NULL,
    size_bytes       INTEGER NOT NULL,
    content_encoding TEXT NOT NULL,
    content_blob     BLOB NOT NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);`

// RunStateSnapshotsRunVersionUniqueIndex enforces unique constraint on (run_id, version).
const RunStateSnapshotsRunVersionUniqueIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_run_state_snapshots_run_version
    ON run_state_snapshots (run_id, version);`

// RunStateSnapshotsRunIDCreatedAtIndex is the SQL DDL for the index on (run_id, created_at).
const RunStateSnapshotsRunIDCreatedAtIndex = `CREATE INDEX IF NOT EXISTS idx_run_state_snapshots_run_created
    ON run_state_snapshots (run_id, created_at);`
