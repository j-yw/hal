package cloud

import (
	"fmt"
	"time"
)

// AttemptStatus represents the lifecycle state of an attempt.
type AttemptStatus string

const (
	AttemptStatusActive    AttemptStatus = "active"
	AttemptStatusSucceeded AttemptStatus = "succeeded"
	AttemptStatusFailed    AttemptStatus = "failed"
	AttemptStatusCanceled  AttemptStatus = "canceled"
)

// validAttemptStatuses is the exhaustive set of allowed attempt statuses.
var validAttemptStatuses = map[AttemptStatus]bool{
	AttemptStatusActive:    true,
	AttemptStatusSucceeded: true,
	AttemptStatusFailed:    true,
	AttemptStatusCanceled:  true,
}

// IsValid reports whether s is one of the allowed attempt statuses.
func (s AttemptStatus) IsValid() bool {
	return validAttemptStatuses[s]
}

// IsTerminal reports whether s is a terminal (final) attempt status.
func (s AttemptStatus) IsTerminal() bool {
	switch s {
	case AttemptStatusSucceeded, AttemptStatusFailed, AttemptStatusCanceled:
		return true
	default:
		return false
	}
}

// Attempt represents a single execution attempt for a cloud run.
type Attempt struct {
	ID             string        `json:"id"`
	RunID          string        `json:"run_id"`
	AttemptNumber  int           `json:"attempt_number"`
	WorkerID       string        `json:"worker_id"`
	SandboxID      *string       `json:"sandbox_id,omitempty"`
	Status         AttemptStatus `json:"status"`
	StartedAt      time.Time     `json:"started_at"`
	HeartbeatAt    time.Time     `json:"heartbeat_at"`
	LeaseExpiresAt time.Time     `json:"lease_expires_at"`
	EndedAt        *time.Time    `json:"ended_at,omitempty"`
	ErrorCode      *string       `json:"error_code,omitempty"`
	ErrorMessage   *string       `json:"error_message,omitempty"`
}

// Validate checks that all required fields are set and the status is valid.
func (a *Attempt) Validate() error {
	if a.ID == "" {
		return fmt.Errorf("attempt.id must not be empty")
	}
	if a.RunID == "" {
		return fmt.Errorf("attempt.run_id must not be empty")
	}
	if a.AttemptNumber < 1 {
		return fmt.Errorf("attempt.attempt_number must be >= 1, got %d", a.AttemptNumber)
	}
	if a.WorkerID == "" {
		return fmt.Errorf("attempt.worker_id must not be empty")
	}
	if !a.Status.IsValid() {
		return fmt.Errorf("attempt.status %q is not a valid status", a.Status)
	}
	return nil
}

// AttemptsSchema is the SQL DDL for the attempts table.
const AttemptsSchema = `CREATE TABLE IF NOT EXISTS attempts (
    id               TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs(id),
    attempt_number   INTEGER NOT NULL,
    worker_id        TEXT NOT NULL,
    sandbox_id       TEXT,
    status           TEXT NOT NULL CHECK (status IN ('active','succeeded','failed','canceled')),
    started_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    heartbeat_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_expires_at TIMESTAMP NOT NULL,
    ended_at         TIMESTAMP,
    error_code       TEXT,
    error_message    TEXT
);`

// AttemptsRunIDIndex is the SQL DDL for the index on run_id.
const AttemptsRunIDIndex = `CREATE INDEX IF NOT EXISTS idx_attempts_run_id ON attempts (run_id);`

// AttemptsStatusIndex is the SQL DDL for the index on status.
const AttemptsStatusIndex = `CREATE INDEX IF NOT EXISTS idx_attempts_status ON attempts (status);`

// AttemptsLeaseIndex is the SQL DDL for the index on lease_expires_at.
const AttemptsLeaseIndex = `CREATE INDEX IF NOT EXISTS idx_attempts_lease_expires_at ON attempts (lease_expires_at);`

// AttemptsOneActiveIndex enforces at most one active attempt per run_id.
const AttemptsOneActiveIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_attempts_one_active_per_run
    ON attempts (run_id) WHERE status = 'active';`
