package cloud

import (
	"fmt"
	"time"
)

// AuthProfileLock represents a lease-based lock on an auth profile for a specific run.
type AuthProfileLock struct {
	AuthProfileID  string     `json:"auth_profile_id"`
	RunID          string     `json:"run_id"`
	WorkerID       string     `json:"worker_id"`
	AcquiredAt     time.Time  `json:"acquired_at"`
	HeartbeatAt    time.Time  `json:"heartbeat_at"`
	LeaseExpiresAt time.Time  `json:"lease_expires_at"`
	ReleasedAt     *time.Time `json:"released_at,omitempty"`
}

// Validate checks that all required fields are set.
func (l *AuthProfileLock) Validate() error {
	if l.AuthProfileID == "" {
		return fmt.Errorf("auth_profile_lock.auth_profile_id must not be empty")
	}
	if l.RunID == "" {
		return fmt.Errorf("auth_profile_lock.run_id must not be empty")
	}
	if l.WorkerID == "" {
		return fmt.Errorf("auth_profile_lock.worker_id must not be empty")
	}
	return nil
}

// AuthProfileLocksSchema is the SQL DDL for the auth_profile_locks table.
const AuthProfileLocksSchema = `CREATE TABLE IF NOT EXISTS auth_profile_locks (
    auth_profile_id  TEXT NOT NULL REFERENCES auth_profiles(id),
    run_id           TEXT NOT NULL REFERENCES runs(id),
    worker_id        TEXT NOT NULL,
    acquired_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    heartbeat_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_expires_at TIMESTAMP NOT NULL,
    released_at      TIMESTAMP
);`

// AuthProfileLocksLeaseIndex is the SQL DDL for the index on (auth_profile_id, lease_expires_at).
const AuthProfileLocksLeaseIndex = `CREATE INDEX IF NOT EXISTS idx_auth_profile_locks_lease
    ON auth_profile_locks (auth_profile_id, lease_expires_at);`

// AuthProfileLocksOneActiveIndex enforces one active lock per auth profile.
const AuthProfileLocksOneActiveIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_profile_locks_one_active
    ON auth_profile_locks (auth_profile_id) WHERE released_at IS NULL;`
