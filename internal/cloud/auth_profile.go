package cloud

import (
	"fmt"
	"time"
)

// AuthProfileStatus represents the lifecycle state of an auth profile.
type AuthProfileStatus string

const (
	AuthProfileStatusPendingLink AuthProfileStatus = "pending_link"
	AuthProfileStatusLinked      AuthProfileStatus = "linked"
	AuthProfileStatusInvalid     AuthProfileStatus = "invalid"
	AuthProfileStatusRevoked     AuthProfileStatus = "revoked"
)

// validAuthProfileStatuses is the exhaustive set of allowed auth profile statuses.
var validAuthProfileStatuses = map[AuthProfileStatus]bool{
	AuthProfileStatusPendingLink: true,
	AuthProfileStatusLinked:      true,
	AuthProfileStatusInvalid:     true,
	AuthProfileStatusRevoked:     true,
}

// IsValid reports whether s is one of the allowed auth profile statuses.
func (s AuthProfileStatus) IsValid() bool {
	return validAuthProfileStatuses[s]
}

// IsTerminal reports whether s is a terminal (final) auth profile status.
func (s AuthProfileStatus) IsTerminal() bool {
	switch s {
	case AuthProfileStatusRevoked:
		return true
	default:
		return false
	}
}

// AuthProfile represents a reusable auth profile record.
type AuthProfile struct {
	ID                 string            `json:"id"`
	OwnerID            string            `json:"owner_id"`
	Provider           string            `json:"provider"`
	Mode               string            `json:"mode"`
	SecretRef          *string           `json:"secret_ref,omitempty"`
	Status             AuthProfileStatus `json:"status"`
	MaxConcurrentRuns  int               `json:"max_concurrent_runs"`
	RuntimeMetadataJSON *string          `json:"runtime_metadata_json,omitempty"`
	LastValidatedAt    *time.Time        `json:"last_validated_at,omitempty"`
	ExpiresAt          *time.Time        `json:"expires_at,omitempty"`
	LastErrorCode      *string           `json:"last_error_code,omitempty"`
	Version            int               `json:"version"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// Validate checks that all required fields are set and the status is valid.
func (p *AuthProfile) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("auth_profile.id must not be empty")
	}
	if p.OwnerID == "" {
		return fmt.Errorf("auth_profile.owner_id must not be empty")
	}
	if p.Provider == "" {
		return fmt.Errorf("auth_profile.provider must not be empty")
	}
	if p.Mode == "" {
		return fmt.Errorf("auth_profile.mode must not be empty")
	}
	if !p.Status.IsValid() {
		return fmt.Errorf("auth_profile.status %q is not a valid status", p.Status)
	}
	if p.MaxConcurrentRuns < 1 {
		return fmt.Errorf("auth_profile.max_concurrent_runs must be >= 1, got %d", p.MaxConcurrentRuns)
	}
	return nil
}

// AuthProfilesSchema is the SQL DDL for the auth_profiles table.
const AuthProfilesSchema = `CREATE TABLE IF NOT EXISTS auth_profiles (
    id                    TEXT PRIMARY KEY,
    owner_id              TEXT NOT NULL,
    provider              TEXT NOT NULL,
    mode                  TEXT NOT NULL,
    secret_ref            TEXT,
    status                TEXT NOT NULL CHECK (status IN ('pending_link','linked','invalid','revoked')),
    max_concurrent_runs   INTEGER NOT NULL DEFAULT 1 CHECK (max_concurrent_runs >= 1),
    runtime_metadata_json TEXT,
    last_validated_at     TIMESTAMP,
    expires_at            TIMESTAMP,
    last_error_code       TEXT,
    version               INTEGER NOT NULL DEFAULT 1,
    created_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);`
