package cloud

import (
	"context"
	"time"
)

// Store is the persistence contract for cloud orchestration. All service-layer
// logic depends on this interface — never on adapter-specific imports.
type Store interface {
	// --- Runs ---

	// EnqueueRun inserts a new run in queued status.
	EnqueueRun(ctx context.Context, run *Run) error

	// ClaimRun atomically transitions one eligible queued run to claimed for
	// the given worker. Returns the claimed run or ErrNotFound if no eligible
	// run exists.
	ClaimRun(ctx context.Context, workerID string) (*Run, error)

	// TransitionRun changes a run's status. Returns ErrNotFound if the run
	// does not exist, ErrInvalidTransition if the from→to transition is not
	// allowed, or ErrConflict if the current status does not match fromStatus.
	TransitionRun(ctx context.Context, runID string, fromStatus, toStatus RunStatus) error

	// GetRun returns the run with the given ID or ErrNotFound.
	GetRun(ctx context.Context, runID string) (*Run, error)

	// ListOverdueRuns returns non-terminal runs whose deadline_at is earlier
	// than the given time. Used by the timeout reconciler to detect overdue runs.
	ListOverdueRuns(ctx context.Context, now time.Time) ([]*Run, error)

	// SetCancelIntent sets the cancel_requested flag on a run. Returns
	// ErrNotFound if the run does not exist. Idempotent — setting cancel on
	// an already-canceled or already cancel-requested run is a no-op success.
	SetCancelIntent(ctx context.Context, runID string) error

	// --- Attempts ---

	// CreateAttempt inserts a new active attempt for a run.
	CreateAttempt(ctx context.Context, attempt *Attempt) error

	// HeartbeatAttempt updates heartbeat_at and extends lease_expires_at for
	// the given attempt. Returns ErrNotFound if the attempt does not exist
	// or ErrLeaseExpired if the lease has already expired.
	HeartbeatAttempt(ctx context.Context, attemptID string, heartbeatAt, leaseExpiresAt time.Time) error

	// TransitionAttempt changes an attempt's status to a terminal state.
	// Returns ErrNotFound if the attempt does not exist.
	TransitionAttempt(ctx context.Context, attemptID string, status AttemptStatus, endedAt time.Time, errorCode, errorMessage *string) error

	// ListActiveAttempts returns all attempts in active status whose lease
	// has expired before the given cutoff time.
	ListStaleAttempts(ctx context.Context, cutoff time.Time) ([]*Attempt, error)

	// UpdateAttemptSandboxID sets the sandbox_id on an existing attempt.
	// Returns ErrNotFound if the attempt does not exist.
	UpdateAttemptSandboxID(ctx context.Context, attemptID, sandboxID string) error

	// GetAttempt returns the attempt with the given ID or ErrNotFound.
	GetAttempt(ctx context.Context, attemptID string) (*Attempt, error)

	// GetActiveAttemptByRun returns the active attempt for a run or
	// ErrNotFound if no active attempt exists.
	GetActiveAttemptByRun(ctx context.Context, runID string) (*Attempt, error)

	// --- Events ---

	// InsertEvent appends an event to the run timeline. Events are immutable
	// once inserted.
	InsertEvent(ctx context.Context, event *Event) error

	// ListEvents returns events for a run ordered by created_at ascending.
	ListEvents(ctx context.Context, runID string) ([]*Event, error)

	// --- Idempotency ---

	// PutIdempotencyKey inserts an idempotency key. Returns ErrDuplicateKey
	// if the key already exists.
	PutIdempotencyKey(ctx context.Context, key *IdempotencyKey) error

	// GetIdempotencyKey returns the idempotency key or ErrNotFound.
	GetIdempotencyKey(ctx context.Context, key string) (*IdempotencyKey, error)

	// --- Auth Profiles ---

	// CreateAuthProfile inserts a new auth profile. Returns ErrDuplicateKey
	// if a profile with the same ID already exists.
	CreateAuthProfile(ctx context.Context, profile *AuthProfile) error

	// GetAuthProfile returns the auth profile with the given ID or ErrNotFound.
	GetAuthProfile(ctx context.Context, profileID string) (*AuthProfile, error)

	// UpdateAuthProfile updates a mutable auth profile record. Returns
	// ErrNotFound if the profile does not exist or ErrConflict if the version
	// does not match (optimistic concurrency).
	UpdateAuthProfile(ctx context.Context, profile *AuthProfile) error

	// --- Auth Profile Locks ---

	// AcquireAuthLock creates a new active lock on an auth profile for a run.
	// Returns ErrConflict if an active lock already exists for the profile
	// that has not expired.
	AcquireAuthLock(ctx context.Context, lock *AuthProfileLock) error

	// RenewAuthLock extends the lease on an active auth lock. Returns
	// ErrNotFound if no active lock exists, ErrLeaseExpired if the lease has
	// already expired, or ErrConflict if the lock is held by a different run.
	RenewAuthLock(ctx context.Context, authProfileID, runID string, heartbeatAt, leaseExpiresAt time.Time) error

	// ReleaseAuthLock marks an active lock as released. Returns ErrNotFound
	// if no active lock exists for the given profile and run.
	ReleaseAuthLock(ctx context.Context, authProfileID, runID string, releasedAt time.Time) error

	// GetActiveAuthLock returns the active (unreleased) lock for the given
	// auth profile, or ErrNotFound if no active lock exists.
	GetActiveAuthLock(ctx context.Context, authProfileID string) (*AuthProfileLock, error)

	// --- Snapshots ---

	// PutSnapshot stores a run state snapshot. Returns ErrConflict if a
	// snapshot with the same (run_id, version) already exists.
	PutSnapshot(ctx context.Context, snapshot *RunStateSnapshot) error

	// GetSnapshot returns the snapshot with the given ID or ErrNotFound.
	GetSnapshot(ctx context.Context, snapshotID string) (*RunStateSnapshot, error)

	// GetLatestSnapshot returns the most recent snapshot for a run (by version
	// descending) or ErrNotFound if no snapshots exist.
	GetLatestSnapshot(ctx context.Context, runID string) (*RunStateSnapshot, error)

	// UpdateRunSnapshotRefs updates the snapshot reference fields on a run:
	// input_snapshot_id, latest_snapshot_id, and latest_snapshot_version.
	// Returns ErrNotFound if the run does not exist.
	UpdateRunSnapshotRefs(ctx context.Context, runID string, inputSnapshotID, latestSnapshotID *string, latestSnapshotVersion int) error
}
