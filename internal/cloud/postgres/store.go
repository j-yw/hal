package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

// Store implements cloud.Store backed by PostgreSQL.
type Store struct {
	db *sql.DB
}

// New creates a new Postgres-backed Store using the given *sql.DB connection.
// The caller is responsible for opening and closing the database connection.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Migrate applies all schema DDL statements to the database.
func (s *Store) Migrate(ctx context.Context) error {
	for _, stmt := range schemaStatements() {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("postgres migrate: %w", err)
		}
	}
	if err := s.ensureAuthProfileOneActiveIndex(ctx); err != nil {
		return err
	}
	if err := s.ensureRunsWorkflowKindColumn(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureAuthProfileOneActiveIndex(ctx context.Context) error {
	// Recreate index to migrate earlier schemas that scoped uniqueness by
	// (auth_profile_id, run_id) instead of auth_profile_id only.
	if _, err := s.db.ExecContext(ctx, `DROP INDEX IF EXISTS idx_auth_profile_locks_one_active`); err != nil {
		return fmt.Errorf("postgres migrate: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, authProfileLocksOneActiveIndex); err != nil {
		return fmt.Errorf("postgres migrate: %w", err)
	}
	return nil
}

func (s *Store) ensureRunsWorkflowKindColumn(ctx context.Context) error {
	const query = `SELECT EXISTS (
		SELECT 1
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = 'runs'
		  AND column_name = 'workflow_kind'
	)`

	var exists bool
	if err := s.db.QueryRowContext(ctx, query).Scan(&exists); err != nil {
		return fmt.Errorf("postgres migrate: %w", err)
	}
	if !exists {
		return fmt.Errorf("postgres migrate: runs.workflow_kind column missing; recreate database with latest schema")
	}
	return nil
}

// validRunTransitions defines the allowed run status transitions.
var validRunTransitions = map[cloud.RunStatus]map[cloud.RunStatus]bool{
	cloud.RunStatusQueued:   {cloud.RunStatusClaimed: true, cloud.RunStatusFailed: true, cloud.RunStatusCanceled: true},
	cloud.RunStatusClaimed:  {cloud.RunStatusQueued: true, cloud.RunStatusRunning: true, cloud.RunStatusFailed: true, cloud.RunStatusCanceled: true},
	cloud.RunStatusRunning:  {cloud.RunStatusSucceeded: true, cloud.RunStatusFailed: true, cloud.RunStatusCanceled: true},
	cloud.RunStatusRetrying: {cloud.RunStatusQueued: true, cloud.RunStatusFailed: true, cloud.RunStatusCanceled: true},
	cloud.RunStatusFailed:   {cloud.RunStatusRetrying: true},
}

// --- Runs ---

func (s *Store) EnqueueRun(ctx context.Context, run *cloud.Run) error {
	if err := run.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO runs (id, repo, base_branch, workflow_kind, engine, auth_profile_id, scope_ref,
			status, attempt_count, max_attempts, deadline_at, cancel_requested,
			input_snapshot_id, latest_snapshot_id, latest_snapshot_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		run.ID, run.Repo, run.BaseBranch, run.WorkflowKind, run.Engine, run.AuthProfileID, run.ScopeRef,
		run.Status, run.AttemptCount, run.MaxAttempts, run.DeadlineAt, run.CancelRequested,
		run.InputSnapshotID, run.LatestSnapshotID, run.LatestSnapshotVersion, run.CreatedAt, run.UpdatedAt,
	)
	return err
}

// SubmitRunWithInputSnapshot atomically persists a queued run, its initial
// input snapshot, and run snapshot references in one transaction.
func (s *Store) SubmitRunWithInputSnapshot(ctx context.Context, run *cloud.Run, snapshot *cloud.RunStateSnapshot) error {
	if err := run.Validate(); err != nil {
		return err
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO runs (id, repo, base_branch, workflow_kind, engine, auth_profile_id, scope_ref,
			status, attempt_count, max_attempts, deadline_at, cancel_requested,
			input_snapshot_id, latest_snapshot_id, latest_snapshot_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		run.ID, run.Repo, run.BaseBranch, run.WorkflowKind, run.Engine, run.AuthProfileID, run.ScopeRef,
		run.Status, run.AttemptCount, run.MaxAttempts, run.DeadlineAt, run.CancelRequested,
		run.InputSnapshotID, run.LatestSnapshotID, run.LatestSnapshotVersion, run.CreatedAt, run.UpdatedAt,
	); err != nil {
		_ = tx.Rollback()
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO run_state_snapshots (id, run_id, attempt_id, snapshot_kind, version, sha256, size_bytes, content_encoding, content_blob, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		snapshot.ID, snapshot.RunID, snapshot.AttemptID, snapshot.SnapshotKind, snapshot.Version, snapshot.SHA256,
		snapshot.SizeBytes, snapshot.ContentEncoding, snapshot.ContentBlob, snapshot.CreatedAt,
	); err != nil {
		_ = tx.Rollback()
		if isUniqueViolation(err) {
			return cloud.ErrConflict
		}
		return err
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE runs SET input_snapshot_id = $1, latest_snapshot_id = $2,
			latest_snapshot_version = $3, updated_at = NOW()
		WHERE id = $4`,
		&snapshot.ID, &snapshot.ID, snapshot.Version, run.ID)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if n == 0 {
		_ = tx.Rollback()
		return cloud.ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Store) ClaimRun(ctx context.Context, workerID string) (*cloud.Run, error) {
	// Use FOR UPDATE SKIP LOCKED to guarantee one winner under contention.
	// The subquery selects the oldest queued run and locks it; the UPDATE
	// transitions it to claimed and increments attempt_count atomically.
	// Runs with cancel_requested are excluded so canceled intent is enforced
	// before claim.
	row := s.db.QueryRowContext(ctx, `
		UPDATE runs SET status = 'claimed', attempt_count = attempt_count + 1, updated_at = NOW()
		WHERE id = (
			SELECT id FROM runs
			WHERE status = 'queued' AND cancel_requested = FALSE
			ORDER BY created_at ASC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, repo, base_branch, workflow_kind, engine, auth_profile_id, scope_ref,
			status, attempt_count, max_attempts, deadline_at, cancel_requested,
			input_snapshot_id, latest_snapshot_id, latest_snapshot_version, created_at, updated_at`)

	run, err := scanRun(row)
	if err == sql.ErrNoRows {
		return nil, cloud.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return run, nil
}

func (s *Store) TransitionRun(ctx context.Context, runID string, fromStatus, toStatus cloud.RunStatus) error {
	// Validate transition is allowed.
	allowed, ok := validRunTransitions[fromStatus]
	if !ok || !allowed[toStatus] {
		return cloud.ErrInvalidTransition
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE runs SET status = $1, updated_at = NOW()
		WHERE id = $2 AND status = $3`,
		string(toStatus), runID, string(fromStatus))
	if err != nil {
		return err
	}

	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		// Determine whether run doesn't exist or status doesn't match.
		var current string
		err := s.db.QueryRowContext(ctx, `SELECT status FROM runs WHERE id = $1`, runID).Scan(&current)
		if err == sql.ErrNoRows {
			return cloud.ErrNotFound
		}
		if err != nil {
			return err
		}
		return cloud.ErrConflict
	}
	return nil
}

func (s *Store) GetRun(ctx context.Context, runID string) (*cloud.Run, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, repo, base_branch, workflow_kind, engine, auth_profile_id, scope_ref,
			status, attempt_count, max_attempts, deadline_at, cancel_requested,
			input_snapshot_id, latest_snapshot_id, latest_snapshot_version, created_at, updated_at
		FROM runs WHERE id = $1`, runID)

	run, err := scanRun(row)
	if err == sql.ErrNoRows {
		return nil, cloud.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return run, nil
}

func (s *Store) ListRuns(ctx context.Context, limit int) ([]*cloud.Run, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, repo, base_branch, workflow_kind, engine, auth_profile_id, scope_ref,
			status, attempt_count, max_attempts, deadline_at, cancel_requested,
			input_snapshot_id, latest_snapshot_id, latest_snapshot_version, created_at, updated_at
		FROM runs
		ORDER BY updated_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []*cloud.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}
	return runs, rows.Err()
}

func (s *Store) ListOverdueRuns(ctx context.Context, now time.Time) ([]*cloud.Run, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, repo, base_branch, workflow_kind, engine, auth_profile_id, scope_ref,
			status, attempt_count, max_attempts, deadline_at, cancel_requested,
			input_snapshot_id, latest_snapshot_id, latest_snapshot_version, created_at, updated_at
		FROM runs
		WHERE deadline_at IS NOT NULL
			AND deadline_at < $1
			AND status NOT IN ('succeeded', 'failed', 'canceled')`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []*cloud.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}
	return runs, rows.Err()
}

func (s *Store) SetCancelIntent(ctx context.Context, runID string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE runs SET cancel_requested = TRUE, updated_at = NOW()
		WHERE id = $1`, runID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return cloud.ErrNotFound
	}
	return nil
}

// --- Attempts ---

func (s *Store) CreateAttempt(ctx context.Context, attempt *cloud.Attempt) error {
	if err := attempt.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO attempts (id, run_id, attempt_number, worker_id, sandbox_id,
			status, started_at, heartbeat_at, lease_expires_at, ended_at, error_code, error_message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		attempt.ID, attempt.RunID, attempt.AttemptNumber, attempt.WorkerID, attempt.SandboxID,
		attempt.Status, attempt.StartedAt, attempt.HeartbeatAt, attempt.LeaseExpiresAt,
		attempt.EndedAt, attempt.ErrorCode, attempt.ErrorMessage,
	)
	if err != nil && isUniqueViolation(err) {
		return cloud.ErrConflict
	}
	return err
}

func (s *Store) HeartbeatAttempt(ctx context.Context, attemptID string, heartbeatAt, leaseExpiresAt time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE attempts SET heartbeat_at = $1, lease_expires_at = $2
		WHERE id = $3 AND status = 'active'`,
		heartbeatAt, leaseExpiresAt, attemptID)
	if err != nil {
		return err
	}

	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		// Check if attempt exists at all.
		var exists bool
		err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM attempts WHERE id = $1)`, attemptID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return cloud.ErrNotFound
		}
		return cloud.ErrLeaseExpired
	}
	return nil
}

func (s *Store) TransitionAttempt(ctx context.Context, attemptID string, status cloud.AttemptStatus, endedAt time.Time, errorCode, errorMessage *string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE attempts SET status = $1, ended_at = $2, error_code = $3, error_message = $4
		WHERE id = $5`,
		string(status), endedAt, errorCode, errorMessage, attemptID)
	if err != nil {
		return err
	}

	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return cloud.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateAttemptSandboxID(ctx context.Context, attemptID, sandboxID string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE attempts SET sandbox_id = $1 WHERE id = $2`,
		sandboxID, attemptID)
	if err != nil {
		return err
	}

	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return cloud.ErrNotFound
	}
	return nil
}

func (s *Store) ListStaleAttempts(ctx context.Context, cutoff time.Time) ([]*cloud.Attempt, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, run_id, attempt_number, worker_id, sandbox_id,
			status, started_at, heartbeat_at, lease_expires_at, ended_at, error_code, error_message
		FROM attempts
		WHERE status = 'active' AND lease_expires_at < $1`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attempts []*cloud.Attempt
	for rows.Next() {
		a, err := scanAttemptFromRows(rows)
		if err != nil {
			return nil, err
		}
		attempts = append(attempts, a)
	}
	return attempts, rows.Err()
}

func (s *Store) GetAttempt(ctx context.Context, attemptID string) (*cloud.Attempt, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, run_id, attempt_number, worker_id, sandbox_id,
			status, started_at, heartbeat_at, lease_expires_at, ended_at, error_code, error_message
		FROM attempts WHERE id = $1`, attemptID)

	a, err := scanAttemptFromRow(row)
	if err == sql.ErrNoRows {
		return nil, cloud.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) GetActiveAttemptByRun(ctx context.Context, runID string) (*cloud.Attempt, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, run_id, attempt_number, worker_id, sandbox_id,
			status, started_at, heartbeat_at, lease_expires_at, ended_at, error_code, error_message
		FROM attempts WHERE run_id = $1 AND status = 'active'`, runID)

	a, err := scanAttemptFromRow(row)
	if err == sql.ErrNoRows {
		return nil, cloud.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

// --- Events ---

func (s *Store) InsertEvent(ctx context.Context, event *cloud.Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO events (id, run_id, attempt_id, event_type, payload_json, redacted, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		event.ID, event.RunID, event.AttemptID, event.EventType, event.PayloadJSON, event.Redacted, event.CreatedAt)
	return err
}

func (s *Store) ListEvents(ctx context.Context, runID string) ([]*cloud.Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, run_id, attempt_id, event_type, payload_json, redacted, created_at
		FROM events WHERE run_id = $1 ORDER BY created_at ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*cloud.Event
	for rows.Next() {
		var e cloud.Event
		if err := rows.Scan(&e.ID, &e.RunID, &e.AttemptID, &e.EventType, &e.PayloadJSON, &e.Redacted, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, &e)
	}
	return events, rows.Err()
}

// --- Idempotency ---

func (s *Store) PutIdempotencyKey(ctx context.Context, key *cloud.IdempotencyKey) error {
	if err := key.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO idempotency_keys (key, run_id, side_effect_type, result_ref, created_at)
		VALUES ($1, $2, $3, $4, $5)`,
		key.Key, key.RunID, key.SideEffectType, key.ResultRef, key.CreatedAt)
	if err != nil && isUniqueViolation(err) {
		return cloud.ErrDuplicateKey
	}
	return err
}

func (s *Store) GetIdempotencyKey(ctx context.Context, key string) (*cloud.IdempotencyKey, error) {
	var k cloud.IdempotencyKey
	err := s.db.QueryRowContext(ctx, `
		SELECT key, run_id, side_effect_type, result_ref, created_at
		FROM idempotency_keys WHERE key = $1`, key).
		Scan(&k.Key, &k.RunID, &k.SideEffectType, &k.ResultRef, &k.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, cloud.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// --- Auth Profiles ---

func (s *Store) CreateAuthProfile(ctx context.Context, profile *cloud.AuthProfile) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_profiles (id, owner_id, provider, mode, secret_ref, status,
			max_concurrent_runs, runtime_metadata_json, last_validated_at, expires_at,
			last_error_code, version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		profile.ID, profile.OwnerID, profile.Provider, profile.Mode, profile.SecretRef,
		profile.Status, profile.MaxConcurrentRuns, profile.RuntimeMetadataJSON,
		profile.LastValidatedAt, profile.ExpiresAt, profile.LastErrorCode,
		profile.Version, profile.CreatedAt, profile.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return cloud.ErrDuplicateKey
		}
		return err
	}
	return nil
}

func (s *Store) GetAuthProfile(ctx context.Context, profileID string) (*cloud.AuthProfile, error) {
	var p cloud.AuthProfile
	err := s.db.QueryRowContext(ctx, `
		SELECT id, owner_id, provider, mode, secret_ref, status, max_concurrent_runs,
			runtime_metadata_json, last_validated_at, expires_at, last_error_code,
			version, created_at, updated_at
		FROM auth_profiles WHERE id = $1`, profileID).
		Scan(&p.ID, &p.OwnerID, &p.Provider, &p.Mode, &p.SecretRef, &p.Status,
			&p.MaxConcurrentRuns, &p.RuntimeMetadataJSON, &p.LastValidatedAt,
			&p.ExpiresAt, &p.LastErrorCode, &p.Version, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, cloud.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) UpdateAuthProfile(ctx context.Context, profile *cloud.AuthProfile) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE auth_profiles SET
			owner_id = $1, provider = $2, mode = $3, secret_ref = $4, status = $5,
			max_concurrent_runs = $6, runtime_metadata_json = $7, last_validated_at = $8,
			expires_at = $9, last_error_code = $10, version = version + 1, updated_at = NOW()
		WHERE id = $11 AND version = $12`,
		profile.OwnerID, profile.Provider, profile.Mode, profile.SecretRef, profile.Status,
		profile.MaxConcurrentRuns, profile.RuntimeMetadataJSON, profile.LastValidatedAt,
		profile.ExpiresAt, profile.LastErrorCode, profile.ID, profile.Version)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var exists bool
		err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM auth_profiles WHERE id = $1)`, profile.ID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return cloud.ErrNotFound
		}
		return cloud.ErrConflict
	}
	return nil
}

// --- Auth Profile Locks ---

func (s *Store) AcquireAuthLock(ctx context.Context, lock *cloud.AuthProfileLock) error {
	if err := lock.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_profile_locks (auth_profile_id, run_id, worker_id, acquired_at, heartbeat_at, lease_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		lock.AuthProfileID, lock.RunID, lock.WorkerID, lock.AcquiredAt, lock.HeartbeatAt, lock.LeaseExpiresAt)
	if err != nil && isUniqueViolation(err) {
		return cloud.ErrConflict
	}
	return err
}

func (s *Store) RenewAuthLock(ctx context.Context, authProfileID, runID string, heartbeatAt, leaseExpiresAt time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE auth_profile_locks SET heartbeat_at = $1, lease_expires_at = $2
		WHERE auth_profile_id = $3 AND run_id = $4 AND released_at IS NULL AND lease_expires_at > NOW()`,
		heartbeatAt, leaseExpiresAt, authProfileID, runID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		// Determine specific error.
		var exists bool
		err := s.db.QueryRowContext(ctx, `
			SELECT EXISTS(SELECT 1 FROM auth_profile_locks WHERE auth_profile_id = $1 AND run_id = $2 AND released_at IS NULL)`,
			authProfileID, runID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return cloud.ErrNotFound
		}
		return cloud.ErrLeaseExpired
	}
	return nil
}

func (s *Store) ReleaseAuthLock(ctx context.Context, authProfileID, runID string, releasedAt time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE auth_profile_locks SET released_at = $1
		WHERE auth_profile_id = $2 AND run_id = $3 AND released_at IS NULL`,
		releasedAt, authProfileID, runID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return cloud.ErrNotFound
	}
	return nil
}

func (s *Store) GetActiveAuthLock(ctx context.Context, authProfileID string) (*cloud.AuthProfileLock, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT auth_profile_id, run_id, worker_id, acquired_at, heartbeat_at, lease_expires_at, released_at
		FROM auth_profile_locks
		WHERE auth_profile_id = $1 AND released_at IS NULL
		LIMIT 1`, authProfileID)

	var lock cloud.AuthProfileLock
	if err := row.Scan(
		&lock.AuthProfileID, &lock.RunID, &lock.WorkerID,
		&lock.AcquiredAt, &lock.HeartbeatAt, &lock.LeaseExpiresAt, &lock.ReleasedAt,
	); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, cloud.ErrNotFound
		}
		return nil, err
	}
	return &lock, nil
}

// --- Snapshots ---

func (s *Store) PutSnapshot(ctx context.Context, snap *cloud.RunStateSnapshot) error {
	if err := snap.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO run_state_snapshots (id, run_id, attempt_id, snapshot_kind, version, sha256, size_bytes, content_encoding, content_blob, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		snap.ID, snap.RunID, snap.AttemptID, snap.SnapshotKind, snap.Version, snap.SHA256,
		snap.SizeBytes, snap.ContentEncoding, snap.ContentBlob, snap.CreatedAt)
	if err != nil && isUniqueViolation(err) {
		return cloud.ErrConflict
	}
	return err
}

func (s *Store) GetSnapshot(ctx context.Context, snapshotID string) (*cloud.RunStateSnapshot, error) {
	var snap cloud.RunStateSnapshot
	err := s.db.QueryRowContext(ctx, `
		SELECT id, run_id, attempt_id, snapshot_kind, version, sha256, size_bytes, content_encoding, content_blob, created_at
		FROM run_state_snapshots WHERE id = $1`, snapshotID).
		Scan(&snap.ID, &snap.RunID, &snap.AttemptID, &snap.SnapshotKind, &snap.Version, &snap.SHA256,
			&snap.SizeBytes, &snap.ContentEncoding, &snap.ContentBlob, &snap.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, cloud.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &snap, nil
}

func (s *Store) GetLatestSnapshot(ctx context.Context, runID string) (*cloud.RunStateSnapshot, error) {
	var snap cloud.RunStateSnapshot
	err := s.db.QueryRowContext(ctx, `
		SELECT id, run_id, attempt_id, snapshot_kind, version, sha256, size_bytes, content_encoding, content_blob, created_at
		FROM run_state_snapshots WHERE run_id = $1 ORDER BY version DESC LIMIT 1`, runID).
		Scan(&snap.ID, &snap.RunID, &snap.AttemptID, &snap.SnapshotKind, &snap.Version, &snap.SHA256,
			&snap.SizeBytes, &snap.ContentEncoding, &snap.ContentBlob, &snap.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, cloud.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &snap, nil
}

func (s *Store) UpdateRunSnapshotRefs(ctx context.Context, runID string, inputSnapshotID, latestSnapshotID *string, latestSnapshotVersion int) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE runs SET input_snapshot_id = $1, latest_snapshot_id = $2,
			latest_snapshot_version = $3, updated_at = NOW()
		WHERE id = $4`,
		inputSnapshotID, latestSnapshotID, latestSnapshotVersion, runID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return cloud.ErrNotFound
	}
	return nil
}

// --- scan helpers ---

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRun(row rowScanner) (*cloud.Run, error) {
	var r cloud.Run
	err := row.Scan(
		&r.ID, &r.Repo, &r.BaseBranch, &r.WorkflowKind, &r.Engine, &r.AuthProfileID, &r.ScopeRef,
		&r.Status, &r.AttemptCount, &r.MaxAttempts, &r.DeadlineAt, &r.CancelRequested,
		&r.InputSnapshotID, &r.LatestSnapshotID, &r.LatestSnapshotVersion, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func scanAttemptFromRow(row *sql.Row) (*cloud.Attempt, error) {
	var a cloud.Attempt
	err := row.Scan(
		&a.ID, &a.RunID, &a.AttemptNumber, &a.WorkerID, &a.SandboxID,
		&a.Status, &a.StartedAt, &a.HeartbeatAt, &a.LeaseExpiresAt,
		&a.EndedAt, &a.ErrorCode, &a.ErrorMessage,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func scanAttemptFromRows(rows *sql.Rows) (*cloud.Attempt, error) {
	var a cloud.Attempt
	err := rows.Scan(
		&a.ID, &a.RunID, &a.AttemptNumber, &a.WorkerID, &a.SandboxID,
		&a.Status, &a.StartedAt, &a.HeartbeatAt, &a.LeaseExpiresAt,
		&a.EndedAt, &a.ErrorCode, &a.ErrorMessage,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// isUniqueViolation checks if the error is a Postgres unique constraint violation (23505).
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	// Match Postgres error code 23505 (unique_violation) via string matching
	// to avoid importing driver-specific packages into the adapter.
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(msg, "duplicate key")
}
