// Package postgres implements the cloud.Store interface backed by PostgreSQL.
package postgres

// Postgres-specific DDL for the cloud orchestration schema.
// These adapt the domain DDL from internal/cloud to Postgres syntax.

const runsSchema = `CREATE TABLE IF NOT EXISTS runs (
    id                      TEXT PRIMARY KEY,
    repo                    TEXT NOT NULL,
    base_branch             TEXT NOT NULL,
    workflow_kind           TEXT NOT NULL CHECK (workflow_kind IN ('run','auto','review')),
    engine                  TEXT NOT NULL,
    auth_profile_id         TEXT NOT NULL,
    scope_ref               TEXT NOT NULL,
    status                  TEXT NOT NULL CHECK (status IN ('queued','claimed','running','retrying','succeeded','failed','canceled')),
    attempt_count           INTEGER NOT NULL DEFAULT 0,
    max_attempts            INTEGER NOT NULL DEFAULT 3,
    deadline_at             TIMESTAMPTZ,
    cancel_requested        BOOLEAN NOT NULL DEFAULT FALSE,
    input_snapshot_id       TEXT,
    latest_snapshot_id      TEXT,
    latest_snapshot_version INTEGER NOT NULL DEFAULT 0,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

const runsQueueIndex = `CREATE INDEX IF NOT EXISTS idx_runs_queue ON runs (status, created_at);`

const attemptsSchema = `CREATE TABLE IF NOT EXISTS attempts (
    id               TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs(id),
    attempt_number   INTEGER NOT NULL,
    worker_id        TEXT NOT NULL,
    sandbox_id       TEXT,
    status           TEXT NOT NULL CHECK (status IN ('active','succeeded','failed','canceled')),
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    heartbeat_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    ended_at         TIMESTAMPTZ,
    error_code       TEXT,
    error_message    TEXT
);`

const attemptsRunIDIndex = `CREATE INDEX IF NOT EXISTS idx_attempts_run_id ON attempts (run_id);`
const attemptsStatusIndex = `CREATE INDEX IF NOT EXISTS idx_attempts_status ON attempts (status);`
const attemptsLeaseIndex = `CREATE INDEX IF NOT EXISTS idx_attempts_lease_expires_at ON attempts (lease_expires_at);`
const attemptsOneActiveIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_attempts_one_active_per_run ON attempts (run_id) WHERE status = 'active';`

const eventsSchema = `CREATE TABLE IF NOT EXISTS events (
    id           TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL REFERENCES runs(id),
    attempt_id   TEXT REFERENCES attempts(id),
    event_type   TEXT NOT NULL,
    payload_json TEXT,
    redacted     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

const eventsRunIDCreatedAtIndex = `CREATE INDEX IF NOT EXISTS idx_events_run_id_created_at ON events (run_id, created_at);`

// Postgres uses rules instead of SQLite triggers for immutability.
const eventsPreventUpdate = `CREATE OR REPLACE RULE events_prevent_update AS ON UPDATE TO events DO INSTEAD NOTHING;`
const eventsPreventDelete = `CREATE OR REPLACE RULE events_prevent_delete AS ON DELETE TO events DO INSTEAD NOTHING;`

const idempotencyKeysSchema = `CREATE TABLE IF NOT EXISTS idempotency_keys (
    key              TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs(id),
    side_effect_type TEXT NOT NULL,
    result_ref       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

const authProfilesSchema = `CREATE TABLE IF NOT EXISTS auth_profiles (
    id                    TEXT PRIMARY KEY,
    owner_id              TEXT NOT NULL,
    provider              TEXT NOT NULL,
    mode                  TEXT NOT NULL,
    secret_ref            TEXT,
    status                TEXT NOT NULL CHECK (status IN ('pending_link','linked','invalid','revoked')),
    max_concurrent_runs   INTEGER NOT NULL DEFAULT 1 CHECK (max_concurrent_runs >= 1),
    runtime_metadata_json TEXT,
    last_validated_at     TIMESTAMPTZ,
    expires_at            TIMESTAMPTZ,
    last_error_code       TEXT,
    version               INTEGER NOT NULL DEFAULT 1,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

const authProfileLocksSchema = `CREATE TABLE IF NOT EXISTS auth_profile_locks (
    auth_profile_id  TEXT NOT NULL REFERENCES auth_profiles(id),
    run_id           TEXT NOT NULL REFERENCES runs(id),
    worker_id        TEXT NOT NULL,
    acquired_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    heartbeat_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    released_at      TIMESTAMPTZ
);`

const authProfileLocksLeaseIndex = `CREATE INDEX IF NOT EXISTS idx_auth_profile_locks_lease ON auth_profile_locks (auth_profile_id, lease_expires_at);`
const authProfileLocksOneActiveIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_profile_locks_one_active ON auth_profile_locks (auth_profile_id, run_id) WHERE released_at IS NULL;`

const runStateSnapshotsSchema = `CREATE TABLE IF NOT EXISTS run_state_snapshots (
    id               TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs(id),
    attempt_id       TEXT REFERENCES attempts(id),
    snapshot_kind    TEXT NOT NULL CHECK (snapshot_kind IN ('input','checkpoint','final')),
    version          INTEGER NOT NULL CHECK (version >= 1),
    sha256           TEXT NOT NULL,
    size_bytes       BIGINT NOT NULL,
    content_encoding TEXT NOT NULL,
    content_blob     BYTEA NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`

const runStateSnapshotsRunVersionUniqueIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_run_state_snapshots_run_version ON run_state_snapshots (run_id, version);`
const runStateSnapshotsRunIDCreatedAtIndex = `CREATE INDEX IF NOT EXISTS idx_run_state_snapshots_run_created ON run_state_snapshots (run_id, created_at);`

// schemaStatements returns all DDL statements in dependency order.
func schemaStatements() []string {
	return []string{
		runsSchema,
		runsQueueIndex,
		attemptsSchema,
		attemptsRunIDIndex,
		attemptsStatusIndex,
		attemptsLeaseIndex,
		attemptsOneActiveIndex,
		eventsSchema,
		eventsRunIDCreatedAtIndex,
		eventsPreventUpdate,
		eventsPreventDelete,
		idempotencyKeysSchema,
		authProfilesSchema,
		authProfileLocksSchema,
		authProfileLocksLeaseIndex,
		authProfileLocksOneActiveIndex,
		runStateSnapshotsSchema,
		runStateSnapshotsRunVersionUniqueIndex,
		runStateSnapshotsRunIDCreatedAtIndex,
	}
}
