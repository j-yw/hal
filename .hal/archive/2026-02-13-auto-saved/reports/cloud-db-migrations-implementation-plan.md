# Cloud DB Migrations Implementation Plan (Deferred)

## Status

- Decision: Defer implementation now.
- Reason: No cloud database has been initialized yet.
- Trigger to execute: Before first persistent/shared cloud database is used (CI, staging, production, or teammate-shared environments).

## Executive Summary

This plan upgrades the cloud persistence layer from implicit schema bootstrap-on-open to explicit, auditable, versioned migrations. The target state is:

1. Migration files in-repo are the source of truth.
2. Each database tracks applied versions in a `schema_migrations` table.
3. An explicit CLI command applies migrations (`hal cloud db migrate`).
4. Runtime commands stop mutating schema and fail fast if schema is outdated.

## Current State

- Runtime DB open path (`internal/cloud/deploy/store_factory.go`) calls adapter `Migrate()` automatically.
- Adapter `Migrate()` methods execute `CREATE TABLE IF NOT EXISTS` statements only:
  - `internal/cloud/turso/store.go`
  - `internal/cloud/postgres/store.go`
- No migration history tracking exists.
- No explicit migration command exists.

## Goals

1. Deterministic and auditable schema evolution.
2. Safe first-time DB setup and repeatable upgrades.
3. Idempotent migration execution across environments.
4. Clear operational workflow for local/dev/CI/staging/prod.
5. Minimal operational surprise (no hidden schema changes during normal runtime commands).

## Non-Goals

1. Multi-tenant database isolation redesign.
2. Data model redesign beyond migration framework.
3. Automatic rollback migrations for every future change (roll-forward is primary).

## Target Architecture

## In-Repo Migration Definitions

- New package layout:
  - `internal/cloud/migrate/runner.go`
  - `internal/cloud/migrate/migrations/` (SQL files)
  - `internal/cloud/migrate/embed.go` (embed SQL assets)
- Adapter-specific SQL files where needed:
  - Example: `001_init.turso.sql`, `001_init.postgres.sql`
  - Future: `002_<change>.turso.sql`, `002_<change>.postgres.sql`

## Database Migration State

- Introduce `schema_migrations` table in each DB:
  - `version` (primary key)
  - `checksum` (sha256 of applied SQL payload)
  - `applied_at` (UTC timestamp)
- The table answers: "what did this exact DB apply?"

## Command and Runtime Separation

- New explicit command:
  - `hal cloud db migrate`
- Runtime path behavior (`run/auto/review/cloud status/logs/pull/cancel`):
  - Opens DB.
  - Validates schema is up-to-date.
  - Does **not** apply migrations.
  - Returns actionable error if not current.

## Detailed Design

## Migration Runner API

- `Apply(ctx, db, adapter)`:
  - Ensure `schema_migrations` exists.
  - Read embedded migration set for adapter.
  - Sort by version ascending.
  - For each migration:
    - Skip if version already applied and checksum matches.
    - Fail if version exists with checksum mismatch.
    - Execute in transaction where adapter supports.
    - Insert migration record atomically.
- `ValidateUpToDate(ctx, db, adapter)`:
  - Ensure `schema_migrations` exists.
  - Compare applied versions with embedded latest.
  - Return typed error with next required version if behind.

## Versioning Rules

- Numeric zero-padded versions (`001`, `002`, ...).
- Version uniqueness required.
- No editing of applied migration files.
- New schema change must be append-only as new migration file.

## Adapter Execution Semantics

### Postgres

- Execute each migration inside transaction.
- Optional advisory lock during apply to prevent concurrent migration races:
  - `pg_advisory_lock(hash('hal_cloud_migrations'))`
  - Release on completion/failure.

### Turso/SQLite

- Use `BEGIN IMMEDIATE` transaction for migration apply to avoid concurrent writers.
- Keep migration files SQLite-compatible.

## First Migration Strategy

- `001_init` includes the full current schema including `runs.workflow_kind`.
- For confirmed no-preexisting DBs, this is sufficient.
- Optional compatibility migration (`002_backfill_workflow_kind`) may be added only if legacy DBs are discovered before rollout.

## CLI and Wiring Changes

## New Command

- Add `hal cloud db migrate` in `cmd/`:
  - Resolves cloud deploy config using existing config resolution path.
  - Opens DB via adapter drivers.
  - Calls migration runner `Apply`.
  - Emits concise success/failure summary.

## Runtime Store Opening

- Replace automatic schema mutation on open:
  - Remove/disable adapter `Migrate()` call from `internal/cloud/deploy/store_factory.go`.
  - Add `ValidateUpToDate()` check.
  - Error message:
    - "Database schema is outdated. Run `hal cloud db migrate`."

## Error Contracts

- Add typed errors in migration package:
  - `ErrChecksumMismatch`
  - `ErrSchemaOutdated`
  - `ErrUnknownAppliedVersion`
- Map to user-friendly CLI output and preserve wrapped cause.

## Test Plan

## Unit Tests

1. Runner ordering and skip behavior.
2. Checksum mismatch detection.
3. Partial apply failure handling.
4. Validation behavior for up-to-date and outdated DBs.
5. Adapter-specific SQL selection logic.

## Integration Tests

1. Fresh DB + apply all migrations succeeds.
2. Re-apply is idempotent.
3. Outdated DB causes runtime command fail-fast with actionable message.
4. Concurrent migrate invocations: one wins, second sees up-to-date outcome.
5. Corrupted migration history (checksum drift) fails hard.

## Command Tests

1. `hal cloud db migrate` happy path (human + JSON if applicable).
2. Config/adapter resolution errors.
3. DB connectivity and auth failures.
4. Outdated-runtime guidance message assertions.

## Rollout Plan

1. Land migration framework and command behind normal code path (no runtime behavior flip yet).
2. Add `001_init` migration files for both adapters.
3. Add migration tests and CI target coverage.
4. Flip runtime from auto-migrate to validate-only.
5. Update docs and runbooks:
  - "Before first cloud use: run `hal cloud db migrate`."
6. Tag release and communicate breaking operational change.

## Operational Runbook

## One-Off First Setup (Fresh DB)

1. Configure cloud DB credentials normally.
2. Run:
   - `hal cloud db migrate`
3. Verify:
   - `schema_migrations` exists.
   - Latest version applied.
4. Run normal cloud commands.

## Upgrade Workflow

1. Deploy new binary with added migration files.
2. Run `hal cloud db migrate`.
3. Validate app/runtime commands.
4. Roll forward if issues (add fix migration).

## Risks and Mitigations

1. Risk: Edited migration file after apply.
   - Mitigation: checksum mismatch hard fail.
2. Risk: Concurrent deploys race.
   - Mitigation: DB lock/advisory lock + transactional apply.
3. Risk: Hidden runtime schema mutation persists.
   - Mitigation: enforce validate-only path and tests.
4. Risk: Adapter drift between Turso/Postgres.
   - Mitigation: required adapter-pair migration files and parity tests.

## Acceptance Criteria

1. Fresh DB can be fully initialized using only `hal cloud db migrate`.
2. Re-running migrate is safe and no-op.
3. Runtime commands never apply schema changes.
4. Runtime commands fail with explicit guidance when schema is outdated.
5. CI validates migration runner behavior and adapter parity.
6. Documentation includes setup and upgrade steps.

## Deferred-Now Follow-Up Ticket Template

- Title: "Introduce versioned cloud DB migrations and explicit db migrate command"
- Scope:
  - Create migration runner + schema_migrations table.
  - Add `hal cloud db migrate`.
  - Move runtime to validate-only.
  - Add tests and docs listed in this plan.
- Priority: Must complete before first persistent/shared cloud DB rollout.

## Gap Audit (Plan Self-Verification)

Checklist used to verify this plan is complete:

1. Schema source of truth defined: PASS
2. Applied-state tracking in DB defined: PASS
3. Fresh setup workflow defined: PASS
4. Upgrade workflow defined: PASS
5. Runtime behavior after migration-framework adoption defined: PASS
6. Error behavior and operator guidance defined: PASS
7. Testing scope (unit/integration/command) defined: PASS
8. Adapter-specific concerns (Postgres/Turso) defined: PASS
9. Rollout and runbook steps defined: PASS
10. Risks and mitigations documented: PASS

Conclusion: No structural gaps found for implementation planning. Execution remains deferred per current project decision.
