# PRD: Hal Cloud Daytona Sandbox Orchestration v1

## Introduction/Overview

This PRD defines v1 cloud orchestration for running `hal` workloads in Daytona sandboxes with terminal-only operations. Operators must manage runs from CLI (`submit`, `status`, `logs`, `cancel`) while the control plane enforces correctness under contention, recovers stale attempts, and keeps GitHub side effects idempotent.

v1 is internal and single-tenant first. The prototype defaults to Turso/libSQL for persistence, keeps Postgres parity coverage, and uses a polyglot sandbox boundary: Go control-plane/worker services call a dedicated Daytona runner service implemented in a Daytona-supported SDK language (TypeScript or Python). The run flow is local-authoring + cloud-execution: operators prepare `.hal` locally, upload an allowlisted state bundle with `hal-cloud run`, and workers hydrate/checkpoint that state across sandbox attempts.

## Goals

- Provide terminal-only run lifecycle operations.
- Guarantee 0 duplicate run claims under concurrency tests.
- Guarantee 0 duplicate PR side effects across retries.
- Recover stale attempts to retry-ready state in <30s p95.
- Use Turso/libSQL as the default prototype datastore while preserving Postgres parity tests.
- Support auth profile lifecycle and compatibility checks for headless workers.
- Support local `.hal` authoring with deterministic cloud state bundle upload and restore.
- Keep Daytona SDK coupling isolated behind an internal runner service API.

## User Stories

### US-001: Create runs table
**Description:** As a platform engineer, I want durable run records so orchestration can recover after restarts.

**Acceptance Criteria:**
- [ ] Add runs table with columns id, repo, base_branch, engine, auth_profile_id, scope_ref, status, attempt_count, max_attempts, deadline_at, input_snapshot_id, latest_snapshot_id, latest_snapshot_version, created_at, updated_at.
- [ ] Status allows exactly queued, claimed, running, retrying, succeeded, failed, canceled.
- [ ] Add queue index on (status, created_at).
- [ ] Tests pass
- [ ] Typecheck passes

### US-002: Create attempts table
**Description:** As a platform engineer, I want attempt-level state so heartbeat and retry behavior is explicit.

**Acceptance Criteria:**
- [ ] Add attempts table with columns id, run_id, attempt_number, worker_id, sandbox_id, status, started_at, heartbeat_at, lease_expires_at, ended_at, error_code, error_message.
- [ ] Enforce at most one active attempt per run_id.
- [ ] Add indexes on run_id, status, and lease_expires_at.
- [ ] Tests pass
- [ ] Typecheck passes

### US-003: Create events table
**Description:** As an operator, I want durable run timelines so status and logs commands read authoritative history.

**Acceptance Criteria:**
- [ ] Add events table with columns id, run_id, attempt_id, event_type, payload_json, redacted, created_at.
- [ ] Prevent UPDATE and DELETE on events rows after insert at the database level.
- [ ] Add index on (run_id, created_at).
- [ ] Tests pass
- [ ] Typecheck passes

### US-004: Create idempotency keys table
**Description:** As a platform engineer, I want persisted idempotency keys so retries cannot duplicate external side effects.

**Acceptance Criteria:**
- [ ] Add idempotency_keys table with columns key, run_id, side_effect_type, result_ref, created_at.
- [ ] Enforce unique constraint on key.
- [ ] Duplicate insert path returns deterministic duplicate_key domain error.
- [ ] Tests pass
- [ ] Typecheck passes

### US-005: Create auth profiles table
**Description:** As an operator, I want reusable auth profiles so credentials are linked once and reused by workers.

**Acceptance Criteria:**
- [ ] Add auth_profiles table with columns id, owner_id, provider, mode, secret_ref, status, max_concurrent_runs, runtime_metadata_json, last_validated_at, expires_at, last_error_code, version, created_at, updated_at.
- [ ] Status allows exactly pending_link, linked, invalid, revoked.
- [ ] Enforce max_concurrent_runs >= 1.
- [ ] Tests pass
- [ ] Typecheck passes

### US-006: Create auth profile locks table
**Description:** As a platform engineer, I want lease-based locks so shared subscription sessions are concurrency-safe.

**Acceptance Criteria:**
- [ ] Add auth_profile_locks table with columns auth_profile_id, run_id, worker_id, acquired_at, heartbeat_at, lease_expires_at, released_at.
- [ ] Add index on (auth_profile_id, lease_expires_at).
- [ ] Prevent duplicate active lock rows for the same (auth_profile_id, run_id).
- [ ] Tests pass
- [ ] Typecheck passes

### US-007: Create run state snapshots table
**Description:** As a platform engineer, I want durable .hal state snapshots so retries can restore run context after sandbox loss.

**Acceptance Criteria:**
- [ ] Add run_state_snapshots table with columns id, run_id, attempt_id, snapshot_kind, version, sha256, size_bytes, content_encoding, content_blob, created_at.
- [ ] Enforce unique constraint on (run_id, version).
- [ ] Add index on (run_id, created_at).
- [ ] Tests pass
- [ ] Typecheck passes

### US-008: Define Store interface and domain errors
**Description:** As a backend engineer, I want a single persistence contract so orchestration logic is adapter-agnostic.

**Acceptance Criteria:**
- [ ] Define Store methods for enqueue, claim, transition, attempt heartbeats, events, idempotency, auth profile read/update, lock acquire/renew/release, and snapshot put/get/list-latest.
- [ ] Define shared domain errors not_found, conflict, duplicate_key, lease_expired, invalid_transition.
- [ ] Service layer compiles without adapter-specific imports.
- [ ] Tests pass
- [ ] Typecheck passes

### US-009: Add adapter contract test suite skeleton
**Description:** As a platform engineer, I want adapter-neutral tests so correctness rules are defined once.

**Acceptance Criteria:**
- [ ] Add contract tests for enqueue, atomic claim, one-active-attempt invariant, heartbeat renew, and transition guards.
- [ ] Add parallel claim test that asserts one winner per run.
- [ ] Test suite accepts adapter factory injection via newStoreForTest.
- [ ] Tests pass
- [ ] Typecheck passes

### US-010: Implement Postgres enqueue and claim operations
**Description:** As a backend engineer, I want Postgres run-claim primitives so workers can safely pick work.

**Acceptance Criteria:**
- [ ] Implement Postgres methods for run enqueue and atomic claim.
- [ ] Claim SQL guarantees one winner under parallel worker contention.
- [ ] Add focused tests for enqueue and one-winner claim behavior.
- [ ] Tests pass
- [ ] Typecheck passes

### US-011: Implement Postgres auth lock lease operations
**Description:** As a backend engineer, I want Postgres lock primitives so auth profile concurrency is enforceable.

**Acceptance Criteria:**
- [ ] Implement Postgres methods for auth lock acquire, renew, and release.
- [ ] Renew operation fails when lease is expired according to lease semantics.
- [ ] Add focused tests for lock acquisition conflict and stale-lock reclaim.
- [ ] Tests pass
- [ ] Typecheck passes

### US-012: Implement Turso enqueue and claim operations
**Description:** As a backend engineer, I want Turso run-claim primitives so workers can safely pick work.

**Acceptance Criteria:**
- [ ] Implement Turso methods for run enqueue and atomic claim.
- [ ] Claim behavior matches one-winner semantics under contention.
- [ ] Add focused tests for enqueue and one-winner claim behavior.
- [ ] Tests pass
- [ ] Typecheck passes

### US-013: Implement Turso auth lock lease operations
**Description:** As a backend engineer, I want Turso lock primitives so auth profile concurrency is enforceable.

**Acceptance Criteria:**
- [ ] Implement Turso methods for auth lock acquire, renew, and release.
- [ ] Renew operation enforces lease-expiry semantics.
- [ ] Add focused tests for lock acquisition conflict and stale-lock reclaim.
- [ ] Tests pass
- [ ] Typecheck passes

### US-014: Run parity benchmark harness for both adapters
**Description:** As a platform owner, I want comparable adapter metrics so default database choice is evidence-based.

**Acceptance Criteria:**
- [ ] Harness executes claim_contention and auth_lock_contention scenarios for both Postgres and Turso adapters.
- [ ] Harness output JSON uses exactly keys scenario, adapter, runs, errors, claim_p95_ms, heartbeat_p95_ms, duplicate_claims, lock_overcommit_violations.
- [ ] Generate a report artifact for each adapter run.
- [ ] Tests pass
- [ ] Typecheck passes

### US-015: Implement control-plane operator auth middleware
**Description:** As a platform owner, I want authenticated API access so only authorized operators can manage runs.

**Acceptance Criteria:**
- [ ] Middleware validates bearer JWT tokens using configured issuer and audience.
- [ ] Middleware validates PAT tokens using configured allowlist.
- [ ] Unauthorized requests return HTTP 401 with error code unauthorized.
- [ ] Tests pass
- [ ] Typecheck passes

### US-016: Implement submit validation and enqueue
**Description:** As an operator, I want invalid runs rejected before queueing.

**Acceptance Criteria:**
- [ ] Validate required fields repo, base_branch, engine, auth_profile_id, and scope_ref.
- [ ] Reject auth profiles not in linked status and reject engine/provider mismatches.
- [ ] Apply provider allow/deny policy before creating queued run.
- [ ] Tests pass
- [ ] Typecheck passes

### US-017: Implement atomic claim and lock acquisition transaction
**Description:** As a worker, I want ownership acquisition to be all-or-nothing.

**Acceptance Criteria:**
- [ ] Single transaction transitions one eligible run to claimed and creates an attempt row.
- [ ] Same transaction acquires auth lock lease.
- [ ] If lock acquisition fails, run claim and attempt creation are rolled back.
- [ ] Tests pass
- [ ] Typecheck passes

### US-018: Implement heartbeat renewals
**Description:** As a worker, I want lease renewals so healthy attempts are not reclaimed.

**Acceptance Criteria:**
- [ ] Heartbeat updates attempts.heartbeat_at and extends attempts.lease_expires_at.
- [ ] Heartbeat updates auth lock heartbeat_at and extends lock lease_expires_at.
- [ ] Lease-loss emits lease_lost terminal event and marks the attempt terminal.
- [ ] Tests pass
- [ ] Typecheck passes

### US-019: Implement stale-attempt reconciler
**Description:** As an operator, I want stale attempts detected and closed automatically.

**Acceptance Criteria:**
- [ ] Reconciler scans active attempts where lease_expires_at is earlier than current time.
- [ ] Reconciler marks stale attempt terminal with error_code stale_attempt.
- [ ] Reconciler releases stale auth lock lease.
- [ ] Tests pass
- [ ] Typecheck passes

### US-020: Implement retry scheduler with backoff
**Description:** As an operator, I want deterministic retry transitions for retryable failures.

**Acceptance Criteria:**
- [ ] Retry policy supports configurable max_attempts and exponential backoff.
- [ ] Retry-eligible runs transition failed to retrying to queued.
- [ ] Runs beyond max_attempts remain terminal failed.
- [ ] Tests pass
- [ ] Typecheck passes

### US-021: Implement hard-timeout enforcement
**Description:** As an operator, I want overdue runs terminated automatically.

**Acceptance Criteria:**
- [ ] Submit sets deadline_at using default or policy timeout value.
- [ ] Reconciler marks runs past deadline_at as failed with error_code run_timeout.
- [ ] Timeout transition emits run_timeout event.
- [ ] Tests pass
- [ ] Typecheck passes

### US-022: Enforce cancellation propagation and claim exclusion
**Description:** As an operator, I want cancellation intent enforced by workers and scheduler logic.

**Acceptance Criteria:**
- [ ] Worker loop checks cancel intent every heartbeat interval and marks active attempt canceled when cancel is set.
- [ ] Claim query excludes runs in terminal canceled state.
- [ ] Retry scheduler skips runs marked canceled.
- [ ] Tests pass
- [ ] Typecheck passes

### US-023: Enforce revoked-profile renewal denial
**Description:** As an operator, I want revoked profiles unusable by active workers.

**Acceptance Criteria:**
- [ ] Lock renew fails with profile_revoked when auth profile state is revoked.
- [ ] Worker receiving profile_revoked marks the attempt failed and releases lock.
- [ ] Integration test covers revoke-during-run behavior.
- [ ] Tests pass
- [ ] Typecheck passes

### US-024: Add Daytona runner API client abstraction in Go
**Description:** As a backend engineer, I want a runner interface so Go services are decoupled from Daytona SDK language constraints.

**Acceptance Criteria:**
- [ ] Define Go interface methods CreateSandbox, Exec, StreamLogs, DestroySandbox, and Health.
- [ ] Worker sandbox lifecycle code depends only on the interface and imports no Daytona SDK packages.
- [ ] Client sends X-Service-Token header on every runner API request.
- [ ] Tests pass
- [ ] Typecheck passes

### US-025: Implement Daytona runner create and destroy endpoints
**Description:** As a platform engineer, I want sandbox lifecycle endpoints isolated in a runner service.

**Acceptance Criteria:**
- [ ] Runner service is implemented in TypeScript or Python and uses official Daytona SDK calls for sandbox create and destroy.
- [ ] Expose internal endpoints POST /sandboxes and DELETE /sandboxes/{id}.
- [ ] Missing or invalid service token returns HTTP 401.
- [ ] Tests pass
- [ ] Typecheck passes

### US-026: Implement Daytona runner exec and logs endpoints
**Description:** As a platform engineer, I want execution and log streaming endpoints isolated in the runner service.

**Acceptance Criteria:**
- [ ] Runner service uses official Daytona SDK calls for command execution and log streaming.
- [ ] Expose internal endpoints POST /sandboxes/{id}/exec and GET /sandboxes/{id}/logs.
- [ ] Exec endpoint returns command exit status and logs endpoint streams ordered output chunks.
- [ ] Tests pass
- [ ] Typecheck passes

### US-027: Implement sandbox provisioning
**Description:** As a worker, I want deterministic sandbox creation so each attempt has isolated runtime.

**Acceptance Criteria:**
- [ ] Provision Daytona sandbox by calling internal runner API with configured template or image.
- [ ] Persist sandbox_id on the attempt row.
- [ ] Emit sandbox_created and sandbox_ready events.
- [ ] Tests pass
- [ ] Typecheck passes

### US-028: Implement sandbox teardown workflow
**Description:** As a worker, I want teardown to always run on terminal paths.

**Acceptance Criteria:**
- [ ] Emit teardown_started event before teardown call.
- [ ] Execute teardown via runner API on both success and failure terminal paths.
- [ ] Emit teardown_done event after teardown completes.
- [ ] Tests pass
- [ ] Typecheck passes

### US-029: Implement bootstrap setup steps
**Description:** As a worker, I want deterministic environment setup before Hal execution.

**Acceptance Criteria:**
- [ ] Clone or fetch repository and checkout target branch before execution.
- [ ] Run hal init in sandbox before Hal execution starts.
- [ ] Clone or init failure emits bootstrap_failed and stops the attempt.
- [ ] Tests pass
- [ ] Typecheck passes

### US-030: Implement Hal execution runner
**Description:** As a worker, I want a controlled execution step so run mode is explicit.

**Acceptance Criteria:**
- [ ] Support execution modes until_complete and bounded_batch.
- [ ] Persist execution start and finish events including selected mode.
- [ ] Capture command exit status for failure classification input.
- [ ] Tests pass
- [ ] Typecheck passes

### US-031: Implement failure classifier
**Description:** As an operator, I want consistent failure codes for retry decisions.

**Acceptance Criteria:**
- [ ] Define failure codes bootstrap_failed, auth_invalid, policy_blocked, stale_attempt, run_timeout, and non_retryable.
- [ ] Implement pure classification helper that maps each code to retryable or terminal outcome.
- [ ] Unit tests cover every classifier code and expected retryability.
- [ ] Tests pass
- [ ] Typecheck passes

### US-032: Implement auth materialization with least-privilege permissions
**Description:** As a platform engineer, I want worker credential materialization to be secure by default.

**Acceptance Criteria:**
- [ ] Materialize auth artifacts from secret_ref only at runtime.
- [ ] Create auth directories with mode 0700 and files with mode 0600.
- [ ] Remove materialized files during teardown path.
- [ ] Tests pass
- [ ] Typecheck passes

### US-033: Implement provider preflight and compatibility checks
**Description:** As a platform engineer, I want headless validation before Hal execution.

**Acceptance Criteria:**
- [ ] Execute provider-specific non-interactive preflight command before run step.
- [ ] Validate runtime metadata compatibility including OS, architecture, and CLI major/minor version.
- [ ] Metadata incompatibility fails with error code auth_profile_incompatible.
- [ ] Tests pass
- [ ] Typecheck passes

### US-034: Implement credential writeback with version checks
**Description:** As a platform engineer, I want refreshed credentials persisted safely.

**Acceptance Criteria:**
- [ ] Detect changed auth artifacts and write back encrypted secret via Auth Broker.
- [ ] Writeback uses optimistic version check on auth_profiles.version.
- [ ] Successful writeback updates last_validated_at and expires_at and clears last_error_code.
- [ ] Tests pass
- [ ] Typecheck passes

### US-035: Implement deterministic redaction rule engine
**Description:** As an operator, I want deterministic masking so secret handling is testable.

**Acceptance Criteria:**
- [ ] Implement explicit masking rules for bearer tokens, GitHub PATs, device codes, session cookies, and API keys.
- [ ] Fixture-based unit tests verify expected masked output for each rule.
- [ ] Mask replacement format is exactly [REDACTED].
- [ ] Tests pass
- [ ] Typecheck passes

### US-036: Integrate redaction into persistence and streaming pipelines
**Description:** As an operator, I want every log path redacted before visibility.

**Acceptance Criteria:**
- [ ] Apply redaction before writing bootstrap, preflight, runtime, and error events.
- [ ] Apply identical redaction before streaming logs to CLI.
- [ ] Integration tests confirm no raw fixture secret appears in DB rows or CLI stream output.
- [ ] Tests pass
- [ ] Typecheck passes

### US-037: Implement idempotent PR create side effect
**Description:** As an operator, I want retries to reuse PR creation results.

**Acceptance Criteria:**
- [ ] PR creation uses deterministic idempotency key.
- [ ] Existing key returns stored PR reference without making external create call.
- [ ] Retry test verifies exactly one external PR create call.
- [ ] Tests pass
- [ ] Typecheck passes

### US-038: Implement idempotent PR update and comment side effects
**Description:** As an operator, I want retries to avoid duplicate PR follow-up actions.

**Acceptance Criteria:**
- [ ] PR update and comment actions use deterministic idempotency keys.
- [ ] Existing key returns stored result without duplicate external call.
- [ ] Retry test verifies no duplicate comment or update side effects.
- [ ] Tests pass
- [ ] Typecheck passes

### US-039: Define .hal state bundle manifest
**Description:** As a platform engineer, I want a deterministic bundle contract so local state uploads are reproducible.

**Acceptance Criteria:**
- [ ] Allowlist paths are exactly .hal/prd.json, .hal/auto-prd.json, .hal/progress.txt, .hal/prompt.md, .hal/config.yaml, and .hal/standards/**.
- [ ] Denylist includes .hal/archive/**, .hal/reports/**, .hal/skills/**, .hal/commands/**, .pi/**, .claude/**, and ~/.codex/**.
- [ ] Bundle hash uses SHA-256 over sorted path plus content-byte records with normalized paths.
- [ ] Tests pass
- [ ] Typecheck passes

### US-040: Implement bundle ingestion and input snapshot persistence
**Description:** As an operator, I want submitted state captured durably so execution can start from local planning context.

**Acceptance Criteria:**
- [ ] Submit accepts bundle payload and manifest and stores snapshot with snapshot_kind input and version 1.
- [ ] Submit sets runs.input_snapshot_id and runs.latest_snapshot_id to the saved snapshot.
- [ ] Manifest hash mismatch is rejected with error code bundle_hash_mismatch.
- [ ] Tests pass
- [ ] Typecheck passes

### US-041: Persist checkpoint and final state snapshots
**Description:** As an operator, I want run state checkpoints so retries and follow-up local work can resume.

**Acceptance Criteria:**
- [ ] Worker stores snapshot_kind checkpoint after each completed story transition.
- [ ] Worker stores snapshot_kind final on terminal states succeeded, failed, and canceled.
- [ ] Snapshot version increases monotonically per run and updates runs.latest_snapshot_id and runs.latest_snapshot_version.
- [ ] Tests pass
- [ ] Typecheck passes

### US-042: Add hal-cloud submit command
**Description:** As an operator, I want a clear submit command response for automation and human use.

**Acceptance Criteria:**
- [ ] Support flags --repo, --base, --engine, --auth-profile, and --scope.
- [ ] Default output includes run_id, status, engine, auth_profile, and submitted_at.
- [ ] --json output returns machine-readable error codes on validation failures.
- [ ] Tests pass
- [ ] Typecheck passes

### US-043: Add hal-cloud status command
**Description:** As an operator, I want quick visibility into run progress and health.

**Acceptance Criteria:**
- [ ] Human-readable output includes run_id, status, attempt_count, max_attempts, current_attempt, last_heartbeat_age, and deadline_at.
- [ ] --json output contains exactly run_id, status, attempt_count, max_attempts, current_attempt, last_heartbeat_age_seconds, deadline_at, engine, auth_profile_id.
- [ ] Unknown run_id exits non-zero and returns error code not_found.
- [ ] Tests pass
- [ ] Typecheck passes

### US-044: Add hal-cloud logs command
**Description:** As an operator, I want historical and live run logs from terminal.

**Acceptance Criteria:**
- [ ] logs <run-id> returns events ordered by ascending timestamp.
- [ ] logs <run-id> --follow streams new events until interrupted.
- [ ] Output never includes unredacted fixture secret tokens.
- [ ] Tests pass
- [ ] Typecheck passes

### US-045: Add hal-cloud cancel command
**Description:** As an operator, I want to request cancellation from terminal with clear feedback.

**Acceptance Criteria:**
- [ ] cancel <run-id> sets cancel intent and returns current cancel state.
- [ ] --json output contains exactly run_id, cancel_requested, status, canceled_at.
- [ ] Unknown run_id exits non-zero with error code not_found.
- [ ] Tests pass
- [ ] Typecheck passes

### US-046: Add hal-cloud run command
**Description:** As an operator, I want one command that uploads local .hal state and submits a cloud run.

**Acceptance Criteria:**
- [ ] run packages allowlisted .hal files into a compressed bundle and computes manifest hash.
- [ ] run calls submit API with bundle payload and returns run_id, status, and bundle_hash.
- [ ] run --dry-run prints included file paths and total bytes without network requests.
- [ ] Tests pass
- [ ] Typecheck passes

### US-047: Add hal-cloud pull command
**Description:** As an operator, I want to pull final state back locally so post-run iteration can continue on my machine.

**Acceptance Criteria:**
- [ ] pull <run-id> downloads latest final snapshot and restores allowlisted files under .hal/.
- [ ] Command refuses overwrite when local target files changed unless --force is provided.
- [ ] Command prints restored snapshot version and sha256.
- [ ] Tests pass
- [ ] Typecheck passes

### US-048: Add hal-cloud auth link command
**Description:** As an operator, I want interactive profile linking outside worker sandboxes.

**Acceptance Criteria:**
- [ ] auth link --provider --profile initiates provider flow from operator environment.
- [ ] Successful link stores encrypted secret reference.
- [ ] Command emits audit event including provider and profile ID.
- [ ] Tests pass
- [ ] Typecheck passes

### US-049: Add hal-cloud auth import command
**Description:** As an operator, I want to import local authenticated artifacts when interactive link is unavailable.

**Acceptance Criteria:**
- [ ] auth import --provider --profile --source reads local auth artifacts.
- [ ] Imported artifacts are encrypted and stored as secret reference.
- [ ] Import path records audit event with profile ID and provider.
- [ ] Tests pass
- [ ] Typecheck passes

### US-050: Add hal-cloud auth status command
**Description:** As an operator, I want profile readiness visibility.

**Acceptance Criteria:**
- [ ] auth status <profile> shows provider, profile state, lock owner, lock expiry, and compatibility summary.
- [ ] Missing profile exits non-zero with error code not_found.
- [ ] --json output contains exactly profile_id, provider, status, lock_owner_run_id, lock_lease_expires_at, runtime_metadata, last_validated_at, expires_at, last_error_code.
- [ ] Tests pass
- [ ] Typecheck passes

### US-051: Add hal-cloud auth validate command
**Description:** As an operator, I want explicit profile validation before submit.

**Acceptance Criteria:**
- [ ] auth validate <profile> runs provider validation checks.
- [ ] Success updates last_validated_at and failure sets last_error_code.
- [ ] Failure exits non-zero with auth_invalid or auth_profile_incompatible.
- [ ] Tests pass
- [ ] Typecheck passes

### US-052: Add hal-cloud auth revoke command
**Description:** As an operator, I want fast profile revocation for compromised credentials.

**Acceptance Criteria:**
- [ ] auth revoke <profile> transitions profile status to revoked.
- [ ] Command emits audit event including profile ID and provider.
- [ ] Missing profile exits non-zero with error code not_found.
- [ ] Tests pass
- [ ] Typecheck passes

### US-053: Add Turso-first deployment profile
**Description:** As a platform engineer, I want a repeatable prototype deployment so the team can run control plane, worker, and runner consistently.

**Acceptance Criteria:**
- [ ] Provide deployment definition for control-plane, worker, and daytona-runner services with explicit env vars HAL_CLOUD_DB_ADAPTER, HAL_CLOUD_TURSO_URL, HAL_CLOUD_TURSO_AUTH_TOKEN, HAL_CLOUD_RUNNER_URL, and HAL_CLOUD_RUNNER_SERVICE_TOKEN.
- [ ] Default datastore adapter is turso and service startup fails fast when Turso URL or token is missing.
- [ ] Include smoke check command that verifies control-plane and runner health endpoints return HTTP 200.
- [ ] Tests pass
- [ ] Typecheck passes

## Functional Requirements

- FR-1: CLI lifecycle commands MUST include `submit`, `status`, `logs`, `cancel`, plus convenience commands `run` and `pull`.
- FR-2: Run lifecycle state MUST be durable and use `queued|claimed|running|retrying|succeeded|failed|canceled`.
- FR-3: Claim-next-run MUST be atomic under concurrent workers.
- FR-4: System MUST enforce at most one active attempt per run.
- FR-5: Attempts MUST use heartbeat + lease timeout semantics.
- FR-6: Retry policy MUST support max attempts and exponential backoff.
- FR-7: Runs MUST enforce hard timeout via `deadline_at`.
- FR-8: Worker pipeline MUST include Daytona provision, bootstrap, Hal execution, and teardown.
- FR-9: PR side effects MUST be idempotent.
- FR-10: Events/logs MUST be queryable by run ID.
- FR-11: Redaction MUST execute before persistence and before stream output.
- FR-12: Storage MUST support interchangeable Postgres and Turso adapters.
- FR-13: Both adapters MUST pass shared contract tests.
- FR-14: Runs MUST bind to one auth profile.
- FR-15: Auth profiles MUST support states `pending_link|linked|invalid|revoked`.
- FR-16: Submit MUST reject profiles not in `linked` state.
- FR-17: Worker auth materialization MUST use least-privilege file permissions.
- FR-18: Worker MUST run provider non-interactive preflight checks.
- FR-19: Worker MUST NOT run interactive browser auth.
- FR-20: Auth profile concurrency MUST use lease-based locks with stale lock recovery.
- FR-21: Submit MUST enforce provider/engine compatibility and provider policy rules.
- FR-22: Auth command set MUST include `link|import|status|validate|revoke`.
- FR-23: Credential writeback MUST be encrypted and version-safe.
- FR-24: v1 MUST be operable fully from terminal without dashboard.
- FR-25: Cancel intent MUST propagate to active workers within one heartbeat interval.
- FR-26: Revoked auth profiles MUST not renew active lock leases.
- FR-27: Turso/libSQL MUST be the default datastore for v1 prototype deployments.
- FR-28: Go control-plane/worker services MUST call Daytona through an internal runner API implemented in TypeScript or Python.
- FR-29: `hal-cloud run` MUST upload an allowlisted `.hal` state bundle with deterministic manifest hash.
- FR-30: Worker bootstrap MUST run `hal init` in sandbox before applying uploaded `.hal` state.
- FR-31: Uploaded bundle restore MUST exclude `.pi/`, `.claude/`, and `~/.codex/` symlink trees.
- FR-32: System MUST persist input/checkpoint/final run state snapshots and support restore from latest snapshot.
- FR-33: CLI MUST provide `hal-cloud pull` to restore final state snapshot into local `.hal/` files.
- FR-34: Control-plane operator APIs MUST require JWT or PAT authentication.
- FR-35: Worker-to-runner calls MUST require service token authentication.

## Non-Goals

- Web dashboard UI in v1.
- Multi-tenant RBAC, billing, and quota systems.
- Temporal migration in v1.
- DB-native replacement of `.hal` local file workflow in v1.
- Long-term full token-stream storage in relational DB.
- Mobile-native app experience in v1.
- GitLab provider support in v1.

## Design Considerations

- Keep operator workflow terminal-first and scriptable.
- Preserve local authoring (`hal init/plan/convert/review`) and use cloud execution via bundle upload.
- Use reconciler loops for stale attempts, stale locks, retries, and timeout enforcement.
- Keep DB as orchestration truth; store large artifacts outside DB with references.
- Use explicit machine-readable error codes for automation.
- Keep interactive auth out of worker sandboxes.
- Recreate skills/commands in-sandbox with `hal init` instead of copying symlink directories from clients.
- Keep Daytona SDK logic isolated in a dedicated runner service boundary.

## Technical Considerations

- Atomic claim and lock acquisition require DB-specific concurrency-safe SQL.
- Lease renew interval should be less than lease TTL (example: 10s renew, 30s TTL).
- Teardown and lock release hooks must execute on every terminal path.
- Policy registry should map provider + mode to allow/deny and expected preflight command.
- Bundle manifest hashing must be deterministic across operating systems (path normalization + sorted records).
- Snapshot persistence in Turso should use compressed payloads and enforce size guardrails per run.
- Runner API authentication should use rotated service tokens over private network transport.
- Benchmark harness must include auth lock contention in addition to run claim contention.

## Success Metrics

- 0 duplicate run claims in stress tests.
- 0 duplicate PR side effects in retry tests.
- <30s p95 stale recovery latency.
- 100% deadline-exceeded runs transition to `failed/run_timeout`.
- 0 secret leaks in redaction integration fixtures.
- `hal-cloud run` bundle hash verification failures are detected 100% with `bundle_hash_mismatch` response.
- Snapshot restore success rate from latest checkpoint to new attempt is >=99% in integration tests.
- Daytona runner health endpoint availability is >=99.9% during load tests.
- Postgres and Turso both pass shared contract tests.

## Open Questions

- Initial target concurrency: 10, 50, or 100 active runs?
- Default run mode: `--until-complete` or bounded batches?
- Git mode in v1: HTTPS only or optional SSH?
- Snapshot size limit per run for Turso prototype: 5 MB, 20 MB, or 50 MB?
- Snapshot checkpoint cadence: per story only, or plus fixed interval checkpoints?
- Operator auth provider for v1: GitHub OIDC only, or support Google/Okta from day one?
- Is operator-local auth link enough for v1, or is a dedicated auth-link runner needed?
- Credential writeback policy: always-on or provider-specific opt-in?
