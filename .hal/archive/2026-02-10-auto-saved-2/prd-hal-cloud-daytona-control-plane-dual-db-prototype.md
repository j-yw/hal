# PRD: Hal Cloud Control Plane (Daytona + Dual-DB Prototype)

## Introduction / Overview

Hal is evolving from a local CLI workflow into a cloud execution platform where coding agents run in Daytona sandboxes with GitHub access, repository context, and project configuration preloaded. The desired operator flow is:

1. Submit work intent (repo + branch + PRD/task scope)
2. Let Hal orchestrate autonomous coding in cloud sandboxes
3. Review resulting PR(s)

To support resilient orchestration (retries, restarts, crash recovery, cancellation, and auditability), we need a durable control-plane state model. This PRD defines a **single control-plane architecture** with **pluggable storage adapters** and validates two database options:

- **Postgres adapter**
- **Turso/libSQL adapter**

The objective is not to build two products, but one codebase with shared semantics and a measured backend decision.

## Goals

1. Build a cloud control plane that can reliably orchestrate Hal runs in Daytona sandboxes.
2. Implement one storage abstraction with two adapters (Postgres, Turso/libSQL).
3. Prove orchestration correctness under contention (no duplicate run claims, idempotent PR creation).
4. Measure real workload characteristics (claims, heartbeats, retries, state transitions) and select a default DB using explicit pass/fail criteria.
5. Keep v1 operator UX simple: submit job, monitor status/logs, cancel, review PR.

## User Stories

### US-001: Submit cloud run
**Description:** As an operator, I want to submit a Hal cloud run for a repository and branch target so work begins without manual sandbox setup.

**Acceptance Criteria:**
- [ ] CLI/API can create a run with repo URL, base branch, engine choice, and task scope reference
- [ ] Run is persisted with `queued` status
- [ ] Run ID is returned immediately
- [ ] Typecheck passes

### US-002: Reliable claim and execution
**Description:** As a worker, I want to atomically claim the next queued run so two workers never execute the same run attempt.

**Acceptance Criteria:**
- [ ] Claim operation is atomic and concurrency-safe
- [ ] At most one active attempt exists per run at any time
- [ ] Duplicate claims are rejected/prevented in both adapters
- [ ] Typecheck passes

### US-003: Recover from worker/sandbox failure
**Description:** As the control plane, I want failed or stale attempts to be retried automatically so runs complete despite transient failures.

**Acceptance Criteria:**
- [ ] Workers send periodic heartbeats for active attempts
- [ ] Reconciler marks expired leases as `stale` and requeues run when retries remain
- [ ] Retry policy is configurable (max attempts + backoff)
- [ ] Typecheck passes

### US-004: Idempotent PR side effects
**Description:** As an operator, I want PR creation and external GitHub side effects to be idempotent so retries do not create duplicate PRs/comments.

**Acceptance Criteria:**
- [ ] PR creation uses idempotency key persisted in storage
- [ ] Replayed attempts do not create duplicate PRs
- [ ] External side-effect status is queryable by run ID
- [ ] Typecheck passes

### US-005: Observe and control runs
**Description:** As an operator, I want status, events, and cancellation controls so I can safely operate autonomous execution at scale.

**Acceptance Criteria:**
- [ ] CLI/API supports `submit`, `status`, `logs`, `cancel`
- [ ] Run timeline events are persisted and queryable
- [ ] Cancellation transitions active attempts to terminal state and prevents new claims
- [ ] Typecheck passes

### US-006: Decide default DB from evidence
**Description:** As a platform owner, I want benchmark and correctness results for both adapters so we can select a default backend confidently.

**Acceptance Criteria:**
- [ ] Same workload harness runs unchanged against Postgres and Turso adapters
- [ ] Decision report includes correctness, latency, failure rate, ops complexity, and cost
- [ ] Default backend recommendation is documented with rollback/migration plan
- [ ] Typecheck passes

### US-007: Persist auth profile and lock state for headless execution
**Description:** As a control-plane owner, I want durable auth profile metadata and lock state so subscription-auth runs are safe under concurrency.

**Acceptance Criteria:**
- [ ] Runs persist `auth_profile_id` and enforce profile existence/policy at submit time
- [ ] Auth profile lock acquisition is concurrency-safe and enforces max-concurrency rules
- [ ] Stale auth locks can be detected and reclaimed safely
- [ ] Typecheck passes

## Functional Requirements

- **FR-1:** The control plane MUST persist run lifecycle state durably (`queued`, `claimed`, `running`, `retrying`, `succeeded`, `failed`, `canceled`).
- **FR-2:** Claim-next-run MUST be atomic and prevent double-claim under concurrent workers.
- **FR-3:** The system MUST enforce at most one active attempt per run.
- **FR-4:** Active attempts MUST update heartbeats; stale attempts MUST be detectable via lease timeout.
- **FR-5:** Retry behavior MUST support capped retries and exponential backoff.
- **FR-6:** External side effects (PR creation, status comments) MUST be idempotent.
- **FR-7:** Storage layer MUST be interface-driven with interchangeable Postgres and Turso adapters.
- **FR-8:** Both adapters MUST satisfy the same contract tests.
- **FR-9:** The system MUST expose run submission, status retrieval, event listing, and cancellation.
- **FR-10:** Daytona worker execution MUST be resumable via persisted control-plane state (new sandbox can continue same run).
- **FR-11:** Operational events MUST be persisted (coarse-grained lifecycle events, not full token stream).
- **FR-12:** Secrets for GitHub/SSH access MUST be short-lived and never persisted in plaintext DB columns.
- **FR-13:** Runs MUST bind to an `auth_profile_id` for engine credential resolution in subscription mode.
- **FR-14:** Control-plane storage MUST persist auth profile metadata and secret references (never plaintext token material).
- **FR-15:** Auth profile concurrency control MUST use lease-based locks with stale-lock recovery semantics.
- **FR-16:** Adapter contract tests MUST include auth profile + lock behavior parity across Postgres and Turso.
- **FR-17:** Auth profile status transitions (`pending_link|linked|invalid|revoked`) MUST be validated consistently by both adapters.

## Non-Goals

- Building a full web dashboard in v1 (CLI/API first).
- Multi-tenant billing, quotas, and enterprise RBAC in v1.
- Long-term archival of full raw model output in DB (use object storage/log sink instead).
- Replacing Hal’s local CLI workflow.
- Implementing Temporal in this phase.

## Design Considerations

- Keep user-facing flow minimal and familiar:
  - `hal cloud submit`
  - `hal cloud status <run-id>`
  - `hal cloud logs <run-id>`
  - `hal cloud cancel <run-id>`
  - `hal cloud auth link|import|status|validate|revoke`
- Treat Git branch and PRD progress as execution artifacts; treat DB as orchestration truth.
- Prefer a reconciler pattern (periodic scan + repair) over tightly coupled long-lived in-memory state.

## Technical Considerations

### A. High-level architecture

1. **Control API**: receives run requests, returns run IDs.
2. **Scheduler/Dispatcher**: selects queued runs and hands off to workers (pull-claim model preferred).
3. **Worker**: provisions Daytona sandbox, injects short-lived credentials, executes Hal batch/flow.
4. **Reconciler**: detects stale attempts (heartbeat TTL exceeded), retries or terminally fails runs.
5. **Store Adapter**: common interface implemented by Postgres and Turso.
6. **Artifact storage**: logs/reports pointers (object store or durable file path), not large blobs in DB.
7. **Auth Broker**: manages linked provider credential references, profile validation metadata, and lock lifecycle hooks.

### B. Data model (logical)

- `runs`
  - `id`, `repo`, `base_branch`, `engine`, `auth_profile_id`, `scope_ref`, `status`, `created_at`, `updated_at`, `attempt_count`, `max_attempts`
- `attempts`
  - `id`, `run_id`, `worker_id`, `sandbox_id`, `status`, `started_at`, `heartbeat_at`, `ended_at`, `error_code`, `error_message`
- `events`
  - `id`, `run_id`, `attempt_id?`, `event_type`, `payload_json`, `created_at`
- `idempotency_keys`
  - `key`, `run_id`, `side_effect_type`, `result_ref`, `created_at`
- `auth_profiles`
  - `id`, `owner_id`, `provider`, `mode`, `secret_ref`, `status` (`pending_link|linked|invalid|revoked`), `max_concurrent_runs`, `runtime_metadata_json`, `last_validated_at`, `expires_at`, `updated_at`
- `auth_profile_locks`
  - `auth_profile_id`, `run_id`, `acquired_at`, `heartbeat_at`, `lease_expires_at`, `released_at`

### C. Expected write patterns (why this matters)

Control-plane writes are small but coordination-critical:
- run enqueue
- atomic claim
- attempt start
- heartbeat updates every 10–30s
- state transitions and retries
- idempotency key upserts for PR side effects
- auth profile lock acquire/renew/release operations
- auth profile validation/writeback metadata updates

These writes determine correctness; performance evaluation must focus on contention behavior, not payload size.

### D. Adapter strategy

Implement one `Store` interface and run shared contract tests against both backends.

Example interface scope:
- EnqueueRun
- ClaimNextRun (atomic)
- StartAttempt
- HeartbeatAttempt
- CompleteAttempt
- TransitionRun
- RecordEvent
- PutIdempotencyKey / GetIdempotencyKey
- GetAuthProfile / UpdateAuthProfile
- AcquireAuthProfileLock / RenewAuthProfileLock / ReleaseAuthProfileLock

### E. Benchmark and decision gate

Run identical workload harness against both adapters at concurrency tiers (10, 50, 100 workers):

**Correctness gates (must pass):**
- 0 duplicate claims
- 0 invalid state transitions
- 0 duplicate PR side effects with retries
- 0 auth profile lock-overcommit violations under contention

**Performance targets:**
- claim p95 < 100ms at target concurrency
- heartbeat p95 < 50ms
- reconciler recovery of stale attempts < 30s

**Operational criteria:**
- setup complexity
- observability quality
- failure recovery complexity
- projected monthly cost

Default DB is selected only after both correctness and operational criteria are reviewed.

## Success Metrics

1. ≥ 99% of runs that experience transient worker failure recover automatically without manual intervention.
2. 0 duplicate run claims in stress test suites.
3. 0 duplicate PR creation side effects in retry tests.
4. Mean time to recover stale attempt < 30s.
5. Operator can complete submit→status→cancel workflow entirely from CLI/API.
6. Documented default DB choice with migration plan for alternate backend.
7. 0 auth profile concurrency lock violations in stress/contract tests.

## Open Questions

1. Initial production concurrency target (e.g., 10 vs 50 vs 100 concurrent active runs)?
2. Should v1 support only GitHub, or GitLab support now as well?
3. Preferred artifact storage for logs/reports (S3/R2/local) for v1?
4. Should run execution use one long-lived sandbox per run or hybrid reuse-with-health-check policy?
5. Do we expose backend selection as config (`postgres|turso`) at runtime, or compile-time deployment profile?
6. Should auth profile lock lease defaults (TTL/renew cadence) be globally fixed or provider-specific?

## Implementation Tasks

### T-001: Define control-plane run state machine and invariants
**Acceptance Criteria:**
- [ ] State diagram for run and attempt lifecycles is documented
- [ ] Invariants are explicit (single active attempt, valid transitions)
- [ ] Contract test cases are derived from invariants
- [ ] Typecheck passes

### T-002: Create store interface and contract test suite
**Acceptance Criteria:**
- [ ] `Store` interface covers enqueue/claim/heartbeat/transition/idempotency/auth-profile-lock operations
- [ ] Contract tests run against any adapter implementation
- [ ] Concurrency tests included for claim correctness
- [ ] Typecheck passes

### T-003: Implement Postgres adapter + schema migrations
**Acceptance Criteria:**
- [ ] Postgres schema for runs/attempts/events/idempotency/auth profiles + locks is migrated
- [ ] Atomic claim and auth-lock semantics are implemented with concurrency-safe SQL pattern
- [ ] All contract tests pass on Postgres
- [ ] Typecheck passes

### T-004: Implement Turso/libSQL adapter + schema migrations
**Acceptance Criteria:**
- [ ] Turso schema mirrors logical model and invariants (including auth profiles + locks)
- [ ] Atomic claim and auth-lock semantics match contract requirements
- [ ] All contract tests pass on Turso
- [ ] Typecheck passes

### T-005: Build worker execution loop for Daytona sandboxes
**Acceptance Criteria:**
- [ ] Worker can claim run, provision sandbox, execute Hal, update attempt status
- [ ] Heartbeat updates emitted on active attempts
- [ ] Failures map to retryable/non-retryable error classes
- [ ] Typecheck passes

### T-006: Implement reconciler for stale attempts and retries
**Acceptance Criteria:**
- [ ] Reconciler detects expired heartbeats via lease timeout
- [ ] Retry/backoff policy applied; terminal failure after max attempts
- [ ] Requeued runs become claimable again
- [ ] Typecheck passes

### T-007: Add idempotent GitHub side-effect layer
**Acceptance Criteria:**
- [ ] PR creation and status-comment actions are idempotent via persisted keys
- [ ] Replay/retry does not duplicate side effects
- [ ] Idempotency behavior is covered by tests
- [ ] Typecheck passes

### T-008: Expose CLI/API operations for cloud runs
**Acceptance Criteria:**
- [ ] `submit`, `status`, `logs`, `cancel` commands/endpoints are functional
- [ ] API responses include run status and latest attempt metadata
- [ ] Cancel blocks future claims and terminates active attempt cleanly
- [ ] Typecheck passes

### T-009: Build benchmark harness and run dual-adapter evaluation
**Acceptance Criteria:**
- [ ] Harness simulates queue claim, heartbeats, retries, cancellations, and auth lock contention
- [ ] Runs at 10/50/100 worker tiers
- [ ] Reports include correctness and latency metrics for both adapters
- [ ] Typecheck passes

### T-010: Publish backend decision report and rollout plan
**Acceptance Criteria:**
- [ ] Recommendation includes rationale, tradeoffs, and fallback path
- [ ] Default backend is documented in ops/runbook docs
- [ ] Migration guidance between adapters is documented
- [ ] Typecheck passes

### T-011: Implement auth profile run-binding and lease-lock lifecycle
**Acceptance Criteria:**
- [ ] Run creation persists `auth_profile_id` and enforces existence/compatibility/state checks
- [ ] Auth profile status transitions (`pending_link|linked|invalid|revoked`) are enforced
- [ ] Acquire/renew/release lock operations enforce profile concurrency limits
- [ ] Stale-lock reclamation behavior is documented and tested
- [ ] Typecheck passes

### T-012: Extend adapter contract tests for auth profile parity
**Acceptance Criteria:**
- [ ] Contract suite validates auth profile CRUD/status-transitions + lock semantics on both adapters
- [ ] Contention tests verify no lock-overcommit under concurrency
- [ ] Failure-path tests cover crash/retry lock recovery
- [ ] Typecheck passes
