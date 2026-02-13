# PRD: Cloud Worker Orchestration Pipeline with Final Artifacts, Optional PR Creation, and Worker CLI Wiring

## 1) Introduction / Overview

Cloud runs can be submitted and observed today, but this iteration requires a deterministic worker-side orchestration pipeline that can actually execute claims end-to-end. The worker must claim queued runs, perform setup and execution, collect final snapshot artifacts by workflow kind, optionally create GitHub PRs for auto/review workflows, and finalize run/attempt states consistently.

This work focuses on worker orchestration and command wiring only. It must preserve existing service interfaces, redaction behavior, and cloud JSON contracts while adding only the minimum new files needed.

## 2) Goals

1. Deliver an end-to-end worker pipeline for `run`, `auto`, and `review` workflows: claim → setup → execute → collect final artifacts → finalize.
2. Make claim/attempt accounting deterministic (including attempt-count behavior) across supported stores.
3. Enforce workflow-specific artifact behavior:
   - `run`: state artifacts
   - `auto` / `review`: state + reports artifacts
4. Support optional idempotent PR creation for `auto`/`review` workflows only.
5. Cover happy and failure paths with automated tests, including:
   - cancel
   - lease_lost
   - profile_revoked
   - setup failures
6. Preserve `ComputeBundleHash` determinism and avoid command/help or JSON contract regressions.

## 3) User Stories

### Schema Changes

### US-001: Fix atomic claim attempt-count semantics in persistence adapters
**Description:** As a platform engineer, I want `ClaimRun` to atomically increment `attempt_count` and enforce eligibility filters so attempt numbering is deterministic under worker contention.

**Acceptance Criteria:**
- [ ] Postgres `ClaimRun` atomically transitions a selected run to `claimed` and increments `attempt_count` in the same statement.
- [ ] Turso `ClaimRun` does the same with equivalent atomic behavior.
- [ ] Claim selection excludes runs that are `cancel_requested` or have exhausted `max_attempts`.
- [ ] Store contract tests assert `attempt_count` increments exactly once per successful claim and does not increment when no run is claimed.
- [ ] Typecheck passes.

### Backend

### US-002: Add worker orchestration composition root
**Description:** As a maintainer, I want a dedicated worker orchestration package with injected dependencies so the run loop is testable and isolated from Cobra wiring.

**Acceptance Criteria:**
- [ ] Add a worker orchestration package (for example `internal/cloud/worker`) with explicit config and dependency injection.
- [ ] Expose a run-loop API that polls for claims and dispatches single-attempt execution.
- [ ] Support graceful shutdown via context cancellation without leaving in-flight state transitions half-applied.
- [ ] Unit tests cover idle polling (no claims), one successful dispatch, and shutdown behavior.
- [ ] Typecheck passes.

### US-003: Orchestrate deterministic setup pipeline for claimed attempts
**Description:** As a worker, I want setup to run in a fixed sequence so every claimed attempt starts from a valid sandbox and auth state.

**Acceptance Criteria:**
- [ ] Setup executes in deterministic order: provision sandbox → bootstrap repo/init → auth materialization → preflight.
- [ ] Run transitions from `claimed` to `running` use valid transition checks and conflict-safe behavior.
- [ ] Setup failures emit corresponding failure events and mark attempts/runs with deterministic status outcomes.
- [ ] Retry evaluation is invoked for setup failures using existing retry classification behavior.
- [ ] Typecheck passes.

### US-004: Execute workflows with heartbeat renewals and cancel propagation
**Description:** As a worker, I want long-running workflow execution to renew leases and honor cancel intent so active attempts are safely controlled.

**Acceptance Criteria:**
- [ ] Workflow dispatch maps `run`/`auto`/`review` to the correct execution command path.
- [ ] During execution, heartbeat renewal and cancel checks run on a configurable interval.
- [ ] `cancel_requested` transitions the active attempt to `canceled` and the run to `canceled` deterministically.
- [ ] Lease renewal failures and lock/profile revocation conditions terminate attempts with correct error code semantics.
- [ ] Typecheck passes.

### US-005: Collect final artifacts by workflow kind and persist final snapshots
**Description:** As a cloud user, I want final snapshots to contain the correct artifact groups for each workflow so `cloud pull` restores expected files.

**Acceptance Criteria:**
- [ ] Final artifact collection uses workflow-specific groups: `run` = state, `auto`/`review` = state+reports.
- [ ] Artifact collection enforces allowlist and path-safety rules (including symlink protections).
- [ ] Final bundle manifests use `ComputeBundleHash` and are persisted with `SnapshotKindFinal`.
- [ ] Run snapshot references are updated to the new final snapshot/version without losing original input snapshot reference.
- [ ] Typecheck passes.

### US-006: Add optional idempotent GitHub PR creation for auto/review
**Description:** As an operator, I want optional PR creation for `auto`/`review` workflows so merge-ready changes can be surfaced automatically without affecting `run` workflows.

**Acceptance Criteria:**
- [ ] PR creation is executed only for `auto`/`review` workflows when enabled by worker configuration.
- [ ] `run` workflow never triggers PR creation side effects.
- [ ] PR creation uses existing idempotency semantics so retries do not create duplicate PRs.
- [ ] PR side-effect events are recorded through existing redaction-aware event paths.
- [ ] Typecheck passes.

### US-007: Deterministic finalization and cleanup across terminal outcomes
**Description:** As a platform engineer, I want terminal transitions and cleanup to be deterministic so runs cannot end in ambiguous states.

**Acceptance Criteria:**
- [ ] Success path finalizes to `attempt=succeeded` and `run=succeeded` after final snapshot handling.
- [ ] Failure paths finalize to retryable/non-retryable outcomes consistent with existing failure classification.
- [ ] `lease_lost` and `profile_revoked` paths are explicitly finalized with correct error codes and lock-release behavior.
- [ ] Sandbox teardown and auth-lock release are attempted on all terminal paths with best-effort semantics.
- [ ] Typecheck passes.

### US-008: Add orchestration scenario tests for happy path and required failures
**Description:** As a maintainer, I want scenario-driven tests so worker state-machine regressions are caught before merge.

**Acceptance Criteria:**
- [ ] Table-driven orchestration tests cover happy path and required failure paths: cancel, lease_lost, profile_revoked, setup failure.
- [ ] Each scenario asserts final run status, final attempt status, and required event emissions.
- [ ] Tests verify final snapshot presence/absence according to scenario outcome.
- [ ] Existing `ComputeBundleHash` stability guarantees are preserved (deterministic output; no input mutation).
- [ ] Typecheck passes.

### Frontend (CLI)

### US-009: Wire a worker CLI entrypoint with testable command handlers
**Description:** As an operator, I want a CLI command to run the worker loop so cloud workers can be started and configured explicitly.

**Acceptance Criteria:**
- [ ] Add worker command wiring (for example `hal cloud worker ...` or equivalent approved surface) with flags for worker identity and loop intervals.
- [ ] Cobra handler delegates to a testable `run<Command>` helper with injectable factories/writers.
- [ ] Command supports a bounded/single-run mode for deterministic test execution.
- [ ] Unit tests cover flag validation, startup errors, and successful command execution.
- [ ] Typecheck passes.

### US-010: Preserve existing command/help output and cloud JSON/redaction contracts
**Description:** As an automation consumer, I want existing CLI help and JSON outputs to remain stable while worker support is added.

**Acceptance Criteria:**
- [ ] Existing cloud command help text for `setup`, `run`, `auto`, `review`, `status`, `logs`, `pull`, `cancel`, and `auth` remains valid.
- [ ] Existing cloud JSON response key contracts remain unchanged for already-supported commands.
- [ ] Worker and lifecycle outputs continue to use redaction chokepoints to prevent secret leakage.
- [ ] Regression tests assert no help-surface breakage and no secret leakage in human/JSON outputs.
- [ ] Typecheck passes.

## 4) Functional Requirements

- **FR-1:** The system must atomically increment `attempt_count` during successful claims across supported stores.
- **FR-2:** The system must exclude ineligible runs from claim (`cancel_requested=true` or attempts exhausted).
- **FR-3:** A worker orchestration run loop must claim and process runs with deterministic control flow.
- **FR-4:** The setup phase must execute in the defined order: provision → bootstrap → auth materialization → preflight.
- **FR-5:** Run/attempt transitions must remain valid under existing state-machine constraints.
- **FR-6:** Execution must renew leases and check cancel intent on a configurable interval.
- **FR-7:** Cancel handling must deterministically transition active work to terminal canceled state.
- **FR-8:** `lease_lost` and `profile_revoked` conditions must terminate attempts with explicit failure codes and cleanup.
- **FR-9:** Final artifact collection must be workflow-specific (`run`: state; `auto`/`review`: state+reports).
- **FR-10:** Final snapshot persistence must use `SnapshotKindFinal` and update latest snapshot references/version.
- **FR-11:** Bundle hashing for final artifacts must preserve `ComputeBundleHash` deterministic semantics.
- **FR-12:** Optional PR creation must be available only for `auto`/`review` and must be idempotent.
- **FR-13:** Worker orchestration must preserve existing cloud service interface contracts.
- **FR-14:** Worker/CLI output and stored event payload handling must preserve redaction guarantees.
- **FR-15:** Existing cloud JSON contracts and help surfaces must not regress.
- **FR-16:** Automated tests must cover happy path plus cancel, lease_lost, profile_revoked, and setup failure paths.
- **FR-17:** Implementation must add only necessary new files and avoid unnecessary command/package sprawl.

## 5) Non-Goals

- Building a separate dedicated reconciler service process in this iteration.
- Redesigning or breaking existing cloud `Store`/service interfaces.
- Introducing new web UI/frontend application surfaces.
- Changing existing end-user semantics for `run --cloud`, `auto --cloud`, `review --cloud`, `cloud status/logs/pull/cancel` outputs.
- Adding new artifact categories beyond current state/reports scope.

## 6) Design Considerations

- Prefer composition of existing services (claim, setup, execution, heartbeat, cancellation, snapshot, retry, teardown, PR side effects) over rewriting domain logic.
- Keep state transitions explicit and ordered so behavior is deterministic across retries and worker restarts.
- Keep Cobra handlers thin and move side-effectful behavior into testable helpers.
- Minimize file churn; favor extending existing packages unless a dedicated worker package materially improves testability.

## 7) Technical Considerations

- Reuse existing factory override patterns for testability (package-level factories with test restoration).
- Keep cloud JSON key contracts stable and avoid casing drift in existing command outputs.
- Route event/log payloads through existing redaction-aware chokepoints.
- Ensure parity across both Turso and Postgres adapters for claim semantics.
- Keep `ComputeBundleHash` behavior stable (normalized paths, sorted records, deterministic hash input).

## 8) Success Metrics

1. Worker pipeline can process at least one full happy-path run from claim through terminal success with a persisted final snapshot.
2. Automated tests explicitly pass for required failure scenarios: cancel, lease_lost, profile_revoked, setup failure.
3. `ComputeBundleHash` determinism tests remain green.
4. Existing cloud help/command conformance tests remain green with no regressions.
5. Existing cloud JSON contract and redaction regression tests remain green.

## 9) Open Questions

1. When optional PR creation is enabled and PR creation fails, should the run fail terminally or complete with a warning/event?
2. Should the worker entrypoint be nested under `hal cloud worker` or exposed as a separate command surface while still preserving existing help contracts?
3. Should this iteration include intermediate checkpoint snapshots during long executions, or only final snapshot collection?
4. What default poll/heartbeat intervals are acceptable for production without introducing noisy event/log traffic?