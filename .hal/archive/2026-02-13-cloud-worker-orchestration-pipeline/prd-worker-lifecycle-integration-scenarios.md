# PRD: Cross-Adapter Worker Lifecycle Integration Scenarios

## 1) Introduction / Overview

Build an integration test suite that exercises the full cloud worker lifecycle for `run`, `auto`, and `review` workflows against both Postgres and Turso adapters.

The suite will validate successful execution and critical failure paths (`cancel`, `lease_lost`, `profile_revoked`) with deterministic assertions for run/attempt transitions, cleanup behavior, snapshot persistence, and artifact restoration. This is a high-priority hardening effort for the newly shipped worker orchestration pipeline.

## 2) Goals

1. Add a single integration-tagged suite that validates worker lifecycle behavior across Postgres and Turso.
2. Reuse one shared lifecycle command flow model so workflow/adaptor coverage does not drift.
3. Verify successful lifecycle behavior end-to-end, including terminal status, snapshot refs, and `pull` artifact restoration.
4. Verify failure-path correctness for cancel, lease loss, and profile revocation with deterministic attempt terminalization semantics.
5. Enforce stable JSON output contracts for `status`, `logs`, and `pull` with camelCase key assertions.
6. Provide a canonical make target (and CI/doc usage) for running this suite.

## 3) Tasks

### T-001: Scaffold integration-tagged worker lifecycle suite
**Description:** As a maintainer, I need a dedicated `//go:build integration` worker lifecycle suite under `cmd/` so lifecycle coverage is isolated from default unit tests.

**Acceptance Criteria:**
- [ ] A new integration test file is added under `cmd/` for worker lifecycle scenarios.
- [ ] The suite has a top-level test entrypoint dedicated to worker lifecycle integration coverage.
- [ ] The suite compiles only when integration tags are enabled.
- [ ] Typecheck passes

### T-002: Define shared lifecycle flow fixtures for run/auto/review
**Description:** As a maintainer, I need one shared command/runner flow definition for `run`, `auto`, and `review` so scenario steps remain consistent.

**Acceptance Criteria:**
- [ ] Shared flow fixtures are defined once and reused by all workflow-kind scenarios.
- [ ] Flow args support run-dependent placeholders (for example `<run-id>`) with deterministic substitution.
- [ ] Scenario runners dispatch through testable `run<Command>` helpers instead of Cobra root execution.
- [ ] Typecheck passes

### T-003: Add deterministic worker lifecycle harness instrumentation
**Description:** As a maintainer, I need harness/store instrumentation for transition and terminalization tracking so scenarios can assert exact run/attempt behavior.

**Acceptance Criteria:**
- [ ] Harness store records run status transitions and attempt terminalization calls in assertion-friendly form.
- [ ] Harness setup supports seeding lifecycle events and snapshot references needed by `status`/`logs`/`pull` checks.
- [ ] Any package-level factory overrides used by the suite are restored during teardown.
- [ ] Typecheck passes

### T-004: Implement successful lifecycle scenarios across workflow kinds
**Description:** As a maintainer, I need success-path scenarios for `run`, `auto`, and `review` so the core worker pipeline is validated end-to-end.

**Acceptance Criteria:**
- [ ] Success scenarios assert terminal success state for run and final attempt.
- [ ] Success scenarios assert persisted snapshot references are present and queryable.
- [ ] Success scenarios run `pull` and verify expected workflow artifact groups are restored from cloud state.
- [ ] Typecheck passes

### T-005: Implement deterministic cancel lifecycle scenarios
**Description:** As a maintainer, I need cancel-path integration scenarios so cancel intent and canceled terminalization behavior are regression-tested.

**Acceptance Criteria:**
- [ ] Cancel scenarios assert cancel intent is persisted and the run reaches canceled terminal state deterministically.
- [ ] Cancel scenarios assert attempt terminalization is recorded exactly once.
- [ ] Cancel scenarios assert post-cancel `status` output reflects the terminal canceled outcome.
- [ ] Typecheck passes

### T-006: Implement lease_lost lifecycle scenarios
**Description:** As a maintainer, I need lease-loss scenarios so lease interruption behavior and attempt finalization invariants are validated.

**Acceptance Criteria:**
- [ ] Lease-loss scenarios assert expected terminal run status and terminal reason for `lease_lost`.
- [ ] Lease-loss scenarios assert no duplicate attempt terminalization is recorded.
- [ ] Lease-loss scenarios verify final persisted run/attempt state matches expected lifecycle contracts.
- [ ] Typecheck passes

### T-007: Implement profile_revoked lifecycle scenarios with cleanup tolerance
**Description:** As a maintainer, I need profile-revoked scenarios so auth-revocation terminalization and cleanup resilience are covered.

**Acceptance Criteria:**
- [ ] Profile-revoked scenarios assert expected terminal run status and terminal reason for `profile_revoked`.
- [ ] Scenario setup forces auth-lock release to return `ErrNotFound` and asserts terminalization still succeeds.
- [ ] Scenarios assert no duplicate attempt terminalization is recorded for this path.
- [ ] Typecheck passes

### T-008: Add status/logs/pull JSON contract assertions
**Description:** As a maintainer, I need shared JSON contract assertions so lifecycle outputs stay stable and camelCase-compliant.

**Acceptance Criteria:**
- [ ] Shared required-key fixtures are defined for `status`, `logs`, and `pull` JSON outputs.
- [ ] Scenarios decode `--json` output and assert required camelCase keys are present.
- [ ] Assertions reject snake_case aliases for commands already migrated to camelCase contracts.
- [ ] Typecheck passes

### T-009: Execute scenario matrix across Postgres and Turso with one runner
**Description:** As a maintainer, I need one adapter matrix runner so identical scenario coverage executes against both Postgres and Turso stores.

**Acceptance Criteria:**
- [ ] Scenario execution is table-driven by adapter and reuses the same scenario definitions for both adapters.
- [ ] Adapter setup/teardown is isolated per case to avoid cross-scenario state leakage.
- [ ] Test names/output clearly identify adapter + scenario combinations for failures.
- [ ] Typecheck passes

### T-010: Add canonical make target and CI/documented invocation
**Description:** As a maintainer, I need a dedicated make target for this suite so local and CI invocation stays consistent.

**Acceptance Criteria:**
- [ ] A new make target is added to run only the worker lifecycle integration suite with integration tags.
- [ ] CI is updated to call this target, or repository docs explicitly define it as canonical invocation.
- [ ] Existing cloud lifecycle integration targets continue to function unchanged.
- [ ] Typecheck passes

## 4) Functional Requirements

- **FR-1:** The repository must include an integration-tagged worker lifecycle suite under `cmd/` that is excluded from default unit-test runs.
- **FR-2:** The suite must run shared lifecycle flows for workflow kinds `run`, `auto`, and `review` using a single reusable command/runner definition.
- **FR-3:** The suite must execute identical lifecycle scenarios against both Postgres and Turso store configurations.
- **FR-4:** Success scenarios must verify terminal success status, persisted snapshot references, and successful artifact restoration via `pull`.
- **FR-5:** Cancel scenarios must verify deterministic canceled outcome and exactly-once attempt terminalization.
- **FR-6:** Lease-loss scenarios must verify expected terminal status/reason and absence of duplicate attempt terminalization.
- **FR-7:** Profile-revoked scenarios must verify expected terminal status/reason and successful terminalization even when cleanup lock release returns `ErrNotFound`.
- **FR-8:** `status`, `logs`, and `pull` JSON outputs in these scenarios must be asserted for required camelCase contract keys.
- **FR-9:** A dedicated make target must exist for this suite and be used by CI or documented as canonical execution.

## 5) Non-Goals

- Changing production worker orchestration behavior beyond what is necessary to expose deterministic test seams.
- Adding new cloud adapters beyond Postgres and Turso.
- Redesigning cloud command UX or introducing new lifecycle commands.
- Replacing existing unit tests; this work supplements them with integration coverage.

## 6) Technical Considerations

- Reuse existing integration harness patterns already used for cloud lifecycle suites: shared fixtures, placeholder substitution, and helper-based JSON decoding.
- Keep adapter coverage table-driven and avoid per-adapter test forks.
- Assert workflow artifact restoration via `cloud.WorkflowArtifactGroups(workflowKind)` to stay aligned with runtime behavior.
- Keep package-level factory overrides isolated and restored during test teardown to avoid global-state leakage.
- Prefer deterministic harness hooks (transition logs, terminalization counters) over timing-based assertions.

## 7) Open Questions

- Assumption: CI environments that run this suite will provide required Postgres and Turso integration prerequisites; otherwise tests should skip with explicit reasons.
- Assumption: Lease-loss and profile-revoked terminal status/reason assertions should follow current worker pipeline constants as the source of truth.
