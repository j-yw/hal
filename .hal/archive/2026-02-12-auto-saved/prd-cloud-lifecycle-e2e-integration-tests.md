# PRD: Full Cloud Lifecycle End-to-End Integration Tests

**Branch:** `cloud-lifecycle-e2e-integration-tests`

## 1) Introduction/Overview

This PRD defines an end-to-end integration test suite for the unified cloud workflow in `hal`. The suite will exercise real command interoperability across `hal cloud setup`, `hal run --cloud`, `hal auto --cloud`, `hal review --cloud`, and lifecycle commands (`status`, `logs`, `cancel`, `pull`) using an ephemeral test harness.

The goal is to reduce cross-command regression risk after the unified cloud rollout by validating workflow-kind persistence, artifact handling, and output contracts (human and JSON) without relying on production services.

## 2) Goals

- Validate the primary cloud user journey across commands in one deterministic integration suite.
- Catch regressions not visible in unit tests or command-local tests.
- Ensure `workflowKind` persistence for run/auto/review flows.
- Verify stable output contracts for both human-readable and `--json` modes, including camelCase JSON fields.
- Enforce redaction guarantees for secret-bearing cloud/auth values.
- Ensure tests run in isolated environments with no external network dependency.
- Gate pull requests with lifecycle integration coverage in CI.

## 3) Tasks

### T-001: Define lifecycle integration fixtures and expected contracts
**Description:** As a developer, I need a shared fixture schema for workflow states, workflow kinds, artifact groups, and expected output keys so that lifecycle tests use one consistent source of truth.

**Acceptance Criteria:**
- [ ] A shared test fixture definition exists for expected lifecycle checkpoints (setup/run/status/logs/pull/cancel).
- [ ] Expected JSON field names are explicitly defined in camelCase for assertions.
- [ ] Fixture definitions include workflow-kind expectations for `run`, `auto`, and `review` scenarios.
- [ ] Typecheck passes

### T-002: Implement ephemeral cloud store/runtime integration harness
**Description:** As a developer, I need an isolated harness that provisions temporary workspace, store, and runtime dependencies so that lifecycle tests are deterministic and network-independent.

**Acceptance Criteria:**
- [ ] Harness creates isolated temp directories/state per test and performs teardown automatically.
- [ ] Harness uses ephemeral or test-double store/runtime components and does not require external cloud services.
- [ ] Harness exposes reusable setup helpers for invoking cloud-capable commands in sequence.
- [ ] Typecheck passes

### T-003: Add command execution helpers for dual output capture
**Description:** As a developer, I need reusable helpers to execute commands and capture both human-readable and JSON outputs so that output contract assertions are consistent across scenarios.

**Acceptance Criteria:**
- [ ] A helper exists to run cloud lifecycle commands with injected stdin/stdout for testability.
- [ ] Helpers support asserting both default human output and `--json` output in the same scenario.
- [ ] Helpers normalize deterministic fields (for example, timestamps/IDs) only where needed for stable assertions.
- [ ] Typecheck passes

### T-004: Implement baseline lifecycle scenario (`setup -> run --cloud -> status`)
**Description:** As a user, I need the core cloud lifecycle to work end-to-end so that a setup and cloud run produce a valid workflow visible in status.

**Acceptance Criteria:**
- [ ] Integration test runs `hal cloud setup` followed by `hal run --cloud` and `hal cloud status` successfully in one flow.
- [ ] Test asserts persisted workflow record exists after run and matches expected non-terminal/terminal progression.
- [ ] Both human and JSON outputs are asserted at run and status checkpoints.
- [ ] Typecheck passes

### T-005: Extend lifecycle scenario with `logs` and `pull` artifact verification
**Description:** As a user, I need logs and artifact retrieval to work after cloud execution so that I can inspect output and download produced files.

**Acceptance Criteria:**
- [ ] Integration test executes `hal cloud logs` and `hal cloud pull` after a successful cloud workflow.
- [ ] Test asserts artifact-group metadata is present and matches expected workflow-kind context.
- [ ] Test asserts pulled artifact files exist on disk at expected locations.
- [ ] Typecheck passes

### T-006: Add `auto --cloud` lifecycle scenario with workflow-kind persistence checks
**Description:** As a developer, I need an `auto --cloud` scenario so that unified lifecycle behavior is validated for autonomous execution paths.

**Acceptance Criteria:**
- [ ] Integration scenario runs `hal auto --cloud` and verifies resulting workflow can be queried via lifecycle commands.
- [ ] Persisted `workflowKind` is asserted as `auto` in store-backed state and JSON outputs.
- [ ] Scenario asserts at least status plus one downstream lifecycle command (`logs` or `pull`).
- [ ] Typecheck passes

### T-007: Add `review --cloud` lifecycle scenario with workflow-kind persistence checks
**Description:** As a developer, I need a `review --cloud` scenario so that unified lifecycle behavior is validated for review workflows.

**Acceptance Criteria:**
- [ ] Integration scenario runs `hal review --cloud` and verifies workflow lifecycle interoperability.
- [ ] Persisted `workflowKind` is asserted as `review` in store-backed state and JSON outputs.
- [ ] Scenario validates status output contract and one artifact/log-related checkpoint.
- [ ] Typecheck passes

### T-008: Add cancel-path lifecycle scenario (`cancel` terminal state)
**Description:** As a user, I need `hal cloud cancel` to transition active workflows into the expected terminal state so that cancellation behavior is reliable.

**Acceptance Criteria:**
- [ ] Integration test starts a cancellable workflow and executes `hal cloud cancel`.
- [ ] Post-cancel status assertion verifies the expected terminal canceled state.
- [ ] Human and JSON outputs both reflect cancel success and terminal status consistently.
- [ ] Typecheck passes

### T-009: Add redaction and JSON contract assertions across all lifecycle scenarios
**Description:** As a security-conscious user, I need cloud/auth outputs to redact secret-bearing values so that tests enforce safe output behavior in every lifecycle command.

**Acceptance Criteria:**
- [ ] Lifecycle tests assert secret-bearing values are redacted in human output checkpoints.
- [ ] Lifecycle tests assert secret-bearing values are redacted in JSON output checkpoints.
- [ ] JSON assertions verify stable camelCase contract fields for cloud/auth responses used by the suite.
- [ ] Typecheck passes

### T-010: Wire lifecycle integration suite into CI pull-request gating
**Description:** As a maintainer, I need CI to run the lifecycle integration suite on pull requests so that regressions fail fast before merge.

**Acceptance Criteria:**
- [ ] CI executes the lifecycle integration test target on pull requests.
- [ ] Pipeline fails when lifecycle integration tests fail.
- [ ] Repository test documentation or Make target usage is updated for local reproduction.
- [ ] Typecheck passes

## 4) Functional Requirements

- **FR-1:** The system shall provide an automated end-to-end integration suite for cloud lifecycle command interoperability.
- **FR-2:** The suite shall execute `setup -> run --cloud -> status -> logs -> pull` in a deterministic flow.
- **FR-3:** The suite shall include dedicated `auto --cloud` and `review --cloud` lifecycle scenarios.
- **FR-4:** The suite shall assert persisted `workflowKind` values for run/auto/review workflows.
- **FR-5:** The suite shall include a cancel-path scenario validating expected terminal canceled workflow state.
- **FR-6:** The suite shall assert both human-readable and `--json` output contracts at key lifecycle checkpoints.
- **FR-7:** JSON output assertions shall validate stable camelCase field names for covered cloud/auth responses.
- **FR-8:** Assertions shall verify secret-bearing values are redacted in all covered outputs.
- **FR-9:** Artifact assertions shall verify artifact-group metadata correctness and pulled file presence.
- **FR-10:** The harness shall run without external network services and with isolated setup/teardown.
- **FR-11:** CI shall run the lifecycle suite on pull requests and fail on regressions.

## 5) Non-Goals

- End-to-end validation against real production cloud providers or real external databases.
- Performance/load benchmarking of cloud command throughput.
- Redesigning command UX, flag semantics, or output formats beyond enforcing current contracts.
- Testing unrelated non-cloud command paths not required for lifecycle coverage.

## 6) Technical Considerations

- Follow existing command-testing patterns with thin Cobra handlers and testable run helpers.
- Reuse unified cloud config/resolve behavior already established in codebase patterns.
- Keep tests deterministic with temp directories, controlled fixture data, and minimal timing assumptions.
- Use existing integration test conventions/build tags in this repository.
- Prefer shared assertion utilities to avoid drift between run/auto/review scenario checks.

## 7) Open Questions

- **Assumption:** The lifecycle suite will live in existing integration-test locations that already support command-level orchestration and build tags.
- **Assumption:** Ephemeral harness components can represent workflow progression and artifact metadata sufficiently for interoperability checks.
- **Assumption:** Current JSON contract fields used by cloud/auth commands are the baseline to lock in via assertions for this PRD.
