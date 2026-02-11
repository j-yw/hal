# PRD: Test Feature

## Introduction/Overview
The Test Feature introduces a standardized developer command to validate Go code changes quickly during development. It solves the current inconsistency where developers run ad-hoc test commands and get inconsistent output formatting. The feature will run a defined test suite and print a deterministic pass/fail summary suitable for local iteration and CI alignment.

## Goals
- Enable core developers to run the project’s standard validation suite with a single command.
- Ensure deterministic execution order and deterministic summary output for unchanged code/config state.
- Provide immediate, concise pass/fail visibility after each run.
- Ship with deterministic automated tests and maintain green CI after merge.

## User Stories

### Schema Changes

### US-001: Define test suite configuration schema
**Description:** As a core developer, I want named test suites in configuration so that everyone runs the same checks consistently.

**Acceptance Criteria:**
- [ ] `.hal/config.yaml` supports a `test` section containing `default_suite` and `suites`, where each suite is an ordered list of commands.
- [ ] Configuration loading returns a clear validation error when `default_suite` is missing/empty, references a non-existent suite, or any suite command is empty.
- [ ] Unit tests cover valid configuration and each validation failure path.
- [ ] Typecheck passes

### Backend

### US-002: Execute configured suite from CLI
**Description:** As a core developer, I want to run a configured suite from the CLI so that I can validate system behavior quickly.

**Acceptance Criteria:**
- [ ] A command (`hal test [suite]`) runs the configured default suite when no suite argument is provided.
- [ ] Passing a suite name runs that suite’s commands in declaration order.
- [ ] The command exits with status code `0` only when all commands pass; otherwise it exits non-zero.
- [ ] Automated tests cover default suite execution, explicit suite execution, unknown suite handling, and a failing command path.
- [ ] Typecheck passes

### US-003: Aggregate deterministic run results
**Description:** As a core developer, I want command-level results aggregated consistently so that downstream summary output is reliable and testable.

**Acceptance Criteria:**
- [ ] Execution result model captures suite name, per-command status, and total duration.
- [ ] Failed command entries are preserved in deterministic order.
- [ ] Unit tests verify identical input execution traces produce identical aggregated results.
- [ ] Typecheck passes

### Frontend

### US-004: Print concise pass/fail CLI summary
**Description:** As a core developer, I want a concise terminal summary so that I can immediately decide whether my change is safe to keep.

**Acceptance Criteria:**
- [ ] CLI output includes suite name, total command count, passed count, failed count, and total duration.
- [ ] On failure, output lists failed command(s) in deterministic order.
- [ ] Snapshot/golden tests assert exact summary output for all-pass and mixed pass/fail scenarios.
- [ ] Typecheck passes

## Functional Requirements
- FR-1: The system must provide a CLI command to run predefined test suites (`hal test [suite]`).
- FR-2: The system must load suite definitions from `.hal/config.yaml`.
- FR-3: The system must support `test.default_suite` when no suite argument is provided.
- FR-4: The system must validate test configuration and return actionable error messages for invalid data.
- FR-5: The system must execute suite commands in deterministic declaration order.
- FR-6: The system must capture pass/fail status for each command and an overall suite result.
- FR-7: The system must print a deterministic pass/fail summary after execution.
- FR-8: The system must return non-zero exit code when any suite command fails.
- FR-9: The system must include deterministic automated tests for config parsing, execution flow, and summary formatting.
- FR-10: The feature must integrate without breaking existing CI checks; CI must remain green.

## Non-Goals
- No UI/TUI redesign or visual styling changes.
- No parallel or distributed test execution.
- No flaky test auto-retry, quarantine, or advanced analytics.
- No replacement of existing CI workflows beyond integrating this command and tests.

## Design Considerations
- Keep CLI output compact and easy to scan in terminal workflows.
- Preserve stable output structure so future tooling can parse it reliably.

## Technical Considerations
- Follow existing Cobra command patterns under `cmd/`.
- Keep command execution testable via an injectable runner abstraction.
- Use controlled/mocked timing in tests to keep duration assertions deterministic.
- Prefer table-driven tests for config validation and summary formatting variants.

## Success Metrics
- 100% of feature runs emit a pass/fail summary with required fields.
- Re-running the same suite with unchanged code/config produces the same command order and summary structure.
- CI remains green after feature merge.
- Core developers can complete standard validation in one command invocation.

## Open Questions
- Should suite commands be represented as shell strings or structured command+args fields?
- Should execution always continue after first failure to maximize summary completeness, or should fail-fast be configurable?
- Should verbose per-command stdout/stderr be always shown, or only shown for failed commands by default?