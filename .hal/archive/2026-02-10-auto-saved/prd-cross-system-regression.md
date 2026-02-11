I’ll draft the PRD from your provided answers, mirror the repo’s existing PRD style, and save it to `.hal/prd-cross-system-regression.md` before returning the markdown content.I found the built-in PRD skill and example in `internal/skills/prd`; next I’m matching that structure exactly and then writing the new PRD file.I have enough context and I’m now writing the PRD with small, verifiable stories ordered by schema-first then backend execution, scoped to `init/run/archive/review` only.I’m replacing the existing PRD with a workflow-scoped version tied to your answers (`init/run/archive/review`, automated execution only), and keeping stories schema-first then backend with explicit frontend exclusion.I’m tightening story granularity one more step so each story is clearly one focused iteration, then I’ll return the final markdown only.# PRD: Cross-System Regression Suite for HAL CLI

## Introduction/Overview

Cross-system regressions in HAL CLI workflows can escape into releases when command-to-package interactions are only validated ad hoc. This feature adds an automated regression suite that validates end-to-end HAL CLI workflows across core command paths before release.

The primary users are core developers working on HAL commands and internal packages. Scope is limited to HAL CLI workflows: `init`, `run`, `archive`, and `review`.

## Goals

- Catch regressions across `init/run/archive/review` workflows before release.
- Provide one automated, repeatable regression execution path for developers and CI.
- Fail release gating when any scoped regression fails.
- Reduce workflow regressions reaching users across the next 3 releases.

## User Stories

#### Schema Changes

### US-001: Define a regression case schema for HAL CLI workflows
**Description:** As a core developer, I want a strict regression case schema so that workflow scenarios are consistently defined and validated.

**Acceptance Criteria:**
- [ ] Add a versioned regression case schema with required fields: `id`, `workflow`, `setup`, `command`, and `assertions`.
- [ ] Schema validation rejects cases where `workflow` is not one of `init`, `run`, `archive`, or `review`.
- [ ] Automated tests include at least 3 invalid schema examples and 1 valid example.
- [ ] Typecheck passes

#### Backend

### US-002: Implement deterministic regression runner
**Description:** As a core developer, I want a runner that executes regression cases in isolation so that failures are reproducible across systems.

**Acceptance Criteria:**
- [ ] Runner executes each case in a fresh temporary workspace and cleans up on completion.
- [ ] Runner records per-case status (`pass`, `fail`, `skip`) and duration.
- [ ] Failure output includes case `id`, executed command, and first failed assertion.
- [ ] Typecheck passes

### US-003: Add regression coverage for `init` and `run`
**Description:** As a core developer, I want automated regression cases for `init` and `run` so that foundational CLI workflows are protected.

**Acceptance Criteria:**
- [ ] At least 1 passing regression case for `init` verifies expected `.hal` state files are created.
- [ ] At least 1 passing regression case for `run` verifies progress/state updates are produced in expected paths.
- [ ] At least 1 failing-path case validates clear error reporting for an invalid `run` precondition.
- [ ] Typecheck passes

### US-004: Add regression coverage for `archive`
**Description:** As a core developer, I want automated regression cases for `archive` so that state transitions remain reliable across create/restore flows.

**Acceptance Criteria:**
- [ ] At least 1 regression case covers `archive create` and verifies archive directory naming and state movement.
- [ ] At least 1 regression case covers `archive restore` and verifies required files are restored.
- [ ] Typecheck passes

### US-005: Add regression coverage for `review`
**Description:** As a core developer, I want automated regression cases for `review` so that completion and reporting behavior remains stable.

**Acceptance Criteria:**
- [ ] At least 1 regression case for `review` validates expected completion/report output for a known fixture.
- [ ] The `review` case asserts at least 2 concrete output conditions (for example status text and completed story count).
- [ ] Typecheck passes

### US-006: Add automated regression execution entrypoint
**Description:** As a core developer, I want a single non-interactive regression execution entrypoint so that the suite can run automatically before release.

**Acceptance Criteria:**
- [ ] Add a documented command/target (for example `make regression`) that runs only the cross-system regression suite.
- [ ] Entrypoint exits with code `0` when all cases pass or are skipped and non-zero when any case fails.
- [ ] CI/release workflow invokes the same entrypoint without interactive prompts.
- [ ] Typecheck passes

#### Frontend

No frontend stories are in scope for this feature because validation targets CLI workflows only.

## Functional Requirements

- FR-1: The system must define and validate a versioned regression case schema.
- FR-2: The system must support only scoped workflows: `init`, `run`, `archive`, and `review`.
- FR-3: The system must execute regression cases in isolated temporary workspaces.
- FR-4: The system must produce deterministic results without network dependencies.
- FR-5: The system must output per-case status and actionable failure details.
- FR-6: The system must provide a single non-interactive regression execution entrypoint.
- FR-7: The release pipeline must run the regression entrypoint and fail on regression failures.

## Non-Goals

- Adding regression coverage for commands outside `init/run/archive/review`.
- Adding manual-only test checklists or human sign-off flows.
- Adding UI/browser-based validation flows.
- Replacing existing unit and integration test suites.

## Design Considerations

- Keep case definitions data-driven and easy to review in code review.
- Use stable case IDs (for example `CSR-INIT-001`) for triage and trend tracking.
- Keep runner output concise for CI logs while preserving actionable failure context.

## Technical Considerations

- Reuse existing Go test patterns (deterministic fixtures, table-driven tests, tagged integration only where required).
- Avoid external network or third-party service dependencies in regression cases.
- Ensure compatibility with existing HAL path conventions and template constants.
- Target practical runtime for release gating (recommended: <= 10 minutes total suite time).

## Success Metrics

- 100% of release-candidate pipelines execute the cross-system regression entrypoint.
- 0 unresolved regression-suite failures are present at release cut time.
- Regressions reported by users for `init/run/archive/review` decrease release-over-release across the next 3 releases.

## Open Questions

- Which operating system matrix is mandatory for release gating (Linux only vs Linux/macOS/Windows)?
- Should regression case results also be stored as machine-readable artifacts (JSON) for trend reporting?
- What maximum runtime threshold should fail the suite as unstable (for example, > 10 minutes)?