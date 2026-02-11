# Product Requirements Document: PydanticAI Migration Plan (Final Validated Version)

## 1. Introduction/Overview
This PRD defines the migration of the internal support agent from a LangGraph-based orchestration runtime to a PydanticAI-based runtime. The primary objective is feature parity with minimal behavior changes for internal support operators and agent workflows.

The migration scope is limited to core orchestration and tool-calling flows. Existing code in `support-agent/` and `support-common/` is frozen and must not be modified. All migration behavior must be introduced through adapters/wrappers and new migration-specific components.

A migration is considered complete only when the critical regression suite passes with behavior parity.

## 2. Goals
- Achieve behavior parity for critical support workflows when moving from LangGraph to PydanticAI.
- Preserve orchestration state progression and tool-calling behavior for in-scope flows.
- Keep frozen directories unchanged by implementing migration via adapters/wrappers only.
- Provide traceable closure for validated gaps (1–59) with linked parity tests.
- Enforce release readiness through a critical regression gate and rollback-safe cutover control.

## 3. User Stories

### Schema Changes

### US-001: Create validated gap traceability schema
**Description:** As a migration lead, I want a typed gap-traceability manifest so that all validated gaps (1–59) are auditable and test-linked.

**Acceptance Criteria:**
- [ ] A schema exists for `gap_id`, `legacy_reference`, `new_component`, `parity_test_id`, and `status`.
- [ ] A manifest instance includes exactly 59 unique gap IDs (1 through 59).
- [ ] Validation fails for missing, duplicate, or out-of-range gap IDs.
- [ ] Typecheck passes

### US-002: Define canonical orchestration state schema
**Description:** As a backend engineer, I want a canonical orchestration state model so that PydanticAI state handling matches baseline runtime semantics.

**Acceptance Criteria:**
- [ ] State schema includes session identifiers, turn identifiers, orchestration phase, selected tool, tool outcome, escalation status, and error status.
- [ ] Baseline state fixtures can be normalized and validated into the new schema without field loss.
- [ ] Invalid state transitions return explicit, typed validation errors.
- [ ] Typecheck passes

### US-003: Define tool request/response contract schemas
**Description:** As a backend engineer, I want typed tool contracts so that tool invocation payloads remain parity-compatible.

**Acceptance Criteria:**
- [ ] Request and response schemas exist for each in-scope tool used by critical flows.
- [ ] Contract tests verify migrated payload shape parity against baseline fixtures.
- [ ] Schema validation behavior for malformed tool payloads matches baseline outcome class (accept/reject category).
- [ ] Typecheck passes

### US-004: Define adapter boundary schemas for frozen interfaces
**Description:** As a platform engineer, I want explicit adapter boundary schemas so that frozen modules are consumed without direct modification.

**Acceptance Criteria:**
- [ ] Adapter input/output DTO schemas mirror current frozen interface contracts.
- [ ] Field-level mapping documentation exists from baseline contract to migrated contract.
- [ ] Missing/optional field defaults at the boundary are explicitly defined and tested.
- [ ] Typecheck passes

### Backend

### US-005: Implement LangGraph-compatible migration entry adapter
**Description:** As a platform engineer, I want an adapter entrypoint so that existing callers can execute PydanticAI orchestration without changing frozen code.

**Acceptance Criteria:**
- [ ] A migration adapter accepts baseline entry payloads and dispatches to PydanticAI runtime.
- [ ] No files under `support-agent/` or `support-common/` are modified.
- [ ] Smoke integration tests confirm top-level response envelope parity for representative calls.
- [ ] Typecheck passes

### US-006: Implement orchestration transition parity in core loop
**Description:** As an internal support operator, I want conversation orchestration transitions to behave the same so that workflows remain predictable.

**Acceptance Criteria:**
- [ ] For critical fixtures, migrated transition sequence matches baseline sequence for each turn.
- [ ] Unsupported transition attempts return baseline-equivalent error category.
- [ ] Tests cover start, tool-needed, tool-completed, escalation, and terminal states.
- [ ] Typecheck passes

### US-007: Implement tool selection parity policy
**Description:** As an internal support operator, I want tool selection decisions to remain consistent so that outcomes do not drift after migration.

**Acceptance Criteria:**
- [ ] For critical decision fixtures, selected tool ID matches baseline result.
- [ ] Tie-break behavior is deterministic and documented.
- [ ] Parity diff output includes scenario ID, expected tool, actual tool, and mismatch reason.
- [ ] Typecheck passes

### US-008: Implement tool execution wrapper with error parity mapping
**Description:** As a backend engineer, I want a tool wrapper so that tool execution outcomes and failures map to baseline behavior classes.

**Acceptance Criteria:**
- [ ] Tool execution runs through adapters/wrappers without direct frozen-code edits.
- [ ] Timeout, validation, and runtime failures map to baseline-equivalent error categories.
- [ ] Each in-scope tool has success/failure parity tests for at least one critical scenario.
- [ ] Typecheck passes

### US-009: Implement response payload parity for operator consumers
**Description:** As an internal support operator, I want response payload semantics to remain unchanged so that downstream operator workflows continue to function.

**Acceptance Criteria:**
- [ ] Required response fields and status semantics match baseline contracts.
- [ ] Contract tests verify parity for success, handled failure, and escalation outcomes.
- [ ] Any approved text variance thresholds are centrally configured and testable.
- [ ] Typecheck passes

### US-010: Add parity observability events and diff reporting
**Description:** As an operations engineer, I want structured parity telemetry so that migration readiness is measurable.

**Acceptance Criteria:**
- [ ] Events are emitted for session start, transition, tool select, tool complete, escalation, and final response.
- [ ] Events include correlation IDs linking run output to gap IDs and scenario IDs.
- [ ] A parity report artifact is generated with pass/fail counts and mismatch details.
- [ ] Typecheck passes

### US-011: Add critical regression suite comparator
**Description:** As a release manager, I want an automated comparator suite so that parity regressions block release.

**Acceptance Criteria:**
- [ ] The suite executes baseline and migrated paths for all critical scenarios.
- [ ] Comparator checks state transitions, tool selections, and outcome classes for parity.
- [ ] The suite exits non-zero on any critical mismatch and writes a machine-readable summary.
- [ ] Typecheck passes

### US-012: Implement cutover flag and rollback-safe routing
**Description:** As a release manager, I want runtime routing control so that migration can be safely enabled and immediately rolled back.

**Acceptance Criteria:**
- [ ] A runtime flag routes traffic to baseline or migrated orchestration path.
- [ ] Cutover is blocked when latest critical regression report is not fully passing.
- [ ] Rollback path is tested and restores baseline routing without code changes.
- [ ] Typecheck passes

### Frontend

### US-013: Preserve operator console status behavior
**Description:** As an internal support operator, I want orchestration status indicators to remain consistent so that I can monitor sessions without relearning UI behavior.

**Acceptance Criteria:**
- [ ] Existing status states (queued/running/tool/escalated/completed/error) render with unchanged semantics.
- [ ] No new required operator inputs are introduced for migrated flows.
- [ ] UI regression test validates one critical end-to-end status progression.
- [ ] Typecheck passes
- [ ] Verify in browser using agent-browser skill (skip if no dev server running)

### US-014: Preserve operator tool-call timeline behavior
**Description:** As an internal support operator, I want tool-call timeline rendering to remain the same so that debugging and intervention workflows are unaffected.

**Acceptance Criteria:**
- [ ] Tool name, state, and completion/failure markers match baseline UI behavior.
- [ ] Failed tool-call scenario shows baseline-equivalent operator affordances.
- [ ] UI assertions compare baseline vs migrated timeline for a critical scenario.
- [ ] Typecheck passes
- [ ] Verify in browser using agent-browser skill (skip if no dev server running)

## 4. Functional Requirements
- FR-1: The system must migrate core orchestration and tool-calling flows from LangGraph to PydanticAI.
- FR-2: The system must preserve behavior parity for critical regression scenarios with minimal behavior changes.
- FR-3: The system must maintain a validated mapping for all 59 migration gaps.
- FR-4: The system must implement migration via adapters/wrappers only.
- FR-5: The system must not modify code under `support-agent/` and `support-common/`.
- FR-6: The system must preserve orchestration state transition outcomes for critical scenarios.
- FR-7: The system must preserve tool selection and tool execution outcome classes for critical scenarios.
- FR-8: The system must preserve operator-facing response contract semantics.
- FR-9: The system must emit parity telemetry with scenario and gap traceability.
- FR-10: The system must provide a regression comparator that evaluates baseline vs migrated behavior.
- FR-11: The system must block cutover when any critical parity regression exists.
- FR-12: The system must provide runtime routing controls for cutover and rollback.
- FR-13: The system must preserve operator console status and tool timeline behavior for in-scope UI surfaces.

## 5. Non-Goals
- Rewriting, refactoring, or extending frozen code inside `support-agent/` and `support-common/`.
- Adding new support-agent capabilities beyond parity migration.
- Expanding scope beyond core orchestration and tool-calling flows.
- Redesigning support operator UI beyond parity-preservation adjustments.
- Replatforming unrelated infrastructure or non-critical workflows.

## 6. Design Considerations
- Keep operator-facing behavior and terminology stable; prioritize familiarity over visual or flow changes.
- Surface parity mismatches in operator-observable logs/reports to accelerate validation.
- Treat parity traceability (gap ID ↔ test ↔ outcome) as a first-class design artifact.

## 7. Technical Considerations
- Implement side-by-side baseline vs migrated execution for deterministic parity comparison.
- Enforce schema-first boundaries for adapter inputs/outputs to prevent implicit behavior drift.
- Use fixture-driven comparator tests for critical scenarios to ensure repeatable regression checks.
- Keep migration logic isolated from frozen modules to guarantee rollback certainty.

## 8. Success Metrics
- 100% pass rate for the critical regression suite comparing baseline and migrated runtimes.
- 100% of validated gaps (1–59) mapped to tests and marked closed with evidence.
- 0 source changes under frozen directories (`support-agent/`, `support-common/`).
- 100% successful execution of rollback drill restoring baseline routing.
- No approved release if any critical parity mismatch remains unresolved.

## 9. Open Questions
- What exact threshold for text-level variance is acceptable while still counting as behavior parity?
- Which scenarios are explicitly designated as “critical” for release gating?
- How long should shadow/parallel validation run before production cutover?
- Who is the final parity sign-off authority (engineering, support operations, or joint approval)?