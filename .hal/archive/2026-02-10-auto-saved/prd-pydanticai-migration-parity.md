# PRD: PydanticAI Migration for Support Chatbot Behavior Parity

## 1. Introduction/Overview
This PRD defines a strict 1:1 migration of the support chatbot orchestration layer from LangGraph to PydanticAI. The problem being solved is framework migration risk: without explicit parity constraints, existing support workflows could regress for end users. The target outcome is near-100% behavior parity, especially for conversation state handling, handoffs, and memory behavior, so users experience no workflow change at cutover.

This is a migration-only effort. No net-new features are in scope.

## 2. Goals
- Achieve behavior parity for existing support chatbot workflows with no user-visible workflow changes.
- Preserve conversation behavior parity across state handling, handoffs, and memory (short-term and long-term).
- Validate parity against predefined benchmark scenarios and require a full pass before cutover.
- Maintain rollback safety by keeping the existing LangGraph path available behind a runtime toggle until post-cutover stabilization.
- Ensure all validated migration gaps (1–59) are tracked and closed with testable evidence.

## 3. User Stories

### Schema Changes

### US-001: Define canonical conversation state schema
**Description:** As a platform engineer, I want a canonical Pydantic conversation state schema so that migrated runtime state matches existing LangGraph state behavior.

**Acceptance Criteria:**
- [ ] A Pydantic schema is defined for conversation state, including existing required state fields and default behaviors.
- [ ] Legacy LangGraph state fixtures can be loaded and validated by the new schema without field loss.
- [ ] Validation errors for missing required fields are explicit and include field names.
- [ ] Typecheck passes

### US-002: Define tool contract schemas
**Description:** As a platform engineer, I want Pydantic models for all existing tool request/response contracts so that tool behavior remains unchanged during migration.

**Acceptance Criteria:**
- [ ] Every currently supported tool has request and response schemas in the new stack.
- [ ] Contract tests verify serialized payload shape parity against existing fixture payloads.
- [ ] Unknown/invalid tool payload handling matches current behavior (same reject/accept outcome class).
- [ ] Typecheck passes

### US-003: Define handoff event schema
**Description:** As a platform engineer, I want a 1:1 handoff event schema so that escalation and handoff behavior is preserved exactly.

**Acceptance Criteria:**
- [ ] Event schemas exist for handoff start, success, and failure events with existing reason/status fields.
- [ ] Existing handoff event fixtures validate under the new schema with equivalent values.
- [ ] Schema docs map old-to-new fields with no net-new required fields.
- [ ] Typecheck passes

### US-004: Define memory record schemas
**Description:** As a platform engineer, I want explicit short-term and long-term memory schemas so that memory read/write behavior remains consistent.

**Acceptance Criteria:**
- [ ] Memory schemas cover current persisted fields, metadata, and retention flags.
- [ ] Round-trip tests prove legacy memory records can be transformed to new schemas and back without data loss.
- [ ] Schema validation behavior for malformed memory records matches current behavior class.
- [ ] Typecheck passes

### US-005: Define benchmark scenario manifest schema
**Description:** As a QA engineer, I want a benchmark manifest schema so that parity validation is structured, repeatable, and auditable.

**Acceptance Criteria:**
- [ ] A scenario manifest schema defines required inputs and expected assertions for state, handoff, and memory.
- [ ] All predefined benchmark scenarios are represented in the manifest format.
- [ ] Each benchmark scenario links to one or more validated gap IDs (1–59) for traceability.
- [ ] Typecheck passes

### Backend

### US-006: Bootstrap PydanticAI runtime with equivalent configuration
**Description:** As a platform engineer, I want the new runtime to load equivalent agent configuration so that model/tool behavior starts from the same baseline.

**Acceptance Criteria:**
- [ ] PydanticAI runtime uses the same effective model/system settings as the current production LangGraph flow.
- [ ] Startup config resolution tests compare old vs new resolved settings and pass on parity assertions.
- [ ] Runtime initialization failure behavior remains compatible with existing operational expectations.
- [ ] Typecheck passes

### US-007: Implement conversation state transition parity
**Description:** As an end user, I want conversations to progress the same way so that my support workflow does not change after migration.

**Acceptance Criteria:**
- [ ] For benchmark conversations, state transitions in the new runtime match expected baseline transition outcomes.
- [ ] Branching outcomes (next-step routing) match baseline for parity scenarios.
- [ ] Regression tests cover normal flow and edge transitions (empty history, interrupted turn, repeated clarification).
- [ ] Typecheck passes

### US-008: Implement tool selection and invocation parity
**Description:** As an end user, I want the agent to call the same tools in the same contexts so that support outcomes remain unchanged.

**Acceptance Criteria:**
- [ ] Tool selection for benchmark scenarios matches baseline decisions.
- [ ] Tool invocation arguments match expected contract shape for parity fixtures.
- [ ] Tool failure propagation and retry/fallback outcomes match baseline behavior class.
- [ ] Typecheck passes

### US-009: Implement handoff orchestration parity
**Description:** As an end user, I want escalation/handoff behavior to remain the same so that I can reliably reach the right support path.

**Acceptance Criteria:**
- [ ] Handoff trigger conditions match baseline behavior in benchmark scenarios.
- [ ] Handoff status progression (start/in-progress/success/failure) matches baseline event sequence.
- [ ] Failure-to-handoff fallback behavior matches existing baseline outcomes.
- [ ] Typecheck passes

### US-010: Implement short-term memory parity
**Description:** As an end user, I want the assistant to retain in-session context exactly as before so that I do not need to repeat information.

**Acceptance Criteria:**
- [ ] In-session context retrieval uses equivalent scope/window rules as baseline.
- [ ] Memory updates per turn produce equivalent state for benchmark conversations.
- [ ] Tests verify parity for first-turn, long-thread, and interrupted-session scenarios.
- [ ] Typecheck passes

### US-011: Implement long-term memory parity
**Description:** As an end user, I want past relevant context to be recalled consistently so that ongoing support interactions feel continuous.

**Acceptance Criteria:**
- [ ] Long-term memory write triggers and retrieval filters match baseline behavior.
- [ ] Benchmark scenarios asserting remembered preferences/history pass parity checks.
- [ ] No new long-term memory fields are introduced without explicit parity mapping.
- [ ] Typecheck passes

### US-012: Implement guardrail and fallback response parity
**Description:** As an end user, I want failures and unsupported cases handled the same way so that support reliability remains predictable.

**Acceptance Criteria:**
- [ ] Safety/guardrail outcomes for benchmark unsafe/unsupported prompts match baseline response class.
- [ ] Tool/runtime failure fallback path returns baseline-equivalent handling outcomes.
- [ ] Regression tests cover policy refusal, unavailable dependency, and timeout behavior.
- [ ] Typecheck passes

### US-013: Implement parity observability and diff reporting
**Description:** As an operations engineer, I want side-by-side parity observability so that migration readiness can be measured objectively.

**Acceptance Criteria:**
- [ ] New runtime emits required parity logs for session, turn, tool, handoff, and memory checkpoints.
- [ ] A parity diff report is generated per benchmark run with pass/fail counts and scenario-level diffs.
- [ ] Missing required telemetry fields fail parity validation checks.
- [ ] Typecheck passes

### US-014: Add automated parity benchmark runner and CI gate
**Description:** As a release manager, I want automated parity validation so that cutover is blocked until parity criteria are met.

**Acceptance Criteria:**
- [ ] A benchmark runner executes predefined scenarios against baseline and migrated runtimes and outputs deterministic results.
- [ ] CI blocks merge/release when any required parity assertion fails.
- [ ] Benchmark artifacts are persisted for audit and release approval.
- [ ] Typecheck passes

### US-015: Add cutover gate and rollback control
**Description:** As a release manager, I want a controlled cutover switch so that migration can be enabled safely and reverted immediately if needed.

**Acceptance Criteria:**
- [ ] Runtime routing can switch between LangGraph and PydanticAI without code changes.
- [ ] Cutover enablement requires a passing parity benchmark status for predefined scenarios.
- [ ] Rollback procedure to baseline runtime is documented and tested.
- [ ] Typecheck passes

### Frontend

### US-016: Preserve chat transcript rendering parity
**Description:** As an end user, I want the chat transcript to look and read the same so that my support interaction remains familiar.

**Acceptance Criteria:**
- [ ] Message ordering and role attribution match baseline in UI parity scenarios.
- [ ] Existing visible transcript elements are preserved (no net-new required UI elements).
- [ ] Snapshot or visual regression checks pass for benchmark transcript views.
- [ ] Typecheck passes
- [ ] Verify in browser using agent-browser skill (skip if no dev server running)

### US-017: Preserve typing/streaming behavior parity
**Description:** As an end user, I want response generation cues to behave the same so that response timing and readability stay predictable.

**Acceptance Criteria:**
- [ ] Typing/streaming indicators appear and clear under the same interaction conditions as baseline.
- [ ] Final rendered assistant content matches expected parity output after streaming completes.
- [ ] UI regression tests cover normal response, delayed response, and interrupted response scenarios.
- [ ] Typecheck passes
- [ ] Verify in browser using agent-browser skill (skip if no dev server running)

### US-018: Preserve handoff and escalation UI parity
**Description:** As an end user, I want handoff status and escalation prompts to remain unchanged so that escalation workflows are familiar.

**Acceptance Criteria:**
- [ ] Handoff and escalation UI states trigger on the same benchmark scenarios as baseline.
- [ ] Available user actions during handoff match current behavior.
- [ ] UI checks confirm equivalent success/failure handoff messaging paths.
- [ ] Typecheck passes
- [ ] Verify in browser using agent-browser skill (skip if no dev server running)

### US-019: Preserve session resume and context continuity parity
**Description:** As an end user, I want session continuity across reload/reconnect so that ongoing support conversations are not disrupted.

**Acceptance Criteria:**
- [ ] Reloading/reconnecting restores the same conversation context depth as baseline.
- [ ] Post-resume responses reflect the same remembered context as baseline parity scenarios.
- [ ] No additional user steps are introduced for resume in migrated flow.
- [ ] Typecheck passes
- [ ] Verify in browser using agent-browser skill (skip if no dev server running)

## 4. Functional Requirements
- FR-1: The system must migrate support chatbot orchestration from LangGraph to PydanticAI with strict 1:1 behavior goals.
- FR-2: The system must preserve end-user workflow semantics with no net-new feature behavior.
- FR-3: The system must define and validate canonical schemas for conversation state, tools, handoffs, and memory.
- FR-4: The system must support parity-compatible loading/validation of legacy baseline fixtures.
- FR-5: The system must execute equivalent conversation state transitions for benchmarked scenarios.
- FR-6: The system must preserve tool selection and invocation behavior for existing workflows.
- FR-7: The system must preserve handoff trigger logic, status progression, and fallback behavior.
- FR-8: The system must preserve short-term memory retrieval/write behavior.
- FR-9: The system must preserve long-term memory retrieval/write behavior.
- FR-10: The system must preserve guardrail and fallback handling behavior.
- FR-11: The system must produce parity observability logs and scenario-level diff artifacts.
- FR-12: The system must execute predefined benchmark scenarios in an automated, deterministic parity runner.
- FR-13: The system must enforce CI/release gating on required parity benchmark pass conditions.
- FR-14: The system must provide a runtime cutover switch between baseline and migrated agent.
- FR-15: The system must provide a tested rollback path to LangGraph baseline.
- FR-16: The system must preserve frontend transcript, streaming cues, handoff UI, and session resume behavior.
- FR-17: The system must include traceability from benchmark scenarios to validated gaps (1–59).
- FR-18: The system must keep frozen baseline directories (`support-agent/`, `support-common/`) unchanged as reference during migration.

## 5. Non-Goals
- Building any new end-user chatbot capabilities beyond parity.
- Redesigning chatbot UX, information architecture, or visual identity.
- Changing support policy/content strategy unrelated to framework migration.
- Introducing new tools, new handoff destinations, or new memory product behavior.
- Replatforming unrelated services or broad infrastructure modernization.

## 6. Design Considerations
- Preserve user-visible wording, interaction order, and escalation affordances wherever parity is required.
- Keep UX deltas explicitly documented when differences are technically unavoidable.
- Prefer consistency over optimization; migration success is measured by behavioral equivalence.

## 7. Technical Considerations
- Maintain side-by-side executable paths (LangGraph baseline and PydanticAI migrated runtime) until cutover confidence is achieved.
- Use fixture-based contract tests and benchmark scenarios as the source of truth for parity assertions.
- Keep migration changes isolated from frozen baseline directories to protect rollback certainty.
- Require deterministic benchmark execution and stable artifact output for release governance.

## 8. Success Metrics
- 100% pass rate on predefined parity benchmark scenarios before production cutover.
- 100% pass rate on benchmark assertions for conversation state handling, handoffs, and memory behavior.
- 0 approved net-new user-facing behaviors introduced by migration.
- 100% of validated gaps (1–59) mapped to implemented stories/tests and marked closed with evidence.
- Successful rollback drill completion prior to cutover, with documented execution steps.

## 9. Open Questions
- What exact tolerance (if any) is acceptable for non-functional response text variation while still counting as parity?
- Which benchmark scenarios are classified as cutover-blocking critical vs non-critical?
- What is the minimum shadow-run duration required before enabling production cutover?
- Who is the final approver for parity sign-off (engineering, support operations, or joint approval)?
