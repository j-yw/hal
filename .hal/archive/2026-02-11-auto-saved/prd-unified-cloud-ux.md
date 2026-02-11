# PRD: Unified Cloud UX for HAL (Clean, No Legacy Abstractions)

## 1) Introduction / Overview
HAL’s cloud UX currently exposes multiple command paths and legacy abstractions that make users think about infrastructure details instead of workflow intent. This feature unifies cloud and local execution behind the same primary commands:

- `hal run [--cloud]`
- `hal auto [--cloud]`
- `hal review [--cloud]`

Cloud-specific actions remain available through a minimal support surface (`setup`, `doctor`, `list`, `status`, `logs`, `cancel`, `pull`, and `auth` subcommands). The feature intentionally removes unreleased legacy command variants (no aliases/shims), enforces non-secret project config, and provides predictable diagnostics and follow-up controls.

## 2) Goals
- Deliver one simple cloud mental model: existing workflows + optional `--cloud`.
- Ensure a new user can run `hal cloud setup` then `hal run --cloud` and complete an end-to-end cloud run.
- Keep cloud support commands minimal and obvious.
- Remove all unreleased legacy/duplicate cloud commands entirely.
- Preserve advanced control via explicit flags and profile overrides.
- Enforce secure defaults: no secrets in `.hal/cloud.yaml`; strict redaction in logs/events/errors.

## 3) User Stories

### Schema Changes

### US-001: Define `.hal/cloud.yaml` profile schema
**Description:** As a product engineer, I want a clear non-secret cloud config schema so that setup is predictable and safe.

**Acceptance Criteria:**
- [ ] `.hal/cloud.yaml` schema supports default profile name and per-profile defaults (mode/endpoints/repo/base/engine/auth profile/scope/wait/pull policy).
- [ ] Schema validation returns actionable field-level errors for invalid or missing required values.
- [ ] Schema explicitly excludes secret-bearing fields (tokens/passwords/DSNs with secrets).
- [ ] Loading and validation are covered by automated tests for valid and invalid files.
- [ ] Typecheck passes

### US-002: Persist workflow kind in cloud run records
**Description:** As the cloud runtime, I want each run to persist `run|auto|review` kind so that workers execute the correct workflow command.

**Acceptance Criteria:**
- [ ] Cloud run persistence includes a required `workflowKind` field with allowed values `run`, `auto`, `review`.
- [ ] Run submission from each workflow command stores the correct `workflowKind`.
- [ ] Worker/job loading fails fast with a clear error if `workflowKind` is missing or invalid.
- [ ] Automated tests verify serialization/deserialization and validation behavior.
- [ ] Typecheck passes

### US-003: Define artifact-group metadata for pull behavior
**Description:** As a user, I want deterministic artifact groups so that `hal cloud pull` can fetch `state`, `reports`, or `all` reliably.

**Acceptance Criteria:**
- [ ] Cloud run artifacts are categorized into `state` and `reports` groups in persisted metadata.
- [ ] `--artifacts state|reports|all` maps to deterministic file selection.
- [ ] Auto/review runs include report artifacts; all workflows include continuation state artifacts.
- [ ] Automated tests verify artifact selection for each workflow kind.
- [ ] Typecheck passes

### Backend

### US-004: Remove legacy cloud command surfaces
**Description:** As a user, I want one clean cloud command set so that help output is simple and unambiguous.

**Acceptance Criteria:**
- [ ] `hal cloud run` is removed.
- [ ] `hal cloud runs ...` namespace is removed.
- [ ] Flat legacy variants `hal cloud submit/status/logs/cancel/pull` are removed.
- [ ] `hal cloud smoke` and `hal cloud env` are removed in favor of `hal cloud doctor`.
- [ ] Removed commands are absent from help output and return unknown-command behavior.
- [ ] Typecheck passes

### US-005: Add `hal cloud list`
**Description:** As a user, I want to list cloud runs quickly so that I can find run IDs and statuses for follow-up actions.

**Acceptance Criteria:**
- [ ] `hal cloud list` returns recent runs with run ID, workflow kind, status, and updated timestamp.
- [ ] `hal cloud list --json` returns valid JSON with no mixed plain-text lines.
- [ ] Empty-state behavior is explicit in human mode and valid in JSON mode.
- [ ] Command-level tests cover success, empty list, and store error paths.
- [ ] Typecheck passes

### US-006: Implement guided `hal cloud setup`
**Description:** As a new user, I want guided setup so that I can configure cloud defaults without editing files manually.

**Acceptance Criteria:**
- [ ] `hal cloud setup` prompts for profile defaults and writes `.hal/cloud.yaml`.
- [ ] Setup writes only non-secret values.
- [ ] Re-running setup can update the selected profile without deleting unrelated profiles.
- [ ] Setup output confirms profile name and resulting default behavior.
- [ ] Typecheck passes

### US-007: Implement `hal cloud doctor`
**Description:** As a user, I want a diagnostic command so that I can resolve setup/auth/connectivity issues quickly.

**Acceptance Criteria:**
- [ ] `hal cloud doctor` validates profile/config resolution.
- [ ] Doctor checks connectivity and auth readiness.
- [ ] Failures include actionable next-step hints.
- [ ] Exit code is non-zero for blocking failures and zero for pass.
- [ ] Typecheck passes

### US-008: Build shared cloud runtime resolver for run/auto/review
**Description:** As a developer, I want one shared resolver for flags/env/config defaults so that cloud behavior is consistent across workflows.

**Acceptance Criteria:**
- [ ] `run/auto/review` expose shared flags: `--cloud`, `--cloud-profile`, `--detach`, `--wait`, `--json`, and documented override flags.
- [ ] Precedence is implemented and tested: CLI flags > process env > `.env` (non-overriding) > `.hal/cloud.yaml` > inferred defaults > hard defaults.
- [ ] `--detach` and waiting are mutually exclusive with a clear validation error.
- [ ] Local execution path is unchanged when `--cloud` is not set.
- [ ] Typecheck passes

### US-009: Add cloud execution path for `hal run --cloud`
**Description:** As a user, I want `hal run --cloud` to submit and track a cloud run so that cloud feels like local run with remote execution.

**Acceptance Criteria:**
- [ ] `hal run --cloud` submits a run with `workflowKind=run`.
- [ ] Wait/detach behavior follows resolved defaults and explicit flags.
- [ ] Human output includes run ID, current status, and next-step command hints.
- [ ] JSON mode returns valid machine-readable submission/progress/summary payloads.
- [ ] Typecheck passes

### US-010: Add cloud execution parity for `hal auto --cloud` and `hal review --cloud`
**Description:** As a user, I want auto and review to support cloud mode identically so that all workflows use one model.

**Acceptance Criteria:**
- [ ] `hal auto --cloud` submits with `workflowKind=auto`; `hal review --cloud` submits with `workflowKind=review`.
- [ ] Both commands reuse shared cloud resolution and submit/wait behavior.
- [ ] Completion summary references report and state artifact availability where applicable.
- [ ] JSON mode is valid and consistent with run command shape.
- [ ] Typecheck passes

### US-011: Enforce workflow-kind worker dispatch
**Description:** As a system owner, I want workers to execute only the command matching persisted workflow kind so that jobs cannot run the wrong workflow.

**Acceptance Criteria:**
- [ ] Worker dispatch maps `run -> hal run`, `auto -> hal auto`, `review -> hal review`.
- [ ] Invalid dispatch patterns (e.g., workflow selection via unrelated mode flags) are not used.
- [ ] Worker tests assert exact command construction by kind.
- [ ] Logs/events include workflow kind for observability.
- [ ] Typecheck passes

### US-012: Finalize status/logs/cancel/pull command behavior
**Description:** As a user, I want reliable follow-up controls so that I can manage cloud runs after submission.

**Acceptance Criteria:**
- [ ] `hal cloud status <run-id>`, `hal cloud logs <run-id> [--follow]`, `hal cloud cancel <run-id>`, and `hal cloud pull <run-id> [--artifacts state|reports|all]` are implemented and documented.
- [ ] `pull` supports deterministic artifact selection for each artifacts mode.
- [ ] Pull behavior is safe for existing local files (no destructive overwrite unless explicitly forced by flag behavior).
- [ ] Each command supports `--json` with valid JSON output.
- [ ] Typecheck passes

### US-013: Complete auth hardening and redaction
**Description:** As a security-conscious user, I want auth flows and logs to avoid secret leakage so that cloud usage is safe by default.

**Acceptance Criteria:**
- [ ] `hal cloud auth import` uses real secure handling (no placeholder success path).
- [ ] `.hal/cloud.yaml` never stores secrets.
- [ ] Logs/events/errors redact tokens, DSNs, and secret references.
- [ ] `hal cloud auth status|validate|revoke` reflect real credential state transitions.
- [ ] Security-focused tests validate redaction and non-persistence of secrets.
- [ ] Typecheck passes

### Frontend (CLI UX)

### US-014: Standardize cloud help text and command discoverability
**Description:** As a user, I want concise help output so that I can learn cloud commands quickly without legacy noise.

**Acceptance Criteria:**
- [ ] `hal cloud --help` lists only supported commands: setup, doctor, list, status, logs, cancel, pull, auth.
- [ ] `hal run --help`, `hal auto --help`, and `hal review --help` each document cloud flags consistently.
- [ ] Removed commands do not appear in any help text.
- [ ] Help snapshots/tests verify exact command tree and key flag docs.
- [ ] Typecheck passes

### US-015: Standardize terminal summaries and machine output
**Description:** As a user and tool integrator, I want predictable human and JSON outputs so that cloud automation and manual usage both work reliably.

**Acceptance Criteria:**
- [ ] Human-mode output includes concise progress and final summary with run ID, terminal status, and next-step commands.
- [ ] JSON-mode output is valid JSON and contains run ID, workflow kind, and status fields.
- [ ] Missing setup/profile/auth errors are explicit and actionable.
- [ ] Integration tests validate JSON parseability and expected fields across run/auto/review and support commands.
- [ ] Typecheck passes

## 4) Functional Requirements
- FR-1: The system must support cloud execution through `hal run [--cloud]`, `hal auto [--cloud]`, and `hal review [--cloud]`.
- FR-2: The system must provide cloud support commands: `setup`, `doctor`, `list`, `status`, `logs`, `cancel`, `pull`, and `auth link|import|status|validate|revoke`.
- FR-3: The system must remove legacy commands (`cloud run`, `cloud runs ...`, flat submit/status/logs/cancel/pull variants, `cloud smoke`, `cloud env`) with no compatibility aliases.
- FR-4: The system must expose shared cloud flags on run/auto/review: `--cloud`, `--cloud-profile`, `--detach`, `--wait`, `--json`, and optional overrides (`--repo`, `--base`, `--engine`, `--auth-profile`, `--scope`).
- FR-5: The system must enforce mutual exclusion between detach and waiting behavior.
- FR-6: The system must preserve existing local behavior when `--cloud` is not specified.
- FR-7: The system must load cloud runtime config using precedence: CLI > process env > `.env` (non-overriding) > `.hal/cloud.yaml` > inferred defaults > hard defaults.
- FR-8: The system must persist run workflow kind (`run`, `auto`, `review`) for every cloud submission.
- FR-9: Worker execution must dispatch to the exact workflow command matching persisted kind.
- FR-10: `.hal/cloud.yaml` must store only non-secret defaults.
- FR-11: `hal cloud setup` must guide users to create/update non-secret profile defaults in `.hal/cloud.yaml`.
- FR-12: `hal cloud doctor` must validate configuration, connectivity, and auth readiness and provide actionable remediation guidance.
- FR-13: `hal cloud list` must return run summaries with status and workflow kind in both human and JSON modes.
- FR-14: `hal cloud status/logs/cancel/pull` must support stable run follow-up management by run ID.
- FR-15: `hal cloud pull` must support `--artifacts state|reports|all` with deterministic selection and safe overwrite behavior.
- FR-16: Auto/review workflows must produce report artifacts for pull.
- FR-17: All `--json` command modes must output valid machine-readable JSON without mixed formatting.
- FR-18: Logs/events/errors must redact secret material (tokens, DSNs, secret refs).

## 5) Non-Goals
- Backward compatibility aliases/shims for removed cloud commands.
- Introducing extra infrastructure nouns/abstractions into primary command names.
- Storing secrets in project files (including `.hal/cloud.yaml`).
- Expanding into unrelated cloud orchestration features beyond setup/doctor/list/status/logs/cancel/pull/auth.

## 6) Design Considerations
- Intent-first UX: users should start work with run/auto/review and opt into cloud via `--cloud`.
- Progressive disclosure: advanced overrides are available as flags but not required for first-run success.
- Help output should be short, consistent, and free of deprecated terminology.
- Diagnostics should always provide a concrete next step (e.g., run setup, validate auth, check profile name).

## 7) Technical Considerations
- Keep cloud runtime resolution centralized to avoid divergent behavior across run/auto/review.
- Maintain strict separation of non-secret config (`.hal/cloud.yaml`) and credential storage.
- Ensure JSON output paths are schema-stable enough for automation consumers.
- Add/expand command and integration tests for command tree cleanup, precedence resolution, worker dispatch, artifact pull behavior, and redaction.

## 8) Success Metrics
- New-user scenario success: from clean repo, `hal cloud setup` + `hal run --cloud` completes submission and progress tracking in one attempt.
- Discoverability: `hal cloud --help` shows only the defined minimal command set; removed commands are unavailable.
- Reliability: command/cloud test suites pass for all new/updated command paths.
- Security: tests confirm no secret persistence in `.hal/cloud.yaml` and redaction in logs/events/errors.
- Output quality: JSON mode is parseable and complete across workflow and support commands.

## 9) Open Questions
- Should default wait behavior differ by workflow kind (run vs auto/review), or remain profile-global?
- Should `hal cloud pull` expose an explicit `--force` flag now, or only safe non-overwrite behavior in this phase?
- Should `hal cloud list` default to active profile only, or all accessible profiles with filtering as a follow-up?
- Should doctor include optional deep checks (e.g., remote execution probe) behind a separate flag?