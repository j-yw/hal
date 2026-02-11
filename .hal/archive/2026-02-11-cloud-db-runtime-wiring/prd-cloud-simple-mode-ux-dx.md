# PRD: Cloud Simple Mode UX/DX

## 1) Introduction/Overview

`hal cloud` is powerful, but normal product engineers currently need to orchestrate multiple operational commands (`submit`, `status`, `logs`, `pull`, `auth`) to complete one cloud run. This is high-friction and hard to adopt as a daily workflow.

This PRD defines a Simple Mode that makes cloud usage feel like `hal run`:
- One-time setup: `hal cloud setup`
- Daily command: `hal cloud run`

Simple Mode must package context, execute in Daytona, stream progress, and return a PR URL (or a clear failure reason), with optional local state sync. Existing advanced commands remain unchanged for operators/power users.

## 2) Goals

- A new user can complete first cloud run with only `hal cloud setup` then `hal cloud run`.
- Daily cloud execution for normal engineers requires one high-level command.
- Successful runs create or reuse a PR automatically and return a PR URL.
- Failures always provide clear reason + actionable next step.
- No secrets are written to local profile state.

## 3) User Stories

### US-001: [Schema] Define `.hal/cloud.yaml` profile model
**Description:** As a developer, I want a versioned cloud profile schema so defaults can be stored and loaded consistently.

**Acceptance Criteria:**
- [ ] A profile model exists with fields: `version`, `mode`, `controlPlaneURL`, `runnerURL`, and `defaults.{repo,base,engine,authProfile,provider,wait,autoPull,autoPR}`.
- [ ] Profile read/write supports round-trip without losing supported fields.
- [ ] Missing `.hal/cloud.yaml` returns a handled “profile not found” path (no panic).
- [ ] Typecheck passes

### US-002: [Schema] Enforce safe persistence and config precedence
**Description:** As a user, I want predictable config resolution that never persists credentials.

**Acceptance Criteria:**
- [ ] `.hal/cloud.yaml` explicitly excludes token/secret fields from persistence.
- [ ] Effective config precedence is implemented and tested as: flags > exported env > profile file > inferred defaults.
- [ ] Unit tests cover precedence for both `managed` and `local` modes.
- [ ] Typecheck passes

### US-003: [Backend] Implement `hal cloud setup` mode detection + env validation
**Description:** As a new user, I want setup to detect mode and validate requirements so setup succeeds on first attempt.

**Acceptance Criteria:**
- [ ] Setup loads config from exported env first, then `.env` fallback.
- [ ] Mode resolves to `managed` when control-plane URL is present (or `--mode managed`), else `local`.
- [ ] Missing required env for the selected mode exits non-zero and lists missing keys.
- [ ] `--yes` runs without interactive prompts.
- [ ] Typecheck passes

### US-004: [Backend] Add local stack bootstrap + health checks to setup
**Description:** As a local-mode user, I want setup to verify services so the next run works immediately.

**Acceptance Criteria:**
- [ ] In local mode, setup can start docker compose services when user confirms or `--yes` is set.
- [ ] Setup checks control-plane and runner health endpoints before reporting ready.
- [ ] Failed health checks show the failing endpoint and a concrete remediation command.
- [ ] Typecheck passes

### US-005: [Backend] Add auth profile configuration in setup
**Description:** As a user, I want setup to configure auth defaults so cloud run requires no manual auth steps.

**Acceptance Criteria:**
- [ ] Setup supports `--provider` and `--profile` with defaults `anthropic` and `default`.
- [ ] Setup supports `--auth-source <path>` import and `--secret-ref <ref>` link flows.
- [ ] Setup fails with actionable message when auth profile cannot be linked/resolved.
- [ ] Successful setup prints a ready summary and next step `hal cloud run`.
- [ ] Typecheck passes

### US-006: [Backend] Implement simple run preflight + submission
**Description:** As a user, I want `hal cloud run` to do preflight checks and submit work automatically.

**Acceptance Criteria:**
- [ ] `hal cloud run` loads profile/env and resolves effective config with precedence rules.
- [ ] Run preflight verifies profile, service health, and linked auth profile before submission.
- [ ] Run packages allowlisted `.hal` context and submits a cloud run.
- [ ] Submission failure exits with non-zero and does not start wait/log follow.
- [ ] Typecheck passes

### US-007: [Backend] Implement default wait + progress streaming
**Description:** As a user, I want default run behavior to stream progress until terminal completion.

**Acceptance Criteria:**
- [ ] By default, `hal cloud run` waits for terminal state and streams progress/logs.
- [ ] Terminal detection handles success, failure, and canceled states.
- [ ] Final summary includes run ID, terminal status, and elapsed time.
- [ ] Typecheck passes

### US-008: [Backend] Add run control flags and one-off overrides
**Description:** As a user, I want lightweight flags for common exceptions without using advanced commands.

**Acceptance Criteria:**
- [ ] `--detach` returns `run_id` immediately and skips wait/log following.
- [ ] `--no-pr` disables PR creation for that invocation.
- [ ] `--no-pull` disables local sync for that invocation.
- [ ] `--repo`, `--base`, `--engine`, `--auth-profile`, `--scope` override stored defaults only for current run.
- [ ] Typecheck passes

### US-009: [Backend] Integrate PR create/reuse on terminal success
**Description:** As a user, I want successful runs to automatically create or reuse a PR.

**Acceptance Criteria:**
- [ ] Terminal-success flow invokes PR creation via idempotent service semantics.
- [ ] GitHub adapter supports create/update/comment and returns canonical PR ref + URL.
- [ ] System emits `pr_create_completed` with `pr_ref`, and run metadata exposes this for CLI retrieval.
- [ ] Tests cover first-create and idempotent-reuse cases.
- [ ] Typecheck passes

### US-010: [Backend] Add optional post-run local pull behavior
**Description:** As a user, I want optional automatic pull so local state stays aligned with cloud output.

**Acceptance Criteria:**
- [ ] On successful runs, pull is executed when auto-pull is enabled and `--no-pull` is not set.
- [ ] Pull result prints either changed-file summary or “no changes”.
- [ ] Pull errors are reported without overwriting the underlying run terminal status.
- [ ] Typecheck passes

### US-011: [Frontend] Standardize human + JSON run output
**Description:** As a user and as automation tooling, I want stable output contracts for simple mode runs.

**Acceptance Criteria:**
- [ ] Human summary includes run ID, terminal status, elapsed time, PR URL (when available), and next step on failure.
- [ ] `--json` emits one valid JSON object with at least `run_id`, `status`, `elapsed_ms`, optional `pr_url`, and optional `next_steps`.
- [ ] In JSON mode, structured output is sent to stdout and log/progress output is sent to stderr.
- [ ] Typecheck passes
- [ ] Verify in browser using agent-browser skill (skip if no dev server running)

### US-012: [Frontend] Publish simple-mode docs and migration guidance
**Description:** As a new user, I want concise docs so I can use Simple Mode without learning operator workflows first.

**Acceptance Criteria:**
- [ ] Docs include a two-command quickstart: `hal cloud setup` then `hal cloud run`.
- [ ] Docs explicitly state advanced commands remain available and unchanged.
- [ ] Troubleshooting section covers setup validation failures, run preflight failures, and PR creation failures.
- [ ] Typecheck passes

## 4) Functional Requirements

- FR-1: Add `hal cloud setup` as a guided one-time initialization command.
- FR-2: `hal cloud setup` must load exported env values before `.env` fallback values.
- FR-3: Setup must detect `managed` vs `local` mode and allow explicit `--mode` override.
- FR-4: Setup must validate mode-specific required env and fail with explicit missing-key output.
- FR-5: Setup in local mode must support optional local stack startup.
- FR-6: Setup must verify control-plane and runner health before declaring readiness.
- FR-7: Setup must support non-interactive operation via `--yes`.
- FR-8: Setup must support auth defaults and auth configuration via `--provider`, `--profile`, `--auth-source`, and `--secret-ref`.
- FR-9: Setup must save defaults to `.hal/cloud.yaml` and print next-step guidance.
- FR-10: `.hal/cloud.yaml` must be versioned and store no secrets/tokens.
- FR-11: Add `hal cloud run` as the high-level simple-mode execution command.
- FR-12: Run must resolve effective config with precedence: flags > env > profile > inferred defaults.
- FR-13: Run must infer repo/base when not provided and supported by local git context.
- FR-14: Run must perform preflight checks (profile, health, auth linkage) before submit.
- FR-15: Run must package allowlisted `.hal` context and submit execution to Daytona.
- FR-16: Default run mode must wait and stream progress/logs until terminal state.
- FR-17: `--detach` must return immediately with run ID.
- FR-18: `--no-pr` and `--no-pull` must disable PR creation and local pull for the current invocation.
- FR-19: Successful terminal runs must trigger idempotent PR create/reuse and expose PR URL.
- FR-20: System must emit and persist PR completion metadata (`pr_create_completed`, `pr_ref`).
- FR-21: Successful runs must perform optional local pull when enabled.
- FR-22: Final output must include run ID, status, elapsed time, PR URL (if any), and actionable failure next steps.
- FR-23: `--json` must provide a stable machine-readable output contract.
- FR-24: Existing advanced cloud commands (`submit/status/logs/cancel/pull/auth/env/smoke`) must remain unchanged.

## 5) Non-Goals

- Removing, replacing, or behavior-changing advanced cloud commands.
- Storing secrets, API keys, or tokens in `.hal/cloud.yaml`.
- Shipping `hal cloud doctor` or `hal cloud down` in this release.
- Building a separate web UI for setup/run.
- Redesigning non-simple-mode operator workflows.

## 6) Design Considerations

- Keep first-time experience guided and low-cognitive-load.
- Preserve scriptability via non-interactive flags.
- Favor actionable error copy over internal implementation details.
- Keep default output concise but information-complete.

## 7) Technical Considerations

- New profile file: `.hal/cloud.yaml` (local-only, non-secret state).
- Implementation split:
  - PR A: profile + setup (`cmd/cloud_setup.go`, `internal/cloud/ux/profile.go`, `internal/cloud/ux/setup.go`)
  - PR B: simple run orchestration (`cmd/cloud.go` run path, wait/detach/no-pr/no-pull)
  - PR C: PR integration (GitHub adapter + idempotent PR service wiring + event persistence)
  - PR D: polish/docs/tests
- Reuse existing `PRCreateService` idempotency model.
- Add command tests for setup/run and integration tests for end-to-end simple flow.

## 8) Success Metrics

- Definition of Done: a new user can run `hal cloud setup` then `hal cloud run` and receive cloud execution, live progress, and a created/reused PR URL without manual submit/status/logs/pull/auth choreography.
- ≥90% of successful simple-mode runs surface a PR URL in final output.
- Median first-time setup-to-first-successful-run time is <15 minutes in internal validation.
- ≥80% of normal product-engineer cloud executions use simple-mode `hal cloud run` after rollout.
- ≥95% of failures include at least one actionable remediation step.

## 9) Open Questions

- Should `--yes` in local mode auto-start docker compose by default, or require an explicit startup flag?
- For v1, should the GitHub adapter use API-first, `gh` CLI-first, or hybrid fallback behavior?
- How should repo inference behave in multi-remote repos (`origin` vs `upstream` ambiguity)?
- What should happen when auto-pull is enabled but the local working tree is dirty?
- Should setup validate PR creation permissions immediately, or defer to run terminal-success path?
