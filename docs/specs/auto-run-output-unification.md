# Spec: Unify `hal auto` / `hal run` Human Output and Preserve Engine Signal

## Problem

Human output styling is currently only partially unified:

- `hal auto` uses shared `engine.Display` command chrome (`ShowCommandHeader`, `ShowCommandSuccess`) but still has a few manual `fmt.Fprintf` branches.
- `hal run` uses shared loop rendering internally (`ShowLoopHeader`, iteration UI, spinner/events) but command-layer preflight and final summary are still custom formatting.
- In some auto steps, useful model output is hidden behind generic text like `assistant response received`, which makes progress feel opaque even when the engine produced structured results.

This creates a mixed UX and lower operator confidence during long auto runs.

## Goals

1. Use one shared visual language (lipgloss styles + display primitives) for **both** `hal auto` and `hal run` human output.
2. Preserve and surface useful engine signal (especially structured JSON responses) without dumping noisy raw payloads.
3. Keep machine output contracts unchanged (`hal auto --json` and `hal run --json` remain byte-shape stable).
4. Avoid command-surface bloat (no new user-facing flags/subcommands).

## Non-Goals

- No pipeline behavior changes (step order/gates remain unchanged).
- No changes to contract versions or field names.
- No changes to engine execution semantics/timeouts/retries.

---

## Current-State Snapshot

### Already unified
- Shared palette/styles: `internal/engine/styles.go`
- Shared renderer: `internal/engine/display.go`
- `hal auto` command header/success box paths.
- `hal run` loop-internal rendering via `loop.Runner` + `engine.Display`.

### Not yet unified
- `cmd/run.go` command-layer preflight errors and summary are still manual render paths.
- `cmd/auto.go` no-report warning path uses direct `fmt.Fprintf` instead of display-owned warning rendering.
- Text event rendering may collapse structured engine output into non-informative generic lines.

---

## UX Contract (Human Mode)

### Shared command chrome (both `auto` and `run`)
- Boxed command header.
- Styled phase/step notes.
- Boxed completion/failure/warning outcomes.
- Muted secondary details (duration, branches, counts).

### Engine signal visibility
- Keep streaming tool/thinking events.
- For structured assistant payloads, show concise semantic summaries (not raw JSON), e.g.:
  - `validation: valid (0 errors, 1 warning)`
  - `conversion: 7 stories generated`
  - `review: 3 issues identified`

### JSON mode guarantees
- `--json` emits JSON only (no human lines, no ANSI).

---

## Design

## 1) Extend display primitives (minimal)

Add small command-level helpers in `internal/engine/display.go` to remove ad-hoc formatting from commands:

- `ShowCommandWarning(title, details string)`
- `ShowCommandHint(lines []string)` (or equivalent small helper)

Purpose: keep warning/hint blocks visually consistent and avoid repeating style logic in command files.

## 2) Normalize `hal run` command-layer rendering

In `cmd/run.go`:

- Create command display in human mode and render header via `ShowCommandHeader("Run", "task loop", ...)`.
- Replace manual summary function output with display-owned outcome methods:
  - success box for complete/partial success
  - warning or error box for blocked/failed states
- Keep loop internals untouched (they already stream rich activity).

## 3) Finish `hal auto` command-layer cleanup

In `cmd/auto.go`:

- Replace remaining raw no-report human path text with display-owned warning/hint rendering.
- Keep all policy/source/status lines routed through display helpers.

## 4) Improve text-event summarization (engine signal)

In `internal/engine/display.go` text-event handling:

- Detect JSON payloads from assistant text events.
- Parse top-level keys and render compact semantic summaries for known shapes:
  - Validation-like: `valid`, `errors`, `warnings`
  - Conversion-like: `userStories`
  - Review-like: `issues`, `summary`
- Fallback behavior remains existing generic message if shape is unknown/unparseable.

Rules:
- Never print raw JSON bodies in human stream by default.
- Keep summaries one-line, muted/info styled, and deterministic.

---

## Implementation Plan

### Phase A — Display helpers + event summaries
1. Add `ShowCommandWarning` (+ optional hint helper).
2. Add structured text summary helper and unit tests in `internal/engine/display_test.go`.

### Phase B — `hal run` command unification
1. Replace command-level manual output paths with display helpers.
2. Keep all error semantics/exit codes unchanged.
3. Update `cmd/run_test.go` expectations for human output patterns.

### Phase C — `hal auto` command cleanup
1. Replace remaining manual warning/hint branch with display helper usage.
2. Verify human-mode output still includes key guidance (`--resume`, source resolution notes).
3. Update `cmd/auto_test.go` where needed.

### Phase D — Contract safety checks
1. Re-run JSON contract tests for `run`/`auto`.
2. Re-run docs/metadata checks if any help text changed.

---

## Test Plan

### Unit tests
- `internal/engine/display_test.go`
  - known JSON shape -> expected summary text
  - unknown/invalid JSON -> fallback generic text

### Command tests
- `cmd/run_test.go`
  - human output uses command header + boxed summary
  - no change in validation error behavior / exit codes
- `cmd/auto_test.go`
  - no-report path renders display warning/hints consistently

### Contract tests (must remain stable)
- `cmd/machine_contracts_test.go`
- `cmd/contracts_doc_test.go` (if docs impacted)

### Manual smoke
- `hal run --dry-run` with valid `.hal/prd.json`
- `hal auto --dry-run <prd>`
- `hal auto --json ...` and `hal run --json ...` (assert pure JSON)

---

## Acceptance Criteria

1. `hal auto` and `hal run` human outputs use the same display style system end-to-end.
2. `hal run` no longer has ad-hoc command summary rendering.
3. Useful structured engine outcomes are summarized in human stream (without raw JSON spam).
4. JSON outputs are unchanged in shape and remain machine-parseable.
5. Existing pipeline behavior and gating semantics remain unchanged.

---

## Estimated Change Size

### Core code
- `internal/engine/display.go`: ~70–120 LOC
- `cmd/run.go`: ~90–140 LOC
- `cmd/auto.go`: ~25–50 LOC
- optional small touches in pipeline messaging: ~20–30 LOC

**Core subtotal:** ~205–340 LOC

### Tests/docs
- `internal/engine/display_test.go`: ~40–80 LOC
- `cmd/run_test.go`: ~60–110 LOC
- `cmd/auto_test.go`: ~30–50 LOC
- minor docs/help sync (if needed): ~10–20 LOC

**Tests/docs subtotal:** ~140–260 LOC

### Total estimated delta

**~345–600 LOC** (including tests).

---

## Risks and Mitigations

- **Risk:** Over-summarization hides important details.  
  **Mitigation:** keep tool/thinking lines unchanged; only summarize assistant text payloads.

- **Risk:** Human-output test brittleness from ANSI/style changes.  
  **Mitigation:** assert key phrases/structure, not exact full ANSI blobs.

- **Risk:** JSON mode leakage with human text.  
  **Mitigation:** retain `io.Discard` display behavior in JSON mode and add explicit regression tests.

---

## Rollout

1. Ship display helper + run/auto unification in one PR.
2. Validate in dry-run and normal-run scenarios.
3. If needed, iterate on summary heuristics in a follow-up PR without changing command contracts.
