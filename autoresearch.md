# Autoresearch: HAL UX & Machine Readability Improvements

## Objective
Improve HAL CLI's operational coherence: fix test failures, add machine-readable output (`--json`) to core commands, fix test isolation (Codex linker leaks), improve UX clarity, and reduce confusing surfaces. Each iteration fixes one concrete issue, verifies the test suite stays green, and commits.

## Metrics
- **Primary**: `test_failures` (count, lower is better)
- **Secondary**: `total_tests` (count of passing tests), `vet_clean` (1 if `go vet` passes)

## How to Run
`./autoresearch.sh` — runs `go test ./...` and `go vet ./...`, outputs `METRIC` lines.

## Files in Scope
- `cmd/*.go` — all CLI command implementations
- `cmd/*_test.go` — all CLI tests
- `internal/engine/claude/claude.go`, `claude_test.go` — Claude engine + tests
- `internal/engine/codex/codex.go`, `codex_exec_test.go` — Codex engine + tests
- `internal/engine/pi/pi_exec_test.go` — Pi engine tests
- `internal/skills/codex.go`, `codex_test.go` — Codex linker (global state leaks)
- `internal/skills/claude.go`, `pi.go` — other engine linkers
- `internal/skills/skills.go`, `linker.go`, `embed.go` — skill infrastructure
- `internal/template/template.go` — constants and defaults
- `internal/status/status.go` — workflow state classification (NEW)
- `internal/doctor/doctor.go` — health/readiness checks (NEW)
- `internal/compound/*.go` — compound pipeline types
- `internal/prd/*.go` — PRD types

## Off Limits
- `internal/sandbox/` — sandbox implementation (separate concern)
- `internal/engine/*/integration_test.go` — integration tests requiring real CLIs
- `.hal/` runtime state — don't modify user state
- `go.mod`, `go.sum` — no new dependencies

## Constraints
- `go test ./...` must pass (0 failures)
- `go vet ./...` must be clean
- No new external dependencies
- All changes must include tests
- Existing test behavior preserved (fix flaky, don't remove)
- Follow conventional commits

## What's Been Tried

### Completed (all kept)
1. **Fix flaky engine tests** — Increased test timeouts from 2s to 10s in claude/codex/pi engine tests. Root cause: process startup under load could exceed 2s. Fixed 3 flaky tests.
2. **hal status --json** — Created `internal/status` package with v1 workflow state machine contract. States: not_initialized, hal_initialized_no_prd, manual_in_progress, manual_complete, compound_active. 14 new tests.
3. **hal doctor --json** — Created `internal/doctor` package with v1 health/readiness contract. Engine-aware: skips Codex checks when engine is pi/claude. 13 new tests.
4. **Codex linker test isolation** — Made `CodexLinker` use `$HOME` env (overridable in tests via `t.Setenv`) instead of cached `os.UserHomeDir()`. Added `t.Setenv("HOME", dir)` to all init tests. 2 new isolation tests verify no real `~/.codex` pollution.
5. **hal report UX** — Removed "legacy session reporting" label, now "Generate a summary report for completed work". Updated root help to include status/doctor.
6. **hal run --json** — Structured `RunResult` with ok/iterations/complete/summary. 3 new tests.
7. **hal analyze --json** — Added `--json` shorthand alongside `--format json` with conflict guard.
8. **hal cleanup expanded** — Now removes orphaned `rules/` directories. 2 new tests.
9. **hal report --json** — Structured `ReportResult` with reportPath/summary/recommendations.
10. **hal auto --json** — Structured `AutoResult` with ok/error/summary.
11. **hal validate --json** — Outputs `ValidationResult` as JSON.
12. **hal init --json** — Structured `InitResult` with created/skipped file lists.

### Summary
- Baseline: 3 test failures, ~387 tests
- Current: 0 test failures, 419 tests
- All core commands now support `--json`: init, status, doctor, run, report, auto, analyze, validate
