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
- `internal/skills/codex.go`, `codex_test.go` — Codex linker (global state leaks)
- `internal/skills/claude.go`, `pi.go` — other engine linkers
- `internal/skills/skills.go`, `linker.go`, `embed.go` — skill infrastructure
- `internal/template/template.go` — constants and defaults
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

## Improvement Queue (Priority Order)
1. Fix flaky claude/codex engine tests (2s timeout too tight)
2. Add `hal status --json` command (workflow state machine contract)
3. Add `hal doctor --json` command (readiness/health contract)
4. Make Codex linker tests hermetic (don't leak to real ~/.codex)
5. Add `--json` to `hal run` (structured completion output)
6. Add `--json` to `hal report` (structured report output)
7. Unify format flags: add `--json` alongside `--format json` on analyze
8. Improve `hal report` description (remove "legacy" confusion)
9. Add engine-awareness to doctor/init linking checks
10. Expand `hal cleanup` orphaned files list

## What's Been Tried
(Updated as experiments accumulate)
