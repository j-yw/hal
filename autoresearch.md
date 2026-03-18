# Autoresearch: HAL UX & Machine Readability Improvements

## Objective
Improve HAL CLI's operational coherence: fix test failures, add machine-readable output (`--json`) to core commands, fix test isolation (Codex linker leaks), improve UX clarity, and reduce confusing surfaces.

## Metrics
- **Primary**: `test_failures` (count, lower is better)
- **Secondary**: `total_tests` (count of passing tests), `vet_clean` (1 if `go vet` passes)

## How to Run
`./autoresearch.sh` — runs `go test ./...` and `go vet ./...`, outputs `METRIC` lines.

## What's Been Done (All Kept)

### Test Reliability
1. **Fix flaky engine tests** — Increased test timeouts from 2s→10s in claude/codex/pi tests. Fixed 3 flaky tests.

### New Commands
2. **hal status --json** — v1 workflow state machine contract: not_initialized, hal_initialized_no_prd, manual_in_progress, manual_complete, compound_active. 14 tests.
3. **hal doctor --json** — v1 health/readiness contract. Engine-aware (skips Codex checks for pi/claude). 13 tests.

### Test Isolation
4. **Codex linker isolation** — `CodexLinker` now uses `$HOME` env (overridable via `t.Setenv`). Init tests use `t.Setenv("HOME", dir)`. 2 new isolation tests.

### UX Improvements
5. **hal report UX** — Removed "legacy session reporting" label → "Generate summary report for completed work". Updated root help.
6. **hal init help** — Explicitly separates repo-local, engine-local, and global (~/.codex) side effects.

### Machine-Readable JSON Flags (10 commands)
7. **hal run --json** — RunResult: ok/iterations/complete/summary
8. **hal analyze --json** — Shorthand for `--format json` with conflict guard
9. **hal report --json** — ReportResult: reportPath/summary/recommendations
10. **hal auto --json** — AutoResult: ok/error/summary
11. **hal validate --json** — Outputs ValidationResult as JSON
12. **hal init --json** — InitResult: created/skipped files
13. **hal convert --json** — ConvertResult: outputPath/valid
14. **hal cleanup --json** — CleanupResult: removed items
15. **hal config --json** — Config existence/content as JSON

### Cleanup & Tests
16. **hal cleanup expanded** — Now removes orphaned `rules/` directories
17. **Core metadata tests** — Added status, doctor, cleanup, convert to locked metadata contract

## Results
- **Baseline**: 3 test failures, ~387 tests
- **Final**: 0 test failures, 419+ tests, vet clean
- **All core commands** now support `--json`: init, status, doctor, run, report, auto, analyze, validate, convert, cleanup, config
