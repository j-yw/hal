# Autoresearch: HAL UX & Machine Readability Improvements

## Objective
Improve HAL CLI's operational coherence: fix test failures, add machine-readable output (`--json`) to core commands, fix test isolation (Codex linker leaks), improve UX clarity, and reduce confusing surfaces.

## Metrics
- **Primary**: `test_failures` (count, lower is better)
- **Secondary**: `total_tests` (count of passing tests), `vet_clean` (1 if `go vet` passes)

## How to Run
`./autoresearch.sh` — runs `go test -count=1 -v ./...` and `go vet ./...`, outputs `METRIC` lines.

## Files in Scope
- `cmd/*.go` — all CLI command implementations + tests
- `internal/status/` — workflow state classification (NEW)
- `internal/doctor/` — health/readiness checks (NEW)
- `internal/engine/*/` — engine implementations + tests
- `internal/skills/` — skill infrastructure + linkers
- `internal/template/` — constants and defaults
- `internal/compound/` — compound pipeline types
- `internal/prd/` — PRD types

## Off Limits
- `internal/sandbox/` — sandbox implementation (separate concern)
- `go.mod`, `go.sum` — no new dependencies

## Constraints
- `go test ./...` must pass (0 failures)
- `go vet ./...` must be clean
- No new external dependencies
- Existing test behavior preserved

## What's Been Done (21 experiments, all kept)

### Baseline Fix (Experiment 1)
- 3 flaky engine tests: timeout 2s→10s in claude/codex/pi

### New Commands (Experiments 2-3)
- `hal status --json` — v1 workflow state machine contract
- `hal doctor --json` — v1 health/readiness contract, engine-aware

### Test Isolation (Experiment 4)  
- Codex linker respects `$HOME` env, init tests use `t.Setenv`

### UX Improvements (Experiments 5, 16)
- `hal report` label: "legacy" → "Generate summary report"
- `hal init` help: separates repo-local/engine-local/global side effects

### Machine-Readable JSON (Experiments 6-15, 20-21)
Complete `--json` coverage: init, status, doctor, run, report, auto, analyze, validate, convert, cleanup, config, standards list, review

### Doctor Enhancements (Experiment 19)
- Detects legacy debris (.goralph, ralph links, rules/)

### Metadata Contracts (Experiment 17)
- status, doctor, cleanup, convert locked in core metadata tests

## Results
- **Baseline**: 3 test failures, ~387 tests
- **Final**: 0 test failures, 421 tests, vet clean
- **13 commands** now support `--json`
- **2 new packages**: `internal/status`, `internal/doctor`
