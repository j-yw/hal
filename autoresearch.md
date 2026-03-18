# Autoresearch: HAL UX & Machine Readability Improvements

## Objective
Improve HAL CLI's operational coherence: fix test failures, add machine-readable output (`--json`) to all core commands, fix test isolation, add status/doctor/continue commands, improve UX clarity, and reduce confusing surfaces.

## Metrics
- **Primary**: `test_failures` (count, lower is better)
- **Secondary**: `total_tests` (count of passing tests), `vet_clean` (1 if `go vet` passes)

## How to Run
`./autoresearch.sh` — runs `go test -count=1 -v ./...` and `go vet ./...`, outputs `METRIC` lines.

## Results Summary
- **Baseline**: 3 test failures, ~387 tests
- **Final**: 0 test failures, 440 tests, vet clean
- **33 experiments**, all kept (100% hit rate)
- **4 new commands**: status, doctor, continue, (archive list --json)
- **15+ commands** now support `--json`
- **3 new packages**: `internal/status`, `internal/doctor`

## What's Been Done

### Test Reliability (Experiment 1)
- Fixed 3 flaky engine tests: timeout 2s→10s in claude/codex/pi

### New Commands (Experiments 2-3, 29)
- `hal status --json` — v1 workflow state machine contract (manual, compound, review_loop, unknown)
- `hal doctor --json` — v1 health/readiness contract, engine-aware
- `hal continue --json` — combines status + doctor into "what to do next"

### Test Isolation (Experiment 4)
- Codex linker respects `$HOME` env, init tests use `t.Setenv`

### Machine-Readable JSON (Experiments 6-15, 20-21, 24, 27)
`--json` on: init, status, doctor, run, report, auto, analyze, validate, convert, cleanup, config, standards list, review, archive list, version, continue

### Status Enrichment (Experiments 22-23, 25)
- Story counts, nextStory, branchName, paths
- Compound detail (step, branch from auto-state.json)
- Review-loop as first-class workflow track
- Human-readable output with story progress and branch

### Doctor Enhancements (Experiments 19, 26, 32)
- Engine-aware: skips Codex checks for pi/claude
- Detects legacy debris (.goralph, ralph links, rules/)
- Detects broken skill symlinks in .claude/skills/ and .pi/skills/
- Actionable remediation commands with safe/command fields
- PrimaryRemediation in result for agents

### UX Improvements (Experiments 5, 16, 30)
- `hal report`: "legacy" → "Generate summary report"
- `hal init` help: separates repo-local/engine-local/global side effects
- Root command help: includes status/doctor/continue

### Cleanup Expansion (Experiments 8, 31)
- Removes orphaned rules/ directories
- Removes deprecated .claude/skills/ralph and .pi/skills/ralph links

### Contract Governance (Experiments 17, 33)
- status, doctor, cleanup, convert, continue, version locked in core metadata tests
- Machine contract field-locking tests for status/doctor/continue JSON
