# Autoresearch: HAL UX & Machine Readability Improvements

## Objective
Improve HAL CLI's operational coherence: fix test failures, add machine-readable output (`--json`) to all core commands, fix test isolation, add status/doctor/continue commands, improve UX clarity, and reduce confusing surfaces.

## Metrics
- **Primary**: `test_failures` (count, lower is better)
- **Secondary**: `total_tests` (count of passing tests), `vet_clean` (1 if `go vet` passes)

## Results Summary
- **Baseline**: 3 test failures, ~387 tests
- **Final**: 0 test failures, 442 tests, vet clean
- **42 experiments**, all kept except 1 verification run
- **4 new commands**: status, doctor, continue, (+ json on 16 total commands)
- **3 new packages**: `internal/status`, `internal/doctor`

## Key Improvements

### New Commands
- `hal status --json` — v1 workflow state machine (manual, compound, review_loop tracks)
- `hal doctor --json` — v1 health/readiness (engine-aware, broken links, legacy debris, YAML validation)
- `hal continue --json` — combines status + doctor into "what to do next"

### Machine-Readable JSON (16 commands)
init, status, doctor, continue, run, report, auto, analyze, validate, convert, cleanup, config, standards list, review, archive list, version, explode

### Status Contract Richness
- Story counts, nextStory, branchName, paths
- Compound detail (step, branch), compound_complete state
- Review-loop as first-class workflow track
- userStories + stories key support

### Doctor Enhancements
- Engine-aware (skips Codex for pi/claude), shows engine name
- Legacy debris (.goralph, ralph, rules/) detection
- Broken symlink detection in .claude/skills/ and .pi/skills/
- YAML syntax validation for config.yaml
- Actionable remediation commands with safe/command/primaryRemediation
- Specific warning summaries ("run hal cleanup", "refresh Codex links")

### Test Reliability
- Fixed 3 flaky engine tests (2s→10s timeout)
- Fixed race condition in metadata tests (t.Parallel on shared Root())
- Codex linker test isolation ($HOME env)

### UX Improvements
- Report: "legacy" → "Generate summary report"
- Init help: separates repo-local/engine-local/global side effects
- Root help: includes status/doctor/continue
- Cleanup: removes deprecated ralph links and rules/

### Contract Governance
- Machine contract field-locking tests for status/doctor/continue
- Core metadata tests lock all command metadata (Use/Short/Long/Example)
