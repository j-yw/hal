# Autoresearch: HAL UX & Machine Readability Improvements

## Objective
Improve HAL CLI's operational coherence: machine-readable output, workflow state, health checks, test reliability, UX clarity, link management, self-repair.

## Results
- **Baseline**: 3 test failures, ~387 tests
- **Final**: 0 test failures, 469 tests, 76 experiments, 75 commits
- **+5800 lines** across 49 files, 16 new files
- **7 new commands**: status, doctor, continue, repair, links status/refresh/clean
- **20+ commands** with `--json` flag
- **3 new packages**: internal/status, internal/doctor

## Deliverables

### Workflow State Machine (`hal status --json`)
8 states, 4 tracks (manual/compound/review_loop/unknown). Smart next-action routing (suggests convert when md PRD exists, auto when reports available). Manual detail: story counts, nextStory, branchName. Compound detail: step, branch, complete detection. Review-loop: latest report. Engine field from config.

### Health Checks (`hal doctor --json`)
13 checks with scope (repo/engine_local/engine_global/migration) and applicability (required/optional/not_applicable). YAML config validation, prd.json schema check, prompt.md content check. Remediation commands with safe flag. Engine-aware. Check pass rate. Deterministic.

### Self-Repair (`hal repair [--dry-run] [--json]`)
Auto-applies safe doctor remediations: init, cleanup, links refresh, links clean. Re-checks after repair.

### Link Management (`hal links`)
`status --json` — per-engine link health with detail. `refresh [engine]` — recreate links. `clean` — remove deprecated/broken links.

### What to Do Next (`hal continue --json`)
Combines status + doctor. Doctor issues shown as blockers. Compound/manual detail.

### Machine-Readable JSON (20+ commands)
init, status, doctor, continue, repair, links status, run, report, auto, analyze, validate, convert, cleanup, config, standards list, review, archive list/create/restore, version, explode

### Test Reliability (82 new tests)
Fixed: 3 flaky engine timeouts, race condition in t.Parallel, Codex linker $HOME isolation. Added: determinism tests, contract field-locking tests, check order tests.
