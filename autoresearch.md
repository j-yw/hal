# Autoresearch: HAL UX & Machine Readability Improvements

## Objective
Improve HAL CLI's operational coherence: machine-readable output, workflow state, health checks, test reliability, UX clarity.

## Results
- **Baseline**: 3 test failures, ~387 tests, no status/doctor/continue commands, no --json
- **Final**: 0 test failures, 450 tests, 56 experiments, ~52 commits
- **+4400 lines** across 45 files
- **4 new commands**: status, doctor, continue, 17+ with --json
- **3 new packages**: internal/status, internal/doctor

## Key Deliverables

### `hal status --json` — Workflow State Machine
8 states × 4 tracks. Manual detail: story counts, nextStory, branchName, paths. Compound detail: step, branch. Review-loop: latest report. Smart next-action: suggests convert when markdown PRD exists, auto when reports available.

### `hal doctor --json` — 12 Health Checks
git_repo, hal_dir, config_yaml (YAML validation), prompt_md (content), progress_file, default_engine_cli, local_skill_links, hal_skills, hal_commands, codex_global_links (engine-aware), legacy_debris, broken_skill_links. Remediation commands. Check pass rate. Deterministic.

### `hal continue --json` — What to Do Next
Combines status + doctor. Doctor issues shown as blockers.

### Machine-Readable JSON (17+ commands)
init, status, doctor, continue, run, report, auto, analyze, validate, convert, cleanup, config, standards list, review, archive list/create/restore, version, explode

### Test Reliability
- 3 flaky engine timeouts (2s→10s)
- Race condition in t.Parallel (shared Root())
- Codex linker $HOME isolation
- Determinism tests for status + doctor
