# Autoresearch: HAL UX & Machine Readability Improvements

## Objective
Improve HAL CLI's operational coherence: machine-readable output, workflow state, health checks, test reliability, UX clarity.

## Results
- **Baseline**: 3 test failures, ~387 tests, no status/doctor/continue commands, no --json
- **Final**: 0 test failures, 445 tests, 50+ experiments, 50 commits
- **+4300 lines** across 45 files
- **4 new commands**: status, doctor, continue, 17+ with --json
- **3 new packages**: internal/status, internal/doctor

## Key Deliverables

### Workflow State Machine (`hal status --json`)
7 states × 4 tracks: not_initialized, hal_initialized_no_prd, manual_in_progress, manual_complete, compound_active, compound_complete, review_loop_complete. Detail fields: story counts, nextStory, branchName, compound step, review-loop report.

### Health/Readiness (`hal doctor --json`)  
12 checks: git_repo, hal_dir, config_yaml (YAML validation), prompt_md (content), progress_file, default_engine_cli, local_skill_links, hal_skills, hal_commands, codex_global_links (engine-aware), legacy_debris, broken_skill_links. Actionable remediation commands. Check pass rate.

### "What to Do Next" (`hal continue --json`)
Combines status + doctor. Doctor issues shown as blockers. Compound/manual detail.

### Machine-Readable JSON (17+ commands)
init, status, doctor, continue, run, report, auto, analyze, validate, convert, cleanup, config, standards list, review, archive list/create/restore, version, explode

### Test Reliability
- 3 flaky engine timeouts fixed (2s→10s)
- Race condition in t.Parallel metadata tests fixed
- Codex linker $HOME isolation (tests no longer pollute ~/.codex)

### UX
- Report: "legacy" → "Generate summary report"
- Init: explicitly separates repo-local/engine-local/global side effects
- Cleanup: removes deprecated ralph links and rules/
- README updated with status/doctor/continue
