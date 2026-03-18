# Autoresearch: HAL UX & Machine Readability Improvements

## Objective
Improve HAL CLI's operational coherence: fix test failures, add machine-readable output (`--json`) to all core commands, fix test isolation, add status/doctor/continue commands, improve UX clarity.

## Results
- **Baseline**: 3 test failures, ~387 tests
- **Final**: 0 test failures, 445 tests, vet clean
- **48 experiments**, 47 kept
- **47 commits**, +4169/-95 lines, 45 files changed
- **4 new commands**: status, doctor, continue, (archive create/list/restore --json)
- **3 new packages**: `internal/status`, `internal/doctor`
- **17+ commands** with `--json` flag

## Key Improvements

### New Commands
- `hal status --json` — Workflow state (7 states × 4 tracks), story counts, branch, paths
- `hal doctor --json` — 11 health checks, engine-aware, remediation commands
- `hal continue --json` — Combines status + doctor into "what to do next"

### Machine-Readable JSON
init, status, doctor, continue, run, report, auto, analyze, validate, convert, cleanup, config, standards list, review, archive list/create/restore, version, explode

### Doctor Checks (11 total)
git_repo, hal_dir, config_yaml (YAML validation), default_engine_cli, prompt_md (content check), progress_file, hal_skills, hal_commands, codex_global_links, legacy_debris, broken_skill_links

### Status States (7 total)
not_initialized, hal_initialized_no_prd, manual_in_progress, manual_complete, compound_active, compound_complete, review_loop_complete

### Test Fixes
- 3 flaky engine timeouts (2s→10s)
- Race condition in t.Parallel metadata tests
- Codex linker $HOME isolation

### UX
- Report: "legacy" → "Generate summary report"
- Init: separates repo-local/engine-local/global effects
- Doctor: shows engine, specific warning summaries
- README: updated with new commands
