# Autoresearch: HAL UX & Machine Readability Improvements

## Objective
Improve HAL CLI's operational coherence: machine-readable output, workflow state, health checks, test reliability, UX clarity.

## Results
- **Baseline**: 3 test failures, ~387 tests
- **Final**: 0 test failures, 467 tests, 73 experiments, 72 commits
- **+5727 lines** across 49 files, 16 new files
- **7 new commands**: status, doctor, continue, repair, links status/refresh/clean
- **20+ commands** with `--json` flag
- **3 new packages**: internal/status, internal/doctor

## Key Deliverables

### New Commands
- `hal status --json` — 8-state workflow machine with manual/compound/review-loop detail
- `hal doctor --json` — 13 health checks with scope/applicability, remediation, pass rate
- `hal continue --json` — "what to do next" combining status + doctor
- `hal repair [--dry-run] [--json]` — auto-applies safe doctor remediations
- `hal links status [--json]` — per-engine link health inspection
- `hal links refresh [engine]` — recreate engine links without touching .hal/
- `hal links clean` — remove deprecated/broken skill links

### Machine-Readable JSON (20+ commands)
init, status, doctor, continue, repair, links status, run, report, auto, analyze, validate, convert, cleanup, config, standards list, review, archive list/create/restore, version, explode

### Doctor: 13 Checks with Scope/Applicability
git_repo, hal_dir, config_yaml, prompt_md, progress_file, prd_json, default_engine_cli, local_skill_links, hal_skills, hal_commands, codex_global_links, legacy_debris, broken_skill_links. Each check: scope (repo/engine_local/engine_global/migration), applicability (required/optional/not_applicable).

### Status: 8 States × 4 Tracks
not_initialized, hal_initialized_no_prd, manual_in_progress, manual_complete, compound_active, compound_complete, review_loop_complete. Smart next-action: convert (md→json), auto (complete+reports).

### Test Reliability
- Fixed 3 flaky engine timeouts, race condition in t.Parallel, Codex linker $HOME isolation
- 80 new tests added (387→467)
