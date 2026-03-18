# Autoresearch: HAL UX & Machine Readability Improvements

## Objective
Improve HAL CLI's operational coherence: machine-readable output, workflow state, health checks, test reliability, UX clarity.

## Results
- **Baseline**: 3 test failures, ~387 tests, no status/doctor/continue/links/repair commands, no --json
- **Final**: 0 test failures, 464 tests, 65 experiments
- **~60 commits**, +4800 lines across 50 files
- **7 new commands**: status, doctor, continue, repair, links status, links refresh
- **20+ commands** with `--json` flag
- **3 new packages**: internal/status, internal/doctor

## Key Deliverables

### `hal status --json` — Workflow State Machine
8 states × 4 tracks. Manual: story counts, nextStory, branchName. Compound: step, branch. Review-loop: latest report. Smart: suggests convert (md→json), auto (complete + reports).

### `hal doctor --json` — 13 Health Checks with Scope/Applicability
git_repo, hal_dir, config_yaml, prompt_md, progress_file, prd_json, default_engine_cli, local_skill_links, hal_skills, hal_commands, codex_global_links, legacy_debris, broken_skill_links. Per-check: scope (repo/engine_local/engine_global/migration), applicability (required/optional/not_applicable). Remediation commands. Check pass rate.

### `hal continue --json` — What to Do Next
Combines status + doctor. Doctor issues as blockers.

### `hal repair [--dry-run] [--json]` — Auto-Fix
Applies safe doctor remediations (init, cleanup). Re-checks after repair.

### `hal links status [--json]` + `hal links refresh [engine]`
Per-engine link health inspection. Targeted refresh without touching .hal/.

### Machine-Readable JSON (20+ commands)
init, status, doctor, continue, repair, links status, run, report, auto, analyze, validate, convert, cleanup, config, standards list, review, archive list/create/restore, version, explode
