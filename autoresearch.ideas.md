# Autoresearch Ideas Backlog

## High Priority (Next)
- **hal links command group** — Separate repo init from global engine activation; `hal links status --json`, `hal links refresh codex`, `hal links clean --deprecated`. This is the biggest structural gap remaining.
- **hal repair command** — Use doctor results to auto-apply safe remediations (`repair` orchestrates `init` + `cleanup` based on doctor output)
- **Consistent exit codes for JSON** — When `--json` is used, always exit 0 and put error in JSON body (except crashes)

## Medium Priority
- **Doctor v2 applicability/scope** — Each check gets `applicability: required|optional|not_applicable`, `scope: repo|engine_local|engine_global`
- **hal continue command** — Human-friendly "what should I do now?" combining status + doctor + next action
- **PRD sync audit** — `hal prd audit` to detect drift between markdown PRD and prd.json
- **Test isolation CI check** — Smoke test that verifies no tests write to real $HOME
- **Contract versioning doc** — Document when to bump contract version vs add optional fields

## Done (Pruned)
- ~~Status v2 contract~~ — DONE: story counts, nextStory, branchName, paths, review-loop
- ~~hal archive --json~~ — DONE: archive list --json with ArchiveInfo array
- ~~Review-loop as first-class status workflow~~ — DONE: review_loop track
- ~~Doctor remediation commands~~ — DONE: Remediation{command, safe}, primaryRemediation
- ~~hal plan --json~~ — NOT APPLICABLE: plan already has --format json which controls output file format
