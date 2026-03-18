# Autoresearch Ideas Backlog

## Medium Priority
- **Doctor v2 applicability/scope** — per-check `applicability: required|optional|not_applicable`, `scope: repo|engine_local|engine_global`
- **Consistent JSON exit codes** — exit 0 + encode errors in JSON body for run/validate
- **PRD sync audit** — `hal prd audit` for markdown↔JSON drift detection
- **hal explode --json output wiring** — flag registered but not yet wired to JSON output
- **Test isolation CI** — Smoke test for $HOME writes

## Lower Priority
- **Contract versioning doc** — Formal policy: when to bump version vs add optional fields
- **hal links clean --deprecated** — Explicit subcommand for removing deprecated links (currently in cleanup)
- **Doctor check for prd.json validity** — Validate JSON schema of the PRD file

## Done
- ~~hal links command group~~ ✅ links status --json + links refresh [engine]
- ~~hal repair command~~ ✅ auto-applies safe remediations with dry-run + json
- ~~Status v2~~ ✅ story counts, nextStory, paths, review-loop, compound detail
- ~~Doctor remediation~~ ✅ actionable commands, primaryRemediation
- ~~17+ commands with --json~~ ✅
- ~~hal continue~~ ✅
- ~~Broken symlink / legacy debris detection~~ ✅
