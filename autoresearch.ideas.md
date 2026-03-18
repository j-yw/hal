# Autoresearch Ideas Backlog

## High Priority (Next)
- **hal links command group** — Separate repo init from global engine activation; `hal links status --json`, `hal links refresh codex`, `hal links clean --deprecated`
- **hal repair command** — Auto-apply safe remediations from doctor results; orchestrate `init` + `cleanup` based on primaryRemediation
- **Consistent exit codes for JSON** — When `--json` is used, exit 0 and encode errors in JSON body for easier agent parsing

## Medium Priority
- **Doctor v2 applicability/scope fields** — `applicability: required|optional|not_applicable`, `scope: repo|engine_local|engine_global` per check
- **PRD sync audit** — `hal prd audit` to detect drift between markdown PRD and prd.json
- **Test isolation CI check** — Smoke test verifying no tests write to real $HOME
- **hal explode --json** — Structured output for explode results

## Done (Pruned)
- ~~Status v2 contract~~ — story counts, nextStory, branchName, paths, review-loop
- ~~hal archive --json~~ — archive list with ArchiveInfo
- ~~Review-loop workflow~~ — first-class track in status
- ~~Doctor remediation~~ — actionable commands with safe/command/primaryRemediation
- ~~hal continue~~ — combines status + doctor
- ~~Broken symlink detection~~ — doctor checks .claude/skills/ and .pi/skills/
- ~~hal plan --json~~ — NOT APPLICABLE (--format already controls output)
- ~~Contract versioning doc~~ — field-locking tests serve same purpose
