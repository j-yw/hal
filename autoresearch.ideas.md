# Autoresearch Ideas Backlog

## High Priority
- **hal links command group** — Separate repo init from global engine activation; `hal links status --json`, `hal links refresh codex`, `hal links clean --deprecated`
- **hal repair command** — Auto-apply safe remediations from doctor results; orchestrate `init` + `cleanup` based on primaryRemediation
- **Consistent JSON exit codes** — When `--json` is used, exit 0 and encode errors in JSON body for commands like run/validate

## Medium Priority  
- **Doctor v2 applicability/scope** — `applicability: required|optional|not_applicable`, `scope: repo|engine_local|engine_global` per check
- **PRD sync audit** — `hal prd audit` to detect drift between markdown PRD and prd.json
- **Test isolation CI smoke test** — Verify no tests write to real $HOME
- **Contract versioning doc** — Formal policy: when to bump version vs add optional fields
- **hal explode --json output wiring** — Flag registered but not yet wired to actual JSON output

## Done/Pruned
- Status: story counts, nextStory, paths, review-loop, compound_complete ✅
- Doctor: engine-aware, remediation, broken links, legacy debris, YAML validation ✅
- 16 commands with --json ✅
- hal continue ✅
- Race condition fix ✅
- Codex linker isolation ✅
- Deprecated link cleanup ✅
