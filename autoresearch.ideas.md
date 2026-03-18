# Autoresearch Ideas Backlog

## High Priority
- **hal links command group** — `hal links status --json`, `hal links refresh codex`, `hal links clean --deprecated`
- **hal repair command** — Auto-apply safe doctor remediations
- **Consistent JSON exit codes** — exit 0 + encode errors in JSON body

## Medium Priority
- **Doctor v2 applicability/scope** — per-check `applicability`/`scope` fields
- **PRD sync audit** — `hal prd audit` for markdown↔JSON drift
- **hal explode --json output wiring** — flag registered but not yet wired
- **Test isolation CI** — Smoke test for $HOME writes

## Done
- Status contract with story detail, compound detail, review-loop ✅
- Doctor with 11 checks, remediation, engine awareness ✅
- 17+ commands with --json ✅
- hal continue ✅
- Race condition fix ✅
- Codex linker isolation ✅
- Legacy/broken link detection+cleanup ✅
- README updated ✅
