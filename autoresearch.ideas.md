# Autoresearch Ideas Backlog

## High Priority (Next Session)
- **hal links command group** — Separate repo init from global engine activation; `hal links status --json`, `hal links refresh codex`, `hal links clean --deprecated`
- **hal repair command** — Doctor can detect issues but can't fix them; `hal repair` should auto-apply safe remediations from doctor
- **Status v2 contract** — Add story counts, next story ID, paths, review-loop state, resolution reasoning
- **Consistent exit codes for JSON** — When `--json` is used, always exit 0 and put error in JSON body

## Medium Priority
- **Doctor v2 with applicability/scope** — Each check gets `applicability: required|optional|not_applicable`, `scope: repo|engine_local|engine_global`
- **hal continue command** — Human-friendly "what should I do now?" combining status + doctor + next action
- **PRD sync audit** — `hal prd audit` to detect drift between markdown PRD and prd.json
- **Test isolation CI check** — Smoke test that verifies no tests write to real $HOME
- **hal plan --json** — Structured output for plan generation

## Lower Priority  
- **Review-loop as first-class status workflow** — Status should detect active review loops
- **hal doctor --fix** — Option to auto-apply safe remediations inline
- **Deprecation timeline enforcement** — Track which deprecated features should be removed by v1.0
- **Contract versioning policy** — Document when to bump contract version vs add optional fields
- **hal archive --json** — Structured output for archive operations
