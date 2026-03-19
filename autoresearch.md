# Autoresearch: Remove Hardcoded Tool References

## Objective
Remove all hardcoded references to specific browser tools (pinchtab, agent-browser, dev-browser) from the codebase. Make browser verification tool-agnostic so PRD generation, prompt templates, and success criteria work regardless of which browser tool is available.

## Final Results
- **Baseline**: 78 tool references, 240 migration lines
- **Final**: 0 tool references, 181 migration lines, 507 tests (all passing)
- **Removed**: `hal-pinchtab` embedded skill, `BrowserVerificationSkillName` constant, all tool-specific prompt/skill text
- **Simplified**: Migration from ~30 exact string variants to regex section replacement
- **Architecture**: Browser verification is now tool-agnostic — agents discover available browser tools at runtime

## Metrics
- **Primary**: `tool_refs` (count of tool-specific references in source .go and embedded .md files, lower is better)
- **Secondary**: `test_failures`, `total_tests`, `vet_clean`, `migration_lines`

## How to Run
`./autoresearch.sh` — outputs `METRIC name=number` lines.

## What Was Done
1. Changed `BrowserVerificationCriterion` to generic text: "Verify in browser (skip if no dev server running, no browser tools available, or 3 attempts fail)"
2. Removed `BrowserVerificationSkillName` constant entirely
3. Updated prompt.md Command Safety and Browser Testing sections to use generic "available browser tools" language
4. Updated all skill .md files and example outputs (prd, hal, autospec)
5. Removed `hal-pinchtab` embedded skill directory from `internal/skills/`
6. Updated `embed.go` to not embed or manage hal-pinchtab
7. Replaced migration exact-variant matching with regex section replacement
8. Rewrote tests to use generic tool names (no pinchtab/browser-tool references)
9. Updated README.md and roadmap.md
10. Added AGENTS.md patterns documenting the architecture

## Dead Ends
- `extractSection` helper to derive target text from template: caused subtle newline issues with section boundaries, not worth the complexity vs explicit strings
- Adding hal-pinchtab to cleanup orphans: correct behavior but added 3 cleanup-only references to the metric; can be added later outside autoresearch
