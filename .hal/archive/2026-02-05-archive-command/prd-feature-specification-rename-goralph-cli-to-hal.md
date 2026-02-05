

I'll start by exploring the codebase to understand the current structure and all the references that need to change.Now let me check a few more files to understand the full scope.Now I have a comprehensive understanding of the codebase. Let me generate the PRD.PRD saved to `.goralph/prd-rename-to-hal.md`. 

The document contains **17 user stories** covering:

1. **US-001–002:** Module path and build system rename
2. **US-003:** Core `GoralphDir` → `HalDir` constant rename
3. **US-004–006:** CLI commands (root, version, init with auto-migration, all other commands)
4. **US-007–008:** Compound pipeline package and its tests
5. **US-009–010:** Ralph skill → Hal skill directory rename + other SKILL.md updates
6. **US-011–012:** PRD package and engine/loop package updates
7. **US-013–014:** Template files and documentation
8. **US-015:** HAL 9000 personality easter eggs
9. **US-016:** `.hal/` runtime directory for self-development
10. **US-017:** Final grep verification + full test suite

Each story is ordered by dependency (module path first, then constants, then consumers) and sized for one iteration. The init command includes auto-migration from `.goralph/` → `.hal/`.