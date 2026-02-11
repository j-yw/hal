

Let me first explore the codebase to understand the current `hal init` implementation and template system before writing the PRD.Now let me check the example PRD for format reference.Now I have a thorough understanding of the codebase. Let me write the PRD.PRD saved to `.hal/prd-refresh-templates.md`.

**Summary of what's in the PRD:**

**7 user stories**, ordered for implementation:
1. **US-001**: Register `--refresh-templates` flag
2. **US-002**: Register `--dry-run` flag
3. **US-003**: Core refresh logic — timestamped backup + overwrite for the 3 templates
4. **US-004**: Dry-run mode that previews without writing
5. **US-005**: Detailed per-file status output (created / refreshed / unchanged)
6. **US-006**: Extract `refreshTemplates()` into a testable function (following `migrateConfigDir` pattern)
7. **US-007**: Tests in existing `cmd/init_test.go` — preserve behavior, backup creation, dry-run no-op

**Key design decisions captured from your answers:**
- Only 3 core templates refreshed (`prompt.md`, `progress.txt`, `config.yaml`)
- Timestamped `.bak` in-place, no automatic cleanup
- Hybrid approach: refresh then still run `migrateTemplates()` for compatibility
- Detailed per-file status lines with backup paths
- `--dry-run` support with `[dry-run]` prefixed output