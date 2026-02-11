# PRD: Init Refresh Templates

## Introduction

`hal init` currently preserves existing `.hal/` template files (prompt.md, progress.txt, config.yaml) to protect user customizations. When Hal ships updated defaults, users have no way to adopt them without manually copying content. This feature adds a `--refresh-templates` flag (with `--dry-run` support) that backs up existing templates and overwrites them with the latest defaults, then runs the existing `migrateTemplates()` compatibility pass.

## Goals

- Let users explicitly opt in to refreshing stale template files with latest defaults
- Protect customizations by creating timestamped backups before any overwrite
- Provide a dry-run mode so users can preview what would change before committing
- Print a detailed per-file status summary (created / preserved / refreshed / backup paths)
- Keep the existing safe default: `hal init` without flags never overwrites

## User Stories

### US-001: Add --refresh-templates flag to init command
**Description:** As a developer, I want a `--refresh-templates` boolean flag on `hal init` so that the CLI accepts the new option and wires it into the init logic.

**Acceptance Criteria:**
- [ ] `initCmd` registers a `--refresh-templates` bool flag defaulting to `false`
- [ ] `hal init --help` shows the flag with description: "Overwrite existing .hal template files with latest defaults (backs up old files)"
- [ ] Flag value is accessible in the `runInit` path (stored in a package-level var or passed to extracted function)
- [ ] Typecheck passes

### US-002: Add --dry-run flag to init command
**Description:** As a developer, I want a `--dry-run` boolean flag on `hal init` so that I can preview template refresh operations without writing anything.

**Acceptance Criteria:**
- [ ] `initCmd` registers a `--dry-run` bool flag defaulting to `false`
- [ ] `hal init --help` shows the flag with description: "Preview changes without writing files"
- [ ] `--dry-run` without `--refresh-templates` is a no-op (init proceeds normally, dry-run only affects template refresh)
- [ ] Flag value is accessible in the `runInit` path
- [ ] Typecheck passes

### US-003: Implement template refresh with timestamped backup
**Description:** As a user, I want `hal init --refresh-templates` to back up my existing template files and replace them with the latest defaults, so I get updated templates without losing my old content.

**Acceptance Criteria:**
- [ ] Only the 3 core templates are refreshed: `prompt.md`, `progress.txt`, `config.yaml` (as returned by `template.DefaultFiles()`)
- [ ] For each existing file: creates a backup named `<filename>.bak.<YYYYMMDD-HHMMSS>` in the same `.hal/` directory (e.g., `prompt.md.bak.20260210-001530`)
- [ ] After backup, the file is overwritten with the content from `template.DefaultFiles()`
- [ ] If a template file does not exist, it is created (no backup needed) — same as current behavior
- [ ] If a template file already matches the default content, it is skipped (no backup, no overwrite)
- [ ] `migrateTemplates()` still runs after refresh to apply any compatibility patches
- [ ] Typecheck passes

### US-004: Implement dry-run mode for template refresh
**Description:** As a user, I want `hal init --refresh-templates --dry-run` to show me what would be refreshed and backed up without actually writing files, so I can review before committing.

**Acceptance Criteria:**
- [ ] When `--dry-run` and `--refresh-templates` are both set, no files are written, backed up, or deleted
- [ ] Output shows the same per-file status lines as a real run, prefixed with `[dry-run]`
- [ ] Each file that would be refreshed shows: `[dry-run] Would refresh: .hal/<filename> (backup: .hal/<filename>.bak.<timestamp>)`
- [ ] Each file that would be created shows: `[dry-run] Would create: .hal/<filename>`
- [ ] Each file that would be skipped (already matches default) shows: `[dry-run] Already up to date: .hal/<filename>`
- [ ] Typecheck passes

### US-005: Print detailed per-file status summary
**Description:** As a user, I want `hal init --refresh-templates` to print a clear summary of what happened to each file, including backup paths, so I can verify the operation.

**Acceptance Criteria:**
- [ ] Output groups files by action: "Created", "Refreshed (backup saved)", "Already up to date"
- [ ] Refreshed files show the backup path: `  .hal/prompt.md → backed up to .hal/prompt.md.bak.20260210-001530`
- [ ] Created files show: `  .hal/<filename>`
- [ ] Up-to-date files show: `  .hal/<filename> (unchanged)`
- [ ] Without `--refresh-templates`, existing behavior is unchanged (shows "Created" and "Already existed (preserved)" lists)
- [ ] Typecheck passes

### US-006: Extract refreshable init logic into testable function
**Description:** As a developer, I want the template refresh logic extracted into a standalone function so it can be unit tested without running the full Cobra command.

**Acceptance Criteria:**
- [ ] A function like `refreshTemplates(configDir string, dryRun bool, w io.Writer) error` (or similar) is extracted in `cmd/init.go`
- [ ] The function accepts an `io.Writer` for output capture (following the `migrateConfigDir` pattern)
- [ ] `runInit` delegates to this function when `--refresh-templates` is set
- [ ] Typecheck passes

### US-007: Add tests for template refresh behavior
**Description:** As a developer, I want tests in `cmd/init_test.go` covering the refresh and dry-run behaviors so we have confidence the feature works correctly.

**Acceptance Criteria:**
- [ ] Test: `hal init` without flag preserves existing customized files (existing behavior — extend current test)
- [ ] Test: `hal init --refresh-templates` creates backup files with `.bak.<timestamp>` suffix
- [ ] Test: `hal init --refresh-templates` overwrites existing files with `template.DefaultFiles()` content
- [ ] Test: `hal init --refresh-templates` skips files that already match default content (no backup created)
- [ ] Test: `hal init --refresh-templates --dry-run` does not write or modify any files
- [ ] Test: `hal init --refresh-templates --dry-run` output contains `[dry-run]` prefixed status lines
- [ ] Test: backup file contains the original (pre-refresh) content
- [ ] All tests are subtests of `TestRunInit` or a new `TestRefreshTemplates` in `cmd/init_test.go` (no new test files)
- [ ] Typecheck passes

## Functional Requirements

- FR-1: Add `--refresh-templates` boolean flag to `hal init` (default `false`)
- FR-2: Add `--dry-run` boolean flag to `hal init` (default `false`)
- FR-3: When `--refresh-templates` is set, back up each existing core template to `<name>.bak.<YYYYMMDD-HHMMSS>` before overwriting
- FR-4: Only refresh the 3 core templates returned by `template.DefaultFiles()`: `prompt.md`, `progress.txt`, `config.yaml`
- FR-5: Skip refresh for files whose content already matches the default (no unnecessary backup)
- FR-6: Run `migrateTemplates()` after refresh to apply compatibility patches on the fresh content
- FR-7: When `--dry-run` is combined with `--refresh-templates`, print what would happen but write nothing
- FR-8: Print per-file status lines showing created/refreshed/skipped with backup paths
- FR-9: Without `--refresh-templates`, init behavior is identical to current (no breaking change)

## Non-Goals

- No automatic cleanup of old `.bak` files — users manage backups manually
- No interactive diff or merge of old vs. new templates
- No selective per-file refresh (all 3 core templates are refreshed together)
- No `--refresh-templates` support for skill files — only core templates
- No changes to the `migrateTemplates()` function itself

## Technical Considerations

- Follow the `migrateConfigDir` pattern: extract logic into a testable function accepting `io.Writer`
- Use `time.Now().Format("20060102-150405")` for backup timestamp (Go reference time format)
- The refresh logic replaces the existing `created`/`skipped` loop in `runInit` when the flag is set
- Backup files live in `.hal/` alongside originals (already covered by `.gitignore` via `.hal/*`)
- Tests should use `t.TempDir()` and `os.Chdir` following the existing `TestRunInit` pattern

## Success Metrics

- `hal init` without flags behaves identically to before (zero regression)
- `hal init --refresh-templates` creates correct backups and overwrites all 3 core templates
- `hal init --refresh-templates --dry-run` produces accurate preview without side effects
- All new tests pass via `make test`

## Open Questions

- Should `--dry-run` also preview what `migrateTemplates()` would change on the refreshed files, or is it sufficient to show only the refresh/backup operations?
