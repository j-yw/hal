# PRD: Unit Tests for Migration and Cleanup

## Introduction

Add comprehensive unit tests for the `migrateAutoProgress` function in `internal/compound/pipeline.go` and the `hal cleanup` command in `cmd/cleanup.go`. These tests lock in the correctness of the progress file consolidation work and prevent future regressions in merge semantics and cleanup behavior.

## Goals

- Ensure `migrateAutoProgress` correctly handles all migration scenarios (merge, replace, no-op, deletion)
- Verify `hal cleanup --dry-run` previews changes without modifying files
- Verify `hal cleanup` actually deletes orphaned files
- Achieve test coverage for edge cases and error conditions
- All tests pass with `make test`

## Tasks

### T-001: Extract migrateAutoProgress for testability
**Description:** As a developer, I need the `migrateAutoProgress` function to be testable in isolation so that unit tests can verify its behavior without needing a full Pipeline instance.

**Acceptance Criteria:**
- [ ] Create standalone `MigrateAutoProgress(dir string, display DisplayWriter) error` function in `internal/compound/migrate.go`
- [ ] Refactor `Pipeline.migrateAutoProgress()` to call the standalone function
- [ ] `DisplayWriter` interface accepts `ShowInfo(format string, args ...any)` method
- [ ] Existing functionality remains unchanged (no behavioral changes)
- [ ] Typecheck passes

### T-002: Test merge when both files have content
**Description:** As a developer, I need a test that verifies when both `auto-progress.txt` and `progress.txt` have meaningful content, they are merged with a separator.

**Acceptance Criteria:**
- [ ] Test creates `progress.txt` with meaningful content (not empty/default)
- [ ] Test creates `auto-progress.txt` with meaningful content
- [ ] After migration, `progress.txt` contains original content + separator + auto-progress content
- [ ] Separator includes "---" and "Migrated from auto-progress.txt" header
- [ ] `auto-progress.txt` is deleted after merge
- [ ] Typecheck passes

### T-003: Test replacement when progress.txt is empty
**Description:** As a developer, I need a test that verifies when `progress.txt` is empty, its content is replaced entirely with `auto-progress.txt` content.

**Acceptance Criteria:**
- [ ] Test creates empty `progress.txt`
- [ ] Test creates `auto-progress.txt` with content
- [ ] After migration, `progress.txt` contains exactly the auto-progress content (no separator)
- [ ] `auto-progress.txt` is deleted after replacement
- [ ] Typecheck passes

### T-004: Test replacement when progress.txt has default content
**Description:** As a developer, I need a test that verifies when `progress.txt` contains only the default template, it is replaced entirely.

**Acceptance Criteria:**
- [ ] Test creates `progress.txt` with `template.DefaultProgress` content
- [ ] Test creates `auto-progress.txt` with meaningful content
- [ ] After migration, `progress.txt` contains exactly the auto-progress content (no separator)
- [ ] `auto-progress.txt` is deleted after replacement
- [ ] Typecheck passes

### T-005: Test no-op when auto-progress.txt does not exist
**Description:** As a developer, I need a test that verifies migration does nothing when there is no legacy file to migrate.

**Acceptance Criteria:**
- [ ] Test creates only `progress.txt` (no `auto-progress.txt`)
- [ ] After migration, `progress.txt` is unchanged
- [ ] Function returns nil (no error)
- [ ] Typecheck passes

### T-006: Test auto-progress.txt with empty content is removed
**Description:** As a developer, I need a test that verifies an empty or default-only `auto-progress.txt` is simply removed without merging.

**Acceptance Criteria:**
- [ ] Test creates `progress.txt` with content
- [ ] Test creates empty `auto-progress.txt`
- [ ] After migration, `progress.txt` is unchanged
- [ ] `auto-progress.txt` is deleted
- [ ] Test also covers `auto-progress.txt` containing only `template.DefaultProgress`
- [ ] Typecheck passes

### T-007: Extract runCleanup for testability
**Description:** As a developer, I need the cleanup logic extracted into a testable function that accepts an output writer.

**Acceptance Criteria:**
- [ ] Create `runCleanupFn(halDir string, dryRun bool, w io.Writer) error` function
- [ ] Refactor `runCleanup` Cobra handler to call `runCleanupFn`
- [ ] Output goes to the writer parameter, not directly to stdout
- [ ] Existing functionality remains unchanged
- [ ] Typecheck passes

### T-008: Test cleanup dry-run output
**Description:** As a developer, I need a test that verifies `--dry-run` shows what would be deleted without actually deleting files.

**Acceptance Criteria:**
- [ ] Test creates `.hal/auto-progress.txt` file
- [ ] Run cleanup with `dryRun=true`
- [ ] Output contains "Would remove:" and the file path
- [ ] File still exists after dry-run
- [ ] Output contains summary of how many files would be removed
- [ ] Typecheck passes

### T-009: Test cleanup actual deletion
**Description:** As a developer, I need a test that verifies cleanup actually deletes orphaned files when not in dry-run mode.

**Acceptance Criteria:**
- [ ] Test creates `.hal/auto-progress.txt` file
- [ ] Run cleanup with `dryRun=false`
- [ ] Output contains "Removed:" and the file path
- [ ] File no longer exists after cleanup
- [ ] Output contains summary of how many files were removed
- [ ] Typecheck passes

### T-010: Test cleanup when no orphaned files exist
**Description:** As a developer, I need a test that verifies cleanup handles the case when there are no orphaned files gracefully.

**Acceptance Criteria:**
- [ ] Test creates `.hal/` directory with no orphaned files
- [ ] Run cleanup with `dryRun=false`
- [ ] Output contains "No orphaned files found."
- [ ] Function returns nil (no error)
- [ ] Typecheck passes

## Functional Requirements

- FR-1: `MigrateAutoProgress` must merge with separator when both files have meaningful content
- FR-2: `MigrateAutoProgress` must replace when `progress.txt` is empty or default-only
- FR-3: `MigrateAutoProgress` must delete `auto-progress.txt` after successful migration
- FR-4: `MigrateAutoProgress` must no-op when `auto-progress.txt` does not exist
- FR-5: `runCleanupFn` must preview changes when dry-run is true
- FR-6: `runCleanupFn` must delete orphaned files when dry-run is false
- FR-7: `runCleanupFn` must report "No orphaned files found" when nothing to clean

## Non-Goals

- Performance optimization of migration/cleanup
- Adding new orphaned file types to cleanup
- Integration tests with actual Cobra command execution
- Testing error conditions for filesystem failures (those are environment-specific)

## Technical Considerations

- Tests should use `t.TempDir()` for isolation
- Follow existing table-driven test patterns from `cmd/archive_test.go` and `cmd/init_test.go`
- Use `bytes.Buffer` for output capture
- Use helper functions (`writeFile`) for test setup consistency
- Migration tests go in `internal/compound/migrate_test.go`
- Cleanup tests go in `cmd/cleanup_test.go`

## Open Questions

- None (scope is clear from analysis)
