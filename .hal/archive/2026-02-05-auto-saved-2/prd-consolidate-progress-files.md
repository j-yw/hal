# PRD: Consolidate Progress Files

## Introduction

Consolidate `auto-progress.txt` into `progress.txt` so both manual and auto workflows use a single progress file. Currently, `hal review` cannot see work completed by `hal auto` because it reads from `progress.txt` while the auto pipeline writes to `auto-progress.txt`. This creates a blind spot in the review cycle.

## Goals

- Unify progress tracking into a single `progress.txt` file for all workflows
- Ensure `hal review` sees work from both manual (`hal run`) and auto (`hal auto`) pipelines
- Add migration logic to merge existing `auto-progress.txt` content into `progress.txt`
- Provide `hal cleanup` command to remove orphaned files from previous versions
- Enhance `hal review` context gathering to include JSON PRD completion status

## User Stories

### US-001: Remove AutoProgressFile constant from template package
**Description:** As a developer, I need the codebase to use a single progress file constant so both workflows write to the same location.

**Acceptance Criteria:**
- [ ] Remove `AutoProgressFile = "auto-progress.txt"` constant from `internal/template/template.go:25`
- [ ] Remove `AutoProgressFile: DefaultProgress` from `DefaultFiles()` map at `internal/template/template.go:35`
- [ ] `hal init` no longer creates `auto-progress.txt`
- [ ] Typecheck passes

### US-002: Update auto pipeline to use unified progress file
**Description:** As an operator running `hal auto`, I want progress written to `progress.txt` so `hal review` can see my work.

**Acceptance Criteria:**
- [ ] Change `template.AutoProgressFile` → `template.ProgressFile` in `internal/compound/pipeline.go:495`
- [ ] Update error messages at lines 501 and 504 to reference `ProgressFile`
- [ ] Change `ProgressFile: template.AutoProgressFile` → `ProgressFile: template.ProgressFile` in loop config at line 511
- [ ] Auto pipeline writes to `progress.txt`
- [ ] Typecheck passes

### US-003: Add migration logic for existing auto-progress.txt
**Description:** As a user with an existing `auto-progress.txt`, I want its content merged into `progress.txt` when running `hal auto` so I don't lose progress history.

**Acceptance Criteria:**
- [ ] Before progress file initialization in `runLoopStep()`, check if `auto-progress.txt` exists
- [ ] If `auto-progress.txt` exists and `progress.txt` is empty/default, append auto-progress content to progress.txt
- [ ] If both files have content, append auto-progress content to progress.txt with a separator line
- [ ] Delete `auto-progress.txt` after successful migration
- [ ] Migration is logged to display output
- [ ] Typecheck passes

### US-004: Fix hardcoded path in hal review context gathering
**Description:** As a user running `hal review`, I want progress read from the correct location using the template constant so maintenance is easier.

**Acceptance Criteria:**
- [ ] Add `"github.com/jywlabs/hal/internal/template"` import to `internal/compound/review.go`
- [ ] Change hardcoded `filepath.Join(dir, ".hal", "progress.txt")` to `filepath.Join(dir, template.HalDir, template.ProgressFile)` at line 133
- [ ] Behavior unchanged for review command
- [ ] Typecheck passes

### US-005: Add JSON PRD reading to hal review context
**Description:** As a user running `hal review`, I want the review to see task completion status from JSON PRDs so recommendations are based on actual progress.

**Acceptance Criteria:**
- [ ] Add `PRDJSONContent string` and `AutoPRDContent string` fields to `reviewContext` struct
- [ ] After reading markdown PRD (around line 155), read `prd.json` content if exists
- [ ] Read `auto-prd.json` content if exists
- [ ] Update `hasAnyContext()` to include new JSON PRD fields
- [ ] Typecheck passes

### US-006: Include JSON PRD content in review prompt
**Description:** As a user running `hal review`, I want the AI to see task completion percentages so it can accurately report what's done vs remaining.

**Acceptance Criteria:**
- [ ] Update `buildReviewPrompt()` to include `PRDJSONContent` section when available
- [ ] Update `buildReviewPrompt()` to include `AutoPRDContent` section when available
- [ ] Truncate JSON PRD content to reasonable size (5000 chars each)
- [ ] Dry-run output shows JSON PRD context sizes when available
- [ ] Typecheck passes

### US-007: Remove AutoProgressFile from archive feature state files
**Description:** As a developer, I need the archive system to stop treating `auto-progress.txt` as a feature state file since it no longer exists.

**Acceptance Criteria:**
- [ ] Remove `template.AutoProgressFile` from `featureStateFiles` slice in `internal/archive/archive.go:23`
- [ ] `hal archive` no longer includes `auto-progress.txt` in new archives
- [ ] Old archives with `auto-progress.txt` still restore correctly (restore iterates all files)
- [ ] Typecheck passes

### US-008: Update archive command help text
**Description:** As a user reading help text, I want accurate documentation about which files are archived.

**Acceptance Criteria:**
- [ ] Remove `auto-progress.txt` from the archived files list in `cmd/archive.go:27` Long description
- [ ] Help text accurately reflects current behavior
- [ ] Typecheck passes

### US-009: Update archive tests for consolidated progress
**Description:** As a developer, I need tests to pass after removing `AutoProgressFile` references.

**Acceptance Criteria:**
- [ ] Remove `writeFile(t, filepath.Join(halDir, template.AutoProgressFile), ...)` calls from `internal/archive/archive_test.go`
- [ ] Remove `template.AutoProgressFile` from verification slices in tests
- [ ] Update "auto-state only archives" test (line ~148-165) to use `ProgressFile` instead
- [ ] All archive tests pass
- [ ] Typecheck passes

### US-010: Add hal cleanup command
**Description:** As a user who upgraded hal, I want a command to remove orphaned files like `auto-progress.txt` that are no longer used.

**Acceptance Criteria:**
- [ ] Create `cmd/cleanup.go` with `hal cleanup` command
- [ ] Command checks for and removes orphaned `auto-progress.txt` in `.hal/`
- [ ] Command reports which files were removed
- [ ] Command is idempotent (safe to run multiple times)
- [ ] Add `--dry-run` flag to preview what would be removed
- [ ] Typecheck passes

### US-011: Document consolidation pattern in AGENTS.md
**Description:** As a future developer, I want documentation about why progress files were consolidated so I understand the design decision.

**Acceptance Criteria:**
- [ ] Add "Patterns from hal/consolidate-progress-files" section to AGENTS.md
- [ ] Document that `progress.txt` is the single source of truth for both workflows
- [ ] Document migration approach (append with separator)
- [ ] Document that old `auto-progress.txt` files are orphaned but harmless
- [ ] Typecheck passes

## Functional Requirements

- FR-1: Remove `AutoProgressFile` constant from `internal/template/template.go`
- FR-2: Remove `AutoProgressFile` from `DefaultFiles()` map so `hal init` doesn't create it
- FR-3: Update `internal/compound/pipeline.go` to use `template.ProgressFile` for auto pipeline
- FR-4: Add migration in `runLoopStep()` that appends `auto-progress.txt` content to `progress.txt`
- FR-5: Update `internal/compound/review.go` to use template constants instead of hardcoded paths
- FR-6: Add JSON PRD fields to `reviewContext` and include in review prompt
- FR-7: Remove `template.AutoProgressFile` from `featureStateFiles` in archive package
- FR-8: Update `cmd/archive.go` help text to remove `auto-progress.txt` reference
- FR-9: Update all archive tests to remove `AutoProgressFile` references
- FR-10: Create `hal cleanup` command that removes orphaned files

## Non-Goals

- Automatic migration on `hal init` (migration happens on first `hal auto` run)
- Removing `auto-progress.txt` from existing archives (restore still works)
- Merging `auto-prd.json` and `prd.json` (they serve different workflows)
- Changing `auto-state.json` behavior (it's pipeline state, not progress)
- GUI or interactive migration wizard

## Technical Considerations

- Migration logic must handle both "progress.txt missing" and "progress.txt exists with content" cases
- Separator line for merged content should be clearly identifiable: `\n--- Migrated from auto-progress.txt ---\n`
- JSON PRD truncation in review prompt prevents context overflow while preserving task completion data
- Archive restore iterates all files in archive directory, so old archives with `auto-progress.txt` restore correctly
- `hal cleanup` should be safe to run repeatedly (idempotent)

## Success Metrics

- `hal review` after `hal auto` shows progress content from the auto run
- No regression in manual workflow (`hal run` → `hal review`)
- All existing tests pass after modifications
- `hal cleanup` removes orphaned files without user intervention

## Open Questions

- Should `hal cleanup` also remove other potential orphans (empty directories, stale state files)?
- Should migration log be written to a dedicated migration log file for auditing?
