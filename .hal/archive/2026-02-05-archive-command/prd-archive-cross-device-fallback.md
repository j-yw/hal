# PRD: Cross-Filesystem Archive Fallback with Copy-and-Remove

## Introduction

Add a copy-and-remove fallback to `archive.Create` and `archive.Restore` so that archiving works when `.hal/` resides on a different filesystem than the archive destination. Currently, `os.Rename` fails with `EXDEV` (cross-device link) when source and destination span different mount points (e.g., home on NFS, project on local disk). This causes silent failures or confusing errors in real-world setups. This also adds CLI-level tests for the archive commands to cover prompt defaulting, verbose output, and error paths.

## Goals

- Archiving and restoring works transparently across filesystem boundaries
- Detect `EXDEV` (cross-device link not permitted) and automatically fall back to copy-and-remove
- Preserve the fast `os.Rename` path when source and destination are on the same device
- Unit test the `copyAndRemove` helper in isolation
- Add CLI-level tests for `hal archive create`, `hal archive list`, and `hal archive restore`
- All existing archive tests continue to pass

## Tasks

### T-001: Add moveFile helper with EXDEV fallback
**Description:** As a developer, I need a `moveFile` helper function in `internal/archive` that wraps `os.Rename` and falls back to copy-and-remove when the rename fails with `EXDEV`, so that file moves work across filesystem boundaries.

**Acceptance Criteria:**
- [ ] `moveFile(src, dst string) error` function exists in `internal/archive/move.go`
- [ ] Calls `os.Rename` first as the fast path
- [ ] When `os.Rename` returns `*os.LinkError` with `syscall.EXDEV`, falls back to copy-and-remove
- [ ] Copy preserves file permissions using `os.Stat` before copy
- [ ] Source file is removed only after successful copy and close
- [ ] Non-EXDEV rename errors are returned as-is (no fallback attempted)
- [ ] Typecheck passes (`go vet ./...`)

### T-002: Add moveDir helper for directory moves with EXDEV fallback
**Description:** As a developer, I need a `moveDir` helper that moves an entire directory tree across filesystem boundaries, so that `restoreDir` and report directory moves work cross-device.

**Acceptance Criteria:**
- [ ] `moveDir(src, dst string) error` function exists in `internal/archive/move.go`
- [ ] Attempts `os.Rename` first as the fast path for the whole directory
- [ ] On EXDEV, walks the source directory and copies files individually using `moveFile`
- [ ] Creates destination directory structure with correct permissions
- [ ] Removes source directory tree after all files are successfully copied
- [ ] Typecheck passes (`go vet ./...`)

### T-003: Unit tests for moveFile
**Description:** As a developer, I need unit tests for `moveFile` to verify both the fast rename path and the copy-and-remove fallback, so we have confidence in the cross-device behavior.

**Acceptance Criteria:**
- [ ] Tests live in `internal/archive/move_test.go`
- [ ] Test: same-device move succeeds (file moved, source gone, content intact)
- [ ] Test: file permissions are preserved after move
- [ ] Test: move to non-existent destination directory returns error
- [ ] Test: move of non-existent source file returns error
- [ ] Table-driven test structure following existing archive test patterns
- [ ] Typecheck passes (`go vet ./...`)

### T-004: Unit tests for moveDir
**Description:** As a developer, I need unit tests for `moveDir` to verify directory tree moves work correctly, so we have confidence in nested directory handling.

**Acceptance Criteria:**
- [ ] Tests live in `internal/archive/move_test.go`
- [ ] Test: same-device directory move succeeds (all files moved, source dir removed)
- [ ] Test: nested subdirectories are handled correctly
- [ ] Test: move of non-existent source directory returns error
- [ ] Table-driven test structure
- [ ] Typecheck passes (`go vet ./...`)

### T-005: Update archive.Create to use moveFile
**Description:** As a developer, I need `archive.Create` to use the new `moveFile` helper instead of raw `os.Rename`, so that archiving works across filesystem boundaries.

**Acceptance Criteria:**
- [ ] All `os.Rename(src, dst)` calls in `Create` are replaced with `moveFile(src, dst)`
- [ ] Report directory moves use `moveDir` or per-file `moveFile`
- [ ] Existing `TestCreate` tests continue to pass
- [ ] Typecheck passes (`go vet ./...`)

### T-006: Update archive.Restore and restoreDir to use moveFile/moveDir
**Description:** As a developer, I need `archive.Restore` and the internal `restoreDir` function to use the new move helpers instead of raw `os.Rename`, so that restoring works across filesystem boundaries.

**Acceptance Criteria:**
- [ ] All `os.Rename` calls in `Restore` are replaced with `moveFile`
- [ ] `restoreDir` uses `moveFile` for individual file moves within the directory
- [ ] Existing `TestRestore` tests continue to pass
- [ ] Typecheck passes (`go vet ./...`)

### T-007: Extract testable archive CLI logic for create command
**Description:** As a developer, I need the archive create CLI logic extracted into a testable function that accepts `io.Writer` and `io.Reader` parameters, so that CLI-level tests can verify prompt defaulting and output without requiring interactive stdin.

**Acceptance Criteria:**
- [ ] `runArchiveCreate(halDir string, name string, in io.Reader, out io.Writer) error` function exists (or similar testable signature)
- [ ] `deriveArchiveName` is exported or accessible for testing
- [ ] `promptForName` accepts `io.Reader` and `io.Writer` instead of using `os.Stdin`/`os.Stdout` directly
- [ ] Existing CLI behavior is unchanged (commands still work)
- [ ] Typecheck passes (`go vet ./...`)

### T-008: CLI tests for hal archive create
**Description:** As a developer, I need CLI-level tests for the archive create command to verify prompt defaulting, --name flag behavior, and error paths.

**Acceptance Criteria:**
- [ ] Tests live in `cmd/archive_test.go`
- [ ] Test: `--name` flag bypasses prompt and uses the provided name
- [ ] Test: when no `--name` and prd.json has branchName, prompt shows the derived default
- [ ] Test: empty input at prompt uses the derived default name
- [ ] Test: error when `.hal/` does not exist
- [ ] Test: error when no feature state files exist
- [ ] Typecheck passes (`go vet ./...`)

### T-009: CLI tests for hal archive list
**Description:** As a developer, I need CLI-level tests for the archive list command to verify default and verbose formatting.

**Acceptance Criteria:**
- [ ] Tests live in `cmd/archive_test.go`
- [ ] Test: default output shows NAME, DATE, PROGRESS columns
- [ ] Test: `--verbose` output shows NAME, DATE, PROGRESS, BRANCH, PATH columns
- [ ] Test: empty archive directory prints "No archives found."
- [ ] Test: error when `.hal/` does not exist
- [ ] Typecheck passes (`go vet ./...`)

### T-010: CLI tests for hal archive restore
**Description:** As a developer, I need CLI-level tests for the archive restore command to verify restore behavior and error paths.

**Acceptance Criteria:**
- [ ] Tests live in `cmd/archive_test.go`
- [ ] Test: restore moves files back to `.hal/` and removes archive directory
- [ ] Test: restore with current state auto-archives before restoring
- [ ] Test: error when archive name does not exist
- [ ] Test: error when `.hal/` does not exist
- [ ] Typecheck passes (`go vet ./...`)

## Functional Requirements

- FR-1: `moveFile` must attempt `os.Rename` first and only fall back to copy-and-remove on `EXDEV`
- FR-2: `moveFile` must preserve file permissions during copy
- FR-3: `moveFile` must remove the source file only after the destination is successfully written and closed
- FR-4: `moveDir` must attempt `os.Rename` first and fall back to recursive copy-and-remove on `EXDEV`
- FR-5: `archive.Create` must use `moveFile` for all file moves
- FR-6: `archive.Restore` must use `moveFile`/`moveDir` for all file moves
- FR-7: All existing archive unit tests must continue to pass unchanged
- FR-8: `make test`, `make vet`, and `make fmt` must all pass cleanly

## Non-Goals

- No support for copying symlinks (archive files are regular files)
- No progress reporting during large cross-device copies
- No atomic cross-device move (copy-then-remove is acceptable)
- No changes to archive directory naming or structure
- No changes to which files are archived (featureStateFiles list unchanged)

## Technical Considerations

- Cross-device detection: check if `os.Rename` error unwraps to `*os.LinkError` with `Err == syscall.EXDEV`
- File copy should use `io.Copy` with buffered I/O for efficiency
- Preserve file mode via `os.Stat` on source before copy, `os.Chmod` on destination after
- The `restoreDir` function currently calls `os.Remove(src)` on the directory after moving contents — this pattern should be preserved but use the new helpers
- CLI test pattern: follow `cmd/init_test.go` approach of extracting testable functions that accept `io.Writer`/`io.Reader`

## Open Questions

- None — the scope is well-defined from the analysis context and existing codebase patterns are clear.
