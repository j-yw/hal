# PRD: Deterministic Template Refresh Output

## Introduction/Overview

The `refreshTemplates` and `runInit` functions in `cmd/init.go` iterate over `template.DefaultFiles()`, which returns a `map[string]string`. Go map iteration order is nondeterministic, causing CLI output to vary between runs. This makes the user experience unpredictable and test assertions fragile. This PRD covers sorting template filenames at call sites so that all CLI output is deterministic and testable.

## Goals

1. **Deterministic CLI output** — `hal init`, `hal init --refresh-templates`, and `hal init --refresh-templates --dry-run` produce identical output ordering across repeated runs.
2. **Stable test assertions** — Tests can assert exact output line order rather than using unordered substring checks.
3. **Minimal change surface** — Sorting happens at call sites in `cmd/init.go`; `template.DefaultFiles()` return type remains `map[string]string`.
4. **Prerequisite for Cobra-level CLI tests** — Deterministic output enables reliable end-to-end test assertions.

## Tasks

### T-001: Sort filenames in refreshTemplates iteration

**Description:** As a developer, I need `refreshTemplates` to iterate over template filenames in sorted (lexicographic) order so that CLI output is deterministic.

**Acceptance Criteria:**
- [ ] `refreshTemplates` in `cmd/init.go` extracts keys from `template.DefaultFiles()`, sorts them with `sort.Strings`, and iterates in sorted order
- [ ] `import "sort"` is added to `cmd/init.go` (if not already present)
- [ ] No changes are made to `template.DefaultFiles()` return type or `internal/template/template.go`
- [ ] `go build ./...` succeeds
- [ ] Typecheck passes

### T-002: Sort filenames in runInit default-file creation loop

**Description:** As a developer, I need the default-file creation loop in `runInit` to iterate in sorted order so that the "Created" and "Already existed" output lists are deterministic.

**Acceptance Criteria:**
- [ ] The `for filename, content := range template.DefaultFiles()` loop in `runInit` extracts keys, sorts them, and iterates in sorted order
- [ ] The `created` and `skipped` slices are populated in sorted filename order
- [ ] `go build ./...` succeeds
- [ ] Typecheck passes

### T-003: Verify existing refreshTemplates unit tests pass with sorted iteration

**Description:** As a developer, I need to confirm that the existing `TestRefreshTemplates` tests in `cmd/init_test.go` still pass after the sorting changes, updating assertions if needed to match sorted order.

**Acceptance Criteria:**
- [ ] `go test -v -run TestRefreshTemplates ./cmd/` passes
- [ ] If any test assertions depended on map iteration order, they are updated to expect sorted order
- [ ] No test logic is removed — only assertion order is adjusted if necessary
- [ ] Typecheck passes

### T-004: Verify existing runInit unit tests pass with sorted iteration

**Description:** As a developer, I need to confirm that the existing `TestRunInit` tests in `cmd/init_test.go` still pass after the sorting changes in `runInit`.

**Acceptance Criteria:**
- [ ] `go test -v -run TestRunInit ./cmd/` passes
- [ ] No test logic is removed
- [ ] Typecheck passes

### T-005: Add deterministic-output unit test for refreshTemplates

**Description:** As a developer, I need a dedicated unit test that asserts the exact output line order of `refreshTemplates` matches sorted filename sequence, proving determinism.

**Acceptance Criteria:**
- [ ] A new test case (or standalone test function) in `cmd/init_test.go` calls `refreshTemplates` and asserts output lines appear in `config.yaml`, `progress.txt`, `prompt.md` order (lexicographic sort of DefaultFiles keys)
- [ ] The test runs `refreshTemplates` multiple times (at least 3) and asserts identical output each time
- [ ] The test validates both dry-run and non-dry-run modes produce sorted output
- [ ] `go test -v -run TestRefreshTemplatesDeterministic ./cmd/` passes
- [ ] Typecheck passes

### T-006: Add Cobra-level integration test for `hal init --refresh-templates`

**Description:** As a developer, I need a Cobra-level integration test that executes the `init` command with `--refresh-templates` through the Cobra command tree, validating full CLI wiring and deterministic output.

**Acceptance Criteria:**
- [ ] A new test function in `cmd/init_test.go` creates a Cobra command, sets `--refresh-templates` flag, captures stdout, and executes
- [ ] The test asserts output lines contain "refreshed" or "created" entries in sorted filename order
- [ ] The test validates that actual files are created/refreshed on disk
- [ ] `go test -v -run TestInitRefreshTemplatesCobra ./cmd/` passes
- [ ] Typecheck passes

### T-007: Add Cobra-level integration test for `hal init --refresh-templates --dry-run`

**Description:** As a developer, I need a Cobra-level integration test that executes `init --refresh-templates --dry-run` through the Cobra command tree, validating dry-run output is deterministic and no files are modified.

**Acceptance Criteria:**
- [ ] A new test function in `cmd/init_test.go` creates a Cobra command, sets both `--refresh-templates` and `--dry-run` flags, captures stdout, and executes
- [ ] The test asserts output lines contain `[dry-run]` prefix and appear in sorted filename order
- [ ] The test validates that no files are modified or created on disk
- [ ] `go test -v -run TestInitDryRunCobra ./cmd/` passes
- [ ] Typecheck passes

### T-008: Run full test suite and verify no regressions

**Description:** As a developer, I need to run the complete test suite to ensure all changes are backward-compatible and no regressions are introduced.

**Acceptance Criteria:**
- [ ] `go test ./...` passes with zero failures
- [ ] `go vet ./...` reports no issues
- [ ] `go build ./...` succeeds
- [ ] Typecheck passes

## Functional Requirements

- **FR-1:** `refreshTemplates` MUST iterate over template filenames in lexicographic (sorted) order.
- **FR-2:** `runInit` default-file creation loop MUST iterate over template filenames in lexicographic (sorted) order.
- **FR-3:** CLI output from `hal init --refresh-templates` MUST be identical across repeated runs on the same file state.
- **FR-4:** CLI output from `hal init --refresh-templates --dry-run` MUST be identical across repeated runs on the same file state.
- **FR-5:** Sorting MUST happen at the call site in `cmd/init.go`, not by changing `template.DefaultFiles()` return type.

## Non-Goals

- Changing `template.DefaultFiles()` to return an ordered type (e.g., slice of pairs) — sorting at call site is sufficient.
- Adding sorting to any other map iterations outside `cmd/init.go`.
- Modifying the `internal/template` package in any way.
- Adding CLI output formatting changes beyond ordering (no color, no table format, etc.).
- Performance optimization — the map has 3 entries; sorting overhead is negligible.

## Technical Considerations

- `template.DefaultFiles()` returns `map[string]string` with 3 entries: `config.yaml`, `progress.txt`, `prompt.md`. Sorted order is: `config.yaml`, `progress.txt`, `prompt.md`.
- Use `sort.Strings` on extracted keys — standard library, no new dependencies.
- Cobra-level tests should use `cmd.SetOut(&buf)` and `cmd.SetArgs([]string{"--refresh-templates"})` to capture output and set flags programmatically.
- Cobra tests need `os.Chdir` to a temp directory (matching existing `TestRunInit` pattern) since `runInit` uses relative paths.
- The `writeFile` helper from `cmd/archive_test.go` is available for test setup.

## Open Questions

- None. The scope is well-defined and all implementation details are clear from the existing codebase.
