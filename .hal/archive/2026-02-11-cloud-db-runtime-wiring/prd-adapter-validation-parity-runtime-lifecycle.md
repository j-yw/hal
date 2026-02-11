# PRD: Adapter Validation Parity & Runtime Lifecycle

## Introduction/Overview

The `internal/cloud/deploy` package contains duplicated adapter validation logic between `Config.Validate()` and `Config.ValidateStore()`. Both methods implement identical `switch` blocks over `DBAdapter` with the same per-adapter field checks. This duplication is a maintenance hazard — when a new adapter is added, a developer must remember to update both methods identically, and there is no automated safeguard against drift.

This PRD addresses the duplication by extracting a shared `validateAdapter` helper, adding a parity test that automatically detects one-sided adapter additions, and introducing explicit runtime lifecycle APIs (`CloseDefaultStore`, `ResetDefaultStoreForTest`) for clean DB connection management in tests and command teardown.

## Goals

1. **Eliminate duplication:** A single `validateAdapter` helper replaces the duplicated switch blocks in both `Config.Validate` and `Config.ValidateStore`.
2. **Prevent future drift:** A parity test automatically fails if a new adapter constant is handled in `OpenStore` but not `validateAdapter` (or vice versa).
3. **Explicit lifecycle management:** `CloseDefaultStore` and `ResetDefaultStoreForTest` provide clear APIs for closing the cached `*sql.DB` and resetting `sync.Once` state.
4. **Driver registration assertion:** A test validates that both `libsql` and `pgx` drivers are registered after the blank import in `drivers.go`.
5. **All existing tests continue to pass** with no regressions.

## Non-Goals

- Adding new database adapters (e.g., MySQL, SQLite) — this PRD only makes it safer to add them later.
- Changing the Store interface or adapter implementations in `internal/cloud/turso` or `internal/cloud/postgres`.
- Modifying the `cmd/` layer or CLI commands — this is purely internal refactoring.
- Adding integration tests that require live database connections.

## Functional Requirements

- **FR-1:** A `validateAdapter` function exists in `config.go` that validates adapter-specific required fields and returns an error for unknown adapters.
- **FR-2:** `Config.ValidateStore()` delegates adapter validation to `validateAdapter` and performs no additional adapter-specific checks.
- **FR-3:** `Config.Validate()` delegates adapter validation to `validateAdapter`, then checks runner-related fields.
- **FR-4:** A `KnownAdapters` slice (or equivalent) exists as the single source of truth for supported adapter names, used by both validation and parity tests.
- **FR-5:** A parity test ensures every adapter in `KnownAdapters` has a corresponding case in `OpenStore`'s switch block (via `sql.Open` driver name or equivalent assertion).
- **FR-6:** `CloseDefaultStore()` in `runtime.go` closes the cached `*sql.DB` if non-nil and is safe to call when no store is open.
- **FR-7:** `ResetDefaultStoreForTest(t *testing.T)` resets `defaultOnce`, `defaultStore`, `defaultDB`, and `defaultErr` for test isolation. It calls `t.Helper()`.
- **FR-8:** A test validates that `sql.Drivers()` contains both `"libsql"` and `"pgx"` after blank import.
- **FR-9:** No duplicate adapter switch/case blocks remain in `config.go`.

## Tasks

### T-001: Extract `KnownAdapters` slice in config.go

**Description:** As a developer, I need a single source of truth for supported adapter names so that validation and parity tests can iterate over them without hardcoding values in multiple places.

**Acceptance Criteria:**
- [ ] A package-level `KnownAdapters` variable of type `[]string` exists in `config.go` containing `AdapterTurso` and `AdapterPostgres`
- [ ] The existing `AdapterTurso` and `AdapterPostgres` constants remain unchanged
- [ ] No behavioral changes to any existing function
- [ ] `go vet ./internal/cloud/deploy/...` passes
- [ ] Typecheck passes

### T-002: Extract `validateAdapter` helper in config.go

**Description:** As a developer, I need to extract the duplicated adapter switch logic from `Config.Validate` and `Config.ValidateStore` into a single `validateAdapter` method so that adapter-specific field checks live in exactly one place.

**Acceptance Criteria:**
- [ ] A `validateAdapter` method exists on `Config` (or a standalone function accepting `Config`) in `config.go`
- [ ] `validateAdapter` contains the adapter switch with per-adapter required-field checks and unknown-adapter default error
- [ ] No duplicate adapter switch/case blocks remain in `config.go`
- [ ] `go vet ./internal/cloud/deploy/...` passes
- [ ] Typecheck passes

### T-003: Refactor `Config.ValidateStore` to use `validateAdapter`

**Description:** As a developer, I need `Config.ValidateStore` to delegate to `validateAdapter` so that its adapter checks are no longer duplicated.

**Acceptance Criteria:**
- [ ] `Config.ValidateStore()` calls `validateAdapter` and returns its error directly
- [ ] `Config.ValidateStore()` body contains no switch statement on `DBAdapter`
- [ ] All existing `TestConfigValidateStore` test cases pass unchanged
- [ ] `go test ./internal/cloud/deploy/...` passes
- [ ] Typecheck passes

### T-004: Refactor `Config.Validate` to use `validateAdapter`

**Description:** As a developer, I need `Config.Validate` to delegate adapter checks to `validateAdapter` then check runner fields, eliminating its own adapter switch block.

**Acceptance Criteria:**
- [ ] `Config.Validate()` calls `validateAdapter` first, returns early on error, then checks `RunnerURL` and `RunnerServiceToken`
- [ ] `Config.Validate()` body contains no switch statement on `DBAdapter`
- [ ] All existing `TestConfigValidate` test cases pass unchanged
- [ ] `go test ./internal/cloud/deploy/...` passes
- [ ] Typecheck passes

### T-005: Add adapter validation parity test

**Description:** As a developer, I need a test that automatically fails if a new adapter is added to `KnownAdapters` but not handled in `OpenStore`, or vice versa, so that future adapter additions cannot silently drift.

**Acceptance Criteria:**
- [ ] A `TestAdapterValidationParity` test exists in `config_test.go` (or a new `parity_test.go`)
- [ ] The test iterates over `KnownAdapters` and verifies each adapter does NOT produce an "unsupported adapter" error from `OpenStore` (it may fail for other reasons like no server)
- [ ] The test verifies that an adapter NOT in `KnownAdapters` (e.g., `"mysql"`) DOES produce an "unsupported adapter" error from `OpenStore`
- [ ] The test verifies `validateAdapter` accepts every adapter in `KnownAdapters` (with valid fields) and rejects unknown adapters
- [ ] `go test ./internal/cloud/deploy/...` passes
- [ ] Typecheck passes

### T-006: Add `CloseDefaultStore` to runtime.go

**Description:** As a developer, I need an explicit function to close the cached `*sql.DB` connection held by `DefaultStoreFactory` so that commands and tests can cleanly release database resources.

**Acceptance Criteria:**
- [ ] `CloseDefaultStore()` function exists in `runtime.go`
- [ ] It closes `defaultDB` if non-nil and returns an error
- [ ] It is safe to call when `defaultDB` is nil (returns nil)
- [ ] `go vet ./internal/cloud/deploy/...` passes
- [ ] Typecheck passes

### T-007: Add `ResetDefaultStoreForTest` to runtime.go

**Description:** As a developer, I need a test helper that resets the package-level `sync.Once` and cached store/DB/error so that multiple tests can exercise `DefaultStoreFactory` in isolation without package-level state leaking between tests.

**Acceptance Criteria:**
- [ ] `ResetDefaultStoreForTest(t *testing.T)` function exists in `runtime.go`
- [ ] It calls `t.Helper()`
- [ ] It resets `defaultOnce` to a zero `sync.Once`, sets `defaultStore` to nil, `defaultDB` to nil, and `defaultErr` to nil
- [ ] `go vet ./internal/cloud/deploy/...` passes
- [ ] Typecheck passes

### T-008: Add driver registration assertion test

**Description:** As a developer, I need a test that verifies the blank imports in `drivers.go` correctly register both `libsql` and `pgx` database drivers so that `sql.Open` calls work at runtime.

**Acceptance Criteria:**
- [ ] A `TestDriversRegistered` test exists (in `drivers_test.go` or equivalent)
- [ ] The test calls `sql.Drivers()` and asserts that `"libsql"` is present in the returned slice
- [ ] The test calls `sql.Drivers()` and asserts that `"pgx"` is present in the returned slice
- [ ] `go test ./internal/cloud/deploy/...` passes
- [ ] Typecheck passes

### T-009: Update existing runtime tests to use `ResetDefaultStoreForTest`

**Description:** As a developer, I need the existing runtime tests to use `ResetDefaultStoreForTest` for cleanup so they demonstrate the lifecycle API and don't leak state.

**Acceptance Criteria:**
- [ ] Existing `TestNewStoreFactory_*` tests remain unchanged (they use isolated `newStoreFactory`, not the package-level default)
- [ ] A new test `TestDefaultStoreFactory_ResetIsolation` exists that calls `ResetDefaultStoreForTest(t)` and then `DefaultStoreFactory()` to verify clean state
- [ ] The new test verifies that after reset, calling `DefaultStoreFactory` re-triggers initialization (calls config loader again)
- [ ] `go test ./internal/cloud/deploy/...` passes
- [ ] Typecheck passes

### T-010: Run full test suite and vet

**Description:** As a developer, I need to verify that all changes integrate cleanly: `make test` and `make vet` pass with no failures or warnings.

**Acceptance Criteria:**
- [ ] `make test` passes with all tests green (exit code 0)
- [ ] `make vet` passes with no issues (exit code 0)
- [ ] No duplicate adapter switch/case blocks remain in `config.go`
- [ ] Typecheck passes

## Technical Considerations

- **`validateAdapter` signature:** Use a method on `Config` (`func (c Config) validateAdapter() error`) to keep it consistent with `Validate` and `ValidateStore` and avoid passing individual fields.
- **`KnownAdapters` ordering:** Place `AdapterTurso` first since it is the default adapter.
- **`ResetDefaultStoreForTest` visibility:** Export the function so tests in other packages (e.g., `cmd`) can also reset state. Require `*testing.T` parameter to signal it's test-only.
- **`CloseDefaultStore` thread safety:** Since it modifies package-level state, document that it should only be called after all goroutines using the store have completed (e.g., during shutdown or `t.Cleanup`).
- **Parity test strategy:** Rather than parsing source code, the parity test calls `OpenStore` with minimal configs for each known adapter and checks the error is NOT "unsupported adapter" — this approach is runtime-based and doesn't depend on AST analysis.

## Open Questions

- **Q1:** Should `CloseDefaultStore` also reset the `sync.Once` so that a subsequent `DefaultStoreFactory` call re-initializes? Current design says no — `CloseDefaultStore` is for production teardown, `ResetDefaultStoreForTest` is for test isolation. If combined behavior is needed later, it can be added.
