# PRD: Compound Pipeline Foundations

## Introduction

Establish the foundational infrastructure for the compound pipeline by hardening `internal/compound` core types, config loader, and config template, and ensuring `hal init` properly installs compound config and the reports directory. The compound package already contains working implementations of types, config loading, and pipeline orchestration. This PRD focuses on adding validation, unit test coverage, and wiring verification so that every downstream compound feature (autospec, explode, analyze, auto) builds on a tested, reliable base.

## Goals

- Add config validation so invalid or partial `config.yaml` files produce clear errors
- Achieve unit test coverage for `LoadConfig`, `DefaultAutoConfig`, and config field merging
- Add unit tests for `FindLatestReport` and `FindRecentPRDs` without integration tags
- Add unit tests for `parseAnalysisResponse` covering valid, malformed, and edge-case inputs
- Verify `hal init` creates `.hal/reports/` with `.gitkeep` and installs `config.yaml` from template
- Ensure `CompoundConfig` / `AutoConfig` struct fields are serializable and match the YAML template
- Ensure `make test` passes with no regressions to existing init, engine, and skills tests

## Tasks

### T-001: Add config validation to AutoConfig
**Description:** As a developer, I need a `Validate()` method on `AutoConfig` so that invalid configurations are caught early with clear error messages.

**Acceptance Criteria:**
- [ ] Add `Validate() error` method to `AutoConfig` in `internal/compound/config.go`
- [ ] Validate `ReportsDir` is non-empty
- [ ] Validate `BranchPrefix` is non-empty
- [ ] Validate `MaxIterations` is greater than 0
- [ ] Return a descriptive error for each invalid field (e.g., `"auto.reportsDir must not be empty"`)
- [ ] `LoadConfig` calls `Validate()` before returning the config
- [ ] Typecheck passes (`go vet ./...`)

### T-002: Unit tests for DefaultAutoConfig
**Description:** As a developer, I need tests that verify `DefaultAutoConfig` returns correct default values so that any accidental change to defaults is caught.

**Acceptance Criteria:**
- [ ] Create `internal/compound/config_test.go` (not integration-tagged)
- [ ] Test `DefaultAutoConfig()` returns `ReportsDir == ".hal/reports"`
- [ ] Test `DefaultAutoConfig()` returns `BranchPrefix == "compound/"`
- [ ] Test `DefaultAutoConfig()` returns `MaxIterations == 25`
- [ ] Test `DefaultAutoConfig()` returns empty `QualityChecks` slice
- [ ] Typecheck passes

### T-003: Unit tests for LoadConfig with missing file
**Description:** As a developer, I need tests covering the missing-file path of `LoadConfig` so that defaults are reliably returned when no config.yaml exists.

**Acceptance Criteria:**
- [ ] Add test in `config_test.go`: `LoadConfig` with non-existent directory returns defaults (not an error)
- [ ] Add test: `LoadConfig` with directory that exists but no config.yaml returns defaults
- [ ] Verify returned config matches `DefaultAutoConfig()` field by field
- [ ] Typecheck passes

### T-004: Unit tests for LoadConfig with valid YAML
**Description:** As a developer, I need tests that verify `LoadConfig` correctly parses a valid config.yaml and merges with defaults.

**Acceptance Criteria:**
- [ ] Add test: write a full config.yaml to temp dir, call `LoadConfig`, verify all fields are read
- [ ] Add test: write a partial config.yaml (only `auto.reportsDir`), verify missing fields use defaults
- [ ] Add test: write config.yaml with empty `auto:` section, verify all defaults apply
- [ ] Typecheck passes

### T-005: Unit tests for LoadConfig with invalid YAML
**Description:** As a developer, I need tests covering error paths so that corrupt YAML and validation failures are handled.

**Acceptance Criteria:**
- [ ] Add test: write invalid YAML content, verify `LoadConfig` returns an error
- [ ] Add test: write YAML with `auto.maxIterations: -1`, verify validation error after T-001 is applied
- [ ] Add test: write YAML with `auto.reportsDir: ""` explicitly, verify validation error
- [ ] Typecheck passes

### T-006: Unit tests for FindLatestReport
**Description:** As a developer, I need unit tests for `FindLatestReport` so that report discovery is reliable across edge cases.

**Acceptance Criteria:**
- [ ] Create `internal/compound/analyze_test.go` (not integration-tagged)
- [ ] Test: directory with one report returns that report's path
- [ ] Test: directory with multiple reports returns the most recently modified one
- [ ] Test: empty directory (only .gitkeep) returns error containing "no reports"
- [ ] Test: non-existent directory returns error containing "does not exist"
- [ ] Test: hidden files (`.hidden.md`) are skipped
- [ ] Typecheck passes

### T-007: Unit tests for FindRecentPRDs
**Description:** As a developer, I need unit tests for `FindRecentPRDs` so that PRD filtering by age works correctly.

**Acceptance Criteria:**
- [ ] Add tests in `analyze_test.go` for `FindRecentPRDs`
- [ ] Test: returns only PRD files modified within the last N days
- [ ] Test: excludes PRD files older than N days
- [ ] Test: returns nil (not error) when `.hal` directory does not exist
- [ ] Test: only matches files with `prd-` prefix and `.md` suffix
- [ ] Typecheck passes

### T-008: Unit tests for parseAnalysisResponse
**Description:** As a developer, I need unit tests for `parseAnalysisResponse` so that JSON extraction from engine output is robust.

**Acceptance Criteria:**
- [ ] Add tests in `analyze_test.go` for `parseAnalysisResponse`
- [ ] Test: valid JSON input returns correct `AnalysisResult` fields
- [ ] Test: JSON wrapped in markdown code fences is extracted correctly
- [ ] Test: missing `priorityItem` field returns error
- [ ] Test: missing `branchName` field returns error
- [ ] Test: no JSON in response returns "no JSON object found" error
- [ ] Test: invalid JSON returns error
- [ ] Use table-driven test pattern
- [ ] Typecheck passes

### T-009: Verify init creates reports directory and config
**Description:** As a developer, I need to verify that `hal init` correctly creates the reports directory and installs `config.yaml` from the embedded template.

**Acceptance Criteria:**
- [ ] Add test in `cmd/init_test.go` that calls `runInit` on a temp directory
- [ ] Verify `.hal/reports/` directory is created
- [ ] Verify `.hal/reports/.gitkeep` file exists
- [ ] Verify `.hal/config.yaml` is created with content matching `template.DefaultConfig`
- [ ] Verify running `runInit` a second time does not overwrite existing `config.yaml`
- [ ] Typecheck passes

### T-010: Run full test suite and verify no regressions
**Description:** As a developer, I need to confirm all existing and new tests pass so that the foundation is solid.

**Acceptance Criteria:**
- [ ] `make test` passes with zero failures
- [ ] `make vet` passes with zero warnings
- [ ] New tests in `config_test.go` and `analyze_test.go` run without integration tag
- [ ] Existing `pipeline_test.go` (integration-tagged) still compiles
- [ ] Existing `init_test.go` tests still pass
- [ ] Typecheck passes

## Functional Requirements

- FR-1: `AutoConfig.Validate()` must reject configs where `ReportsDir` is empty
- FR-2: `AutoConfig.Validate()` must reject configs where `BranchPrefix` is empty
- FR-3: `AutoConfig.Validate()` must reject configs where `MaxIterations` is <= 0
- FR-4: `LoadConfig` must return `DefaultAutoConfig()` values when config.yaml does not exist
- FR-5: `LoadConfig` must merge partial YAML with defaults (missing fields get default values)
- FR-6: `LoadConfig` must call `Validate()` on the merged config before returning
- FR-7: `FindLatestReport` must skip hidden files and `.gitkeep`
- FR-8: `FindRecentPRDs` must only match `prd-*.md` files
- FR-9: `hal init` must create `.hal/reports/` with `.gitkeep`
- FR-10: `hal init` must install `config.yaml` from embedded template and preserve existing files

## Non-Goals

- No new CLI commands (analyze, explode, auto commands are out of scope for this PRD)
- No changes to pipeline orchestration logic (`pipeline.go`)
- No changes to git helpers (`git.go`)
- No changes to review logic (`review.go`)
- No new skills or skill embedding changes
- No integration tests requiring the Claude CLI
- No changes to the config.yaml template content (structure is already correct)

## Technical Considerations

- Unit tests must NOT use the `integration` build tag — they should run with `go test ./...`
- Use `t.TempDir()` for all filesystem tests for automatic cleanup
- Follow existing table-driven test patterns (see `review_test.go`)
- `parseAnalysisResponse` is unexported — tests must be in the `compound` package
- The `runInit` function in `cmd/init.go` is unexported — `init_test.go` must be in `package cmd`
- Config validation errors should use `fmt.Errorf` with descriptive messages (no sentinel errors needed)

## Open Questions

- None (scope is well-defined from existing code and analysis context)
