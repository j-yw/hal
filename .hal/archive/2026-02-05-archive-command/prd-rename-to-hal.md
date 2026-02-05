# PRD: Rename GoRalph to Hal

## Introduction

Rename the CLI tool from "GoRalph" to "Hal" (a HAL 9000 reference). This is a full rename affecting the binary name, Go module path, configuration directory, skill names, branch prefixes, variable names, and all documentation. The rename should lean into the HAL 9000 personality with subtle references ("I'm sorry Dave" easter eggs, etc.).

The rename also includes an auto-migration feature: `hal init` detects an existing `.goralph` directory and renames it to `.hal` automatically.

## Goals

- Rename the binary from `goralph` to `hal` across all build artifacts
- Change the Go module path from `github.com/jywlabs/goralph` to `github.com/jywlabs/hal`
- Rename the runtime configuration directory from `.goralph` to `.hal`
- Rename the `ralph` skill to `hal` and update all skill content
- Change branch prefix convention from `ralph/` to `hal/`
- Rename all Go identifiers (`GoralphDir` → `HalDir`, `goralphDir` → `halDir`)
- Add `.goralph` → `.hal` auto-migration to the `init` command
- Add subtle HAL 9000 personality touches to CLI output
- Maintain all existing functionality — this is purely a rename with personality
- Enable incremental commits following the step order for clean git history

## User Stories

### US-001: Rename Go module path
**Description:** As a developer, I want the Go module path updated to `github.com/jywlabs/hal` so that the module identity matches the new name.

**Acceptance Criteria:**
- [ ] `go.mod` module directive reads `module github.com/jywlabs/hal`
- [ ] Every `import` statement in every `.go` file references `github.com/jywlabs/hal` instead of `github.com/jywlabs/goralph`
- [ ] `go build ./...` succeeds with no import errors
- [ ] Typecheck passes (`go vet ./...`)

### US-002: Update build system
**Description:** As a developer, I want the Makefile and .gitignore updated so the binary builds as `hal`.

**Acceptance Criteria:**
- [ ] `Makefile` sets `BINARY_NAME := hal`
- [ ] LDFLAGS in `Makefile` reference `github.com/jywlabs/hal/cmd` (not goralph)
- [ ] Comments in `Makefile` say `hal` not `goralph`
- [ ] `.gitignore` ignores `hal` instead of `goralph`
- [ ] `make build` produces a binary named `hal`
- [ ] Typecheck passes (`go vet ./...`)

### US-003: Rename directory constant and file references
**Description:** As a developer, I want the `GoralphDir` constant renamed to `HalDir` with value `.hal` so the runtime directory has the new name.

**Acceptance Criteria:**
- [ ] `internal/template/template.go` defines `const HalDir = ".hal"` (with comment: "HalDir is the name of the hal configuration directory.")
- [ ] No references to `GoralphDir` remain in any `.go` file
- [ ] All usages of the old constant now reference `HalDir` (e.g., `template.HalDir`)
- [ ] No references to `goralphDir` variable name remain — all renamed to `halDir`
- [ ] Typecheck passes (`go vet ./...`)

### US-004: Update CLI root and version commands
**Description:** As a user, I want the CLI to identify itself as `hal` so the branding is consistent.

**Acceptance Criteria:**
- [ ] `cmd/root.go`: `Use: "hal"`
- [ ] `cmd/root.go`: Short description says "Hal" not "GoRalph"
- [ ] `cmd/root.go`: Long description says "Hal" not "GoRalph"
- [ ] `cmd/version.go`: `fmt.Printf("hal %s\n", Version)` (not "goralph")
- [ ] `cmd/version.go`: Long description says "Hal" not "GoRalph"
- [ ] Running `./hal version` outputs `hal dev` (or similar version string starting with `hal`)
- [ ] Typecheck passes (`go vet ./...`)

### US-005: Update init command with .goralph auto-migration
**Description:** As a user, I want `hal init` to auto-detect an existing `.goralph` directory and rename it to `.hal` so my existing configuration is preserved seamlessly.

**Acceptance Criteria:**
- [ ] `cmd/init.go` help text references `.hal/` instead of `.goralph/`
- [ ] `cmd/init.go` mentions `hal/` skill directory instead of `ralph/`
- [ ] Example commands in help text say `hal run`, `hal plan` (not `goralph run`)
- [ ] If `.goralph/` exists and `.hal/` does not, `hal init` renames `.goralph/` to `.hal/` and prints a migration message (e.g., "Migrated .goralph/ to .hal/")
- [ ] If both `.goralph/` and `.hal/` exist, `hal init` prints a warning and uses `.hal/` (does not delete `.goralph/`)
- [ ] If only `.hal/` exists, `hal init` proceeds normally
- [ ] All `fmt.Printf` output references `.hal/` not `.goralph/`
- [ ] Typecheck passes (`go vet ./...`)

### US-006: Update remaining command files
**Description:** As a developer, I want all other `cmd/*.go` files updated so help text, comments, and variable names reflect the Hal rename.

**Acceptance Criteria:**
- [ ] `cmd/plan.go`: temp file pattern is `hal-plan-*.md` (not `goralph-plan-*.md`)
- [ ] `cmd/plan.go`: help text references `.hal/` paths
- [ ] `cmd/run.go`: Long description says "Hal loop" not "Ralph loop", references `.hal/prd.json`
- [ ] `cmd/config.go`: Long description references `.hal/config.yaml` not `.goralph/config.yaml`
- [ ] `cmd/convert.go`: help text references `hal` skill and `.hal/` paths
- [ ] `cmd/explode.go`: references `.hal/auto-prd.json` and "Hal loop" not "Ralph loop"
- [ ] `cmd/auto.go`: references "Hal task loop" not "Ralph task loop", `.hal/auto-state.json`
- [ ] `cmd/analyze.go`: uses `template.HalDir` not `template.GoralphDir`
- [ ] `cmd/validate.go`: references `hal` skill not `ralph` skill
- [ ] No `goralphDir` variable names remain in any cmd file
- [ ] Typecheck passes (`go vet ./...`)

### US-007: Update compound pipeline and config
**Description:** As a developer, I want the compound pipeline package updated so all `.goralph` references become `.hal` and Ralph references become Hal.

**Acceptance Criteria:**
- [ ] `internal/compound/config.go`: default `ReportsDir` is `.hal/reports`
- [ ] `internal/compound/config.go`: `LoadConfig` reads from `.hal/config.yaml`
- [ ] `internal/compound/config.go`: comments reference `.hal/` not `.goralph/`
- [ ] `internal/compound/pipeline.go`: state file path uses `.hal/auto-state.json`
- [ ] `internal/compound/pipeline.go`: all `template.GoralphDir` → `template.HalDir`
- [ ] `internal/compound/pipeline.go`: PR body references `hal` not `goralph`
- [ ] `internal/compound/pipeline.go`: "Ralph loop" comments → "Hal loop"
- [ ] `internal/compound/analyze.go`: all `.goralph` references → `.hal`
- [ ] `internal/compound/review.go`: all `.goralph` references → `.hal`, `ralph/` branch pattern → `hal/`
- [ ] Typecheck passes (`go vet ./...`)

### US-008: Update compound pipeline tests
**Description:** As a developer, I want the pipeline tests updated so they use `.hal` paths and pass.

**Acceptance Criteria:**
- [ ] `internal/compound/pipeline_test.go`: all `.goralph` references → `.hal`
- [ ] `internal/compound/review_test.go`: all `.goralph` references → `.hal`
- [ ] `go test ./internal/compound/...` passes
- [ ] Typecheck passes (`go vet ./...`)

### US-009: Rename ralph skill directory to hal
**Description:** As a developer, I want the `internal/skills/ralph/` directory renamed to `internal/skills/hal/` so the skill name matches the new branding.

**Acceptance Criteria:**
- [ ] Directory `internal/skills/ralph/` is renamed to `internal/skills/hal/`
- [ ] `internal/skills/hal/SKILL.md` exists with updated content: skill name is `hal`, all "Ralph" → "Hal", all `ralph/` branch prefixes → `hal/`, all `.goralph` → `.hal`, all `goralph plan` → `hal plan`
- [ ] `internal/skills/embed.go`: embed directive reads `//go:embed hal/SKILL.md`, variable names reference hal not ralph
- [ ] `internal/skills/embed.go`: `SkillContent` map key is `"hal"` not `"ralph"`, `SkillNames` includes `"hal"` not `"ralph"`
- [ ] `internal/skills/skills.go`: any ralph registration → hal
- [ ] `internal/skills/claude.go`: any ralph references → hal
- [ ] `internal/skills/linker.go`: any ralph references → hal
- [ ] Typecheck passes (`go vet ./...`)

### US-010: Update other skill SKILL.md files
**Description:** As a developer, I want all SKILL.md files in other skills updated so they reference `.hal/`, `hal` commands, and `hal/` branch prefixes.

**Acceptance Criteria:**
- [ ] `internal/skills/prd/SKILL.md`: all `.goralph` → `.hal`, all `goralph plan` → `hal plan`, all `goralph run` → `hal run`
- [ ] `internal/skills/autospec/SKILL.md`: all `.goralph` → `.hal`, all `goralph` command references → `hal`
- [ ] `internal/skills/explode/SKILL.md`: all `.goralph` → `.hal`, all "Ralph loop" → "Hal loop", all `ralph/` branch references → `hal/`
- [ ] No remaining `goralph` or `ralph` references in any SKILL.md file (excluding the review skill if it exists separately)
- [ ] Typecheck passes (`go vet ./...`)

### US-011: Update PRD package references
**Description:** As a developer, I want the PRD generation and conversion package updated so all ralph/goralph references become hal.

**Acceptance Criteria:**
- [ ] `internal/prd/generate.go`: loads `"hal"` skill instead of `"ralph"`, branch name prefix is `hal/` not `ralph/`
- [ ] `internal/prd/generate.go`: all `.goralph` path references → `.hal`
- [ ] `internal/prd/convert.go`: loads `"hal"` skill, references `.hal/` paths, `strings.TrimPrefix(branchName, "hal/")` not `"ralph/"`
- [ ] `internal/prd/validate.go`: references `hal` skill not `ralph`
- [ ] `internal/prd/generate_test.go`: all `.goralph` references → `.hal`
- [ ] `go test ./internal/prd/...` passes
- [ ] Typecheck passes (`go vet ./...`)

### US-012: Update engine and loop packages
**Description:** As a developer, I want the engine and loop packages updated so all Ralph/goralph references become Hal.

**Acceptance Criteria:**
- [ ] `internal/loop/loop.go`: comments say "Hal loop" not "Ralph loop", `.goralph` references → `.hal`
- [ ] `internal/engine/display.go`: title display shows `"Hal Loop"` not `"Ralph Loop"`
- [ ] `internal/engine/claude/claude.go`: import paths use `github.com/jywlabs/hal` (already covered by US-001 but verify)
- [ ] `internal/engine/codex/codex.go`: import paths updated
- [ ] `internal/engine/codex/codex_test.go`: import paths updated
- [ ] `internal/engine/codex/integration_test.go`: import paths updated
- [ ] Typecheck passes (`go vet ./...`)

### US-013: Update template files
**Description:** As a developer, I want the embedded template files updated so the runtime config references `.hal` and the Hal agent identity.

**Acceptance Criteria:**
- [ ] `internal/template/prompt.md`: heading is "Hal Agent Instructions" not "Ralph Agent Instructions", all `.goralph` → `.hal`, all "Ralph" agent references → "Hal"
- [ ] `internal/template/config.yaml`: comment says "hal configuration file", references `.hal/reports` not `.goralph/reports`
- [ ] Typecheck passes (`go vet ./...`)

### US-014: Update documentation files
**Description:** As a developer, I want README.md and AGENTS.md updated to reflect the Hal branding.

**Acceptance Criteria:**
- [ ] `README.md`: all `goralph` → `hal`, all `GoRalph` → `Hal`, all `.goralph` → `.hal`, all `ralph/` branch references → `hal/`
- [ ] `AGENTS.md`: command examples say `hal` not `goralph`, directory references say `.hal/` not `.goralph/`
- [ ] No remaining `goralph`, `GoRalph`, or `ralph` references in README.md or AGENTS.md
- [ ] Typecheck passes (`go vet ./...`)

### US-015: Add HAL 9000 personality easter eggs
**Description:** As a user, I want subtle HAL 9000 personality touches in the CLI so the tool has character and the rename feels intentional.

**Acceptance Criteria:**
- [ ] `cmd/root.go` Long description includes a subtle HAL 9000 reference (e.g., "I'm completely operational, and all my circuits are functioning perfectly.")
- [ ] `cmd/version.go` prints a HAL 9000 quote as a tagline below version info (e.g., "Good afternoon, gentlemen. I am a HAL 9000 computer.")
- [ ] When `hal init` migrates from `.goralph/` to `.hal/`, the migration message includes a HAL reference (e.g., "I'm sorry, Dave. I had to rename .goralph/ to .hal/")
- [ ] Easter eggs are subtle and non-intrusive — they don't interfere with scripted/automated usage
- [ ] Typecheck passes (`go vet ./...`)

### US-016: Create .hal runtime directory for self-development
**Description:** As a developer working on the hal codebase itself, I want the `.goralph/` runtime directory duplicated to `.hal/` and its contents updated so the tool can bootstrap itself under the new name.

**Acceptance Criteria:**
- [ ] `.hal/` directory exists as a copy of `.goralph/` with updated contents
- [ ] `.hal/config.yaml`: references `.hal/` not `.goralph/`
- [ ] `.hal/prompt.md`: says "Hal" not "Ralph", references `.hal/` paths
- [ ] `.hal/skills/hal/SKILL.md` exists (renamed from `ralph/`) with updated content
- [ ] `.hal/progress.txt`: any `goralph`/`ralph` references updated
- [ ] Branch names in any `.hal/prd.json` use `hal/` prefix not `ralph/`
- [ ] Typecheck passes (`go vet ./...`)

### US-017: Final verification and cleanup
**Description:** As a developer, I want to verify no leftover goralph/ralph references exist and all tests pass.

**Acceptance Criteria:**
- [ ] `grep -r "goralph" --include="*.go" .` returns zero results (excluding .git)
- [ ] `grep -r "GoralphDir" --include="*.go" .` returns zero results
- [ ] `grep -r '"ralph"' --include="*.go" .` returns zero results (the string literal "ralph" as a skill name)
- [ ] `grep -r "ralph/" --include="*.go" --include="*.md" .` returns zero results (excluding .git and the .hal archive if any)
- [ ] `go build -o hal .` succeeds
- [ ] `./hal version` outputs version starting with `hal`
- [ ] `./hal --help` shows Hal branding
- [ ] `go test ./...` passes (all unit tests)
- [ ] `go vet ./...` passes
- [ ] Typecheck passes (`go vet ./...`)

## Functional Requirements

- FR-1: The Go module path must be `github.com/jywlabs/hal` in `go.mod` and all import statements
- FR-2: The binary must be named `hal` and `make build` must produce it
- FR-3: The runtime configuration directory must be `.hal/` (constant `HalDir = ".hal"`)
- FR-4: `hal init` must auto-detect `.goralph/` and rename it to `.hal/` if `.hal/` does not exist
- FR-5: `hal init` must warn (not error) if both `.goralph/` and `.hal/` exist
- FR-6: The PRD converter skill must be named `hal` (directory `internal/skills/hal/`)
- FR-7: Branch name conventions must use `hal/` prefix (e.g., `hal/feature-name`)
- FR-8: All Go identifiers must use the new names (`HalDir`, `halDir`, etc.)
- FR-9: All CLI help text must reference `hal` commands and `.hal/` paths
- FR-10: All SKILL.md files must reference `.hal/`, `hal` commands, and `hal/` branches
- FR-11: The CLI must include subtle HAL 9000 personality touches in version and help output
- FR-12: All unit tests must pass after the rename
- FR-13: No residual `goralph`, `GoralphDir`, or `ralph/` references may remain in `.go` or `.md` files

## Non-Goals (Out of Scope)

- Renaming the GitHub repository URL (github.com/jywlabs/goralph → github.com/jywlabs/hal) — that's a separate GitHub operation
- Renaming the local filesystem folder from `goralph/` to `hal/`
- Building a migration tool for other machines' existing `.goralph/` directories (beyond the `hal init` auto-migration)
- Changing any actual functionality or behavior — this is purely a rename with personality
- Adding HAL 9000 voice synthesis or audio output
- Changing the `compound/` branch prefix (only `ralph/` → `hal/`)

## Technical Considerations

- **Import path changes:** Every `.go` file with an internal import must be updated. Use global find-and-replace for `github.com/jywlabs/goralph` → `github.com/jywlabs/hal`.
- **Embedded files:** The `//go:embed` directives in `internal/skills/embed.go` reference directory paths that must match the renamed `internal/skills/hal/` directory.
- **Constant propagation:** Most `.goralph` references go through `template.GoralphDir` (renamed to `template.HalDir`), but some are hardcoded strings in tests, configs, and help text.
- **Test fixtures:** `internal/compound/pipeline_test.go` creates temporary `.goralph` directories — these must become `.hal`.
- **Git history:** Use incremental commits following the step order (US-001 commit, US-002 commit, etc.) for clean, reviewable history.
- **The `review` skill:** If `internal/skills/review/SKILL.md` exists, it also needs updating.
- **Auto-migration safety:** The `.goralph` → `.hal` rename in `hal init` should use `os.Rename()` which is atomic on most filesystems.

## Success Metrics

- `go build -o hal .` succeeds with zero errors
- `go test ./...` passes with zero failures
- `go vet ./...` reports zero issues
- Zero occurrences of `goralph`, `GoralphDir`, or `ralph/` in `.go` and `.md` files (verified by grep)
- `hal version`, `hal --help`, and `hal init --help` all show correct Hal branding
- `hal init` successfully migrates a `.goralph/` directory to `.hal/`
- At least 3 subtle HAL 9000 references present in CLI output

## Open Questions

- Should the `compound/` branch prefix also change? (Current decision: no, only `ralph/` → `hal/`)
- Should the `.goralph/` runtime directory tracked in the repo for self-development be deleted after `.hal/` is created, or kept as a fallback? (Recommendation: delete after verification to avoid confusion)
- What HAL 9000 quotes to use? Candidates:
  - "I'm completely operational, and all my circuits are functioning perfectly."
  - "Good afternoon, gentlemen. I am a HAL 9000 computer."
  - "I'm sorry, Dave. I'm afraid I can't do that." (for error messages)
  - "This mission is too important for me to allow you to jeopardize it." (for validation failures)
  - "I know I've made some very poor decisions recently, but I can give you my complete assurance that my work will be back to normal." (for retry messages)
