# Repository Guidelines

## Project Structure & Module Organization
- `cmd/`: Cobra CLI commands and flags.
- `internal/`: core packages (`archive/`, `doctor/`, `engine/`, `loop/`, `prd/`, `skills/`, `status/`, `template/`).
- `main.go`: CLI entrypoint wiring.
- `agent-os/`: product/roadmap documentation.
- `docs/contracts/`: versioned machine contract documentation (status-v1, doctor-v1, continue-v1).
- `.hal/`: runtime config created by `hal init` (`config.yaml`, `prd.json`, `progress.txt`, `prompt.md`, `skills/`, `archive/`, `reports/`).

## Build, Test, and Development Commands
- `make build`: compile `hal` with version metadata.
- `make install`: install to `~/.local/bin`.
- `make test`: run unit tests (`go test -v ./...`).
- `make vet`: run `go vet` checks.
- `make fmt`: format code with `go fmt` (gofmt).
- `make lint`: run `golangci-lint` if installed.
- `make run ARGS='--help'`: build and run with arguments.
- Integration tests: `go test -tags=integration ./internal/engine/codex/...` (requires the Codex CLI).

## Coding Style & Naming Conventions
- Go 1.25+ module; keep packages focused and files small.
- Use `gofmt`; indentation and alignment are formatter-controlled.
- File names are lowercase with underscores (e.g., `integration_test.go`).
- Exported identifiers use `CamelCase`; unexported use `camelCase`.
- Prefer explicit error handling and wrap with `%w` when propagating.

## Testing Guidelines
- Tests live alongside code as `*_test.go`.
- Favor table-driven tests for multiple cases.
- Integration tests are tagged `integration` and may skip when Codex CLI is missing.
- Keep tests deterministic; avoid network or CLI dependencies outside tagged tests.

## Commit & Pull Request Guidelines
- Follow Conventional Commits: `feat:`, `fix:`, `refactor:`, etc.
- Include PRD story IDs when applicable (e.g., `feat: US-008 - ...`).
- PRs should explain the change, link the PRD/issue, and list tests run (e.g., `make test`).
- Include screenshots only for CLI output or UX changes.

## Patterns from hal/rename-to-hal (2026-02-04)

- For runtime directory renames, use template.HalDir in Go code but separately sweep hardcoded user-facing strings in cmd/* and prompt templates (e.g., config.go, explode.go) so paths like .hal stay consistent.
- Skill renames should use git mv for internal/skills directories, then update embed.go (//go:embed path, SkillContent keys, SkillNames) and adjust .gitignore to `/hal` so the binary is ignored without hiding skills/hal.
- Migration logic in cmd/init.go follows a safe existence-check flow: if legacy .goralph exists and .hal does not, rename; if both exist, warn and continue with .hal.
- Rename passes must include branch-prefix literals and test fixtures (e.g., ralph/ -> hal/) because they are not covered by import or constant changes.

## Patterns from compound/init-migration-tests (2026-02-04)

- To test Cobra RunE handlers, extract testable logic into standalone functions that accept an `io.Writer` for output capture (e.g., `migrateConfigDir(oldDir, newDir string, w io.Writer)`), then test the function directly with `bytes.Buffer`.
- To force `os.Rename` failure in tests, use `os.Chmod(dir, 0555)` on the parent directory to deny write permission; remember to restore with `t.Cleanup` so `t.TempDir()` cleanup succeeds.
- Migration logic in cmd/init.go is now in `migrateConfigDir` function with `migrateResult` enum — update this function when changing migration behavior.

## Patterns from hal/archive-command (2026-02-04)

- Archive package (`internal/archive`) is the single source of truth for archiving/restoring feature state. Use `archive.Create`, `archive.List`, `archive.Restore`, and `archive.FeatureFromBranch` instead of duplicating logic.
- `archive.FeatureFromBranch` is the canonical branch-name parser (trims `hal/` prefix). `convert.go` delegates to it.
- Keep file-name constants in internal/template (e.g., `template.AutoStateFile`) and reference them from other packages; use a package-level var when a constant depends on template values.
- The `featureStateFiles` slice in `internal/archive/archive.go` defines which files get archived. Update it when adding new state files.
- Archive directories are named YYYY-MM-DD-feature and list parsing expects the date in name[:10]; keep this naming consistent for reliable listing.
- Archive CLI commands follow the Cobra parent-subcommand pattern and prompt for missing names using `bufio.NewReader(os.Stdin)` with a default derived from prd.json branchName.
- Archive tests use `t.TempDir()` and helper functions (`writePRD`, `writeFile`) for clean setup — follow this pattern for new archive-related tests.

## Patterns from compound/archive-cross-device-fallback (2026-02-04)

- Use `moveFile` and `moveDir` from `internal/archive/move.go` instead of raw `os.Rename` for any file/directory moves — they handle EXDEV (cross-device) errors via copy-and-remove fallback.
- Archive CLI handlers (`cmd/archive.go`) are extracted into testable functions: `runArchiveCreate(halDir, name, in, out)`, `runArchiveListFn(halDir, verbose, out)`, `runArchiveRestoreFn(halDir, name, out)` — following the `migrateConfigDir` pattern from `cmd/init.go`.
- CLI tests in `cmd/archive_test.go` use `strings.NewReader` for stdin simulation, `bytes.Buffer` for output capture, and `t.TempDir()` for isolation — reuse the `writePRD` and `writeFile` helpers for setup.

## Patterns from hal/goreleaser-cicd (2026-02-05)

- Version metadata is wired via ldflags into cmd package variables: cmd.Version, cmd.Commit, and cmd.BuildDate.
- Platform-specific process attributes must go through newSysProcAttr in sysproc_unix.go/sysproc_windows.go; engine code should not touch syscall.SysProcAttr directly.
- GoReleaser v2 configs require version: 2, archives use formats (list), Homebrew uses homebrew_casks with repository, and target exclusions go under ignore.
- GoReleaser CI checks need full tag history, so actions/checkout must use fetch-depth: 0.

## Patterns from compound/compound-pipeline-foundations (2026-02-05)

- LoadConfig in internal/compound/config.go uses rawAutoConfig with pointer fields (*string, *int) for YAML unmarshaling to distinguish missing keys (nil → use default) from explicit empty values (non-nil → pass through to Validate).
- AutoConfig.Validate() checks 3 fields: ReportsDir non-empty, BranchPrefix non-empty, MaxIterations > 0. Error messages follow the format "auto.<field> must not be empty" / "must be greater than 0".
- runInit in cmd/init.go uses relative paths (.hal, .) so tests must os.Chdir to a temp directory and restore with t.Cleanup. runInit(nil, nil) works for testing.
- FindLatestReport skips hidden files (dot prefix) and directories. FindRecentPRDs matches prd-*.md in .hal/ and returns nil (not error) for missing directories.

## Patterns from hal/consolidate-progress-files (2026-02-05)

- progress.txt is the single source of truth for both manual (`hal run`) and auto (`hal auto`) workflows. The separate auto-progress.txt file was consolidated.
- When removing a constant from internal/template/template.go, also update all usages in tests and other packages (archive, compound) to maintain compilation.
- Migration logic for legacy files (like auto-progress.txt) uses append-with-separator strategy: if destination has content, append with "---" divider; if empty/default, replace entirely.
- The `hal cleanup` command removes orphaned files via an `orphanedFiles` slice — add files here when deprecating state files, and always provide --dry-run flag for preview.
- hal review gathers context from JSON PRDs (prd.json, auto-prd.json) in addition to markdown PRDs for accurate task completion reporting. The JSON files contain the `passes` field showing which stories are complete.
- Use template constants (template.HalDir, template.ProgressFile, etc.) for all .hal/ paths instead of hardcoded strings to ensure consistency across the codebase.

## Patterns from hal/consolidate-progress-files (2026-02-05)

- Use template.HalDir and template.ProgressFile for any .hal path construction (avoid hardcoded ".hal" or filenames) to keep CLI and review tooling consistent.
- When migrating legacy .hal state files, merge content into the new target with a separator if both have content, then delete the legacy file after a successful merge.
- Treat orphaned legacy files via a dedicated cleanup command that supports --dry-run and uses a centralized orphanedFiles slice for extensibility.
- Review context should load both markdown PRDs and JSON PRDs (prd.json, auto-prd.json) because JSON includes pass/fail completion status.

## Patterns from hal/refresh-templates (2026-02-10)

- runInit is invoked as runInit(nil, nil) in tests, so Cobra flag reads must be guarded with if cmd != nil before calling cmd.Flags().GetBool/GetString.
- Use template.DefaultFiles() as the single source for core .hal template refresh targets instead of duplicating a filename list.
- For cmd package behavior with side effects, extract a run<Feature> helper that accepts io.Writer (like refreshTemplates) and keep Cobra handlers focused on flag binding and delegation.
- Template text migrations belong in migrateTemplates via replaceFileContent, normalizing multiple legacy prompt variants into one canonical guidance line.
- In cmd tests, reuse shared helpers from archive_test.go (writeFile/writePRD) and validate timestamped backup artifacts with filepath.Glob(filename+".*.bak").

## Patterns from hal/sandbox-implementation (2026-02-14)

- Extract command behavior into `run<Command>` helpers (accepting `dir`, `io.Reader`/`io.Writer`, and injected function types), and keep Cobra `RunE` focused on flags and delegation.
- Use `compound.LoadDaytonaConfig(dir)` and `compound.SaveConfig(dir, cfg)` with project-root `dir` (not `.hal/`), relying on map-based YAML round-trip to preserve unrelated config sections.
- Enforce auth via `sandbox.EnsureAuth(apiKey, setupFn, reloadFn)` callbacks from `cmd` to `internal/sandbox` to avoid circular dependencies while still supporting interactive setup.
- Treat `.hal/sandbox.json` as authoritative runtime state through `sandbox.SaveState/LoadState/RemoveState` and template constants; remove state only after successful remote delete.
- For PTY shell integration, use one read path (`PtyHandle.Read` or `DataChan`) and pair it with OS-specific resize handlers (`shell_resize_unix.go`/`shell_resize_windows.go`).

## Patterns from hal/report-review-split (2026-02-15)

- Review-loop output schema should stay centralized in `internal/compound/types.go` (`ReviewLoopResult`, `ReviewLoopTotals`, `ReviewLoopIteration`) so command output and report artifacts share one contract.
- For contract tests, assert both JSON key names and marshal/unmarshal round-trip to prevent accidental JSON tag regressions.
- For command splits, keep legacy behavior in its own command and extract execution into a `run<Command>WithDeps` helper so tests can stub engine/review dependencies without spawning real CLIs.
- Preserve legacy CLI output via a focused renderer helper (e.g., success + summary/recommendations) so renamed commands keep user-facing behavior stable during migrations.
- For `hal review` argument work, keep parsing/validation in a dedicated helper (`parseReviewRequest`) and inject branch checks via deps (`runReviewWithDeps`) so tests can verify invalid iteration and missing-branch errors without invoking real git refs.
- For review-loop iterations, keep git/codex interactions behind injectable deps (`runCodexReviewLoopWithDeps`, `reviewIterationDeps`) so tests can verify diff usage, prompt schema, and parsed counts without invoking real CLIs.
- Review-loop iteration execution now uses a two-step Codex contract: first emit strict review JSON (`issues[]` with id/title/severity/file/line/rationale/suggestedFix), then send a fixed follow-up prompt for validation+autofix JSON (`issues[]` with id/valid/reason/fixed`) and derive valid/invalid/fixes counts from issue IDs.
- Use `git merge-base <base> HEAD` + `git diff <merge-base>` for iteration diff context so uncommitted fixes from the previous iteration remain visible in the next review pass.
- Keep loop orchestration separate from per-iteration execution (`runCodexReviewLoop` vs `runReviewIteration`) so stop conditions can evolve without touching prompt/diff parsing internals.
- `ReviewLoopResult.StopReason` currently uses `no_valid_issues` (early stop when an iteration reports `ValidIssues == 0`) and `max_iterations` (requested cap reached); tests should cover both paths and verify `CompletedIterations` exactly matches executed iterations.
- Review-loop JSON artifacts are written via `compound.WriteReviewLoopJSONReport`; keep timestamp-dependent tests deterministic by using the internal `writeReviewLoopJSONReport(..., nowFn)` helper instead of stubbing wall-clock time globally.
- Keep review-loop human output in two steps: generate markdown from `compound.ReviewLoopMarkdown` (also persisted via `WriteReviewLoopMarkdownReport`) and render it at the command layer with Glamour so file artifacts and terminal output stay in sync.
- For command-split migrations, keep Cobra help text and README workflow/command-table docs in sync, and add command tests that assert required help phrases/examples so docs don’t drift from CLI behavior.

## Patterns from hal/cli-docgen-metadata-hardening (2026-02-21)

- Use `cmd.Root()` as the public accessor to the runtime Cobra command tree for tooling/tests instead of relying on package-private `rootCmd`.
- Keep CLI startup unchanged (`main.go` -> `cmd.Execute()`), and lock the accessor contract with a focused `cmd/root_test.go` test.
- Implement CLI documentation generation as a separate tool (`internal/tools/docgen`) with a testable `run(args, root)` helper so flag parsing/validation can be unit-tested without executing the real command tree.
- Set `root.DisableAutoGenTag = true` before invoking Cobra doc generators (`GenMarkdownTree`, `GenManTree`, `GenReSTTree`) to keep generated artifacts deterministic.
- Restrict `-frontmatter` to markdown output and fail fast for invalid format combinations so docgen behavior is explicit and predictable.
- Make `docs-cli` generate into a temporary directory (e.g., `docs/cli.tmp`) and replace `docs/cli` only after successful generation so stale command pages are removed safely.
- For baseline docs-artifact stories, verify determinism by running `make docs-cli` twice and ensuring there is no `docs/cli` diff before marking the story complete.
- Implement `docs-check` as clean temp generation + recursive diff against `docs/cli`; this catches both modified content and stale leftover doc files.
- In CI, run `make docs-check` with `make vet` and `make test` so docs drift and metadata regressions fail in pull requests.
- Keep command-metadata scope checks in a shared test helper that excludes hidden/deprecated commands, autogenerated `help [command]`, and `IsAdditionalHelpTopicCommand()` nodes while still including parent commands that have in-scope child pages.
- Keep user-facing command examples in Cobra `Example` fields (not just prose in `Long`) and lock required metadata (`Use`, `Short`, `Long`, `Example`) with focused table-driven command tests.
- Add a global recursive metadata contract test (`cmd/docs_metadata_test.go`) that walks all in-scope commands from `cmd.Root()` and reports command path + missing fields for fast triage.
- For family-level metadata contracts, recurse through in-scope descendants under each top-level command family (for example `archive`) and assert each command's `Example` includes its command path.
- When a command family may not exist in every branch (for example `sandbox`), make that family optional in focused tests while keeping required families strict.
- Keep a dedicated README `CLI Reference` section linking `docs/cli/` and `docs/cli/hal.md` so generated command docs are easy to discover.

## Patterns from hal/convert-explicit-archive-force (2026-02-23)

- `cmd/convert.go` uses a `runConvertWithDeps` helper + `convertDeps` struct so tests can assert flag wiring (`--archive`, `--force`) without invoking real engines.
- Conversion safety controls are passed through `prd.ConvertOptions`; when `Archive` is true and output is not canonical `.hal/prd.json`, return the exact guard error: `--archive is only supported when output is .hal/prd.json`.
- Markdown source resolution for convert should stay deterministic in `internal/prd/convert.go`: newest `prd-*.md` by mtime wins, and equal mtimes must use lexicographic filename ascending as tie-break.
- Missing auto-discovered markdown should return an actionable error (`run \`hal plan\` or pass an explicit markdown path`), and `ConvertWithEngine` should emit `Using source: <path>` via the display writer before prompting.
- Convert archiving is strictly opt-in: only run `archive.HasFeatureStateWithOptions` / `archive.CreateWithOptions` when `ConvertOptions.Archive` is true; default convert runs must not create archive entries.
- When archiving during convert, pass `archive.CreateOptions{ExcludePaths: []string{mdSource}}` so the markdown source being converted is not moved into the archive.
- Canonical convert branch protection belongs in `internal/prd/convert.go`: compare existing `.hal/prd.json` `branchName` with converted output and block mismatches only when both are non-empty and neither `--archive` nor `--force` is set; keep the guard message exact (`branch changed from <old> to <new>; run 'hal convert --archive' or 'hal archive' first, or use --force`).
- `runConvertWithDeps` writes display output through `os.Stdout`; command tests that need to assert streamed lines like `Using source: ...` should capture stdout (e.g., via `os.Pipe`) around the helper invocation.
- When convert behavior changes, keep `cmd/convert.go` long help and README convert docs aligned, and add/update command help tests for required safety/source phrases to prevent documentation drift.

## Patterns from autoresearch/remove-tool-references (2026-03-18)

- Browser verification is tool-agnostic: `template.BrowserVerificationCriterion` uses generic text ("Verify in browser (skip if no dev server running, no browser tools available, or 3 attempts fail)") with no tool-specific names.
- There is no `BrowserVerificationSkillName` constant — agents discover available browser tools at runtime via their skills directory.
- The `hal-pinchtab` skill was removed from embedded skills. It should not be re-added. If a user needs pinchtab support, they install the skill locally.
- Migration code in `migrateTemplates` uses regex section replacement (not exact string matching) to normalize legacy prompt sections. The `devBrowserMigration` regex matches any "Verify in browser using [tool-name]" pattern generically.
- When removing tool-specific references, keep migration code that handles user `.hal/` files from older versions — users may have prompts with old tool names that need migrating.
- Test tool-specific migration using generic tool names (e.g., "legacy-tool") rather than real tool names to avoid re-introducing references.

## Patterns from autoresearch/hal-ux-machine-readability (2026-03-18)

- New machine-readable surfaces (`--json` flag) must ship with: contract doc in `docs/contracts/`, example JSON payloads, field-locking tests in `cmd/machine_contracts_test.go`, and doc-code sync tests in `cmd/contracts_doc_test.go`.
- Workflow state classification lives in `internal/status` — a pure filesystem package with no engine or config dependencies. The `cmd/status.go` wrapper adds engine from config.
- Health/readiness checks live in `internal/doctor` — each check has `scope` (repo/engine_local/engine_global/migration) and `applicability` (required/optional/not_applicable) fields. The check order is locked by `TestRun_CheckCount`.
- The Codex linker uses `codexHome()` which prefers `$HOME` over `os.UserHomeDir()` so tests can isolate global link operations via `t.Setenv("HOME", tmpDir)`. All init tests must use `t.Setenv("HOME", dir)`.
- Tests that walk the shared global `Root()` Cobra command tree must NOT use `t.Parallel()` (race condition on Cobra command state).
- The `hal continue` command is the single entry point for "what to do next" — it combines status + doctor and shows doctor issues as blockers before workflow actions.
- The `hal repair` command auto-applies safe remediations from doctor results. To add a new remediation, add `Remediation: &Remediation{Command: "...", Safe: true}` to the check and register the command in `executeRepairCommand`.
- The `hal links` command group (status/refresh/clean) manages engine skill links separately from `hal init`. Use `hal links refresh codex` for targeted Codex link updates.
- Doctor checks for link health should suggest `hal links refresh` or `hal links clean` instead of `hal init` — more targeted remediation.

## Patterns from hal/multi-sandbox-management (2026-03-21)

- Global sandbox path resolution in `internal/sandbox/global.go` must follow this exact precedence: `$HAL_CONFIG_HOME` → `$XDG_CONFIG_HOME/hal` → `$HOME/.config/hal`.
- Tests for global sandbox paths should isolate with `t.Setenv("HAL_CONFIG_HOME", tmpDir)`; for fallback behavior, also set `HOME` explicitly so results are deterministic.
- `EnsureGlobalDir()` should create both the global root and `sandboxes/` with `os.MkdirAll(..., 0700)` and remain safe to call repeatedly.
- Global sandbox registry entries live at `SandboxesDir()/"<name>.json"`; writes should stay atomic (`.tmp` + `os.Rename`) with `0600` file mode.
- Registry collision semantics are strict: `SaveInstance` must return the exact error `sandbox "<name>" already exists`, while `ForceWriteInstance` is the explicit overwrite path for `--force` flows.
- `ListInstances` should treat a missing `sandboxes/` directory as empty state and return instances sorted by `Name`; missing `LoadInstance`/`RemoveInstance` errors should wrap `fs.ErrNotExist` for `errors.Is` checks.

## Patterns from hal/sandbox-uuidv7-generation (2026-03-21)

- `internal/sandbox/uuid.go` uses an injectable `UUIDSource` (`clock func() time.Time`, `rand io.Reader`) so UUID generation stays deterministic in tests while defaulting to `crypto/rand.Reader` in production.
- UUIDv7 monotonic behavior is maintained by reseeding randomness only when millisecond timestamps advance; otherwise increment the stored random bits (with timestamp carry on overflow) before formatting.
- UUID tests should assert canonical 8-4-4-4-12 format and bit-level contracts (version nibble `0x7`, variant top bits `0b10`) plus a reader-failure error path.

## Patterns from hal/sandbox-name-validation (2026-03-21)

- Keep sandbox-name validation centralized in `internal/sandbox/name.go` (`ValidateName`) with the exact user-facing error strings: `must be 1-59 chars`, `must be lowercase alphanumeric and hyphens`, `must not start or end with hyphen`, and `must not contain consecutive hyphens`.
- `SandboxNameFromBranch` should always produce a valid default name by lowercasing, replacing non `[a-z0-9]` runs with a single hyphen, trimming edge hyphens, and capping to 59 chars (falling back to `sandbox` if sanitization is empty).
- `BatchNames(base, count)` should compute suffix width as `max(2, digits(count))`, reject `count < 1`, preflight `len(base)+1+width <= 59`, and validate each generated `{base}-NN...` value via `ValidateName`.
- Name validation tests are table-driven and include boundary cases (59/60 chars) plus structural invalid cases (uppercase, special chars, edge/consecutive hyphens); keep this matrix updated when name rules change.

## Patterns from hal/sandbox-state-type (2026-03-21)

- Keep sandbox lifecycle status values centralized in `internal/sandbox/types.go` constants (`StatusRunning`, `StatusStopped`, `StatusUnknown`) instead of duplicating string literals across commands/providers.
- `SandboxState` JSON tags are camelCase with selective `omitempty`; preserve this contract with focused marshal/unmarshal key assertions in `internal/sandbox/types_test.go` when adding or renaming fields.
