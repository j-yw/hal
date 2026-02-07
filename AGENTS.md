# Repository Guidelines

## Project Structure & Module Organization
- `cmd/`: Cobra CLI commands and flags.
- `internal/`: core packages (`archive/`, `engine/`, `loop/`, `prd/`, `skills/`, `template/`).
- `main.go`: CLI entrypoint wiring.
- `agent-os/`: product/roadmap documentation.
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

## Patterns from main (2026-02-07)

- Drive HAL progress UI from parsed engine lifecycle events (thinking/tool/completion) rather than raw output text heuristics.
- Spinner behavior contract is strict: keep it active across loading-text to tool-activity transitions, include HAL-eye branding, and preserve completed thinking lines as quoted output.
- Engine install commands are coupled with symlink creation and matching .gitignore exceptions; tests should assert symlink targets directly.
- Standards injection is implemented as loader + prompt placeholder + CLI wiring, and user-facing paths should consistently use .hal/standards.
- Release workflow conventions are repository-specific: use git-flow-style release/hotfix branches and v-prefixed tags, then keep docs aligned to that process.

## Patterns from compound/spinner-state-machine-refactor (2026-02-07)

- In `internal/engine/display.go`, all logical spinner lifecycle changes should go through `d.fsm.GoTo(...)`/`d.fsm.Reset()`; do not reintroduce direct `isThinking`, `thinkingStart`, or `lastTool` fields on `Display`.
- Canonical terminal-event teardown in this codebase is `GoTo(StateCompletion|StateError, ...)` followed by `Reset()`; keep this pattern for `EventThinking end`, `EventResult`, and `EventError` handlers.
- Tool dedup is keyed as `e.Tool + e.Detail` (no inserted space); apply presentation spacing only when building display text, not in the dedup key.
- Display lifecycle tests should use `bytes.Buffer` (non-TTY) and call `StopSpinner()` between events when asserting FSM state to avoid goroutine timing contamination.
- `Display` keeps split locking (`mu` for output/FSM access, `spinMu` for spinner goroutine control); new state logic should remain under `mu` and not bypass this discipline.

## Patterns from compound/tty-spinner-lifecycle-integration-tests (2026-02-07)

- TTY lifecycle tests for `internal/engine/display.go` should live in `internal/engine/display_tty_integration_test.go` with both `//go:build integration` and `// +build integration` tags, use `package engine`, and document PTY determinism constraints at the top of the file.
- Use a PTY harness (`github.com/creack/pty`): open master/slave, build `Display` with the slave writer (so `isTTY` is true), and capture terminal output by reading the master in a dedicated goroutine.
- PTY harness cleanup must be strict and idempotent: call `Display.StopSpinner()` before closing descriptors, treat `io.EOF`/`os.ErrClosed`/`syscall.EIO` as expected read-termination errors, and wait on a bounded `readDone` channel in `t.Cleanup`.
- For deterministic assertions, poll with explicit timeout/interval parameters (e.g., `WaitForOutputContains`) and assert against normalized PTY output that strips ANSI CSI sequences and converts `\r` redraws to `\n`; timeout errors should include latest normalized and raw output snapshots.
- Lifecycle integration tests should drive events through reusable helpers (`emitCanonicalThinkingEvents`, `emitCanonicalToolEvent`, terminal emitters) plus a phase driver that captures per-phase output snapshots after checkpoint waits, so later assertions can compare thinking/tool/terminal boundaries without re-implementing event sequencing.
- For tool-phase spinner assertions, wait on spinner-inclusive markers like `[●] Read README.md` (not only `Read README.md`) so tests confirm animated PTY spinner frames rendered in addition to immutable tool history lines.
- For continuity assertions across spinner-active transitions (thinking→tool, text→tool), capture `Display` spinner runtime state under `spinMu` and compare `spinDone` channel identity before/after; unchanged channel proves the spinner goroutine was not restarted.
- For error-path lifecycle assertions, validate output ordering on normalized terminal snapshots (for example `strings.Index` on `> Read ...` before `[!!]`) to prove tool history is emitted before terminal error output.
- For terminal teardown assertions in PTY tests, verify both `d.fsm.State() == StateIdle` and `!d.isThinkingSpinnerActive()` after completion/error markers to ensure FSM reset and spinner shutdown are both enforced.
