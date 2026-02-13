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
- Cloud lifecycle integration suite: `make test-integration-cloud-lifecycle` (runs `go test -tags=integration -v -run '^TestCloudLifecycle' ./cmd`).

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

## Patterns from hal/cloud-db-runtime-wiring (2026-02-11)

- Register production database/sql adapters only via blank imports in internal/cloud/deploy/drivers.go; OpenStore depends on these init-time side effects and command packages should not duplicate driver imports.
- Use deploy.DefaultStoreFactory as the command composition root by wiring each cloud/auth store factory variable in cmd init() with an if-nil guard so tests can still override factories.
- For code that uses sync.Once, create isolated factories with newStoreFactory(func() Config { return LoadConfig(customGetenv) }) in tests to avoid package-level once-state leakage.
- In cloud deploy CLI paths, call godotenv.Load() before LoadConfig(getenv); ignore os.ErrNotExist and warn (non-fatal) on other dotenv errors.
- Construct Turso DSNs with parse-modify-stringify (url.Parse -> Query().Set("authToken") -> String()) and validate in tests by reparsing URL/query instead of raw string matching.

## Patterns from hal/unified-cloud-ux (2026-02-12)

- Use `RegisterCloudFlags(cmd)` and `ValidateCloudFlags(flags)` on every cloud-capable workflow command to keep flag semantics and `--detach/--wait` conflict handling consistent.
- Always resolve cloud runtime settings through `config.Resolve(ResolveInput{...})` with the fixed precedence chain: CLI > process env > .env (non-overriding) > `.hal/cloud.yaml` > inferred defaults > hard defaults.
- Keep Cobra handlers thin and delegate to testable helpers (`run<Command>` functions) that accept `io.Writer` plus injectable store/config factories to avoid hard-coupled network/database behavior in tests.
- Model cloud enums as typed strings with a validation map and `IsValid()` (e.g., workflow kind, artifact group), and centralize defaults in constructors like `NewArtifactMetadata(kind)`.
- Route all cloud/auth output through redaction-aware chokepoints (`cloud.Redact()` wrappers) and keep JSON contracts stable with camelCase field names.

## Patterns from compound/cloud-lifecycle-e2e-integration-tests (2026-02-12)

- Keep cloud lifecycle suite scaffolding in a dedicated `//go:build integration` file under `cmd/` so integration metadata and shared fixtures are excluded from default unit-test runs.
- Define the lifecycle command flow once as shared table data (`setup`, `run`, `auto`, `review`, `status`, `logs`, `pull`, `cancel`) and reuse it across scenario tests to prevent command-surface drift.
- Use explicit placeholders like `<run-id>` in shared command args so scenario helpers can substitute IDs consistently across status/logs/pull/cancel assertions.
- Centralize lifecycle checkpoint fixtures (`setup`/`run`/`status`/`logs`/`pull`/`cancel`) in one integration helper table with `RequiresRunID`, `SupportsJSON`, and `RequiredJSONKeys` so scenario tests assert one contract source of truth.
- Keep lifecycle JSON contract keys as shared camelCase constants (e.g., `runId`, `workflowKind`, `filesRestored`) and validate key format in tests to prevent snake_case drift.
- Define workflow-kind expectations for `run`, `auto`, and `review` in shared fixtures so scenario tests can assert persisted `workflowKind` consistently.
- Integration harnesses that override package-level cloud factories (`runCloudStoreFactory`, `autoCloudStoreFactory`, etc.) should use `snapshotCloudLifecycleHarnessFactories` + `restoreCloudLifecycleHarnessFactories` and register teardown via `t.Cleanup` to avoid cross-test global state leakage.
- For lifecycle harness stores, extend `cloudMockStore` with overrides for `EnqueueRun`, `PutSnapshot`, and `UpdateRunSnapshotRefs` so submitted runs/snapshots are queryable by downstream `status`/`pull` commands without external services.
- For worker lifecycle scenarios, also override `TransitionRun` and `TransitionAttempt` in the harness store to both mutate persisted records and append assertion-friendly tracking slices (`RunTransitions`, `AttemptTerminalizations`, `AttemptTerminalizationCount`).
- Expose snapshot refs via a harness helper (`SnapshotRefs(runID)`) backed by a dedicated map, and return cloned pointers so tests can safely mutate local copies without corrupting stored assertions.
- In lifecycle harness stores, override `SetCancelIntent` to transition non-terminal runs to `canceled` immediately (while setting `cancel_requested`) so `cancel -> status` scenarios are deterministic without a live worker loop.
- Lifecycle logs scenarios should seed events via `h.SeedTimelineEvents(t, runID, ...)` after submission because `SubmitWithBundle` persists runs/snapshots but does not emit timeline events on its own.
- Lifecycle command runners in integration tests should dispatch directly to testable `run<Command>` helpers (instead of Cobra root execution), substitute `<run-id>` placeholders, and capture output with `io.MultiWriter` so assertions can use both injected writers and returned output text.
- For lifecycle `--json` assertions, decode output through shared helpers (`decodeLifecycleJSONOutput` / `mustDecodeLifecycleJSONOutput`) and normalize only explicit nondeterministic keys (for example run IDs and timestamps) via `normalizeLifecycleJSONPayload` so stable fields remain assertion-visible.
- Baseline lifecycle scenarios should run `setup -> run --cloud -> status` in one harness flow, assert both human and JSON outputs at run/status checkpoints, and confirm persistence by reading the run back from harness store (`GetRun`).
- For shared lifecycle JSON key assertions during output-contract migrations, check canonical camelCase keys with explicit snake_case fallback aliases rather than hardcoding one casing per scenario.
- Pull lifecycle scenarios should derive `--artifacts` from `cloud.WorkflowArtifactGroups(run.WorkflowKind)` and delete target files before `cloud pull` so tests verify actual restoration instead of pre-existing local files.
- For lifecycle security coverage, seed secret-bearing values (for example in run IDs or log payloads) and assert redaction through shared helpers (`assertLifecycleOutputRedacted`, `assertLifecycleJSONOutputRedacted`) in both human and `--json` command paths.
- Keep auth JSON contract checks explicit in integration tests by asserting required camelCase keys (`profileId`, `validatedAt`, `revokedAt`) and rejecting snake_case aliases for commands that already migrated.
- Keep the lifecycle integration invocation centralized in `make test-integration-cloud-lifecycle` and have CI pull-request checks call that target directly to prevent command drift.
- For worker lifecycle integration suites, use a shared `runWorkerLifecycleAdapterMatrix` helper with adapter fixtures (`postgres`, `turso`) and `adapter/scenario` subtest names; each case should create its own `setupCloudLifecycleIntegrationHarness(t)` and register teardown via `t.Cleanup` to avoid cross-adapter global factory leakage.

## Patterns from hal/cloud-worker-orchestration-pipeline (2026-02-13)

- Keep claim semantics adapter-first: Postgres/Turso `ClaimRun` must atomically set `status='claimed'` and `attempt_count=attempt_count+1`, and ClaimService must use returned `Run.AttemptCount` directly (no additional increment).
- Construct worker runtime via `WorkerPipelineConfig` -> `NewWorkerPipeline`; all core dependencies (`Store`, `Runner`, `WorkerID`, `Claim`, `Checkpoint`, `Heartbeat`, `Cancel`, `Execution`, `Snapshot`) are required and validated up front.
- Cleanup/failure handlers should always use `context.WithTimeout(context.Background(), cleanupTimeout)` (not parent ctx) and call `releaseAuthLockBestEffort` so shutdown cancellation and already-released locks do not break terminalization.
- Snapshot identity must use record-based hashing (`ComputeSandboxBundleHash(records)` -> `ComputeBundleHash`) while bundle payloads keep `path\x00size\x00content` + gzip framing for pull compatibility.
- For `cmd` worker tests, override package-level factories via `injectWorkerTestFactories(t)` and restore in cleanup; no-work polling is modeled by mock `ClaimRun` returning `ErrNotFound`.
