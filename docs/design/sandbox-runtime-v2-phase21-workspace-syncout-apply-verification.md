# Sandbox Runtime v2 Phase 21 Workspace Sync-Out And Apply Verification

Phase 21 covers explicit non-factory workspace sync-out and safe host apply for
`hal run --sandbox` and `hal auto --sandbox`. It adds command-agnostic
sync-out contracts, recovery-first command wiring, explicit opt-in CLI flags,
safe apply validation, handoff output, redaction coverage, and additive
manifest and JSON metadata while preserving default no-mutation behavior.

## Scope

Workspace sync-out metadata belongs in `internal/sandboxworkspace` as
redaction-safe data contracts and in `internal/sandboxexecution` as a pure
adapter from durable execution artifact metadata. Command wiring in `cmd`
enables sync-out only for explicit local non-factory sandbox requests:

- `hal run --sandbox --sandbox-sync-out`
- `hal run --sandbox --sandbox-apply`
- `hal auto --sandbox --sandbox-sync-out`
- `hal auto --sandbox --sandbox-apply`
- `hal sandbox apply EXECUTION_ID`

The run/auto `--sandbox-apply` flags apply artifacts from the new execution
they launch. They do not select a prior named sandbox workspace or stored run.
Sandbox JSON with explicit sync-out metadata includes `sandboxExecutionId` so
operators can select the exact durable result later.

`hal sandbox apply EXECUTION_ID` is the apply-only path for a prior completed
execution. It must not resolve, provision, start, materialize, or execute a
sandbox. It requires a succeeded manifest, a collected `.hal/prd.json` with
every story passing, an eligible committed patch or bundle, a stored project
and branch matching the current host worktree, and a host worktree that passes
the existing lock, cleanliness, and Git dry-run checks. A commit-valued stored
sync ref must also match the current host HEAD.
Already-applied executions are rejected to prevent accidental double apply.
Tracked uncommitted output, including PRD completion metadata, remains a
separate manual-review handoff after a committed patch is applied.

Default `hal run --sandbox` and `hal auto --sandbox` must preserve default
no-mutation behavior. They must not invoke sync-out apply, host dry-run apply,
host Git mutation, or host worktree lock acquisition unless `--sandbox-sync-out`
or `--sandbox-apply` is selected. Default manifests must omit `syncOut` and
`syncOutApply` fields.

Recovery-before-apply is required. Non-factory sandbox commands must persist
durable core, generated, output, and recovery artifact metadata before host
dry-run or mutation can run, so failed or skipped apply still leaves durable
handoff metadata.

Safe host apply accepts only explicitly eligible committed patch or bundle
artifacts selected by command code. Untracked archives, raw artifact
directories, recovery payloads, warning-only outputs, uncommitted diffs, and
otherwise ineligible artifacts are handoff-only.

Explicit sync-out collection generates committed and tracked-uncommitted
artifacts separately. The committed patch contains commits after the prepared
workspace baseline. The uncommitted diff contains staged and unstaged tracked
changes, is omitted when empty, and always requires manual review rather than
automatic host apply. Production sync-out also generates an untracked tar
archive and quoted file list from `git ls-files --others --exclude-standard`.
Ignored files and Hal's generated sync-out payloads are excluded, empty
untracked output is omitted, and both artifacts remain handoff-only rather than
eligible for automatic host apply.

## Focused Verification Commands

Run sync-out workspace contract and import-boundary checks:

```sh
go test -timeout=120s ./internal/sandboxworkspace -run 'TestWorkspaceSyncOutContractShape|TestSyncOutImportBoundaries|TestSyncOutForbiddenImportListCoversRequiredBoundaries|TestSyncOutImportBoundaryAllowsStableContractsOnly'
```

Run sync-out summary and execution import-boundary checks:

```sh
go test -timeout=120s ./internal/sandboxexecution -run 'TestBuildSyncOutSummaryFromArtifacts|TestBuildSyncOutSummaryRedaction|TestCollectUncommittedSyncOutArtifactBestEffort|TestUncommittedSyncOutDiffGenerationScript|TestCollectUntrackedSyncOutArtifactsBestEffort|TestUntrackedSyncOutArtifactsGenerationScript|TestPackageImportBoundaries'
```

Run safe apply dry-run, dirty worktree, lock, and redaction checks:

```sh
go test -timeout=120s ./internal/sandboxworkspace -run 'TestSafeApply(RunsDryRunBeforePatchMutation|DryRunValidatesEligibleBundle|DryRunRejectsIncompatiblePatch|RefusesDirtyWorktreeByDefault|UsesWorkspaceLock|LockFailurePreventsApply|Redaction)'
```

Run command default no-mutation, explicit flag scope, recovery-before-apply,
eligible artifact selection, handoff, additive JSON, and redaction checks:

```sh
go test -timeout=120s ./cmd -run 'TestSandboxRunAutoDefaultDoesNotMutateHostWorktree|TestSandboxSyncOutApplyFlagsAreExplicitAndScoped|TestSandboxApplyPersistsRecoveryBeforeHostMutation|TestSandboxApplyOnlyUsesEligibleSyncOutArtifacts|TestSandboxSyncOutHandoffInstructions|TestSandboxSyncOutManifestJSONAdditiveContract|TestSandboxSyncOutApplyRedaction|TestRunSandboxApplyExecution|TestSandboxAugmentedJSONExposesStoredExecutionID'
```

Run additive contract documentation and example checks:

```sh
go test -timeout=120s ./cmd -run 'TestContractDocsIncludeAutoV2Fields|TestContractDocsIncludeAutoV2Examples|TestMachineContractFields_AutoV2Examples|TestSandboxSyncOutManifestJSONAdditiveContract'
```

Run the Phase 21 documentation guard:

```sh
go test -timeout=120s ./cmd -run 'TestPhase21VerificationDocsCurrent'
```

Run doc/build/typecheck verification:

```sh
make docs-check
git diff --check
go test -timeout=300s ./...
go vet ./...
make build
make lint
```

Run `make docs-cli` before `make docs-check` when command metadata, examples,
or generated CLI surfaces change.

These commands cover the command-agnostic sync-out contract, summary
construction from durable artifacts, host apply dry-run validation, dirty
worktree refusal, workspace lock acquisition, default no-mutation behavior,
recovery-before-apply ordering, explicit non-factory run/auto flags, eligible
artifact selection, handoff guidance, additive manifest/JSON output, redaction
safety, generated documentation drift, the full Go package graph, vet, build,
and lint when the linter is installed.

## Fake-Only Non-Goals

Phase 21 verification is fake-only. Tests should use temporary repositories,
temporary execution stores, fake runtime drivers, fake providers, fake locks,
fake Git adapters, fake clocks, and temporary `HAL_CONFIG_HOME` values.

Phase 21 verification has no real worker daemon, Podman, Docker, cloud,
network, microVM, scheduler daemon, policy proxy, or secret broker requirement.

Do not start a real worker daemon, run `hal sandboxd`, bind real worker
sockets, contact remote worker hosts, run Podman or Docker workflows, pull
images, access cloud APIs, open network connections, execute microVM runtimes,
start a scheduler daemon, configure a policy proxy, configure a secret broker,
or require provider credentials as part of Phase 21 story verification.

## Review Notes

`internal/sandboxworkspace` sync-out files must stay data-only and
command-agnostic. Production `sync_out*.go` files may use only standard library
imports plus the root `internal/sandbox` and `internal/sandboxruntime` data
contracts. They must not import Cobra, `cmd`, factory, engine, loop, PRD,
compound, worker clients, concrete provider adapters, concrete runtime
adapters, or network-only packages.

Command code owns local host apply intent. `--sandbox-sync-out` records durable
sync-out and handoff metadata without mutating the host, while `--sandbox-apply`
is the explicit opt-in path for automatic eligible host apply from the new
run/auto execution. Use `hal sandbox apply EXECUTION_ID` to apply a prior
completed execution without launching another sandbox run. Keep the flags
scoped to local non-factory run and auto sandbox commands and omit them from
remote command builders and factory commands.

Redaction belongs at shared contract boundaries. Persisted manifests, human
handoff output, JSON output, warnings, and errors should use safe artifact IDs,
display names, relative display paths, store-relative paths, warning codes, and
apply eligibility reasons. They must not include raw worker endpoints, Unix
socket paths, host temp paths, remote temp paths, credentials, provider secrets,
or secret-bearing repository URLs.
