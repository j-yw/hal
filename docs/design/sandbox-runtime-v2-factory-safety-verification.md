# Factory verification and recovery safety

This slice owns the command boundary in `cmd/factory.go`. It does not change
worker protocols, runtime drivers, publication authority, or strict defaults.

## R2: remote verification

Parseable stdout is not proof that a remote command completed. Verification
artifacts and success metadata must not be collected or persisted until both
execution and the `verify-v1` result have been validated.

- Legacy provider execution retains its existing command. A nil execution
  error means exit 0; an actual typed exit 4 is accepted only with `status=fail`.
  A single wrapped typed process exit remains valid; joined errors are rejected
  because another arm may be a transport or write failure. Unknown errors,
  caller cancellation, other exits, and contradictory results fail.
- Worker execution cannot classify every `driver_failed` error as an ordinary
  failed check: the adapter also uses that error for other failures. A small
  command-local shell wrapper therefore waits for Hal, appends exactly one
  terminal `HAL_FACTORY_VERIFY_EXIT=<code>` line, and succeeds only after that
  write. It creates no status file and changes no public or durable schema.
- The worker route requires a non-nil outer execution result, exit 0, no
  execution error, at most 1 MiB of untruncated output, one JSON object and one
  terminal footer. The reported Hal exit must be 0 for pass/warn or 4 for fail.
  Missing, interrupted, duplicated, early or trailing-garbage footers fail.
- The shared parser checks the version, status, known field types and aggregate
  check facts. Top-level, summary and check objects reject duplicate/case-alias
  keys; counts and required/status facts must be present and correctly typed.
  Empty check arrays remain valid, but null arrays do not. Unknown additive
  JSON fields remain compatible. Errors contain
  fixed safe text while preserving original error identity where available.
- A legitimate failed verification remains a valid result: existing required
  versus advisory factory policy decides whether it blocks the run.

R2 focused tests use fake worker/provider execution plus a local shell fixture
with configured required checks. No network, credentials, container, publication,
or privileged host operation is needed.

## R1: recovery

The same apply helper serves explicit recovery and host publication (including
automatic fallback). Its safety checks must hold for every caller; this does not
add publication authority. A JSON failure remains one `factory-recover-v1`
document, with `ok=false`, safe text and a nonzero returned error. Rendering
failure joins the original error rather than converting recovery into success.

Before host mutation, recovery checks canonical branch names (not checkout
expressions), acquires the existing `hal-workspace-locks` manager using the
`workspace:<canonical project root>` key, and rejects staged, unstaged or
untracked work without listing paths. There is no stash/reset/force behavior.
The same lock stays owned through host apply and is released on every outcome.
The shared manager canonicalizes existing absolute `workspace:` paths so direct,
SafeApply and factory callers using symlinked parents contend on one identity.
Opaque/custom keys and absent paths retain their previous key behavior. This
does not coordinate older binaries or adversarial directory renames/uncooperative
Git processes; detected concurrent changes require handoff, not rollback.

Exactly one complete bundle artifact must resolve inside its run's artifact
directory. Recovery retains each opened directory, checks per-component and
leaf `SameFile` identity and non-symlink bindings before/after the copy, and
opens the leaf without following symlinks or blocking on a FIFO on Unix.
It copies the regular file into a private, context-aware, bounded snapshot
(512 MiB maximum).
All Git verification and consumption use that snapshot, not a reopened stored
path. No new durable digest or schema is claimed. Temporary state is removed.

A verified bundle must advertise one unambiguous `HEAD` commit. Analysis imports
it only into a temporary bare shared clone of the already-local destination;
local objects may be read, but no remote is contacted. Rejected history never
changes host objects, refs, the index or worktree.

- Worker `git_bundle` input requires the recorded immutable
  `Sandbox.Workspace.SyncRef`, already present locally and ancestral to the
  advertised output. A moving branch cannot replace missing recorded evidence.
- Legacy records without an input pin may use the already-local canonical
  `BaseBranch` tip as a conservative compatibility-only ancestry anchor. This
  is not a claim about the original input commit. A missing or divergent local
  base requires manual handoff; recovery does not fetch missing private history.
  Legacy symbolic `SyncRef` values such as `origin/main` are not immutable pins;
  they take this same compatibility path. Worker `git_bundle` never does so.

Any existing destination branch must be an ancestor of the inspected output
before checkout. Recheck cleanliness and exact host refs before and after host
object import, and the expected checked-out branch before fast-forwarding it.
Verify the final branch, commit and clean state before success. Fetch only the
inspected local snapshot without writing `FETCH_HEAD`,
and create/fast-forward the branch by immutable commit identity, preserving
ignored-file collision protection. Never use `FETCH_HEAD` or force a branch.
Cancellation or failed preflight cannot publish success. Cancellation during an
accepted Git object import can leave unreachable objects, but does not authorize
resetting user refs or deleting repository data to roll them back.

R1 design/red tests precede implementation. Tagged real-Git cases cover clean
and repeated recovery, dirty categories, canonical refs, missing/corrupt or
unrelated bundles, missing pins/history, divergent destinations, lock contention,
Git failures and cancellation; no real publication or runtime is required.

## Focused gates

```sh
go test -p 2 ./cmd -run 'TestFactoryVerificationSafety' -count=1
go test -p 2 -race ./cmd -run 'TestFactoryVerificationSafety' -count=3
go test -p 2 -tags=integration ./cmd -run 'TestFactoryVerificationSafety' -count=1
go test -p 2 ./cmd -run 'TestFactoryRecoverySafety' -count=1
go test -p 2 -race -tags=integration ./cmd -run 'TestFactoryRecoverySafety' -count=3
go test -p 2 -tags=integration ./cmd -run '^TestFactory|^TestRunFactory|^TestRecordFactory|^TestPublishFactory' -count=1
go vet -p 2 ./cmd
git diff --check
```

Whole-repository, live rootless and final PR gates remain supervisor-owned. A
passing local fixture is not a new provider, macOS, or strict/microVM acceptance.

## Native Linux R1/R2 checkpoint (2026-09-06)

The reviewed `02757af4fd13e460dca02b8949a37e9d21a0642d` candidate ran the
nonpublishing keyboard-game factory fixture with Pi inside rootless Podman.
Its static Go 1.25.7 Linux/amd64 CLI SHA-256 was
`ee7617f2ef797c57d51934648f80b331d43ac441072908be7a1998e2dcad3d35`;
host and container binaries matched. All 18 image smoke checks passed offline.

Run `01a076b4-6fbd-7a42-879a-af128531884a` returned one successful
`factory-run-v1` document, process exit 0, no signal and empty stderr.
Its own required Verification recorded three passing checks: 17 unit tests
(zero skips), typecheck and production build. The three stored stdout artifacts
and verification/policy timeline matched that same run. This is not a separate
post-run verification substituted for an empty factory check set. Publication,
CI, PR creation and merge were disabled. The earlier attempt failed before
container creation when its background lab daemon disappeared; that failed
attempt remains separate from the successful foreground-daemon retry.

Actual recovery into a separate clean clone produced
`9c6f36c6b4a5da817e59b1aa511323aba87482e4`, descending from recorded input
`7974e05dd778b9ed033c0550b818d29216b09651`. The bundle SHA-256 was
`719c1e918d4aba212ef059353a50d2db13d5a897fc0dd738565b2a00407559c9`.
Repeated recovery succeeded without changes. Staged, unstaged and untracked
dirt, a divergent destination, unrelated history, a missing run and a copied
invalid-bundle fixture each returned nonzero with one `ok=false` document;
destination refs and file contents remained unchanged.

Independent review confirmed only the requested guide and one deterministic
test were added to the game; its original source, package/lock files and 16
tests were unchanged. All 17 tests also passed in the recovered host clone.
The exact candidate's seven selected native lifecycle/recovery tests passed
under race across three packages, with zero skips or failures.

Evidence is retained under the supervisor's `hal-factory-safety-e2e.9Eoz16nK`
task directory: `factory-required-checks-retry.*`, `native-recovery-acceptance.json`,
individual recovery captures, and `02757af4-live-lifecycle.*`. The full ignored
runtime archive was preserved separately and matched against original Git and
stored artifacts; it is not native artifact-collection coverage. Three optional
legacy artifact gaps (CI, PR and the archived source path) remain explicit.
The separate doctor snapshot failed initialization checks: installed Hal skills
were missing, with additional default/config and broken-link warnings. Passing
the three project checks does not make that doctor snapshot successful; this
initialization gap remains a release follow-up. The completed game sandbox,
worker registration, foreground daemon and temporary copied auth were removed;
the recovered source, bundle, archives, logs and original credentials remain.

This checkpoint accepts the R1/R2 Linux slice only. It is not a fresh macOS run,
complete Sandbox v2, strict network/credential enforcement, microVM boot or final
PR acceptance. Later integrated changes still require their own affected gates.
