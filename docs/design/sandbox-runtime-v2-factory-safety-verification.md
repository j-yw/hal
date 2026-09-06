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

R2 verification uses fake worker/provider execution plus a local shell fixture
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

Exactly one complete bundle artifact must resolve inside its run's artifact
directory. Recovery opens a regular non-symlink file through a contained root
and copies it into a private, context-aware, bounded snapshot (512 MiB maximum).
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

Any existing destination branch must be an ancestor of the inspected output
before checkout. Immediately before host mutation, recheck cleanliness and exact
host refs. Fetch only the inspected local snapshot without writing `FETCH_HEAD`,
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
go vet -p 2 ./cmd
git diff --check
```

Whole-repository, live rootless and final PR gates remain supervisor-owned. A
passing local fixture is not a new provider, macOS, or strict/microVM acceptance.
