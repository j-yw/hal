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

## R1: recovery (next checkpoint)

Recovery will reuse the existing workspace lock and Git boundaries. It must
reject dirty worktrees and unprovable or divergent bundle inputs before mutation,
bind worker input ancestry to recorded immutable workspace metadata, and return
a failing process status for rendered JSON failures. Legacy records without an
immutable input pin must not manufacture one or fetch private history.

R1 is not implemented or accepted by the R2 checkpoint. Its design and meaningful
red cases must be committed before its production changes; real Git validation
will use isolated repositories and remain explicitly tagged.

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
