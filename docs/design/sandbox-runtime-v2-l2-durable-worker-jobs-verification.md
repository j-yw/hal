# Sandbox Runtime v2 L2 Durable Worker Jobs Verification

L2 moves sandbox execution ownership into the local worker daemon. Durable
admission makes a submitted job survive client disconnect, while conservative
reconciliation makes a daemon crash and restart report `interrupted` or
`unknown` when terminal state cannot be proved. Recovery must never silently
rerun admitted work.

## Implemented boundary

- `internal/sandboxworker` owns admission, durable state, lifecycle
  reconciliation, bounded redacted logs, cancellation, and protocol handling.
- `internal/sandboxruntime` defines process-group cancellation proof and
  explicit asynchronous job-execution capability.
- `internal/sandboxruntime/rootlesspodman` supplies the L2 rootless Podman
  adapter and only advertises job execution for an explicitly supported image.
- `internal/sandboxexecution` persists only the safe `sandboxjob-v1` recovery
  reference.
- `cmd` configures an explicit job state root for `hal sandboxd`; default
  foreground execution behavior remains compatible.

The daemon durably records admission before acknowledging `job_start`.
Caller-stable submission identity is hashed before persistence and a separate
private digest binds the complete accepted execution request. Changed work
under the same submission identity fails with a sanitized conflict.
Cancellation is durable before it is acknowledged, and `canceled` requires
process-group cancellation proof.
The rootless runtime observes the owned group before signaling and proves it
absent afterward, so a same-UID workload replacing the control FIFO cannot
manufacture proof. Linux keeps the host process-group leader unreaped until
signaling finishes so PID reuse cannot target another group. Logs are
sanitized while streaming, bounded on disk and on reads, publish complete safe
lines during execution, become visible in memory only after persistence
succeeds, and remain cursor-addressable after restart.

## Focused verification

```sh
go test ./internal/sandboxworker ./internal/sandboxexecution ./cmd
go test -race ./internal/sandboxworker ./internal/sandboxruntime/rootlesspodman
go test -tags='podman_integration' ./internal/sandboxworker ./internal/sandboxruntime/rootlesspodman
```

The tagged Linux gate requires an existing local image selected through the
test environment. It proves rootless Podman client-disconnect continuity,
process-group cancellation isolation, rejection of workload control-FIFO
tampering, and real daemon crash/restart reconciliation without rerun. A skip
is a boundary result, not a pass.

## Broad verification

```sh
go test ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run gofmt verification and `golangci-lint` when the executable is installed.
Repository-wide lint findings that predate L2 must be reported separately from
changed-code lint.

## Security and failure semantics

Durable state roots are private, exclusively locked, bound to the configured
worker identity, and reject symlink or malformed-state ambiguity. Job
snapshots and errors contain safe identifiers and enum-like reason codes only.
The worker never persists commands, environment values, stdin, process
identifiers, endpoints, host paths, or credentials.

An unproven live process after restart is `unknown`; work admitted but not
started is `interrupted`. Neither state claims successful cleanup or terminal
execution. Daemon context cancellation and deadline expiry are also
`interrupted`, not driver failures. The daemon does not silently retry
execution.

## Deferred work

Retention pruning is deferred. L3 owns sandbox-centric status, log, recovery,
and sync-out command surfaces. Guest execution, Firecracker transport,
production proxying, firewall topology, credential delivery, OCI trust, and
strict secure-default composition remain later phases.
