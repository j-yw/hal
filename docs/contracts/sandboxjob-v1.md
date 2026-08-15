# Sandbox Job Contract v1

**Contract version:** `sandboxjob-v1`
**Scope:** local sandbox worker asynchronous execution

This contract defines the redaction-safe, durable job interface between a Hal
client and a sandbox worker daemon. A job is owned by the daemon after durable
admission and continues independently of the submitting client connection.

## Admission and identity

`job_start` requires a caller-stable submission identifier. The worker hashes
that identifier before persistence and uses the digest as its lookup key. A
separate private digest binds the complete accepted execution request,
including its runtime target, arguments, environment, stdin, working
directory, and output limits. A retry returns the original job only when that
request identity matches. Reusing the caller identifier for different work
fails with a sanitized `submission_conflict`; neither private digest is exposed
as raw caller input. The request identity includes the normalized runtime
driver and runtime ID.

The worker persists a generated job ID, worker and host identity, runtime
driver and runtime ID, state, lifecycle timestamps, safe failure codes,
truncation flags, and log cursor. The public and durable job representation
does not expose command arguments, environment values, stdin, process IDs,
filesystem paths, endpoints, or credentials.

## Lifecycle

The states are:

- `queued`
- `running`
- `succeeded`
- `failed`
- `canceled`
- `interrupted`
- `unknown`

Lifecycle timestamps are monotonic relative to `submittedAt`. Queued jobs have
no progress timestamps. Running jobs require `startedAt` and cannot have
`finishedAt`. Terminal jobs require `finishedAt`; successful and failed jobs
also require `startedAt`.

After daemon restart, an unproven queued job becomes `interrupted`; an
unproven running job becomes `unknown`. A daemon-owned context cancellation or
deadline also becomes `interrupted`, not a driver failure. Recovery must not
rerun an admitted job. A canceled result is claimed only when the runtime
returns explicit process-group cancellation proof. Rootless Podman proof
requires an external runtime observation of the owned process group before
signaling and a second observation that the group no longer exists; successful
access to a workload-writable control path is not proof by itself. On Linux,
the host-side process-group leader remains unreaped while its group ID is used,
preventing a recycled process-group ID from being signaled.

## Logs

`job_logs` returns bounded, redacted records in a global monotonically
increasing cursor order. `nextCursor`, `oldestCursor`, and `truncated` let a
client detect retention gaps without exposing spool paths. Record and page
byte limits are enforced by both server and client. Cursor, record, byte-count,
and truncation updates become observable only after their durable write
succeeds. Complete safe lines are durable and readable while execution is
still running; unterminated suffixes remain bounded until they can be safely
classified across write boundaries.

## Compatibility

Fields may be added only when optional and redaction-safe. A client must reject
an unsupported contract version, a mismatched response identity, invalid
lifecycle metadata, or an invalid cursor progression.
