# Sandbox Runtime v2 L3 Recovery Architecture

## Authority and scope

This document refines the L3 implementation details from the locked issue #49
Linux-first specification and phase plan. It does not replace those comments.
L3 adds sandbox-centric discovery, observation, and recovery on top of the L2
durable worker-job contract.

The supported operator surface is:

```text
hal sandbox list --live [--json]
hal sandbox status NAME [--live] [--json]
hal sandbox logs NAME [--run RUN_ID] [--follow]
hal sandbox recover NAME [--run RUN_ID]
hal sandbox sync-out NAME [--run RUN_ID]
```

The existing `hal sandbox apply EXECUTION_ID` command remains the only L3 host
worktree mutation surface. Recovery and sync-out never apply implicitly.

## Ownership

- `internal/sandboxworker` owns asynchronous job admission, submission
  resolution, status, log cursors, cancellation, daemon supervision, and live
  active-job truth. Its `ClientDriver` exposes a narrow job adapter while
  retaining the synchronous runtime-driver interface for compatibility.
- `internal/sandboxexecution` owns safe manifest job references, execution
  discovery, finalization metadata, per-execution locking, and idempotent
  manifest/artifact transitions. It also owns execution-store containment and
  verified payload access. It does not import worker clients, command packages,
  concrete runtimes, or providers.
- `cmd` joins sandbox registry records, execution manifests, durable hosts, and
  live worker responses. It owns CLI selection, orchestration, rendering, and
  dependency wiring only.
- `internal/sandboxworkspace` continues to own safe host apply and host-worktree
  locks.
- `internal/sandbox` continues to own durable lease transitions.

Execution/job projections are response data. They are not copied into the
durable sandbox registry merely for display.

## Production asynchronous adoption

Explicit worker-backed `rootless_podman` run and auto execution uses the L2 job
adapter for the final agent command:

1. Resolve/start the selected runtime and perform the existing workspace,
   command-context, and auth preparation exactly once.
2. Submit the final command with the execution ID as the stable submission
   identity.
3. Persist the sanitized worker-job reference and pending finalization intent
   before waiting for output or terminal state.
4. In the foreground, read redacted log pages and poll job status until the job
   is terminal.
5. On normal terminal completion, use the same finalization path as
   `sandbox recover`.

The protocol includes a read-only submission-resolution operation. It returns
the already admitted job for a hashed caller submission identity and never
submits work. Recovery uses it to close the acknowledgement-to-manifest crash
window: a `running` execution with no job reference may resolve its execution
ID to the previously admitted job, but must never reconstruct or resubmit the
command.

Losing or canceling only the foreground client does not call `job_cancel`,
release the lease, collect artifacts, change the manifest to a terminal state,
or submit another job. A later retry of admission uses the same submission
identity and must return the original L2 job.

Legacy SSH-machine execution and non-worker routes remain synchronous.
Preparation, bootstrap, input materialization, and auth are never moved into a
recoverable job and are never repeated by recovery.

Every status, log, and submission-resolution response must match the selected
manifest's sanitized job, worker, host, runtime-driver, runtime, and submission
identity. A mismatch fails closed with a safe reason code. The local worker
channel is same-user only: its Unix-socket parent and socket are private,
symlink and non-socket replacements are rejected, and peer identity is checked
where the platform exposes it.

## Durable execution and finalization state

The non-factory execution status accepts:

- `running`
- `succeeded`
- `failed`
- `canceled`
- `interrupted`
- `unknown`

Queued and running worker jobs project as `running`. A succeeded worker job
does not project as a succeeded execution until finalization completes.
Failed, canceled, interrupted, and unknown jobs project to the matching
execution state only after their allowed finalization work is durably
checkpointed. `unknown` and `interrupted` are never rendered as live-running or
successful.

`sandbox-finalization-v1` records only safe intent and checkpoints:

- state: `pending`, `finalizing`, `blocked`, or `completed`;
- whether sync-out collection was requested;
- terminal worker-job state when known;
- artifact, sync-out, lease-release, and terminal-publication checkpoints;
- sanitized reason codes and timestamps.

The per-execution OS file lock spans one recovery/finalization attempt.
Checkpoint writes are atomic. Each step is skipped after its completed
checkpoint. Artifact payload writes use stable destinations and metadata merge
semantics, so retrying a crash window does not duplicate manifest entries.
Lease release is an idempotent durable transition; a retry may re-read or call
the release API after a crash, but it cannot create a second release state.

Finalization order is:

```text
terminal job proof
  -> terminal log drain
  -> core/recovery/output artifact collection
  -> requested sync-out collection
  -> lease release
  -> terminal manifest publication
```

A failure records `blocked` with a safe reason code and leaves completed
checkpoints intact. A later recovery resumes at the first incomplete step.
Recovery never creates or starts a target, bootstraps a workspace, writes
project inputs, syncs auth, launches an agent, or cleans a resource it did not
create.

An `unknown` or `interrupted` job is not terminal proof. Recovery must not
collect mutable runtime output, release the lease, or publish success until
non-execution or terminal state is independently proved. It records a
conservative blocked handoff instead of guessing.

## Execution-store containment

Recovery treats every durable manifest and artifact reference as untrusted
input. Store setup, manifest loading, payload creation, payload resolution, and
apply handoff reject:

- symlinked store, execution, area, manifest, and payload components;
- absolute, traversal, sibling-execution, and non-regular-file references;
- existing directories or files with unsafe ownership or permissions; and
- replacement detected between validation and the verified open operation.

JSON decoding rejects unknown manifest fields. Errors expose safe codes and
execution/artifact IDs only. Host apply consumes a verified regular payload
handle or equivalent race-resistant reference that remains contained beneath
the selected execution; it does not reopen an unchecked path. An ambiguous
crash after apply intent but before a durable result fails closed for explicit
manual inspection rather than applying again.

## Selection

Commands first match non-factory manifests by exact sandbox name.

- An explicit `--run` must match both the execution ID and sandbox name.
- Without `--run`, one active or recoverable execution is selected.
- More than one active or recoverable execution is an `ambiguous_run` error
  containing safe execution IDs only.
- `recover` requires an incomplete recoverable execution.
- When no run is active/recoverable, status and logs may select the newest
  completed execution deterministically by `startedAt`, then execution ID.
- Corrupt committed manifests fail discovery closed with a sanitized execution
  ID; they are never silently ignored as unrelated.

Dry-run does not enter any L3 discovery, job, lock, finalization, or rendering
path.

## Logs and follow

The manifest worker-job cursor is the latest producer cursor reported by the
worker, not a global reader-consumption position. Viewing logs is read-only.
Each logs session starts at cursor zero and follows the server-provided
`oldestCursor`/`nextCursor` chain.

- Retention gaps render one sanitized warning and continue from the oldest
  retained record.
- Records preserve worker cursor order and stdout/stderr routing.
- A terminal job is not complete for the follower until records through its
  terminal `logCursor` are drained or a marked retention gap accounts for
  them.
- `--follow` uses bounded polling/backoff, retries transient daemon
  unavailability until its context ends, and never cancels the job.
- Non-follow mode drains the records currently available and returns.

Logs are already redacted by the L2 worker boundary. Command rendering applies
the normal sandbox redactor again and never exposes endpoints, paths,
credentials, or request contents.

## Status precedence and active counts

Live worker job state is authoritative when it is available and valid. The
manifest is the durable fallback and must be labeled cached. A transport
failure does not overwrite a previously proven job state.

The worker derives `activeSandboxes` from distinct runtime IDs of queued or
running durable jobs. Sandbox list/status execution counts use the same
queued/running definition. Terminal recovery updates the manifest and worker
count independently, and tests require eventual convergence to zero.

Named status uses the new `sandbox-status-v1` JSON contract. Sandbox list moves
to `sandbox-list-v2` for `--live --json`, where the execution projection is
present; cached `sandbox list --json` remains the documented v1 contract. The
v1 required sandbox identity fields remain unchanged in v2. Both live
contracts include source, execution summary, safe recommended action,
diagnostics, and no raw worker endpoint or host path.

## Sync-out and apply

`hal sandbox sync-out NAME` requires terminal worker proof and runs only the
existing collection primitives through the already selected runtime. It marks
sync-out intent and finalizes the durable summary under the execution lock.
Repeated calls are idempotent.

It never mutates the host worktree. The user may subsequently run
`hal sandbox apply EXECUTION_ID`, which retains the existing project identity,
branch/revision, clean-worktree, workspace-lock, and Git dry-run checks.

## Red-first and live acceptance

Before implementation, tests must fail for:

- run and auto production job admission plus pre-wait manifest persistence;
- client loss without job cancellation, lease release, or duplicate work;
- sandbox/run discovery and ambiguity;
- JSON contracts, state precedence, active-count convergence, and redaction;
- log cursor gaps, terminal drain, follow cancellation, and daemon reconnect;
- concurrent and repeated recovery under one execution lock;
- crash/retry at every finalization checkpoint;
- deduplicated artifacts and idempotent lease release;
- execution-store symlink, ownership, mode, and replacement containment;
- private same-user worker sockets and response identity binding;
- recovery guards for bootstrap, input writes, auth sync, agent execution,
  target create/start, implicit apply, and unrelated cleanup;
- corrupt manifests and unavailable workers failing closed.

Prepared-Linux acceptance kills the initiating CLI during a real rootless
Podman job, proves the job continues, rediscovers it by sandbox name, follows
logs, recovers repeatedly, collects requested output, releases the lease,
and observes manifest/job/runtime/active-count convergence. A daemon restart
must produce proven terminal state or conservative `interrupted`/`unknown`
without rerun. A skipped tagged test is not a pass.

## Non-goals and L4 handoff

L3 does not add retention pruning, guest-agent server behavior, Firecracker
guest transport or images, proxy/firewall topology, credential activation,
OCI acquisition, strict secure-default composition, provider work, or billed
cloud calls.

L4 begins with the independent guest-agent server and injected-transport
protocol-security tests for readiness/version negotiation, exec/copy, bounds,
path containment, timeout/cancel, redaction, and malformed requests.
