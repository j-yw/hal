# Sandbox Runtime v2 L8 Production Credential Delivery Architecture

## Authority and phase boundary

This document refines issue #49 locked comments `5068151561`, `5068157402`,
and `5068162708` for L8. The cross-phase architecture remains
`sandbox-runtime-v2-linux-completion-architecture.md`. L8 starts from the
completed L7 topology and enforcement proof and consumes L2/L3 durable job and
recovery ownership plus L4/L5 guest execution. It does not weaken or replace
any of those proofs.

L8 owns production credential activation in this order:

1. an explicit application-level HTTP credential proxy;
2. per-job file delivery in a private tmpfs mount namespace; and
3. per-job SSH-agent forwarding through a restricted relay.

Environment delivery, legacy auth synchronization, metadata handoffs, and
simulated activation remain compatibility-only. They cannot produce an L8 live
proof. L8 emits correlated live evidence for L10 but does not select or claim
the strict secure default itself.

No production implementation begins until this design, its verification note,
contract/source guards, and red acceptance tests are committed. A shared
contract change is merged before independent implementation slices start.

## Exit contract

L8 is complete only when a prepared-Linux run proves all of the following:

- the intended sandbox and worker job can use each selected production mode;
- a neighboring job, stale generation, old guest protocol, and unrelated
  runtime cannot use the activation;
- raw secret canaries never enter arguments, durable environment, job state,
  manifests, factory records, timelines, logs, errors, status JSON, artifacts,
  or sync-out content;
- success, nonzero exit, activation failure, cancellation, timeout, proxy or
  relay loss, guest loss, Firecracker exit, daemon restart, and partial prepare
  all converge through bounded cleanup;
- no owned ticket, connection, listener route, secret buffer, file, mount,
  namespace keeper, relay, guest socket, session, or live proof remains after
  cleanup; and
- the resulting sanitized proof is exact, current, warning-free, and bound to
  the same sandbox, execution, worker, runtime, network, and job generations.

A selected live test that skips is a failure. Tests use local fixtures and
already available L7 assets only. They do not access the internet or a billed
provider.

## Security properties

### Authority is live and job-scoped

An L8 activation is an opaque live capability, not a durable metadata record.
It is bound to:

- sandbox ID;
- execution ID;
- worker and host IDs;
- runtime driver, runtime ID, and runtime generation;
- Firecracker process and vsock generations when applicable;
- worker job and submission identities;
- credential plan, activation, and credential generations;
- exact binding IDs and delivery modes;
- L7 policy, proxy, topology, and rule generations for HTTP delivery; and
- a monotonic revision and bounded expiry.

Every operation revalidates the identities it uses. Partial, missing, stale,
cross-job, replayed, or warning-bearing identity fails closed. A valid L7
network proof is required for HTTP activation but is never itself credential
delivery proof.

### Raw values stay outside durable contracts

`internal/credentialdelivery` remains metadata-only. Its existing
`ActivationAdapter`, `SanitizedActivationRequest`, `ActivationResult`, and
proof-reference types remain compatibility projections. They do not receive a
raw value or an opaque live handle and cannot authorize production delivery.

Raw values exist only inside explicitly live, non-JSON objects. No live object
implements JSON or text marshaling. Errors expose stable codes and field or
record positions only. Formatting, logging, reflection helpers, panic output,
and test failure output must not stringify a secret, ticket, key blob, socket
identity, or live endpoint.

Every Hal-owned secret copy uses mutable owned bytes. The owner attempts to
lock pages, exposes bytes only through a bounded callback, overwrites them
before unlock, and destroys them on every return path. Existing
`ResolvedRunSecret.Value string` and environment-derived string copies remain
compatibility ingress and cannot satisfy a warning-free L8 proof.

Physical zeroization cannot be promised by Go, the kernel, firmware, or an
external provider. The precise claim is that Hal does not intentionally create
immutable live copies, overwrites every owned mutable buffer, closes the
broker session, disables core dumps and process dumpability, and proves the
prepared acceptance host has no active swap. Page-lock failure is a safe
warning in advisory operation and blocks later strict composition.

### Cleanup precedes terminal success

The worker cannot publish a terminal job state, release admission, or let L3
finalization collect artifacts while credential cleanup is incomplete.
Terminal execution outcome and credential cleanup outcome are separate facts.
If process-group termination, credential revocation, or cleanup absence cannot
be proved, the public state is `unknown` with reason
`credential_cleanup_incomplete`; it is never succeeded or strict-active.

## Package ownership and dependency direction

### Existing metadata packages

- `internal/credentialdelivery` retains safe plans, bindings, projections,
  validation, normalization, sanitization, and compatibility activation.
- `internal/sandbox` retains safe credential-proxy and security metadata.
- `internal/factory` owns broker sessions and the factory-side bridge from
  configured secret sources to live, callback-scoped secret access.
- `internal/sandboxexecution` owns additive safe job-credential references and
  the ordered recovery checkpoint, never values or live handles.

### New live behavior

- `internal/credentialmemory` owns mutable buffers, page-lock attempts,
  overwrite, unlock, dumpability checks, and platform fail-closed behavior.
- `internal/credentialproxy` owns the static service registry, one-job ticket
  store, verified upstream HTTP client, request transformation, and safe live
  proof. It may depend on L7 network-enforcement contracts but not on `cmd`,
  factory orchestration, concrete runtimes, or durable stores.
- `internal/sandboxruntime` owns neutral optional job-credential lifecycle
  interfaces used by `internal/sandboxworker`.
- `internal/sandboxruntime/microvm/guestagent` owns versioned v2 wire contracts
  and a v2 client while preserving v1 byte and behavior compatibility.
- `internal/sandboxruntime/microvm/guestagent/server/credentialfs` owns guest
  Linux tmpfs namespace mechanics behind injected syscall interfaces.
- `internal/sandboxruntime/microvm/guestagent/server/sshrelay` owns the guest
  restricted relay endpoint and protocol codec.
- `internal/sandboxruntime/microvm/firecrackerhost` owns v2 transport
  correlation, host HTTP activation, the host SSH relay, and the concrete L8
  runtime wrapper.
- `internal/sandboxworker` owns prepare/renew/loss/revoke ordering around a
  durable job. It sees the neutral runtime interface and safe projections, not
  concrete Firecracker, proxy, mount, SSH, or factory implementations.
- `cmd` constructs explicit dependencies and renders sanitized status. It does
  not implement a second broker, proxy, guest protocol, relay, or lifecycle.

Import-boundary tests enforce these directions. In particular, the existing
metadata-only guards are not relaxed to make room for live code.

## Neutral runtime lifecycle

The optional root runtime boundary has this shape; exact Go names may change
without weakening the semantics:

```go
type JobCredentialRuntime interface {
	PrepareJobCredentials(context.Context, JobCredentialPrepareRequest) (JobCredentialSession, error)
	RecoverJobCredentials(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error)
}

type JobCredentialSession interface {
	ExecBinding() JobCredentialExecBinding
	Proof() JobCredentialProof
	Renew(context.Context) (JobCredentialProof, error)
	Revoke(context.Context, JobCredentialRevokeReason) (JobCredentialCleanupProof, error)
	Loss() <-chan JobCredentialLoss
}
```

`JobCredentialPrepareRequest` carries exact safe identity, a sanitized plan,
explicit binding metadata, and an opaque callback-scoped secret source. It is
not serializable and is never included in the worker request-key material.
`ExecBinding` contains only ephemeral capabilities needed by the exact exec;
it is not copied into the durable `Job`.

Prepare and revoke are idempotent for the same full identity and revision.
Prepare with conflicting identity fails. Renew is monotonic, cannot resurrect
an expired or revoking session, and issues a new bounded expiry without
changing job ownership. Revoke first denies new use, then terminates active
use, then removes resources, and finally proves absence. Repeated revoke
returns the same safe cleanup result only after reinspection.

### Live state machine

```text
preparing -> active -> renewing -> active
    |          |          |
    +----------+----------+----> revoking -> revoked
    |          |          |          |
    +----------+----------+----------+----> cleanup_incomplete
                         active -> expired -> revoking
```

Allowed durable projection states are `preparing`, `active`, `renewing`,
`revoking`, `revoked`, `expired`, and `cleanup_incomplete`. Only a live handle
can be active. Durable reload never reconstructs active state from the label.

Stable failure codes include:

- `credential_protocol_unsupported`;
- `credential_identity_mismatch`;
- `credential_replay_rejected`;
- `credential_revision_stale`;
- `credential_expired`;
- `credential_memory_unlocked`;
- `credential_network_proof_unavailable`;
- `credential_service_unapproved`;
- `credential_prepare_failed`;
- `credential_renew_failed`;
- `credential_revoke_failed`;
- `credential_process_termination_unconfirmed`; and
- `credential_cleanup_incomplete`.

Messages remain generic and do not attach raw causes from a provider, HTTP
server, filesystem, mount tool, SSH agent, guest, or runtime.

## Guest-agent v2

V1 readiness, exec, copy-in, and copy-out remain unchanged. The host does not
rewrite v1 requests to v2 and never retries v1 after a v2 failure.

V2 adds exact operations:

- `readiness` with required credential lifecycle capabilities;
- `credential_prepare`;
- `credential_renew`;
- `credential_revoke`; and
- `exec` with an opaque job credential binding.

The host sends `guest-agent-v2` directly. An old server's v1
`unsupported_protocol_version` response is terminal. No v1 readiness proof,
environment fallback, or compatibility handoff can satisfy L8.

Each lifecycle request carries the full identity and generation tuple, a
monotonic revision, bounded expiry, and exact mode/binding declarations.
Responses echo request identity and return safe proof or cleanup IDs only.
Unknown or duplicate fields, noncanonical scalars, oversized arrays or frames,
stale revision, cross-job identity, replay, and malformed payloads fail before
mutation.

Raw file payload bytes are confined to wire-private DTOs. They have strict
aggregate and per-binding bounds, cannot marshal through generic diagnostic
paths, and are destroyed after the guest takes ownership. SSH private keys are
never a protocol payload.

V2 exec is admitted only into the exact prepared job namespace. V1 exec and a
v2 exec with a missing, stale, or neighboring binding cannot see L8 files or
sockets. Losing the authenticated v2 session revokes every job generation
owned by that session and notifies the host loss watcher.

## HTTP credential proxy

### Explicit non-MITM protocol

L6 CONNECT remains an opaque byte tunnel. L8 does not inspect TLS inside
CONNECT, install a guest CA, terminate arbitrary workload TLS, or inject a
header into a CONNECT stream. A credential ticket presented to generic CONNECT
fails closed and performs no secret lookup.

Credential-bearing HTTP uses a distinct application-level Hal endpoint in the
same L7-proven listener/topology. The workload sends a one-job ticket and safe
service ID to that endpoint. Hal selects a sealed service definition and makes
its own separately verified upstream TLS request. Generic L6 HTTP and CONNECT
remain byte-compatible when the L8 route is absent.

### Static service registry

The live registry is host-owned and immutable for a daemon generation. A
project, template, request, binding, or guest cannot supply or override an
authority, port, TLS server name, authentication transform, redirect policy,
method set, or path policy. Durable metadata contains the safe service ID only.

Every production entry fixes:

- stable service ID;
- canonical authority and port;
- TLS server name and trusted-root policy;
- exact authentication transformation;
- allowed methods and path shapes;
- request and response size bounds;
- allowed content handling; and
- redirect behavior, which is always disabled in L8.

The first implementation commit must lock the initial production catalog in
table-driven tests before adding a live dialer. Tagged tests use a separate
fixture-only registry constructor that cannot enter production composition.
Unknown and empty catalogs fail closed; no arbitrary-public-host fallback is
allowed.

### Tickets and request path

A ticket is cryptographically random, one job, one service, one binding, one
activation generation, and short lived. Stores retain only a keyed digest and
constant-time comparison material. Tickets are bounded in count, request use,
concurrency, and lifetime. They are invalidated before cleanup begins and
cannot be renewed after loss or expiry.

For every request the proxy:

1. validates framing, method, path, headers, body bounds, ticket, and exact job
   correlation without reading a secret;
2. re-inspects the exact active L7 listener, topology, and rule generations;
3. resolves all upstream DNS answers and rejects the entire result if any
   answer is private, metadata, loopback, link-local, special-use, or an unsafe
   NAT64 translation;
4. dials only a numeric address from the validated set;
5. verifies TLS with the sealed server name and trusted roots, with no
   `InsecureSkipVerify` or plaintext downgrade;
6. revalidates ticket and L7 proof immediately before secret access;
7. obtains the secret through the bounded callback, adds the sealed auth
   transformation last, and writes the upstream request; and
8. closes and revokes in-flight connections on ticket, network-proof, job, or
   runtime loss.

Client authorization headers, duplicate controlled headers, userinfo,
trailers, upgrades, authority override, arbitrary ports, and host/URL mismatch
are rejected. The proxy never follows redirects. Secret, ticket, authority,
resolved address, header, path, body, response payload, and raw TLS/DNS errors
do not enter decisions or diagnostics.

## File-on-tmpfs delivery

Every credential-bearing job gets a private mount namespace used by its v2
exec operations. Preparation:

1. creates an owned namespace and bounded keeper;
2. makes mount propagation private;
3. mounts a bounded tmpfs with `nodev,nosuid,noexec,mode=0700`;
4. creates a generation directory beneath a fixed agent-owned root;
5. opens every component with beneath, no-symlink, no-magic-link, and
   no-cross-mount resolution;
6. writes regular mode-`0600`, single-link files owned by the fixed workload
   identity from mutable buffers; and
7. atomically publishes and reinspects mount type/options, device boundary,
   ownership, mode, linkage, file count, and generation identity.

Caller paths must be canonical relative names from a sealed binding schema.
Absolute paths, `..`, empty components, alternate separators, symlinks,
hardlinks, devices, FIFOs, sockets, caller-selected mount flags, and existing
unexpected entries fail closed.

Renewal never replaces files while a process may hold an old descriptor. L8
locks the simpler contract: renew only extends the activation lease; rotating
file content requires the current process group to terminate and a new
credential generation to prepare before another exec.

Revoke denies new exec, terminates the job process group, confirms
termination, closes agent-owned descriptors, unlinks files, destroys buffers,
unmounts normally, proves mount absence, stops/reaps the keeper, and removes
the owned directory. Lazy unmount is not successful cleanup proof.

## SSH-agent relay

SSH private keys remain in the host agent. L8 never copies a private key into a
guest, file, environment value, manifest, or protocol payload.

The relay uses a separate runtime/job-bound vsock stream; the existing framed
one-request/one-response guest control transport is not reused for a persistent
SSH-agent stream. The v2 control plane mints and revokes the opaque relay
capability. A guest Unix socket exists only inside the job's private mount
namespace and is exposed to that job's v2 exec as transient `SSH_AUTH_SOCK`.

The host relay binds exact runtime, Firecracker process, vsock, job,
activation, and relay generations. It connects only to the configured host
agent identity and permits only identity enumeration and signing. Add, remove,
remove-all, lock, unlock, extension, and unknown messages fail closed. Frames,
keys, signatures, concurrent streams, operations, and duration are bounded.
An optional sealed public-key fingerprint set further narrows signing.

The relay never logs host or guest socket paths, public-key blobs, signature
payloads, comments, request bytes, or raw agent errors. Relay or v2 session
loss closes streams, removes the guest socket, cancels the job, and invalidates
proof. Cleanup proves host listener/connection and guest socket absence.

## Worker, execution, and recovery ordering

The L2 worker job lifecycle becomes:

1. validate request and persist the queued job plus safe credential intent;
2. persist credential state `preparing`;
3. call optional `JobCredentialRuntime.PrepareJobCredentials` and mechanically
   inspect its exact proof;
4. persist only the sanitized active proof reference;
5. execute with the opaque transient binding;
6. renew from the heartbeat path and concurrently watch loss;
7. on expiry/loss, cancel and prove process-group termination;
8. revoke and prove cleanup on success, failure, cancel, timeout, daemon close,
   state-write failure, or runtime loss; and
9. only then persist terminal job outcome and release admission.

A nil lifecycle dependency preserves existing jobs with no live L8 intent. A
request for production L8 modes with a nil or unsupported dependency fails
before exec; it does not downgrade to environment or legacy delivery.

`internal/sandboxexecution.FinalizationCheckpoints` gains an additive
`CredentialCleanup` checkpoint before `Artifacts`. Older manifests with no
live credential intent load compatibly and treat the step as not applicable.
With live intent, artifacts, sync-out, lease release, and terminal publication
cannot precede proven credential cleanup.

Worker restart reconciliation runs before accepting new jobs. Every durable
nonterminal credential reference is reconciled through the runtime. In-memory
tickets and buffers are already unusable after process death; reconciliation
does not reconstruct a secret or resume an exec. It reinspects and removes
owned guest/runtime resources. If the guest cannot be reauthenticated, the
runtime is stopped or quarantined and process termination is proved before
cleanup can complete.

## Runtime composition

The explicit L8 Firecracker composition wraps the L7 live runtime and requires:

- exact L5 process/vsock ownership;
- v2 guest readiness and lifecycle capabilities;
- the same active L7 network session for HTTP mode;
- active loss watchers for process, vsock, network, HTTP, tmpfs, and relay
  generations; and
- warning-free mechanical inspection for every requested mode.

Default L5/L7 constructors remain unchanged and do not activate credentials.
The L8 constructor is not reachable from ordinary command paths until its
capability and live gates pass.

Rootless Podman remains advisory. L8 may expose the explicit HTTP route through
its real L7 topology, but it does not gain a microVM, guest-v2, tmpfs namespace,
or SSH relay claim by projection. L10 cannot use rootless metadata to satisfy
strict composition.

## Durable and status projection

Additive durable metadata is limited to safe identities, mode/state enums,
timestamps/expiry, revisions, reason/warning codes, and proof/cleanup
references. It excludes values, secret names, tickets, service authorities,
paths, sockets, endpoints, PIDs, inode/device numbers, mount targets, key IDs,
public keys, headers, and request destinations.

Projection rules are conservative:

- plan, request, handoff, simulation, or compatibility activation is not live;
- `active` requires an inspected unexpired live handle and exact correlation;
- `renewing` is not warning-free active proof;
- loss, expiry, revoke, cleanup warning, or identity mismatch removes active
  modes immediately; and
- status code can downgrade live evidence but never upgrade metadata.

Existing JSON fields remain optional and compatible. New machine-contract
fields are documented before use. Default no-credential output remains byte
compatible where existing contracts require it.

## Red-first implementation order

### D0 — design and guards

- Lock this architecture, verification commands, package owners, imports,
  state machine, failure codes, and non-goals.
- Guard existing metadata packages and default constructors from live behavior.
- Guard simulation, handoff, env, and legacy modes from live projection.

### D1 — shared contracts and memory ownership

- Red tests for lifecycle transitions, correlation, replay, idempotence,
  expiry, loss, and cleanup ordering.
- Red tests for mutable buffer ownership, page-lock success/failure, overwrite,
  dumpability, string/JSON/log exclusion, and cancellation.
- Lock the initial host-owned HTTP service catalog before a live dialer exists.

### D2 — guest v2 protocol

- Preserve v1 byte/behavior compatibility.
- Reject v2-to-v1 downgrade, unknown fields, replay, stale revisions, cross-job
  identity, overflows, and malformed private payloads.

### D3 — HTTP credential route

- Implement ticket store and sealed registry before network behavior.
- Implement destination/TLS/request hardening with local verified-TLS fixtures.
- Integrate the optional route into L6 and prove generic HTTP/CONNECT unchanged.

### D4 — guest tmpfs

- Implement through injected syscall fakes first.
- Cover namespace/mount flags, path traversal and replacement races, partial
  prepare, open-descriptor rotation, teardown retry, and orphan recovery.

### D5 — SSH relay

- Lock codec and operation allowlist before host/guest streams.
- Cover replay, generation mismatch, agent replacement, bounds, loss, and
  cleanup.

### D6 — Firecracker and worker lifecycle

- Compose v2, HTTP, tmpfs, relay, process/vsock, and L7 generations.
- Wire prepare/renew/loss/revoke around worker exec and recovery.
- Add the finalization cleanup checkpoint and conservative projections.

### D7 — prepared-Linux acceptance

- Run each mode alone, all modes together, neighboring-job negatives, every
  terminal/failure/restart path, durable canary scans, and zero-resource
  cleanup against the exact phase head.
- Run focused/race/repetition, full repository, docs, build, lint when
  installed, cross-platform compilation, and independent Hal/manual reviews.

Independent slices may run in parallel only after their shared D1/D2 contracts
are merged. HTTP, tmpfs, and SSH implementations are separate worktrees.
Worker/recovery integration waits for the neutral lifecycle contract; final
composition waits for all three adapters.

## Non-goals and L10 handoff

L8 does not add environment delivery to strict mode, sync arbitrary auth
directories, accept arbitrary HTTP destinations, MITM TLS, forward unrestricted
SSH agents, persist raw secrets, change OCI trust, select the secure default,
upgrade rootless advisory isolation, implement provider/cloud APIs, or call a
billed service.

L10 consumes only warning-free, unexpired L8 live proof correlated to the exact
L3 job, L5 runtime, L7 network session, L9 immutable template, and workspace
state. Corrupting or omitting any L8 identity or cleanup fact must make strict
composition fail closed.
