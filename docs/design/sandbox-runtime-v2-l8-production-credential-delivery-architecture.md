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
cached offline L7 parent inputs, but they boot only the freshly built,
digest-locked L8 guest artifact. They do not access the internet or a billed
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
can serialize to JSON or text; designated live boundary types implement only
fail-closed marshal methods that return a stable denial without inspecting
their bodies. Safe `String`/`GoString` formatting likewise cannot traverse a
live body. Errors expose stable codes and field or record positions only.
Formatting, logging, reflection helpers, panic output, and test failure output
must not stringify a secret, ticket, key blob, socket identity, live body, or
live endpoint.

Every Hal-owned secret copy uses mutable owned bytes. Warning-free production
ingress is a worker-daemon-owned `LiveSecretSource` that fills a fixed-capacity
anonymous locked mapping directly with Linux `keyctl_read` from a host-admin
registered user/session-keyring entry. The safe job reference identifies an
opaque registry entry, never a key serial or value, and never authorizes its
use. The entry is reachable only after the separate admission grant below
authorizes the server-authenticated caller and exact job intent. The
implementation sizes and reads
directly into the owned mapping, rejects replacement/revocation/permission
races, and never returns a Go `string` or a freely copyable `[]byte`. Access is
callback-scoped through a noncopyable borrowed view whose only operations copy
into another owned locked mapping or write to an approved bounded sink; it has
no `Bytes`, string, formatting, or marshal method. The owner overwrites the full
capacity before unlock and unmap on every return path. The worker starts
non-dumpable with core limits disabled before it opens the source or accepts
jobs. Existing `ResolvedRunSecret.Value string`, factory broker strings,
environment/file reads, command-process callbacks, and keyctl command output
remain compatibility ingress and cannot satisfy a warning-free L8 proof.

Physical zeroization cannot be promised by Go, the kernel, firmware, or an
external provider. The precise claim is that the strict path does not
intentionally create immutable live copies, overwrites every owned mutable
mapping, closes the source session, disables core dumps and process
dumpability, and proves the prepared acceptance host has no active swap.
Page-lock failure is a safe warning in advisory operation and blocks later
strict composition. Upstream HTTP/1.1 authentication is emitted by a bounded
codec directly from mutable locked bytes into `tls.Conn`; it does not place the
secret in `net/http.Header`, convert it to `string`, negotiate HTTP/2, or retain
the encoded request after the write completes.

### Cleanup precedes terminal success

The worker cannot publish a terminal job state, release admission, or let L3
finalization collect artifacts while credential cleanup is incomplete.
Terminal execution outcome and credential cleanup outcome are separate facts.
If cgroup-zero or whole-runtime termination, credential revocation, or cleanup
absence cannot be proved, the public state is `unknown` with reason
`credential_cleanup_incomplete`; it is never succeeded or strict-active.

## Package ownership and dependency direction

### Existing metadata packages

- `internal/credentialdelivery` retains safe plans, bindings, projections,
  validation, normalization, sanitization, and compatibility activation.
- `internal/sandbox` retains safe credential-proxy and security metadata.
- `internal/factory` retains its compatibility string broker. It does not own
  warning-free L8 bytes and no factory callback crosses a worker protocol.
- `internal/sandboxexecution` owns additive safe job-credential references and
  the ordered recovery checkpoint, never values or live handles.

### New live behavior

- `internal/credentialmemory` owns noncopyable anonymous locked mappings,
  callback-scoped borrowed views, overwrite, unlock/unmap, dumpability startup
  checks, and platform fail-closed behavior.
- `internal/credentialsource` owns the byte-native source implementation and
  host-admin source/admission-grant registry implementation. The first
  production source is Linux keyring v1 through direct syscalls into
  `credentialmemory`; non-Linux, environment, file, subprocess, and
  command-callback sources are compatibility-only. Tests may inject a mutable
  byte fixture source that is unreachable from production composition.
- `internal/credentialproxy` owns the static service registry, one-job ticket
  store, verified upstream HTTP client, request transformation, and safe live
  proof. It may depend on L7 network-enforcement contracts but not on `cmd`,
  factory orchestration, concrete runtimes, or durable stores.
- `internal/sandboxruntime/networkenforcement/applicationroute` owns the
  neutral data/handler contract for reserved application routes. Both L6
  `policyproxy` and L8 `credentialproxy` may depend on it; neither implementation
  package imports the other.
- `internal/sandboxruntime` owns neutral optional job-credential lifecycle
  interfaces used by `internal/sandboxworker`.
- `internal/sandboxruntime/microvm/guestagent` owns versioned v2 wire contracts
  and a v2 client while preserving v1 byte and behavior compatibility.
- `cmd/hal-guest-credential-helper` is the narrowly privileged PID1 child that
  owns per-job cgroups, mount namespaces, credential files, the restricted
  guest SSH endpoint, and credential-aware exec entry.
- `internal/sandboxruntime/microvm/guestagent/credentialprotocol` owns the
  shared data-only credential lifecycle and SSH-agent wire codecs.
- `internal/sandboxruntime/microvm/guestagent/server/credentialclient` owns the
  unprivileged guest-agent client for the helper's authenticated local IPC.
- `internal/sandboxruntime/microvm/firecrackerhost` owns v2 transport
  correlation, host HTTP activation, the host SSH relay, and the concrete L8
  runtime wrapper.
- `internal/sandboxworker` owns use of injected neutral source-registry and
  credential-admission-authorizer interfaces plus prepare/renew/loss/revoke
  ordering around a durable job. It imports only the neutral interfaces from
  `internal/sandboxruntime`; `cmd` injects the `internal/credentialsource`
  implementation. The worker sees safe source and admission-grant references,
  not concrete keyring, Firecracker, proxy, mount, SSH, or factory
  implementations.
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
	ActiveProof() JobCredentialActiveProof
	Renew(context.Context) (JobCredentialActiveProof, error)
	Revoke(context.Context, JobCredentialRevokeReason) (JobCredentialCleanupProof, error)
	Loss() <-chan JobCredentialLoss
}
```

`JobCredentialPrepareRequest` carries exact safe identity, a sanitized plan,
explicit binding metadata, the accepted admission-grant identity/revision, and
a worker-local `LiveSecretSource` selected from authorized safe source
references. The source is never serializable. Command-to-worker requests carry
only safe source-reference and admission-grant IDs; neither kind of ID is a
bearer capability. The command never transports raw bytes, a callback, a live
endpoint, or a reusable authorization secret. This makes job admission and
recovery independent of command-process lifetime.
`ExecBinding` contains only ephemeral capabilities needed by the exact exec;
it is not copied into the durable `Job`.

### Admission authorization precedes source resolution

Source reference IDs are identity, never authorization. Before lookup, sizing,
or `keyctl_read`, the worker passes a server-derived
`AuthenticatedWorkerPrincipal` and the exact credential request to a
daemon-owned `CredentialAdmissionAuthorizer`. The principal comes only from an
authenticated connection context established by production transport code; no
request JSON field can name, replace, or weaken it. Unix `SO_PEERCRED` is one
input and the existing owner-only socket plus exact peer UID/GID check is the
concrete Linux bootstrap. The L8 host control-plane trust boundary includes the
daemon owner and every same-UID process that can open that socket; L8 does not
claim isolation from a malicious process already running as that trusted host
identity. Untrusted repository/workload code must never execute in that host
identity before admission and runs only in the sandbox afterward. A missing or
mismatched peer identity fails closed before v2 credential dispatch. Stronger
same-UID local multi-tenant authentication would require an external privileged
issuer or kernel identity boundary and is an explicit future hardening layer,
not an invented L8 claim.

The host-admin grant registry is immutable for a daemon generation. Each
`CredentialAdmissionGrant` binds one safe grant ID and revision to the exact
authenticated principal, registered host/runtime and immutable template or
workspace policy identities, normalized credential plan, allowed source
reference set, service IDs, delivery modes, and binding declarations. The
repository, template payload, project configuration, command request, guest,
and workload cannot create or alter a grant or supply the authenticated
principal. Repository-controlled configuration may request a source reference,
but only the intersection with the separately administered grant is eligible.
Unknown grants, nonmatching principals or policy identity, extra references,
weaker modes, and changed bindings fail with a generic
`credential_admission_denied` result. Grants are not enumerable through worker
status, errors, or logs.

The safe grant ID/revision and server-derived principal ID join the plan,
source references, modes, host/runtime/template/workspace identity, submission
identity, and daemon generation in the private request key and idempotency
digest. Durable v2 state stores only those safe identities for recovery. A
restart proceeds only if the same immutable grant revision still authorizes the
stored server-derived principal and exact intent; it never trusts a new caller
assertion or falls back to a different source. D1 locks the neutral
authentication/authorization contracts and denial tests before any v2
dispatcher or live source can exist; D6 provides the explicit production
composition and proves that missing/wrong-UID/wrong-GID peers and any
caller-supplied principal fail while the exact owner principal remains bound to
the host-admin grant.

`JobCredentialActiveProof` and `JobCredentialCleanupProof` are distinct sealed
contracts. Active proof requires live resources and cannot contain cleanup
claims. Cleanup proof requires revoked authority plus inspected absence and
cannot be projected active. They have disjoint proof kinds and validators; a
zero value, stale proof, or conversion between them is invalid.

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
- `credential_admission_denied`;
- `credential_source_unavailable`;
- `credential_worker_protocol_unsupported`;
- `credential_network_proof_unavailable`;
- `credential_service_unapproved`;
- `credential_prepare_failed`;
- `credential_renew_failed`;
- `credential_revoke_failed`;
- `credential_process_termination_unconfirmed`;
- `credential_guest_helper_unavailable`; and
- `credential_cleanup_incomplete`.

Messages remain generic and do not attach raw causes from a provider, HTTP
server, filesystem, mount tool, SSH agent, guest, or runtime.

## Worker job protocol v2

Production credential intent crosses the command-to-worker boundary only as
safe metadata in `sandboxjob-v2`. The existing outer `sandboxworker-v1`
envelope remains unchanged; v2 uses distinct operations `job_start_v2`,
`job_resolve_v2`, `job_status_v2`, `job_logs_v2`, and `job_cancel_v2` with
distinct payload fields. It never adds fields to `job_start` or its
`sandboxjob-v1` payload. V2 has a required
`productionCredentialsRequested` boolean, required safe source references and
binding declarations plus one safe, non-authoritative admission-grant ID when
the boolean is true, and no raw value, live callback, ticket, socket, endpoint,
or host path. The server attaches its authenticated principal before
validation; the request cannot supply that principal. The production-intent
bit, normalized plan identity, admission-grant ID/revision, authenticated
principal ID, source-reference IDs, and binding modes participate in both the
submission idempotency digest and private request-key material. A retry that
changes any of them conflicts instead of reusing an uncredentialed job.

All outer envelopes and the `sandboxjob-v2` payloads are decoded with
unknown-field rejection, exactly one JSON value, canonical scalar validation,
duplicate-key rejection before unmarshal, and the existing byte limits. A
pre-L8 daemon sees the distinct operation before any mutation and returns its
bounded `protocol_error`/`malformed_request` unsupported-operation response. A
v2 client may accept that exact legacy envelope, or the new daemon's exact
`unsupported_operation` response for the matching request ID and v2 operation,
only as terminal proof that L8 is unavailable. Every other response mismatch is
malformed. The client never strips credential fields, retries a v1 operation,
or treats an error as admission. Existing jobs with no production intent remain
on byte-compatible v1 operations.

The durable v2 job stores safe credential intent, the accepted admission-grant
identity/revision, server-derived principal ID, and source-reference identities
for restart reconciliation, never a secret, keyring serial, or transient exec
binding. At daemon startup the host administrator maps each safe reference to
an exact keyring identity and maps each admission grant to an exact principal
and allowed job intent; requests cannot add or replace either registry. A
worker must authorize the complete request, then resolve every allowed source
locally, revalidate ownership and permissions, and prepare credentials before
it acknowledges runnable admission. Missing/replaced/revoked source, denied or
changed grant, unsupported v2, client loss, or daemon restart fails closed; it
cannot silently create a normal v1 exec.

## Guest-agent v2

V1 readiness, exec, copy-in, and copy-out remain unchanged. The host does not
rewrite v1 requests to v2 and never retries v1 after a v2 failure.

V2 adds exact operations:

- `readiness` with required credential lifecycle capabilities;
- `credential_prepare`;
- `credential_renew`;
- `credential_revoke`; and
- `exec` with an opaque job credential binding.

The host sends `guest-agent-v2` directly. The v2 client may accept a
`guest-agent-v1` envelope only when it is the exact bounded
`unsupported_protocol_version` error for the matching request ID and operation;
that response is terminal. Every other response-version mismatch is malformed.
No v1 readiness proof, retry, environment fallback, or compatibility handoff
can satisfy L8.

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

V2 uses a dedicated persistent vsock port, not the v1 one-request-per-connection
listener. The accept boundary retains and validates `SockaddrVM`: the peer CID
must be `VMADDR_CID_HOST`, and the expected guest CID/port, Firecracker process,
runtime, vsock, boot, and image generations must match before a handshake. Peer
CID alone is not authentication because another host process could connect.

The worker daemon owns an Ed25519 controller identity in a separate sealed
Linux-keyring entry. Firecracker passes only its public key and safe key
generation in runtime-owned boot configuration; project/template/job input
cannot replace them. Before any untrusted exec, host and guest perform a
signed ephemeral X25519 handshake over the CID-checked stream. The transcript
covers both ephemeral keys, a guest boot nonce, controller-key generation,
guest CID and port, image digest, and every runtime/process/vsock generation.
HKDF derives directional AEAD keys. Every later frame has a monotonic
direction-specific sequence number and authenticated identity tuple; replay,
gap, wrap, bad tag, unexpected peer, reconnect, or transcript mismatch revokes
the session. Raw file payload and transient exec binding frames are encrypted.
Private controller keys never cross the protocol, and public boot material is
not a credential-delivery proof.

V2 exec is admitted only into the exact prepared job namespace on that
authenticated persistent session. V1 exec and a
v2 exec with a missing, stale, or neighboring binding cannot see L8 files or
sockets. Losing the authenticated v2 session revokes every job generation
owned by that session and notifies the host loss watcher.

## HTTP credential proxy

### Explicit non-MITM protocol

L6 CONNECT remains an opaque byte tunnel. L8 does not inspect TLS inside
CONNECT, install a guest CA, terminate arbitrary workload TLS, or inject a
header into a CONNECT stream. A credential ticket presented to generic CONNECT
fails closed and performs no secret lookup.

Credential-bearing HTTP uses one exact initial origin-form route on the same
L7-proven listener/topology:

```text
POST /.well-known/hal/credential-http/v1/azure-openai-responses-v1/
     deployments/<sealed-deployment>/responses?api-version=<sealed-version>
```

The two displayed lines are one URI. The deployment is the catalog's canonical
safe model/deployment token and the version is an exact catalog constant; no
other segment, query key, encoding, or value is admitted. The request authority
must exactly match the runtime-generated guest mapping for that listener;
absolute-form requests, CONNECT, userinfo, and any other authority cannot reach
it. The mapping is carried only in the transient exec binding and is never
durable. The workload sends a one-job ticket as the sole `api-key` header. The
handler strips it, selects the sealed definition, and makes its own separately
verified upstream TLS request. It never forwards the local authority, ticket,
or reserved prefix upstream.

An L8 Firecracker runtime/listener generation is exclusively leased to one
credential-aware worker job from prepare through cleanup. While that lease is
active, every other job and every v1 exec is rejected for that runtime; L8 does
not multiplex credential-aware jobs over one guest address or L7 listener.
Arrival on the exact listener therefore supplies the runtime/job attribution
that is rechecked with the ticket. A ticket replayed through another job's
runtime/listener generation has no matching activation or digest and fails
before source access. Processes within the admitted job intentionally share
that job's authority; the neighboring-job guarantee is not based on pretending
that a bearer ticket identifies individual processes inside one job.

The route accepts HTTP/1.1 only, one request per connection, a declared bounded
`Content-Length`, no transfer coding, no trailers, no upgrade, no hop-by-hop
headers, and canonical path/query encoding. The response is similarly bounded;
streaming entries may allow only event-stream framing with per-event and total
limits. Generic L6 HTTP and CONNECT remain byte-compatible for nonreserved
requests. The reserved prefix always fails locally when the L8 handler is
absent; it can never fall through to the generic forward proxy.

The neutral `applicationroute.Registry` registers singular leaf route handlers
and may deterministically order multiple leaves only when their prefixes do not
overlap. The Registry itself is the single composed `applicationroute.Handler`:
it returns sorted defensive copies of every registered definition, while L6
matches the parsed reserved path against those definitions and supplies the
exact selected route ID when handling the request. D1 does not add a path to
the live request or perform HTTP prefix parsing. The L6 `policyproxy.Config` D3
seam still receives at most one optional composed handler, so presenting the
Registry there does not widen L6 into a multiple-handler configuration surface.
A second Config handler, duplicate route ID, or overlapping Registry prefix is
a construction error. L6 owns parse, prefix selection, actual byte counting,
connection bounds, and stop ordering; L8 owns request authorization and
upstream behavior. D1 validates positive limit metadata, nonnegative
request/response counts, and overflow-safe comparisons. Enforcement as bytes
are read remains the L6/D3 handler and connection responsibility; neutral route
limits are not required to equal any service catalog's fixed production limits.

The composed handler is started before the listener becomes ready, loses
readiness with the L7 session, and is closed and awaited before the listener
reports stopped. A failed start stops admission and closes the failing handler
then every previously started handler in reverse order. Any failed close leaves
the Registry non-admitting in `cleanup_incomplete`; it cannot claim `closed`
until a later `Close` retries every unconfirmed handler and all closes succeed.
Raw start, close, and rollback causes are dropped in favor of stable sanitized
errors. The neutral contract contains bounded request/response streams and safe
metadata only, so `policyproxy` and `credentialproxy` never import one another.

### Static service registry

The live registry is worker-daemon-owned and immutable for a daemon generation.
A host administrator seals endpoint entries before the daemon accepts jobs. A
project, template, command request, binding, or guest cannot supply or override
an authority, port, TLS server name, authentication transform, redirect policy,
method set, or path policy. Durable metadata contains the safe service ID and
catalog generation only.

Every production entry fixes:

- stable service ID;
- canonical authority and port;
- TLS server name and trusted-root policy;
- exact authentication transformation;
- allowed methods and path shapes;
- request and response size bounds;
- allowed content handling; and
- redirect behavior, which is always disabled in L8.

The first implementation commit locks this initial production entry before a
live dialer:

| service ID | production consumer | local request | upstream transform |
| --- | --- | --- | --- |
| `azure-openai-responses-v1` | Hal's `internal/engine/pi` adapter using Pi provider `azure-openai-responses` | exact deployment-prefixed Responses route above with sealed `api-version`; ticket carried only in one `api-key` | map the exact local route to upstream `POST /openai/v1/responses` and replace the ticket with borrowed source bytes in `api-key`; JSON request and JSON/event-stream response only |

The host-admin entry fixes one upstream authority, TLS name/root policy,
deployment/path prefix, and API version for the daemon generation. Hal's Pi
adapter supplies the reserved local base URL as transient
`AZURE_OPENAI_BASE_URL` and the job ticket as transient
`AZURE_OPENAI_API_KEY`, and supplies the catalog's sealed
`AZURE_OPENAI_API_VERSION`. It constructs the exec environment from the fixed
guest baseline plus these three values, rather than inheriting host/project
provider variables; clears resource, deployment-map, base, key, proxy, and
other provider credential variables; and starts Pi with exact sealed
`--provider azure-openai-responses`, `--model <sealed-deployment>`, `--offline`,
`--no-extensions`, `--no-prompt-templates`, `--no-themes`, `--no-session`, and
no `--api-key`. It also points
`PI_CODING_AGENT_DIR` at an owned empty private directory so ambient model and
provider configuration cannot replace the catalog. These are an endpoint, safe
version, and opaque job capability, not a raw credential, and they are never
added to the serialized RPC exec, original request, durable job environment,
manifest, logs, or status. After v2 admission and active-proof inspection, the
worker clones the safe baseline and adds the three values only to the in-memory
`JobCredentialExecBinding` immediately before runtime `Exec`; that object is
destroyed before cleanup. The binding is available only inside the exact job
cgroup and mount namespace. Direct Pi `xai`, generic OpenAI-compatible, and
other providers are unsupported by this first entry and cannot count as L8
proof.

This split follows the installed Pi coding agent 0.82.1 behavior: Pi normalizes
the Azure Responses base to `/openai/v1`, its bundled Responses client appends
`/responses`, and its Azure deployment endpoint set does not include the
Responses operation. Consequently the local reserved route remains
deployment-prefixed and query-sealed for Hal admission, but the sealed upstream
path template is exactly `/openai/v1/responses`; Hal must not transform it to a
deployment-prefixed upstream Responses path.

The sealed invocation intentionally does not set `--no-context-files` or
`--no-skills`: repository instructions and text-only skills are explicit
workspace inputs needed for Hal's agent task, not provider configuration or
credential authority. The admission grant binds the exact workspace policy,
and neither input can change the command-line provider/model, sealed local
route, clean provider environment, network policy, or credential bindings.
Executable Pi extensions, prompt-template discovery, theme discovery, session
reuse, and ambient Pi configuration are disabled. D3 negative tests seed
project and global provider settings, executable extensions, prompt templates,
themes, sessions, and conflicting model/base/key variables and prove that none
can alter the sealed route or consumer; context/skill text remains ordinary
sandboxed workload input.

The production adapter is acceptance-tested against the fixture registry
without contacting Azure or any billed service. Tagged tests use a separate
fixture-only endpoint constructor that cannot enter production composition.
Unknown and empty catalogs fail closed; no arbitrary-public-host fallback is
allowed.

### Tickets and request path

A ticket is exactly 32 cryptographically random bytes encoded as
43 unpadded base64url characters. It is one job, service, binding, activation,
catalog, and L7 proof generation. Stores retain only an HMAC-SHA-256 digest
under a daemon-generation key and compare digests in constant time. Its sliding
lease is 60 seconds, worker renewal occurs no later than every 20 seconds,
maximum clock skew is 5 seconds, and hard lifetime is 35 minutes. Each ticket
permits at most 4 concurrent requests and 4096 total requests. It is invalidated
before cleanup begins and cannot be renewed after loss, expiry, hard lifetime, or
revocation.

The initial catalog fixes: 32 KiB request headers, 16 MiB JSON body, 32 KiB
response headers, 64 MiB total response, 2 MiB per SSE event, 5 minute read
idle, one request per connection, no retry by the proxy, and HTTP/1.1 ALPN only.
Values are construction constants, not project or job settings. Overflow or
timeout closes the upstream and returns only a safe reason code.

For every request the proxy:

1. validates framing, exact method/path/query, headers, bounds, ticket, sealed
   deployment/version, and exact job correlation without reading a secret;
2. re-inspects the exact active L7 listener, topology, and rule generations;
3. resolves all upstream DNS answers and rejects the entire result if any
   answer is private, metadata, loopback, link-local, special-use, or an unsafe
   NAT64 translation;
4. dials only a numeric address from the validated set;
5. verifies TLS with the sealed server name and trusted roots, with no
   `InsecureSkipVerify` or plaintext downgrade;
6. revalidates ticket and L7 proof immediately before secret access;
7. revalidates the JSON body model/deployment equals the sealed catalog token,
   obtains a borrowed locked view from the daemon-owned byte source, constructs
   the authentication line in a second bounded locked mapping, writes a sealed
   HTTP/1.1 request directly through `tls.Conn`, then overwrites both mappings;
   and
8. closes and revokes in-flight connections on ticket, network-proof, job, or
   runtime loss.

Client authentication headers other than the exact catalog-declared ticket
header, duplicate controlled headers, userinfo, trailers, upgrades, authority
override, arbitrary ports, and host/URL mismatch are rejected. The ticket
header is consumed locally and is never forwarded. The proxy never follows
redirects. Secret, ticket, authority, resolved address, header, path, body,
response payload, and raw TLS/DNS errors do not enter decisions or diagnostics.

## File-on-tmpfs delivery

The L8 image separates its service and workload identities. PID1 runs the guest
agent as dedicated UID/GID 998 and every workload as UID/GID 1000. The L8
isolation verifier takes the expected service identity explicitly; completed L5
images and their UID/GID-1000 verifier remain byte-compatible. Both identities
have empty capability sets and `no_new_privs`, and L8 never raises or restores
their privilege. Before dropping the agent, PID1 starts
`hal-guest-credential-helper` on one end of an inherited `SOCK_SEQPACKET`
socketpair. The helper bounding set is exactly
`CAP_SYS_ADMIN`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SETPCAP`, and `CAP_CHOWN`:
namespace/mount ownership, final child identity/capability drop, and file
ownership only. PID1 removes every other bounding/ambient capability.

PID1 gives the helper a private mount namespace, preopened fixed credential and
cgroup roots, and a minimal root containing only those mounts and required
runtime objects. The helper pivots into it before serving. Its seccomp profile
denies unrestricted `open`, `mount`, and pathname mutation, permits only the
fd-oriented mount API plus `openat2` beneath the fixed dirfds with
no-symlink/no-magic-link/no-cross-mount resolution, and allows `AF_UNIX` relay
sockets while denying network/vsock families, device opens, module/keyring
operations, ptrace/process-memory/pidfd-getfd/perf/BPF access, and arbitrary
namespace entry. Seccomp is not claimed to inspect pathname strings; root
confinement, fixed dirfds, protocol validation, and fd reinspection provide the
path boundary.

The socketpair has no filesystem name and both ends become close-on-exec after
the intended handoff. PID1 records the guest-agent PID in a pidfd. The helper
enables per-message credentials and requires every frame's SCM PID/UID/GID to
match that still-live pidfd and UID/GID 998, plus the boot/session nonce
established before privilege drop, strict credential-protocol frame, and
monotonic job generation. The guest agent is non-dumpable; PID1 mounts proc with
protected visibility before workload admission. Workload seccomp denies
ptrace, process-memory, pidfd-getfd, kcmp, perf, and BPF primitives. The
unprivileged guest agent owns no helper listener and passes file bytes through
bounded mutable locked frames without strings, generic marshalers, or logs.
Workloads never inherit either control FD or nonce. Helper or agent identity
loss invalidates readiness and every active proof; neither is restarted
in-place. The host stops and reaps that microVM before recovery may prove
absence.

Every credential-bearing job gets a private mount namespace used by its v2
exec operations. Preparation:

1. asks the helper to create a cgroup-v2 leaf and an owned mount namespace with
   a bounded keeper;
2. makes mount propagation private;
3. mounts a bounded tmpfs with `nodev,nosuid,noexec,mode=0700`;
4. creates a generation directory beneath a fixed agent-owned root;
5. opens every component with beneath, no-symlink, no-magic-link, and
   no-cross-mount resolution;
6. writes regular mode-`0600`, single-link files owned by the fixed workload
   identity from mutable buffers; and
7. atomically publishes and reinspects mount type/options, device boundary,
   ownership, mode, linkage, file count, cgroup, and generation identity.

Caller paths must be canonical relative names from a sealed binding schema.
Absolute paths, `..`, empty components, alternate separators, symlinks,
hardlinks, devices, FIFOs, sockets, caller-selected mount flags, and existing
unexpected entries fail closed.

Renewal never replaces files while a process may hold an old descriptor. L8
locks the simpler contract: renew only extends the activation lease; rotating
file content requires the current job cgroup to reach zero population (or the
microVM to be stopped) and a new credential generation to prepare before
another exec.

Every credential-aware v2 exec enters through the helper. The helper uses
race-free cgroup placement before the workload can execute, enters the exact
mount namespace, sets UID/GID 1000 with no supplementary groups, clears every
capability, applies `no_new_privs`, then launches the existing bounded
stdin/stdout/stderr supervision contract. Direct unprivileged-agent exec cannot
join a credential namespace. Job/process/file/FD/count/byte/time limits are
fixed at construction and are charged before allocation.

Revoke denies new exec, writes `1` to the exact job cgroup's `cgroup.kill`,
waits for `cgroup.events` to report `populated 0`, closes helper-owned
descriptors, unlinks files, destroys buffers, unmounts normally, proves mount
absence, stops/reaps the keeper, and removes the owned directory and cgroup.
Process-group termination alone is never L8 cleanup proof because a descendant
can call `setsid` or `setpgid`. If cgroup creation, race-free placement,
`cgroup.kill`, zero-population inspection, normal unmount, or helper inspection
is unavailable, cleanup stops and reaps the entire microVM; without that proof
the result is `credential_cleanup_incomplete`.
Lazy unmount is not successful cleanup proof.

## SSH-agent relay

SSH private keys remain in the host agent. L8 never copies a private key into a
guest, file, environment value, manifest, or protocol payload.

The relay uses a separate runtime/job-bound vsock stream; the existing framed
one-request/one-response guest control transport is not reused for a persistent
SSH-agent stream. The stream performs the same CID check and signed v2
handshake, then derives a relay-specific AEAD subkey. The helper creates and
accepts the guest Unix socket inside the job mount namespace, passes each
accepted connected FD plus exact job identity to the dedicated-UID guest agent
over authenticated `SCM_RIGHTS`, and closes its duplicate. The agent pumps only
the neutral bounded SSH codec between that FD and the authenticated host relay;
neither side accepts a second request on a connection until its response is
complete. Backpressure pauses reads rather than allocating unbounded queues.
The v2 control plane mints and revokes the opaque relay capability. The guest
socket is exposed to that job's v2 exec as transient `SSH_AUTH_SOCK`.

The host relay binds exact runtime, Firecracker process, vsock, job,
activation, and relay generations. Each binding requires a nonempty immutable
allowlist of public-key fingerprints and allowed signature algorithms/flags;
missing or empty policy fails preparation. On every new connection the relay
reopens only the configured host-agent identity, revalidates its peer identity,
filters enumeration to allowed key blobs, and rejects signing for every other
key or algorithm. It permits only filtered identity enumeration and signing.
Add, remove, remove-all, lock, unlock, extension, and unknown messages fail
closed. Frames, keys, signatures, concurrent streams, operations, and duration
are bounded: 4 connections, 1 outstanding request per connection, 256 KiB per
frame, 4096 operations per activation, 5 minute idle, and the same 35 minute
hard lifetime as the job ticket. The helper permits at most 16 credential
bindings, 64 KiB per file, 1 MiB aggregate file payload, and a 4 MiB tmpfs per
job. These fixed limits may be lowered by a sealed catalog but never raised by
a project, job, guest, or provider.

The relay never logs host or guest socket paths, public-key blobs, signature
payloads, comments, request bytes, or raw agent errors. Relay or v2 session
loss closes streams, removes the guest socket, cancels the job, and invalidates
proof. Cleanup proves host listener/connection and guest socket absence.

## Worker, execution, and recovery ordering

The L2 worker job lifecycle becomes:

1. derive the peer principal, strictly decode/validate the request, and
   authorize its complete grant/source/plan/binding/host/runtime/template/workspace
   intent without resolving a source;
2. persist the queued job plus safe authorized credential intent;
3. persist credential state `preparing`;
4. call optional `JobCredentialRuntime.PrepareJobCredentials` and mechanically
   inspect its exact proof;
5. persist only the sanitized active proof reference;
6. execute with the opaque transient binding;
7. renew from the heartbeat path and concurrently watch loss;
8. on expiry/loss, cancel and prove cgroup zero population or stop/reap the
   entire runtime;
9. revoke and prove cleanup on success, failure, cancel, timeout, daemon close,
   state-write failure, or runtime loss; and
10. only then persist terminal job outcome and release admission.

A nil lifecycle dependency preserves existing jobs with no live L8 intent. A
request for production L8 modes with a nil or unsupported dependency fails
before exec; it does not downgrade to environment or legacy delivery.

`internal/sandboxexecution.FinalizationCheckpoints` gains
`CredentialCleanup *FinalizationCheckpoint` with
`json:"credentialCleanup,omitempty"` before `Artifacts`. Nil means not
applicable and preserves the exact default `sandbox-finalization-v1` JSON for
older/no-credential manifests. Non-nil is required for live intent. Validation,
clone/sanitize helpers, `anyCheckpoint`, recovery, completion, timestamp order,
and transition code all treat it as the first checkpoint. With live intent,
artifacts, sync-out, lease release, and terminal publication cannot precede its
successful cleanup proof. The existing post-publication sync-out recovery
exception remains only after credential cleanup, artifacts, lease release, and
terminal publication; it can never bypass or reorder credential cleanup.

Worker restart reconciliation runs before accepting new jobs. Every durable
nonterminal credential reference is reconciled through the runtime. In-memory
tickets and buffers are already unusable after process death; reconciliation
does not reconstruct a secret or resume an exec. It reinspects and removes
owned guest/runtime resources. If the guest cannot be reauthenticated, the
runtime is stopped or quarantined and process termination is proved before
cleanup can complete.

## L8 guest asset profile

Guest protocol v2, tmpfs namespaces, and the guest relay are production guest
behavior and must exist in the immutable booted image. L8 therefore emits a
distinct reproducible guest profile and descriptor. It does not rewrite the L5
or L7 distributions, descriptors, or digests into a new capability claim.

The L8 builder preserves the complete L7 kernel/network configuration and adds
only the kernel/userland support mechanically required by the locked L8 guest
behavior. In addition to the exact source commit's guest agent, init, and
credential helper, it builds Buildroot's musl target `nodejs` 22.22.0 and
installs `@earendil-works/pi-coding-agent` 0.82.1 as `/usr/bin/pi`. The L8
source lock records the Node source archive, Pi package, its exact
`npm-shrinkwrap.json`, and every transitive npm archive by filename, size, and
SHA-256. Installation uses the verified cache under `--network=none`; floating
semver resolution, an online `npm install`, a host Pi tree, and an unrecorded
native or optional package are forbidden. The package is installed from a
clean offline dependency tree with lifecycle scripts disabled unless an exact
script and its outputs are separately locked.

The builder records the parent profile identity and the Node/Pi versions and
tree digests in safe provenance, runs final-image inspection, and performs two
independent offline builds with byte comparison. The L8 rootfs size is raised
by a fixed profile value sufficient for the locked runtime/package tree; it is
not host-derived. Host paths, build endpoints, credentials, and secret material
never enter provenance or artifacts. Final-image inspection uses debugfs to
prove regular root-owned, non-setuid `/usr/bin/node` and `/usr/bin/pi`, the
locked Pi package manifest/dependency-tree digest, no package-manager cache,
and no credential/config/session material. It never executes rootfs content on
the host.

Prepared acceptance boots only the fresh digest-locked L8 distribution. It
first executes the image's exact `/usr/bin/node` and `/usr/bin/pi --version`
through credential-aware v2 and requires the locked versions. The HTTP-only
and all-modes cases then execute that exact guest `/usr/bin/pi` process with the
sealed clean environment and arguments against the owned TLS fixture, and the
fixture must observe the expected real Pi Azure Responses request. A host Pi,
adapter-only request generator, or copied Pi test double cannot satisfy the
gate. Small file and SSH protocol probes may be compiled by the test harness,
copied into the guest workspace through the existing bounded copy contract,
and executed through v2 with the exact job binding. They are not installed in
the production image and are not accepted as proof without the live L8 runtime,
guest, network, and cleanup correlations.

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
- `active` requires an inspected unexpired `JobCredentialActiveProof` and exact
  correlation;
- `renewing` is not warning-free active proof;
- loss, expiry, revoke, cleanup warning, or identity mismatch removes active
  modes immediately; cleanup state may appear only from a separately validated
  `JobCredentialCleanupProof`; and
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
  expiry, loss, mutually exclusive active/cleanup proofs, and cleanup ordering.
- Red tests for Linux-keyring source registration/direct reads and races,
  anonymous locked mapping ownership, page-lock success/failure, full-capacity
  overwrite, unmap, process startup dumpability, string/JSON/log exclusion, and
  cancellation.
- Red tests for server-derived authenticated principals and immutable
  admission-grant authorization before source resolution, including
  missing/wrong-UID/wrong-GID peers, caller-supplied principal/grant
  substitution, unauthorized
  source/plan/binding/template/workspace intent, grant revision/restart races,
  non-enumeration, and request-key correlation.
- Lock distinct `job_*_v2` operations and strict `sandboxjob-v2`,
  request-key/idempotency credential identity, unknown-field rejection, exact
  old-daemon failure, and no v1 retry.
- Lock the neutral reserved application-route handler, live stream
  non-serialization, safe positive metadata/bounds, and collision/lifecycle
  cleanup-retry semantics before either L6 or L8 implementation imports it.
- Lock the initial host-owned HTTP service catalog before a live dialer exists.

### D2 — guest v2 and privileged-helper contracts

- Preserve v1 byte/behavior compatibility.
- Reject v2-to-v1 downgrade, wrong host CID/key/generation, handshake/frame
  replay or tamper, unknown fields, stale revisions, cross-job identity,
  overflows, and malformed private payloads.
- Lock the neutral lifecycle/SSH codec, signed ephemeral v2 handshake,
  dedicated service/workload identities, exact-PID socketpair authentication,
  helper fd-root/capability/seccomp boundary, cgroup-v2 placement/kill proof,
  numeric resource limits, and stop-VM fallback before live helper or
  guest-agent behavior.

### D3 — HTTP credential route

- Implement the exact ticket format/lease/limits, HMAC store, and sealed
  deployment/version registry before network behavior.
- Implement the Pi Azure Responses hardening flags, clean environment, sealed
  model, post-admission transient runtime binding, exact deployment-prefixed
  local request framing mapped to upstream `/openai/v1/responses`, and
  destination/TLS/raw-HTTP/1.1 hardening with local verified-TLS fixtures.
- Integrate the optional route into L6 and prove generic HTTP/CONNECT unchanged.

### D4 — guest tmpfs

- Replace the D0 recursive command blanket only for the exact
  `hal-guest-agent`, `hal-guest-init`, and `hal-guest-credential-helper`
  composition files that this slice needs. Lock their allowed L8 imports and
  constructors file by file; keep every root command and `sandboxd*.go` path
  forbidden until D6 and every other command file forbidden throughout L8.
- Implement the PID1 child, protected proc, agent pidfd/socketpair, helper
  pivot/fd/seccomp exec/cgroup boundary, and namespace/tmpfs behavior through
  injected syscall fakes first.
- Cover namespace/mount flags, path traversal and replacement races, partial
  prepare, open-descriptor rotation, `setsid` escape, cgroup kill/zero-populated
  proof, teardown retry, helper loss, whole-VM fallback, and orphan recovery.

### D5 — SSH relay

- Lock AEAD relay subkeys, SCM_RIGHTS handoff, backpressure, numeric limits,
  operation policy, and mandatory key/algorithm allowlists before host/guest
  streams.
- Cover replay, generation mismatch, per-connection agent peer revalidation,
  filtered enumeration, key/flag rejection, bounds, loss, and cleanup.

### D6 — Firecracker and worker lifecycle

- Compose v2, HTTP, tmpfs, relay, process/vsock, and L7 generations.
- Wire prepare/renew/loss/revoke around worker exec and recovery.
- Add the optional finalization cleanup checkpoint, existing post-publication
  sync-out ordering, and conservative active-versus-cleanup projections.

### D7 — prepared-Linux acceptance

- Run each mode alone, all modes together, neighboring-job negatives, every
  terminal/failure/restart path, durable canary scans, and zero-resource
  cleanup against the exact phase head.
- Prove the locked Node/Pi files in the fresh image and execute the exact guest
  Pi Azure Responses consumer against the owned local TLS fixture.
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

During execution L10 consumes only warning-free, unexpired
`JobCredentialActiveProof` correlated to the exact L3 job, L5 runtime, L7
network session, L9 immutable template, and workspace state. After execution it
must discard active proof and require the mutually exclusive
`JobCredentialCleanupProof` before terminal secure completion. Cleanup is not
expected or claimed while authority is active. Corrupting, conflating, or
omitting either phase's identity makes strict composition fail closed.
