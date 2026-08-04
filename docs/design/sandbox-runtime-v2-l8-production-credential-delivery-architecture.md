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
- `internal/sandboxruntime/microvm/guestagent` keeps the frozen v1 contract.
  Its leaf child `session` owns only the authenticated binary session, and
  sibling `v2control` owns strict v2 control unions, compatibility negotiation,
  and the injected client. Neither child changes a v1 production file.
- `cmd/hal-guest-credential-helper` is the narrow process entrypoint and PID1
  bootstrap adapter. It contains no independently testable privilege or
  lifecycle policy.
- `internal/sandboxruntime/microvm/guestagent/credentialhelper` owns the
  testable privileged service policy for per-job cgroups, mount namespaces,
  credential files, the restricted guest SSH endpoint, credential-aware exec,
  and cleanup outcomes. D2 keeps it contract/fake-only; D4 adds the Linux
  implementation behind those boundaries.
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

The optional root runtime boundary has these exact Go shapes:

```go
type JobCredentialRuntime interface {
	PreflightJobCredentials(context.Context, JobCredentialIdentitySeed) (JobCredentialRuntimePreflight, error)
	RecoverJobCredentials(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error)
}

type JobCredentialRuntimePreflight interface {
	Identity() JobCredentialIdentity
	PrepareJobCredentials(context.Context, JobCredentialPrepareRequest) (JobCredentialSession, error)
	Abort(context.Context) (JobCredentialCleanupProof, error)
	Loss() <-chan JobCredentialLoss
}

type JobCredentialSession interface {
	ExecBinding() JobCredentialExecBinding
	ActiveProof() JobCredentialActiveProof
	Renew(context.Context) (JobCredentialActiveProof, error)
	Revoke(context.Context, JobCredentialRevokeReason) (JobCredentialCleanupProof, error)
	Loss() <-chan JobCredentialLoss
}
```

`JobCredentialPrepareRequest` carries an exact complete safe identity, a
sanitized plan, explicit binding metadata, the accepted admission-grant
identity/revision, and
a worker-local `LiveSecretSource` selected from authorized safe source
references. The source is never serializable. Command-to-worker requests carry
only safe source-reference and admission-grant IDs; neither kind of ID is a
bearer capability. The command never transports raw bytes, a callback, a live
endpoint, or a reusable authorization secret. This makes job admission and
recovery independent of command-process lifetime.
`ExecBinding` contains only ephemeral capabilities needed by the exact exec;
it is not copied into the durable `Job`.

D2 completes the neutral identity before guest proofs exist. In addition to the
D1 fields, `JobCredentialIdentity` and its canonical proof digest bind required
`TemplatePolicyID`, `WorkspacePolicyID`, `ControllerKeyGeneration`,
`GuestBootGeneration`, `GuestImageGeneration`, `GuestImageDigest`,
`GuestSessionGeneration`, and `GuestHelperGeneration` safe fields. The
admission request and accepted grant carry the same template/workspace values.
`GuestImageDigest` is exactly the ASCII prefix `sha256-` followed by exactly 64
lowercase hexadecimal characters. The handshake carries the decoded 32-byte
suffix; uppercase, `sha256:`, base64, abbreviated, or alternate-algorithm forms
are invalid.

The complete identity is acquired through an explicit two-stage neutral seam;
it is never synthesized before guest authentication. The seed type is exact:

```go
type JobCredentialIdentitySeed struct {
	SandboxID, ExecutionID, WorkerID, HostID                 string
	RuntimeDriver, RuntimeID, RuntimeGeneration              string
	FirecrackerProcessGeneration, VsockGeneration            string
	WorkerJobID, SubmissionID, PlanID                        string
	ActivationGeneration, CredentialGeneration               string
	NetworkPlanID, PolicySnapshotID                          string
	ProxySessionID, ProxyGenerationID                        string
	TopologyGenerationID, RuleGenerationID                   string
	AdmissionGrantID, PrincipalID                            string
	TemplatePolicyID, WorkspacePolicyID                      string
	ControllerKeyGeneration, GuestBootGeneration             string
	GuestImageGeneration, GuestImageDigest                   string
	AdmissionGrantRevision                                   uint64
	BindingIDs                                               []string
	DeliveryModes                                            []JobCredentialDeliveryMode
	IssuedAt                                                 time.Time
}
```

`JobCredentialIdentity` has those fields in that order plus
`GuestSessionGeneration` and `GuestHelperGeneration` immediately after
`GuestImageDigest`. `JobCredentialRuntime.PreflightJobCredentials`
accepts only a validated seed and returns one opaque, nonserializable
`JobCredentialRuntimePreflight`. That preflight retains the exact authenticated
control session and exposes:

- `Identity() JobCredentialIdentity`, which must equal the seed field-for-field
  and add only the two nonempty guest generations;
- `PrepareJobCredentials`, which is the only preparation call and uses that
  same authenticated session;
- `Abort`, which closes a preflight that did not transfer ownership to a
  successful `JobCredentialSession`; and
- `Loss`, which closes preparation on authenticated-session/helper loss.

The pure root identity API is exact:

```go
func ValidateJobCredentialIdentitySeed(JobCredentialIdentitySeed) error
func CloneJobCredentialIdentitySeed(JobCredentialIdentitySeed) (JobCredentialIdentitySeed, error)
func CompleteJobCredentialIdentity(JobCredentialIdentitySeed, string, string) (JobCredentialIdentity, error)
func ValidateJobCredentialIdentityCompletion(JobCredentialIdentitySeed, JobCredentialIdentity) error
func ValidateJobCredentialIdentity(JobCredentialIdentity) error
func JobCredentialIdentityDigest(JobCredentialIdentity) ([32]byte, error)
```

The two strings passed to `CompleteJobCredentialIdentity` are the authenticated
guest-session and helper generations in that order. The seed validator requires
every seed field and applies the same mode-dependent network rules as the
complete validator without mutating its input. The clone helper validates and
returns a field-for-field value with fresh ordered binding/mode slices; callers
never duplicate this root-owned cloning logic. Completion validates the seed,
deep-copies ordered binding/mode slices, adds only those two generations, and
validates the result. Completion validation independently compares every seed
field and ordered slice before accepting both added generations. `Identity()`
returns a defensive deep copy. `GuestSessionGeneration` is exactly 43
unpadded-base64url characters that decode to 32 bytes; helper generation uses
the safe-ID grammar. There is deliberately no seed digest: a seed is not a
proof, wire identity, authorization token, or bearer capability, and only the
complete identity has the canonical digest below.

The worker persists the validated, privately cloned seed with the queued job
before calling preflight. The durable representation is the package-private
`sandboxworker.storedJobStateV2.CredentialState` field with JSON tag
`credentialState,omitempty`; it is never added to public `JobV2`:

```go
type storedJobCredentialStateV2 struct {
	ContractVersion string                                `json:"contractVersion"`
	Seed            storedJobCredentialIdentitySeedV1     `json:"seed"`
	Identity        *storedJobCredentialIdentityV1        `json:"identity,omitempty"`
	Revision        uint64                                `json:"revision"`
}
```

`ContractVersion` is exactly `sandboxjob-credential-private-v1`. The two
private DTOs use the exact lower-camel JSON field order of the canonical
`JobIdentity` below; the seed omits only `guestSessionGeneration` and
`guestHelperGeneration`. They have no exported conversion outside
`internal/sandboxworker`. Conversion calls the root validators and clone helper,
strict decoding rejects unknown/duplicate/trailing fields, and every load/save/
list path returns fresh slices. `CredentialState` is nil for no-live-intent
jobs. With live intent it is first atomically saved with seed, nil identity,
and revision zero. After preflight validation, the same record atomically adds
the complete identity while retaining the seed; activation/renewal atomically
updates revision. It is removed only in the same or a later durable write after
valid cleanup proof. A crash at any earlier write therefore retains enough
private correlation for seed-only stop/reap or complete-identity recovery.
The existing 64 KiB stored-record cap includes this field; exceeding it fails
before preflight, and tests lock maximum and plus-one encodings. Store/status/
logs/command-result sanitizers and public JSON tests prove `credentialState`,
`seed`, and complete private identity never appear outside the owner-only store.

The seed is safe durable recovery input but is never public status, a proof, or
a command-result JSON field; the preflight handle is never durable. Preflight
receives no live source and cannot create a credential job, read a credential
value, or publish an active proof. Its only valid return
is a non-nil, non-typed-nil handle with nil error. Any error must return a nil
handle after closing its attempted host session; the worker nevertheless
stops/reaps the exact runtime before terminal persistence. A non-nil handle
with error or a nil/typed-nil handle with nil error is a contract violation and
also forces exact stop/reap.

On successful return, the worker starts the preflight `Loss()` watcher before
calling `Identity`, validation, persistence, source resolution, or prepare.
The preflight channel emits exactly one value then closes; one worker-owned
goroutine receives it and stores an in-memory terminal latch, so closed-channel
zero values and competing consumers cannot lose or duplicate it. Its identity
is the defensive `Identity()` value, revision is exactly one, and its code is
only `credential_identity_mismatch`, `credential_expired`, or
`credential_guest_helper_unavailable`. Before `BeginPrepare`, any latched loss
requires abort followed by exact stop/reap; it is never applied to a nonexistent
lifecycle. After `BeginPrepare`, the worker first applies it through
`ObserveLoss` and then cleans up. The same latch remains observable until
ownership transfers, so no nonblocking receive may consume and discard it.
The worker validates completion, persists the complete identity, constructs
the lifecycle, and calls `BeginPrepare` before resolving the authorized live
source handles.

`PrepareJobCredentials` has an exact ownership matrix. A non-nil,
non-typed-nil `JobCredentialSession` with nil error atomically transfers all
prepared state to that session. The preflight and session loss channels expose
the same terminal latch; the worker transfers its watcher without a gap or
duplicate event. A nil/typed-nil session, any non-nil error, or a session plus
error leaves ownership with preflight and requires `Abort`. Once transfer
occurs, an invalid active proof requires `JobCredentialSession.Revoke`, not
preflight abort.

Preflight owns an internal atomic state `open`, `preparing`, `transferred`, or
`aborted`. `PrepareJobCredentials` and `Abort` linearize on that state. Prepare
may publish a session only by changing `preparing` to `transferred`; if abort or
loss wins first it returns nil session plus `ErrJobCredentialTransition` after
creating no state. If transfer wins, abort returns that error and touches
nothing. Loss is latched before making the same ownership decision and is then
handled by the winning owner. No prepared resource can exist between owners.

`Abort` is idempotent before transfer and returns the same valid complete-
identity `JobCredentialCleanupProof` after proving session/helper/job-resource
absence. After a successful `BeginPrepare`, its root proof revision is exactly
two: the worker calls `BeginRevoke`, validates the proof at an injected
observation time not before `AbsenceInspectedAt` and no more than
`MaxJobCredentialCleanupObservationAge` later, then calls lifecycle `Revoke`.
`RevokedAt` is not before identity issue time and `AbsenceInspectedAt` is not
before `RevokedAt`. Repeated abort on the same live handle returns the identical
proof for immediate idempotent completion; a stale proof is never refreshed by
that handle and instead forces stop/reap or ordinary recovery reinspection.
If the
preflight identity itself cannot be validated, no cleanup proof can validate
against it: abort is still attempted, then exact runtime stop/reap supplies the
absence evidence. After transfer, `Abort` returns
`ErrJobCredentialTransition` without touching session-owned state. Guest/helper
revision one is preparation correlation; it maps to root cleanup revision two
when a begun preparing lifecycle aborts. Abort/loss
that cannot produce valid absence proof escalates to D6's exact whole-VM
stop/reap path. A daemon crash before complete-identity persistence is recovered
by unconditionally stopping/reaping the exact runtime named by the durable seed;
after complete persistence, ordinary `RecoverJobCredentials` proves cleanup.
A nil preflight dependency preserves only jobs with no live L8 intent and can
never fabricate generation fields.

The guest-session generation is the unpadded base64url session ID derived only
after the authenticated handshake; it identifies but does not independently
authorize that session. The helper generation is accepted only from
authenticated readiness on that session. Raw boot nonce, session keys,
private/public keys, helper nonce, CID, ports, and live handles do not enter the
neutral identity or durable/status projection. Root active and cleanup proof
tokens commit to every added field, and the Firecracker adapter proves lossless
order-preserving mapping to `credentialprotocol.JobIdentity`.

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
worker Unix connection carries exactly one request and one response. Every
request writer must successfully write-half-close after its single JSON request
so EOF is the request-frame boundary; failure is terminal. The official client
does this before reading, and the server closes the connection after its single
response. The server does not dispatch a
complete-looking prefix before that EOF, and neither side multiplexes another
JSON value on the connection. A peer that omits the half-close cannot cause
partial dispatch and remains blocked only until that peer closes or server
context cancellation promptly closes the connection and cleans up. A
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

The three guest ports are fixed production constants and cannot be selected by
project, template, job, guest, provider, or command input:

```text
GuestAgentV1Port = 1024
GuestAgentV2ControlPort = 1025
GuestAgentV2SSHRelayPort = 1026
```

Port 1024 and every v1 request, response, client, listener, frame, and
one-request connection remain byte- and behavior-compatible. V2 never connects
to port 1024. On port 1025 it opens one persistent stream and first writes this
exact two-field compatibility preface as one length-framed JSON object:

```json
{"protocolVersion":"guest-agent-v2","operation":"readiness"}
```

The 512-byte compatibility limit applies to the preface JSON payload (516 bytes
including the four-byte outer length). After consuming it, a v2 guest
immediately emits the length-framed binary `GuestHello` defined below; there is
no separate plaintext v2 JSON acknowledgement. The host reads the next outer
frame with the 4096-byte handshake bound. A payload beginning with `HL8H` must
be the exact valid `GuestHello`. A payload beginning with `{` is considered
only as the legacy exception, must be no larger than the 512-byte JSON payload
compatibility limit, and is accepted only when it is byte-for-byte the
canonical JSON encoding of the frozen v1 unsupported-version envelope below.
Every other prefix or payload is terminal.

```json
{"protocolVersion":"guest-agent-v1","operation":"readiness","error":{"code":"unsupported_protocol_version","operation":"readiness","field":"protocolVersion","message":"guest agent protocol version is unsupported"}}
```

This exception uses same-stream positional correlation with the one in-flight
`readiness` preface: no request ID exists in the frozen v1 envelope. It is a
terminal `credential_protocol_unsupported` result, never admission. An absent
port-1025 listener, any other v1 envelope, any near-miss field, a response on a
new stream, or any v2 negotiation failure is terminal and cannot trigger a v1
readiness request, retry, downgrade, environment fallback, or compatibility
handoff. Receiving and validating `GuestHello` is the only successful v2
classification. After the authenticated handshake, every encrypted application
request and response has an exact echoed request ID.

Each lifecycle request carries the full identity and generation tuple, a
monotonic revision, bounded expiry, and exact ordered mode/binding
declarations. The child `credentialprotocol.JobIdentity` is a data-only wire
mirror mapped losslessly at the Firecracker host boundary; it does not import
the root `sandboxruntime` package. The signed handshake binds a base guest
session identity containing the host-generated guest-session boot nonce and
generation, controller signing-key generation, expected CID, fixed channel
port, image digest/generation,
runtime ID/generation, Firecracker process generation, and vsock generation.
`GuestCredentialSessionIdentity` then contains that base session ID, the exact
job identity, and helper-session generation. Every application request, proof,
and helper packet binds its canonical digest; no post-handshake field is
pretended to have been present in the earlier signed transcript.

The network fields are mode-dependent rather than filled with sentinel IDs.
HTTP-proxy mode requires the complete network tuple: network plan, policy
snapshot, proxy session, proxy generation, topology generation, and rule
generation. Mixed mode has the same requirement when any binding is HTTP.
Conversely, file-only and SSH-only modes require that tuple to be absent.
Changing this validation is an intentional D2 correction to the D1 neutral
contract and must retain order-sensitive binding/mode correlation. The same
mode-dependent rule applies independently in
`credentialsource.validAdmissionRequest`; D2 changes and cross-tests both
validators so file-only and SSH-only admission do not require invented network
IDs and HTTP or mixed admission cannot omit them.

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
cannot replace them. The host also generates and retains the 32-byte
guest-session boot nonce, passes the same value only through runtime-owned boot
configuration, and rejects a `GuestHello` that does not echo it. This nonce is
distinct from the PID1/helper-local boot nonce below and neither is durable or
project-selectable. Before any untrusted exec, host and guest perform a
signed ephemeral X25519 handshake over the CID-checked stream. The transcript
covers both ephemeral keys, a guest boot nonce, controller-key generation,
guest CID and port, image digest, and every runtime/process/vsock generation.
HKDF derives directional AEAD keys. Every later frame has a monotonic
direction-specific sequence number and authenticated identity tuple; replay,
gap, wrap, bad tag, unexpected peer, reconnect, or transcript mismatch revokes
the session. Raw file payload and transient exec binding frames are encrypted.
Private controller keys never cross the protocol, and public boot material is
not a credential-delivery proof.

### Normative guest-session wire contract

Handshake suite `0x0001` is X25519, pure Ed25519, SHA-256,
HKDF-SHA-256, HMAC-SHA-256, and AES-256-GCM using the Go standard-library
implementations. A strict prepared-Linux proof additionally requires hardware
AES-GCM acceleration visible to the host and guest. This avoids extending D2
with a second cryptographic dependency or making a timing claim that the
portable Go GCM implementation cannot support. Go cryptographic objects may
retain internal copies that expose no destruction API; the physical-zeroization
disclaimer above applies, while every Hal-owned mutable input, derived byte
buffer, and plaintext buffer is still overwritten and logically released.

The handshake order is exact:

1. plaintext `GuestHello`;
2. plaintext signed `ControllerAuth`;
3. encrypted guest-to-controller `Finished` at sequence 0;
4. encrypted controller-to-guest `Finished` at sequence 0; and
5. application records begin at sequence 1 independently in each direction.

No application decode, dispatch, helper call, or mutation occurs until both
Finished messages validate. A pre-authentication failure closes the stream and
emits no plaintext alert. The handshake and Finished deadline is 5 seconds.

Each plaintext handshake record is `uint32_be(innerLength) || inner`.
`innerLength` is 1 through 4096; zero, overflow, truncation, and trailing bytes
are rejected before allocation. The common inner header is:

```text
offset  size  field
0       4     ASCII "HL8H"
4       1     wire version 1
5       1     type: 1 GuestHello, 2 ControllerAuth
6       2     reserved zero, big-endian
```

Every variable token is `uint16_be(length) || ASCII bytes`, length 1 through
128, matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` exactly, with no trimming,
Unicode, normalization, defaulting, or case folding. Job-identity fields retain
their narrower neutral safe-ID validator.

`GuestHello` appends:

```text
suite:u16_be = 1
channel:u8 = 1 control, 2 ssh-relay
reserved:u8 = 0
guestX25519Public:[32]byte
guestBootNonce:[32]byte
guestCID:u32_be
guestPort:u32_be
controllerKeyGeneration:token
runtimeID:token
runtimeGeneration:token
firecrackerProcessGeneration:token
vsockGeneration:token
bootGeneration:token
imageGeneration:token
imageSHA256:[32]byte
```

`imageSHA256` is exactly the 32 decoded bytes of the complete identity's
`GuestImageDigest` `sha256-` suffix.

The fixed local guest CID is 3. On accept, the guest also retains the separate
peer `SockaddrVM` and requires its CID to be `VMADDR_CID_HOST`; it queries and
validates the local CID/port rather than confusing the peer's ephemeral port
with the fixed local port. Channel 1 requires port 1025. Channel 2 requires port
1026 and appends `jobGeneration`, `activationGeneration`, and
`relayGeneration` tokens. The relay performs a separate handshake; it never
reuses control keys.

The unsigned `ControllerAuth` appends suite 1, the matching channel, a zero
reserved byte, and the 32-byte controller ephemeral X25519 public key. Its wire
form then appends the 64-byte Ed25519 signature. Let `guestInner` and
`controllerUnsignedInner` be the exact inner records, without outer lengths or
the signature, and let `opaque16(s)` mean `uint16_be(len(s)) || ASCII(s)`:

```text
transcript =
    opaque16("hal/l8/guest-session/transcript/v1") ||
    uint32_be(len(guestInner)) || guestInner ||
    uint32_be(len(controllerUnsignedInner)) || controllerUnsignedInner

TH = SHA256(transcript)

signatureInput =
    opaque16("hal/l8/guest-session/controller-signature/v1") || TH
```

The guest verifies pure Ed25519 over `signatureInput` with the exact pinned
32-byte controller public key and matching generation from runtime-owned boot
configuration. X25519 shares are exactly 32 bytes; malformed and low-order
shares and every ECDH failure are terminal. Derivation is:

```text
SS = X25519(localEphemeralPrivate, peerEphemeralPublic)
sessionID = SHA256(opaque16("hal/l8/guest-session/id/v1") || TH)
PRK = HKDF-Extract(SHA-256, secret=SS, salt=TH)
```

HKDF Expand info is one raw ASCII label below, without a length prefix or NUL:

```text
hal/l8/guest-session/<channel>/controller-to-guest/key/v1
hal/l8/guest-session/<channel>/guest-to-controller/key/v1
hal/l8/guest-session/<channel>/controller-to-guest/nonce-prefix/v1
hal/l8/guest-session/<channel>/guest-to-controller/nonce-prefix/v1
hal/l8/guest-session/<channel>/controller-to-guest/finished-key/v1
hal/l8/guest-session/<channel>/guest-to-controller/finished-key/v1
```

`<channel>` is exactly `control` or `ssh-relay`. Keys and Finished keys are 32
bytes; nonce prefixes are 4 bytes. The secure record header and wire form are:

```text
offset  size  field
0       4     ASCII "HL8F"
4       1     wire version 1
5       1     frame type
6       2     flags zero, big-endian
8       8     sequence, uint64 big-endian
16      4     ciphertextLength, uint32 big-endian, includes 16-byte tag
20      32    sessionID

wire = header[52] || ciphertextAndTag[ciphertextLength]
AAD = ASCII("hal/l8/guest-session/frame-aad/v1\x00") || header[52]
nonce = derivedNoncePrefix[4] || uint64_be(sequence)
```

Frame types are `0x01 guest_finished` guest-to-controller,
`0x02 controller_finished` controller-to-guest, `0x10 control_request`
controller-to-guest, `0x11 control_response` and `0x12 control_event`
guest-to-controller, and `0x13 control_private` controller-to-guest. On the
control channel, `0x14 control_stream` is direction-constrained by its inner
stream kind. On the relay, `0x20 relay_request` is guest-to-controller and
`0x21 relay_response` is controller-to-guest; `0x7f close_notify` is valid in
either direction. `0x13` carries one binary `HL8B` record only; it never
multiplexes JSON into `0x10` or another type. `0x14` carries one binary `HL8S`
record only. Magic, version, zero flags, channel/type/direction, session ID,
expected sequence, and length are validated before allocation or AEAD open.

Finished plaintexts are these exact 32-byte HMACs, encrypted with the matching
direction at sequence 0 and compared in constant time after GCM succeeds:

```text
guestVerify = HMAC-SHA256(
    guestToControllerFinishedKey,
    opaque16("hal/l8/guest-session/<channel>/guest-finished/v1") || TH || sessionID)

controllerVerify = HMAC-SHA256(
    controllerToGuestFinishedKey,
    opaque16("hal/l8/guest-session/<channel>/controller-finished/v1") || TH || sessionID)
```

Application control plaintext is at most 2 MiB and relay plaintext is at most
256 KiB; these are plaintext payload bounds, so complete encrypted wires are
2,097,220 and 262,212 bytes respectively after the 52-byte header and 16-byte
GCM tag. Private file payloads remain separately typed and bounded to 64 KiB
per binding and 1 MiB aggregate.
Every encrypted control request carries a 16-byte random request ID rendered in
JSON as exactly 22 unpadded base64url characters, its canonical job/session
identity digest, operation, and body. Responses echo the same request ID and
identity digest. Safe JSON control uses strict known-field decoding and a
canonical fixed-field re-encoding for idempotency; raw file payload and opaque
exec bindings use separate binary private records and never generic JSON,
base64, formatting, or errors.

Each direction has an independent `uint64` counter. Finished consumes zero;
the first application record is one. Receipt must equal the next expected
value: lower is replay and higher is a gap. Counters advance only after
authentication and semantic validation, and writers are serialized. The hard
per-direction cap is `2^32` total encrypted records, legal sequences zero
through `2^32-1`; the session closes before another record. Replay, gap,
duplicate, cap/wrap attempt, bad tag, wrong direction/type, partial write,
truncation, decode failure, or post-handshake identity drift closes and revokes
the session before payload mutation.

There is no resumption or transparent reconnect. While one session is active,
a second connection for the same generation is rejected before handshake and
cannot invalidate or perturb the active session. After EOF, timeout,
Firecracker process or socket replacement, generation drift, or authentication
failure, the failed session becomes permanently non-admitting, logically
releases session material, notifies the loss watcher, and revokes every job
generation it owned. A reconnect under that same generation is terminal; a
later job requires a new runtime/session generation rather than reconstructing
live state.

Before a session authenticates, a malformed connection is closed without
claiming the generation or mutating guest/job state. At most three pre-auth
connections, each under the five-second deadline, are allowed for one boot
generation; reaching that cap makes readiness false and requires exact VM
stop/reap. The official controller performs one attempt and never retries or
falls back. The first successfully authenticated session exclusively claims
the generation, after which every loss/failure is permanently non-reconnectable
as above.

The root `MaxJobCredentialLifetime` one-hour value remains a generic neutral
ceiling. L8 adds `MaxGuestCredentialSessionLifetime = 35 minutes`: handshake
time, every guest job activation/expiry, ticket hard expiry, helper/keeper
state, and SSH relay hard expiry must fit inside it. The 60-second ticket lease,
20-second renewal cadence, and five-second skew allowance never extend the
35-minute hard expiry.

The D2 implementation locks one deterministic suite-1 control vector. The guest
is RFC 7748 Alice and the controller is Bob. Full inputs are:

```text
guest X25519 private = 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
guest X25519 public  = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
controller X25519 private = 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
controller X25519 public  = de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
controller Ed25519 seed   = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
controller Ed25519 public = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

The boot nonce is bytes `00..1f`, CID 3, port 1025, image SHA-256
`5756b67946a36d1e78ce0b3ae6f1131ead840b828d41b334de1594a7c8a00687`,
and the tokens `controller-key-gen-1`, `runtime-1`, `runtime-gen-1`,
`process-gen-1`, `vsock-gen-1`, `boot-gen-1`, and `image-gen-1`. The required
canonical encodings are:

```text
GuestHello outer length = 000000d9
GuestHello inner =
484c384801010000000101008520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000003000004010014636f6e74726f6c6c65722d6b65792d67656e2d31000972756e74696d652d31000d72756e74696d652d67656e2d31000d70726f636573732d67656e2d31000b76736f636b2d67656e2d31000a626f6f742d67656e2d31000b696d6167652d67656e2d315756b67946a36d1e78ce0b3ae6f1131ead840b828d41b334de1594a7c8a00687

ControllerAuth unsigned inner =
484c38480102000000010100de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f

ControllerAuth outer length = 0000006c
signatureInput =
002c68616c2f6c382f67756573742d73657373696f6e2f636f6e74726f6c6c65722d7369676e61747572652f76315ca9d78096d266d650caef23a7619548039feffcd6ef4d4636d8e330c3c9591a
signature =
f40a8509d1881897bfd0838d2008290d71287a45ab92a811450e71a74b26243766c6e1a62de2a1a13064cbd8c8f512cd9be8dd49ed840c4fe765468eb5d27600
ControllerAuth wire = outer length || unsigned inner || signature
```

The required intermediate/output values are:

```text
SS = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
TH = 5ca9d78096d266d650caef23a7619548039feffcd6ef4d4636d8e330c3c9591a
signature = f40a8509d1881897bfd0838d2008290d71287a45ab92a811450e71a74b26243766c6e1a62de2a1a13064cbd8c8f512cd9be8dd49ed840c4fe765468eb5d27600
sessionID = 8bb2532307629fb19302a9e5ee11490e8c9f2265f030bcc46a13391dc9759efb
PRK = ba5a837774445109cd4be8509cbc19261278240efe08f5882e8f32c2b926c2a4
controller-to-guest key = 1dc71db6479a93a9fa784b8aa4e6fa94997fb7d9dbbc7ac549087bc06e04c9b1
guest-to-controller key = 2a0ca1e4bf700414c0af68a90d46086a3dc075a314f4a3d0349f1066f775e52f
controller-to-guest nonce prefix = 525309e4
guest-to-controller nonce prefix = 3737cc07
controller-to-guest Finished key = 6296f230589ee300af728605d996be1d5deb7724c6f0a1fbbb59e34b2325df07
guest-to-controller Finished key = 538a2ed25a05b640e8aa35b1e7ca989d428949e8198030232866d139ad762e6f
guestVerify = 7869fb8ddfac62aaa8a8a59febda424eb1d31834e2ba89d433ba69ef17c763f2
controllerVerify = 4489107525a59d2174bfed691601ce21f6389420f3151cdc26c65f23f9c797dd
```

The exact encrypted vectors are:

```text
guest Finished wire =
484c3846010100000000000000000000000000308bb2532307629fb19302a9e5ee11490e8c9f2265f030bcc46a13391dc9759efbfb955227d8d3bf927f66b3e947f3dd2608bc81ba3070ab22d1aef360e6579366d5e79ee66d83dcf5234495deaf608cae

controller Finished wire =
484c3846010200000000000000000000000000308bb2532307629fb19302a9e5ee11490e8c9f2265f030bcc46a13391dc9759efbdacd029fbeabc81d3644fc6c194f5ade5082bcf21140d99a286ea0ca7d730267bfe2fb9806023953216d89368c00ec23

controller-to-guest application plaintext at sequence 1 = bytes 00..1f
nonce = 525309e40000000000000001
header =
484c3846011000000000000000000001000000308bb2532307629fb19302a9e5ee11490e8c9f2265f030bcc46a13391dc9759efb
ciphertext and tag =
5a7ea7228a09f92f035b0bd61133da82428eb55e9a5c2d54004927c84edecc39cf4512c772cbf1ad10e9a6c317411a34
```

That final item is deliberately a session-layer plaintext vector, not a v2
control-envelope fixture; request ID, identity digest, and operation-union
canonicalization have separate exact codec vectors.

Tests lock the full GuestHello, ControllerAuth, both Finished frames, and the
sequence-1 application ciphertext—not only these abbreviated display values—
and independently recompute them from the normative encoding above. Each
transcript identity, signature, X25519 share, Finished tag, sequence, session
ID, header field, length boundary, and reconnect state has a mutation-negative
test.

### Normative v2 control unions

`v2control` uses canonical JSON only for safe control metadata. The encoder
emits fields in the order below with no insignificant whitespace. The decoder
first rejects invalid UTF-8, unknown/case-aliased/duplicate/null/trailing
fields, noninteger or alternate numeric encodings, excessive depth, and bounds;
it then re-encodes and requires byte equality. It uses concrete discriminated
structs—never `map[string]any`, `json.RawMessage`, or an interface body.

Every request has this root field order:

```json
{"protocolVersion":"guest-agent-v2","operation":"<operation>","requestId":"<22-char-base64url>","identityDigest":"<43-char-base64url>","body":{}}
```

Every response has the same first four fields followed by `ok`. Success has one
operation-specific `body` and omits `error`; failure has no `body` and one
`error` with exact field order `code`, optional `field`, and `message`. Error
codes/messages are the closed pairs below and never wrap a cause:

```text
malformed_request     "credential request is malformed"
unknown_operation     "credential operation is unsupported"
request_conflict      "credential request conflicts with prior state"
identity_mismatch     "credential identity does not match"
revision_stale        "credential revision is stale"
expired               "credential request is expired"
resource_limit        "credential request exceeds a fixed limit"
prepare_failed        "credential preparation failed"
renew_failed          "credential renewal failed"
revoke_failed         "credential revocation failed"
exec_failed           "credential execution failed"
helper_unavailable    "credential helper is unavailable"
cleanup_incomplete    "credential cleanup is incomplete"
```

Only `malformed_request` may include `field`, which is a static schema field
path produced by the concrete decoder and never input text or a value; every
other code omits it. The operation/code matrix is closed:

```text
readiness:          malformed_request, request_conflict, identity_mismatch,
                    helper_unavailable
credential_prepare: malformed_request, request_conflict, identity_mismatch,
                    revision_stale, expired, resource_limit, prepare_failed,
                    helper_unavailable, cleanup_incomplete
credential_renew:   malformed_request, request_conflict, identity_mismatch,
                    revision_stale, expired, renew_failed, helper_unavailable
credential_revoke:  malformed_request, request_conflict, identity_mismatch,
                    revision_stale, revoke_failed, helper_unavailable,
                    cleanup_incomplete
exec:               malformed_request, request_conflict, identity_mismatch,
                    revision_stale, expired, resource_limit, exec_failed,
                    helper_unavailable
safe unknown token: unknown_operation only
```

A known operation with any other code is invalid. Root decoding first accepts
only a 1..64-byte lowercase token matching `[a-z][a-z0-9_]*`. A syntactically
safe but unknown token is not body-decoded and receives the concrete
unknown-operation failure struct echoing that token. An unsafe/unreadable
operation closes the session without response because it cannot be safely
echoed. The five known request unions remain closed.

The exact envelope orders are
`protocolVersion,operation,requestId,identityDigest,ok,body` for success and
`protocolVersion,operation,requestId,identityDigest,ok,error` for failure. The
16-byte request ID is nonzero. The 32-byte digest is unpadded base64url and is the base
session ID itself for readiness or the exact
`GuestCredentialSessionIdentity` digest for job operations. Responses echo
operation, request ID, and digest byte-for-byte.

The child `JobIdentity` JSON order is the root neutral field order:

```text
sandboxId, executionId, workerId, hostId, runtimeDriver, runtimeId,
runtimeGeneration, firecrackerProcessGeneration, vsockGeneration,
workerJobId, submissionId, planId, activationGeneration,
credentialGeneration, networkPlanId, policySnapshotId, proxySessionId,
proxyGenerationId, topologyGenerationId, ruleGenerationId,
admissionGrantId, principalId, templatePolicyId, workspacePolicyId,
controllerKeyGeneration, guestBootGeneration, guestImageGeneration,
guestImageDigest, guestSessionGeneration, guestHelperGeneration,
admissionGrantRevision, issuedAtUnixNano, bindings
```

`bindings` is an ordered nonempty array of exact `{bindingId,mode}` objects.
The digest is SHA-256 over eight-byte big-endian length plus bytes for every
string above through `guestHelperGeneration`, then big-endian `uint64`
admission revision, big-endian `uint64(issuedAtUnixNano)`, big-endian binding
count as `uint64_be`, and the same length-plus-bytes encoding for each ordered
binding ID then mode. The root and child expose validated digest functions;
conformance tests prove equality, and no package copies an undocumented digest
variant.

`GuestCredentialSessionIdentity` is exactly the current 32-byte session ID plus
that validated `JobIdentity`. Its `JobIdentity.guestSessionGeneration` must be
the 43-character unpadded base64url encoding of the same session ID. Its digest
is `SHA256(opaque16("hal/l8/guest-credential-identity/v1") || sessionID ||
jobIdentityDigest)`. It is live-only; durable proof tokens commit to the root
job-identity digest and safe session generation, never the raw wrapper or
session keys.

Operation strings are exactly `readiness`, `credential_prepare`,
`credential_renew`, `credential_revoke`, and `exec`. Their concrete body field
orders and types are fixed below. Angle-bracket names denote the concrete
objects defined immediately afterward, not generic JSON values:

```text
readiness request:
  {requiredCapabilities:[string], expectedServiceUID:uint32,
   expectedServiceGID:uint32, expectedWorkloadUID:uint32,
   expectedWorkloadGID:uint32, helperProtocol:string}
readiness success:
  {capabilities:[string], serviceUID:uint32, serviceGID:uint32,
   workloadUID:uint32, workloadGID:uint32, helperProtocol:string,
   guestSessionGeneration:string, helperGeneration:string}

credential_prepare request:
  {identity:<JobIdentity>, revision:uint64, expiresAtUnixNano:int64,
   bindings:[<BindingManifest>], privateRecordCount:uint32,
   privateAggregateBytes:uint64}
credential_prepare success:
  {revision:uint64, expiresAtUnixNano:int64, activeProofId:string,
   execBindingId:string, bindingProofs:[<BindingProof>]}

credential_renew request:
  {identity:<JobIdentity>, revision:uint64, expiresAtUnixNano:int64,
   priorProofId:string}
credential_renew success:
  {revision:uint64, expiresAtUnixNano:int64,
   replacementActiveProofId:string}

credential_revoke request:
  {identity:<JobIdentity>, revision:uint64, reason:string}
credential_revoke success:
  {revision:uint64, cleanupProofId:string, authorityAbsent:bool,
   resourcesAbsent:bool, cleanupDisposition:string}

exec request:
  {identity:<JobIdentity>, revision:uint64, execBindingId:string,
   plan:<ExecPlan>, privateRecordCount:uint32,
   privateAggregateBytes:uint64, privateAggregateSha256:string}
exec success:
  {revision:uint64, exitCode:int32, stdinBytes:uint64, stdinSha256:string,
   stdoutBytes:uint64, stdoutSha256:string, stdoutTruncated:bool,
   stderrBytes:uint64, stderrSha256:string, stderrTruncated:bool,
   execTransactionSha256:string}
```

Readiness capabilities are exactly this order:
`credential_lifecycle,credential_exec_binding,helper_exact_pid,file_tmpfs,ssh_agent`.
The request uses service UID/GID 998, workload UID/GID 1000, and helper protocol
`guest-helper-v1`; success echoes those values, derives the 43-character guest
session generation from `sessionID`, and returns the authenticated helper safe
ID.

`JobIdentity` uses the field order listed above, with every scalar represented
as its declared JSON string/integer type and `bindings` as ordered concrete
`{"bindingId":string,"mode":string}` objects. A `BindingManifest` is one of
three concrete objects, each with exactly the shown field order:

```text
HTTP: {bindingId:string, mode:"http_proxy", serviceId:string}
file: {bindingId:string, mode:"file_tmpfs", targetPath:string,
       declaredFileBytes:uint32, fileSha256:string}
SSH:  {bindingId:string, mode:"ssh_agent", sshPolicyId:string,
       sshPolicyRevision:uint64}
```

File SHA-256 is exactly 64 lowercase hexadecimal characters. Target-path rules
are the helper rules below. The SSH policy ID/revision select only immutable
host-admin policy and expose no fingerprint. A `BindingProof` is exactly
`{"bindingId":string,"mode":string,"proofId":string}` and appears in manifest
order with one entry per binding. Every `JobIdentity` JSON key is always
present. For file/SSH-only jobs the network tuple
`networkPlanId,policySnapshotId,proxySessionId,proxyGenerationId,topologyGenerationId,ruleGenerationId`
is six empty strings and its digest therefore encodes six zero lengths. A job
with HTTP, including mixed mode, requires all six nonempty safe IDs. Omission,
`null`, or a partly populated tuple is invalid. Both root and child validators
apply this identical rule.

The initial production catalog permits at most one HTTP binding in a job. File
bindings may use the remaining binding slots, and SSH has its separately
bounded policy. A second HTTP binding fails admission before source resolution;
this version therefore needs no repository-selected binding index and the one
HTTP binding unambiguously supplies the single Pi environment trio.

Prepare revision is exactly 1. Renew revision is exactly prior plus one. Revoke
uses the current revision and reason `requested`, `expired`, `session_loss`,
`source_revoked`, `worker_cancel`, or `daemon_shutdown`. Revoke success requires
both booleans true and `cleanupDisposition="cleanup_complete"`. All proof and
binding IDs use the safe-ID grammar. Expiries are positive signed Unix
nanoseconds inside both the 35-minute session limit and root lifetime.

`ExecPlan` is exactly:

```text
{args:[string], env:[<Environment>], workDir:string,
 stdinMaxBytes:uint32, stdoutMaxBytes:uint32, stderrMaxBytes:uint32,
 timing:<Timing>}

Environment = {name:string, source:string, value:string}
Timing timeout = {kind:"timeout_millis", value:int64}
Timing deadline = {kind:"deadline_unix_millis", value:int64}
```

Arguments, environment, path, stream, aggregate, and timing bounds match the
binary helper `ExecPlan` below. Environment source is `literal`, `inherited`,
or `generated`; `secret` is forbidden. Values contain no credential binding.
Only generated entries may use the four names `HTTP_PROXY`, `HTTPS_PROXY`,
`http_proxy`, and `https_proxy`; all four are present exactly once and equal the
same already-proved L7 proxy base URL. Every other name uses
`[A-Z_][A-Z0-9_]*`. The three protected Pi names
`AZURE_OPENAI_BASE_URL`, `AZURE_OPENAI_API_KEY`, and
`AZURE_OPENAI_API_VERSION` are forbidden in `ExecPlan`; the helper constructs
them only from the authenticated private binding. Neither JSON nor helper
`ExecPlan` contains stdin bytes.

Exec success is emitted only after the three stream EOF rules below and child
exit. Exit code is nonnegative. Byte counts and truncation flags exactly match
the streamed data; each SHA-256 string is 64 lowercase hexadecimal characters,
including SHA-256 of empty input/output when the count is zero. The response
contains no stdin/stdout/stderr content.

Repeating the same request ID plus identical canonical bytes is idempotent. For
exec, "canonical bytes" means the complete control/private/stdin logical
transaction and its helper-computed transaction digest, not merely the JSON
request or initial `0x15` body; reusing an ID with different bytes, changing any
identity field, stale/gapped revision, expiry outside the job/session window,
or a response mismatch closes and revokes the session. Readiness has no job and
cannot authorize prepare by itself.

Prepare private-record count equals the number of file bindings, zero through
16, with aggregate at most 1 MiB. Exec private-record count is exactly one when
the prepared manifest contains its permitted single HTTP binding and zero
otherwise; aggregate is at most 64 KiB. `privateAggregateSha256` is the SHA-256
of the exact kind-2 `HL8B` plaintext payload, or SHA-256 of empty bytes when
count is zero; its lowercase hex form must match before helper dispatch. Renew,
revoke, readiness, and every response require
both private fields absent and accept no private record.

Sensitive data uses an encrypted binary private record inside `HL8F`, never a
JSON field. Its plaintext header is exactly:

```text
magic[4]="HL8B" | version:u8=1 | kind:u8 | flags:u16_be=0
requestID:[16]byte | identityDigest:[32]byte | bindingIndex:u16_be
chunkIndex:u16_be | chunkCount:u16_be | reserved:u16_be=0
payloadLength:u32_be | payloadSHA256:[32]byte | mutable payload
```

Kinds are 1 file bytes and 2 opaque exec binding. File bindings use one record,
so chunk index is zero and count one; the explicit fields reject accidental
future chunking without a protocol version. Exec-binding records have binding
index zero and the same zero/one chunk rule. Payload is at most 64 KiB and the
aggregate/count exactly match the preceding control request. Digests, request
ID, identity, index, order, count, and length validate before a sink receives
bytes. Any mismatch aborts the request and wipes every owned buffer.

Kind 2 contains this exact mutable binary payload:

```text
httpBindingCount:u16
for each HTTP binding in manifest order:
  bindingIndex:u16 | serviceID:token | localBaseURL:blob16 |
  ticket:blob16 | apiVersion:token
```

The count is exactly one and equals the sole HTTP binding. `localBaseURL` is
canonical ASCII, 1..512 bytes, and exactly
`http://<runtime-owned-authority>/.well-known/hal/credential-http/v1/azure-openai-responses-v1/deployments/<sealed-deployment>`
with no trailing slash, `/responses`, query, fragment, or userinfo. Ticket is
exactly the 43-byte unpadded-base64url
job capability. API version and service ID use the token grammar and must match
the sealed catalog. The record contains no upstream endpoint or raw source
credential. The guest agent treats it as opaque mutable bytes; only the
authenticated helper decodes it to construct the three selected transient
environment values, then wipes it.

Every `HL8B` record is the entire plaintext of one `0x13 control_private`
frame, controller-to-guest on the control session. Exactly the count declared
by the preceding `0x10 control_request` follows it at consecutive secure
sequences and before any response or unrelated application frame. File records
are ordered by binding index; the optional exec-binding record has index zero.
Zero declared records forbid `0x13`. Missing, extra, reordered, interleaved, or
wrong-request private frames close and revoke the session before any sink sees
bytes.

Exec stream bytes use one `0x14 control_stream` frame per binary `HL8S`
plaintext record:

```text
magic[4]="HL8S" | version:u8=1 | streamKind:u8 | flags:u16_be
requestID:[16]byte | identityDigest:[32]byte | offset:u64_be
payloadLength:u32_be | payloadSHA256:[32]byte | mutable payload
```

The fixed header is 100 bytes. Stream kind is 1 stdin, 2 stdout, or 3 stderr.
Flags are zero or exactly 1 (`EOF`). Non-EOF payload is 1..64 KiB and its
SHA-256 must match; EOF has zero payload, the SHA-256 of empty bytes, and the
next contiguous offset. Stdin is controller-to-guest only; stdout/stderr are
guest-to-controller only. Offsets begin at zero and advance without gap or
overlap. Aggregate bytes cannot exceed the matching declared stream maximum.

Exactly one stdin EOF and one stdout/stderr EOF belong to the outstanding exec
request. No new control request may interleave, although the three stream kinds
may interleave at ordinary monotonically increasing secure-frame sequences.
The controller sends an immediate zero-offset stdin EOF when input is empty.
The guest emits stdout/stderr EOF only after the helper closes those pipes and
emits the JSON exec response only after both EOF records and child exit. Output
beyond a declared maximum is drained under the fixed process limit, not sent,
and sets the matching truncation flag. Every owned chunk buffer is wiped after
authenticated write/read on success and every failure path.

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

D2 extends the already-merged neutral route request before D3. The exact live,
nonserializable shapes are:

```go
type RequestTarget struct {
	Authority string
	Path      string
	RawQuery  string
}

type RequestHeaderValues interface {
	Names() []string
	ValueCount(name string) int
	CopyValue(name string, index int, destination []byte) (int, error)
}

type Request struct {
	Metadata RequestMetadata
	Target   RequestTarget
	Headers  RequestHeaderValues
	Body     io.Reader
}
```

L6 supplies an origin-form canonical ASCII path, canonical raw query without
`?`, and canonical authority without userinfo; path and query are each at most
4096 bytes and authority at most 512. `Names` returns a sorted defensive copy of
unique lowercase canonical header names, at most 128 names and 256 bytes each;
`ValueCount` preserves duplicates. `CopyValue` accepts only a listed name and
index, writes no partial value, returns only the exact byte count on success,
and overwrites the whole caller-owned destination on every failure. A value is
at most the route's header bound. Implementations never return a header value as
`string` or owned `[]byte`, and request formatting/JSON/text/error paths expose
none of target, names, values, or body. D3 copies only the sole 43-byte
`api-key` value into locked mutable storage; it uses names/counts to reject
duplicate or competing authentication/authority headers before source access.
Nil/typed-nil header access, invalid canonical target, a name/value mismatch,
or a route prefix that does not match `Target.Path` fails dispatch.

The neutral `applicationroute.Registry` registers singular leaf route handlers
and may deterministically order multiple leaves only when their prefixes do not
overlap. The Registry itself is the single composed `applicationroute.Handler`:
it returns sorted defensive copies of every registered definition, while L6
matches the parsed reserved path against those definitions and supplies the
exact selected route ID plus the D2 `RequestTarget` and header accessor when
handling the request. D1 intentionally added no target data; D2 adds only this
bounded live seam and still performs no HTTP parsing itself. The L6
`policyproxy.Config` D3 field is exactly
`ApplicationRoutes applicationroute.Handler`. Nil means disabled; typed nil is
a construction error. There is one field and no slice, callback, or second
handler, so presenting the Registry there does not widen L6 into a
multiple-handler configuration surface.
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

This split follows the installed Pi coding agent 0.82.1 behavior precisely.
Its Azure adapter rewrites only recognized Azure host suffixes with an empty,
`/`, `/openai`, or `/openai/v1/responses` path to `/openai/v1`; it preserves
Hal's runtime-local reserved base unchanged. The bundled Responses client then
appends `/responses` and the Azure client appends the sealed `api-version`
query. The Azure deployment endpoint set does not include Responses, so it does
not insert another deployment segment. Therefore the injected local base ends
exactly at `/deployments/<sealed-deployment>`, the observed local request is the
deployment-prefixed route above, and Hal's proxy alone transforms that route to
the sealed upstream `/openai/v1/responses` path.

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
without contacting Azure or any billed service. Tagged tests use exactly
`credentialproxy/fixturetest.NewOwnedAzureResponsesCatalog`, defined only in
the `internal/credentialproxy/fixturetest` package behind the L8 live build tag.
Source guards allow that package only from `_test.go`, reject it from every
production import graph, and reject any fixture catalog passed to the command or
daemon constructor. No other fixture endpoint constructor exists.
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

The D2 bootstrap contract resolves process-identity ordering explicitly. PID1
creates the seqpacket socketpair, enables `SO_PASSCRED` on both endpoints,
creates a 32-byte random helper-local boot nonce and start-gate pipe, and starts
the helper first. The helper rechecks `SO_PASSCRED`, fixed descriptors,
generation, and hardening, then sends `helper_ready`; PID1 verifies the exact
known helper PID/UID/GID before doing anything else. A bootstrap can never be
queued before that ready message.

PID1 then creates the guest agent with `clone3(CLONE_PIDFD)` behind the gate and
sends one atomic bootstrap datagram from exact PID 1, UID 0, and GID 0. It
carries exactly one `SCM_RIGHTS` descriptor: the agent pidfd. The helper treats
the trusted PID1 packet as the binding between that pidfd and the reported
agent PID/UID/GID 998, proves current liveness with
`pidfd_send_signal(pidfd, 0, nil, 0)` and a non-readable/non-hung-up poll, and
records both. It does not claim that pidfd alone reveals a numeric PID. PID1
verifies the correlated bootstrap acknowledgement and only then releases the
agent gate and closes its control duplicate.

The sealed start-gate record gives the agent the expected helper PID/UID/GID,
helper and boot generations, nonce, and bootstrap digest. The agent verifies
those exact `SCM_CREDENTIALS` on every helper response; socket EOF is permanent
helper loss, so PID reuse cannot acquire the unshared socketpair endpoint. The
helper requires every later request's one credentials record to match the
recorded agent and its still-live pidfd. `MSG_TRUNC`, `MSG_CTRUNC`, missing or
duplicate credentials, unexpected rights, extra file descriptors, stale
boot/helper/job generation, replay, sequence gap, and sequence wrap fail
closed. Any received descriptor is closed on every rejection path.

Inherited descriptor numbers are fixed. The helper receives control socket 3,
credential-root `O_PATH` directory 4, delegated cgroup-v2 `O_PATH` directory 5,
minimal-root `O_PATH` directory 6, and sealed read-only bootstrap config 7,
which it closes after validation. It reserves internal fixed slots 8 for the
one active job's mount namespace, 9 for its cgroup directory, 10 for the keeper
pidfd, and 11 for a child start gate. The agent receives control socket 3 and
the sealed start-gate/config read end 4. All unrelated descriptors are closed;
intended descriptors become close-on-exec after bootstrap, and no workload
inherits a control, root, namespace, cgroup, pidfd, config, or nonce descriptor.

The neutral helper packet codec is one seqpacket datagram with a fixed header:

```text
magic[4] = "HL8P" | version:u8 = 1 | type:u8 | flags:u16_be = 0
sequence:u64_be | requestID:[16]byte | bodyLength:u32_be
guestCredentialIdentityDigest:[32]byte | bootNonce:[32]byte | body
```

The fixed header is 100 bytes. `bodyLength` is payload bytes only, must equal the
remaining datagram, and is at most 72 KiB; therefore the complete maximum
datagram is 73,828 bytes. A private file body remains at most 64 KiB. Integer
body fields are big-endian. A body token uses the handshake token encoding and
grammar; a body blob is `uint32_be(length) || bytes` with a type-specific bound.
Timestamps are signed Unix nanoseconds. Booleans are exactly zero or one.

Packet type numbers, directions, sequence starts, and bodies are fixed:

```text
0x01 helper_ready      helper -> PID1, seq 0, empty body
0x02 bootstrap         PID1 -> helper, seq 0,
                       agentPID:u32 | agentUID:u32 | agentGID:u32 |
                       bootGeneration:token | helperGeneration:token
0x03 bootstrap_ack     helper -> PID1, seq 1, bootstrapSHA256:[32]byte
0x04 agent_hello       agent -> helper, seq 1,
                       bootstrapSHA256:[32]byte | bootGeneration:token |
                       helperGeneration:token
0x05 agent_hello_ack   helper -> agent, seq 2, bootstrapSHA256:[32]byte
0x10 prepare_begin     agent -> helper, revision:u64 | expiryUnixNano:i64 |
                       bindingCount:u16 | ordered binding manifest
0x11 prepare_file      agent -> helper, revision:u64 | bindingIndex:u16 |
                       fileLength:u32 | fileSHA256:[32]byte | private bytes
0x12 prepare_commit    agent -> helper, revision:u64 | manifestSHA256:[32]byte
0x13 renew             agent -> helper, revision:u64 | expiryUnixNano:i64 |
                       priorProofID:token
0x14 revoke            agent -> helper, revision:u64 | reason:u8
0x15 exec              agent -> helper, revision:u64 | execBindingID:token |
                       privateBindingLength:u32 | privateBindingSHA256:[32]byte |
                       bounded binary ExecPlan
0x16 ssh_accepted_fd   helper -> agent, revision:u64 | bindingIndex:u16 |
                       connectionOrdinal:u8 | relayCapabilityDigest:[32]byte
0x17 exec_private      agent -> helper, revision:u64 | privateBindingLength:u32 |
                       privateBindingSHA256:[32]byte | mutable private binding
0x18 exec_stream       either direction, revision:u64 | streamKind:u8 |
                       flags:u8 | reserved:u16=0 | offset:u64 |
                       payloadLength:u32 | payloadSHA256:[32]byte | mutable payload
0x20 response          helper -> agent, requestType:u8 | disposition:u8 |
                       revision:u64 | failureCode:u8 | typed result union
0x21 event             helper -> agent, eventCode:u8 | revision:u64 |
                       eventID:token
0x7f close_notify      either direction, reasonCode:u8
```

Numeric body catalogs are closed and reject zero or unknown values except
`failureCode=0` on success:

```text
revoke reason: 1 requested, 2 expired, 3 session_loss, 4 source_revoked,
               5 worker_cancel, 6 daemon_shutdown
response disposition: 1 accepted, 2 rejected, 3 cleanup_complete,
                      4 cleanup_retry, 5 stop_vm_required
failure code: 0 none, 1 malformed, 2 identity_mismatch, 3 revision_stale,
              4 expired, 5 resource_limit, 6 prepare_failed, 7 renew_failed,
              8 revoke_failed, 9 exec_failed, 10 cleanup_incomplete,
              11 helper_unavailable
event code: 1 expired, 2 session_loss, 3 source_revoked, 4 cleanup_required
close reason: 1 normal, 2 protocol_error, 3 identity_drift, 4 expired,
              5 helper_loss, 6 shutdown
```

Response `requestType` is exactly `0x12` for the logical prepare transaction,
`0x13` renew, `0x14` revoke, or `0x15` exec. After the common fields, a
successful response has exactly one request-type result:

```text
prepare accepted:
  expiresAtUnixNano:i64 | activeProofID:token | execBindingID:token |
  bindingProofCount:u16 |
  each manifest-ordered bindingID:token | mode:u8 | proofID:token
renew accepted:
  expiresAtUnixNano:i64 | replacementActiveProofID:token
revoke cleanup_complete:
  cleanupProofID:token | authorityAbsent:u8=1 | resourcesAbsent:u8=1
exec accepted:
  exitCode:i32 | stdinBytes:u64 | stdinSHA256:[32]byte |
  stdoutBytes:u64 | stdoutSHA256:[32]byte | stdoutTruncated:u8 |
  stderrBytes:u64 | stderrSHA256:[32]byte | stderrTruncated:u8 |
  execTransactionSHA256:[32]byte
```

Prepare proof count equals the manifest and every identity/mode/proof is exact.
Exec byte counts, all four digests, and zero/one truncation flags match the
`0x15`/`0x17`/`0x18` transaction and streams. `accepted` is valid only for
prepare, renew, and exec;
`cleanup_complete` only for revoke. These successful dispositions require
failure code zero. `rejected`, `cleanup_retry`, and `stop_vm_required` have no
trailing result bytes and require a nonzero failure code. Unknown request types,
disposition/type combinations, trailing bytes, and noncanonical booleans fail
before state mutation.

The wire-to-neutral cleanup mapping is closed: disposition
`cleanup_complete` maps to neutral `cleanup_complete`, wire `cleanup_retry`
maps to neutral `retry_required`, and wire `stop_vm_required` maps to neutral
`stop_vm_required`. `accepted` and `rejected` are never cleanup results. No
other spelling, default, or success inference is permitted.

The ordered manifest record is:

```text
bindingID:token | mode:u8 | targetPath:optional-relative-path | declaredFileBytes:u32 | fileSHA256:[32]byte
```

Modes are 1 HTTP, 2 file-tmpfs, and 3 SSH-agent. Only file mode has a target,
nonzero declared bytes, and nonzero digest; the others encode the optional
relative path as length zero and both numeric/digest fields as zero. A relative
path is `uint16_be(length) || ASCII bytes`, length 1..4096, with forward-slash
separated components of 1..255 bytes. It rejects a leading/trailing slash,
empty, `.` or `..` components, backslash, NUL/control bytes, and any alternate
encoding; joining and cleaning it must return the identical relative bytes.
There are at most 16 unique bindings, 64 KiB per file, and 1 MiB aggregate.

The `ExecPlan` body is encoded exactly in this order:

```text
argumentCount:u16
arguments[argumentCount]: blob16
environmentCount:u16
environment[environmentCount]: name:blob16 | source:u8 | value:blob16
workDirectory:blob16
stdinMode:u8 | stdoutMode:u8 | stderrMode:u8
stdinMaxBytes:u32 | stdoutMaxBytes:u32 | stderrMaxBytes:u32
timingKind:u8 | timingValue:i64
```

`blob16` is `uint16_be(length) || bytes`. Argument count is 1..128; each
argument is valid UTF-8, at most 8192 bytes, contains no NUL/control byte, and
argument zero is not blank. Environment count is 0..256. Source is 1 literal,
2 inherited, or 3 generated; secret/zero/unknown values are forbidden. Each
unique ordinary name is 1..128 ASCII bytes matching `[A-Z_][A-Z0-9_]*` and each
value is 0..8192 bytes without NUL. Only source 3 may instead name exact
`HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, or `https_proxy`; all four occur
exactly once with the same value fixed to the already-proved L7 proxy base URL.
The three protected Pi names are forbidden in the binary plan just as they are
in JSON. The work directory is 1..4096-byte canonical absolute
UTF-8 and passes the frozen v1 guest-path rules. All three modes are exactly 1
(`pipe`) and every maximum is 1..4 MiB. No pipe descriptor crosses the helper
control socket; stdin bytes never appear in `ExecPlan`.

`timingKind` is 1 (`timeout_millis`) or 2 (`deadline_unix_millis`). Its signed
value is positive and must satisfy the frozen L4 timing bounds plus the current
35-minute job/session hard expiry. No zero/unused bytes or alternate union
encoding exist. The complete encoded `ExecPlan`, including counts and lengths,
is at most 64 KiB so the exec body fits its 72 KiB helper bound; this L8
aggregate may be stricter than v1 without changing v1. Direct
credential-bearing environment names/values are forbidden; the helper
constructs selected credential bindings only from its prepared live state.

The helper hashes have exact domain-separated encodings. Let
`bootstrapHeader` be the exact 100-byte `0x02` header (including zero request
ID/identity digest, sequence zero, body length, and boot nonce),
`bootstrapBody` its canonical body, and `manifestBytes` the concatenation of
the ordered encoded manifest records:

```text
bootstrapSHA256 = SHA256(
  opaque16("hal/l8/guest-helper/bootstrap/v1") ||
  bootstrapHeader || bootstrapBody)

manifestSHA256 = SHA256(
  opaque16("hal/l8/guest-helper/manifest/v1") ||
  uint16_be(bindingCount) || manifestBytes)

transactionSHA256 = SHA256(
  opaque16("hal/l8/guest-helper/prepare-transaction/v1") ||
  guestCredentialIdentityDigest || uint64_be(revision) ||
  int64_be(expiryUnixNano) || manifestSHA256 || uint16_be(fileCount) ||
  for each file in ascending binding index:
    uint16_be(bindingIndex) || uint32_be(fileLength) || fileSHA256)

stdinSHA256 = SHA256(concatenated stdin payload bytes)

stdinTranscriptSHA256 = SHA256(
  opaque16("hal/l8/guest-helper/stdin-transcript/v1") ||
  uint32_be(stdinRecordCount) ||
  for each stdin record, including the final EOF, in offset order:
    flags:u8 || uint64_be(offset) || uint32_be(payloadLength) ||
    payloadSHA256 || payload)

execTransactionSHA256 = SHA256(
  opaque16("hal/l8/guest-helper/exec-transaction/v1") ||
  guestCredentialIdentityDigest || uint64_be(revision) ||
  uint32_be(execBodyLength) || exact canonical 0x15 body ||
  uint32_be(privateBindingLength) || privateBindingSHA256 ||
  uint64_be(stdinBytes) || stdinSHA256 || stdinTranscriptSHA256)
```

The single ancillary pidfd and kernel credentials are verified independently;
unstable numeric FD values never enter `bootstrapSHA256`. Every file's bytes
must hash to its declared digest before `transactionSHA256` is accepted. The
request ID is an independent idempotency key and does not enter either logical
transaction digest. `stdinSHA256` hashes stream content only, including the
ordinary SHA-256 of empty input. `stdinTranscriptSHA256` additionally binds
chunk boundaries, offsets, per-chunk digests, content, and the unique EOF, so a
rechunked replay is not identical. The exact canonical `0x15` body already
binds the exec plan, private length/digest, revision, and exec binding ID.

Ready, bootstrap, bootstrap-ack, and both hello packets require an all-zero
request ID and all-zero job identity digest. `helper_ready` alone has an
all-zero nonce; bootstrap and every later packet echo the exact helper-local
nonce. Every job request has a nonzero 16-byte request ID, exact nonzero
`GuestCredentialSessionIdentity` digest, and positive revision. A response
echoes its request ID/digest/type/revision; an event has its own nonzero ID.
`close_notify` consumes the ordinary next sequence and record cap and contains
only its safe reason.

Both endpoints require exactly one kernel-supplied credentials record on every
packet. Ancillary rights cardinality is zero except bootstrap (exactly one live
pidfd) and SSH handoff (exactly one connected `AF_UNIX` `SOCK_STREAM`). Exec
packets carry no rights. `MSG_TRUNC` or `MSG_CTRUNC` rejects the
entire packet and closes all received rights. Direction counters are continuous
across PID1-to-agent handoff: inbound PID1 bootstrap is helper receive sequence
0, agent hello is receive sequence 1, and the first job request is sequence 2;
helper ready/ack/hello-ack are send sequences 0/1/2 and its first job response
is sequence 3. Later packets increment exactly by one after authentication,
canonical decode, and either a state transition or a committed safe rejection;
authentication, framing, credential, descriptor, or sequence failure closes
the IPC and cannot continue at the same counter.

Preparation is an atomic `prepare_begin`, then exactly one `prepare_file` for
each file binding in ascending manifest index, then `prepare_commit`
transaction. The helper stages but does not publish a namespace, file,
capability, or proof before commit verifies the manifest digest, counts,
aggregate, identity, revision, and expiry. Duplicate, missing, reordered,
changed, replayed, canceled, disconnected, or failed packets abort the whole
unpublished transaction, wipe every buffer, close staging descriptors, and
remove exact owned staging state. Retrying the identical request ID and
canonical transaction digest is idempotent; reuse with different bytes is a
terminal correlation failure.

All packets in one prepare transaction carry the same nonzero request ID,
identity digest, and revision and count as one logical outstanding request.
There is no intermediate response. The one terminal `0x20 response` echoes
`requestType=0x12` (`prepare_commit`), including when an earlier transaction
packet has a safe semantic failure. An authenticated, canonically decoded
semantic failure aborts staging and emits exactly one safe failure response
when the IPC remains usable; an authentication/framing failure closes it
without a response. After a lost success response, the agent retransmits the
entire canonical transaction at fresh packet sequences with the same request
ID and logical digest. A cached identical success re-emits the prior safe
result without mutation; changed content under that ID is terminal. No other
request may interleave before the terminal response.

Exec is one separate logical transaction. `0x15` declares zero private bytes
and an all-zero private digest when the manifest has no HTTP mode. Otherwise it
declares 1..64 KiB and the SHA-256 of the exact host `HL8B` kind-2 payload; one
`0x17 exec_private` with the same request ID, identity digest, revision,
length, and digest follows immediately. No child, pipe, gate, or pidfd exists
while the helper authenticates and decodes that payload. A missing, extra,
reordered, changed, or zero/nonzero-mismatched private packet aborts exec, wipes
the payload, and cannot leave an orphan because process creation has not begun.
Only after private authentication does the helper create all three pipe pairs,
keeping the parent-side stdin-write, stdout-read, and stderr-read endpoints and
placing the child-side stdin-read, stdout-write, and stderr-write endpoints
behind its internal start gate. It then uses
`clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)` and releases the gate only after every
post-clone identity, namespace, capability, descriptor, and exec check passes.
Any failure after clone but before gate release closes the child-side endpoints,
kills and reaps the exact pidfd/cgroup child, proves zero population, wipes the
private buffer, and only then returns a safe failure.

After the child gate opens, each `0x18 exec_stream` maps one-for-one to the
correlated host `HL8S` record. Its stream kind, EOF flag, offset, length, digest,
direction, and aggregate obey the same rules; agent-to-helper carries stdin and
helper-to-agent carries stdout/stderr. The helper concurrently forwards stdin
while draining stdout and stderr; it never waits for stdin EOF before reading
either output pipe. One bounded mutable chunk per stream may be outstanding,
and a single serialized packet writer preserves the helper send sequence, so a
blocked receiver backpressures only the corresponding pipe instead of creating
an unbounded queue or deadlocking another stream. The terminal exec response is
emitted only after stdin closure, both output EOF packets, child exit/reap, and
stream metadata reconciliation. It contains the independently recomputed
`stdinSHA256` and `execTransactionSHA256`. Loss,
cancel, timeout, or malformed stream closes pipes, kills/reaps under the exact
cgroup policy, wipes chunks/private binding, and returns failure only when the
authenticated IPC remains usable.

The helper retains exactly one non-evicting terminal exec-cache slot for each
of the activation's at most 4096 launch attempts, keyed by request ID and
storing only the transaction digest and safe terminal response. Capacity is
charged before launch; exhaustion rejects a new ID without mutation. A
duplicate request while the original is active is a terminal conflict. After a
lost terminal response, the agent replays `0x15`, optional
`0x17`, and every stdin `0x18` record at fresh packet sequences with the same
request ID. The helper enters comparison-only mode: it creates no pipes or
child, consumes and authenticates the complete private/input transaction,
recomputes its digest, and re-emits the cached response only on an exact match.
A changed plan, private record, chunking, content, EOF, identity, or revision
closes and revokes the session. A canonically framed semantic rejection enters
the same no-launch drain mode, consumes the declared private/input transaction
through its unique EOF, and caches its safe failure only after the complete
digest exists. Authentication/framing failure, loss, cancellation, or timeout
before that point closes the session without a reusable response. Only a
complete cached failure replays under the same rule; no same-ID path may launch
twice. Entries are never evicted or reused and are wiped on activation
revoke/loss/expiry.

The decoder validates header, exact datagram length, credentials, descriptor
kinds/counts, sequence, identity, revision, and body bounds before touching
helper state. D2 implements only codecs and transition decisions; D4 supplies
seqpacket, pidfd, pipe, clock, cgroup, mount, and process enforcement, while D5
supplies live SSH connection and backpressure enforcement.

Safe lifecycle and SSH metadata use fixed binary codecs in
`credentialprotocol`; sensitive bodies decode directly into caller-owned
mutable locked sinks. No interface returns live body content as `string` or an
owned raw `[]byte`, and neither the v1 frame codec nor generic JSON,
`fmt`, reflection, panic, or error paths may traverse it. Full capacity is
overwritten on success, error, cancellation, truncation, authentication
failure, partial write, and cleanup.

The helper starts with precisely the five capabilities above in both permitted
and effective sets; its bounding set contains only those five, and inheritable
and ambient sets are empty. It locks `SECBIT_NOROOT`,
`SECBIT_NO_SETUID_FIXUP`, and `SECBIT_NO_CAP_AMBIENT_RAISE` with their locked
bits before serving. The workload child has an empty bounding, permitted,
effective, inheritable, and ambient set, no supplementary groups, UID/GID 1000,
and `no_new_privs` before exec. D2 represents the permitted helper operations
as an exact syscall-and-argument policy. D4's seccomp implementation may allow
namespace entry only through the helper-owned fixed namespace descriptor and
may allow filesystem/cgroup/mount operations only through revalidated fixed
dirfds. It rejects arbitrary `setns`, networking/vsock, unrestricted path
opens, device/module/keyring operations, `ptrace`, `process_vm_*`,
`pidfd_getfd`, `kcmp`, perf, and BPF.

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
`clone3(CLONE_INTO_CGROUP | CLONE_PIDFD)` with the revalidated exact cgroup
directory FD for race-free placement before the workload can execute. There is
no successful spawn-then-write-`cgroup.procs` fallback. The placed child remains
behind an internal start gate while it enters the exact
mount namespace, sets UID/GID 1000 with no supplementary groups, clears every
capability, applies `no_new_privs`, then launches the existing bounded
stdin/stdout/stderr supervision contract. Direct unprivileged-agent exec cannot
join a credential namespace. Job/process/file/FD/count/byte/time limits are
fixed at construction and charged before allocation: one active credential
job, one pending prepare transaction, one mount namespace/cgroup/keeper, one
outstanding helper request, at most 64 concurrently populated workload
processes, 4096 launches over the activation lifetime, 256 helper-owned file
descriptors, 16 bindings/files, and the byte limits above. The keeper and helper
job state cannot outlive the 35-minute guest activation. Guest cleanup gets at
most three idempotent attempts within one 30-second total deadline before
`stop_vm_required`; retry clocks and observations are injected in D2 tests.

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

The guest/helper cleanup result is exactly one of `cleanup_complete`,
`retry_required`, or `stop_vm_required`. A retry for the same identity and
revision is idempotent and resumes from reinspection rather than recreating a
resource. `cleanup_complete` requires every ordered absence check above.
`retry_required` means owned guest cleanup can still be retried within its
bounded deadline. `stop_vm_required` is emitted for lost helper identity,
unavailable cgroup placement/kill/inspection, unknown mount ownership, normal
unmount failure after bounded retries, or any condition the guest cannot prove
absent. The helper can never convert `stop_vm_required` into success: the host
must stop and reap the exact Firecracker process and inspect host-owned
resources before a root cleanup proof exists.

## SSH-agent relay

SSH private keys remain in the host agent. L8 never copies a private key into a
guest, file, environment value, manifest, or protocol payload.

D2 locks the neutral SSH-agent codec before D5 opens a live socket. Every
message is `uint32_be(payloadLength) || payload`, payload length 1 through 256
KiB and therefore complete wire length at most 262,148 bytes,
with no truncation, trailing byte, concatenated frame, or allocation before the
length check. The only accepted client messages are
`SSH_AGENTC_REQUEST_IDENTITIES` (11) with no body and
`SSH_AGENTC_SIGN_REQUEST` (13) with exact SSH strings for public-key blob and
challenge followed by one `uint32_be` flags field. The only emitted response
types are `SSH_AGENT_IDENTITIES_ANSWER` (12), `SSH_AGENT_SIGN_RESPONSE` (14),
and `SSH_AGENT_FAILURE` (5). Add/remove/remove-all, smartcard, lock/unlock,
extension, protocol-v1, unknown types, unknown flags, and trailing fields
receive failure without contacting the host agent.

The immutable host-admin live policy identifies public keys only as the
OpenSSH-style `SHA256:` prefix plus unpadded base64 of SHA-256 over the exact
public-key blob. That fingerprint is a registry-private selector, not durable
job/status metadata; durable state contains only the separately safe SSH policy
ID and revision. The fingerprint never crosses the host relay boundary.
Enumeration preserves host-agent order after filtering and rewrites comments
to empty strings. Supported key/signature policy is exact: `ssh-ed25519` and
`ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, or
`ecdsa-sha2-nistp521` require flags zero; `ssh-rsa` requires exactly
`SSH_AGENT_RSA_SHA2_256` (2) or `SSH_AGENT_RSA_SHA2_512` (4), never zero,
their combination, or SHA-1. Security-key, certificate, DSA, legacy RSA, and
unknown algorithms are unsupported in L8. A sign response must be a canonical
SSH signature string whose algorithm exactly matches the admitted request
policy: an `ssh-rsa` key with flag 2 must return `rsa-sha2-256`, and flag 4
must return `rsa-sha2-512`. Enumeration parses at most 256 host identities;
each public-key blob and signature is at most 16 KiB, each discarded source
comment at most 4 KiB, and each signing challenge at most 192 KiB within the
outer bound. Key blobs, comments, challenges, signatures, frames, and raw agent
errors are ephemeral and never logged or persisted; owned mutable frame and
challenge buffers are wiped after each response.

The pure D2 state machine decides whether a read is permitted for one
outstanding request per connection, at most four concurrent and 64 lifetime
connections per job, and 4096 total attempted operations across all
connections; rejected and malformed attempts count. It models a five-minute
idle deadline and 35-minute hard lifetime but opens no connection and reads no
clock or stream. D5 supplies clocks, connections, reads, and live backpressure
and must consult those decisions before reading a second request. D2 tests
exact-bound and plus-one cases, malformed nested SSH
strings/counts, forbidden operations, algorithm/flag mismatch, filtered stable
ordering, and buffer destruction. It contains no Unix listener, vsock stream,
`SCM_RIGHTS`, host-agent dial, or relay pump.

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
are bounded: 4 concurrent and 64 lifetime connections, 1 outstanding request
per connection, 256 KiB SSH payload (262,148-byte complete wire), 4096 attempted
operations per activation including rejected/malformed attempts, 5 minute idle,
and the same 35 minute hard lifetime as the job ticket. The helper permits at
most 16 credential bindings, 64 KiB per file, 1 MiB aggregate file payload, and
a 4 MiB tmpfs per job. These fixed limits may be lowered by a sealed catalog but
never raised by a project, job, guest, or provider.

The relay never logs host or guest socket paths, public-key blobs, signature
payloads, comments, request bytes, or raw agent errors. Relay or v2 session
loss closes streams, removes the guest socket, cancels the job, and invalidates
proof. Cleanup proves host listener/connection and guest socket absence.

## Worker, execution, and recovery ordering

The L2 worker job lifecycle becomes:

1. derive the peer principal, strictly decode/validate the request, and
   authorize its complete grant/source/plan/binding/host/runtime/template/workspace
   intent without resolving a source;
2. construct, validate, privately clone, and persist the queued job plus safe
   authorized intent and exact identity seed before any runtime preflight;
3. call optional `JobCredentialRuntime.PreflightJobCredentials` with that seed
   and no live source; an error, typed nil, or other return-contract violation
   forces exact runtime stop/reap before terminal persistence;
4. on the sole valid non-nil-handle/nil-error return, immediately start the
   latched preflight-loss watcher, obtain its defensively copied identity,
   validate every seed field and both authenticated guest generations, and
   persist the complete safe identity;
5. create the lifecycle, call `BeginPrepare`, and persist credential state
   `preparing` before source lookup;
6. resolve only the authorized source set into transient live sources;
7. call `JobCredentialRuntimePreflight.PrepareJobCredentials` on the same
   authenticated session and apply the exact ownership matrix: failure remains
   preflight-owned and requires proof-bearing `Abort`, while success transfers
   ownership and the terminal loss latch without a gap;
8. mechanically inspect the exact active proof; invalid post-transfer proof
   requires session `Revoke`, then persist only a sanitized valid proof
   reference;
9. execute with the opaque transient binding;
10. renew from the heartbeat path and continuously watch the transferred loss
    latch;
11. on expiry/loss, cancel and prove cgroup zero population or stop/reap the
   entire runtime;
12. revoke and prove cleanup on success, failure, cancel, timeout, daemon close,
   state-write failure, or runtime loss; and
13. only then persist terminal job outcome and release admission.

Any failure after the valid return in step 4 and before successful ownership
transfer in step 7 calls idempotent `JobCredentialRuntimePreflight.Abort` and
validates its complete-identity cleanup proof. After `BeginPrepare`, that proof,
not the return of a void close operation, drives preparing lifecycle
revoke/cleanup. Before `BeginPrepare`, including invalid preflight identity,
abort is best-effort and exact stop/reap is mandatory because no lifecycle-
correlated cleanup proof can be accepted. The already-started loss watcher
remains active while aborting. A missing, invalid, or incomplete absence proof
also escalates to exact runtime stop/reap. It never resolves a source before
authenticated guest preflight, identity validation, complete-identity
persistence, and `BeginPrepare` succeed.

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
owned guest/runtime resources. A job with a durable seed but no complete
identity is never passed to ordinary credential recovery: the worker uses the
seed's exact runtime identity to stop/reap the runtime and proves process
absence before cleanup. A job with a complete identity calls
`RecoverJobCredentials`; failure to reauthenticate or produce valid absence
proof similarly stops/reaps or quarantines the exact runtime, and process
termination is proved before cleanup can complete.

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

D2 owns immutable contracts, strict codecs, cryptographic/session state
machines, validators, fakeable helper/cgroup policy, source/import guards, and
negative tests. D4 owns live helper/PID1/agent composition, syscalls,
namespaces, tmpfs, cgroups, workload launch, and guest cleanup retries.
D5 owns live SSH-agent sockets, descriptor passing, host-agent validation, and
relay pumping. D6 owns whole-VM stop/reap fallback, Firecracker host
composition, worker/runtime proof projection, and final host absence evidence.
D2 must not resolve a source, mount, launch, open a live socket, contact an
agent, stop a VM, add HTTP behavior, or wire a production command.

- Preserve v1 byte/behavior compatibility.
- Reject v2-to-v1 downgrade, wrong host CID/key/generation, handshake/frame
  replay or tamper, unknown fields, stale revisions, cross-job identity,
  overflows, and malformed private payloads.
- Lock the neutral lifecycle/SSH codec, signed ephemeral v2 handshake,
  dedicated service/workload identities, exact-PID socketpair authentication,
  helper fd-root/capability/seccomp boundary, cgroup-v2 placement/kill proof,
  numeric resource limits, and stop-VM fallback before live helper or
  guest-agent behavior.
- Lock the two-stage `JobCredentialRuntimePreflight` seam so authenticated
  guest/helper generations exist before complete identity validation and
  lifecycle construction; D2 supplies only contracts and fakes, not a live
  connection.

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

- Implement live AEAD relay subkeys, SCM_RIGHTS handoff, clocks, streams, and
  backpressure under D2's already locked numeric limits, operation policy, and
  mandatory key/algorithm allowlists.
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
