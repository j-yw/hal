# Sandbox Runtime v2 L8 Production Credential Delivery Architecture

## Authority and phase boundary

This document refines issue #49 locked comments `5068151561`, `5068157402`,
and `5068162708` for L8. The cross-phase architecture remains
`sandbox-runtime-v2-linux-completion-architecture.md`. L8 starts from the
completed L7 topology and enforcement proof and consumes L2/L3 durable job and
recovery ownership plus L4/L5 guest execution. It does not weaken or replace
any of those proofs.

Two D2 supplements are normative parts of this architecture:
`sandbox-runtime-v2-l8-helper-syscall-policy.md` freezes the helper's exact
syscall/argument boundary, and
`sandbox-runtime-v2-l8-guest-extension-seams.md` freezes the D4/D5 package,
registry, host-agent, composition, and image-profile ownership seams. A later
slice may implement those contracts but may not reinterpret them locally.

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
  namespace monitor, relay, guest socket, session, or live proof remains after
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
- `cmd/hal-guest-init` owns the exact PID1 launch supervisor. It launches only
  image-pinned `hal-guest-role-bootstrap` modes through the private D2 launch
  protocol; it is not a general process runner.
- `internal/sandboxruntime/microvm/guestagent/rolebootstrap` owns the
  freestanding Linux-amd64 native `_start` plus only generated native
  callsite/install tables derived mechanically from the D7-verified artifact
  and goldens. D4 owns the native consumer, installer, source/disassembly
  verification seam, and fakes; it never authors policy rows, rule authority,
  or an independent table. D7 is the sole author and issuer of the canonical
  rows and artifact, and its locked offline image build is the sole production
  generator/compiler/installer. The native leaf imports no Go package and has
  no host or non-L8 production use.
  In policy terms, D4 `rolebootstrap` owns only generated native callsite/install tables from the D7-verified artifact and goldens.
- `cmd/hal-guest-credential-helper`, `cmd/hal-guest-mount-monitor`, and
  `cmd/hal-guest-workload-shim` are narrow process entrypoints for the
  capability-free credential controller, per-job mount owner, and one workload
  transition respectively. They contain no independently testable policy.
- `internal/sandboxruntime/microvm/guestagent/credentialhelper` owns the
  testable privileged service policy for per-job cgroups, mount namespaces,
  credential files, the restricted guest SSH endpoint, credential-aware exec,
  and cleanup outcomes. D2 keeps it contract/fake-only; D4 adds the Linux
  implementation behind those boundaries. Its immutable extension registry,
  D4 Linux child, D5 SSH child, typed-nil rules, and D6 composition junction are
  the exact APIs in the extension-seam supplement; no package-global or
  side-effect registration exists.
- `internal/sandboxruntime/microvm/guestagent/syscallpolicy` is the
  standard-library-only neutral leaf for D2's canonical artifact schema,
  importer/verifier, immutable copied views, pure scalar/adapter decisions,
  fingerprints, exact `FilterRules` own/ancestry projection, complete
  catalog-bound `FilterProfile`, and fixtures. D7
  alone authors and issues the complete rule artifact. D4 compiles only that `FilterProfile` and
  projection and consumes semantic rows only through the exact
  operation-scoped `AdapterBindings`, `AuthorizePre` permit, one-call syscall
  wrapper, and `AuthorizePost` or
  `CommitNoObject` live adapter sequence. That sole private D4 wrapper has the
  exact `unstarted -> claimed -> executed -> finalized` catalog. D4 allocates
  one inert `unstarted` wrapper before `NewAdapterBindings`; that same wrapper identity is the sole production `BindingSource` and initially has no permit,
  syscall closure, or live syscall authority. It retains the exact opaque
  bindings snapshot/token. Binding construction or pre-authorization failure
  synchronously destroys it with zero syscall or terminal calls and no escape.
  Successful pre authorization installs the permit and closure in the same
  wrapper identity, then claims atomically before escape. There is no replacement,
  cross-wrapper transfer, or acceptance of foreign bindings. After claim,
  pre-syscall cancellation or
  failure finalizes through one phase-explicit `AbortPermit` with
  `AdapterPhasePre`, the exact same permit, and zero syscall calls. The normal
  path makes exactly one syscall, then finalizes through one post/commit on
  success or one phase-explicit `AbortPermit` with `AdapterPhasePost` and the
  exact same permit on syscall failure. All wrong-phase, duplicate, wrong-state,
  concurrent, repeated, and post-finalization calls fail closed before any D2
  terminal call; there is no retry on the same wrapper, ticket, or permit.
  Abort routes never call post/commit and successful-syscall routes never call
  abort. State/fact-narrowed authority is
  always `EnforcementPathAdapter`; direct rows are all-stage and cannot overlap
  adapter authority. `EnforcementPathPinnedDirect` is the only pointer-bearing
  helper exception: it is restricted to D7 source-locked native/bootstrap or
  pinned-Go runtime callsites and requires an exact per-role/kind binary binding
  set plus independently verified final-binary callsite evidence; it accepts no
  live observation or D4/D6 widening. The scalar-only workload exception is a
  source-locked `RuleOriginWorkload` ordinary-catalog filter row after final
  exec; it has no helper pointer provenance, conditional/fatal authority,
  ticket, or D4 adapter claim. It
  imports no D4 package and performs no syscall, BPF compilation, installation,
  process, filesystem, socket, or other live operation. The exact numeric ABI,
  immutable artifact schema, amd64 catalog source pin, opacity rules, and mechanical
  ancestry are frozen in the syscall-policy supplement.
- `internal/sandboxruntime/microvm/guestagent/credentialprotocol` owns the
  shared data-only credential lifecycle and SSH-agent wire codecs.
- `internal/sandboxruntime/microvm/guestagent/server/credentialclient` owns the
  unprivileged guest-agent client for the helper's authenticated local IPC and
  the matching immutable D5 extension registry from that supplement.
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
the safe-ID grammar. There is deliberately no public or reusable seed digest:
a seed is not a proof, wire identity, authorization token, or bearer
capability, and only the complete identity has the canonical digest below. The
sole exception is the sealed, domain-separated seed-correlation digest inside
the private runtime-absence proof defined below. It has no accessor or
independent authority.

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

## Restart-stable Firecracker runtime owner

D6 uses a separate Linux host runtime-owner supervisor. The supervisor, not the
sandbox daemon, directly starts and remains the parent of the exact Firecracker
process. It remains alive when the daemon exits and exposes one private,
reconnectable control plane. A daemon restart therefore reacquires authority
from the supervisor; it never reconstructs authority from `Target.Metadata`, a
process name, a public status record, or the worker's credential state alone.
Daemon-death containment by itself is not the normal recovery design.

The additive neutral recovery API has these exact names and declaration order:

```go
const (
	MaxJobCredentialRuntimeAbsenceObservationAge = 5 * time.Minute
	JobCredentialRuntimeStopReapTimeout          = 30 * time.Second
	JobCredentialRuntimeRecoveryCloseTimeout     = 5 * time.Second
)

type JobCredentialRuntimeAbsenceProofInput struct {
	Seed               JobCredentialIdentitySeed
	AbsenceInspectedAt time.Time
}

type JobCredentialRuntimeAbsenceProof struct {
	token [41]byte
}

func NewJobCredentialRuntimeAbsenceProof(JobCredentialRuntimeAbsenceProofInput) (JobCredentialRuntimeAbsenceProof, error)
func ValidateJobCredentialRuntimeAbsenceProof(JobCredentialRuntimeAbsenceProof, JobCredentialIdentitySeed, time.Time) error

type JobCredentialRuntimeRecoveryCommitReceipt struct {
	CommitID string `json:"-" xml:"-"`
	FinalizedRevision uint64 `json:"-" xml:"-"`
}

func ValidateJobCredentialRuntimeRecoveryCommitReceipt(JobCredentialRuntimeRecoveryCommitReceipt) error
func (JobCredentialRuntimeRecoveryCommitReceipt) String() string
func (JobCredentialRuntimeRecoveryCommitReceipt) Format(fmt.State, rune)
func (JobCredentialRuntimeRecoveryCommitReceipt) MarshalJSON() ([]byte, error)
func (JobCredentialRuntimeRecoveryCommitReceipt) MarshalText() ([]byte, error)
func (JobCredentialRuntimeRecoveryCommitReceipt) MarshalBinary() ([]byte, error)
func (JobCredentialRuntimeRecoveryCommitReceipt) GobEncode() ([]byte, error)

type JobCredentialRuntimeRecoveryProvider interface {
	BindJobCredentialRuntimeRecovery(context.Context, JobCredentialIdentitySeed) (JobCredentialRuntimeRecoveryBinding, error)
}

type JobCredentialRuntimeRecoveryBinding interface {
	RecoverJobCredentials(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error)
	StopReapJobCredentialRuntime(context.Context) (JobCredentialRuntimeAbsenceProof, error)
	FinalizeJobCredentialRuntimeRecovery(context.Context, JobCredentialRuntimeAbsenceProof) (JobCredentialRuntimeRecoveryCommitReceipt, error)
	CommitJobCredentialRuntimeRecovery(context.Context, JobCredentialRuntimeRecoveryCommitReceipt) error
	Close(context.Context) error
}
```

The root binder validates and defensively clones the seed before calling
`BindJobCredentialRuntimeRecovery`. A nil or typed-nil provider, binding, or
context; a panic; a value plus error; or a seed mismatch returns only a stable
sanitized root error. No provider is called for a job without live L8 intent.
The provider receives the validated seed directly and never a `Target`; target
metadata, endpoints, runtime labels, caller-carried proofs, and public job
fields cannot select or recreate recovery authority.

The returned binding is seed-bound. `RecoverJobCredentials` accepts a complete
identity only after `ValidateJobCredentialIdentityCompletion` proves exact
equality with that seed, and otherwise does not call the concrete runtime.
`StopReapJobCredentialRuntime` takes no caller identity because the binding
already owns the exact cloned seed. It returns only a nonzero, validated
`JobCredentialRuntimeAbsenceProof` whose observation is not in the future and
is no older than `MaxJobCredentialRuntimeAbsenceObservationAge` at worker
acceptance. Error-plus-proof, zero-proof success, typed nils, and panics are
contract violations and retain cleanup uncertainty. Stop/reap retains the
private owner record, exact seed binding, L7 correlation, and absence evidence;
it does not clean L7 state or retire ownership before the caller can validate
the proof.

The worker validates the retained absence proof before calling `FinalizeJobCredentialRuntimeRecovery`.
Finalize revalidates the exact bound seed, proof kind, correlation digest,
observation time, and current owner revision. It then performs the correlated
same-boot L7 cleanup and durably persists the idempotent `finalized` tombstone
and its owner-authenticated commit ID before returning a nonzero validated
`JobCredentialRuntimeRecoveryCommitReceipt`. The commit ID is the 32-byte HMAC
defined below, encoded as exactly 43 unpadded-base64url characters, and
`FinalizedRevision` is the exact finalized record revision. It is not a public safe ID:
the receipt is accepted only from this exact injected binding, and `CommitID` carries `json:"-" xml:"-"`.
String and every fmt verb return only `[job-credential-runtime-recovery-commit-receipt]`.
JSON, gob, text, and binary encoding fail closed; XML encoding omits the field
and cannot expose the ID. Failures use the stable redaction error and no bytes.
Outside the private owner record's `FinalizedCommitID`, the ID is persisted only
in the private worker recovery receipt described below.
A value plus error, zero/malformed receipt, or panic is failure. A crash after stop/reap but before finalize leaves
the `absent` owner state retryable. Repeated stop/reap in that state performs no
signal and returns a newly inspected proof; repeated finalize against the exact
proof or already-finalized correlation succeeds without repeating resource
removal and returns the exact same receipt. After finalize succeeds, one atomic
worker-store replacement removes the complete credential state and writes a
private `job-credential-runtime-recovery-receipt-v1` containing the validated
safe seed plus exact commit ID and finalized revision. In other words, the worker atomically replaces CredentialState with a private recovery receipt;
there is never a durable state containing neither. The receipt is bounded,
mode/ownership protected with the existing private worker store, excluded from
`JobV2`, status, runtime metadata, manifests, logs, and errors, and contains no
complete identity, credential, endpoint, path, live handle, or process data.
Its exact private DTO is:

```go
type storedJobCredentialRuntimeRecoveryReceiptV1 struct {
	ContractVersion string `json:"contractVersion"`
	Seed storedJobCredentialIdentitySeedV1 `json:"seed"`
	CommitID string `json:"commitId"`
	FinalizedRevision uint64 `json:"finalizedRevision"`
}
```

`storedJobStateV2` adds
`CredentialRecoveryReceipt *storedJobCredentialRuntimeRecoveryReceiptV1` with
tag `json:"credentialRecoveryReceipt,omitempty"`. Recovery-state validation
requires exactly one of CredentialState or CredentialRecoveryReceipt until
commit has acknowledged the exact receipt, and forbids the receipt for jobs
without live L8 credential intent. A repo-wide AST guard permits a `CommitID`
read only as one direct selector on the exact receipt-typed parameter object.
The permitted package functions have no receiver, contain exactly one
receipt-typed parameter whose type object is the canonical root receipt or the
exact imported root receipt, return only `error`, and read that parameter's
`CommitID` exactly once. The root validator has no other parameter. The
private-store converter instead returns exactly
`(storedJobCredentialRuntimeRecoveryReceiptV1, error)` so it can copy the
validated receipt plus seed into the private DTO. The functions are:
the root `ValidateJobCredentialRuntimeRecoveryCommitReceipt`, concrete
`firecrackerhost.commitJobCredentialRuntimeRecovery`, and, when worker receipt
persistence lands, private-store
`storedJobCredentialRuntimeRecoveryReceiptV1FromRuntime`. Receipt replay is
confined to the adjacent exact private-store decoder
`storedJobCredentialRuntimeRecoveryReceiptV1ToRuntime`, which accepts only the
private DTO, reconstructs and validates the sealed neutral receipt, and returns
it only to the seed-bound recovery binding's commit call. The root validator
and owner verifier land together; both private-store functions remain optional
until worker receipt persistence lands.
Accordingly, only `internal/sandboxworker/job_store_v2.go` may copy `CommitID`
from the neutral receipt into the private DTO, and only
`internal/sandboxworker/job_store_v2_recovery_receipt.go` may copy it back into
the sealed neutral receipt for commit-only replay. Reflection, unsafe conversion, receipt aliases, receiver methods, closures, and helper escape are forbidden,
as are same-name functions with an unrelated `CommitID` field, a receipt type
alias, a wrong signature, or an indirect field read. Worker services, statuses,
commands, runtime metadata, and every other file cannot project it, including
through a cross-file alias. Any production file outside the four allowlisted
files/functions that names the receipt type through a default, explicit, dot,
or raw-string import fails the guard. A receipt-bearing allowlisted file also
fails if it imports `reflect` or `unsafe`; reflection cannot hide a field read
that has no `CommitID` selector.

Inside the root neutral API file, receipt-type references are confined to the exact type declaration,
the exact validator parameter, the unnamed receivers
of the sealed `String`, `GoString`, `Format`, JSON/text/binary/gob denial
methods, and the exact Finalize result plus Commit parameter in
`JobCredentialRuntimeRecoveryBinding`. No other root helper, value, assignment,
receiver, parameter, result, interface method, or `any` retention may name or
capture the receipt. This confinement includes unresolved bare cross-file type
identifiers in every sibling production file of the root `sandboxruntime`
package; a file-local object is not required for the guard to reject them.

The sole future concrete exception is frozen to the package-private
`type l8RuntimeOwnerRecoveryBinding` in
`internal/sandboxruntime/microvm/firecrackerhost/l8_runtime_owner_recovery.go`
and this exact pointer-receiver signature:

```go
func (*l8RuntimeOwnerRecoveryBinding) FinalizeJobCredentialRuntimeRecovery(context.Context, sandboxruntime.JobCredentialRuntimeAbsenceProof) (sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt, error)
```

The guard permits the receipt type only as that exact first result. It permits
no `CommitID` or other receipt-field access in the method, rejects a value or
different receiver, file, parameter, result, alias, or additional receipt type
reference, and leaves `commitJobCredentialRuntimeRecovery` as the sole owner
field reader. The method remains absent until `l7network` exposes a truthful
recovered `TerminatedVMBinding`; freezing its future shape is not a cleanup or
provider implementation claim.

The worker rebinds from the receipt's validated seed and calls
`CommitJobCredentialRuntimeRecovery` with the exact commit receipt. Commit is
the only transition that may retire the finalized owner tombstone; it checks
the bound seed, finalized revision, and HMAC commit ID, performs no process or
L7 cleanup. With a finalized record present, Commit requires that record's
exact seed digest, finalized revision, and commit ID. That HMAC could only have
been durably minted by Finalize after correlated same-boot L7 cleanup succeeded.
Commit then durably unlinks the per-job owner record and syncs its directory.

After that per-job record is retired, `BindJobCredentialRuntimeRecovery` may
return only a commit-only/record-absent binding for the validated receipt seed.
Every other method on that binding fails closed. Commit recomputes the full-seed
digest, verifies the HMAC and finalized revision with the stable owner-root key,
and requires the exact per-job owner record still absent under lock. The valid
HMAC proves that Finalize minted the receipt only after its L7 cleanup; replay
does not reopen the now-removed private L7 journal or invent a new absence API.
Only all of those facts return idempotent committed success. Missing/wrong key,
wrong HMAC, revision, seed, any reappearing or nonfinalized record, or
panic/error retains
the worker receipt and fails sanitized; the caller-held ID alone is never a
bearer authority and no per-job committed tombstone is fabricated.

The owner record is retired only after
same-boot L7 finalization and the worker's atomic private-receipt replacement
have both succeeded. The worker then
atomically clears its private receipt. If it crashes after receipt replacement
but before commit, restart rebinds and commits it. If it crashes after commit
but before receipt clear, post-commit restart validates the same receipt and accepts the idempotent committed result
without reconstructing process or cleanup proof, then clears the receipt. Thus
no timeout or `Close` acts as acknowledgement and no permanent finalized record
or unbounded receipt is required. A stale, substituted, expired, or mismatched
proof, or any finalize panic/error/deadline, leaves the record and credential
state cleanup-incomplete.

The absence token is exactly 41 bytes: kind byte `0x03`, a 32-byte internal
seed-correlation digest, and the signed `AbsenceInspectedAt.UnixNano()` encoded
as eight-byte big-endian. The digest is SHA-256 over the length-prefixed domain
`hal/job-credential-runtime-absence/seed/v1`, followed by a length-prefixed
encoding of every `JobCredentialIdentitySeed` field. Each length prefix and
the binding count is an unsigned big-endian 32-bit byte count. First, every
string field from `SandboxID` through `GuestImageDigest` is encoded in exact
declaration order as byte length then bytes. Next,
`AdmissionGrantRevision` is one unsigned big-endian 64-bit value. The adjacent
`BindingIDs` and `DeliveryModes` slices are then encoded as one count followed
by exactly that many ordered pairs, each pair containing the length-prefixed
binding ID followed by the length-prefixed delivery mode. Last, `IssuedAt` is
its signed UnixNano value encoded as its two's-complement big-endian 64-bit
representation, never time text, zone, or location. This is their exact
declaration position: `IssuedAt` follows both parallel slices. No zero, empty,
or optional scalar is omitted. The constructor validates the seed and requires a nonzero observation
not before `Seed.IssuedAt`; the validator recomputes the digest and enforces the
freshness bound. The digest has no accessor, is never a public seed-digest API,
and the token implements no JSON, text, or binary projection. The same digest,
encoded as exactly 64 lowercase hexadecimal characters, is permitted only in
the private owner record to prevent seed substitution; it has no other durable
or public projection. A proof supplied
through metadata or by a caller has no authority; the worker accepts one only
as the validated result of the injected binding's exact stop/reap call.
The sole production call to `NewJobCredentialRuntimeAbsenceProof` is owned by
`internal/sandboxruntime/microvm/firecrackerhost/l8_runtime_owner_recovery.go`
after its private owner has proved exact absence. Root defines the constructor;
tests may call it, but no worker, command, metadata adapter, other runtime file,
or provider wrapper may become a second production issuer. An AST guard locks
that one-callsite rule. Until a concrete private owner has implemented
`StopReapJobCredentialRuntime` and causally produced that exact validated
absence fact, the default-off R1 foundation contains no host production constructor call;
caller-supplied booleans, timestamps, or nominal observation
DTOs cannot stand in for the missing fact. The guard must be tightened from
zero to exactly one only in the same reviewed slice that lands that concrete
stop/reap owner.

`Close` releases only the reconnect controller binding. It is idempotent,
panic-contained, caller-independent after entry, and bounded by
`JobCredentialRuntimeRecoveryCloseTimeout`. Close does not imply process or resource absence
and never manufactures either proof. A close error is joined
only through stable sanitized sentinels and leaves the owner record available
for retry. Close cannot retire an `absent`, unacknowledged, or nonfinalized
record and cannot stand in for finalize.

### Private owner record and publication

Each explicit Linux D6 composition supplies one private owner-state root owned
by the daemon service UID. The root and its per-runtime child are existing or
new real directories at mode `0700`, opened component-by-component without
following symlinks. Before any supervisor or per-runtime record can be created,
the root contains one stable private owner-root HMAC key file named
`receipt-hmac.key`. It is exactly 32 random bytes in a root-owned, mode-`0600`,
regular, single-link, no-symlink file, created through exclusive sibling write,
file sync, Linux `renameat2(RENAME_NOREPLACE)`, and root-directory sync. Initial
provisioning is permitted only while the locked root is provably empty of any
key, per-runtime record, or recovery artifact. `EEXIST` never overwrites: the
loser destroys its temporary file and strictly reopens and validates the
winner. A successful no-replace rename followed by directory-sync failure is
commit-uncertain; while retaining the same intended key bytes, initialization
reopens the key path with no-follow checks and accepts either that exact key or
another strictly valid concurrent winner. If the path is absent it retries the
same intended bytes within the bounded initialization attempt; a malformed,
replaced, or otherwise ambiguous path fails closed. It never generates a new
candidate during reconciliation. The winning key is a constant baseline
resource, never copied into a per-runtime record, worker state, proof, receipt,
status, log, error, or public projection, and is never automatically replaced,
rotated, or removed while any worker recovery receipt can exist. A missing,
replaced, malformed, wrongly owned, or uncertain key fails closed; an owner
root with any prior state never generates a replacement key.

The commit ID is `HMAC-SHA256` under that key. Its preimage uses the
length-prefixed domain `firecracker-runtime-owner-receipt-hmac-v1`, then the
length-prefixed owner contract version, the private key generation, the raw
32-byte full-seed correlation digest, and the finalized revision as unsigned
big-endian 64 bits. The private key generation is
`SHA-256(length-prefix("firecracker-runtime-owner-receipt-key-generation-v1") || key)`;
it never leaves the owner boundary. All length prefixes here and in the seed
digest are unsigned big-endian 32-bit byte counts. HMAC verification is
constant-time.

The sole per-runtime record is a regular, single-link file at mode
`0600`; its strict JSON encoding is bounded to exactly 16 KiB including the
trailing newline. The package-private DTO and field order are exact:

```go
type firecrackerRuntimeOwnerRecordV1 struct {
	ContractVersion              string `json:"contractVersion"`
	Revision                     uint64 `json:"revision"`
	State                        string `json:"state"`
	ControllerState              string `json:"controllerState"`
	AbsenceKind                  string `json:"absenceKind"`
	AbsenceRevision              uint64 `json:"absenceRevision"`
	AbsenceObservedAtUnixNano    int64 `json:"absenceObservedAtUnixNano"`
	FinalizeTargetRevision       uint64 `json:"finalizeTargetRevision"`
	HostBootID                   string `json:"hostBootId"`
	SeedCorrelationDigest        string `json:"seedCorrelationDigest"`
	SupervisorGeneration         string `json:"supervisorGeneration"`
	SupervisorPID                uint32 `json:"supervisorPid"`
	SupervisorStartTime          uint64 `json:"supervisorStartTime"`
	FirecrackerPID               uint32 `json:"firecrackerPid"`
	FirecrackerStartTime         uint64 `json:"firecrackerStartTime"`
	FinalizedCommitID            string `json:"finalizedCommitId"`
	SandboxID                    string `json:"sandboxId"`
	ExecutionID                  string `json:"executionId"`
	WorkerID                     string `json:"workerId"`
	HostID                       string `json:"hostId"`
	RuntimeDriver                string `json:"runtimeDriver"`
	RuntimeID                    string `json:"runtimeId"`
	RuntimeGeneration            string `json:"runtimeGeneration"`
	FirecrackerProcessGeneration string `json:"firecrackerProcessGeneration"`
	VsockGeneration              string `json:"vsockGeneration"`
	NetworkPlanID                string `json:"networkPlanId"`
	PolicySnapshotID             string `json:"policySnapshotId"`
	ProxySessionID               string `json:"proxySessionId"`
	ProxyGenerationID            string `json:"proxyGenerationId"`
	TopologyGenerationID         string `json:"topologyGenerationId"`
	RuleGenerationID             string `json:"ruleGenerationId"`
	ReconnectListenerIdentity    string `json:"reconnectListenerIdentity"`
	ReconnectSecret              string `json:"reconnectSecret"`
}
```

`ContractVersion` is exactly `firecracker-runtime-owner-private-v1`. Lifecycle
`State` is exactly one of `starting`, `running`, `stopping`, `absent`,
`finalizing`, `finalized`, or `uncertain`. `ControllerState` is independently
exactly one of `none`, `unclaimed`, or `controlled`. Revision-zero and
revision-one `starting` use `none`; publication changes lifecycle to `running`
and controller state to `unclaimed`. Handshake, EOF, and Close rotate only
`ControllerState` plus the one-use secret and preserve lifecycle `State`,
including while `stopping`, `absent`, `uncertain`, `finalizing`, or `finalized`.
A controller claim is never process-liveness authority. `HostBootID` is the exact lowercase canonical UUID read from
`/proc/sys/kernel/random/boot_id` through a bounded no-symlink Linux reader.
`SeedCorrelationDigest` is the exact private lowercase-hex digest defined for
the absence token. Before binding, reconnect, signal, absence inspection, or
cleanup, the owner recomputes it from every `JobCredentialIdentitySeed` field
and rejects any mismatch; the safe L7 subset alone is never sufficient
authority.
`AbsenceKind`, `AbsenceRevision`, and `AbsenceObservedAtUnixNano` are zero in
`starting`, `running`, and `stopping`. An `absent`, `finalizing`, or `finalized`
record carries exactly `direct_wait` or `replacement_proc`, binds
`AbsenceRevision` to the revision at which that fresh observation was
persisted, and carries a positive signed Unix-nanosecond observation no earlier
than the seed. Repeated StopReap against `absent` must reobserve exact absence
and persist a new `absent` revision/time before reissuing it; it never returns a
cached stale observation. `uncertain` may retain the last complete absence
tuple only as non-authoritative history and may move to `absent` only after a
new exact direct Wait or double-`/proc` observation.

`FinalizedCommitID` and `FinalizeTargetRevision` are empty/zero outside
`finalizing` and `finalized`. Before correlated L7 cleanup, Finalize computes
the commit ID for the exact target revision and atomically persists
`finalizing` with that ID and target. It then performs the recovered
`CleanupAfterVMQuiesced` and only then persists `finalized` at the
exact target revision. Restart from `finalizing` verifies the HMAC and retries
the cleanup while its exact journal remains. If cleanup already durably retired
that journal, the exact private retired-generation marker, cryptographically
bound to every L7 identity field, completes the retry without reopening
topology or requiring a second successful Recover. Legacy, missing, malformed,
or differently correlated state remains cleanup-incomplete. The
intent record never returns a receipt. The transition
to `finalized` persists the state, target revision, and commit ID before returning the same
`CommitID` and `FinalizedRevision` in the worker receipt. A finalized record
with an empty, malformed, or recomputation-mismatched commit ID is uncertain.
Supervisor PID/start identity is always nonzero. Firecracker PID and start time
are either both zero only for a revision-zero prelaunch `starting` record or are
both nonzero; every other combination is invalid. Revision one is the first
record containing the exact child PID/start identity, and every later state or
secret replacement increments it by exactly one. Both start times are the
unsigned field-22 start-time clock ticks read from the corresponding proc stat
record while an already-open pidfd pins the inspected process incarnation. The
supervisor generation, reconnect-listener identity, and reconnect secret are
independently generated 32-byte random values encoded as exactly 43
unpadded-base64url characters. `ReconnectSecret` is a one-use reconnect secret,
not a safe ID or bearer value outside this owner protocol.

Every stored safe identity field equals its corresponding validated seed field.
Fields not projected into the record remain bound by `SeedCorrelationDigest`;
no omitted field may be substituted while retaining the same L7 subset. The
exact L7 identity is derived without fallback as follows:

```text
SandboxID            = Seed.SandboxID
ExecutionID          = Seed.ExecutionID
WorkerID             = Seed.WorkerID
RuntimeGenerationID  = Seed.RuntimeGeneration
PlanID               = Seed.NetworkPlanID
PolicySnapshotID     = Seed.PolicySnapshotID
ProxySessionID       = Seed.ProxySessionID
ProxyGenerationID    = Seed.ProxyGenerationID
TopologyGenerationID = Seed.TopologyGenerationID
RuleGenerationID     = Seed.RuleGenerationID
```

File decoding rejects unknown or duplicate fields, trailing bytes, oversize
input, `null` or a wrong JSON scalar type, invalid modes, numeric values outside the exact revision-zero `starting`
exception, overflow, invalid safe IDs, wrong ownership/mode/link count,
symlinks, host-boot mismatch at a same-boot operation, a noncanonical or
mismatched seed digest, and any seed/L7 mismatch. The
private reconnect socket pathname is derived inside the owned directory from
the listener identity; neither that pathname nor any endpoint is stored in the
record.

Every create or replacement writes a new sibling with exclusive creation and
mode `0600`, writes the complete bounded payload, syncs it, atomically renames
it over the prior record without a visibility gap, and syncs the directory.
A failure before rename leaves the exact prior record. A rename followed by directory-sync failure is commit-uncertain:
the owner closes the controller without acknowledgement, retains quarantine,
and reopens the record under the exclusive directory lock. It accepts only the
strict byte-valid prior revision/digest or the exact intended next
revision/digest, and aligns the in-memory FSM and reconnect secret to that
observed value before retry. A missing, third, malformed, or mismatched value
stays `uncertain`; it is never overwritten, signalled through, or described as
the prior record. Crash recovery uses the same reconciliation rule.

Startup closes the pre-publication crash window through a
private bootstrap pipe and start gate. The daemon retains live ownership of the supervisor process
and bootstrap pipe until revision-one `starting` durability and publication
acknowledgement. The supervisor first persists a revision-zero `starting` record
with the exact host boot and supervisor identity and zero Firecracker PID/start
fields. It cannot fork or exec Firecracker until the daemon sends the sole
authenticated start-gate packet. It then forks the direct child with a separate
private pre-exec gate. Before reading that gate, the child installs
`PR_SET_PDEATHSIG=SIGKILL`, rechecks that the expected supervisor is still its
parent, and sends a child-armed acknowledgement over the private bootstrap
pipe. Gate EOF, bootstrap loss, parent mismatch, or setup error exits without
executing Firecracker. The supervisor must receive the child-armed acknowledgement,
then opens the child pidfd, validates its exact start time, atomically persists the
revision-one `starting` record, and only then releases the child's pre-exec gate
and sends the publication acknowledgement. The revision-one `starting` record is durable before Firecracker publication or acknowledgement.
No backend handle, readiness bridge,
worker reference, or status is published before that acknowledgement. The
supervisor atomically changes lifecycle to `running` and controller state to
`unclaimed` before admitting the
ordinary reconnect controller.

Bootstrap pipe, daemon controller, supervisor, child-armed acknowledgement, record-write, child-gate, or
acknowledgement loss before durable publication requires the supervisor to
TERM/KILL and `Wait` the child under the shared bounded containment path, write
`absent` if possible, close the bootstrap channel, and exit. It cannot leave an
unrecorded surviving supervisor or child. `AbortStart` is the only recovery
command accepted for a `starting` record. For revision zero, the exact live
supervisor must prove from its serialized bootstrap FSM that it has not forked
the child and that the start-gate packet was not consumed; while holding the
owner lock it then closes retained namespace/assets, unlinks the exact genesis
record, syncs the directory, acknowledges retirement, and exits. Directory
sync uncertainty receives no acknowledgement and retains quarantine. A new
owner may request this causal retirement from that exact supervisor, but an
absent supervisor plus revision zero is not enough: no unrecorded PID is
available to inspect, so replacement retains the record rather than fabricating
never-launched absence. For revision one, AbortStart first persists `stopping`
at revision two, then TERM/KILL/Waits the exact child and persists `absent` with
fresh direct-Wait evidence at revision three before replying. It never jumps
revision-one `starting` directly to `absent`, launches, publishes, adopts, or
replaces a runtime from `starting`. Any uncertain gate, supervisor, child,
record-unlink, or record observation retains quarantine.

No PID, start time, host boot ID, listener identity, secret, record pathname,
live descriptor, bootstrap capability, or raw capability leaves this owner-only
state and control boundary.

### Reconnect and replay state machine

The default-off owner executable is exactly
`hal-firecracker-runtime-owner`. It accepts no flags or environment-derived
configuration and has exactly two private modes: `supervise` and `child-gate`.
The complete argv is exactly `[resolved-binary-path, "supervise"]` or
`[resolved-binary-path, "child-gate"]`; empty, extra, repeated, or alternate
arguments fail closed.
The supervisor mode receives an already-connected daemon bootstrap
`SOCK_SEQPACKET` socket as fd 3, the pinned mode-`0700` owner directory as fd
4, a sealed bounded supervisor configuration memfd as fd 5, and exactly two
sealed launch-asset descriptors as fd 6 then fd 7 in kernel-then-rootfs order.
Fd 8 is an already-open read-only handle to the stable owner-root
`receipt-hmac.key`. Before supervisor launch the daemon opens the pinned owner
root component-by-component with `openat` plus `O_NOFOLLOW`, then opens that
exact basename relative to the pinned root with
`O_RDONLY|O_CLOEXEC|O_NOFOLLOW`. Both daemon and supervisor require a regular
mode-`0600`, current-service-UID, single-link file, read exactly 32 bytes by
`pread`, and reject size change, replacement, wrong inode identity, or any
read/close uncertainty. The key is never named in argv/config, sent through a
packet, or inherited by child-gate/Firecracker. Missing or invalid fd 8 fails
before revision-zero creation; the supervisor never creates or replaces the
stable key.
The supervisor owns those descriptors before acknowledging bootstrap and
retains them until it has either transferred duplicates into the child or
completed bounded abort containment. The child-gate
mode receives its supervisor gate `SOCK_SEQPACKET` socket as fd 3, the same
sealed configuration memfd as fd 4, and the exact Firecracker inherited
descriptors starting at fd 5 in user-namespace, network-namespace, kernel, and
rootfs order. Child-gate has no key descriptor. Every other inherited
descriptor is closed before entering either mode. The supervisor configuration
is at most 32 KiB, strictly decoded, contains the complete validated seed plus
the clean absolute namespace-wrapper and Firecracker executable paths, exact
arguments, and the fixed inherited-descriptor count of two, and is
never durable or projected. The executable path is clean and absolute, the
environment is exactly empty, and the helper replaces itself with the exact
namespace wrapper through `execve` only after the release gate. Its argv is
exactly `nsenter --preserve-credentials --keep-caps --user=/proc/self/fd/3
--net=/proc/self/fd/4 -- firecracker` followed by the validated Firecracker
arguments. The child first duplicates its inherited user, network, kernel, and
rootfs sources from fds 5, 6, 7, and 8 to four collision-free private
`F_DUPFD_CLOEXEC` temporaries at fd 9 or higher. It then maps those temporaries
to fds 3, 4, 5, and 6 with `dup3`, closes the temporaries plus the old gate,
configuration, and source descriptors, clears close-on-exec only on 3 through
6, and closes every descriptor above 6 before `execve`. It never overwrites fd
3 or fd 4 before the gate/config reads complete and never maps in-place across
an as-yet-unduplicated source. Non-Linux builds return exit code
127 before reading an inherited descriptor. Configuration and asset memfds are
regular anonymous zero-link descriptors with `FD_CLOEXEC`; the configuration memfd
requires exactly `F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE`. Kernel
and rootfs asset descriptors require those four seals, read-only access,
distinct device/inode identity, and exact identity/digest correlation supplied
by the validated live launch lease. A wrong type, seal, access mode,
descriptor identity, order, count, or correlation closes every accepted
duplicate and fails before revision-zero publication.

The private wire ABI is big-endian and exact:

```go
const (
	l8RuntimeOwnerProtocolMagic = "HL8OWNR1"
	l8RuntimeOwnerProtocolVersion uint16 = 1
	l8RuntimeOwnerPacketHeaderSize = 24
	l8RuntimeOwnerPacketLimit = 512
	l8RuntimeOwnerHandshakeTimeout = 5 * time.Second

	l8RuntimeOwnerOpcodeReject uint16 = 0
	l8RuntimeOwnerOpcodeBootstrapStart uint16 = 1
	l8RuntimeOwnerOpcodeBootstrapPublished uint16 = 2
	l8RuntimeOwnerOpcodeChildArmed uint16 = 3
	l8RuntimeOwnerOpcodeChildRelease uint16 = 4
	l8RuntimeOwnerOpcodeHandshake uint16 = 5
	l8RuntimeOwnerOpcodeAbortStart uint16 = 6
	l8RuntimeOwnerOpcodeInspect uint16 = 7
	l8RuntimeOwnerOpcodeStopReap uint16 = 8
	l8RuntimeOwnerOpcodeAcquireNamespaces uint16 = 9
	l8RuntimeOwnerOpcodeFinalize uint16 = 10
	l8RuntimeOwnerOpcodeCommit uint16 = 11
	l8RuntimeOwnerOpcodeClose uint16 = 12

	l8RuntimeOwnerStatusOK uint16 = 0
	l8RuntimeOwnerStatusRejected uint16 = 1
	l8RuntimeOwnerStatusInvalidState uint16 = 2
	l8RuntimeOwnerStatusUncertain uint16 = 3
	l8RuntimeOwnerStatusUnsupported uint16 = 4
)

type l8RuntimeOwnerPacketHeaderV1 struct {
	Magic [8]byte
	Version uint16
	Opcode uint16
	Status uint16
	BodyLength uint16
	Sequence uint64
}
```

Every packet is one complete `SOCK_SEQPACKET` datagram. Truncation,
`MSG_TRUNC`, `MSG_CTRUNC`, a packet longer than 512 bytes, a noncanonical
header, an unknown opcode/status, a nonzero request status, an unexpected
sequence, or a body whose exact length does not match its opcode is rejected.
The 24-byte header is the eight ASCII magic bytes, version, opcode, status,
body length, and sequence in that order. There are no padding or reserved
bytes. A rejected authentication or malformed packet receives the same empty
body with `StatusRejected`; field-specific diagnostics never cross the socket.
Opcode zero is response-only generic Reject: status rejected, sequence zero,
empty body, and no rights. For a structurally valid authenticated request, an
invalid-state, uncertain, or unsupported response echoes its opcode and
sequence, carries the corresponding nonzero status, and has empty body/no
rights. No request may carry nonzero status and no successful response may use
an unlisted body or rights role.

The complete role matrix is exact: BootstrapStart request `(seq=0,body=32,rights=2)`;
BootstrapPublished response `(seq=0,body=8,rights=0)`; ChildArmed request and
ChildRelease response `(seq=0,body=0,rights=0)`; Handshake request
`(seq=0,body=97..224,rights=0)` and response `(seq=0,body=51,rights=0)`;
AbortStart, Inspect, StopReap, AcquireNamespaces, and Close requests
`(seq>=1,body=43,rights=0)`; AbortStart, Inspect, StopReap, and Close successful
responses `(same seq,body=24,rights=0)`; AcquireNamespaces successful response
`(same seq,body=24,rights=2)`; Finalize request `(seq>=1,body=59,rights=0)` and
response `(same seq,body=51,rights=0)`; Commit request
`(seq>=1,body=94,rights=0)` and response `(same seq,body=8,rights=0)`. The role
validator is applied before body decoding or descriptor adoption. Rights on
any other role, missing rights on a rights-bearing role, multiple control
messages, non-`SCM_RIGHTS` control data, and any received descriptor count
other than the exact role count are rejected and all received descriptors are
closed.

The bootstrap-start packet has sequence zero and a 32-byte body of four
big-endian uint64 values: user-namespace device, user-namespace inode,
network-namespace device, and network-namespace inode. It carries exactly two
`SCM_RIGHTS` descriptors in user-then-network order. The supervisor requires
both descriptors to be `NSFS_MAGIC` namespace files and to match the supplied
device/inode correlation, sets `FD_CLOEXEC`, and retains them before it forks
the child. Missing, duplicate, extra, reordered, non-namespace, or mismatched
descriptors close every received descriptor and fail publication. The
bootstrap-published reply has sequence zero and exactly an eight-byte durable
record revision. Child-armed and child-release packets have sequence zero,
empty bodies, and no rights.

The handshake packet has sequence zero. Its body is the exact 43-byte
supervisor generation, a two-byte runtime-generation length followed by one to
128 validated safe-ID bytes, an eight-byte record revision, and the exact
43-byte reconnect secret. The successful response body is the new 43-byte
controller-session generation followed by the new eight-byte controller-claim
record revision. `AbortStart` is accepted only before ordinary controller
admission and otherwise uses the request shape below.

Every authenticated controller request body is exactly its 43-byte
controller-session generation. Its header sequence starts at one. Successful
inspect, abort-start, stop/reap, and close responses have an exact 24-byte body:
one owner-state byte, one absence-kind byte, six zero bytes, the record
revision, and a signed Unix-nanosecond observation encoded in an eight-byte
two's-complement field. Observation and absence kind are nonzero only for an
exact `absent` stop/reap result. Acquire-namespaces has the same 24-byte body
with zero observation fields and carries exactly two freshly duplicated
`SCM_RIGHTS` descriptors in user-then-network order. Its immediate replay
returns the byte-identical body plus fresh duplicates of the same retained
handles; this is an idempotent read, not a transfer of ownership from the
supervisor. Send failure closes only the duplicates. The supervisor retains
the originals through daemon restart, Firecracker absence, and same-boot
Finalize; supervisor loss makes namespace recovery uncertain. All receive,
validation, replay, controller-loss, and rejection paths close unaccepted or
created descriptors exactly once.

The exact lifecycle state-byte mapping is `starting=1`, `running=2`,
`stopping=3`, `absent=4`, `finalizing=5`, `finalized=6`, and `uncertain=7`.
Controller state is not encoded in the 24-byte lifecycle response. Absence kind is
zero for none, one for direct-child `Wait`, and two for replacement-owner
double-`/proc` absence. No packet transports an absence proof.

Finalize and commit remain protocol-complete even before their L7 caller is
wired. Finalize is accepted only on the authenticated controller after an
Acquire-namespaces response and only while the exact durable state is `absent`.
Its request body is the 43-byte controller-session generation, the eight-byte
absence record revision, and the signed eight-byte Unix-nanosecond observation
that must equal the supervisor's private fresh absence observation. It is sent
only after the daemon-side binding has validated the neutral absence proof and
completed correlated same-boot L7 cleanup. The supervisor first persists
`finalizing` with the HMAC commit ID and exact target revision, closes both
retained namespace originals, then persists `finalized`, and returns
exactly that 43-byte commit ID plus the eight-byte finalized revision. Failure
to close either namespace descriptor or persist the record returns uncertain
and retains the record; it never reports finalized.

Commit is accepted only for `finalized`. Its request body is the 43-byte
controller-session generation, the exact 43-byte commit ID, and the eight-byte
finalized revision. The supervisor verifies the owner-root HMAC, atomically
retires the per-runtime owner record, closes and removes its reconnect socket,
acknowledges success, and exits. The stable owner-root HMAC key is not a
per-runtime artifact and is not removed by this request. A response-loss replay
with record absent is authenticated by that stable key and is idempotent.
Controller Close is distinct: it has only the 43-byte session body, rotates
controller state to `unclaimed` without changing lifecycle, and never closes namespace originals, retires owner state, or
implies process/L7 absence.

The reconnect transport is a private Linux Unix `SOCK_SEQPACKET` listener. The
supervisor first obtains peer credentials and requires the exact daemon service
UID through same-UID `SO_PEERCRED`; request fields cannot supply or override the
peer. The first packet carries the fixed protocol version, supervisor
generation, runtime generation, record revision, and current one-use secret in
that order. Every comparison is exact and the secret comparison is constant
time. Wrong UID, malformed input, stale revision/generation, wrong secret,
timeout, extra packet, or concurrent claimant returns a generic rejection and
does not disclose which field failed.

At most one handshake and exactly one live controller are admitted. Before
acknowledging a successful handshake, the supervisor generates a new one-use
secret, atomically persists the next lifecycle-preserving controller
`controlled` revision, invalidates the old
secret, and binds a new random controller-session generation to that
connection. If persistence fails, it sends no success and the prior record
is reconciled under the commit-uncertain rule above. If success persistence completed but the acknowledgement is
lost, the daemon must reread the record and reconnect with the replacement
secret; replaying the consumed secret always fails. EOF or authenticated
controller close changes only controller state from `controlled` to `unclaimed`
with another atomic secret rotation while leaving lifecycle unchanged.

Controller requests carry the controller-session generation and an unsigned
64-bit sequence starting at one. Exactly one request may be outstanding. The
next sequence executes once; a duplicate of the immediately preceding sequence
returns the byte-identical cached sanitized response without repeating its
side effect; older, skipped, wrapped, cross-session, or concurrently outstanding
sequences fail closed. A lost connection never transfers a response cache to a
new session. New-session inspection and stop/reap are idempotent against the
durable owner FSM, so recovery resumes from lifecycle `running`, `stopping`,
`absent`, `uncertain`, `finalizing`, or `finalized` without replaying an
unproved transition. Admission never changes lifecycle. No request can move
`uncertain` to `absent` without a new exact absence observation or move
`absent` back to live.

### Stop, reap, supervisor loss, and L7 cleanup

Normal containment is owned by the still-parent supervisor. One internal
caller-independent deadline supplies one shared 30-second budget for the entire
`TERM -> KILL -> Wait/reap` sequence. The supervisor atomically records
`stopping`, sends TERM, waits for at most the first five seconds while consuming
that same budget, then sends KILL if terminal state was not observed and spends
only the remaining budget in the child's `Wait`. A signal error does not skip
KILL or Wait. Caller cancellation after admission does not detach cleanup or
shorten the internal budget. Only successful `Wait` of the exact child changes
the normal parent-owned state to `absent` and returns the private exact-absence observation. Deadline,
panic, signal failure without later confirmed reap, wait failure, controller
loss, record-write failure, or any ambiguous return records `uncertain`, returns
only a sanitized error, and preserves every owner and quarantine artifact.

Before exec, the supervisor sets Firecracker's Linux `PR_SET_PDEATHSIG` to
`SIGKILL` in the child and rechecks that its parent PID is still the expected
supervisor before exec. This is the exceptional containment path if the
supervisor itself crashes; it is not a substitute for normal direct-parent
reaping. A replacement owner serializes acquisition with the private directory
lock and reads the current `/proc/sys/kernel/random/boot_id` before inspecting a
PID. If it differs from `HostBootID`, no process from the recorded boot can
survive, but the owner never signals any current PID and never retires state on
that fact alone. A host-boot mismatch never authorizes signaling a current PID.
It retains quarantine and performs the exact seed-derived L7
cleanup correlation check, but the existing `l7network.Reconciler` cannot
reconstruct a vanished old-boot namespace or access its unexported journal
schema. This slice freezes no invented retirement authority. Old-boot owner and L7 journals remain quarantined
and finalize fails closed until a later `l7network`-owned old-boot durable
journal retirement API with exact proof input is separately designed and
implemented.

On the same recorded boot, the replacement uses `pidfd_open` for the recorded
supervisor and Firecracker PIDs, compares each pinned process's exact proc start
time with the record, and reinspects after every signal or poll. An exact
surviving supervisor is reconnected, never replaced. If the recorded supervisor
is absent and the exact recorded Firecracker incarnation remains, the
replacement additionally requires its observed parent PID to be exactly one.
This slice does not assume or authorize an unrecorded subreaper; any other
parent after exact supervisor absence is a replacement/mismatch and remains
uncertain without signalling. The replacement sends SIGKILL through that pidfd and waits for pidfd terminal
readiness. Readiness alone, including a zombie, never proves reap. Replacement
may record externally reaped absence only after the exact `/proc/<pid>` entry
is absent in two inspections separated by the acquisition barrier; it does not
claim that the replacement called `Wait` for a non-child. If the PID is already
absent, the same two inspections are required. A
different start time, PID reuse, replaced process, partial record,
supervisor/child mismatch, zombie, present proc entry, unavailable pidfd,
permission error, inspection race,
or uncertain terminal observation retains the record and L7 quarantine; it
neither signals the mismatched process nor returns absence.

During same-boot finalize after exact Firecracker absence, D6 constructs the exact seed-derived
`l7network.Identity` above and calls `l7network.NewReconciler`. The recovered
VM-termination verifier receives a private recovered `TerminatedVMBinding`
correlated to that identity and the exact supervisor/pidfd absence observation;
the binding, PID data, and termination proof ID are never worker or status
metadata. D6 calls `CleanupAfterVMQuiesced` with that identity and binding. It
accepts cleanup only after existing L7 recovery has quarantined the exact rule
generation and positively removed the correlated proxy, rules, TAP, namespace,
and topology journal. Finalize persists `finalizing` before starting that
cleanup and then persists `finalized` before returning. A retry from
`finalizing` either resumes cleanup from the exact retained journal or accepts
only its exact full-identity-bound durable retired-generation marker; it does
not reopen a removed journal. The
owner record is retired only by the later post-worker-clear commit and only
after that call and all required L7 release/record operations succeed. Missing topology state,
correlation mismatch, typed nil, panic, stale proof, cleanup error, or deadline
retains quarantine and the owner record for bounded retry.

On complete-identity restart, the binding first calls its exact credential
`RecoverJobCredentials` and validates any returned cleanup proof. Whether that
call succeeds, fails, panics, returns an invalid proof, or times out, the worker
then calls the same seed-bound `StopReapJobCredentialRuntime` and validates its
fresh absence proof, calls `FinalizeJobCredentialRuntimeRecovery`, durably
clears credential state, and calls `CommitJobCredentialRuntimeRecovery`. A failed recovery proof is
never trusted, but it cannot skip containment. Seed-only restart never calls
ordinary credential recovery and immediately follows that same stop/reap,
validation, finalize, durable-clear, and commit order.
Complete-identity recovery always proceeds to `StopReapJobCredentialRuntime` after `RecoverJobCredentials`, including after a valid cleanup proof.
Stop/reap is mandatory for both seed-only and complete-identity restart because
daemon reconciliation never resumes execution. Neither route recreates tickets,
sources, guest sessions, live handles, or execution.

This contract is Linux-only and explicit. Non-Linux implementations fail closed
with stable unsupported/dependency errors before creating a record, listener,
provider binding, or proof. Default and v1 constructors remain byte-for-byte inert
and do not start a supervisor, read owner state, import the concrete owner, bind
recovery, or project capability. This contract correction does not implement
the supervisor, neutral root API, Firecracker wrapper, provider, worker recovery
wiring, guest protocol, prepare/session transfer, or live verification.

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

PID1 preopens the three fixed `AF_VSOCK` listeners in the single-threaded
native launch bootstrap before installing `launch-base`. It binds CID any at
ports 1024/1025/1026 with fixed backlogs 64/1/4, reinspects them, and carries
them as PID1 FDs 12/13/14. Native PID1 clears close-on-exec only for its
immediate target; Go PID1 restores it before child creation. The exact agent
`ForkExec` maps copies to FDs 5/6/7 for the role-bootstrap and agent execs; Go
agent restores close-on-exec before admission. The agent verifies their
domain/type/listening/local-port identity before attestation and accepts only
after `steady-agent` and `composition_accepted`. PID1 then closes its
duplicates. No Go role creates,
binds, or listens on VSOCK, and a failed/partial listener set fails boot before
readiness. Port 1024 continues through the existing v1 transport behavior;
ports 1025 and 1026 use only the v2 control and relay paths below.

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
listener. The accept boundary retains and validates the kernel peer
`SockaddrVM`: the peer CID must be `VMADDR_CID_HOST`; the inherited listener's
revalidated local port, sealed expected guest CID, and Firecracker process,
runtime, vsock, boot, and image generations must match before a handshake. Peer CID alone is
not authentication because another host process could connect.

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
stream kind and `0x15 control_stream_credit` travels in the opposite direction
for that same kind. On the relay, `0x20 relay_request` is guest-to-controller and
`0x21 relay_response` is controller-to-guest; `0x7f close_notify` is valid in
either direction. `0x13` carries one binary `HL8B` record only; it never
multiplexes JSON into `0x10` or another type. `0x14` carries one binary `HL8S`
record only and `0x15` carries one binary `HL8C` credit record only. Magic,
version, zero flags, channel/type/direction, session ID, expected sequence, and
length are validated before allocation or AEAD open.

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

Each direction has an independent `uint64` counter. `Finished` is the first encrypted record and counts
toward the hard per-direction cap at sequence zero; the first application
record is one. Receipt must equal the next expected value: lower is replay and
higher is a gap. Counters advance only after authentication and semantic
validation, and writers are serialized. The cap is `2^32` total encrypted
records per direction, so legal sequences are zero through `2^32-1` and at
most `2^32-1` application records follow Finished; the session closes before
sequence `2^32`. Replay, gap,
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
time, every guest job activation/expiry, ticket hard expiry, helper/monitor
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

That rule is implemented through two-stage, bodyless request-root inspection,
not a generic JSON body. `v2control.InspectCredentialRequestRoot` consumes one
bounded root, retains only a private nonserializable operation token, request
ID, identity digest, and known-operation classification, and never retains a
body, map, `json.RawMessage`, unvalidated or raw string echo, or raw bytes. The
operation token contains only the validated private operation string. The
inspector requires exact canonical root-key order
`protocolVersion,operation,requestId,identityDigest,body`, compact scalar spellings and punctuation with no insignificant whitespace or alternate JSON encoding for the four inspected scalars, then token-skips exactly one syntactically complete bounded body value and requires EOF. Wrong root order, whitespace, extra/missing/duplicate root fields, incomplete syntax, or trailing data is unsafe and closes without a response.
A safe unknown operation receives `unknown_operation` without body decode only
after a job identity is active and the root digest exactly equals that active
identity. Its body schema remains uninterpreted. Before activation an unknown
operation is unsafe for response and closes without one: only readiness or a
known initial prepare can establish pre-active correlation. If safely
correlated, a malformed known operation receives `malformed_request` only when its concrete decoder reports
a body schema or canonical re-encode failure after complete root inspection;
the optional static field is omitted.
An unsafe or unusably correlated root closes without a response.
The first prepare is decoded only by
`DecodeInitialCredentialPrepareRequest`, which derives and authenticates its
`GuestCredentialSessionIdentity` from the canonical body `JobIdentity`, the
authenticated session ID, and the root digest; it accepts no caller-supplied
expected job identity. The returned request exposes only `JobIdentity`; Client
reconstructs the wrapper with
`NewGuestCredentialSessionIdentity(sessionID, request.Identity())`, verifies
the same root digest, and stores that exact
identity. `InspectedRequest` and the unknown/malformed dispatch arms use only
static fail-closed formatting, deny JSON/text/binary marshal and unmarshal
operations for value and pointer forms as applicable, preserve seeded receivers
unchanged on every unmarshal denial, and expose no mutation.

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

Stream admission uses one encrypted credit record per data record. The exact
64-byte `HL8C` plaintext is:

```text
magic[4]="HL8C" | version:u8=1 | streamKind:u8 | flags:u16_be=0
requestID:[16]byte | identityDigest:[32]byte | nextOffset:u64_be
```

The complete encrypted credit wire is exactly 132 bytes: the 52-byte `HL8F`
header, 64-byte plaintext, and 16-byte GCM tag. A credit authorizes exactly one
next `HL8S` data-or-EOF record for the same request, identity, stream kind, and
offset. At most one unused credit exists per stream. Duplicate, stale, gapped,
wrong-direction, wrong-request, wrong-identity, post-EOF, or second-outstanding
credit is a terminal protocol error. Stdin credit travels guest-to-controller;
stdout and stderr credit travel controller-to-guest. The controller grants an
output credit only while its corresponding bounded consumer slot is empty. The
guest grants upstream credit only while it owns that downstream credit and its
matching fixed slot is empty. An output stream at its byte maximum receives one
final EOF-only credit after excess bytes are drained and discarded under the
fixed process limit.

Each endpoint has one mutable payload slot per stream, capped at 64 KiB, and one
shared encoded transmit slot. Sends are nonblocking or use an effective write
deadline no later than the exec/session deadline. `EAGAIN` retains the exact
encoded frame in that slot and does not advance the secure sequence. The event
loop continues polling control reads, transport writability, stdin pipe
writability, both output pipes, the child pidfd, and cancellation. Ready credits
are scheduled before data; simultaneously ready stdout/stderr data use fixed
round-robin order, initially stdout. A peer that stops reading can still stall
the whole transport; that is session loss/timeout and follows ordinary cleanup,
never a claim of per-stream progress.

#### Safe-metadata transmit scratch correction

The single shared encoded transmit slot remains the only body retained for
socket retry. A redaction-safe metadata body may be constructed in one bounded
transient ordinary-heap scratch from a validated deep immutable typed snapshot;
its exact length and SHA-256 are pinned, it is copied synchronously into the
locked slot, and the scratch is overwritten through full capacity immediately
after every construction, digest, or copy attempt. This exception applies only
to fields already classified as safe IDs, catalogs, counts, timestamps, and
digests. It does not apply to file, opaque-exec, stdin, stdout, or stderr
payloads: those move from their locked body capability directly into the shared
encoded transmit slot without an ordinary-heap payload copy. The transport
does not retain or re-encode a `SendPacket` on `EAGAIN`; it retries the exact
already-filled slot and wipes that slot after commit or terminal failure.

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

D2 closes only the exact lexical boundary representable without parsing HTTP.
Before calling the selected leaf, the Registry requires a nonempty authority of
at most 512 ASCII bytes with no control/space, userinfo `@`, `/`, `\\`, `?`, or
`#`; a nonempty origin path of at most 4096 ASCII bytes beginning with `/` and
containing no control/space, `\\`, `?`, or `#`; and a raw query of at most 4096
ASCII bytes with no leading `?`, control/space, `\\`, or `#`. Path and query
percent triplets are exactly uppercase `%HH`; malformed triplets and lowercase
hex are rejected. This is lexical contract validation, not URL or HTTP parsing.

The header accessor must be nonnil and not typed nil. Two safe reads of `Names`
must agree and yield no more than 128 strictly increasing unique lowercase
canonical names. Each name is 1..256 ASCII bytes drawn only from
lowercase letters, digits, and the exact punctuation
``!#$%&'*+-.^_`|~``; every listed name has a stable positive
`ValueCount` across two reads. An accessor panic, changed snapshot, or invalid
count fails with the existing sanitized `ErrHandlerDispatch`. Registry does not
probe unlisted names or invoke `CopyValue`; the selected handler owns exact
per-name, duplicate-count, and value-bound enforcement. The accessor contract
still requires defensive `Names` copies and all-or-error `CopyValue`: success
returns the exact copied byte count with no retained destination alias, while
every failure overwrites the caller's entire destination. D2 tests this with
conforming and adversarial fakes but cannot structurally enforce arbitrary
implementations.

`RequestTarget` remains the exact exported three-string live boundary above so
the selected handler can inspect it. It nevertheless has static value-receiver
`String`, `GoString`, and `Format` output, denies JSON/text/binary marshaling,
and its pointer denies JSON/text/binary unmarshaling without inspecting or
changing the receiver. The containing `Request` keeps the same live opacity;
its formatting and serialization paths never traverse target, header accessor,
or body. Target/header validation happens before leaf dispatch and uses
`ErrHandlerDispatch`; existing request metadata size failures remain
`ErrStreamBounds`. No new public error identity is introduced.

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

The L8 image separates its service and workload identities. The guest-agent
bootstrap reaches dedicated UID/GID 998 with every capability set empty before
descriptor hello or admission; every workload reaches UID/GID 1000 before its
final exec. The L8
isolation verifier takes the expected service identity explicitly; completed L5
images and their UID/GID-1000 verifier remain byte-compatible. Both identities
have empty capability sets and `no_new_privs`, and L8 never raises or restores
their privilege.

PID1 is the one explicit immutable launch authority. Before protocol input,
its one-way `launch-bootstrap` establishes the frozen FDs, exact six-bit
capability inheritance, the three fixed VSOCK listeners, locked securebits, and
`no_new_privs`, then commits the
`launch-base` filter and can never return. That filter
is the common ancestor policy for the image-pinned credential controller,
service agent, per-job mount monitor, and workload transition shim. PID1's bounding set is
exactly `CAP_SYS_ADMIN`, `CAP_SYS_CHROOT`, `CAP_SETUID`, `CAP_SETGID`,
`CAP_SETPCAP`, and `CAP_CHOWN`; those exact six bits populate its bounding,
permitted, effective, inheritable, and ambient sets, and every other bit is
removed. The launch supervisor accepts only the D2 closed launch protocol over
an unnamed private `SOCK_SEQPACKET` socket. It never accepts from the preopened
VSOCK listeners and exposes no public launch endpoint. It accepts no executable
path, arbitrary clone flag, argv, environment, or credential body. It launches
only the immutable image-owned
`hal-guest-role-bootstrap` in exact monitor or workload-shim mode. There is no
general-purpose or unmediated privileged launcher.

`hal-guest-role-bootstrap` is the single-threaded native role bootstrap for
PID1 init, controller, agent, monitor, and shim. It has no Go runtime, allocator,
thread creation, dynamic loader, network client, public input, or generic
process API. PID1 mode's sole network exception is the compiled creation of the
three fixed VSOCK listeners before `launch-base` commits.
The image entrypoint invokes its fixed PID1 mode; every later `syscall.ForkExec`
targets only this binary with one adapter-owned closed role enum and fixed
target. The bootstrap runs before any Go runtime starts and establishes that
role's pre-runtime root/UID/GID/capability/securebit state, reinspects its
inherited FD inputs, and `execve`s the corresponding image-profile-pinned Go
binary in the same PID and pidfd. PID1 mode establishes the exact six-set
inheritance before execing `hal-guest-init`; controller mode pivots then clears
all capability sets; agent mode drops bounding state and switches to UID/GID
998 under normal fixups; monitor mode retains exactly
`CAP_SYS_ADMIN|CAP_CHOWN`; shim mode enters the verified job mount namespace
while still single-threaded, then retains only
`CAP_SETUID|CAP_SETGID|CAP_SETPCAP` for the Go identity transition.
After PID1 target exec, `hal-guest-init` constructs the remaining frozen
supervisor FD table before readiness.
Unknown role, changed argv/environment/path/FD, failed reinspection, or failed
exec exits without starting a Go runtime and forces owned-role cleanup.

Seccomp ancestry is explicit. The credential controller stacks the narrow
`steady-controller` filter and the agent stacks `steady-agent`; neither
launches a process. A mount monitor is a
direct PID1 child created by pinned Go 1.25.7 `syscall.ForkExec` with
`SysProcAttr.Cloneflags=CLONE_NEWNS`, `UseCgroupFD=false`, and a non-nil
`PidFD`; the pinned runtime materializes exact kernel `clone` flags
`CLONE_VFORK|CLONE_VM|CLONE_NEWNS|CLONE_PIDFD` plus `SIGCHLD`. A workload shim
is a direct PID1 child placed atomically by the same pinned launcher with
`SysProcAttr.Cloneflags=0`, `UseCgroupFD=true`, exact `CgroupFD=9`, and a
non-nil `PidFD`; the pinned runtime materializes exact kernel `clone3` flags
`CLONE_VFORK|CLONE_VM|CLONE_PIDFD|CLONE_INTO_CGROUP` plus `SIGCHLD`. The shim
native stage performs `setns` before Go can create a `CLONE_FS` thread; the Go
stage stacks `workload-transition` before reading its launch block or gate and
the verified `WorkloadSnapshot`-derived filter before the final pinned-FD
`execveat`.
Neither is descended from a filtered service process, so no child must relax
an inherited filter. The launch-base policy
is a reviewed superset needed by its descendants; PID1 is part of the guest TCB,
contains no credential bytes, and remains reachable only from the authenticated
controller endpoint.

The D2 bootstrap contract resolves process-identity ordering explicitly. PID1
creates separate agent-controller, controller-supervisor, and agent-supervisor
seqpacket pairs, enables `SO_PASSCRED` on every endpoint, creates a 32-byte random
controller-local boot nonce, and starts the credential controller role
bootstrap first with the exact image-profile-pinned service `clone` tuple
`CLONE_VFORK|CLONE_VM|CLONE_PIDFD|SIGCHLD`. The controller rechecks
`SO_PASSCRED`, fixed descriptors, generation, sealed runtime settings, and
hardening, verifies every capability set was already cleared by the native
bootstrap, stacks `steady-controller`, sends its canonical
`controller_attestation` over the supervisor endpoint, then sends
`helper_ready`; PID1 verifies the sealed descriptor digest and exact known
controller PID/UID/GID before doing anything else. A bootstrap can never be
queued before both records are accepted.

PID1 then creates the guest-agent role bootstrap with pinned
`syscall.ForkExec` and exact
`clone(CLONE_VFORK|CLONE_VM|CLONE_PIDFD|SIGCHLD)` behind the application gate.
It sends the agent one authenticated `HL8A agent_config` packet containing the
expected controller PID/UID/GID, helper and boot generations, nonce, bootstrap
digest, expected client process-descriptor digest, and sealed VSOCK-generation
identity. The agent receives the preopened v1/control/relay listeners as fixed
FDs 5/6/7 in the same launch. No request or credential body is present.

The native `agent-bootstrap` drops all bounding bits while `CAP_SETPCAP` is
effective, switches supplementary groups/GID/UID to exact 998 under normal
kernel UID capability fixups, clears remaining inheritable state, and execs the
agent. The Go agent therefore starts with every capability set empty; before
any hello or admission release it verifies that state and the exact three
inherited listener identities, commits the steady-agent filter, and only then
constructs the client descriptor.
It sends that canonical descriptor directly to PID1 in authenticated
`HL8A client_attestation`; PID1 verifies the packet's exact agent PID/UID/GID
998 against the new pidfd and sealed digest before representing that identity
to the controller.

PID1 now sends one atomic helper bootstrap datagram from exact PID 1, UID 0,
and GID 0. It carries exactly one `SCM_RIGHTS` descriptor: the already-verified
agent pidfd. The helper treats the trusted PID1 packet as the binding between
that pidfd and the reported agent PID/UID/GID 998. The controller proves agent liveness by pidfd polling only,
requiring a non-readable/non-hung-up result; it has no signal permission for UID
998 and never calls `pidfd_send_signal`. It records both identities without
claiming that pidfd alone reveals a numeric PID. PID1
requires the correlated bootstrap acknowledgement before composition release.

PID1 verifies both sealed descriptor digests, validates the matching extension
sets and policy identities, then sends `composition_accepted` with the canonical
composition digest independently over HL8L to the controller and HL8A to the
agent. Only then does the agent send `agent_hello` with its canonical client
descriptor over the agent-controller endpoint. The controller authenticates
the already-pinned agent identity and descriptor, sends `agent_hello_ack`, and
admits v2 requests. The agent verifies those exact `SCM_CREDENTIALS` on every
helper response; socket EOF is permanent helper loss, so PID reuse cannot
acquire the unshared socketpair endpoint. The
helper requires every later request's one credentials record to match the
recorded agent and its still-live pidfd. `MSG_TRUNC`, `MSG_CTRUNC`, missing or
duplicate credentials, unexpected rights, extra file descriptors, stale
boot/helper/job generation, replay, sequence gap, and sequence wrap fail
closed. Any received descriptor is closed on every rejection path. PID1 closes
its agent-supervisor, temporary agent-control, and VSOCK-listener duplicates
only after both accepted packets commit. The agent then accepts v1 on FD 5, one
active v2 control stream on FD 6, and at most four relay streams on FD 7. Any
mismatch, missing/duplicate attestation, or loss before release stops/reaps the
microVM; no partially composed agent admits a request.

Inherited descriptor numbers are role-specific and frozen in the syscall
supplement. The controller receives agent socket 3, supervisor socket 4,
minimal-root FD 5, and sealed bootstrap config 6. Active job slots hold only the
monitor endpoint, namespace FD, cgroup identity capability, and safe PID1-owned
launch correlation; the controller never owns a clone or mount capability. A
monitor receives its direct controller endpoint at FD 3, verified proc-root and
fixed mount-target FDs, sealed config, self namespace FD 7, plus launch-only
controller peer FD 9 and PID1 bootstrap endpoint FD 10. It sends FD 9 and FD 7
once over FD 10, closes FD 9 and FD 10 permanently, and retains FD 3 and FD 7.
PID1's fixed FD 10 independently remains the monitor pidfd; its bootstrap peer
is instead recorded in a transient slot. A workload shim receives the inspected
namespace/workdir/executable/pipe/gate/launch-block FDs for one launch; the
native shim consumes and closes the namespace FD before starting Go; the launch
block is the Go shim's complete sealed config and FD 8 is closed. The agent
receives controller socket 3, agent-supervisor socket 4, and the preopened
VSOCK listeners at 5/6/7. All
unrelated descriptors are closed, and no workload inherits a control, root,
namespace, cgroup, pidfd, config, gate, launch-block, or nonce descriptor.

### Normative HL8L controller-supervisor ABI

The private controller-supervisor codec is one atomic Unix
`SOCK_SEQPACKET|SOCK_CLOEXEC` datagram per packet. It is neither a byte stream
nor a public or durable protocol. The constants are exact:

```text
HL8LHeaderBytes = 68
HL8LMaxBodyBytes = 8192
HL8LMaxDatagramBytes = 8260
HL8LMaxPacketsPerDirection = 4294967296
```

The header byte layout is:

```text
offset  size  field
0       4     magic[4] = ASCII "HL8L"
4       1     version:u8 = 1
5       1     type:u8
6       2     flags:u16_be = 0
8       8     sequence:u64_be
16      16    requestID:[16]byte
32      32    jobIdentityDigest:[32]byte
64      4     bodyLength:u32_be
68      n     body
```

`bodyLength` is body bytes only, equals the datagram remainder exactly, and is
at most 8192. A shorter datagram is truncation and a longer one has trailing
data; neither is a second packet. Every multibyte integer is big-endian. A body
`token` delegates exactly to `credentialprotocol.EncodeBodyToken`,
`DecodeBodyTokenPrefix`, `ValidateBodyToken`, and `MaxBodyTokenBytes`: its wire
is `uint16_be(length) || ASCII bytes`, length 1 through 128, matching
`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` without trimming, normalization, Unicode,
case folding, or defaulting. A field identified below as a safe ID is first
decoded as that body token and then must pass
`credentialprotocol.ValidateSafeID`, whose exact grammar is 1 through 128
ASCII bytes from `[A-Za-z0-9._-]`; a colon is therefore rejected for every
generation, launch, and limit-set ID. An
`optional-token` is `uint16_be(0)` for absent or the same canonical nonempty
token form; no other nullable encoding exists. Booleans are one byte and are
exactly zero or one. SHA-256 fields are 32 raw bytes and are nonzero unless a
type-specific matrix below explicitly requires the all-zero value. No body is
JSON, text, a generic map, a generic body, or an extensible tagged union.

Every receive supplies this independent kernel metadata to the pure decoder:

```text
Direction:closed enum | CredentialCount:uint32 = 1 |
Credential:{PID:uint32, UID:uint32, GID:uint32} |
RightsCount:uint32 | MSG_TRUNC:bool | MSG_CTRUNC:bool
```

D2 represents inspected rights without representing live descriptors. The
exact concrete, non-JSON vocabulary is:

```text
right kind: 1 monitor_endpoint, 2 monitor_namespace, 3 workdir,
            4 executable, 5 stdin_read, 6 stdout_write, 7 stderr_write,
            8 start_gate_read, 9 launch_block_read
right access: 1 duplex_seqpacket, 2 namespace_enter, 3 directory_chdir,
              4 executable_read, 5 pipe_read, 6 pipe_write,
              7 sealed_pipe_read

HL8LRightMetadata = {
  Kind:HL8LRightKind, Access:HL8LRightAccess, Generation:SafeID,
  SHA256:[32]byte
}

HL8LReceiveMetadata = {
  Direction:HL8LDirection, Credential:HL8LKernelCredential,
  CredentialCount:uint32, RightsCount:uint32,
  Rights:[8]HL8LRightMetadata,
  MessageTruncated:bool, ControlTruncated:bool
}
```

The fixed array prevents a generic or caller-sized rights body; only its first
`RightsCount` entries may be nonzero and every remaining entry must be zero.
`RightsCount > 8` is rejected before any array index or role comparison.
For `job_created`, endpoint metadata uses `monitorGeneration` and namespace
metadata uses `mountGeneration`; both SHA-256 fields are exactly the received
and validated `monitorReadySHA256`, which is protocol correlation only and is
not proof of either live object. For `launch_shim`, namespace and workdir use
`mountGeneration`/`launchShimSHA256`, executable uses
`jobGeneration`/`executableSHA256`, the four ordinary pipe/gate rights use
`launchID`/`launchShimSHA256`, and the launch block uses
`launchID`/`launchBlockSHA256`. Endpoint is `duplex_seqpacket`, namespace is
`namespace_enter`, workdir is `directory_chdir`, executable is
`executable_read`, stdin and gate are `pipe_read`, stdout/stderr are
`pipe_write`, and launch block is `sealed_pipe_read`. No production D2 type has
an `FD`, integer descriptor, `any`, map, raw ancillary bytes, callback, live
handle, or interface body. D4 constructs this metadata only after kernel
inspection and remains owner of all live rights until the D2 transition says
ownership committed.

The role metadata order is closed and exact:

| Packet/index | kind | access | generation | SHA-256 metadata |
| --- | --- | --- | --- | --- |
| `job_created/0` | `1 monitor_endpoint` | `1 duplex_seqpacket` | `monitorGeneration` | `monitorReadySHA256` |
| `job_created/1` | `2 monitor_namespace` | `2 namespace_enter` | `mountGeneration` | `monitorReadySHA256` |
| `launch_shim/0` | `2 monitor_namespace` | `2 namespace_enter` | `mountGeneration` | `launchShimSHA256` |
| `launch_shim/1` | `3 workdir` | `3 directory_chdir` | `mountGeneration` | `launchShimSHA256` |
| `launch_shim/2` | `4 executable` | `4 executable_read` | `jobGeneration` | `executableSHA256` |
| `launch_shim/3` | `5 stdin_read` | `5 pipe_read` | `launchID` | `launchShimSHA256` |
| `launch_shim/4` | `6 stdout_write` | `6 pipe_write` | `launchID` | `launchShimSHA256` |
| `launch_shim/5` | `7 stderr_write` | `6 pipe_write` | `launchID` | `launchShimSHA256` |
| `launch_shim/6` | `8 start_gate_read` | `5 pipe_read` | `launchID` | `launchShimSHA256` |
| `launch_shim/7` | `9 launch_block_read` | `7 sealed_pipe_read` | `launchID` | `launchBlockSHA256` |

No SHA-256 metadata in this table attests a live FD. It only binds the role to
an already defined canonical protocol correlation or content digest; D4's
kernel reinspection is separately mandatory and authoritative.

PID1 credentials are exactly PID 1, UID 0, GID 0. Controller credentials are
the PID from 2 through `math.MaxInt32` pinned from the successful image-owned
controller launch, distinct from PID1 and the pinned agent PID, and UID 0,
GID 0. D2 retains all kernel PID/UID/GID metadata as `uint32` and validates
bounds before any conversion; it never narrows the values. A request field can
never select either identity. Missing or
duplicate `SCM_CREDENTIALS`, a changed PID/UID/GID, `MSG_TRUNC`, `MSG_CTRUNC`,
or any wrong/missing/extra right is a terminal protocol failure. There is no
numeric FD, PID, UID, GID, inode, device, cgroup path, mount path, executable
path, socket address, credential body, argv, or environment value in an HL8L
body or digest.

The type/direction/identity/rights matrix is closed:

| Type | Name and direction | request ID | job digest | rights |
| --- | --- | --- | --- | ---: |
| `0x01` | `supervisor_ready`, PID1 -> controller | zero | zero | 0 |
| `0x02` | `create_job`, controller -> PID1 | nonzero | nonzero | 0 |
| `0x03` | `job_created`, PID1 -> controller | exact echoed `0x02` | exact echoed `0x02` | 2 |
| `0x04` | `launch_shim`, controller -> PID1 | nonzero | exact active job | 8 |
| `0x05` | `shim_started`, PID1 -> controller | exact echoed `0x04` | exact echoed `0x04` | 0 |
| `0x06` | `terminate_job`, controller -> PID1 | nonzero | exact active job | 0 |
| `0x07` | `destroy_job`, controller -> PID1 | nonzero | exact active job | 0 |
| `0x08` | `supervisor_event`, PID1 -> controller | exact causative request | exact active job | 0 |
| `0x09` | `controller_attestation`, controller -> PID1 | zero | zero | 0 |
| `0x0a` | `composition_accepted`, PID1 -> controller | zero | zero | 0 |
| `0x7f` | `close_notify`, either direction | zero | zero | 0 |

No type is valid in the opposite direction. “Exact echoed” is byte equality,
not re-encoding. A job request ID is a nonzero 16-byte idempotency/correlation
identifier and is unique for the lifetime of the link. It cannot be reused for
another operation, even with identical bytes. For a launch, `launchID` is the
exact 22-character unpadded-base64url encoding of that request ID; decoding it
must reproduce the header bytes. An event reuses its causative operation's
request ID and never invents a second event identifier. Loss of an atomic local
response is link loss: response loss is supervisor loss and requires whole-VM
stop/reap, not request replay. This deliberately avoids retaining or
retransferring live rights for idempotency.

The two rights on `job_created` are, in order:

1. the controller side of the new monitor's inspected
   `AF_UNIX/SOCK_SEQPACKET|SOCK_CLOEXEC` pair with `SO_PASSCRED`; and
2. the monitor-created, PID1-reinspected live mount-namespace capability received
   through authenticated `HL8M monitor_ready`, with `NSFS_MAGIC`,
   `NS_GET_NSTYPE == CLONE_NEWNS`, exact generation, and inequality from the
   supervisor namespace already proved.

Thus `job_created` transfers exactly one monitor endpoint right and one
monitor-created namespace authority; “exactly one endpoint right” never meant
that the namespace authority could be omitted. PID1 creates both the temporary
PID1-monitor bootstrap pair and the separate long-lived controller-monitor
pair before launch. The monitor receives its long-lived endpoint at fixed FD 3,
the long-lived controller peer at launch-only FD 9, and its temporary bootstrap
endpoint at launch-only FD 10. PID1 holds the matching bootstrap peer in a
recorded transient slot; PID1 fixed FD 10 remains the monitor pidfd. Its
`HL8M monitor_ready` sequence-zero packet sends exactly two rights over monitor
FD 10 to PID1 in this order: monitor FD 9, the long-lived controller peer, then
monitor FD 7, the live namespace
capability. Its body carries revision, job, monitor, mount, and cgroup
generations, `helper-limits-v1`, the exact `createJobSHA256`, and the exact
`monitorReadySHA256`. PID1 requires byte equality with its pending create tuple,
recomputes the ready digest, and authenticates and reinspects both rights before
the monitor permanently closes FD 9 and FD 10 and retains only fixed FD 3 and
namespace FD 7. PID1 relays those same two
authorities in `job_created` in the same order, echoes the same
`monitorReadySHA256`, and closes its duplicates after authenticated transfer.
Direct controller-monitor HL8M traffic begins with controller send
sequence zero and monitor send sequence one, preserving the monitor's consumed
sequence-zero readiness record without replaying it.

The controller owns both only after
the complete packet, credentials, body, digests, rights, and state transition
commit. Before commit the receiver owns and closes both on every error. The
controller retains the endpoint for `HL8M` and the namespace capability for
the job lifetime, passes a fresh duplicate of the namespace capability in each
launch, performs all direct monitor cleanup through that endpoint, and closes
both before it is permitted to send `destroy_job`.

The eight controller-supplied rights on `launch_shim` retain the already frozen
order: monitor namespace, workdir, executable, child stdin-read, stdout-write,
stderr-write, start-gate read, and sealed launch-block read. Their exact
required kinds are:

```text
monitor namespace, workdir, executable, child stdin-read, stdout-write, stderr-write, start-gate read, and sealed launch-block read
```

1. a duplicate of the active inspected `NSFS` mount-namespace capability;
2. an `O_PATH|O_DIRECTORY|O_CLOEXEC` workdir beneath the pinned workspace root;
3. the frozen L4 regular executable capability, `O_PATH|O_CLOEXEC`, executable
   and contained beneath an image-pinned executable root;
4. the read end of the inspected stdin pipe;
5. the write end of the inspected stdout pipe;
6. the write end of the inspected stderr pipe;
7. the read end of the empty, unread supervisor start-gate pipe; and
8. the read end of the bounded launch-block pipe after its controller write
   end is closed and the exact bytes hash to `launchBlockSHA256`.

PID1 takes ownership of all eight only after one atomic receive. It reinspects
kind, access direction, close-on-exec state, generation, namespace and cgroup
correlation before launch. Rejection closes all eight. After successful pinned
`ForkExec`, the child mappings own the required copies and PID1 closes every
unneeded copy; the gate's PID1 write end remains the sole release authority.
No descriptor integer enters `launchShimSHA256`. The controller retains only
its parent pipe ends and its original job namespace capability.

The bodies are exact, in the displayed byte order:

```text
0x01 supervisor_ready:
  bootGeneration:token | helperGeneration:token |
  supervisorGeneration:token | limitSetID:token |
  supervisorReadySHA256:[32]byte

0x02 create_job:
  revision:u64 | jobGeneration:token | monitorGeneration:token |
  mountGeneration:token | cgroupGeneration:token | limitSetID:token |
  monitorConfigSHA256:[32]byte | cgroupConfigSHA256:[32]byte

0x03 job_created:
  revision:u64 | jobGeneration:token | monitorGeneration:token |
  mountGeneration:token | cgroupGeneration:token | limitSetID:token |
  createJobSHA256:[32]byte | monitorReadySHA256:[32]byte

0x04 launch_shim:
  revision:u64 | jobGeneration:token | monitorGeneration:token |
  mountGeneration:token | cgroupGeneration:token |
  launchID:token | limitSetID:token |
  executableSHA256:[32]byte | launchBlockSHA256:[32]byte

0x05 shim_started:
  revision:u64 | jobGeneration:token | monitorGeneration:token |
  mountGeneration:token | cgroupGeneration:token |
  launchID:token | launchShimSHA256:[32]byte

0x06 terminate_job and 0x07 destroy_job:
  revision:u64 | jobGeneration:token | monitorGeneration:token |
  mountGeneration:token | cgroupGeneration:token | reason:u8

0x08 supervisor_event:
  eventCode:u8 | requestType:u8 | failureCode:u8 | reserved:u8=0 |
  revision:u64 | jobGeneration:token | monitorGeneration:token |
  mountGeneration:token | cgroupGeneration:token | launchID:optional-token |
  exitCategory:u8 | exitCode:i32 | zeroPopulation:u8 |
  monitorState:u8 | cleanupCategory:u8

0x09 controller_attestation:
  descriptorLength:u16 | canonical controller ProcessDescriptor

0x0a composition_accepted:
  compositionSHA256:[32]byte

0x7f close_notify:
  closeReason:u8
```

`descriptorLength` is 1 through `MaxProcessDescriptorBytes` (currently the
existing locked value 1898) and equals the remaining descriptor
bytes. Decoding delegates to the canonical `DecodeProcessDescriptor`, requires
`ProcessRoleHelper`, re-encodes with `EncodeProcessDescriptor`, requires byte equality,
and compares SHA-256 of those exact bytes with the image-sealed controller
descriptor digest. Reusing `ProcessRoleHelper` is deliberate: the credential
controller process hosts the privileged helper service policy, while
`ProcessRoleClient` names the unprivileged agent-side client. There is no third
controller descriptor role to invent. PID1 never copies or locally redefines
`HL8D`. The
`composition_accepted` value is exactly the `CompositionSHA256` returned by
`ValidateProcessDescriptors(helper, client)`, whose existing domain is
`hal/l8/process-composition/v1`; HL8L does not wrap or reinterpret it.

All generation fields and `limitSetID` are safe IDs. The controller mints the
job, monitor, mount, and cgroup generations, and every job-scoped request or
result carries that complete tuple. `revision` is positive;
create is exactly revision 1. A later new operation's revision is not less
than the current revision; an increase atomically replaces the current value
only when that request commits. Equal revisions allow multiple launches under
one activation. A lower revision is stale and terminal. All later generation
and limit fields equal the committed create tuple byte-for-byte. The sole limit
set is `helper-limits-v1`, the one fixed limit-set ID shared by the HL8L
supervisor, HL8M monitor, HL8P helper service, and client policy. It denotes one
job, one monitor/cgroup/namespace, one active credential-aware execution,
4096 lifetime launches, 256 role FDs,
the existing body/file/stream limits, three cleanup attempts, the 30-second
cleanup deadline, and the 35-minute hard session lifetime. No caller-selected
number accompanies that ID. The generic L4 server may support up to 64
concurrent ordinary v1 executions, but this L8 limit set deliberately narrows
the one-outstanding helper transaction and `CoreExecution` ownership to one;
neither catalog is projected as the other.

The supervisor reason catalog is closed and nonzero:

```text
supervisor reason: 1 requested, 2 expired, 3 session_loss,
                   4 source_revoked, 5 worker_cancel, 6 daemon_shutdown,
                   7 launch_failed, 8 exec_failed
```

The `supervisor_event` catalogs are closed:

```text
event code:       1 shim_exited, 2 operation_failed, 3 job_terminated,
                  4 job_destroyed, 5 cleanup_observed
failure code:     0 none, 1 resource_limit, 2 create_failed,
                  3 launch_failed, 4 terminate_failed, 5 destroy_failed,
                  6 cleanup_incomplete, 7 monitor_unavailable,
                  8 cgroup_unavailable,
                  9 process_termination_unconfirmed
exit category:    0 not_applicable, 1 exited, 2 signaled,
                  3 launch_transition_failed, 4 unknown
monitor state:    0 not_applicable, 1 starting, 2 ready,
                  3 cleanup_pending, 4 absent, 5 lost
cleanup category: 1 not_applicable, 2 cleanup_complete,
                  3 retry_required, 4 stop_vm_required
close reason:     1 normal, 2 protocol_error, 3 identity_drift,
                  4 expired, 5 helper_loss, 6 shutdown
```

`close reason` deliberately reuses the exact `credentialprotocol.CloseReason`
numeric catalog used by `HL8P` and `HL8A`; no conversion table exists.
`terminate_job` accepts supervisor reasons 1 through 8. `destroy_job` accepts
only reasons 1 through 6 because launch/exec failure is a termination cause,
not authority to skip the required terminated state. The failure-code/request
matrix is exact:

```text
0x02 create_job:    1 resource_limit, 2 create_failed,
                    6 cleanup_incomplete, 7 monitor_unavailable,
                    8 cgroup_unavailable
0x04 launch_shim:   1 resource_limit, 3 launch_failed,
                    6 cleanup_incomplete, 7 monitor_unavailable,
                    8 cgroup_unavailable,
                    9 process_termination_unconfirmed
0x06 terminate_job: 4 terminate_failed, 6 cleanup_incomplete,
                    7 monitor_unavailable, 8 cgroup_unavailable,
                    9 process_termination_unconfirmed
0x07 destroy_job:   5 destroy_failed, 6 cleanup_incomplete,
                    7 monitor_unavailable, 8 cgroup_unavailable
```

No other request/failure pair is valid.
`exitCode` is 0 through 255 for `exited`, 1 through 64 for `signaled`, exactly 1
for `launch_transition_failed`, and zero for `not_applicable` or `unknown`.
Zero population is a canonical boolean and is evidence only when one. The
event union rules are:

| Event | Correlation and exact canonical fields |
| --- | --- |
| `shim_exited` | `requestType=0x04`; header request ID and `launchID` match one entry in the completed-launch ledger; `failureCode=0`; exit category is 1, 2, or 3 with its allowed code; `zeroPopulation` is the exact observation and may be zero or one; monitor state is ready or cleanup-pending; `cleanupCategory=not_applicable`. This event correlation does not reuse the ID for a controller request. |
| `operation_failed` | `requestType` is 0x02, 0x04, 0x06, or 0x07 and header request ID echoes that outstanding request; the matching nonzero failure code is required; launch ID is present only for 0x04; exit fields are not-applicable/zero; cleanup is not-applicable only for a pre-mutation resource-limit rejection, otherwise complete, retry, or stop-VM. |
| `job_terminated` | `requestType=0x06`, exact outstanding request, `failureCode=0`, absent launch ID, not-applicable/zero exit, `zeroPopulation=1`, monitor ready or cleanup-pending, cleanup not-applicable. |
| `job_destroyed` | `requestType=0x07`, exact outstanding request, `failureCode=0`, absent launch ID, not-applicable/zero exit, `zeroPopulation=1`, monitor absent, cleanup complete. |
| `cleanup_observed` | is the sole terminal result for the exact outstanding causative 0x02/0x04/0x06/0x07 request; `failureCode=cleanup_incomplete`; launch ID is present only when the cause is 0x04; exit fields are not-applicable/zero; cleanup is retry-required or stop-VM and monitor/zero-population report the inspected state. It is never spontaneous and never references a completed request. |

Any other enum, zero/nonzero combination, reserved byte, result request type,
or trailing byte is malformed. `job_created` and `shim_started` mean success
only; failure is never inferred from an empty body and is represented only by
the exact `operation_failed` event. Successful terminate and destroy results
are respectively `job_terminated` and `job_destroyed` events. A canonical
resource-limit request can be an accepted semantic rejection: it consumes the
receive sequence, performs no mutation, and gets exactly one correlated
`operation_failed` event with `failureCode=resource_limit` and cleanup
not-applicable. Authentication, framing, identity, sequence, generation,
rights, or transition failures are not semantic rejections and emit no packet.

The digest definitions use the existing `opaque16` encoding. Exact token wire
bytes below include their `uint16_be` length:

```text
supervisorReadySHA256 = SHA256(
  opaque16("hal/l8/controller-supervisor/supervisor-ready/v1") ||
  bootGeneration:token || helperGeneration:token ||
  supervisorGeneration:token || limitSetID:token)

monitorConfigSHA256 = SHA256(
  opaque16("hal/l8/controller-supervisor/monitor-config/v1") ||
  jobIdentityDigest || jobGeneration:token || monitorGeneration:token ||
  mountGeneration:token || limitSetID:token)

cgroupConfigSHA256 = SHA256(
  opaque16("hal/l8/controller-supervisor/cgroup-config/v1") ||
  jobIdentityDigest || jobGeneration:token || cgroupGeneration:token ||
  limitSetID:token)

createJobSHA256 = SHA256(
  opaque16("hal/l8/controller-supervisor/create-job/v1") ||
  jobIdentityDigest || uint64_be(revision) || jobGeneration:token ||
  monitorGeneration:token || mountGeneration:token ||
  cgroupGeneration:token || limitSetID:token || monitorConfigSHA256 ||
  cgroupConfigSHA256)

monitorReadySHA256 = SHA256(
  opaque16("hal/l8/controller-monitor/monitor-ready/v1") ||
  jobIdentityDigest || uint64_be(revision) || jobGeneration:token ||
  monitorGeneration:token || mountGeneration:token ||
  cgroupGeneration:token || limitSetID:token || createJobSHA256)

launchShimSHA256 = SHA256(
  opaque16("hal/l8/controller-supervisor/launch-shim/v1") ||
  jobIdentityDigest || uint64_be(revision) || jobGeneration:token ||
  monitorGeneration:token || mountGeneration:token ||
  cgroupGeneration:token || launchID:token || limitSetID:token ||
  executableSHA256 || launchBlockSHA256)
```

The canonical fixed body and digest vector table uses these complete inputs:

```text
bootGeneration       = "boot-1"
helperGeneration     = "helper-1"
supervisorGeneration = "supervisor-1"
limitSetID            = "helper-limits-v1"
revision              = 1
jobGeneration         = "job-1"
monitorGeneration     = "monitor-1"
mountGeneration       = "mount-1"
cgroupGeneration      = "cgroup-1"
jobIdentityDigest     = a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
                        b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
launch request ID     = 000102030405060708090a0b0c0d0e0f
launchID              = "AAECAwQFBgcICQoLDA0ODw"
executableSHA256      = 202122232425262728292a2b2c2d2e2f
                        303132333435363738393a3b3c3d3e3f
launchBlockSHA256     = 404142434445464748494a4b4c4d4e4f
                        505152535455565758595a5b5c5d5e5f
```

The required digest outputs are:

```text
supervisorReadySHA256 = f184ff36331fa69007751e7a567f03dd
                        9c9b369125a984f99ac7f5b02cfb70b3
monitorConfigSHA256   = 8f77e47200fe4b9fc5f8cb48f2840a50
                        487f80b3b1fc6b373d29199778c8e3d4
cgroupConfigSHA256    = 4c0b5daf0102f695bfa60c63c5a99361
                        2d61f99161a735217eb9d12f76e6b05b
createJobSHA256       = f4ff4d17dfe08c11946ddb35dbb7c7c5
                        3f72c31ea14f0655c5e30c66819b0d38
monitorReadySHA256    = fef4fb8972101ac91c792380e1f06cc3
                        713c69ba68ca89cbcaf63aee73458cae
launchShimSHA256      = 8b2dedea6f00f15c8d1e404ee84efee4
                        6c905e1e8f4aa27e7a03d06b1e1ae404
```

For the event vector, `shim_exited`, request type `0x04`, no failure, exited
with code zero, zero-population false, monitor ready, and cleanup
not-applicable are selected. The attestation vector reuses the existing exact
42-byte empty-extension helper descriptor. The canonical body hex and byte
lengths for every type are:

```text
0x01 len=82
0006626f6f742d31000868656c7065722d31000c73757065727669736f722d31
001068656c7065722d6c696d6974732d7631
f184ff36331fa69007751e7a567f03dd9c9b369125a984f99ac7f5b02cfb70b3

0x02 len=127
000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e
742d3100086367726f75702d31001068656c7065722d6c696d6974732d7631
8f77e47200fe4b9fc5f8cb48f2840a50487f80b3b1fc6b373d29199778c8e3d4
4c0b5daf0102f695bfa60c63c5a993612d61f99161a735217eb9d12f76e6b05b

0x03 len=127
000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e
742d3100086367726f75702d31001068656c7065722d6c696d6974732d7631
f4ff4d17dfe08c11946ddb35dbb7c7c53f72c31ea14f0655c5e30c66819b0d38
fef4fb8972101ac91c792380e1f06cc3713c69ba68ca89cbcaf63aee73458cae

0x04 len=151
000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e
742d3100086367726f75702d31001641414543417751464267634943516f4c4441
304f4477001068656c7065722d6c696d6974732d7631
202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f

0x05 len=101
000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e
742d3100086367726f75702d31001641414543417751464267634943516f4c4441
304f44778b2dedea6f00f15c8d1e404ee84efee46c905e1e8f4aa27e7a03d06b
1e1ae404

0x06 len=46
000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e
742d3100086367726f75702d3101

0x07 len=46
000000000000000100056a6f622d3100096d6f6e69746f722d3100076d6f756e
742d3100086367726f75702d3101

0x08 len=81
01040000000000000000000100056a6f622d3100096d6f6e69746f722d310007
6d6f756e742d3100086367726f75702d3100164141454341775146426763494351
6f4c4441304f44770100000000000201

0x09 len=44
002a484c3844010100000000702f1015d6dded7d0991d3275cb3f36d4ddab234
d208a9b851369dc6d5fb7df6

0x0a len=32
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

0x7f len=1
01
```

The vector's exact complete datagrams covering every new digest domain are:

```text
supervisor_ready (150 bytes; PID1 send sequence 0):
484c384c01010000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
000000520006626f6f742d31000868656c7065722d31000c73757065727669736f
722d31001068656c7065722d6c696d6974732d7631f184ff36331fa69007751e7a
567f03dd9c9b369125a984f99ac7f5b02cfb70b3

create_job (195 bytes; controller send sequence 1; request ID 10..1f):
484c384c010200000000000000000001101112131415161718191a1b1c1d1e1f
a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
0000007f000000000000000100056a6f622d3100096d6f6e69746f722d310007
6d6f756e742d3100086367726f75702d31001068656c7065722d6c696d697473
2d76318f77e47200fe4b9fc5f8cb48f2840a50487f80b3b1fc6b373d29199778
c8e3d44c0b5daf0102
f695bfa60c63c5a993612d61f99161a735217eb9d12f76e6b05b

job_created (195 bytes; PID1 send sequence 2; same request and identity):
484c384c010300000000000000000002101112131415161718191a1b1c1d1e1f
a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
0000007f000000000000000100056a6f622d3100096d6f6e69746f722d310007
6d6f756e742d3100086367726f75702d31001068656c7065722d6c696d697473
2d7631f4ff4d17dfe08c11946ddb35dbb7c7c53f72c31ea14f0655c5e30c668
19b0d38fef4fb8972101ac91c792380e1f06cc3713c69ba68ca89cbcaf63aee7
3458cae

launch_shim (219 bytes; controller send sequence 2; request ID 00..0f):
484c384c010400000000000000000002000102030405060708090a0b0c0d0e0f
a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
00000097000000000000000100056a6f622d3100096d6f6e69746f722d310007
6d6f756e742d3100086367726f75702d3100164141454341775146426763494351
6f4c4441304f4477001068656c7065722d6c696d6974732d763120212223242526
2728292a2b2c2d
2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d
4e4f505152535455565758595a5b5c5d5e5f

shim_started (169 bytes; PID1 send sequence 3):
484c384c010500000000000000000003000102030405060708090a0b0c0d0e0f
a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
00000065000000000000000100056a6f622d3100096d6f6e69746f722d310007
6d6f756e742d3100086367726f75702d3100164141454341775146426763494351
6f4c4441304f44778b2dedea6f00f15c8d1e404ee84efee46c905e1e8f4aa27e
7a03d06b1e1ae404
```

Concatenating display lines yields the exact bytes; there are no whitespace
bytes. `job_created` carries the two out-of-band rights and `launch_shim` the
eight out-of-band rights, so the datagram bytes remain independent of unstable
descriptor integers. Tests must reproduce these hashes from the domains and
inputs rather than treating the literals as the hash implementation.

The monitor and cgroup configuration digests therefore bind only canonical
safe identity/configuration, not kernel object numbers. The monitor-ready
digest binds the exact cross-protocol create/readiness correlation;
authenticated rights and D4 post-receive reinspection independently prove the
live endpoint and namespace objects. Executable and launch-block SHA-256 are
over the exact pinned executable bytes and exact bounded sealed launch-block
bytes. These live-only digests are never durable credential proof and never
substitute for descriptor or object inspection.

The deterministic state model has these rules:

1. PID1 sends `supervisor_ready` at PID1-to-controller sequence 0. The
   controller compares the sealed boot/helper/supervisor generations, exact
   limit ID, and recomputed digest before sending anything.
2. The controller sends `controller_attestation` at controller-to-PID1
   sequence 0. PID1 validates the canonical helper-role descriptor and sealed
   descriptor digest. A second ready or attestation is terminal.
3. After the independently authenticated agent/helper bootstrap and matching
   descriptors, PID1 sends `composition_accepted` at its sequence 1. The
   controller requires the independently computed composition digest. This
   enters `composed_idle`; job traffic before it is terminal.
4. Exactly one `create_job` may leave `composed_idle`. Success commits the
   identity, revision, complete job/monitor/mount/cgroup generation tuple,
   limit set, cgroup, monitor, validated `monitorReadySHA256`, two-right
   transfer, and `job_created` together. A proven pre-publication rollback may
   emit `operation_failed`; uncertainty emits stop-VM and becomes terminal.
   A committed create failure is the final HL8L packet for that non-reusable
   guest session. After the exact correlated result commits, the pure state
   returns `stop_vm_required` after that result commits, accepts no normal
   close or second create, and D6 stops/reaps the microVM. This teardown is
   required even for a canonical pre-mutation resource denial or completely
   proved rollback because the authenticated generation and one-job lease
   cannot be reused; it does not turn the safe failure result into a cleanup
   or live-absence proof.
5. The controller has one outstanding request. PID1 sends its one correlated
   terminal result before an asynchronous event. A second request, duplicate
   active request, response with the wrong type/ID/identity/revision, or
   unexpected result is terminal. Response/event correlation may echo an old
   request ID, but only controller requests are subject to the never-reuse
   rule. PID1 holds a non-evicting used-request/launch-ID ledger with at most
   4096 launch tombstones and one completed-launch entry
   `{requestID, launchID, revision, launchShimSHA256, exitPending}`.
   `shim_started` records the tombstone and completed-launch correlation before
   the result becomes sendable. The exact `shim_exited` send consumes the
   completed-launch entry while the tombstone remains, so exactly one event
   exists and neither identifier can ever be reused.
6. There is exactly one active credential-aware execution. `launch_shim` is
   valid only when no launch is active and fewer than 4096 launch IDs have
   been charged. Capacity is charged before D4 launch. Success commits
   `shim_started`; a failed adapter path emits the exact failure result only
   after its cleanup category is known. If a gated workload exit is observed
   before `shim_started` is sent, PID1 first commits/sends `shim_started`, then
   emits the queued `shim_exited`; an exit before gate release is instead a
   launch failure and never produces `shim_started`. A successful launch
   remains active until one exact `shim_exited` event. Launch-ID tombstones are
   never reused or evicted during the link lifetime; the sole live
   completed-launch entry is consumed only by that event.
7. The first accepted `terminate_job` permanently denies new launches. Success
   requires cgroup `populated 0` and emits `job_terminated`. Retry-required
   permits only a fresh-ID `terminate_job` with the same generations and a
   nondecreasing revision, within the shared three-attempt/deadline limit.
   Stop-VM is terminal. Terminate and destroy charge one shared cleanup-attempt counter
   before work, not separate per-operation counters. At most three
   total terminate/destroy request IDs exist inside the one 30-second deadline.
8. `destroy_job` is valid only after termination proved zero population and the
   controller has first denied new exec/accept, driven direct HL8M
   revoke/cleanup to `cleanup_complete`, closed every listener and accepted
   connection, received the monitor cleanup result, committed bilateral normal
   HL8M close, closed its direct monitor endpoint and namespace duplicate, and
   observed monitor exit. PID1 never
   contacts the monitor: its bootstrap endpoint was permanently closed after
   readiness and PID1 owns neither direct capability. PID1 performs only any
   still-needed cgroup kill/zero confirmation, monitor-pidfd exit/reap,
   PID1-owned directory and cgroup removal, and absence reinspection. Success
   emits `job_destroyed` and enters `destroyed`; a request before the exact
   monitor-exit/cleanup precondition gets one canonical correlated operation
   failure with retry/stop cleanup disposition. A later fresh-ID destroy retry
   remains inside the same three-attempt/deadline bound. Stop-VM is terminal.
   The complete non-evicting request-ID ledger bound is therefore exactly
   create + launches + shared cleanup attempts: `1 + 4096 + 3 = 4100`.
9. PID1 has exactly one pending asynchronous-event slot. Only `shim_exited`
   may occupy it. If an exit races any outstanding request, the immutable exit
   tuple is placed in that slot; PID1 completes and sends the outstanding
   request's result, then sends the queued exit before accepting another
   controller request. Exit data is never folded into another result. The
   controller may not send while the slot is pending. A second event while
   occupied, a missing ledger entry, or inability to send the event is
   supervisor loss and stop-VM. With one active execution, no conforming path
   needs a second slot.
10. In `destroyed`, either peer may send one normal `close_notify`; the receiver
   sends its own normal close at its next sequence if it has not already, and
   both close only after both normal packets commit. This is graceful local
   HL8L closure, not a guest or host cleanup proof. A new create is not session
   reuse: the runtime/job lease requires a new authenticated guest session
   generation. Any job or boot-class post-accept packet is terminal.

Directions have independent counters starting at zero. A packet sequence must
equal the exact next value. Counters advance only after credentials, framing,
body, rights, canonical encoding, correlation, and either a state transition
or committed accepted semantic rejection all validate. Lower is replay and
higher is loss/gap. Legal sequences are zero through `2^32-1`; accepting the
last legal value exhausts that direction, and attempting a later packet or
counter wrap is terminal. The D4 sender serializes each direction and never
advances after a partial/failed send.

Unknown type, wrong direction or credentials, bad body length, truncation,
trailing data, noncanonical token, zero required digest, wrong or reordered
rights, request/job zero-semantics error, stale identity/revision/generation,
sequence replay/gap/exhaustion, duplicate request ID, illegal transition, result/event
correlation mismatch, or any packet after terminal failure permanently latches
the pure state to `stop_vm_required`. EOF before the two committed normal close
packets, controller/PID1 loss, an abnormal `close_notify`, and policy-kill also
latch role loss. The exact paired normal close after `destroyed` enters
`closed_clean` rather than stop-VM, but it does not by itself prove guest or
host cleanup; D6 still owns exact Firecracker reap and host absence inspection.
A post-accept packet means a repeated boot-class 0x01/0x09/0x0a after
composition acceptance; ordinary valid job traffic is not “post-accept.”

Canonical no-rights composition vector (spaces and newlines are display only):

```text
sequence = 1
requestID = 00000000000000000000000000000000
jobIdentityDigest =
  0000000000000000000000000000000000000000000000000000000000000000
compositionSHA256 =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
complete datagram =
  484c384c010a00000000000000000001
  00000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  00000020
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

The complete vector is exactly 100 bytes. Tests independently assemble it,
then mutate every header byte class, sequence, identity, body length, digest,
direction, credential count/value, rights count/order/kind, truncation flag,
and trailing byte. Separate canonical vectors lock every body and every digest
domain above; maximum token/body/datagram and plus-one cases are mandatory.

Formerly ambiguous choices are closed as follows: `job_created` carries two
rights because the controller's frozen FD table needs both the single monitor
endpoint and monitor-created namespace authority; launch identity is the
canonical request-ID encoding rather than a second independent capability;
terminate/destroy success uses the existing event type because no new type ID
is available; response loss never triggers rights replay; and the process
composition digest remains the existing `HL8D` digest rather than an HL8L
variant. These choices preserve all already frozen type IDs, the eight-right
launch order, the controller/PID1 capability split, and the D4 cgroup/mount
cleanup order.

D2 owns the pure codec, canonical body and digest functions, fixed-size
rights-role metadata, descriptor delegation, deterministic transition state,
opaque formatting, fail-closed JSON/text/binary marshal and unmarshal methods,
defensive ownership copies, and fake-only negative tests. D4 owns every live
syscall, socketpair, credentials/rights receive, descriptor close/dup/remap,
pidfd, cgroup, namespace, monitor, pipe, `ForkExec`, gate, reap, and cleanup
operation behind D2 decisions. D2 opens no socket or process, receives no FD,
mounts nothing, serializes nothing durably, and does not claim live cleanup.
D2's exported packet, body, enum, metadata, and state values format only as
their static type name from both `String` and `GoString`; they expose no field
value, byte, digest, ID, generation, reason, or credential. Their
`MarshalJSON`, `MarshalText`, and `MarshalBinary` methods return no bytes and
the one stable opaque-serialization error. Their matching unmarshal methods
return that error without mutating even a seeded receiver. No D2 struct has a
JSON tag. The explicit canonical encode/decode APIs are the sole wire boundary,
defensively copy every accepted input and returned byte slice, and return only
closed stable error codes that contain no input-derived text.
D4 may not reinterpret a body, add a type/right, weaken a terminal disposition,
or bypass D2 correlation. D6 alone turns `stop_vm_required` into exact
Firecracker stop/reap and host-owned absence evidence.

The direct agent-supervisor codec uses the same 68-byte header and 8-KiB body
bound with `magic[4] = "HL8A"`, version 1, zero flags/request/job identity, and
independent per-direction sequences starting at zero. Its closed no-rights types
are `0x01 agent_config` PID1 to agent, `0x02 client_attestation` agent to PID1,
`0x03 composition_accepted` PID1 to agent, and `0x7f close_notify` either way.
`agent_config` is the exact safe boot tuple above; client attestation is
`descriptorLength:u16 | descriptor`; accepted is
`compositionSHA256:[32]byte`. Every packet requires the expected PID1 or
already-pinned agent kernel credentials. Unknown type, rights, nonzero identity,
sequence error, wrong descriptor/digest, truncation, loss, or packet after
accepted is a pre-admission VM-stop failure. The agent closes FD 4 after
accepted; HL8A never carries a credential value or becomes a job protocol.

### Normative HL8M controller-monitor ABI

The direct controller-monitor codec is one atomic Unix
`SOCK_SEQPACKET|SOCK_CLOEXEC` datagram per packet. It is neither a byte stream
nor a public or durable protocol. The constants are exact:

```text
HL8MHeaderBytes = 68
HL8MMaxBodyBytes = 73728
HL8MMaxDatagramBytes = 73796
HL8MMaxPacketsPerDirection = 4294967296
```

The retained 68-byte header is:

```text
offset  size  field
0       4     magic[4] = ASCII "HL8M"
4       1     version:u8 = 1
5       1     type:u8
6       2     flags:u16_be = 0
8       8     sequence:u64_be
16      16    requestID:[16]byte
32      32    jobIdentityDigest:[32]byte
64      4     bodyLength:u32_be
68      n     body
```

`bodyLength` is body bytes only, equals the datagram remainder exactly, and is
at most 73728. A shorter datagram is truncation and a longer one has trailing
data; neither is a second packet. Every multibyte integer is big-endian. A body
`token` is the existing helper encoding `uint16_be(length) || ASCII bytes`,
length 1 through 128, matching
`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` without trimming, normalization, Unicode,
case folding, or defaulting. A safe ID additionally passes the narrower
`credentialprotocol` safe-ID validator. An `optional-token` is
`uint16_be(0)` for absent or the same canonical nonempty token form. A relative
path uses the already locked helper optional-relative-path codec and its exact
4096-byte/component rules. Booleans are one byte and exactly zero or one.
SHA-256 values are 32 raw bytes and are nonzero unless an exact result matrix
below requires zero. No body is JSON, text, a generic map, a generic body, or
an extensible tagged union.

Every receive supplies independent kernel metadata to the pure decoder. These
are closed non-JSON value types:

```text
HL8MRightKind:u8:
  1 controller_endpoint, 2 mount_namespace, 3 ssh_listener
HL8MRightAccess:u8:
  1 duplex_seqpacket, 2 namespace_enter, 3 listen_stream

HL8MRightMetadata:
  Index:uint32 | Kind:HL8MRightKind | Access:HL8MRightAccess |
  Generation:token | CorrelationSHA256:[32]byte

HL8MReceiveMetadata:
  Direction:closed enum | CredentialCount:uint32 = 1 |
  Credential:{PID:uint32, UID:uint32, GID:uint32} |
  RightsCount:uint32 | Rights:[2]HL8MRightMetadata |
  MSG_TRUNC:bool | MSG_CTRUNC:bool
```

The receive wrapper rejects `RightsCount > 2` before indexing the fixed array;
unused entries are the zero value and are never decoded. Ready metadata is
exactly index 0 `controller_endpoint/duplex_seqpacket`, monitor generation and
`monitorReadySHA256`, followed by index 1
`mount_namespace/namespace_enter`, mount generation and the same
`monitorReadySHA256`. An accepted SSH response has exactly index 0
`ssh_listener/listen_stream`, endpoint generation and `endpointSHA256`.
Metadata is safe expected-role correlation only. D4/D5 live inspection of the
received object remains authority and must agree before the transition commits.

The monitor credentials are its exact positive PID pinned from the successful
PID1 launch and UID 0, GID 0. PID1 credentials are exactly PID 1, UID 0, GID 0;
controller credentials are the exact positive PID pinned at controller launch
and UID 0, GID 0. Monitor and controller PIDs are each 2..2147483647, distinct
from PID1, each other, and the pinned agent PID. PID values remain `uint32`
through collection and comparison with no signed or narrower conversion. A
body can never select an identity. Missing or duplicate
`SCM_CREDENTIALS`, changed credentials, `MSG_TRUNC`, `MSG_CTRUNC`, or a wrong,
missing, extra, or reordered right is terminal. Bodies and digests contain no
numeric FD/PID/UID/GID, inode/device, mount/cgroup path, socket address,
credential name/value, executable path, argv, or environment value.

The type/direction/identity/rights matrix is closed:

| Type | Name and direction | request ID | job digest | rights |
| --- | --- | --- | --- | ---: |
| `0x01` | `monitor_ready`, monitor -> PID1 | zero | exact nonzero job | 2 |
| `0x10` | `prepare_begin`, controller -> monitor | new nonzero | exact active job | 0 |
| `0x11` | `prepare_file`, controller -> monitor | exact active `0x10` | exact active job | 0 |
| `0x12` | `prepare_commit`, controller -> monitor | exact active `0x10` | exact active job | 0 |
| `0x13` | `create_ssh_endpoint`, controller -> monitor | new nonzero | exact active job | 0 |
| `0x14` | `revoke`, controller -> monitor | new nonzero | exact active job | 0 |
| `0x20` | `response`, monitor -> controller | exact echoed request | exact echoed job | 0 or exact typed result count |
| `0x21` | `monitor_event`, monitor -> controller | new nonzero event ID | exact active job | 0 |
| `0x7f` | `close_notify`, either direction | zero | exact active job | 0 |

No type is valid in the opposite direction. `response` has one right only for
an accepted `create_ssh_endpoint`; every other response has zero. A nonzero
request ID is unique for the link lifetime, except that every packet in one
prepare transaction intentionally repeats its `prepare_begin` ID. The exact
22-character unpadded-base64url encoding of an event header request ID equals
its body `eventID`. Responses echo header bytes, not a re-encoding. Loss of an
atomic response is monitor loss: response loss is monitor loss and requires
whole-VM stop/reap, never a request replay or live-right retransmission.

#### PID1 bootstrap relay and live-right ownership

PID1 creates the direct controller-monitor pair and a separate one-use
PID1-monitor bootstrap pair before launch. The monitor inherits its direct side
at FD 3, the controller peer side at transient FD 9 solely for transfer, and
the bootstrap side at FD 10 solely for the one ready send; PID1 owns the
bootstrap peer in a recorded transient slot, not its fixed FD 10 monitor pidfd
slot. After stacking `steady-monitor`, the monitor creates and reinspects its
namespace handle at FD 7. Its sequence-zero `monitor_ready` sends exactly two
rights over FD 10 to PID1, in this order:

1. the controller peer endpoint, reinspected as the other side of the exact
   `AF_UNIX/SOCK_SEQPACKET|SOCK_CLOEXEC` pair with `SO_PASSCRED`; and
2. exactly one inspected mount-namespace capability, proved independently as
   `NSFS_MAGIC`, `NS_GET_NSTYPE == CLONE_NEWNS`, the expected mount
   generation, and unequal to PID1's namespace.

The namespace is live authority, never proof. `monitorReadySHA256` is safe
correlation metadata and never substitutes for either right or its
reinspection. On a successful atomic send the monitor closes FDs 9 and 10
permanently, never reuses either number, and retains direct endpoint FD 3 plus
namespace FD 7. Any send failure closes both handoff FDs and is terminal. PID1
owns both
received rights, authenticates and reinspects them, and relays those same two
authorities in the matching HL8L `job_created`, ordered monitor endpoint then
namespace capability. PID1 closes its duplicates only after that atomic send
succeeds. The controller's receive wrapper owns and closes both until the
complete HL8L packet, credentials, body, digests, rights, and transition commit;
job state then owns both for the job lifetime. PID1 closes its bootstrap peer
after successful relay or on every failure and has no remaining HL8M channel.
The logical monitor send sequence
is deliberately shared across the one-use bootstrap and direct channels under
the same sealed monitor identity/config: PID1 consumes sequence zero on the
bootstrap pair, so the controller starts its direct monitor receive counter at
one. The controller's independent send sequence starts at zero.

This is the only PID1 bootstrap relay. PID1 never originates an HL8M packet,
forwards an HL8M body, or receives credential bytes. After `job_created`, all
prepare, SSH-endpoint, revoke, response, event, and close packets travel only
between controller-owned locked buffers and the authenticated direct monitor
endpoint. The controller retains the namespace right for later HL8L launch
duplication. For normal cleanup the controller first closes the published D5
listener and accepted connections, then alone sends HL8M `revoke` over FD 3.
After receiving cleanup-complete it completes the bilateral normal-close
handshake, observes the expected monitor endpoint closure, closes its endpoint
and namespace duplicate. PID1 never requests monitor cleanup; only then does
the controller send HL8L `destroy_job`, which authorizes PID1
to reap the already-exited monitor and remove/reinspect the PID1-owned cgroup
and directories.

#### Exact bodies and canonical codec reuse

The bodies are exact, in the displayed byte order:

```text
0x01 monitor_ready:
  revision:u64 | jobGeneration:token | monitorGeneration:token |
  mountGeneration:token | cgroupGeneration:token | limitSetID:token |
  createJobSHA256:[32]byte | monitorReadySHA256:[32]byte

0x10 prepare_begin:
  revision:u64 | expiryUnixNano:i64 | bindingCount:u16 |
  ordered helper binding manifest

0x11 prepare_file:
  revision:u64 | bindingIndex:u16 | fileLength:u32 |
  fileSHA256:[32]byte | mutable private bytes

0x12 prepare_commit:
  revision:u64 | manifestSHA256:[32]byte

0x13 create_ssh_endpoint:
  revision:u64 | bindingIndex:u16 | bindingID:token |
  endpointGeneration:token | manifestSHA256:[32]byte |
  endpointConfigSHA256:[32]byte

0x14 revoke:
  revision:u64 | reason:u8

0x20 response:
  requestType:u8 | disposition:u8 | revision:u64 | failureCode:u8 |
  exact typed result union

0x21 monitor_event:
  eventCode:u8 | failureCode:u8 | cleanupCategory:u8 | reserved:u8=0 |
  revision:u64 | eventID:token | mountGeneration:token |
  postinspectionSHA256:[32]byte

0x7f close_notify:
  closeReason:u8
```

The structural body bounds are exact. `prepare_begin` has a fixed 18-byte
prefix and 1..16 records; its minimal record is
`token(3) + mode(1) + absent-path(2) + declared-length(4) + digest(32) = 42`
bytes. Therefore:

```text
prepare_begin: 18 + 1..16 encoded manifest records = 60..68258
```

The delegated helper codec rejects zero bindings before HL8M state and enforces
the same 16-record maximum. `prepare_file` is `46 + fileLength` (47..65582
bytes), and file length is 1..65536.
`monitor_ready` is 87..722 bytes, `prepare_commit` is 40,
`revoke` is 9, and `close_notify` is 1. The remaining arithmetic is frozen, not
inferred from the aggregate ceiling:

```text
create_ssh_endpoint: 8 + 2 + (2 + 1..128) + (2 + 1..128) + 32 + 32 = 80..334
monitor_event: 4 + 8 + (2 + 22) + (2 + 1..128) + 32 = 71..198
failed response: 11
prepare response: 11 + (2 + 1..128) + 32 + 32 + 2 + 8 + 32 = 120..247
SSH response: 11 + 2 + (2 + 1..128) + (2 + 1..128) + 32 = 51..305
revoke response: 11 + 32 + 1 + 1 + 1 = 46
```

These per-type bounds are checked before allocation and do not relax the
73728-byte aggregate body ceiling.

`monitor_ready` revision is exactly one. Every generation and limit-set value
is a safe ID and equals sealed monitor configuration. The sole limit-set ID is
`helper-limits-v1`. For HL8M it denotes one active job, one monitor and mount
namespace, one prepare transaction, one fixed private receive slot, at most 16
bindings, at most one HTTP and one SSH binding, 64 KiB per file, 1 MiB file
aggregate, one optional listener, 256 role descriptors, one credential-aware
exec at a time, 4096 lifetime credential-aware launch attempts, three cleanup
attempts, a 30-second cleanup deadline, and the 35-minute hard lifetime. The
generic L4 process ceiling of 64 is distinct and never raises credential-aware
execution concurrency above exactly 1.

The codec does not read a clock or choose a horizon. Monitor construction state
receives `AuthenticatedSessionHardExpiryUnixNano:int64`, derived from the
successfully authenticated session's fixed 35-minute hard horizon and no later
than root `MaxJobCredentialLifetime`, and each prepare transition receives
`TrustedObservationUnixNano:int64` from D4's trusted clock. Both are positive
signed Unix nanoseconds and are not body fields. `prepare_begin.expiryUnixNano`
must be greater than the trusted observation and less than or equal to the
authenticated session hard horizon; the exact value is then correlated
unchanged through the helper prepare transaction and publication. A body,
controller argument, retry, or later observation cannot authorize an extension
of the construction-time horizon. An otherwise canonical out-of-window expiry
is pre-mutation `operation_denied`, consumes the prepare attempt, clears the
outstanding request, and returns to `ready_transferred` for revoke. Missing,
nonpositive, untrusted, or internally inconsistent construction/clock input is
not a peer rejection: it is terminal `stop_vm_required` with no mutation.

The `0x10`, `0x11`, and `0x12` encodings are byte-for-byte the already locked
`HelperPrepareBeginBody`, `HelperPrepareFileBody`, and
`HelperPrepareCommitBody` encodings. HL8M implementations delegate to those
canonical safe codecs; they do not copy, reinterpret, or reorder them. The
ordered manifest record therefore remains exactly:

```text
bindingID:token | mode:u8 | targetPath:optional-relative-path |
declaredFileBytes:u32 | fileSHA256:[32]byte
```

Modes remain 1 HTTP, 2 file-tmpfs, and 3 SSH-agent. Only file mode has a path,
nonzero size, and nonzero digest. HL8M's monitor-state validator additionally
requires at most one SSH binding because this ABI publishes one
`SSH_AUTH_SOCK`; that restriction does not change the shared helper codec.
File packets occur only for file-mode records, in ascending manifest index.
The monitor decodes mutable file bytes directly into one fixed 64-KiB locked
receive slot. It authenticates header and metadata before the slot is exposed,
writes from that borrowed slot to the one inspected staging file, and
overwrites the slot through full capacity before accepting another packet.
The decoder never returns an owned body `[]byte` or `string`. The controller
likewise sends from one controller-owned locked slot and overwrites it after
the atomic send. No second file slot, retained packet copy, generic formatter,
JSON path, or PID1 path exists.

The production D2/D4 seam for that requirement is exact. D2 exports a fixed
`ControllerMonitorPrepareFileSlot` array sized to the maximum complete `0x11`
datagram and an opaque one-owner-pointer
`ControllerMonitorPrepareFileObservation`. D4 receives directly into the
mlocked slot, then calls
`InspectControllerMonitorPrepareFileSlot(*ControllerMonitorPrepareFileSlot,
receivedBytes uint32)`. The inspector validates the fixed 68-byte header and
46-byte safe prefix in place, exact type/request/job/sequence/body/received
length bounds, revision/index/file length, nonzero declared digest, and
SHA-256 of the payload bytes in that same slot. It returns only the opaque safe
header/revision/index/length/digest observation and does not expose or retain the slot pointer.
The observation is canonical byte correlation only; it never treats locking or object existence as proved.

`ControllerMonitorState.AcceptPrepareFile(metadata,
ControllerMonitorPrepareFileObservation)` authenticates credentials,
direction, zero rights, no truncation, active request, identity, exact sequence,
manifest order, and the observation's one-use owner before committing the safe
metadata to the canonical prepare transaction and advancing the controller
counter. The ordinary `Accept` path rejects `0x11` before generic body decoding;
the generic packet encoder and decoder both reject `0x11`, the packet union
contains no private file-body owner, and there is no public `PrepareFile` packet accessor.
Tests construct only the safe fixed prefix and caller-owned
fixed slot; a diagnostic exception is forbidden.
Production D4 sends through `ControllerMonitorPrepareFilePrefixBytes`, exactly
`ControllerMonitorHeaderBytes + 46`, and
`EncodeControllerMonitorPrepareFilePrefix(header ControllerMonitorHeader,
revision uint64, bindingIndex uint16, fileLength uint32,
fileSHA256 [32]byte)`. That function returns the fixed 68-byte header and 46-byte safe prefix
only after validating type `0x11`, sequence/request/job,
`header.BodyLength == 46 + fileLength`, revision one, index below 16, length
1..64 KiB, and nonzero digest. D4 copies that value into its existing locked
transmit slot followed by the separately filled and hashed payload; it does not
call a full-wire encoder that copies payload bytes.
Every success and failure leaves D4 responsible for full-capacity wipe/unlock/
unmap of its slot. D2 holds neither an owned secret body nor a second payload
copy.

The `0x14` body is byte-for-byte `HelperRevokeBody`; its reason catalog is the
existing exact catalog:

```text
revoke reason: 1 requested, 2 expired, 3 session_loss, 4 source_revoked,
               5 worker_cancel, 6 daemon_shutdown
```

The response common prefix deliberately reuses the existing disposition
numbers, while its request and result arms are HL8M-specific:

```text
response disposition: 1 accepted, 2 rejected, 3 cleanup_complete,
                      4 cleanup_retry, 5 stop_vm_required

monitor failure code: 0 none, 1 resource_limit, 2 prepare_failed,
                      3 ssh_endpoint_failed, 4 revoke_failed,
                      5 inspection_failed, 6 cleanup_incomplete,
                      7 operation_denied
```

After the 11-byte response prefix, successful results are:

```text
prepare accepted (`requestType=0x12`, zero rights):
  mountGeneration:token | manifestSHA256:[32]byte |
  prepareTransactionSHA256:[32]byte | fileCount:u16 |
  aggregateFileBytes:u64 | preparePostinspectionSHA256:[32]byte

SSH endpoint accepted (`requestType=0x13`, exactly one right):
  bindingIndex:u16 | bindingID:token | endpointGeneration:token |
  endpointSHA256:[32]byte

revoke cleanup_complete (`requestType=0x14`, zero rights):
  cleanupSHA256:[32]byte | entriesAbsent:u8=1 | socketAbsent:u8=1 |
  mountAbsent:u8=1
```

An accepted prepare result exactly matches the active manifest, transaction,
counts, byte total, and generation. An accepted SSH result is valid only when
D5 was attested in the process descriptors, the unique manifest record is SSH
mode, and the sole received right is an inspected listening
`AF_UNIX/SOCK_STREAM|SOCK_CLOEXEC` capability at the sealed job-relative leaf,
with backlog 1 through 4, mode 0600, fixed UID/GID 1000, and matching endpoint
generation/digests. The controller receive wrapper owns and closes that right
on every failure; job state owns it only after full response commit. The
monitor closes its original after its authenticated atomic response send. The
controller owns and accepts on the published listener, validates each connected
peer separately, and closes listener/connections before monitor cleanup.

`accepted` is valid only for prepare and SSH creation, and requires failure
zero plus the exact result. `cleanup_complete` is valid only for revoke,
requires failure zero and the exact three true fields, and proves only
monitor-local entry/socket/mount absence. A monitor cannot prove or commit its
own exit while sending. The successful bilateral close handshake below occurs
only after that response; after monitor exit and the later HL8L `destroy_job`,
PID1 separately reaps the monitor and proves process, cgroup, and directory
absence.
`rejected` is valid only for a pre-mutation `resource_limit` or
`operation_denied` result, or a prepare/SSH operational failure after exact
rollback and postinspection prove no unowned partial state. `cleanup_retry` is
valid only for retryable revoke observation and retains monitor ownership.
`stop_vm_required` is required for nonretryable revoke/inspection/cleanup
failure and every prepare/SSH failure whose rollback/absence is not proved.
Both carry no result. Every failure result has exactly the 11-byte prefix, no
trailing arm, and zero rights. A disposition/type/failure mismatch,
noncanonical boolean, missing/extra result, or trailing byte is malformed.

The monitor event catalogs are closed:

```text
monitor event code: 1 expired, 2 mount_drift, 3 endpoint_drift,
                    4 cleanup_required
monitor cleanup category: 1 not_applicable, 2 cleanup_complete,
                          3 retry_required, 4 stop_vm_required
close reason: 1 normal, 2 protocol_error, 3 identity_drift,
              4 expired, 5 helper_loss, 6 shutdown
```

Close reason is exactly the existing `credentialprotocol.CloseReason` numeric
catalog. Event `expired` requires failure `operation_denied` and cleanup
category `retry_required`; `mount_drift` and `endpoint_drift` require
`inspection_failed` and `stop_vm_required`; `cleanup_required` requires
`cleanup_incomplete` and `retry_required` or `stop_vm_required`. Event revision
and generations equal active state, event ID equals the encoded header request
ID, and the postinspection digest equals the exact event-postinspection digest
below. Events carry no rights and never authorize use or prove whole-job
cleanup. The monitor has exactly one pending-event slot. If an observation is
already represented by the outstanding request's response, it is suppressed;
it is never duplicated as an event. One relevant orthogonal observation is
stored in the slot, the correlated response is sent first, and the event is
then sent exactly once if it is still relevant. A second pending observation
or either failed send is terminal `stop_vm_required`. No event can precede or
interleave with a prepare transaction's sole response.

#### Local observation transition matrix

An event reports a monitor-local observation; it never chooses its own source
or next state. The closed matrix is:

| Observation | Legal source state | Event tuple | State fixed before send |
| --- | --- | --- | --- |
| session/job expired | `ready_transferred`, `preparing`, `prepared`, or `prepared_with_endpoint` | `expired / operation_denied / retry_required` | `revoke_required`; permanently deny use and endpoint creation |
| mount identity/property drift | `preparing`, `prepared`, `prepared_with_endpoint`, or `revoking` while the mount exists | `mount_drift / inspection_failed / stop_vm_required` | `stop_pending_event`, then terminal regardless of send success |
| endpoint identity/property drift | `prepared_with_endpoint` or `revoking` while the endpoint exists | `endpoint_drift / inspection_failed / stop_vm_required` | `stop_pending_event`, then terminal regardless of send success |
| retryable cleanup required outside an outstanding revoke | `ready_transferred`, `prepared`, or `prepared_with_endpoint`, with no request outstanding | `cleanup_required / cleanup_incomplete / retry_required` | `revoke_required`; permanently deny use and endpoint creation |
| nonretryable cleanup required | `ready_transferred`, `preparing`, `prepared`, `prepared_with_endpoint`, or `revoking` | `cleanup_required / cleanup_incomplete / stop_vm_required` | `stop_pending_event`, then terminal regardless of send success |

With no outstanding response, the monitor sets the next state before sending
the event immediately. `revoke_required` accepts exactly one fresh-ID `revoke`;
it cannot accept prepare, endpoint creation, or any use-producing transition.
`stop_pending_event` accepts no packet; after its one safe event send attempt it
is terminal, and failed send still requires stop-VM.

With an outstanding prepare or SSH operation, the monitor first denies use,
rolls back as required, and fixes `revoke_required` or terminal state before
the response send. An expiry already represented by an `operation_denied`
response plus the `revoke_required` latch is suppressed. An independent expiry
uses the sole pending slot, follows the response exactly once, and leaves the
already-fixed `revoke_required` state. Drift or nonretryable cleanup forces the
outstanding response to `stop_vm_required`; that response represents the
observation, so its event is suppressed and the state is terminal. Retryable
`cleanup_required` is not legal during prepare/SSH. During an outstanding
revoke, retryable cleanup is represented only by `cleanup_retry`, while drift
or nonretryable cleanup is represented by `stop_vm_required`; neither produces
a duplicate event. An expiry observed after entry to `revoking` is subsumed by
the existing deny-use latch and emits no event. A second orthogonal observation
cannot be queued and is terminal. Thus no event opens a path forbidden by the
primary state table.

#### Digest domains and fixed vectors

Digest inputs use existing `opaque16`; every displayed token includes its
canonical `uint16_be` length. The definitions are exact:

```text
monitorReadySHA256 = SHA256(
  opaque16("hal/l8/controller-monitor/monitor-ready/v1") ||
  jobIdentityDigest || uint64_be(revision) || jobGeneration:token ||
  monitorGeneration:token || mountGeneration:token ||
  cgroupGeneration:token || limitSetID:token || createJobSHA256)

manifestSHA256 and prepareTransactionSHA256 are exactly the existing
  hal/l8/guest-helper/manifest/v1 and
  hal/l8/guest-helper/prepare-transaction/v1 digests.

preparePostinspectionSHA256 = SHA256(
  opaque16("hal/l8/controller-monitor/prepare-postinspection/v1") ||
  jobIdentityDigest || uint64_be(revision) || monitorGeneration:token ||
  mountGeneration:token || manifestSHA256 || prepareTransactionSHA256 ||
  uint16_be(fileCount) || uint64_be(aggregateFileBytes))

endpointConfigSHA256 = SHA256(
  opaque16("hal/l8/controller-monitor/ssh-endpoint-config/v1") ||
  jobIdentityDigest || uint64_be(revision) || uint16_be(bindingIndex) ||
  bindingID:token || endpointGeneration:token || mountGeneration:token ||
  manifestSHA256)

endpointSHA256 = SHA256(
  opaque16("hal/l8/controller-monitor/ssh-endpoint/v1") ||
  jobIdentityDigest || endpointConfigSHA256 || endpointGeneration:token ||
  monitorGeneration:token || mountGeneration:token)

event postinspectionSHA256 = SHA256(
  opaque16("hal/l8/controller-monitor/event-postinspection/v1") ||
  jobIdentityDigest || eventCode:u8 || failureCode:u8 ||
  cleanupCategory:u8 || uint64_be(revision) || eventID:token ||
  monitorGeneration:token || mountGeneration:token)

cleanupSHA256 = SHA256(
  opaque16("hal/l8/controller-monitor/cleanup/v1") ||
  jobIdentityDigest || uint64_be(revision) || reason:u8 ||
  monitorGeneration:token || mountGeneration:token ||
  endpointGeneration:optional-token || entriesAbsent:u8 ||
  socketAbsent:u8 || mountAbsent:u8)
```

The prepare transaction digest includes file bodies through the already frozen
helper file digests/order. Endpoint and cleanup digests bind safe correlation,
not a pathname, inode, socket, FD, or kernel proof. D4 independently reinspects
every live object before accepting the corresponding digest.

Canonical monitor-ready vector (spaces and newlines are display only):

```text
revision = 1
sequence = 0
requestID = 00000000000000000000000000000000
jobIdentityDigest =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
jobGeneration = "job-gen-1"
monitorGeneration = "monitor-gen-1"
mountGeneration = "mount-gen-1"
cgroupGeneration = "cgroup-gen-1"
limitSetID = "helper-limits-v1"
createJobSHA256 =
  202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
monitorReadySHA256 =
  d1eb1ee5d971de0f1c771fd564443c651c176e977ba8da11248b7c7b47f9080b
complete datagram =
  484c384d01010000000000000000000000000000000000000000000000000000
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  0000008f000000000000000100096a6f622d67656e2d31000d6d6f6e69746f72
  2d67656e2d31000b6d6f756e742d67656e2d31000c6367726f75702d67656e2d
  31001068656c7065722d6c696d6974732d7631202122232425262728292a2b2c
  2d2e2f303132333435363738393a3b3c3d3e3fd1eb1ee5d971de0f1c771fd564
  443c651c176e977ba8da11248b7c7b47f9080b
ancillary credentials = {monitor PID, UID 0, GID 0}
ancillary rights roles = [controller_endpoint, mount_namespace]
ancillary right metadata[0] =
  {Index:0, Kind:controller_endpoint, Access:duplex_seqpacket,
   Generation:"monitor-gen-1",
   CorrelationSHA256:d1eb1ee5d971de0f1c771fd564443c651c176e977ba8da11248b7c7b47f9080b}
ancillary right metadata[1] =
  {Index:1, Kind:mount_namespace, Access:namespace_enter,
   Generation:"mount-gen-1",
   CorrelationSHA256:d1eb1ee5d971de0f1c771fd564443c651c176e977ba8da11248b7c7b47f9080b}
complete datagram bytes = 211
```

The complete vector has exactly two rights and one credentials record; rights
are not wire bytes and numeric descriptor values never enter the digest. D2
tests independently reconstruct it and mutate every header/body field, digest
input, sequence, credential, right count/order/kind, truncation flag, and
trailing byte. Separate vectors lock every body/result/event arm and every
digest domain; exact maximum token/file/body/datagram and plus-one cases are
mandatory.

The digest-domain fixtures additionally freeze these independent expected
values. Unless a line overrides a value, they use the ready vector's job
digest, revision, monitor generation, and mount generation:

```text
manifestSHA256 = bytes 40..5f
prepareTransactionSHA256 = bytes 60..7f
fileCount = 1
aggregateFileBytes = 3
preparePostinspectionSHA256 =
  38f6cff0a56628b30fd7f4127242a45acabd288deac94cb170c99205cbff8918

bindingIndex = 2
bindingID = "ssh-binding-1"
endpointGeneration = "endpoint-gen-1"
endpointConfigSHA256 =
  8791ee5446150ccea1c9f78dd4005a1d0be14053f7bea7d455f9b6f872cc6748
endpointSHA256 =
  50a4ae4feeac5718dcfef009f6e994ee38da6c66201f82b14dbacb2e7b71d94d

eventCode = 1 expired
failureCode = 7 operation_denied
cleanupCategory = 3 retry_required
eventID = "AAECAwQFBgcICQoLDA0ODw"
event postinspectionSHA256 =
  f139a2d62a6e9ebdd8d6857e2888b04eed654a151d6a29a6df563ff6e41198e8

revoke reason = 1 requested
entriesAbsent = 1
socketAbsent = 1
mountAbsent = 1
cleanupSHA256 =
  b9e0cab24180f9cc5ada909e2b6de84a5ab7061e87d634259c701c8dfda51219
```

#### State and correlation matrix

The deterministic state model is exact:

| State | Accepted input | Committed result and next state |
| --- | --- | --- |
| native bootstrap | monitor constructs and sends `monitor_ready` sequence 0 | PID1 validates two rights; monitor enters `ready_transferred`; any ambiguity is terminal |
| `ready_transferred` | controller's first `prepare_begin` at sequence 0 if no prepare was consumed, or a fresh `revoke` | prepare validates exact revision/identity/manifest/expiry, latches prepare consumed, creates unpublished mount staging, and enters `preparing`; revoke enters `revoking` |
| `preparing` | next manifest-ordered `prepare_file`, or `prepare_commit` after all files | one-slot file write/wipe stays `preparing`; valid commit publishes prepared monitor state, responds once, enters `prepared` |
| `prepared` without SSH | optional sole `create_ssh_endpoint` if no endpoint attempt was consumed, or `revoke` | endpoint attempt latches consumed; accepted endpoint enters `prepared_with_endpoint`; revoke enters `revoking` |
| `prepared_with_endpoint` | `revoke` only | denies new accepts externally, enters `revoking` |
| `revoke_required` | one fresh-ID `revoke` only | enters `revoking`; prepare, endpoint creation, and use are permanently denied |
| `revoking` | no new operation; a fresh-ID revoke retry only after `cleanup_retry` | complete absence sends cleanup-complete and enters `cleanup_reported`; retry remains `revoking`; stop-VM is terminal |
| `stop_pending_event` | none | makes at most one safe event send attempt, then enters terminal regardless of success |
| `cleanup_reported` | no request | monitor sends normal `close_notify` at its exact next sequence and enters `close_wait` |
| `close_wait` | controller normal `close_notify` at its exact next sequence | after commit, monitor closes FD 3 and calls `exit_group`; controller observes expected EOF, closes endpoint/namespace, and sends later HL8L `destroy_job` |
| terminal/closing | none | every packet is terminal protocol failure; no state or right is recreated; PID1 separately proves monitor process/cgroup/directory absence after `destroy_job` |

There is one logical outstanding request and one active job. Prepare begin,
zero or more ordered file packets, and commit are one request with one terminal
response; while `preparing` no new request, including revoke, may interleave.
An authenticated canonical pre-mutation denial, or a prepare semantic failure
whose rollback is proved, aborts and wipes all unpublished staging, emits the
single `requestType=0x12` rejection when the link remains usable, clears the
outstanding request, and returns to `ready_transferred` with prepare consumed;
only a fresh-ID revoke is then accepted. An unproved rollback emits
`stop_vm_required` when sendable and becomes terminal.
Authentication,
framing, credential, right, identity, sequence, or canonical-decode failure
closes without response. `create_ssh_endpoint` is valid exactly once after
prepare commit and only when the sealed unique SSH binding exists. A prepare or
endpoint failure never permits exec; the controller drives revoke. An SSH
failure with proved listener/socket-leaf absence returns to `prepared` with the
endpoint attempt consumed, after which only a fresh-ID revoke is accepted. A
prepare or SSH rollback whose
absence is not proved is terminal after `stop_vm_required` is sent when
possible and accepts no later packet. Revoke may start only from
`ready_transferred`, `prepared`, or `prepared_with_endpoint`; it first denies
use, then removes exact owned entries/listener/mount, and never reports
cleanup-complete before all three result booleans are true.

Directions have independent counters. Monitor send sequence zero is readiness;
its first controller-visible response/event is one. Controller send sequence
starts at zero. A received sequence must equal the exact next value. Counters
advance only after credentials, framing, body, rights, canonical encoding,
correlation, and either a state transition or committed accepted semantic
rejection validate. Lower is replay and higher is loss/gap. Legal sequences are
zero through `2^32-1`; accepting the last exhausts that direction, and a later
packet or wrap is terminal. Each sender serializes its direction and does not
advance after a failed or partial send.

Normal close is valid only in the post-cleanup handshake. The cleanup-complete
response commits first; the monitor's normal close consumes its next send
sequence, and the controller commits it before its normal reply consumes the
controller's next send sequence. Only after both close records commit may the
monitor close/exit and the controller close its endpoint/namespace. EOF then is
an expected transport consequence, but neither close record nor EOF is cleanup
or process-absence proof.

#### Response outcome and next-state matrix

Every sendable operational outcome has one exact next state and ownership
decision:

| Operation outcome | Required next state | Ownership after committed send |
| --- | --- | --- |
| prepare `resource_limit`/`operation_denied` before mutation | returns to `ready_transferred`; prepare consumed and outstanding request cleared; only revoke next | no staging or published mount exists; locked slot is wiped |
| prepare expiry outside `(TrustedObservationUnixNano, AuthenticatedSessionHardExpiryUnixNano]` | `operation_denied`; returns to `ready_transferred`; prepare consumed and only revoke next | no mutation; caller-selected expiry cannot widen authenticated authority |
| absent/invalid trusted time or hard-horizon state | terminal `stop_vm_required`; no later packet accepted | no mutation and no caller-controlled fallback clock/horizon |
| prepare `prepare_failed` after complete rollback and inspection | returns to `ready_transferred`; prepare consumed and outstanding request cleared; only revoke next | unpublished staging is absent, every transient is closed, locked slot is wiped |
| SSH `resource_limit`/`operation_denied` before mutation | returns to `prepared`; endpoint attempt consumed and outstanding request cleared; only revoke next | prepared mount remains owned; no listener/socket leaf exists |
| SSH `ssh_endpoint_failed` after proved rollback | returns to `prepared`; endpoint attempt consumed and outstanding request cleared; only revoke next | prepared mount remains owned; listener/right/socket leaf are absent |
| revoke `cleanup_retry` | remains `revoking`; outstanding request cleared | monitor retains the exact remaining owned objects; only a fresh-ID revoke retry is accepted |
| any `stop_vm_required`, including unproved prepare/SSH rollback | terminal; no later packet accepted | no ownership is released or treated as usable; D6 stops/reaps the VM and proves host absence |
| any atomic send loss, including response/event/close | terminal `stop_vm_required`; no replay | peer commit is unknown, received/uncommitted rights are closed, and all remaining ownership converges only through D6 |

An `accepted` prepare enters `prepared`, an accepted SSH response enters
`prepared_with_endpoint`, and revoke cleanup-complete enters `cleanup_reported`
as stated in the primary state table. There is no implicit "continue" state.

#### Failure and cleanup matrix

| Failure class | response/event | ownership and cleanup |
| --- | --- | --- |
| canonical, authenticated resource/bound denial before mutation | one correlated `rejected` response | no mutation or cleanup; exact next state is fixed by the response-outcome matrix |
| prepare/file/commit mismatch with proven rollback | one `requestType=0x12` rejected response | no partial publication; controller must revoke before any exec |
| SSH creation/inspection failure with proven listener absence | rejected `0x13`, zero rights | close listener/socket leaf, retain prepared mount only for revoke |
| revoke observation incomplete but retryable | `cleanup_retry` | monitor retains exact ownership; fresh-ID retry reinspects and never recreates |
| unknown ownership, mount/listener replacement, monitor/PID1/controller loss, or failed normal unmount | `stop_vm_required` when sendable, otherwise no packet | latch terminal; D6 stops/reaps the microVM and inspects host absence |
| framing/authentication/credentials/rights/sequence/identity/correlation failure | no response | close every received right, wipe buffers, terminal stop-VM path |
| atomic send or response loss | no replay | monitor loss; close controller-owned rights and use whole-VM cleanup |

Unknown type, wrong direction/credentials, bad length, truncation, trailing or
noncanonical data, zero required digest, wrong/reordered rights, request/job
identity error, stale revision/generation, replay/gap/exhaustion, duplicate ID,
illegal transition, response/event mismatch, or any packet after terminal
failure permanently latches `stop_vm_required`. EOF outside the committed
bilateral normal-close state, any non-normal close, a normal close in any other
state, close-send failure, policy kill, and role loss do the same. Even the
valid normal close and expected EOF are not cleanup proof.

The operational response matrix is closed:

| Request | `accepted` / `cleanup_complete` | `rejected` | `cleanup_retry` / `stop_vm_required` |
| --- | --- | --- | --- |
| prepare transaction (`0x12`) | `accepted`, failure `none`, exact prepare result | `resource_limit` or `operation_denied` before mutation; `prepare_failed` only after complete rollback and inspection | only `stop_vm_required` with `prepare_failed`, `inspection_failed`, or `cleanup_incomplete` when rollback/absence is not proved |
| create SSH endpoint (`0x13`) | `accepted`, failure `none`, exact result and one listener right | `resource_limit` or `operation_denied` before mutation; `ssh_endpoint_failed` only after listener/socket-leaf rollback and inspection | only `stop_vm_required` with `ssh_endpoint_failed`, `inspection_failed`, or `cleanup_incomplete` when rollback/absence is not proved |
| revoke (`0x14`) | `cleanup_complete`, failure `none`, exact absence result | never | `revoke_failed`, `inspection_failed`, or `cleanup_incomplete` |

No other combination exists. In particular, `accepted` and
`cleanup_complete` always require failure zero; `resource_limit` and
`operation_denied` always mean a pre-mutation rejection with cleanup category
not applicable; and revoke, inspection, or cleanup failure never maps to an
ordinary rejection that leaves state looking usable.

Formerly ambiguous HL8M choices are closed as follows: readiness transfers two
rights, not one, because PID1 must relay both the controller peer endpoint and
live namespace authority in HL8L `job_created`; PID1 consumes readiness rather
than forwarding its body, so the controller begins monitor receive sequence at
one; monitor readiness is job-correlated with a nonzero job digest even though
its request ID is zero; prepare reuses the already implemented helper body and
digest codecs byte-for-byte; one logical prepare has no intermediate response;
the single D5 endpoint is created only after file commit and before overall
helper activation; response loss never replays live rights; cleanup-complete is
monitor-local and cannot stand in for PID1 reap/cgroup or D6 whole-VM evidence;
and `helper-limits-v1` distinguishes exactly one credential-aware exec from the
generic L4 ceiling. These choices preserve
the already frozen 68-byte header,
type IDs, helper layouts/catalog values, direct credential-body path, syscall
supplement, and D2/D4/D5 ownership split.

D2 owns the pure HL8M codec, canonical body/digest functions, fixed-size rights
role metadata, safe formatting and denied serialization, one-slot proposal and
transition state, fake-only correlation/cleanup decisions, vectors, and
plus-one tests. D4 owns the PID1 bootstrap relay, live socketpair and
credentials/rights receive, FD close/dup/remap, pidfd/namespace/mount/file
syscalls, locked receive mapping, listener-independent core cleanup, monitor
exit/reap coordination, the later HL8L destroy path, and all object
reinspection behind D2 decisions. D5
owns only the optional live Unix endpoint creation/accept/peer-validation and
relay behavior reached through the frozen `0x13` seam; it cannot add a type,
right, body, proof, or state transition. D6 alone turns `stop_vm_required` into
exact Firecracker stop/reap and host-owned absence evidence.

HL8M has no public listener, reconnect, resumption, arbitrary path/mount/socket/
clone/exec operation, general FD transfer, PID1 credential-body path, durable
projection, proof-minting authority, live implementation in D2, or authority
available to the agent or workload. D4 and D5 may not reinterpret an encoding,
weaken a terminal result, infer success, or bypass the pure state machine.

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
                       helperGeneration:token | descriptorLength:u16 |
                       canonical client process descriptor
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
0x19 exec_credit       opposite direction from matching stream data,
                       revision:u64 | streamKind:u8 | reserved[7]=0 |
                       nextOffset:u64
0x20 response          helper -> agent, requestType:u8 | disposition:u8 |
                       revision:u64 | failureCode:u8 | typed result union
0x21 event             helper -> agent, eventCode:u8 | revision:u64 |
                       eventID:token
0x7f close_notify      either direction, reasonCode:u8
```

The `0x19` credit body is exactly 24 bytes and its complete helper datagram is
124 bytes. It carries no rights or sensitive body. A helper credit authorizes
exactly one next data-or-EOF `0x18` record at `nextOffset`; its direction,
single-outstanding, terminal-error, and wipe rules are identical to `HL8C`.

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
`0x15`/`0x17`/`0x18` transaction and streams. `0x19` is transport flow control
and never changes a logical result. `accepted` is valid only for
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

### Helper-Service normative closure

The helper-Service normative closure is the exact D2/D4 orchestration contract;
the companion extension-seams document freezes every Go declaration. Service
is constructed with Core, Transport, Policy, immutable Extensions, ExtensionHost,
and ServiceRuntime, and exposes only one `Serve` lifetime returning either
clean `ServiceClosed` after a bilateral normal/shutdown close or
`ServiceStopVMRequired` plus a sanitized error and terminal reason. There is no
public Close or Wait race.

The private Service topology is also closed: its exact top-level field order is
Core, Transport, Policy, a canonical private `[]extensionEntry` snapshot,
ExtensionHost, ServiceRuntime, and one `*serviceState`. That state is the sole
synchronized owner and includes `sync.Mutex`, the never-reset
`serveCalled` latch, and the sole `CoreExecution` value derived from
Service.core.BeginExec. NewService typed-nil validates each configured live
dependency, treats only a nil Extensions pointer as the empty registry,
snapshots nonnil entries through
`snapshotServiceExtensionEntries(*ExtensionRegistry) []extensionEntry`, which
allocates a distinct slice, preserves canonical order/factory identity, and
uses `credentialprotocol.CloneExtensionDescriptor` for every descriptor;
initializes all seven fields; and allocates one fresh empty `&serviceState{}`
with no keyed values, pre-set latch, or execution. Serve classifies a plain or
typed-nil context before the latch and returns that exact classification error;
a noncontrolling check or suppressed error is invalid.
The first valid caller atomically claims the sole lifetime and every later
caller receives `ErrContractTransition` without a dependency call. Context
classification is the first operation, and the latch check and set occupy one
unbroken mutex critical section. The latch is never reset and the state owner
is never replaced through direct access, a receiver alias, or a state alias in
any private Service method reachable from Serve. Ignored/late dependency
checks, source-slice aliases, and split or unlocked latch operations are
rejected. The
constructor/Serve signatures, storage, state allocation, and synchronized
one-Serve transition are production AST requirements, not documentation-only
markers.
All five invalid dependency cases return the exact sanitized
`ErrContractDependency` before snapshot or storage.
After that constructor returns, Core, Transport, Policy, ExtensionHost,
ServiceRuntime, and the owned extension snapshot are immutable across the
entire Serve-reachable Service graph. No reachable method may replace one
directly, through a receiver alias or pointer, through a composite/field
assignment, or by giving the field or its address to a helper. Only a direct
method invocation on the exact stored dependency is an authorized use, so the
validated object is the object used at dispatch and Core boundaries.

ServiceRuntime exclusively owns authenticated bootstrap/agent binding, live
job generation/time observation, loss notification, and one cleanup budget.
That budget has an exact 30-second limit shared by the whole drain. It requires
conforming trusted dependencies to observe the supplied context but makes no
in-process forced-return promise for an arbitrary blocker; nonconformance or
unknown absence escalates to D6 kill/reap.

Core execution uses the grant-driven CoreExecution event loop: WriteStdin,
GrantOutput, Next, and Cancel. An output event owns the full canonical `0x18`
body, not a second payload buffer; after its frozen context/body preconditions,
its leading-context constructor takes ownership and synchronously destroys
post-transfer failure with that supplied context. The helper SendPacket keeps
the existing CredentialSink but makes the write context-aware;
credentialclient's two BodySegmentSink contracts remain separate and
unchanged. Every live body/right receive or private-send constructor likewise
takes a leading context; it rejects plain or typed nil before transfer, applies
the additional Exec-plan precondition when applicable, then owns on entry and
never uses a background/TODO substitute.

Retained receive payload access threads the exact supplied context through
owner borrow, scoped-view length/write, and destination maximum/write
callbacks, with cancellation checks before and immediately after every
external callback. Observed cancellation prevents every later call, fill, and
success and is reported only as sanitized ownership failure. Cleanup still
calls each owned body destroy/right close exactly once with a non-nil canceled
context. Cleanup callbacks are isolated from one another: a panic is reduced
to sanitized ownership failure and cannot skip another live owner's mandatory
cleanup or escape the transport constructor.

Core correlation capabilities use the single
`hal/l8/guest-helper/core-capability/v1` domain with four exact kinds and all
six fixed generation positions; partial prepare values encode the final three
positions empty. Extension exec bindings are Service-minted opaque values under
`hal/l8/guest-helper/extension-exec-binding/v1` and are echo-only for D4/D5.
Public active/binding/exec/cleanup proof labels and event IDs are deterministic
nonsecret digests with literal prefixes `active.`, `binding.`, `exec.`, and
`cleanup.`; no live capability becomes a proof string.

The state machine reuses the existing credentialprotocol prepare transaction
and `credentialprotocol.HelperExecTransactionSeed` rather than inventing
Service-local prepare/exec FSMs. It stores two non-evicting fixed ledgers: a
4,096-entry non-exec ledger
whose last three entries are three reserved Revoke slots, and a separate
4,096-entry exec ledger. Exact replay consumes no slot. A first-seen ID is
charged before mutation. The sole overflow exception is terminal and uncached:
drain declared input without mutation, best-effort emit the operation's allowed
failure while IPC is usable, then mandatory drain/stop-VM; no 4,097th cached ID
is promised.

The three reserved Revoke slots are outer wire attempt correlations. The first
Revoke establishes one inner Core cleanup correlation and capability; a
fresh-ID retry retains that inner correlation/capability and uses its new ID
only for transport, policy, runtime-observation, response, and replay-cache
correlation. The outer wire retry trigger never replaces or remints the retained cleanup capability.
After `cleanup_retry`, the peer-driven cleanup episode denies ordinary
admission and accepts only the next fresh-ID Revoke under the same cleanup
budget to start new work. An exact duplicate outer Revoke remains replayable
from cache without starting absence work. An internally driven cleanup episode uses the owning prepare/exec
cleanup correlation, consumes no reserved Revoke slot, and drives retries
without exposing `cleanup_retry`.

Extension lifecycle is one activation: open selected sessions in order before
Core BeginPrepare. Precommit Rollback before reverse extension Close is
mandatory on pre-commit failure.
Core Commit precedes ordered extension Prepare and publish; any begun
post-commit Prepare failure reverse-revokes including the failing session and
Core-revokes (never rolls back); renew is Core then extensions and failure
revokes the activation; revoke denies new work, cancels, reverse-revokes
extensions, then Core-revokes. Every retry or unknown result flows through the
repeatable absence pass; reverse Close occurs only in the one-time finalization
pass after the absence loop ends. Close is called once and never substitutes
for Revoke or absence proof.

Terminal cleanup is one fixed budget and one exact three-pass cleanup protocol:
deny ordinary admission once; run at most three repeatable absence passes of
Cancel, reverse extension Revoke, and precommit Rollback or postcommit Core
Revoke. Complete Revoke proves Core absence and stop-VM Revoke escalates; only a retry-required Core Revoke is followed by Core Inspect.
In the peer-driven cleanup episode, Service must
wait for that retry under the same cleanup budget after attempt one or two
returns cleanup-retry; an internally driven cleanup episode advances without a
packet.
A third incomplete attempt is terminal. Then run one one-time finalization pass
of reverse extension Close, Service-owned packet destruction, Core Close,
Runtime Close, correlated close-notify if unambiguously usable, and Transport
Close last. Completed absence work is skipped, retry never recreates, no
finalizer begins before the
absence loop ends, and no absence operation runs after finalization begins.
Stop/deadline/unknown absence dominates, while finalizers remain best-effort
inside the same budget before D6 kill/reap.

The stop-VM response correction is closed: `cleanup_retry` is Revoke-only;
`stop_vm_required` is legal only for PrepareCommit, Renew, Exec, or Revoke;
Renew and Exec admit `cleanup_incomplete`; non-Revoke stop uses only
cleanup-incomplete for unknown absence or helper-unavailable for a proved-clean
terminal dependency failure; Revoke stop uses revoke-failed,
helper-unavailable, or cleanup-incomplete. A terminal response is best effort
only while IPC is unambiguously usable and never converts stop-VM into success.

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
  for each stdin record, including the final EOF, in offset order:
    flags:u8 || uint64_be(offset) || uint32_be(payloadLength) ||
    payloadSHA256 || payload ||
  uint32_be(stdinRecordCount))

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
Credit records are transport flow control only. They do not enter
`stdinRecordCount`, `stdinTranscriptSHA256`, `stdinSHA256`, or
`execTransactionSHA256`; credit timing and stdout/stderr interleaving likewise
do not change the per-stream content hashes. They do consume ordinary secure
and helper sequences and the existing record caps.

This count-trailer formula is the sole canonical construction. The record
count is appended after the last record, immediately before finalizing the
hash. The receiver initializes the domain-separated hash once, streams each
authenticated canonical record header and payload into it, increments one
bounded counter, performs the downstream write, then performs an immediate
full-capacity wipe of the sole at-most-64-KiB payload slot. At the unique EOF it
hashes that record, appends `uint32_be(stdinRecordCount)`, and finalizes. The
comparison-only replay path uses the identical one-pass construction. This
requires O(1) hash state plus the one payload slot and preserves exact chunk
boundaries, offsets, per-chunk digests, content, and EOF.

For the helper Service observed path, that one payload slot is precisely D4
Transport's retained locked `ReceivedPacket` body. The transaction never
allocates or copies a second heap payload slot: it retains only proposal-local
candidate hash state and safe counters until commit. The older decoded-body
transaction API's compatible heap slot is not used by configured Service.

**Pre-production transcript correction.** The earlier count-prefix expression
required knowing the count before consuming records, contradicting immediate
wipe/no-retention and the single-slot bound. No D4 producer, live L8 deployment,
or accepted L8 proof has shipped, so D2 deliberately corrects the vector before
compatibility exists. Two-pass replay is rejected because it adds a second
input/retention seam; retained leaf digests are rejected because they add
record-count-sized state and still cannot recover payload content. No prior
count-prefix vector is accepted or negotiated.

Ready, bootstrap, bootstrap-ack, and both hello packets require an all-zero
request ID and all-zero job identity digest. `helper_ready` alone has an
all-zero nonce; bootstrap and every later packet echo the exact helper-local
nonce. Every job request has a nonzero 16-byte request ID, exact nonzero
`GuestCredentialSessionIdentity` digest, and positive revision. A response
echoes its request ID/digest/type/revision; an event and SSH-accepted packet use
their own producer-owned nonzero ID while no operation is outstanding.
`close_notify` consumes the ordinary next sequence and record cap, has an exact
zero request ID, and contains only its safe reason. Thus a Client helper receive
with no expected request ID is legal only for idle event/SSH or drain-time
close-notify; all ordinary response/stream/credit packets match an outstanding
nonzero ID. Readiness and bootstrap remain separately correlated.

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
without a response. A host/controller that deliberately retries a completed ID
on the same still-authenticated control session must retransmit the entire
canonical transaction from its own replayable source at fresh secure sequences.
The agent forwards those newly supplied bytes at fresh helper sequences; it
does not retain or reconstruct wiped file bodies. A cached identical success
re-emits the prior safe result without mutation; changed content under that ID
is terminal. Loss, timeout, or ambiguity on the local seqpacket response is
helper-role loss and whole-VM cleanup, never an agent-initiated retry. No other
request may interleave before the terminal response.

Exec is one separate logical transaction. `0x15` declares zero private bytes
and an all-zero private digest when the manifest has no HTTP mode. Otherwise it
declares 1..64 KiB and the SHA-256 of the exact host `HL8B` kind-2 payload; one
`0x17 exec_private` with the same request ID, identity digest, revision,
length, and digest follows immediately. No child, pipe, gate, or pidfd exists
while the helper authenticates and decodes that payload. A missing, extra,
reordered, changed, or zero/nonzero-mismatched private packet aborts exec, wipes
the payload, and cannot leave an orphan because process creation has not begun.
Only after private authentication does the credential controller create all
three pipe pairs, keeping the parent-side stdin-write, stdout-read, and
stderr-read endpoints. It sends the inspected child ends, exact namespace,
workdir and executable FDs, sealed launch-block FD, and start gate to the PID1
launch supervisor under the closed D2 launch request. Credential bytes travel
only through the direct controller-to-shim launch block; PID1 never receives or
parses them. PID1 starts only immutable `hal-guest-role-bootstrap` in shim mode
with pinned Go 1.25.7 `SysProcAttr.Cloneflags=0`, `UseCgroupFD=true`, exact
`CgroupFD=9`, and a non-nil `PidFD`. The pinned runtime commits kernel `clone3`
flags `CLONE_VFORK|CLONE_VM|CLONE_PIDFD|CLONE_INTO_CGROUP` plus `SIGCHLD`
before the shim can run. PID1 releases the gate
only after exact pidfd, cgroup placement, FD roles, generation, executable, and
input correlation pass. The shim performs the syscall supplement's ordered
namespace, identity, capability, seccomp, and pinned-FD exec transition; a
failure exits without workload exec and is reported through the supervisor's
authenticated exit event. Any failure after shim start but before gate release
closes the child-side endpoints and gate, writes `1` to the exact owned job
cgroup's `cgroup.kill`, proves zero population, reaps the recorded shim pidfd,
wipes the private buffer, and only then returns a safe failure. PID1 never sends
a signal to a shim after it can become UID 1000.

After the child gate opens, each `0x18 exec_stream` maps one-for-one to the
correlated host `HL8S` record. Its stream kind, EOF flag, offset, length, digest,
direction, and aggregate obey the same rules; agent-to-helper carries stdin and
helper-to-agent carries stdout/stderr. The helper concurrently forwards stdin
while draining stdout and stderr; it never waits for stdin EOF before reading
either output pipe. `0x19 exec_credit` propagates the corresponding host `HL8C`
credit across the agent. Stdin credit flows helper-to-agent; stdout/stderr credit
flows agent-to-helper. The agent grants helper output credit only while it owns
the matching controller credit and an empty fixed slot. After a complete stdin
pipe write, the helper wipes that slot before granting another stdin credit;
after an authenticated output write upstream, the agent wipes its slot before
granting another helper credit. This keeps one bounded mutable chunk per stream
without filling the shared seqpacket queue with a stream whose consumer is not
ready. The terminal exec response is
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
duplicate request while the original is active is a terminal conflict. The agent never retains or autonomously replays
wiped plan/private/stdin chunks. A host/controller may deliberately submit a
completed request ID again on the same authenticated session only by supplying
the complete `0x15`, optional `0x17`, and every stdin `0x18` record again from
its own replayable source at fresh secure sequences. The agent forwards those
records at fresh helper sequences with the same request ID and fresh per-record
credits. The helper enters comparison-only mode:
it creates no pipes or child, issues only stdin credits, accepts no stdout or
stderr credit, emits no output stream records, consumes and authenticates the
complete private/input transaction, recomputes its digest, and re-emits the
cached response only on an exact match.
A changed plan, private record, chunking, content, EOF, identity, or revision
closes and revokes the session. A canonically framed semantic rejection enters
the same no-launch drain mode, consumes the declared private/input transaction
through its unique EOF, and caches its safe failure only after the complete
digest exists. Authentication/framing failure, loss, cancellation, or timeout
before that point closes the session without a reusable response. Only a
complete cached failure replays under the same rule; no same-ID path may launch
twice. Entries are never evicted or reused and are wiped on activation
revoke/loss/expiry. Comparison replay proves no second launch and can recover
only the safe terminal response, never output stream bytes; a host that cannot
resupply the exact input transcript or that loses output treats the operation
as terminal. Local helper-response loss is role loss and never enters this
comparison path.

**D2 Service-readiness payload closure.** The helper never converts received
`exec_private` or stdin `exec_stream` payloads into the heap-owning decoded
credentialprotocol bodies. Trusted Transport first completes canonical packet
validation and mints an opaque one-use safe-metadata observation whose declared
length/digest equals the independently observed locked payload digest. Service
privately takes that observation and the sole retained body. The existing exec
transaction consumes the observation: private input reserves the existing
proposal while the same scoped view goes to Core; stdin synchronously hashes a
single supplied `credentialmemory.BorrowedView` through cloned hash state and
then the same view goes to Core. Comparison replay performs the identical
metadata, offset, EOF, content, record-count, transcript, and transaction hash
work but never calls Core. The observation proves canonical metadata/digest
only; configured Service sequencing and Core's echo/result matrix own live-use
assurance. No second FSM, payload owner, slot, transcript, or heap copy exists.

The exact pure bridge API is
`NewHelperExecPrivateObservation`, `NewHelperExecStreamObservation`,
`(*HelperExecTransaction).ProposeObservedPrivate`, and
`(*HelperExecTransaction).ProposeObservedStdin(context.Context,
HelperExecTransactionCorrelation, HelperExecStreamObservation,
credentialmemory.BorrowedView)`. Observation aliases share one-use state.
Hash reservation and installation are synchronized, while no transaction lock
is held across a borrowed-view method. Cancellation, panic, concurrent alias
use, duplicate or missing writes, error suppression, changed state, or digest
mismatch wipes proposal-local candidate state and terminally fails the
transaction. The transaction's current hashes and counters remain unchanged
until `HelperExecPayloadProposal.Commit`, which alone atomically installs and
advances the candidate after Core success (or immediately for comparison).
`Wipe` never installs it. EOF remains one exact zero-payload record and the
existing count trailer is appended only on its successful commit.

Every observation field is rebound under the transaction mutex before a
proposal becomes usable. Request ID and identity digest correlation and all
SHA-256 values compare in constant time; revision, private length, stream kind,
flags, offset, payload length, current credit, aggregate, record count, and EOF
state compare exactly against the transaction owner. The observation is first
validated and charged once; only that alias winner may attempt transaction
admission. Precedence is plain/typed-nil context or view before touch,
observation structural error, observation-used error, transaction
terminal/completed/correlation, transition or credit, field binding,
record-count and aggregate/offset bounds, external view consumption, then
pending-state revalidation. Any mismatch after the one-use charge is terminal
and wipes pending and candidate state; it cannot be retried with an alias.
AST guards bind the constant-time requirement to the exact observation
constructors and observed admission methods, their calls to
`helperExecDigestsEqual` and `helperExecTransactionCorrelationEqual`, and the
helpers' exact direct return expressions over `subtle.ConstantTimeCompare`.
Every unshadowed helper call in those four declarations must itself be a direct
term in an immediate nonnil-error rejection. Discarded, dead, nested
noncontrolling, equality-substituted, or locally shadowed calls and a
constant-time call elsewhere in the package do not satisfy this closure.
Each call's operands are exact too: constructor declared digest versus observed
digest; supplied correlation versus the transaction owner's correlation;
private observation digest versus the owner's private digest; and stdin
observation digest versus the digest computed only from that same method's
borrowed view. Self, swapped, foreign, global, shadowed, dead, discarded, or
noncontrolling operand substitutions are rejected.

Proposal source is explicit and private: legacy is 1 and observed is 2, with
an `observedReady` latch. Legacy normal/comparison commit keeps its existing
copied/hashed predicate. Observed private commits only an observation-ready
metadata proposal; observed stdin commits only an observation-ready proposal
with both candidate hash owners and exact next offset/bytes/records/EOF.
Commit does not attest that Core ran. Under the transaction mutex it first
fully wipes the superseded current stdin/transcript hash owners, transfers the
candidate pointers, nils the proposal pointers without wiping the transferred
owners, installs counters, and finalizes EOF. Failure/Wipe wipes candidates and
leaves the current transaction unadvanced and terminal.

The borrowed view and private sink are synchronous scoped TCB values. Neither
may be retained and every concurrent sink call must join before `WriteTo`
returns; duplicates completed in that scope are synchronized and rejected.
Use after return is a D4 Transport contract violation, not a retroactive
detection promise made by the returned proposal. Source and shape guards
forbid transaction or observation struct state from retaining either interface
through pointer, array, map, channel, index/generic, named, alias, nested
struct, interface, or function-valued fields. A retained function field is
forbidden when a parameter or result reaches either scoped interface; top-
level function and method parameters remain the required scoped API. Generic
constraints from every `TypeSpec.TypeParams` are recursive retention edges:
`holder[T BorrowedView]`, `holder[T CredentialSink]`, and constrained
function-field parameter or result variants are forbidden, while a top-level
function or method parameter remains allowed. The same recursion treats every
package-level `ValueSpec` variable as a retention root and follows explicit or
inferred types, cross-file aliases, containers, channels, function
values/results, and closure captures. Later package-variable assignment,
locally returned closures, and interface/container assignment sinks are also
retention roots. While either scoped interface is lexically live, no function
literal is permitted except the one direct synchronous body-borrow callback;
that callback has no nested literal, IIFE, `defer`, `go`, or retained method
value. Direct, aliased, shadowed, and composite captures are equivalent.
The no-retention analyzer credits only an unrebound exact
`ReceivedBodyCapability` or `CoreOutputBody` identifier declared directly in
the enclosing top-level function parameter list. That identifier may make one
immediate inline synchronous `Borrow` call, directly or as a direct `defer`;
the call is outside `for`/`range` loops, no second `Borrow` call is present, the
callback has one named, nonblank, exact import-bound
`credentialmemory.BorrowedView` parameter, the context and callback identifiers
are those exact parameter objects rather than same-spelled shadows throughout
the callback's scoped-view consumers. Alias propagation follows the exact
range role, so slice indexes and unrelated map keys do not inherit value-side
scope; named and aliased container types resolve to those same underlying
roles, and callback `go`, `defer`, and sends are forbidden. Its
bound method value cannot escape. Assignment/comma-ok and function
results, composites, fields/promoted fields, indexes, range/channel values,
slices, pointers, address/dereference, parentheses or other wrappers,
branch/loop joins, and nested-function parameters are deliberately unresolved.
Direct `Borrow` and bound methods from those forms are rejected instead of
requiring a general control-flow/location analyzer. This narrow rule does not
relax the exact Prepare-file handler shape.
The exact already-landed synchronous transport-wrapper calls in
`receivedPayloadBody.Borrow`, `SendPacket.WriteCanonicalBody`, and
`validSendExecStreamArm` remain governed by their separate frozen transport
proof. Each contains exactly one synchronous `Borrow`; the receiver, arm, and
stream are unrebound, their selected body owner is neither written nor
addressed, and `WriteCanonicalBody` obtains the stream only through the exact
unrebound `packet.sealedArm()` result. The sealed pointer is confined to its
direct read-only selector and nil-check uses; it is never aliased, passed,
returned, stored, sent, or addressed. Its selector grammar is exactly the
body-length comparison, one `written.CompareAndSwap(false, true)`, stream-arm
assertion, configured/canonical-length/scratch arm calls, and body-digest
comparison through the declaration-bound `crypto/sha256` import. Every listed
occurrence is unique and direct (the digest read is inside the one synchronous
scratch callback); loop, `go`, and `defer` ancestors are not equivalents.
Selector methods and standalone stored selector values are also invalid. No
selected field is written or
addressed outside the named atomic gate. This does not create a general
field-owner exception. The readiness proof compares the complete formatted
`WriteCanonicalBody` body plus every trusted scoped-value helper body against
the already-landed declarations: `configuredDependency`, `typedNil`,
`destroyTransportBody`, `isNilCoreDependency`, and `withCanonicalScratch`.
Helper imports are resolved from their own declaration files. The protocol
wrapper form additionally requires the unique exact standard-library
`reflect`-bound `helperExecConfiguredDependencyNil` leaf, and the scratch form
requires the unique exact `wipeBytes` leaf that clears the supplied
full-capacity slice before the exact standard-library `runtime.KeepAlive`.
Signature-only helpers, lookalike imports, retaining classifier/wipe leaves,
reordered gates, ignored results, and dead-branch observations are invalid.
The exact Prepare-file path may use the single-assignment local
`body := packet.body` from its exact `ReceivedPacket` parameter, then call only
`configuredDependency(body)`, `body.Len()`, `body.SHA256()`, and one direct
inline `body.Borrow(ctx, callback)`. Rebinding, address-taking, returning,
sending, passing, storing, further aliasing, a lookalike packet owner, a method
value, or an escaped callback makes that local ineligible for scoped Borrow
credit.
Within the inline callback, only the exact
`preparing.preparation.StageFile(ctx, fileRequest, view)` call may consume the
scoped view for Prepare-file staging; foreign owners, requests, contexts,
helpers, and method values remain invalid.
The generic scoped-flow scan has exactly three closed execution composition
allowances: the entire canonical `private` function may install its already
validated `Core.BeginExec` result under `state.mu`, and the entire canonical
`stdin` function may copy the retained execution under that mutex and consume
the callback view synchronously in its one `WriteStdin`. The exact free
`observeServiceCoreOutput` function may Borrow one `CoreOutputBody` only to
synchronously call the view's `WriteTo` into the payload-digest sink. Each
allowance compares the complete function signature and body with the
independently guarded canonical AST. It is not inferred from a statement,
receiver, or name. Any
mutation, extra statement, reorder, shadow, rebind, wrapper, or asynchronous
use loses the allowance and returns to the ordinary fail-closed scan.
Required test evidence is one unique
top-level exact `func TestX(t *testing.T)` AST declaration using the real
`testing` import; text markers, function literals, lookalike imports, wrong
signatures, and duplicate declarations do not count. The exact
one shared helper `helperExecConfiguredDependencyNil(any) bool` handles all
arbitrary typed-nil context and borrowed-view values before any owner is
touched. A plain nil context or typed-nil context returns the same stream error
before any context or view method, so no `ctx.Err` call can panic. `reflect` is
confined to that helper and cannot emit a dynamic type or value.

After observation consumption, cancellation, view length/write errors, sink
errors or suppressed/duplicate/no writes, and panics from the two external view
calls are narrowly recovered and collapse to
`ErrHelperExecTransactionStream`. No cause or panic escapes; the proposal and
candidate hashes are wiped and the transaction is terminal. Internal invariant
panics outside that narrow external-call boundary are not recovered.

Normal Service sequencing keeps the body scope intact: it invokes
`ProposeObservedStdin` and then `Core.WriteStdin` sequentially inside the same
outer body-borrow callback, commits only after the Core call returns nil, and
wipes before leaving that callback on error. Comparison proposes and commits
inside the same outer body-borrow callback without calling Core. Private input
uses the corresponding same-scope ordering around `ProposeObservedPrivate` and
`Core.BeginExec`.

The production wiring privately takes the matching received arm, the exact
`*credentialprotocol.HelperExecTransaction`, and its sole retained body before
that outer Borrow. Its parameters bind the credentialhelper package's exact
`ReceivedBodyCapability`, the exact imported
`credentialmemory.BorrowedView`, and the same handler context across Borrow,
observed stdin admission, and Core; suffix lookalikes and background-context
substitution are rejected. The exact transaction correlation and exact
private/stream observation taken from that received arm remain the handler
parameters passed to Propose; zero values, package globals, foreign values, or
shadowed replacements are invalid. Reassignment or shadowing cannot substitute
any
handler receiver/context/body/transaction/comparison parameter or callback
view/proposal/proposal-error/Core-result variable.

The matching-arm extraction is one closed private topology. A live dispatch
method receives the packet through `s.transport.Receive(ctx, request)` and
immediately propagates the receive error, selects exactly `packet.ExecPrivate()`
or `packet.ExecStream()` and immediately rejects a false arm result, then calls
the sole `s.takeExecDispatch(arm.Revision())` transition and immediately
propagates its error. Its exact private result is `serviceExecDispatch` with
fields, in order, `transaction *credentialprotocol.HelperExecTransaction`,
`correlation credentialprotocol.HelperExecTransactionCorrelation`, and
`comparison bool`. The branch directly returns the matching handler with
exactly `ctx`, `packet.body`, `dispatch.transaction`, `dispatch.correlation`,
`arm.observation`, and `dispatch.comparison`. Those locals cannot be rebound;
cross-arm, zero, global, foreign, shadowed, and background-context values are
rejected. Handler reachability from `Serve` follows only actual returned
Service `CallExpr` values in live control-flow branches. The sole dispatch-state
transition may instead bind its result and error when the immediately following
gate propagates that exact error. Method values, discarded or non-propagated
results, calls after an unconditional return, and statically false branches
cannot satisfy the production AST requirements.

The Service state guard permits the exact synchronization that this closed FSM
requires instead of rejecting its own implementation. The matching request,
claimed plan, exec transaction, transaction correlation, comparison bit,
revision, and retained `CoreExecution` are value-copied or taken only under the
exact `serviceState.mu`. `takeExecDispatch` checks the supplied revision against
the same exec-ledger entry, rejects an already-taken entry, copies that entry's
transaction/correlation/comparison tuple, and latches that same entry taken in
one lexical and control-flow-complete critical section. Its exact revision-
mismatch-or-taken condition immediately unlocks and returns an error, while the
success path performs exactly one latch write and unlock before returning the
copied tuple. Every path which acquired the lock unlocks exactly once before
leaving the critical section. Nested or aliased returns, panics, no-return
calls, conditional terminals, and other control transfers before that unlock
are rejected, including after the taken latch is written. Critical-section
rejection conditions are pure: helper calls, callbacks, receives, initializers,
and else paths cannot panic, block, or bypass the exact unlock-and-return body.
Assignments in a critical section are only exact state-field value copies or
latch writes with safe local/state-field targets; indexing, calls, conversions,
indirect targets, and other panic-capable expressions are invalid.
Conditional early
unlocks, missing success unlocks, empty or noncontrolling gates, and
false-conjoined lookalikes are invalid. A handler may copy the matching request/plan or retained
execution for its one immediate Core boundary under the same mutex. These are
value transfers, not a second state owner: no state pointer, field address, or
live owner escapes. Unlocked access, an arbitrary helper over a state value,
global or cross-entry substitution, a wrong revision, and duplicate take/retry
are rejected. This is the sole state-copy allowance; it does not weaken the
never-reset latch, immutable configured dependencies, or owner-replacement
guards.

Before Service wiring can retain a prepared activation or install a first-seen
Exec dispatch, three private D2 prerequisites are present together and are
guarded as one dependency chain. This bounded slice covers Prepare, Commit,
Renew, and authenticated first-seen Exec request/in-flight dispatch issuance.
Exec completion, the fixed 4,096-entry result ledger, and comparison-replay
issuance remain a separate prerequisite slice. The unique
`newServiceCoreCapabilityDigest` implements the exact
`hal/l8/guest-helper/core-capability/v1` encoding and private 1..4 kind catalog;
there is no public or alternate-build issuer. Its domain literal is unique, and
every nonzero Prepare capability literal is built only by the exact
`newServicePrepareCapabilities` body from the returned digests. Direct or
aliased capability composites or conversions, digest field writes, a copied
encoder, or an execution-capability literal cannot establish authority. This
includes nested selector/index/container fields, pointer and parenthesized
forms, package or function-local named container types and aliases, method
receivers, type assertions, inferred package owners, and range-derived aliases.
Address-taking of `.digest`, slicing it into `copy`, indexed assignment or
increment/decrement, and any returned, passed, stored, or aliased writable view
are invalid. Tracking is bound to exact lexical declarations and exact
field/index/range positions: container copies preserve only their capability
field paths, map key/value roles remain distinct, and unrelated siblings or
same-spelled local values/types do not inherit capability classification. Exact
generic instantiations substitute their declaration-bound type arguments;
anonymous embedded fields, interface method results, positional multi-results,
and range-over-function yields preserve only their exact value paths.
Parentheses preserve call-result positions, named callback types preserve
range-function yield positions, and recursive generic declarations converge on
a finite declaration-cycle proof. Ordinary, generic, and mutually recursive
edges terminate without losing an owner reachable after the cycle. A local
lookalike capability type or Core-constructor value is not the package
declaration and remains unrelated. Exact value reads remain valid. Digest
slices may reach `ConstantTimeCompare` only
through the exact file import bound to `crypto/subtle`; a local/package shadow
or same-named receiver is not accepted, while parentheses around that exact
imported function leave the binding unchanged. The Core
Prepare/File/Commit/Renew/Revoke and receive constructors are each confined to
their exact declaration-bound call sites rather than accepted by name; Revoke
construction is limited to the two exact cleanup owners, while an unrelated
receiver method sharing a constructor spelling remains unrelated.
Every prerequisite declaration and live edge is selected in each supported
linux, darwin, freebsd, and windows amd64 build context where Service is built;
a sole build-tag-specific or alternate declaration is insufficient. The unique
`newServicePrepareAuthority` mints one exact private `servicePrepareAuthority`;
the configured Core result and that authority become one exact state-owned
`servicePreparing`. The issuer consumes only the exact authenticated
`PacketTypePrepareBegin` header and typed arm, configured Runtime
bootstrap/complete observation, and retained protocol transaction. It projects
the exact partial Prepare tuple only through
`NewCoreGenerations(boot, helper, job, "", "", "")`, checks that constructor
error immediately, and retains the complete observation independently. It derives
the exact transaction correlation, pre-mints the three partial-tuple
capabilities, and solely calls `NewCorePrepareRequest`. The configured Core's
exact successful `BeginPrepare` result and that authority are installed in the
one Service-owned `servicePreparing` entry under `state.mu`. Before the Core
call, `reservePreparing` atomically installs the exact authority and transaction
with `beginTaken`; duplicates and an existing activation fail before Core. An
outer handler recovery closes that exact transaction and rolls back any exact
returned `CorePreparation` on every pre-install failure or panic. Only
`installPreparing` consumes the reservation and transfers both owners.

Every configured Transport receive calls the exact private
`newServiceReceiveRequest` to issue exactly one state-sequenced
`NewReceiveRequest(sequence, MaxHelperPacketBodyBytes, 0)` and passes that same
local value to configured Transport. The main loop and private continuation
cross the exact panic-isolated `receiveServicePacket`, so a synchronous
Transport panic becomes `ErrContractOwnership`. This includes the main Serve loop and
each private/stdin continuation dispatcher; each checks the issuer error
immediately. Global, caller-provided, foreign, stale, ignored-error, or rebound
requests are invalid. The one returned packet dispatches by exact authenticated
type. Every post-receive path—including handler panic/error and
unknown type—runs the same panic-isolated cleanup, checks body `Destroy(ctx)`,
and checks an unexpected right `Close(ctx)` exactly once with the same context.
An error from the main Receive enters exact `finishServiceReceive`, which
synchronously converges a preparing transaction through abort, a prepared
activation through revoke, or an installed Exec through `finishExecDispatch`;
it returns a valid stop-VM result and cannot expose a live owner.
The state field order is exact: `mu`, `nextReceiveSequence`, `preparing`, then
`prepared`.

For `PacketTypePrepareFile`, the handler atomically sets `fileTaken`, while
Commit rejects that latch. Before Core, the sole file-request issuer,
`newServiceFileRequest`, snapshots the retained transaction, proves its exact
next binding index, resolves the
same `file_tmpfs` manifest binding, and binds its metadata and stored Prepare
correlation into `NewCoreFileRequest`. The retained packet body supplies the
independently observed length and digest. In one synchronous Borrow callback,
the exact state-owned `CorePreparation.StageFile` must succeed before the exact
transaction `AcceptObservedFileObservation` accepts a declared-versus-observed
`NewHelperPrepareFileObservation`. Only full success clears `fileTaken`; any
post-take error or panic enters the reachable precommit cleanup owner.

The matching authenticated `PacketTypePrepareCommit` arm takes that entry once.
The sole `newServiceCommitRequest` drives its exact retained protocol
transaction with the typed Commit body and solely calls `NewCoreCommitRequest`
from the stored Prepare request/capabilities and transaction result. Only the
stored `CorePreparation` receives it. The unique
`newServicePreparedActivationCandidate` derives an ephemeral
`servicePreparedActivationCandidate` only from that taken entry, authenticated
Commit header, configured Runtime observation, issued Commit request, and
successful Core result. It checks exact request/identity/revision/boot and
generation provenance plus every result echo. `installPreparedActivation`
takes those exact five values, invokes only that candidate issuer and, under
`state.mu`, installs one `servicePreparedActivation` only when the one-use
preparing entry still exists and no activation already exists, then clears the
preparing owner. No state-owned candidate slot or caller-mintable shortcut
exists. `servicePreparing` stores exact `beginTaken`, `fileTaken`,
`commitTaken`, and `active` latches after its authority/Core owners. Candidate
and activation retain the exact copy-safe manifest, binding count, prepared
capability, and original Prepare cleanup capability; Renew cannot rewrite any
of them. Aliases,
addresses, returns, increments, alternate writers, function-value issuer
aliases, and wrappers are rejected package-wide. The proof follows transitive
Service-state aliases in methods and package free functions, plus aliased field
pointers and package- or function-local named/alias spellings, nested pointer
layers such as `**Service`, container wrappers, conversions, and type assertions
whose underlying value is `*Service`, plus direct/named/asserted
`*serviceState` owners and selectors extracting either owner from a container,
including pointer-wrapped and copied containers and function-valued factories.
Package-global Service/state owners seed the same provenance graph. Anonymous
embedding and promoted selectors, instantiated generic fields, interface
method results, each positional function result, and range-over-function yields
retain the owner at the exact value position. Function-local activation types
or issuer values that merely reuse package spellings remain unrelated; only the
declaration-bound candidate and activation constructors receive authority.
Lexical
identity plus exact field/index/range roles prevent an inner same-spelled
binding or unrelated sibling/map value from inheriting owner classification.
The graph rejects state-owner escape
through globals, helpers, returns, sends, containers, or conversions.

The only state-owner functions in this prerequisite are the exact receive
issuer, reservation/install, file take/finish, commit take, precommit
`abortPreparing`,
prepared install, postcommit revoke, Renew request/advance, and their exact
handlers. Precommit failure atomically takes the owner, closes the transaction,
and performs bounded `CorePreparation.Rollback` with the frozen cleanup-result
matrix. Immediately before Core Commit is invoked, ownership switches to the
postcommit path because a Core error or panic cannot prove absence of mutation.
If that call errors/panics, candidate validation/install fails, or received-packet
cleanup then fails, `revokeCommittedPreparation` uses the
retained prepared/cleanup capabilities and exact complete observation to call
Core Revoke, never Rollback. Transaction Close failure or panic is accumulated
and cannot suppress that Core Revoke attempt. A complete result reaches absent;
malformed,
panic, stop-VM, or retry-required results reduce to the sanitized stop-VM path.
This bounded prerequisite never immediately repeats Revoke: the later full
cleanup episode alone owns the frozen Revoke-then-Inspect retry protocol.

These are live Serve edges, not pasted or post-terminal statement sequences.
The public `Serve(context.Context) (ServiceResult, error)` retains its exact
context-first one-shot latch, then uses the exact request/receive loop and
packet-type switch. Its four Prepare/Renew clauses assign the exact handler
error and share the immediate error gate. This bounded composition admits no
arbitrary extra clause: before another boundary is composed, the sole
additional clause is the exact returned `PacketTypeExec` edge. A direct Core
call, foreign request, or other packet type is invalid. The combined
satisfiability proof carries that exact edge from the switch to the already-guarded Exec
handler and its live private, stdin, and literal-nil zero-private branches. A
Prepare-only switch, dead edge, ignored result, rebound packet/context, or extra
receiver helper cannot substitute.
Lexically visible named boolean constants participate in reachability, so a
named `false` condition cannot make a textual branch authoritative; an
assignment-form call after an unconditional return is also dead.
The matching Begin and Commit handlers obtain packet/header/typed arm only from
configured Transport, bootstrap only from configured Runtime, the exact
`ServiceOperationPrepare` observation request only from that header, issued
typed-arm revision, and bootstrap generations, the matching observation only
from configured Runtime, and preparation only from configured Core's exact
`BeginPrepare(ctx, authority.prepare)` result after its immediate error/typed-nil matrix.
That exact stored owner alone receives the solely issued Commit request; its exact successful value
alone reaches the installer. The candidate also requires
`PacketTypePrepareCommit`. Dead helpers, foreign owners, globals, cross-packet
headers, and rebound Prepare/Commit requests are rejected.

The stored activation separates its immutable issuing Prepare correlation from
its current revision. It also retains the current Runtime observation time,
immutable Runtime hard horizon, current expiry, manifest/transaction digests,
and the exact current `active.` proof ID needed for Renew correlation; the
prepared and cleanup capabilities remain bound to the issuing Prepare. Initial expiry is
strictly after observed time and no later than the hard horizon. The unique
private `newServiceActiveProofID` implements the exact already-frozen label
formula; no caller supplies that ID or its digest. A live Renew handler derives
the exact `ServiceOperationRenew` observation request from the
authenticated Renew header/arm and stored boot/helper generations. Exact
`validateServiceRenewArm` rejects stale/untrusted correlation before Runtime.
The
configured Runtime observation must match all generations and the hard horizon,
advance observed time, and bound expiry to
`(observedUnixNano, hardExpiryUnixNano]`. The arm must be current revision plus
one, exceed current expiry, and carry the exact digest of the current active
proof. `newServiceRenewRequest` creates the sole exact `CoreRenewRequest`; only
a nil return from configured `s.core.Renew(ctx, request)` allows
`advancePreparedActivation` to revalidate the unchanged activation under
`state.mu` and update exactly current revision, observation time, expiry, and
replacement active-proof ID. No Renew path may write issuing correlation,
prepared or cleanup capability, generations, boot nonce, hard horizon,
manifest/binding count, or manifest and transaction identities.
After Runtime is called for that prevalidated arm, a Runtime error/panic or
malformed observation is a trusted dependency failure and revokes the active
owner. Core Renew's mutation boundary begins before its call; Core error/panic,
post-call state failure, or received-packet cleanup failure after success runs
`revokeServicePreparedActivation`. That exact reducer uses the retained issuing
Prepare request ID/identity, current activation revision/generations, and
prepared/cleanup capabilities. It never substitutes the outer Renew request ID
and never immediately repeats a retry-required Core Revoke. After a Core Renew
error or panic, Service retains the old installed revision and uses it for the
cleanup attempt; it neither guesses nor installs the attempted revision, and a
cleanup mismatch becomes sanitized stop-VM. After nil Core success and state
install, a later packet-cleanup failure uses the new current revision. Noncomplete cleanup
conservatively becomes stop-VM pending the full cleanup FSM.

The third prerequisite issues and installs only the authenticated first-seen
Exec request and in-flight dispatch owner. `serviceExecCapabilities` contains
the exact execution and cleanup capabilities; `serviceExecAuthority` contains,
in order, the exact `CoreExecRequest`, claimed `ExecPlanCapability`, revision,
helper Exec transaction, transaction correlation, and comparison bit. A
fixed-array `serviceExecPlanSink` accepts one nonempty canonical plan no larger
than `MaxHelperExecPlanBytes` and wipes its full capacity on every path.
`newServiceExecBodyIdentity` copies the claimed plan once, binds its encoded
length and SHA-256, decodes it, reconstructs the exact canonical
`HelperExecBody` from the authenticated `ReceivedExec` arm, requires the
encoded length to equal `packet.Header().BodyLength`, hashes those exact bytes,
and wipes both temporary canonical buffers.

The prerequisite resolves every qualifier from the declaration's own file:
`sha256` is the standard `crypto/sha256`, `subtle` is the standard
`crypto/subtle`, `sync` is the standard package behind `serviceState.mu`,
`credentialmemory` is the repository's exact
`internal/credentialmemory` package, and `credentialprotocol` is the exact
guest-agent protocol package. This identity also covers the
`ExecPlanCapability.CopyCanonicalTo` signature, the state mutex, and the Exec
authority, body-identity, and plan-sink declarations. Import aliases for those
exact paths are normalized through their lexical import object and are
equivalent; lookalike packages, local shadows, or bindings inherited from
another file are not.
The `CopyCanonicalTo` check follows Go signature identity: it erases only
parameter/result identifiers, preserving exact arity, order, variadic shape,
import-bound types, and the error result. Its already-frozen implementation,
single-claim provenance, and destroy behavior remain separate mandatory
checks, so naming the sink cannot broaden the accepted data flow.

`newServiceExecAuthority` accepts only an exact `PacketTypeExec` packet/arm and
the immutable active prepared snapshot. It binds request ID, identity,
revision, boot nonce, complete generations, safe Exec binding, private binding
metadata, reconstructed body identity, and claimed plan. The sole
`newServiceExecCapabilities` calls the private capability issuer for execution
kind `3` and cleanup kind `4`; only this authority issuer calls
`NewCoreExecRequest`. It then derives the exact helper transaction correlation
and begins the arm's retained transaction seed. Failure or panic before
transfer closes that seed and destroys the plan.

The live handler immediately gates the authority error, then obtains the result
of `installExecDispatch`. That installer requires
`comparison == false`, locks `state.mu`, revalidates the current prepared
revision and empty dispatch slot, and installs the exact request, plan,
revision, transaction, correlation, false comparison bit, and false taken
latch. Constructor/issuer references are declaration-bound and confined to
these functions across every supported build context; globals, caller values,
function values, wrappers, alternate constructors, dead calls, ignored errors,
unlocked writes, field substitution, and alternate-build declarations are
invalid. On installation failure, the sole panic-isolated
`closeServiceExecAuthority` closes the transferred helper transaction and
destroys the claimed plan before the installer error is returned; cleanup
failure becomes the sanitized ownership error. This prerequisite deliberately
cannot authorize comparison: it does
not implement or claim the separate fixed 4,096-entry completion/result ledger
or comparison-replay issuance.

The sole state execution install is the exact result of the sole
`Service.core.BeginExec` call after its canonical rejection gate, assigned once
under `state.mu`. Before that gate, the result and any alias are confined to the
exact configured-dependency operand: global/other-owner assignment, return,
address-taking, receiver use, helper arguments, containers/composites, and
method calls are invalid. Inspection, switch/tag use, comparison, formatting,
or any other pre-gate read is also invalid. Foreign, pre-gate, rebound, duplicate, or overwritten
values cannot become launch authority.

The canonical zero-private Exec path is separate from observed private input.
When the exact typed `ReceivedExec` arm carried by that dispatch, obtained by
the exact `arm, ok := packet.Exec()` extraction and immediate not-ok rejection,
declares the canonical zero length/all-zero
digest pair, Service takes no `ExecPrivate` packet and performs no Borrow or
observed proposal. A same-shaped or foreign owner is invalid and the comparison
branch is a direct terminal accepted result with no Core, Borrow, body,
proposal, or observed-input authority, including through helpers, method
values, aliases, callbacks, interfaces, or containers. Merely omitting a direct
`BeginExec` spelling is insufficient. The normal branch calls exact `Service.core.BeginExec` with
the state-backed request and a literal untyped `nil` view, applies the same
`coreErr != nil || !configuredDependency(execution)` matrix, and retains that
exact execution under `state.mu` only after acceptance. Typed-nil or
zero-length lookalike views and global nil-like values are invalid. Comparison
calls no Core. The existing Service structural diagnostic and
`TestServiceObservedInputsTakenOnceBeforeDispatch` cover this branch; it does
not add a disconnected ProductGuard marker.

The outer Borrow is one
direct reachable call; its returned error is bound and propagated after
cleanup, never swallowed or placed under an unreachable condition. The exact
proposal error controls a direct return before comparison, Core, or Commit.
Its proposal, comparison, Core, canonical rejection, retained execution, and
final Commit are direct callback statements, not markers hidden under a
noncontrolling branch. For private input the callback orders
one exact proposal value, Service.core.BeginExec with the scoped view, strict
nil-error/non-nil-execution return validation through the canonical
`coreErr != nil || !configuredDependency(execution)` rejection, retention of
that exact result as the sole serviceState execution, then a directly returned
Commit on that same proposal. For
stdin it orders one exact proposal and that Service-owned execution's
WriteStdin with the same scoped view and the authenticated received arm's exact
offset/EOF flag, validates the exact `coreErr != nil`
rejection, then directly returns Commit on that same proposal. Both callbacks
invoke the exact same proposal's no-result Wipe as the statement immediately
before a nonnil failure return; discarded Commit results and omitted or
non-direct Wipe calls are invalid. Across each callback there is exactly one
matching Propose call, one normal Core call, two mutually exclusive Commit call
sites, and one Wipe call; expression-statement duplicates, rebound same-named
proposal values, and any earlier or extra terminal side effect are invalid.
The total includes executable nested/IIFE closures. The guard rejects every
nested function literal in the callback, including IIFE, `defer`, `go`, and
terminal method-value forms, so hidden calls, asynchronous view use, and
closure retention cannot evade that count.
The private CoreExecution is retained only after the canonical
`coreErr != nil || !configuredDependency(execution)` rejection. Comparison's
entire branch condition
is the exact handler `comparison bool` parameter and the branch terminates by
directly returning Commit in the same callback without Core or fallthrough.
The observed-input handlers own pending proposal wipe and the received body,
not the terminal exec ledger. Their one outer recovery first lets the Borrow
callback unwind, wipes a pending proposal, and invokes the exact panic-isolated
`destroyServiceObservedBody(ctx, body)` helper. That helper recovers a body
Destroy panic and treats either panic or nonnil Destroy error as
`ErrContractOwnership`. The handler returns its Borrow/cleanup outcome; it does
not close the helper transaction, destroy the plan, cancel the retained
CoreExecution, revoke the prepared activation, or mint the final Service
result. A dispatcher with a nonnil handler outcome immediately returns
`finishExecDispatch(ctx, handlerErr)`. A successful private handler issues the
first stdin credit and enters stdin dispatch. A successful stdin handler reads
the actual transaction snapshot: non-EOF sends the next exact credit and
continues, while EOF stops stdin credit but never permits normal terminal
reduction by itself.

`dispatchStdin` is the bounded continuation coordinator. It has at most one
authenticated Receive worker, at most one stdin worker, and at most one serial
output worker. Its Receive owner routes either stdin `exec_stream` or
normal-mode stdout/stderr `exec_credit` while Core is live, including output
before stdin EOF, but never invokes blocking `WriteStdin` or `Next` inline. One
stdin `WriteStdin` may overlap one output `Next`; `Next` is never parallel with another `Next`.
At most one copy-safe credit from either output stream may be queued after its
received metadata packet has been destroyed. Offset and EOF validation occur
after the active worker publishes its ledger transition, so a causally next same-stream credit received after the prior output becomes visible remains
valid even when the local Transport `Send` has not returned. A second queued
credit is rejected. The exact Service state
adds one `sendMu sync.Mutex`. Stdin-credit, output-stream, and response owners
hold it across send-sequence reservation, packet construction, and configured
Transport `Send`; none holds `state.mu` across construction or Send. Output
headers bind the live state tuple without requiring the transient
`dispatchTaken` latch, while responses still require the terminal take. The
serial output worker likewise validates correlation, activation, and the
retained execution without consulting that per-packet latch; the coordinator
may legitimately hold it for the next authenticated continuation while the
previously authorized output worker starts. After the revision take,
each private/stdin/output-credit header must echo the installed request ID,
identity digest, and boot nonce. Comparison mode rejects output credits and
sends the completed replay response only after stdin EOF, with no Core call.
The exact coordinator owner is one `context.CancelFunc`, three capacity-one
result channels (`serviceExecReceiveResult`, stdin `serviceExecWorkResult`, and
output `serviceExecWorkResult`), three pending latches, one queued-credit latch,
and one `ReceivedExecCredit` plus `serviceExecDispatch` queued pair. The only
worker/termination helpers are `startServiceExecReceive`,
`receiveServiceExecContinuation`, `runServiceExecStdin`,
`runServiceExecOutput`, `stopServiceExecCoordinator`, and
`finishServiceExecCoordinator`. Each started worker recovers panic and sends
exactly one result; termination cancels once and joins every true pending latch
before the terminal reducer takes retained state. A joined nil-error Receive
destroys its packet and converts even a previously nil terminal cause into a
transition failure. Output-ledger EOF fields are read only after
`outputPending` is false, using the result-channel handoff as their
happens-before edge. A successful output result is valid while the overlapping
stdin transaction proposal still reports `PendingPayload`; final completion,
response construction, and terminal reduction additionally require
`stdinPending == false`, after stdin commit and deferred received-body cleanup.
Normal mode creates one output ledger from the installed execution/request/plan
and exact stdout/stderr maxima. For each authenticated output credit, the
coordinator validates kind/next offset and destroys the metadata packet before
the serial output worker enters `drainExecOutput`, mints one bounded
`CoreOutputRequest`, calls `GrantOutput`, and consumes exactly
one `Next` output event. It correlates the execution, stream, offset, capacity,
count, digest and full canonical owned body, independently hashes only the
payload, then transfers that body to one authenticated output stream packet.
An exact context precondition runs while the local ownership latch remains set.
After that precondition passes, the latch is cleared immediately before the
panic-capable packet-constructor call, whose frozen post-precondition contract
consumes or destroys the body on every outcome, so nested recovery never
destroys the transferred body twice.
Each stream advances contiguously to one empty EOF; truncation is accepted only
at its plan maximum. Only after stdin EOF and both output EOF records,
`completeServiceExecOutput` makes one final `Next`, which must return the
bodyless complete event. That event is the child-exit/reap boundary. Its input,
output and transaction summaries must equal the transaction snapshot and the
independently accumulated ledgers. Service clears the completed execution,
completes the helper transaction, sends the exact accepted response, and only
then permits closed/normal reduction. Any panic, credit/grant/event/body/send
failure, early complete, missing/duplicate EOF, correlation drift, or response
failure leaves the execution noncomplete and runs cancellation plus all other
terminal cleanup. Every returned Core output body is either transferred once or
destroyed with a checked result; Destroy failure is promoted to
`ErrContractOwnership`. Output observation installs recovery before calling
even `Len`, preserving the caller's cleanup latch, and response sending
recovers packet-constructor or Transport panic before coordinator teardown.
Stdin and plan maxima plus unique EOF events bound the
loop, which never waits for stdin EOF before servicing ready output. Every
terminal path cancels and joins all pending Receive/stdin/output workers,
checked-destroys any packet returned by the joined Receive, clears the single
queued copy-safe credit, and only then invokes `finishExecDispatch`; a worker
cannot outlive the Serve result.

The exact output digest sink retains only `hash.Hash`, the expected canonical
length, and its one-write latch. Package-wide constructor confinement permits
`NewCoreOutputRequest`, `newExecCreditPacket`, `newExecStreamPacket`, and
`newResponsePacket` only in their exact drain/continuation/send owners; an
unrelated call site cannot mint or transmit an alternate ledger edge.

`finishExecDispatch` is the sole terminal owner reducer. In one exact mutex
critical section it validates a live exec entry, copies the retained execution,
request, plan, transaction, and activation, and clears execution/request/plan/
revision/comparison while latching dispatch taken. It performs no external call
while locked. After unlock it always attempts, in order,
`closeServiceExecAuthority` (transaction Close plus claimed-plan destroy),
`cancelServiceExecution` (panic-isolated Core cancellation with exact cleanup
echo and complete/absent validation when execution is nonnil), and
`revokeServicePreparedActivation` (retained activation cleanup). A prior cause
or cleanup failure never short-circuits later attempts. Only nil cause and all
three successful cleanup outcomes yield `ServiceClosed`/`normal`; every other
case yields `ServiceStopVMRequired`/`protocol_error` plus sanitized
`ErrContractOwnership`. The retained transaction may remain only as a terminal,
non-dispatchable snapshot tombstone after it has been closed; no live authority
remains.

`continueExecDispatch` is the sole nonterminal handoff. It requires the same
live transaction/correlation/revision, private completion, no pending proposal,
no prior credit, no EOF, and matching comparison mode. It calls that
transaction's unique `GrantStdinCredit`, revalidates the ledger under the
Service mutex, reserves the send sequence, clears the take latch, constructs
the exact authenticated credit packet through the unique issuer, and calls the
configured Transport `Send`. Panic, drift, construction failure, or send
failure terminal-reduces the installed owners.

Continuation request issuance and Receive failure, wrong arm, failed take, and
handler error/panic reduction converge on the reducer. Wrong-arm and failed-
take packets are destroyed before reduction. The initial Exec wrong-arm and
authority-error paths destroy the packet before returning; install failure
closes the not-installed authority and destroys that packet. Landed metadata
packet constructors already destroy their received body and return nil
body/right fields; exact cleanup treats those nil fields as already clean while
still destroying/closing every configured nonnil field once with panic/error
reduction. Cleanup after ledger installation is checked and converges on the
reducer on failure. The
zero-private branch installs one named
result recovery that always destroys its received packet and reduces panic or
cleanup failure to stop-VM/ownership. Invalid arm/binding, Core error, and
invalid Core return terminal-reduce. Valid comparison or Core success issues
the first stdin credit and enters the same stdin loop; zero-private never
directly destroys the plan. The comparison branch calls no Core. Successful
normal completion requires stdin EOF, both output EOF records, the correlated
complete event, transaction completion, and response send. Missing, duplicate,
discarded, disconnected,
pre-gate, callback-local, or short-circuit cleanup is rejected. Source guards
bind both concrete Borrow-callback orders, every live dispatch exit, the
zero-private result matrix, and the terminal cleanup order. Tests cover normal,
comparison, failure, typed-nil, continuation failure, cancellation, panic,
body destruction, and exactly-once plan/transaction/execution/activation
cleanup rather than accepting disconnected call markers.

`newServiceResult` is a package-wide unique private declaration with the exact
landed `service_values.go` signature and body. It cannot be a variable, alias,
alternate-build duplicate, or lookalike. It validates disposition and close
reason first, enforces exactly the closed/normal-or-shutdown and
stop-VM/protocol-error-or-identity-drift-or-expired-or-helper-loss matrix, and
mints only those exact private fields. Recovery and body-destroy failure use
that same unshadowed issuer, so the terminal reduction is authority-bound and
not merely name-shaped.
The reducer is selected in every supported Service build context—Linux,
Darwin, FreeBSD, and Windows on amd64 with the repository's default non-cgo
tags—and remains unique across all parsed tagged files. A platform-only issuer
cannot stand in for a context where Service also builds.

The thirteen named Service behavioral tests are structural evidence in the exact
`credentialhelper` package rather than declarations alone. Each unique exact
`func TestX(t *testing.T)` has one
unconditionally live `NewService` construction, invokes `Serve` on that exact
never-rebound returned Service without `go` or `defer`, and subsequently asserts its test-specific observable via a
live `Fatal`/`Fatalf`/`Error`/`Errorf` condition containing that exact
fake-field selector; a same-named local constant is not evidence. The
observable catalog is:
plan destruction across success, invalid Core, panic, stdin failure, and
multi-record output through actual plan state and `planDestroyCalls`; causal
same-stream credit after peer-visible output; Receive error/panic convergence
for preparing, prepared, and installed Exec; constructor/one-shot
`dependencyCalls,ownedSnapshotEntries,serveCalls`; context precedence
`dependencyCalls,serveCalls`; input take `takeCalls`; private lifecycle
`beginExecCalls,commitCalls,bodyDestroyCalls,planDestroyCalls`; valid private
Core gate `beginExecCalls,commitCalls,wipeCalls`; stdin lifecycle
`writeStdinCalls,commitCalls,bodyDestroyCalls`; nil-error stdin gate
`writeStdinCalls,commitCalls,wipeCalls`; comparison
`beginExecCalls,writeStdinCalls,commitCalls`; body ownership
`bodyDestroyCalls`; and exhaustive failure/panic cleanup
`wipeCalls,bodyDestroyCalls,planDestroyCalls`. Empty/no-op, skip/Goexit,
early-return, dead/comment/string-only, shadow/foreign-boundary, pre-exercise
assertion, and assertion-free substitutes do not satisfy the evidence.
The credited mismatch body is exactly one direct call to the original
unshadowed `t` owner's `Fatal`, `Fatalf`, `Error`, or `Errorf`; a preceding
return, skip, Goexit, panic, helper, deferred/goroutine call, or other statement
makes the assertion non-evidence; a terminal helper evaluated as a failure
argument is rejected too, even when a failure call remains textually present.
Credited failure arguments contain no `CallExpr`, function literal, or channel
receive; the canonical literal, identifier, and selector forms needed by the
required tests remain valid. This conservative grammar closes package-global,
closure-aliased, and channel-transported terminal callables without inventing
a second provenance graph for test messages.
Each required test is itself selected and runnable in every supported build
context where Service is selected. Its NewService and Serve operations are one
direct, unconditionally live top-level path: short-circuiting, conditionals,
loops, switches, selects, goroutines, defers, or a package-helper chain that
terminates through the real `testing.T` or `runtime` boundary cannot supply the
exercise. The returned Service local stays single-assignment and cannot escape
through addressing, return, send, closure, interface/container storage, helper
argument, conversion, or method value before its exact direct Serve receiver
use.

The same direct-live topology governs the original direct-Serve tests. The
claimed-plan, causal-credit, and Receive-convergence tests instead use their
exact table/channel/state-backed causal matrices. The comparison no-Core test
constructs one real Service, one completed normal transaction, and the exact
comparison transaction, directly invokes the private and stdin handlers with
comparison true, replays the cached result, and asserts both Core counters
remain zero; normal Serve cannot substitute for that comparison evidence.
Pre-NewService setup is restricted to direct assignments and
value/constant declarations with no call, function literal, or channel receive,
apart from exact unshadowed predeclared `int(raw-integer-literal)` conversion.
Only the matching `if err != nil { t.Fatal(err) }` constructor-error gate may
stand between NewService and Serve. Between Serve and the last credited
evidence, only its matching captured-error gate and the credited top-level
assertion clauses may appear. Thus a runtime-true but analyzer-unknown
conditional return before construction, between construction and Serve, or
before fake or Service-owned evidence cannot yield a vacuous pass. Supplemental
tables are valid only after the direct credited evidence. Credited evidence
conditions contain no `CallExpr`, function literal, or channel receive;
non-exercise result fields and inert table data may be inspected afterward,
but the supplemental tail is recursively call-free and cannot invoke an
accessor, helper, constructor, deferred call, goroutine, or channel operation. Credited assertions
have nil `Init` and nil
`Else`, so an alternate return, skip, Goexit, panic, or other terminal branch
cannot bypass the remaining clauses of a multi-evidence test. The supplemental
tail is exercise-data-only: it contains no occurrence of the returned Service
owner, no function literal, call expression, send, or receive, and no `NewService` identifier.
The exact constructor `CallExpr.Fun` is the sole `NewService` identifier across
the whole test, excluding prebound aliases and package-helper construction.
Exact one-construction/one-Serve therefore holds across the complete test, not
merely through the last evidence clause. Supplemental `range` accepts only a
provably inert direct string/integer/array/slice/map value or a local
single-assignment alias recursively initialized from one. Channel, function,
unknown, and reassigned operands are rejected, closing implicit receive and
range-over-function invocation while preserving inert table loops. Range
key/value bindings invalidate same-named inert provenance and never become an
inert nested-range operand. The proof follows lexical blocks sequentially, so a
nested block may declare and then range over its own inert single-assignment
table without inheriting or leaking a shadowed name. Provenance is keyed by the
parser's exact lexical object, not identifier spelling. Assignment-form control
initializers, labeled assignments, loop post statements, and increment or
decrement are writes; any second write kills inert provenance across every
reachable child scope. Parentheses cannot hide a write, and the supplemental
tail rejects address-taking so an indirect pointer write cannot bypass the
single-assignment proof.

Except for the Service-owned snapshot count called out below, observable
evidence is causal: its fake owner is initialized before and reaches NewService
through the exact options/dependency value graph, remains
single-assignment, begins at canonical zero, and the test never writes the
observed field directly or through an alias, pointer, container, or arbitrary
helper call. Range key/value transport through arrays, slices, maps, or nested
containers, channel send/receive round-trips, package-global storage, and all
subsequent aliases remain in that causal graph or are rejected conservatively;
unrelated range/table structure remains permitted. A nonzero/positional seed
or helper-issued fake is invalid. After
Serve, one exact unmasked `observed != expected` clause compares the tracked
selector with an independently defined integer literal or immutable constant
whose `ValueSpec.Type` is explicitly the exact predeclared `int`, fixed before
NewService, and initialized only by an integer literal or
`int(integer-literal)` in the raw AST; parenthesized initializers do not count.
Any active package declaration named `int`, or explicit/default file import
binding named `int`, invalidates this named grammar in that supported build
context. Dot imports remain valid because Go exposes only exported identifiers
through them and therefore cannot introduce lowercase `int`. Default import
bindings use the actual build-context package declaration, with deterministic
module-local active-production-source resolution, rather than the path
basename. Test files and external test-package variants cannot define an
imported binding. A bounded analysis-local positive-only offline `go list`
resolves the effective module graph for local replacements, vendor mode, and
present module-cache dependencies. It uses readonly module mode (or vendor for
an existing vendor manifest), exact GOOS/GOARCH, `CGO_ENABLED=0`,
`GO111MODULE=on`, `GOENV=off`, empty `GOFLAGS`, `GOWORK=off`, `GOPROXY=off`,
`GOSUMDB=off`, empty `GOPRIVATE`/`GOINSECURE`, `GONOPROXY=none`,
`GONOSUMDB=none`, `GOVCS=*:off`, and `GOTOOLCHAIN=local`; inherited duplicates
are removed before those single values are installed. Source and module-root
directories are absolute, clean, and symlink-canonical before discovery and
execution. Broken/cyclic links fail unresolved, and module-local fallback
paths cannot escape the canonical module root. The resolver never writes
module metadata, reaches direct/vanity or network resolution, caches a
timeout/error, or reuses cache state across an analyzer invocation/source
mutation; module-local parsing is fallback only. An
unresolved unrelated import is not a shadow. Package-level
constants are definitionally pre-construction independent of file padding or
order. Function-local constants must be in the same function and structurally
precede NewService; positions from separately parsed files are not ordered.
Untyped constants, aliases, other integer/numeric or string types, and values
derived through another name do not count. The
constant cannot derive from the fake. Named-constant/conversion evaluation
rejects constant-false conjunctions,
constant-true disjunctions, equality/inverted polarity, and other vacuous
conditions. That clause drives `Fatal`, `Fatalf`, `Error`, or `Errorf` on the
original unshadowed `t`. Foreign selectors, self-comparisons, indirect expected
values, manual writes, pre-exercise comparisons, and rebound/fake test owners
fail.

`ownedSnapshotEntries` is deliberately not a fake-field counter. It is the
exact live post-Serve check
`len(service.extensions) != positiveExpected` on the sole Service owner
returned by the test's exact `NewService` call, using the same canonical
integer-literal or explicit `int` constant grammar. `len` is the exact
unshadowed predeclared builtin across the test file, package, and every
applicable build context; local, file-import, or cross-file package
declarations named `len` invalidate the evidence. Caller-registry counters,
`len(registry.entries)`, foreign or rebound Service owners, zero expected
counts, and pre-Serve checks are invalid. Outside the exact direct Serve
call recorded as the one required exercise and this one length check, the
Service owner and its `extensions` selector cannot be used: an additional
expression, deferred, goroutine, or indirect Serve call, direct or aliased
replacement, append, index/field mutation, helper passing, or any other
test-authored snapshot change is invalid. The runtime count observation is
on a direct top-level path and immediately follows the Serve assignment. The
sole permitted intervening statement is the exact
`if serveErr != nil { t.Fatal(serveErr) }` gate for the non-blank error captured
from that same Serve call. In the constructor/one-shot test the snapshot is the
first credited statement; no fake-field assertion may intervene. Any other
assignment, call, conditional, return, loop, switch, select, defer, or goroutine
invalidates the observation, closing runtime-true but analyzer-unknown early
exits. Pre-NewService setup is limited
to direct assignments and value/constant declarations with no call, function
literal, or channel-receive expression. Between the exact NewService assignment
and Serve, its matching captured-error gate
`if err != nil { t.Fatal(err) }` is required. Tests crediting `commitCalls` or
`wipeCalls` then perform exactly one direct `transport.service = service`
assignment. That exact Transport already feeds `ServiceOptions.Transport`; the
test-only link permits read-only observation of the installed transaction and
no other Service escape. Thus control flow before
construction, between construction and Serve, and before evidence cannot turn
the test into a vacuous pass. It is paired with the production AST proof that
`snapshotServiceExtensionEntries` allocates a distinct slice, deep-clones
descriptors, and preserves order and factory identity. It never requires or permits mutation or instrumentation
of the caller-owned immutable `ExtensionRegistry`.

The observable binds to its exact Go-checked `ServiceOptions` dependency field
and to the transition that actually causes it. Core owns
`beginExecCalls,writeStdinCalls,planDestroyCalls`; Transport owns
`takeCalls,commitCalls,bodyDestroyCalls`; `wipeCalls` is Transport-owned for a
verified failed proposal transition and Core-owned for the recovered-panic
cleanup path. Before the embedded exact `transportTestBody.Borrow`, the exact
test body reads the real installed transaction from the bound Service under
its mutex, retains that pointer for panic observation, snapshots it, and
snapshots the exact Core counters. After Borrow returns it snapshots the same
transaction again. `commitCalls` requires a nil Borrow result, the exact
private-complete or stdin-record transition, and the matching one-call Core
delta (or zero Core delta in comparison mode). Normal `wipeCalls` requires a
nonnil result, a real nonterminal-to-terminal transition, and the matching
one-call Core delta. The embedded callback still receives the actual retained
region and is invoked exactly once. Exact Core revoke may increment
`planDestroyCalls` only after reading the scenario's actual plan `destroyed`
state, and may increment the panic `wipeCalls` only when the retained real
transaction is terminal, the panic mode is exact, and the Core call occurred.
Skipped callbacks, synthesized errors or snapshots, a foreign transaction,
missing exact Service observer binding, constant Core delta or plan state, and
unrelated counters do not satisfy the observable. Extensions
is proven through the Service-owned `ownedSnapshotEntries` rule above; the five
configured live fields may own their own
`dependencyCalls`; and Transport or Runtime owns `serveCalls`. Recursive
occurrence in an unrelated field or container is not provenance. A
supplemental table may follow the direct exercise but is never its substitute.
Seeded negative AST fixtures reject unrelated names and suffix-lookalike scoped
types, background-context substitution, proposal-variable substitution or
ignored proposal/Borrow results, noncontrolling and AND Core gates, wrong Core
or foreign
execution receivers, local-lookalike comparison values, comparison fallthrough,
any Core call in the comparison branch, retention before validation, extra
Propose/Core/Commit/Wipe calls, and direct or aliased method access that lets
the private service state reset or escape.

The Service proof is evaluated as one combined construction, one-shot,
reachability, and state-stability graph. A canonical combined fixture must pass
with both the exact returned private dispatcher/handler path and the exact
returned stdin dispatcher/handler path live under the claimed Serve lifetime.
Only those argument-bound returned `CallExpr` edges are trusted and recursively
inspected. Unknown returned Service calls, returned method values, dead,
discarded, or nonpropagated calls, receiver escape, and unknown Service/state
methods fail the complete graph; a state-stability scan cannot reject the very
validated edge on which the required Service wiring depends.

The scoped no-retention proof spans `credentialprotocol` and
`credentialhelper` and includes ordinary call dataflow. It propagates
`BorrowedView`/`CredentialSink` aliases through private helper parameters and
rejects global storage and closure/container/channel/interface returns. Exact
synchronous consumers are structurally allowlisted; arbitrary function,
method, interface, variadic/generic, function-value, deferred, and goroutine
calls remain escapes. The allowlist covers only the frozen view/sink methods,
body Borrow scope, observed/Core consumers, and already audited transport
forwarding/validation helpers, never a name-only lookalike.
Taking a scoped view/sink method without invoking it immediately creates a
bound method value which carries the receiver capability. That value is always
an escape when assigned, stored in a field/container/interface, returned, or
passed to a call; there is no bound-method exception to the direct synchronous
consumer rule.
Reflection, custom/generic identity helpers, interface conversions, containers,
and nested wrapper calls do not declassify a bound scoped method. Their results
remain tainted; `reflect.ValueOf` has no exception. Only an exact audited
nonretaining consumer invoked directly and returning no storable scoped value
can terminate the taint.
The expression graph includes ordinary and full slices, parentheses, indexes
and generic indexes, assertions/conversions, pointer/unary/binary operations,
key/value composites, containers, and nested calls. None declassifies scoped
authority.
Every direct nonretaining method call is bound to the exact imported
`credentialmemory` interface receiver, declared signature, argument positions,
and result behavior. Embedded, promoted, generic, alias-import, or user-defined
lookalikes do not qualify. `reflect.ValueOf` of a bound method is always
tainted. A raw scoped interface is accepted only as the transient operand of
the exact confined typed-nil helper, whose result cannot escape; it is not a
general declassification rule.
The exception is tied to one unique exact helper body, not its name or
signature: after the plain-nil return, a sole local `reflect.ValueOf` feeds only
the exact six-kind `Kind` switch and `IsNil` return. Storage, containers,
helper calls, returns of the reflected value, extra calls, or side effects
invalidate the helper package-wide.

Each constant-time gate also dominates the exact issued authority. From the
constructor comparison to the returned observation-owner literal, and from
the admission correlation/digest gates to the installed and returned observed
proposal owner, all checked parameters, transaction-owner fields,
observation-owner fields, and derived digest are immutable. Assignment,
inc/dec, shadowing, pointer/alias or closure mutation, owner-field mutation,
alternate composite construction, and a self-check followed by foreign issue
are rejected. The returned observation fields and the proposal's exact
transaction/source/kind/observation metadata/candidate state/`observedReady`
must be the checked values, and the same proposal owner must be installed as
the transaction's pending value and returned.
Correlation and digest inputs are protected independently from their own
successful gates. The proposal owner must be constructed after both gates,
remain immutable, be installed by one live dominating pending assignment, and
be returned without overwrite. Stdin candidate hash/counter/EOF provenance is
bound to the same checked view, current transaction owner, and observation;
arbitrary helper calls receiving any protected value are mutation authority,
not pure uses.
The alias graph is built before each gate and recursively follows pointers,
struct fields, arrays, slices, maps, indexes, interfaces, composites, and
further aliases. A pre-gate container holding an operand pointer remains
protected after the gate, so mutation through a nested selector/dereference or
by passing that container to a helper invalidates issuance. The exact pending
install is the direct statement immediately before the unique live success.
Any earlier unconditional return, panic, `runtime.Goexit`, constant-true
terminal branch, infinite loop, empty select, or equivalent terminal statement
makes a later textual success dead and invalid.
The pre-gate graph also tracks closures and callable aliases that capture a
protected root. Invoking or escaping such a callable after the root's gate is
mutation authority even through an interface, wrapper, or container and even
when the invocation has no arguments. Terminal aliases and wrappers of
`panic`, `runtime.Goexit`, `Exit`, `Fatal`, or `FailNow`, terminal IIFEs, and
nested terminal closures are resolved conservatively so their dead successor
cannot satisfy the live-success proof.
Callable-mutator taint traverses the same complete slice/index/map/struct/
interface/generic/composite/call expression graph. Terminal analysis reaches a
package fixed point across private helper chains and exact recursive no-return
cycles, not just local aliases. It also evaluates exact safe compile-time
literal, unary, logical, and basic-literal comparison conditions, so a constant
terminal branch cannot precede an apparently successful issuance.
The two stdin hash-state helpers are pure only at their exact package
declarations and exact operand-bound `ProposeObservedStdin` call sites; shadowed
locals, parameters, dot/alias imports, function values, and wrappers remain
tainted, and their arguments are always traversed first. Terminal analysis keys
all declarations by exact package/import and receiver-type identity, includes
receiver methods and terminal-callable factories, and conservatively unions
duplicate build-tag declarations independent of parse order. It never treats a
`Goexit`, `Exit`, `Fatal`, or `FailNow` suffix or a lookalike import as terminal
authority by name alone.
The terminal fixed point additionally derives exact parameter-position
summaries for wrapper functions and methods: a terminal callable passed through
one or more ordinary, generic, or interface wrapper calls makes the call
nonreturning only when the matching parameter is invoked unconditionally on
the live callee path. Reordered parameters are bound by position; unused and
conditional callable parameters remain returning paths.
Those summaries retain their exact qualified wrapper identity through local
assignment/reassignment, parentheses, interfaces and type assertions,
slices/maps/structs/generic composites and indexes, helper-returned wrapper
factories, and exact receiver method values. Invocation resolves the complete
alias/factory identity set before applying parameter positions. Resolution is
flow-sensitive to declarations and assignments preceding that invocation and
tracks exact identifier, selector, pointer/nested-field, and array/slice/map
index storage locations plus aliases of their containing storage. Static fields
and constant indexes remain separate; dynamic indexes and unresolved pointer
aliases union possible locations conservatively, while containing aliases
translate descendant paths without contaminating sibling paths. Constant
indexes use an import-safe canonical constant evaluator, so equivalent
interpreted/raw strings, rune/integer spellings, safe unary/binary expressions,
typed constants, and declared package/local constants including `iota` share
one canonical representable identity while unequal constants remain siblings.
Resolution is lexical and position-aware: parameters, results, and dynamic local
bindings shadow package constants instead of inheriting their values, and
numerically equal representable forms such as `1` and `1.0` share an identity.
Exactly representable modeled built-in constant conversions are evaluated without executing code, and
forward package constants reach an order-independent fixed point. Map keys are
canonicalized after conversion to their exact statically resolved key type,
including floating-point precision rounding and integer range/overflow
rejection. The type graph follows local/package named maps, generic named
instantiations, variable aliases, exact receiver-method and local helper/closure
sole result types, interface assertions, and pointer-to-map normalization.
Value and type-name resolution is lexical, position-aware, and follows Go
scope. Function and closure parameters/results, sequential block and
case/communication-clause declarations, `if`/`for`/`switch` initializers,
range key/value declarations, type-switch arm declarations, and select receive
declarations shadow an outer package type only inside their exact scope. A type
declaration in a nested active scope can re-establish the type name there; an
ended control or clause scope and a sibling scope cannot shadow it. Ambiguous
or external identities remain dynamic.
Indexed storage with an unresolved or merely suspected map key type is always
wildcarded rather than exact-canonicalized as an untyped constant; known arrays
and slices retain exact constant integer indexes. Unresolved/illegal conversions and
arbitrary-magnitude integer-to-string conversions not exactly modeled also
remain dynamic and conservatively union possible keys rather than minting a
false distinct identity.
Wildcard ambiguity matches each nested selector/index segment, so a dynamic
parent index conservatively aliases an exact descendant without contaminating a
statically distinct sibling. Recursive containing aliases use a finite symbolic
path graph bounded by syntactically observable storage paths: cycles close
without unbounded string expansion, and every used nested descendant remains
reachable. Selector/index subpaths and pointer-normalized nested paths may
themselves be containing aliases. A later
assignment does not retroactively define an earlier call. Named or anonymous
closure factories, their aliases, IIFEs, nested factories, and cyclic
alias/factory chains participate in the same fixed point. Alternate
build-context declarations and preceding ambiguous reassignments are unioned
conservatively—any terminal identity makes the successor dead—while aliases of
unused or conditional wrappers remain valid returning paths.
The same reachability proof detects unconditional no-return calls in every
synchronously evaluated expression: assignment/declaration values, nested call
arguments, composites and indexes, returns and sends, plus control-statement
initializers and conditions. It also follows synchronous switch-case
expressions, type-switch assignments, and select communication channel/send
operands in execution order without treating conditional clause bodies as
unconditional. Every expression-switch case expression remains source-ordered
even when `default` appears earlier, because default selection occurs only after
case-expression evaluation. Select entry evaluates receive channels and send
channels/values; receive-assignment destinations are evaluated only after their
clause is selected and are not unconditional entry expressions. Tagless-switch
conditions use the same lexical constant environment, so named false constants
continue to later cases while unknown conditions stay conservative. It does not execute an uncalled function-literal
body, a deferred call body, or a new goroutine body; `defer` and `go` still
evaluate their callee and arguments synchronously.
The stdin clone and sink exceptions likewise require one unique exact package
implementation across build variants. The clone nil-checks, value-copies the
entire wipeable hash owner, and returns only the fresh address. The sink
constructor performs one return of a fresh sink initialized only from the exact
stdin/transcript candidate parameters. Input aliasing/retention, global or
scoped retention, helper calls, side effects, alternate composites, or duplicate
declarations invalidate the exception before any caller is analyzed.

After the accepted transport constructor transfers an exec packet, Service
destroys the claimed plan exactly once on every dispatch path: directly after
normal `Core.BeginExec` returns or panics; after comparison seed/cache
validation and before response; and before any return, response, or drain on
policy, cache, observation, cancellation, pre-Core denial, error, or panic.
Cleanup never depends on Core having been invoked.

**D2 Service-readiness bootstrap closure.** The shared leaf authority is
`credentialprotocol.ComputeCanonicalHelperBootstrapSHA256(header,
canonicalBody)`. It accepts already-validated canonical safe metadata,
requires bootstrap type, sequence zero, exact canonical header semantics and
body length, retains no input, and hashes exactly
`opaque16("hal/l8/guest-helper/bootstrap/v1") || canonicalHeader ||
canonicalBody`. `l8composition.ComputeHelperBootstrapSHA256` keeps its current
public types and semantic validation and delegates only this final digest step.
The received helper bootstrap constructor independently validates its scalar
arguments and exact body, delegates to the same primitive, and stores the
result in the final private `ReceivedBootstrap.bootstrapSHA256` field. No
caller-supplied digest is accepted and no dependency cycle is introduced.

Implementation merge ordering is satisfied by this phase head. The
transport-context correction is already present: all `Received*` constructors take the leading
`context.Context`, receive/send ownership and failure cleanup use that supplied
context, and `ReceivedPrepareBegin.transaction` plus
`ReceivedExec.transactionSeed` are present. The observation, bootstrap, and
Service-readiness implementation may turn the remaining D2 product guard green
only while preserving that accepted transport surface.

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

PID1 starts with exactly the six launch capabilities above in bounding,
permitted, and effective sets. PID1 inheritable and ambient sets are exactly the same six bits
so the four image-profile-pinned nonprivileged service execs receive only the
transition authority the native role bootstrap must reduce before each Go
service starts. The credential controller starts with bounding, permitted,
effective, inheritable, and ambient capability sets already empty and verifies
that state before serving.
The mount monitor retains only `CAP_SYS_ADMIN|CAP_CHOWN` until it has normally
unmounted and inspected absence, then monitor exits the entire process so no
runtime thread or capability survives. The workload shim temporarily inherits
the six-bit transition set only in its single-threaded native stage because
Linux mount-namespace `setns` requires both `CAP_SYS_ADMIN` and
`CAP_SYS_CHROOT`. Immediately after native namespace entry it drops to exactly
`CAP_SETUID|CAP_SETGID|CAP_SETPCAP` before starting Go; before workload exec the
caller has empty capability sets, no supplementary groups, UID/GID 1000, and
`no_new_privs`. Its final single-thread transition drops the caller's
bounding/capability state;
successful `execveat` atomically destroys every other Go runtime thread, while
failure uses `exit_group` before any retry or success claim.
Every privileged role inherits locked-on `SECBIT_NOROOT` and
`SECBIT_NO_CAP_AMBIENT_RAISE`. `SECBIT_KEEP_CAPS` is unset and locked off.
`SECBIT_NO_SETUID_FIXUP` is unset and locked off so agent/workload UID changes
perform normal kernel capability clearing. PID1 raises no ambient bit after
that lock; each child clears ambient state during bootstrap, and no child can
restore it before accepting input.

D2 represents each role as an exact syscall-and-argument policy. The steady
controller has no `clone3`, `setns`, mount API, cgroup mutation, or workload
exec authority. Only the PID1 supervisor starts image-pinned monitors and shims
and manages cgroup placement/kill/reap. Only the monitor mutates its current
mount namespace and creates the optional fixed-path `AF_UNIX` endpoint. Only
the single-threaded native workload-shim stage uses the exact validated
namespace descriptor; its Go target drops identity/capability, stacks the
workload policy, and executes the pinned workload FD. Network/VSOCK authority is
limited to native PID1's exact fixed-listener creation, the steady agent's
acceptance on those inherited listeners, D5's fixed Unix relay, and the final
L4/L7 workload policy; every other role rejects it. Every role rejects
unrestricted path opens, device/module/keyring operations,
`ptrace`, `process_vm_*`, `pidfd_getfd`, `kcmp`, perf, and BPF.

Contained file lookup starts beneath a reinspected monitor-owned dirfd and uses
`openat2` with beneath, no-symlink, no-magic-link, and no-cross-mount
resolution. The sole namespace-handle exception is the monitor's compiled
`self/ns/mnt` lookup relative to `verified_proc_root_fd` with exact
`O_RDONLY|O_CLOEXEC`, mode zero, `.resolve = 0`, and the v0 `open_how` size.
It occurs before monitor protocol input and is immediately correlated to its
pidfd/credentials and reinspected for `NSFS_MAGIC`,
`NS_GET_NSTYPE == CLONE_NEWNS`, expected device/inode, and inequality from the
supervisor namespace. Seccomp is not claimed to inspect pathname strings;
compiled constants, fixed dirfds, closed protocols, and FD reinspection provide
the path boundary.

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

1. asks the PID1 launch supervisor to create the cgroup-v2 leaf and an
   image-pinned per-job mount monitor with exact pinned `syscall.ForkExec`
   `CLONE_VFORK|CLONE_VM|CLONE_NEWNS|CLONE_PIDFD` plus `SIGCHLD`;
2. requires the monitor to open and return its exact namespace handle under the
   namespace exception above, make propagation private, and retain only
   `CAP_SYS_ADMIN|CAP_CHOWN`;
3. has that monitor mount a bounded tmpfs with
   `nodev,nosuid,noexec,mode=0711` at the one fixed job target in its current
   namespace; the tmpfs root is root-owned mode-`0711`, searchable but neither
   listable nor writable by UID 1000;
4. sends credential bodies directly from controller-owned locked buffers to the
   authenticated monitor endpoint, never through PID1;
5. has the monitor create every traversed generation/nested directory root-owned
   mode-`0711` and open every contained component with beneath, no-symlink,
   no-magic-link, and no-cross-mount resolution;
6. has the monitor write regular mode-`0600`, single-link files owned by the
   fixed workload identity from mutable buffers; and
7. for D5 on the pinned Linux 6.1.178 guest kernel, has the monitor complete all
   directory and regular-file creation, make a one-way `umask(0177)` transition,
   perform the sole D5 bind at mode `0600`, and then change the sealed socket
   leaf to fixed UID/GID 1000 ownership last through exact contained
   parent-FD-relative `fchownat(..., AT_SYMLINK_NOFOLLOW)`; and
8. atomically publishes and reinspects mount type/options, device boundary,
   ownership, mode, linkage, file count, cgroup, monitor, and generation
   identity before PID1 accepts a launch.

Caller paths must be canonical relative names from a sealed binding schema.
Absolute paths, `..`, empty components, alternate separators, symlinks,
hardlinks, devices, FIFOs, sockets, caller-selected mount flags, and existing
unexpected entries fail closed.

Renewal never replaces files while a process may hold an old descriptor. L8
locks the simpler contract: renew only extends the activation lease; rotating
file content requires the current job cgroup to reach zero population (or the
microVM to be stopped) and a new credential generation to prepare before
another exec.

Every credential-aware v2 exec enters through the controller and exact PID1
launch supervisor. PID1 starts only immutable `hal-guest-role-bootstrap` in
shim mode with pinned Go 1.25.7 `SysProcAttr.Cloneflags=0`, `UseCgroupFD=true`, exact
`CgroupFD=9`, and a non-nil `PidFD`. The resulting kernel `clone3` requires
`CLONE_VFORK|CLONE_VM|CLONE_PIDFD|CLONE_INTO_CGROUP` plus `SIGCHLD` against the
revalidated exact cgroup FD before the shim runs. There is no successful
spawn-then-write-`cgroup.procs` fallback.
Before any Go thread exists, the native shim enters the exact monitor namespace,
closes that namespace FD, and reduces its six capabilities to the three needed
for the later identity drop. The Go shim then reads the bounded controller-to-
shim launch block but remains behind the supervisor-owned start gate. After
release it sets UID/GID 1000 with no supplementary groups, clears every
capability, applies `no_new_privs` and the verified
`WorkloadSnapshot`-derived filter, then uses
pinned-FD `execveat` under the existing bounded stdin/stdout/stderr supervision
contract. Direct unprivileged-agent or steady-controller exec cannot join a
credential namespace. Job/process/file/FD/count/byte/time limits are
fixed at construction and charged before allocation: one active credential
job, one pending prepare transaction, one mount namespace/cgroup/monitor, one
outstanding helper request, exactly one active credential-aware workload
execution beneath the separate generic L4 ceiling of 64, 4096 launches over
the activation lifetime, 256 helper-owned file
descriptors, 16 bindings/files, and the byte limits above. The monitor and helper
job state cannot outlive the 35-minute guest activation. Credential-aware v2
execution admits exactly one populated workload at a time; the generic L4
ceiling of 64 processes remains a separate non-credential workload bound and
does not widen this job. Guest cleanup gets at
most three idempotent attempts within one 30-second total deadline before
`stop_vm_required`; retry clocks and observations are injected in D2 tests.

Revoke first makes the controller deny new exec and accepts. It sends HL8L
`terminate_job`; PID1 writes `1` to the exact job cgroup's `cgroup.kill`, waits
for `cgroup.events` to report `populated 0`, and reaps every workload
shim/leader. After correlated `job_terminated`, the controller closes pipes and
wipes private buffers. The controller closes the published listener plus every
accepted connection, and drives direct HL8M `revoke`/cleanup through the
controller-owned monitor endpoint. The still-capable monitor unlinks files and
the socket entry, normally unmounts in its current namespace, inspects
mount/file absence, returns
`cleanup_complete`, and only then calls `exit_group`. The controller receives
that result, commits bilateral normal HL8M close, observes monitor exit, and
closes its direct endpoint and namespace duplicate. Only then may it send HL8L
`destroy_job`. PID1 never contacts the monitor during destroy; it uses its
monitor pidfd to confirm/reap exit, performs any still-needed cgroup kill/zero
check, removes the PID1-owned directory and cgroup, and reinspects absence
before returning `job_destroyed`.
Process-group termination alone is never L8 cleanup proof because a descendant
can call `setsid` or `setpgid`. If cgroup creation, race-free placement,
`cgroup.kill`, zero-population inspection, normal unmount, or monitor inspection
is unavailable, cleanup stops and reaps the entire microVM; without that proof
the result is `credential_cleanup_incomplete`.
Lazy unmount is not successful cleanup proof.

The guest/helper cleanup result is exactly one of `cleanup_complete`,
`retry_required`, or `stop_vm_required`. A retry for the same identity and
revision is idempotent and resumes from reinspection rather than recreating a
resource. `cleanup_complete` requires every ordered absence check above.
`retry_required` means owned guest cleanup can still be retried within its
bounded deadline. `stop_vm_required` is emitted for lost helper, supervisor, or
monitor identity,
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
accepts the guest Unix socket inside the job mount namespace. The guest relay accepts exact UID/GID 1000
only after exact-size `getsockopt(SOL_SOCKET, SO_PEERCRED)` proof on each
connected FD; peer PID is positive ephemeral check metadata, never durable
identity. It passes the accepted FD plus exact job identity to the dedicated-UID
guest agent over authenticated `SCM_RIGHTS` and closes its duplicate. The agent pumps only
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
validated seed to bind `JobCredentialRuntimeRecoveryBinding`, calls its
`StopReapJobCredentialRuntime`, and validates the returned exact runtime-
absence proof before calling `FinalizeJobCredentialRuntimeRecovery`. After
finalize durably records the tombstone, the worker durably clears credential
state and calls `CommitJobCredentialRuntimeRecovery`; only commit may retire
the owner record. A job with a complete identity binds through the
same seed and calls `RecoverJobCredentials`; failure to reauthenticate or
produce valid absence proof is retained as cleanup uncertainty. Success or
failure then invokes the same mandatory seed-bound stop/reap, validate,
finalize, durable-clear, and commit order; any uncertainty
quarantines the exact runtime. Process termination and L7 cleanup are proved
before credential state clears, and durable clear is acknowledged before the
owner tombstone can be retired.

## L8 guest asset profile

Guest protocol v2, tmpfs namespaces, and the guest relay are production guest
behavior and must exist in the immutable booted image. L8 therefore emits a
distinct reproducible guest profile and descriptor. It does not rewrite the L5
or L7 distributions, descriptors, or digests into a new capability claim.
Its manifest and provenance both declare exact protocol `guest-agent-v2` and
the ordered feature catalog `copy_in`, `copy_out`, `credential_delivery_v2`,
`exec`, `readiness`, `ssh_agent_relay_v1`; the L5/L7 v1 validator and bytes
remain unchanged.

The extension-seam supplement's “L8 D2 image-profile concrete closure” is the
normative API/schema definition. In particular, an L8 profile carries separate
private descriptor and evidence fingerprints. The evidence fingerprint binds
the exact seven-file L8 bundle, typed manifest/provenance/source-lock/final-
inspection correlation, explicit parent L7 evidence fingerprint, and the
helper/client/composition plus the exact ordered
`WorkloadSnapshotSHA256`, `RuntimeProfileSHA256`, `PolicyArtifactSHA256`,
`PolicySourceLockSHA256`, `PolicyBinaryBindingSetSHA256`, and
`PinnedCallsiteEvidenceSHA256` values. This is one canonical HL8Q artifact and
its external HL8E evidence; the first two fields are immutable views derived
from the sole HL8Q artifact, never separate artifacts. Private launch-material
preparation may remint only the descriptor fingerprint and must copy the
evidence fingerprint, four host-authority bindings, and measured rootfs image
digest unchanged. The fingerprint builder returns that independently measured
image digest separately from the evidence fingerprint, and the sole profile
sealer receives both as distinct arguments. This prevents
evidence substitution through a descriptor-only proof while preserving the L7
API and artifacts byte-for-byte.

The Pi dependency-tree digest is the canonical domain-separated source-lock
record digest—not npm output or a filesystem tree walk—and final inspection
recomputes it. Filename URL/credential rejection uses the closed byte-marker
catalog, and a failed launch-material preparation leaves its writer with the
caller for exactly-once close; only a fully successful preparation transfers
writer ownership into the lease.

Profile/lease pair correlation is separately mandatory: the opaque profile
and lease must carry the same sealed evidence fingerprint, and the profile's
descriptor fingerprint must match the lease's source or sole prepared-material
descriptor fingerprint. Descriptor equality alone never makes values from two
bundles composable. D6 supplies the pair through the exact
`L8LiveBootConfigProvider` ownership-transferring live overlay defined in the
extension-seam supplement. A provider error retains every returned value;
nil-error return provisionally transfers the exact lease to Firecracker before
validation so cleanup ownership is never ambiguous. Firecracker snapshots the
profile by value and all mutable overlay fields, validates only those copies,
then retains the lease on success or closes it exactly once on rejection. The
provider is injected through the exact L8 field adjacent to the L7 provider in
`BackendOptions`; selecting both is rejected before either call.
In particular, a post-start validation failure stops and reaps the exact
Firecracker process and proves its absence before closing the lease or
returning an error; no live handle escapes that path.

The source-record digest includes kind, name, version, filename, size, and
digest for the Pi package, shrinkwrap, and every npm archive. Temporary parent
L7 verification leases are resolver-owned, exactly-once closed, and must close
successfully before L8 authority can issue.

The repository baseline contains no L4/L7 workload seccomp artifact or complete
L8 role table. That is an explicit readiness boundary, not permission for D2 or
D4 to infer rules from prose, traces, host headers, or an empty table. D2
provides the canonical `VerifiedPolicyArtifact` grammar, importer/verifier,
pure engines, and fail-closed default placeholder only. It does not ship exact
role or Go-runtime rows.

D7 is the sole rule author and issuer. Its source lock produces one canonical
artifact from the approved role FSM, L4 execution policy, L7 network policy,
pinned Go 1.25.7 source, and pinned x/sys catalog source. D7 embeds the bytes and
expected artifact/source-lock digests in the guest binaries. After each final
binary exists, D7 also resolves every `EnforcementPathPinnedDirect` callsite
against its locked per-role/kind executable text and issues the exact complete
binary-binding and external evidence sets.
Independently, the host asset manifest binds the identical policy artifact
digest under `policyArtifactSHA256`, the source lock under
`policySourceLockSHA256`, the complete role-binary set under
`policyBinaryBindingSetSHA256`, and final callsite evidence under
`pinnedCallsiteEvidenceSHA256` into `VerifiedL8Profile` together with the native
bootstrap source, image, parent-profile, launch descriptor, and generator
digests. Every guest binary digest is already inside the complete canonical
binary-binding set. The guest binary does not receive
or decode the host profile. D4 trace is verification evidence only. D4 and D6
live composition remain disabled until the guest artifact verifies locally and
the host profile independently binds the same artifact/source-lock, exact
complete binary-set, and evidence digests. A fake profile, zero or mismatched digest,
absent generated source/evidence, or independently assembled metadata cannot
enable production.

The local-resolver request has final field
`PinnedCallsiteEvidence []byte`. It is non-nil, nonempty, and at most 16 MiB;
the resolver checks that bound before allocating the snapshot and then
deep-snapshots `PinnedCallsiteEvidence` before hashing or import,
so caller mutation cannot affect verification. It accepts authority only from
`EmbeddedVerifiedPolicyArtifact` and
`EmbeddedExpectedPinnedCallsiteEvidence`, imports that copied HL8E against the
single embedded HL8Q, and retains no caller slice or imported evidence graph
after sealing. D7 passes the fixed HL8E output bytes. The seven-file
distribution remains unchanged.

Before issuance the resolver derives, rather than trusts, the exact private
`l8VerifiedPolicyCompositionDigests`. Its six direct values in declared order
are `artifact.Workload().SHA256()`, `artifact.Runtime().SHA256()`,
`artifact.SHA256()`, `artifact.SourceLockSHA256()`,
`evidence.BinaryBindings().SHA256()`, and `evidence.SHA256()`, using the exact
successfully imported HL8Q and HL8E receivers. It separately decodes manifest,
provenance, and final-inspection `ProcessComposition` and performs the complete
six-field accumulated `crypto/subtle.ConstantTimeCompare` against the derived
value in manifest-first, provenance-second, final-inspection-third order. The
final inspection independently repeats the complete six-field equality;
cross-document equality is insufficient. Invalid digest syntax precedes the
internal typed `correlation_mismatch`; the issuer's exact classifier maps a
valid-syntax mismatch to public resolver `asset_lock_mismatch`, field
`processComposition`, static message, and only `ErrAssetLockMismatch` unwrap.
No authority issues on either result.
Eighteen `VerifyL8DistributionBundle` one-field mutations and an AST guard lock the accessor chains, field
order, comparison operands, accumulator, and return; mere disconnected
accessor or comparison marker calls do not satisfy the guard.

The AST closure crosses the helper/issuer boundary. It parses exact production
file `localresolver/l8_distribution_verifier.go` and the real top-level
`VerifyL8DistributionBundle`, whose protected imported/decoded/derived values
are single-assignment. The same closure protects the normalized descriptor and
validated clean root directory and passes them, with the validated manifest and
provenance, to the sole distribution sealer; lease source state is never
recovered from a cache or an unvalidated path. Its exact contiguous authority block passes the
successful embedded HL8Q result plus the separately checked embedded expected-
HL8E result and copied HL8E bytes to import, then passes the imported evidence
with the artifact to derivation. Its
four bounded document decoder/immediate-error pairs are an ordered prelude;
all existing pure validation finishes before the authority block. The block
then passes the three independently decoded document records to one controlling
validation. That validation error returns before
`buildL8EvidenceFingerprint`, `sealVerifiedL8Profile`,
`sealVerifiedL8Distribution`, or any successful return. The verifier never
mints a live lease; without its successfully returned distribution the later
`AcquireL8AssetLease` path is unreachable. Dead, discarded, unreachable, noncontrolling, aliased, lookalike,
reassigned, or late validation is rejected. The helper's mismatch constructor
is the exact typed `assetbuild.L8ValidationError` with only static
`correlation_mismatch`/`processComposition` metadata; the exact issuer
`classifyL8PolicyCompositionCorrelationError` ignores that input value and
returns only the sanitized resolver result above.
The package-wide parsed production reference guard has no basename-wide
allowlist. It parses every production declaration and permits the protected
fingerprint/profile seal/distribution seal/classifier references only as their
one exact direct calls in `VerifyL8DistributionBundle` after the controlling
validation. Same-file or alternate-file helpers, wrappers, methods, closures,
`defer`, `go`, function values, shadows, aliases, and transitive call paths are
rejected. The case-insensitive authority verb family is closed to `mint`,
`new`, `create`, `construct`, `make`, `build`, `issue`, `seal`, `acquire`,
`prepare`, and `remint` when one name also contains a verified L8 profile,
distribution, or lease type. The verifier cannot invoke one or directly
construct that authority. The closed authority graph includes each exported
profile/distribution/lease and private seal, policy-binding, correlation, and
lease-state owner. Exact signature-locked seal/acquisition functions may
construct only their one matching direct returned result. No authority or
nested owner may be staged, copied, aliased, cached, assigned, stored in
package/global/interface/container/channel/generic state, passed to an
arbitrary helper, closure-captured, factory-returned, or exposed by an
alternate getter; aliases and derived authority types are forbidden.
Authority taint is recursive across every named type/field and every package
file/build context, including pointers, containers, generics, and nested
selectors. Added containing wrappers fail, and selector extraction, accessor
return, copy, and helper passage cannot erase taint. Exactly one
all-build-context definition of each profile sealer, distribution sealer, and
lease acquirer is permitted; alternate build-tagged exact definitions fail.
Recursive type collection preserves and deterministically unions every
same-named definition across mutually exclusive build contexts: if any
definition reaches authority, the name is tainted. Sorted fixed point closure
handles cycles, aliases, and generic instantiations; no last-writer map choice
can let a benign definition mask an authority-bearing definition.

Exact test file `localresolver/l8_distribution_verifier_test.go` contains a
parsed top-level runnable test with one function-local
`[18]struct { document string; field string }` 3x6 array over manifest,
provenance, and final inspection crossed with the six policy-composition
fields. An exact baseline fixture must first succeed through the real issuer.
For each tuple, a fresh fixture also succeeds through the real issuer before
mutation. Exact independently decoded 18-field before/after snapshots prove
that the selected index alone changed to the valid 32-byte `0x01` digest and
every other field remains identical; three canonical JSON hashes computed
after zeroing only complete `ProcessComposition` values prove all non-policy
document semantics remain identical. The tuple then drives the real issuer
call, the exact sanitized assertion completes, a local counter increments, and the final
executed count must equal exactly 18. There is no package type/table/slice or
init mutation surface. Marker comments/strings, dead/cleared/incomplete
tables, duplicate/wrong/reordered tuples, ignored dimensions, alternate issuer
calls, invalid/unchecked baseline, no-op/fixed/alternate mutation, lying
snapshot, missing/wrong-index/non-policy change proof, skip/continue, zero increments,
and weak assertions do not count.
Package/test guards reject `unsafe`, `go:linkname`, assembly, reflection-based
case aliases, init mutation, and external case references. The package, exact
correlation helper, issuer, test, and underlying fixture file may be jointly
absent before D2 product implementation, but any partial presence fails closed
and all five must appear together.
Exact file `localresolver/l8_distribution_policy_composition_fixture_test.go`
contains the sole all-build-context underlying builder and mutator. Their
parsed bodies bind a complete fixture checked by the real verifier and the
exact request/document/field/replacement rewrite call. Skip/`runtime.Goexit`,
no-op,
fixed-field, lookalike, dropped-argument, or duplicate build-tagged helpers
fail. Initial and per-tuple real verification plus selected-only, other-17,
and non-policy semantic comparisons make their behavior non-vacuous. The
syscallpolicy package, correlation helper, issuer, mutation test, and this
fixture file therefore appear together or remain jointly absent.

Both the opaque profile and lease privately retain one
`verifiedL8PolicyAuthorityBindings` in exact field order:
`policyArtifactSHA256`, `policySourceLockSHA256`,
`policyBinaryBindingSetSHA256`, `pinnedCallsiteEvidenceSHA256`, and
`imageSHA256`. The first four are the host-authority bindings and the fifth is
the measured rootfs image digest. Issuance and acquisition copy them from the
same verified import/measurement result; `VerifiedL8ProfileMatchesLease`
compares all five in constant time in addition to the evidence and descriptor
correlation. `PrepareLaunch` preserves all five unchanged when it remints the
private prepared descriptor/profile. No public digest accessor exists.

Ownership and sequencing are exact in the extension-seam supplement. D2 owns
the opaque profile contracts and guards; D4 and D5 land guest behavior without
an image claim; D6 requires the opaque verified L8 profile in explicit
composition; and D7 alone creates `tools/microvm/l8`, locks its sources and
profile inputs, performs the two offline builds, issues the verified profile,
and runs prepared-Linux acceptance. No D4/D5 branch edits L5/L7 image inputs or
creates a competing profile.

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

The owner-only supervisor record above is private operational authority, not a
worker, execution, factory, manifest, runtime-metadata, status, proof, or command
projection. Its narrowly permitted PID/start-time/listener/secret fields do not
relax any public or ordinary durable schema.

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
machines, validators, fakeable supervisor/controller/agent/monitor/shim policy,
source/import guards, and negative tests. D4 owns live PID1/controller/monitor/shim/agent composition,
syscalls,
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
  launch-base ancestry, process-safe descriptor attestation, exact private
  supervisor/agent/monitor protocols, native role bootstrap,
  fd/capability/seccomp boundaries,
  cgroup-v2 placement/kill proof,
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

- Add the Linux native role bootstrap, controller core, PID1 supervisor
  adapter, mount monitor, and workload shim behind D2's exact interfaces and
  lock their production
  imports and constructors file by file. D4 changes no command constructor and
  does not import the D5 SSH children. The exact `hal-guest-agent`,
  `hal-guest-init`, `hal-guest-credential-helper`, `hal-guest-mount-monitor`,
  and `hal-guest-workload-shim` production composition plus the native
  `hal-guest-role-bootstrap` target table
  files remain guarded until D6 assembles the matching immutable helper/client
  extension sets; every root command and `sandboxd*.go` path remains forbidden
  until that same junction.
- Implement protected proc, native-preopened VSOCK listener handoff, agent
  pidfd/socketpairs, exact Go `UseCgroupFD`/`PidFD` starts, controller
  pivot/drop, monitor current-namespace mount ownership, native pre-Go shim
  namespace entry, Go identity/read-back transition, and cgroup-only workload
  termination through injected fakes first.
- Cover namespace/mount flags, path traversal and replacement races, partial
  prepare, directory/socket access modes, open-descriptor rotation, `setsid`
  escape, forbidden cross-UID signals, cgroup kill/zero-populated proof,
  host-resupplied retry, local-response loss, teardown retry, role loss,
  whole-VM fallback, and orphan recovery.

### D5 — SSH relay

- Implement live AEAD relay subkeys, SCM_RIGHTS handoff, clocks, streams, and
  backpressure under D2's already locked numeric limits, operation policy, and
  mandatory key/algorithm allowlists.
- Implement the daemon-owned immutable host-agent live registry through the
  extension supplement's exact config/policy identity and per-connection peer
  verification APIs; never persist or project its entry, path, peer, or key
  selectors.
- Cover replay, generation mismatch, per-connection agent peer revalidation,
  filtered enumeration, key/flag rejection, bounds, loss, and cleanup.

### D6 — Firecracker and worker lifecycle

- Compose v2, HTTP, tmpfs, relay, process/vsock, and L7 generations.
- Implement the explicit Linux runtime-owner supervisor and neutral recovery
  API exactly as frozen above: private atomic owner state before publication,
  same-UID one-use-secret reconnect, direct-parent bounded stop/reap, pidfd
  replacement-owner containment, and L7 reconciliation before record retirement.
- Own the sole production `guestagent/l8composition` junction and exact guest
  command wiring; construct helper/client objects only in their own processes
  and have PID1 validate their canonical process descriptors before releasing
  the agent start gate, with no implicit/default registration.
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
