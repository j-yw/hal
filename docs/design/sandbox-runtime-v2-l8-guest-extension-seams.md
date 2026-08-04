# Sandbox Runtime v2 L8 Guest Extension and Ownership Seams

## Authority and scope

This is the normative D2 package-extension and ownership closure for
`sandbox-runtime-v2-l8-production-credential-delivery-architecture.md`. The
main architecture remains authoritative for the wire encodings, identity
fields, limits, state transitions, security properties, and D2 through D7
outcomes. If an implementation choice conflicts with this file, the
implementation is wrong unless both design files are deliberately revised.

D2 freezes only types, constructor rules, ownership transfer, fake boundaries,
and red-test obligations. It adds no live socket, syscall, namespace, mount,
cgroup, process, relay, host-agent, image build, or command composition. D4 may
implement the tmpfs/helper core and D5 may implement SSH extensions against
these seams without importing or editing each other's implementation. D6 alone
owns production composition. D7 alone may claim the freshly built L8 image and
prepared-Linux acceptance.

## Frozen package graph

The following package names and import directions are exact:

```text
guestagent/credentialprotocol                         data/codecs
        ^                         ^
        |                         |
guestagent/credentialhelper      guestagent/server/credentialclient
        ^                         ^
        |                         |
credentialhelper/sshrelay        credentialclient/sshrelay          D5

credentialhelper/linux                                              D4

guestagent/l8composition                                            D6
        | imports helper core and both registered SSH extensions
        | never imported by a contract or implementation leaf
        v
cmd/hal-guest-init, cmd/hal-guest-agent,
cmd/hal-guest-credential-helper                                    D6 wiring

firecrackerhost/sshrelay                                            D5 host side
        ^
        |
firecrackerhost L8 runtime wrapper                                  D6
```

All paths above are below
`internal/sandboxruntime/microvm/guestagent`, except
`firecrackerhost/sshrelay`, which is below
`internal/sandboxruntime/microvm/firecrackerhost`.

The rules are:

- `credentialprotocol` imports only the standard library and the already
  approved mutable-memory sink contract. It imports no helper, client, server,
  runtime, worker, command, factory, network, filesystem, or concrete adapter.
- `credentialhelper` and `server/credentialclient` may import
  `credentialprotocol`; neither imports the other. Neither imports its child
  `sshrelay` package.
- Each D5 child imports only its parent contract, `credentialprotocol`, and
  narrow standard-library live interfaces needed by that side. Guest D5 code
  does not import `firecrackerhost/sshrelay`.
- `firecrackerhost/sshrelay` may import the root neutral
  `internal/sandboxruntime` contracts, `credentialprotocol`, and the v2 session
  package. It does not import a guest helper/client implementation,
  `sandboxworker`, `cmd`, factory, or a durable store.
- `guestagent/l8composition` is the only guest package allowed to import the
  D4 Linux core and both D5 guest extensions together. Its production
  constructors are added in D6, not D4 or D5.
- No package uses `init`, a mutable package-global registry, blank imports, or
  side-effect registration. Existing v1 files and default constructors remain
  byte- and behavior-compatible.

Import guards match production `.go` files, not fixture text, and reject the
reverse of every arrow above.

## Shared extension descriptor

`credentialprotocol` owns this safe, immutable descriptor:

```go
type ExtensionID string

const ExtensionIDSSHRelayV1 ExtensionID = "ssh-relay-v1"

type ExtensionDescriptor struct {
	ID                       ExtensionID
	Modes                    []DeliveryMode
	AgentToHelperPacketTypes []PacketType
	HelperToAgentPacketTypes []PacketType
}

func ValidateExtensionDescriptor(ExtensionDescriptor) error
func ExtensionDescriptorEqual(ExtensionDescriptor, ExtensionDescriptor) bool
func ValidateMatchingExtensionSets(helper, client []ExtensionDescriptor) error
```

Descriptors have no JSON tags and are never durable or public status. The
validator accepts canonical values only; it does not trim, sort, deduplicate,
or default. Slices are nonempty where required, strictly increasing by the
closed numeric catalogs, and defensively copied. An ID is a nonempty safe ID.
One descriptor cannot claim a core packet type. `ssh-relay-v1` claims exactly
delivery mode `ssh_agent` and helper-to-agent packet type
`PacketTypeSSHAcceptedFD` (`0x16`); it claims no agent-to-helper packet type.
The SSH-agent application frames remain the separate D2 relay codec, not new
helper packet types.

`ValidateMatchingExtensionSets` requires the two sets to have identical
descriptor count and field-for-field descriptors in ascending ID order. It
does not accept one-sided optional support. This function is pure; only D6
calls it for production assembly.

## Privileged helper service seam

### Constructor and registry

`credentialhelper` exposes these exact construction shapes:

```go
type ServiceOptions struct {
	Core       Core
	Transport  Transport
	Policy     Policy
	Extensions *ExtensionRegistry
}

func NewService(ServiceOptions) (*Service, error)

type ExtensionRegistration struct {
	Descriptor credentialprotocol.ExtensionDescriptor
	Factory    ExtensionFactory
}

func NewExtensionRegistry(...ExtensionRegistration) (*ExtensionRegistry, error)
func (r *ExtensionRegistry) Descriptors() []credentialprotocol.ExtensionDescriptor
```

There is deliberately no `Register`, `MustRegister`, default registry, clone
with additions, or lookup that exposes a factory. `NewExtensionRegistry`
validates the complete set, copies it, and freezes it. `Descriptors` returns a
deep copy in ascending extension-ID order. A nil registry means an empty set;
it never means “install defaults.” `NewService` snapshots the registry and
does not retain caller-owned slices.

`Core`, `Transport`, and `Policy` are D2 narrow interfaces. D4 supplies their
Linux implementations. D2 supplies fakes and transition tests only. The
service remains the sole owner of helper packet sequencing, authenticated
kernel credentials, request correlation, core prepare/renew/revoke/exec state,
and terminal cleanup disposition. Extensions cannot send an arbitrary packet,
advance a sequence, manufacture a proof, publish a response, or bypass the
core state machine.

### Extension contract

The helper extension API is exact:

```go
type ExtensionFactory interface {
	Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error)
}

type ExtensionOpenRequest struct {
	Descriptor credentialprotocol.ExtensionDescriptor
	Host       ExtensionHost
}

type ExtensionSession interface {
	Prepare(context.Context, ExtensionPrepareRequest) (ExtensionPrepareResult, error)
	BindExec(context.Context, ExtensionExecRequest) (ExtensionExecResult, error)
	Renew(context.Context, ExtensionRenewRequest) error
	Revoke(context.Context, ExtensionRevokeRequest) (ExtensionCleanupResult, error)
	Close(context.Context) error
}
```

The request/result structs are concrete, non-JSON, closed unions owned by
`credentialhelper`. They contain only canonical safe identity/digest/revision
metadata and opaque capabilities owned by `ExtensionHost`; they contain no
path string, raw secret, key, key fingerprint, socket address, numeric file
descriptor, PID, or generic `any`/map/body. `ExtensionHost` is the D4-owned
narrow capability for the already-created exact job namespace and for one
authenticated `0x16` rights publication. It does not expose namespace or root
file descriptors. D5 cannot open outside the owned job namespace or publish
another packet type through it.

The SSH registration is constructed only by:

```go
func sshrelay.NewHelperExtension(sshrelay.HelperOptions) (credentialhelper.ExtensionRegistration, error)
```

It creates no resource at registration time. `Open` creates only
service-lifetime extension state. `Prepare` may create the job-scoped guest
socket and acceptor through `ExtensionHost`; `BindExec` may return only the
opaque generated `SSH_AUTH_SOCK` binding understood by the core; `Renew` may
only shorten or extend within the core hard expiry; `Revoke` must stop accepts,
close connections, and prove its owned guest resource absent. The core combines
that result with D4 cgroup/mount/keeper absence. An extension cannot return
`cleanup_complete` for the whole helper job.

### Uniqueness and typed nil

Registry construction rejects all of the following before invoking an
extension method:

- an empty or invalid extension ID;
- a nil `Factory` interface or an interface containing a typed-nil pointer,
  map, slice, function, channel, or nested interface;
- duplicate IDs, duplicate delivery modes, or duplicate packet-type claims,
  including byte-for-byte duplicate registrations;
- a claim on a core mode or reserved core packet type;
- noncanonical order, an unknown mode/type, or a descriptor inconsistent with
  the locked SSH descriptor.

The common private `configuredDependency` rule checks nil-capable dynamic
kinds with reflection and treats their nil value as absent. It never calls a
method to discover nil. The same rule applies to `ServiceOptions` dependencies,
factory results, session results, transports, extension hosts, and D5 live
registry entries.

`ExtensionFactory.Open` and every constructor follow one return matrix:

```text
non-nil, non-typed-nil value + nil error       success
nil or typed-nil value + nil error             contract violation
nil value + non-nil error                      ordinary safe failure
non-nil or typed-nil value + non-nil error     contract violation; close if callable
```

A contract violation has a stable generic error code, never formats the
candidate, and forces rollback. The service does not recover by omitting the
extension or downgrading the requested mode.

### Concurrency, lifecycle, and cleanup

An `ExtensionRegistry` is immutable and safe for concurrent reads. A `Service`
has one `Serve` lifetime and one drain path. For a prepare transaction it opens
only the extensions named by the sealed manifest, in manifest order. It calls
`Prepare` only after core staging exists and before publication. On failure it
revokes prepared extensions in reverse order, then rolls back core staging.
No extension call is concurrent with another transition for the same job.

An extension session is owned by the service from a valid `Open` return until
exactly one successful transfer into job state. After transfer, job state owns
it until revoke. `Close` is idempotent, may be called after partial open, and
does not substitute for `Revoke` or absence proof. The service calls it exactly
once after terminal revoke/rollback or during service drain. All caller
contexts may stop waiting; cleanup continues under the service's bounded
cleanup context.

For SSH cleanup the order is fixed: deny new exec and new accepts; close guest
listeners; cancel relay pumps; close every service-owned accepted descriptor;
wait for extension absence; perform D4 cgroup kill/zero-population and tmpfs
cleanup; close the extension session. `retry_required` keeps ownership and
reinspects without recreating. `stop_vm_required`, helper loss, a stuck pump,
or missing extension absence proof escalates unchanged to D6 whole-VM
stop/reap. A timeout never detaches a goroutine or leaks a descriptor.

## Unprivileged credential client seam

`guestagent/server/credentialclient` mirrors registration without importing
the helper:

```go
type ClientOptions struct {
	Transport   Transport
	Policy      Policy
	Extensions *ExtensionRegistry
}

func NewClient(ClientOptions) (*Client, error)

type ExtensionRegistration struct {
	Descriptor credentialprotocol.ExtensionDescriptor
	Factory    ExtensionFactory
}

func NewExtensionRegistry(...ExtensionRegistration) (*ExtensionRegistry, error)
func (r *ExtensionRegistry) Descriptors() []credentialprotocol.ExtensionDescriptor

type ExtensionFactory interface {
	Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error)
}

type ExtensionSession interface {
	Handle(context.Context, ExtensionPacket) error
	Close(context.Context) error
}
```

Its registry has the identical immutability, uniqueness, ordering, typed-nil,
return-matrix, snapshot, and no-global-registration rules. The D5 constructor
is:

```go
func sshrelay.NewClientExtension(sshrelay.ClientOptions) (credentialclient.ExtensionRegistration, error)
```

`ExtensionPacket` is a closed client-owned union already authenticated and
correlated by the core client. For `ssh-relay-v1` it can represent only one
`0x16` packet plus exactly one inspected connected `AF_UNIX SOCK_STREAM`
rights capability. It cannot represent raw integer FDs or arbitrary packet
bodies. The extension takes ownership only after returning nil. Before that
return, the client owns and closes the capability on every error, cancellation,
typed-nil, unexpected type, or correlation failure. After transfer, the SSH
extension pumps that guest connection only through the authenticated D5 host
relay boundary and closes it on EOF, loss, revoke, or client drain.

The client serializes packet delivery for one helper session. It starts the
extension loss watcher before acknowledging transfer, never dispatches a
second SSH request while one response is outstanding, and applies bounded
backpressure instead of a queue. Client and helper descriptors must match
through `ValidateMatchingExtensionSets` before D6 releases the guest-agent
start gate. A mismatch makes readiness false and requires VM stop/reap.

The existing v1 `guestagent/server.Options`, `server.New`, v1 backend, and v1
client are unchanged. V2 composition receives `*credentialclient.Client`
through a new explicit D6-only option; nil preserves v1 only and cannot admit a
production credential request.

## D5 daemon-owned host-agent registry

### Ownership and exact API

`firecrackerhost/sshrelay` owns the live implementation, but the worker daemon
owns the registry instance and closes it. `cmd` may translate host-admin-only
startup configuration into registrations; request, repository, template,
guest, runtime metadata, and status code cannot register or mutate one.

The D5 API is:

```go
type RegistryOptions struct {
	DaemonGeneration string
	Entries          []LiveHostAgentEntry
}

func NewRegistry(RegistryOptions) (*Registry, error)
func (r *Registry) Acquire(context.Context, AcquireRequest) (Lease, error)
func (r *Registry) Close(context.Context) error

type LiveHostAgentEntry interface {
	Identity() ConfigIdentity
	Open(context.Context) (AgentConnection, error)
	VerifyPeer(context.Context, AgentConnection) (PeerProof, error)
	Policy() LivePolicy
}

type Lease interface {
	Identity() ConfigIdentity
	PolicyIdentity() PolicyIdentity
	OpenVerifiedConnection(context.Context) (VerifiedAgentConnection, error)
	Close(context.Context) error
}
```

`ConfigIdentity` is a registry-private safe entry ID, daemon generation, entry
generation, and positive revision. `PolicyIdentity` is the safe SSH policy ID
and positive revision. `AcquireRequest` carries the exact runtime, process,
vsock, worker-job, activation, and relay generations plus the registry-private
entry identity selected by the accepted host-admin grant. These concrete
types have private fields, constructors that validate exact identities, and
fail-closed `MarshalJSON`, `MarshalText`, `String`, and `GoString`; callers use
comparison/accessor functions, not formatting.

`LivePolicy` owns a nonempty immutable set of exact public-key blob SHA-256
selectors and allowed key/algorithm/flag tuples. Selectors are the locked
OpenSSH `SHA256:` form internally, but no fingerprint accessor exists. The
only policy operations are bounded filtering and authorization over mutable
SSH codec views. `AgentConnection`, `VerifiedAgentConnection`, `PeerProof`,
and `LivePolicy` are non-JSON live handles and obey the same typed-nil rules.

### Registration, peer validation, and projection

Registry construction is all-or-nothing and freezes the entries for one daemon
generation. It rejects duplicate entry IDs, config identities, policy
identities, typed nils, empty allowlists, unknown algorithms/flags, or a config
whose daemon generation differs from `RegistryOptions`. There is no runtime
register/reload API. A configuration change requires a new daemon generation;
durable in-flight jobs from the old generation reconcile by revocation and
cannot bind to the replacement.

Every guest SSH connection calls `Lease.OpenVerifiedConnection`. That method
opens a fresh connection through the configured entry and then calls
`VerifyPeer` on that exact connected object before sending even an identities
request. A cached proof, path inspection alone, proof from another connection,
or peer validation performed only at registry startup is invalid. Peer proof
is bound to the connected socket and current config identity; it is consumed
when producing `VerifiedAgentConnection` and cannot be replayed. Open or
verification failure closes the connection and revokes that guest connection.

The production Linux entry opens only its private configured Unix endpoint,
uses no environment fallback, reinspects the connected socket and kernel peer
credentials, and enforces the host-admin expected owner/peer policy. D5 owns
those syscalls behind `AgentDialer` and `PeerVerifier` fakes. Raw open/peer
errors are replaced by stable codes. No path, endpoint, PID, UID/GID detail,
public-key blob, fingerprint, comment, challenge, or signature is logged or
returned.

No socket path or key fingerprint appears in `sandboxjob-v2`, durable job
state, recovery checkpoints, manifests, factory records, timelines, status
JSON, errors, proof metadata, or command output. Durable private recovery state
may contain only the already-authorized safe SSH policy ID/revision and the
neutral complete job identity; it does not contain `ConfigIdentity` or an
entry ID. The live active-proof digest privately commits to config and policy
identity, but public proof projection exposes only the safe mode proof ID and
policy ID/revision. Cleanup projection exposes only a safe cleanup proof ID and
absence booleans.

The registry is safe for concurrent acquisition. A lease is job-scoped and
enforces the architecture's four concurrent, 64 lifetime connection, 4096
attempt, five-minute idle, and 35-minute hard-lifetime limits. Closing the
registry atomically denies acquisition, cancels leases, closes live
connections, waits for bounded pump cleanup, and returns only after absence or
a cleanup-incomplete error. Close is idempotent. A caller timeout stops waiting
but does not abandon cleanup.

## Production composition is D6-owned

D4 exports a constructor for the Linux helper core and D5 exports the two SSH
registrations plus the host registry. None changes a default constructor or a
command. D6 adds the only explicit composition package and functions:

```go
type GuestOptions struct {
	HelperCore      credentialhelper.Core
	HelperTransport credentialhelper.Transport
	HelperPolicy    credentialhelper.Policy
	HelperSSH       credentialhelper.ExtensionRegistration
	ClientTransport credentialclient.Transport
	ClientPolicy    credentialclient.Policy
	ClientSSH       credentialclient.ExtensionRegistration
}

func NewGuest(GuestOptions) (*Guest, error)
```

`NewGuest` constructs both immutable registries, calls
`credentialprotocol.ValidateMatchingExtensionSets`, then constructs the helper
service and credential client. It rejects missing, extra, typed-nil, or
mismatched production dependencies. It never auto-installs an SSH extension.
The exact D6 command files may call this explicit constructor only after PID1
bootstrap identities and the L8 image profile are validated. Existing v1 and
L5/L7 command paths do not import `l8composition`.

On the host, D6 injects the daemon-owned `*sshrelay.Registry` into the explicit
L8 Firecracker runtime wrapper. The worker imports only the neutral
`JobCredentialRuntime`; it neither imports nor looks up the concrete registry.
D6 owns loss fan-in, whole-VM stop/reap fallback, proof projection, and final
host listener/connection absence. D4 and D5 tests may compose fakes, but such
test constructors are named `NewFake...`, live only in `_test.go` or explicit
fake files, and cannot be reached from production commands.

## L8 image source lock, build, and profile ownership

The exact ownership is:

- `tools/microvm/l8/` owns the L8 build scripts, Buildroot/kernel fragments,
  rootfs overlay, `sources.lock.json`, `cache.manifest`, offline Node/npm cache
  verification, final-image inspection, and reproducibility scripts. It copies
  the exact phase-head guest binaries; D4 or D5 must not create a competing
  image directory or edit L5/L7 image inputs.
- `internal/sandboxruntime/microvm/assets/build` owns
  `ImageProfileL8ProductionCredentials = "l8-production-credentials-v1"`, the
  additive L8 manifest/provenance/source-lock schema, validation, and safe
  Node/Pi version and dependency-tree digest facts. It owns no build process or
  host path.
- `internal/sandboxruntime/microvm/assets/localresolver` is the sole issuer of
  opaque `VerifiedL8Profile`. It issues that value only after checksums,
  manifest, provenance, parent L7 profile, source lock, final inspection, and
  descriptor correlation all validate. The zero value and external literal
  are invalid. `VerifiedL8ProfileMatches` binds it to the exact normalized
  launch descriptor.
- `internal/sandboxruntime/microvm/firecracker` consumes the opaque profile and
  rejects L8 boot material without a matching verified profile. It does not
  parse source locks or infer L8 from a label.
- `firecrackerhost` D6 composition requires that verified profile before
  advertising v2 credential capability. `cmd` may select an already verified
  distribution but cannot mint, weaken, or project the profile.

Sequencing is fixed. D2 lands this ownership and red guards. D4 lands helper,
PID1, tmpfs, and guest cleanup code with fake syscall tests but no image claim.
D5 lands guest/host SSH relay code and fake connection tests but no image claim.
D6 lands the explicit production composition, opaque profile requirement, and
worker/runtime cleanup wiring; all defaults remain off. D7 creates and locks
`tools/microvm/l8`, builds twice offline, installs the exact D4/D5/D6 phase-head
binaries plus locked Node 22.22.0 and Pi 0.82.1, issues the verified profile,
boots only that digest-locked output, and runs the prepared-Linux acceptance.
No earlier slice may satisfy a gate by reusing an L5/L7 image, a host binary,
an unlocked overlay, or a hand-authored descriptor.

## Required red tests

D2 implementation starts with failing tests for these exact obligations:

- `credentialhelper`: duplicate ID/mode/packet claims, reserved core claims,
  noncanonical descriptors, nil and every typed-nil dependency, all four
  factory return cases, immutable/sorted defensive registry snapshots, no
  global registration, reverse-order rollback, retry ownership, cleanup after
  caller cancellation, and no extension-driven proof/sequence bypass.
- `server/credentialclient`: the matching registry cases, ownership of a
  received rights capability before/after `Handle`, descriptor mismatch before
  start-gate release, serialized dispatch, bounded backpressure, loss while
  transferring ownership, and close-on-every-rejection.
- D4/D5 independence guards: helper core production files cannot import either
  SSH child or host relay; each SSH child cannot import the other side; only
  `l8composition` may import both registrations; no `init`, blank import, or
  default constructor reaches an L8 extension.
- `firecrackerhost/sshrelay`: immutable daemon-generation registry, duplicate
  config/policy rejection, nil/typed-nil entry rejection, empty allowlist
  rejection, a fresh open and peer proof for every guest connection, cached or
  cross-connection proof rejection, limits at exact bound and plus one,
  restart-generation mismatch, bounded/idempotent close, and concurrent
  acquire/close under `go test -race`.
- redaction scans seed socket paths, key fingerprints, public-key blobs,
  comments, challenges, signatures, raw agent errors, PIDs, and endpoints and
  assert their absence from JSON, text, errors, logs, durable state, public
  proofs, status, artifacts, and formatting/panic paths.
- image/profile guards reject L8 claims from an L5/L7 descriptor, missing or
  mismatched parent profile, unlocked Node/npm/Pi inputs, wrong phase-head
  binary digest, online resolution, forged/zero opaque profile, and any command
  or D4/D5 package that mints a profile.

All D2 red tests are fake-only and deterministic. They use fake core,
transport, extension factory/session, extension host, owned-right capability,
agent dialer/connection, peer verifier, clock, pump, cleanup observer, source
lock, and profile resolver boundaries. They do not bind sockets, inspect a host
agent, mount, enter namespaces, invoke syscalls, build an image, boot KVM, or
run a worker daemon.

## Explicit non-goals

This closure does not implement D4, D5, D6, or D7; change the main architecture
or existing v1 APIs; define a plugin ABI; permit third-party or runtime-loaded
extensions; add multiple credential jobs; add registry reload; expose socket
paths or fingerprints; persist live config identity; provide host-agent
discovery; forward unrestricted SSH operations; add SSH key material to the
guest; make cleanup best-effort; enable credentials in default constructors;
build or publish an image; or claim prepared-Linux, strict-default, or L10
completion.
