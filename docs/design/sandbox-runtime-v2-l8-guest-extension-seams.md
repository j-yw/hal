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
implement the controller/supervisor/monitor/shim core and D5 may implement SSH extensions against
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
guestagent/rolebootstrap (freestanding native, no Go imports)       D4

guestagent/l8composition                                            D6
        | imports helper core and both registered SSH extensions
        | never imported by a contract or implementation leaf
        v
cmd/hal-guest-init, cmd/hal-guest-agent, cmd/hal-guest-credential-helper,
cmd/hal-guest-mount-monitor, cmd/hal-guest-workload-shim            D6 wiring

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

The D2 method sets are exact:

```go
type Core interface {
	BeginPrepare(context.Context, CorePrepareRequest) (CorePreparation, error)
	BeginExec(context.Context, CoreExecRequest) (CoreExecution, error)
	Renew(context.Context, CoreRenewRequest) error
	Revoke(context.Context, CoreRevokeRequest) (CoreCleanupResult, error)
	Inspect(context.Context, CoreInspectRequest) (CoreInspection, error)
	Close(context.Context) error
}

type CorePreparation interface {
	StageFile(context.Context, CoreFileRequest, credentialmemory.BorrowedView) error
	Commit(context.Context, CoreCommitRequest) (CorePreparedResult, error)
	Rollback(context.Context) (CoreCleanupResult, error)
}

type CoreExecution interface {
	WriteStdin(context.Context, credentialmemory.BorrowedView, uint64, bool) error
	ReadOutput(context.Context, CoreOutputRequest, credentialmemory.CredentialSink) (CoreOutputResult, error)
	Wait(context.Context) (CoreExecResult, error)
	Cancel(context.Context) (CoreCleanupResult, error)
}

type Transport interface {
	Receive(context.Context, ReceiveRequest) (ReceivedPacket, error)
	Send(context.Context, SendPacket) error
	Close(context.Context) error
}

type Policy interface {
	Authorize(PolicyRequest) (PolicyDecision, error)
	Descriptor() PolicyDescriptor
}
```

The named request/result types are concrete non-JSON closed unions. Every core
request contains only exact identity digest, positive revision, safe request/
binding IDs, safe generation IDs, expiry, fixed-limit-set ID, declared byte
counts/digests, and closed operation/reason enums required by that method.
`CoreFileRequest` adds binding index and the canonical relative-path capability;
`CoreOutputRequest` adds stdout/stderr kind, exact offset, and at-most-64-KiB
capacity. Results contain only safe generations, counts/digests, exit category,
truncation, cleanup category, and private opaque capabilities. No request/result
contains `any`, map, callback, raw `[]byte`, path string, FD integer, PID, socket
address, environment, or proof token.

`ReceiveRequest` supplies fixed mutable body and ancillary-capability sinks plus
the exact next sequence; `ReceivedPacket` is the already decoded closed helper
packet union and never owns sensitive bytes. `SendPacket` is the service-built
closed outbound union with no public constructor. `PolicyRequest` contains only
the decoded safe operation/identity/revision/manifest/limit metadata;
`PolicyDecision` is exactly allow or a stable safe rejection code and cannot
mint proof, sequence, transport, or resource authority.

`PolicyDescriptor` is a concrete non-JSON value with private fields, safe ID and
SHA-256 accessors, fail-closed formatting, and no public literal constructor.
The helper's sole production policy ID is `helper-policy-v1`; the client's is
`client-policy-v1`. For either exact ID, the digest is
`SHA256(opaque16("hal/l8/process-policy/v1") || opaque16(policyID))`. A policy
with an unknown ID, zero/wrong digest, typed nil, or changing descriptor is a
constructor failure. `NewHelper`/`NewClient` snapshot the descriptor before
opening extensions and put its digest in `ProcessDescriptor.PolicySHA256`; the
sealed image-profile descriptor digest independently binds that result to the
exact production binary. Authorization cannot change or mint the descriptor.

D4 supplies Linux `Core` and transport implementations; D2 supplies the sole
production policy, codecs, fakes, and transition tests. The service remains the
sole owner of packet sequencing, authenticated kernel credentials, request
correlation, core prepare/renew/revoke/exec state, and terminal cleanup
disposition. Extensions cannot send an arbitrary packet, advance a sequence,
manufacture a proof, publish a response, or bypass the core state machine.

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

type ExtensionHost interface {
	CreateSSHAgentEndpoint(context.Context, SSHAgentEndpointRequest) (SSHAgentEndpoint, error)
	PublishSSHAcceptedConnection(context.Context, SSHAcceptedPublication, SSHAgentConnection) error
}

type SSHAgentEndpoint interface {
	ExecBinding() ExecBindingCapability
	Accept(context.Context) (SSHAgentConnection, error)
	Close(context.Context) (ExtensionCleanupResult, error)
}

type SSHAgentConnection interface {
	Read(context.Context, credentialmemory.CredentialSink) (SSHIOResult, error)
	Write(context.Context, credentialmemory.BorrowedView) (SSHIOResult, error)
	Shutdown(context.Context, SSHShutdownDirection) error
	Close(context.Context) error
}

type ExtensionPrepareRequest struct {
	IdentityDigest [32]byte
	Revision       uint64
	ExpiresAt      time.Time
	BindingID      credentialprotocol.SafeID
	BindingIndex   uint16
	Mode           credentialprotocol.DeliveryMode
}

type ExtensionPrepareResult struct {
	ExecBinding ExecBindingCapability
}

type ExtensionExecRequest struct {
	IdentityDigest [32]byte
	Revision       uint64
	ExecBindingID  credentialprotocol.SafeID
}

type ExtensionExecResult struct {
	ExecBinding ExecBindingCapability
}

type ExtensionRenewRequest struct {
	IdentityDigest [32]byte
	Revision       uint64
	ExpiresAt      time.Time
}

type ExtensionRevokeRequest struct {
	IdentityDigest [32]byte
	Revision       uint64
	Reason         credentialprotocol.RevokeReason
}

type SSHAgentEndpointRequest struct {
	IdentityDigest [32]byte
	Revision       uint64
	BindingID      credentialprotocol.SafeID
	BindingIndex   uint16
}

type SSHAcceptedPublication struct {
	IdentityDigest [32]byte
	Revision       uint64
	BindingIndex   uint16
	Ordinal        uint8
	CapabilitySHA256 [32]byte
}
```

`ExecBindingCapability`, `ExtensionCleanupResult`, `SSHIOResult`, and live
endpoint/connection values have private concrete implementations, no public
literal constructor, and fail-closed formatting/serialization. Cleanup result
contains only the extension resource-absence boolean and retry/stop-VM category;
it can never claim whole-job cleanup. `SSHIOResult` contains only byte count,
EOF, and truncation. Shutdown direction is a closed read/write/both enum.

These request/result structs are concrete, non-JSON closed types owned by
`credentialhelper`. They contain only canonical safe identity/digest/revision
metadata and opaque capabilities owned by `ExtensionHost`; they contain no
path string, raw secret, key, key fingerprint, socket address, numeric file
descriptor, PID, or generic `any`/map/body. `ExtensionHost` is the D4-owned
narrow capability backed by the authenticated mount-monitor protocol for the
already-created exact job namespace and by the core service for one
authenticated `0x16` rights publication. It exposes no namespace or root FD.
D5 cannot open outside the owned job namespace or publish another packet type.

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
that result with D4 cgroup/mount/monitor absence. An extension cannot return
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

For SSH cleanup the order is fixed: deny new exec and new accepts; the
controller closes every published listener; cancel relay pumps; close every
service-owned accepted descriptor; wait for extension connection absence;
perform D4 cgroup kill/zero-population; instruct the monitor to unlink the
socket entry and complete tmpfs cleanup; close the extension session.
`retry_required` keeps ownership and
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

type Transport interface {
	ReceiveController(context.Context, ControllerReceiveRequest) (ControllerPacket, error)
	SendController(context.Context, ControllerSendPacket) error
	ReceiveHelper(context.Context, HelperReceiveRequest) (HelperPacket, error)
	SendHelper(context.Context, HelperSendPacket) error
	Close(context.Context) error
}

type Policy interface {
	Authorize(ClientPolicyRequest) (ClientPolicyDecision, error)
	Descriptor() PolicyDescriptor
}
```

Its registry has the identical immutability, uniqueness, ordering, typed-nil,
return-matrix, snapshot, and no-global-registration rules. The D5 constructor
is:

```go
func sshrelay.NewClientExtension(sshrelay.ClientOptions) (credentialclient.ExtensionRegistration, error)
```

The four transport packet/request types are private-constructor closed unions
over the exact v2 controller and helper codecs. Receive requests provide fixed
mutable/ancillary sinks and expected sequence/identity; send values are built
only by the core client. They expose no generic body or arbitrary frame/packet
type. `ClientPolicyRequest` contains only safe operation, identity, revision,
manifest, descriptor, and fixed-limit metadata. `ClientPolicyDecision` is allow
or a stable rejection code and has no transport, proof, credential, or rights
authority.

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
backpressure instead of a queue. Client and helper process descriptors must
arrive through the authenticated PID1 bootstrap; PID1 calls
`ValidateProcessDescriptors`, which applies `ValidateMatchingExtensionSets`,
before releasing the guest-agent start gate. A mismatch makes readiness false
and requires VM stop/reap.

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

D4 exports constructors for the Linux core, PID1 supervisor adapter, monitor,
and workload shim plus the freestanding native role-bootstrap source contract;
D5 exports the two SSH registrations plus the host registry.
None changes a default constructor or command. Because init, agent, and
controller are separate executables, no live Go object or registry may cross an
`exec` boundary. D6 adds one explicit composition package with separate
process-local constructors and a process-safe descriptor attestation:

```go
type HelperOptions struct {
	Core      credentialhelper.Core
	Transport credentialhelper.Transport
	Policy    credentialhelper.Policy
	SSH       credentialhelper.ExtensionRegistration
}

type ClientOptions struct {
	Transport credentialclient.Transport
	Policy    credentialclient.Policy
	SSH       credentialclient.ExtensionRegistration
}

type ProcessRole uint8

const (
	ProcessRoleHelper ProcessRole = 1
	ProcessRoleClient ProcessRole = 2
)

type ProcessDescriptor struct {
	ContractVersion string
	Role            ProcessRole
	Extensions      []credentialprotocol.ExtensionDescriptor
	PolicySHA256    [32]byte
}

type CompositionDescriptor struct {
	ContractVersion string
	HelperSHA256    [32]byte
	ClientSHA256    [32]byte
	CompositionSHA256 [32]byte
}

func NewHelper(HelperOptions) (*credentialhelper.Service, ProcessDescriptor, error)
func NewClient(ClientOptions) (*credentialclient.Client, ProcessDescriptor, error)
func ValidateProcessDescriptors(ProcessDescriptor, ProcessDescriptor) (CompositionDescriptor, error)
func EncodeProcessDescriptor(ProcessDescriptor) ([]byte, error)
func DecodeProcessDescriptor([]byte) (ProcessDescriptor, error)
```

`NewHelper` is called only inside `cmd/hal-guest-credential-helper`; `NewClient`
only inside `cmd/hal-guest-agent`. Each constructs one immutable local registry,
rejects missing/extra/typed-nil dependencies, never installs a default SSH
extension, and returns a defensively copied safe descriptor. Descriptor encoding
is one canonical bounded binary form with strict field order, exact contract
version `l8-process-composition-v1`, closed roles, no unknown/trailing fields,
and SHA-256 over the complete encoding. It contains no live handle, path, FD,
PID, endpoint, secret, config value, or JSON tag.

The process descriptor encoding is exact:

```text
magic[4] = "HL8D" | version:u8=1 | role:u8 | reserved:u16=0
extensionCount:u16 | policySHA256:[32]byte
for each extension in strictly increasing ID order:
  idLength:u8 | id:idLength bytes
  modeCount:u8 | modes:modeCount*u8
  agentPacketCount:u8 | agentPacketTypes:agentPacketCount*u8
  helperPacketCount:u8 | helperPacketTypes:helperPacketCount*u8
```

There are 0..16 extensions. Each ID is 1..64 canonical safe ASCII bytes and
each list has 0..16 entries in strictly increasing order; the descriptor
validator still requires every registered extension to claim at least one mode
or packet direction. Role 1 is helper and role 2 client. All integers wider
than one byte are big-endian. The complete encoding is at most 1,898 bytes.
Decode rejects a wrong magic/version/role/reserved byte, count overflow,
unknown catalog value, noncanonical ordering, invalid descriptor, truncation,
or trailing byte. `ContractVersion` is the fixed in-memory projection of wire
version 1 and is not encoded a second time.

`HelperSHA256` and `ClientSHA256` are SHA-256 of the exact respective encodings.
`CompositionSHA256` is SHA-256 of
`opaque16("hal/l8/process-composition/v1") || HelperSHA256 || ClientSHA256`.
`ValidateProcessDescriptors` requires helper then client roles, validates both
canonical descriptors, requires the exact `helper-policy-v1` digest for the
helper and exact `client-policy-v1` digest for the client, and applies
`ValidateMatchingExtensionSets`; it never sorts or normalizes caller values.

PID1 owns the sealed expected helper/client descriptor digests from the verified
L8 image profile. The helper sends its canonical descriptor during authenticated
readiness. The gated agent sends its descriptor directly to PID1 over the
authenticated agent-supervisor endpoint after dropping to the already-pinned
agent identity and before admission release. PID1 decodes both, checks the sealed
digests, calls `ValidateProcessDescriptors`, which in
turn calls `credentialprotocol.ValidateMatchingExtensionSets`, and sends the
same canonical composition digest independently to helper and agent only on
exact agreement. The helper then verifies the descriptor repeated in
`agent_hello` before admitting requests. A descriptor cannot attest a live object;
the object remains process-local and its loss invalidates readiness. Mismatch,
missing attestation, noncanonical encoding, or wrong policy digest requires
whole-VM stop/reap. Existing v1 and L5/L7 paths never import `l8composition`.

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

Sequencing is fixed. D2 lands this ownership and red guards. D4 lands the native
role bootstrap, controller, PID1 supervisor, mount monitor, workload shim,
tmpfs, and guest cleanup code
with fake syscall tests but no image claim.
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
  authenticated composition/admission release, serialized dispatch, bounded backpressure, loss while
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
