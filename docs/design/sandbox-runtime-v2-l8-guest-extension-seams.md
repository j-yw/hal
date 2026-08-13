# Sandbox Runtime v2 L8 Guest Extension and Ownership Seams

## Authority and scope

This is the normative D2 package-extension and ownership closure for
`sandbox-runtime-v2-l8-production-credential-delivery-architecture.md`. The
main architecture remains authoritative for the wire encodings, identity
fields, limits, state transitions, security properties, and D2 through D7
outcomes. If an implementation choice conflicts with this file, the
implementation is wrong unless both design files are deliberately revised.
Its normative HL8M controller-monitor ABI is also the sole authority for the
monitor extension packet, rights, sequence, correlation, and ownership
boundary; this supplement exposes only a typed capability seam over that ABI.

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

guestagent/v2control --------read-only------^                       controller codec authority

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
- `credentialhelper` may import `credentialprotocol` and the approved
  `credentialmemory` sink contract. `server/credentialclient` may import those
  two packages and has one additional one-way read-only
  `credentialclient -> v2control` edge so its controller arms reuse the exact
  closed operation, request, response, error, and scalar authorities. It does
  not redefine or migrate those authorities into `credentialprotocol`.
  `v2control` and its tests must not import `credentialclient`, directly or
  transitively; an AST import-cycle guard locks that reverse edge out. Helper
  and client never import one another or their child `sshrelay` package.
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

### Helper Service normative closure

This section closes the public lifecycle and live-runtime authority of the
privileged helper. It is normative over the earlier high-level seam. The
Service has one constructor and one Serve lifetime; terminal ownership is
reported as a value rather than hidden behind an error or a second wait path.

### Constructor and registry

`credentialhelper` exposes these exact construction shapes:

```go
type ServiceOptions struct {
	Core       Core
	Transport  Transport
	Policy     Policy
	Extensions *ExtensionRegistry
	Host       ExtensionHost
	Runtime    ServiceRuntime
}

func NewService(ServiceOptions) (*Service, error)
func (s *Service) Serve(context.Context) (ServiceResult, error)

type ServiceDisposition uint8
const (
	ServiceClosed         ServiceDisposition = 1
	ServiceStopVMRequired ServiceDisposition = 2
)

type ServiceResult struct {
	liveValue
	disposition ServiceDisposition
	closeReason credentialprotocol.CloseReason
}

func (r ServiceResult) Disposition() ServiceDisposition
func (r ServiceResult) CloseReason() credentialprotocol.CloseReason

type ExtensionRegistration struct {
	Descriptor credentialprotocol.ExtensionDescriptor
	Factory    ExtensionFactory
}

func NewExtensionRegistry(...ExtensionRegistration) (*ExtensionRegistry, error)
func (r *ExtensionRegistry) Descriptors() []credentialprotocol.ExtensionDescriptor
```

There is no public `Close` or `Wait` method. `Serve` returns `ServiceClosed`
only after an authenticated bilateral normal or shutdown close commits and all
Service-owned authority is proved absent. `ServiceClosed` is legal after either
committed bilateral `normal` or `shutdown`. It returns
`ServiceStopVMRequired` when in-process absence is unproved or a terminal
close/send/loss condition requires D6 to stop and reap the whole VM. A nil
error means the returned `ServiceResult` is structurally valid; it does not
turn stop-VM into success. `closeReason` is the exact safe closed
`credentialprotocol.CloseReason` selected by the terminal transition.

The exact D4 runtime boundary is:

```go
type ServiceRuntime interface {
	Bootstrap(context.Context) (ServiceBootstrap, error)
	BindAgent(context.Context, ServiceAgentBindingRequest, ReceivedCapability) error
	ObserveJob(context.Context, ServiceJobObservationRequest) (ServiceJobObservation, error)
	Loss() <-chan ServiceLoss
	BeginCleanup() (ServiceCleanupBudget, error)
	Close(context.Context) error
}

type ServiceBootstrap struct {
	liveValue
	bootNonce       [32]byte
	bootGeneration  credentialprotocol.SafeID
	helperGeneration credentialprotocol.SafeID
}

type ServiceAgentBindingRequest struct {
	liveValue
	agentIdentitySHA256      [32]byte
	bootstrapSHA256          [32]byte
	processDescriptorSHA256  [32]byte
	bootGeneration           credentialprotocol.SafeID
	helperGeneration         credentialprotocol.SafeID
}

type ServiceOperation uint8
const (
	ServiceOperationPrepare ServiceOperation = 1
	ServiceOperationExec    ServiceOperation = 2
	ServiceOperationRenew   ServiceOperation = 3
	ServiceOperationRevoke  ServiceOperation = 4
	ServiceOperationInspect ServiceOperation = 5
)

type ServiceJobObservationRequest struct {
	liveValue
	operation        ServiceOperation
	requestID        [16]byte
	identityDigest   [32]byte
	revision         uint64
	bootGeneration   credentialprotocol.SafeID
	helperGeneration credentialprotocol.SafeID
}

type ServiceJobObservation struct {
	liveValue
	generations       CoreGenerations
	observedUnixNano  int64
	hardExpiryUnixNano int64
}

type ServiceLossCategory uint8
const (
	ServiceLossAgent   ServiceLossCategory = 1
	ServiceLossJob     ServiceLossCategory = 2
	ServiceLossMonitor ServiceLossCategory = 3
	ServiceLossMount   ServiceLossCategory = 4
	ServiceLossCgroup  ServiceLossCategory = 5
)

type ServiceLoss struct {
	liveValue
	category ServiceLossCategory
}

type ServiceCleanupBudget interface {
	Context() context.Context
	Limit() time.Duration
	DeadlineExceeded() bool
	Close() error
}

func NewServiceBootstrap(
	bootNonce [32]byte,
	bootGeneration, helperGeneration credentialprotocol.SafeID,
) (ServiceBootstrap, error)
func (b ServiceBootstrap) BootNonce() [32]byte
func (b ServiceBootstrap) BootGeneration() credentialprotocol.SafeID
func (b ServiceBootstrap) HelperGeneration() credentialprotocol.SafeID

func (r ServiceAgentBindingRequest) AgentIdentitySHA256() [32]byte
func (r ServiceAgentBindingRequest) BootstrapSHA256() [32]byte
func (r ServiceAgentBindingRequest) ProcessDescriptorSHA256() [32]byte
func (r ServiceAgentBindingRequest) BootGeneration() credentialprotocol.SafeID
func (r ServiceAgentBindingRequest) HelperGeneration() credentialprotocol.SafeID

func (r ServiceJobObservationRequest) Operation() ServiceOperation
func (r ServiceJobObservationRequest) RequestID() [16]byte
func (r ServiceJobObservationRequest) IdentityDigest() [32]byte
func (r ServiceJobObservationRequest) Revision() uint64
func (r ServiceJobObservationRequest) BootGeneration() credentialprotocol.SafeID
func (r ServiceJobObservationRequest) HelperGeneration() credentialprotocol.SafeID

func NewServiceJobObservation(
	generations CoreGenerations,
	observedUnixNano, hardExpiryUnixNano int64,
) (ServiceJobObservation, error)
func (o ServiceJobObservation) Generations() CoreGenerations
func (o ServiceJobObservation) ObservedUnixNano() int64
func (o ServiceJobObservation) HardExpiryUnixNano() int64

func NewServiceLoss(category ServiceLossCategory) (ServiceLoss, error)
func (l ServiceLoss) Category() ServiceLossCategory

func ValidateServiceDisposition(ServiceDisposition) error
func (d ServiceDisposition) String() string
func ValidateServiceOperation(ServiceOperation) error
func (o ServiceOperation) String() string
func ValidateServiceLossCategory(ServiceLossCategory) error
func (c ServiceLossCategory) String() string
```

D4 constructs `ServiceBootstrap`, `ServiceJobObservation`, and `ServiceLoss`
only through those validating public constructors. Service constructs both
request types through package-private constructors, so D4 cannot mint an
expected binding or observation; their public methods are only the listed
fixed-array, safe-ID, scalar, and enum copy accessors. `ServiceResult` is minted
only through a private Service constructor and has no public constructor.
Every constructor rejects zero, unknown, invalid, or inconsistent fields.
The three closed enums accept only their listed values through the named
validators and expose only their canonical `String`; no enum parser, numeric
fallback, or generic serialization API is part of the contract. Every concrete
runtime request/result value has `liveValue` first, static safe formatting, and
the same value-and-pointer JSON/text/binary marshal and unmarshal denial,
seeded-receiver nonmutation and absence of exported fields
or mutators as the other live helper values. Bootstrap is called exactly once
before helper-ready.

BindAgent ownership is exact. After the authenticated bootstrap,
agent identity/digest, and process-descriptor checks, a nil `BindAgent` return
atomically transfers the sole bootstrap pidfd capability to Runtime. On error
or panic, Service retains that capability and closes it during drain. Runtime
independently validates the pinned process descriptor and bootstrap facts. No
descriptor or numeric PID accessor is exposed, and there is no ambiguous
non-nil-error transfer. Ambiguous transfer is forbidden.

The observation matrix is exact. `NewServiceJobObservation` requires all six
canonical nonempty generations,
`observedUnixNano > 0`, and `hardExpiryUnixNano >= observedUnixNano`. For every
observation, Service requires the request's Boot and Helper generations to
equal the exact Bootstrap Boot and Helper generations, and independently
requires operation, request ID, identity digest, and revision to equal its
current ledger. The first prepare latches the complete six-generation
observation and hard horizon. Every later observation must equal all six
latched generations and that exact hard horizon; observation time advances
monotonically and never regresses. A prepare or renew expiry must be in the
half-open interval `(observedUnixNano, hardExpiryUnixNano]`. Renew additionally
requires `revision == current revision + 1` and `expiry > the prior expiry`.
The runtime cannot extend or replace the hard horizon.

The loss-channel matrix is exact. `Loss` returns one stable non-nil receive-only
channel for the complete Service
lifetime. Exactly one valid nonzero `ServiceLoss` may be delivered, after which
the channel closes. A nil channel, close-before-value, or invalid value is
`ContractResultMatrix` and terminal `HelperLoss`. More than one value is
invalid for the same reason. Service owns exactly one loss watcher, cancels any
blocking receive during terminal
drain, and joins it before `Serve` returns. A missing, nil, typed-nil, unstable,
or malformed runtime result is a dependency contract failure, never an inferred
healthy state.

`BeginCleanup` is the sole cleanup-clock authority. It returns a fresh budget
whose `Context` is non-nil, whose `Limit` is exactly 30 seconds, and whose
deadline equals its creation time plus that fixed internal limit. No option,
caller context, environment value, or dependency may shorten, extend, reset,
or replace it. The budget is shared by one entire terminal cleanup, not renewed
per pass or resource. `DeadlineExceeded` is checked after every cleanup call
and before accepting absence. `Close` is called exactly once after cleanup,
under that same budget context, and the budget is then closed exactly once.
The 30-second contract requires conforming trusted dependencies to return under
the supplied context; it does not promise forced in-process return from an
arbitrary blocking implementation. Nonconformance or unknown absence yields
`ServiceStopVMRequired` and D6 kill/reap rather than a detached goroutine.

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
	BeginExec(context.Context, CoreExecRequest, credentialmemory.BorrowedView) (CoreExecution, error)
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
	GrantOutput(context.Context, CoreOutputRequest) error
	Next(context.Context) (CoreExecutionEvent, error)
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

`ReceiveRequest` supplies exact sequence and body/right budgets. The configured
D4 Transport receives directly into its own fixed-capacity locked mapping and
returns that mapping as the opaque body capability of the already decoded
`ReceivedPacket`; the packet owns no raw sensitive byte slice, and service
borrows then destroys the capability on every path. `SendPacket` is the service-built
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

### Core contract concrete closure

This section is the implementation authority for every named value in the
method sets above. It deliberately replaces the earlier prose-only field
description. The declarations below show the exact field order and field types;
all fields are private, have no tags, and are immutable after their validating
constructor returns. `liveValue` is the common zero-sized private marker whose
methods deny JSON, text, and binary marshal/unmarshal and render every `fmt`
verb as `credentialhelper.live[redacted]`. No request or result contains a raw
`[]byte`, path string, descriptor number, PID, socket address, environment,
proof token, `any`, map, or callback.

The shared concrete values are:

```go
type requestCorrelation struct {
	requestID      [16]byte
	identityDigest [32]byte
	revision       uint64
}

type CoreGenerations struct {
	boot    credentialprotocol.SafeID
	helper  credentialprotocol.SafeID
	job     credentialprotocol.SafeID
	monitor credentialprotocol.SafeID
	mount   credentialprotocol.SafeID
	cgroup  credentialprotocol.SafeID
}

type RelativePathCapability struct {
	liveValue
	length uint16
	bytes  [credentialprotocol.MaxRelativePathBytes]byte
}

type ManifestCapability struct {
	liveValue
	count   uint16
	records [credentialprotocol.MaxHelperBindings]manifestRecord
}

type manifestRecord struct {
	bindingID         credentialprotocol.SafeID
	mode              credentialprotocol.DeliveryMode
	target            RelativePathCapability
	declaredFileBytes uint32
	fileSHA256        [32]byte
}

type ExecPlanCapability struct {
	liveValue
	state *execPlanCapabilityState
}

type execPlanCapabilityState struct {
	mu            sync.Mutex
	encodedLength uint32
	sha256        [32]byte
	canonical     [credentialprotocol.MaxHelperExecPlanBytes]byte
	destroyed     bool
}

type CorePreparationCapability struct { liveValue; digest [32]byte }
type CorePreparedCapability struct    { liveValue; digest [32]byte }
type CoreExecutionCapability struct   { liveValue; digest [32]byte }
type CoreCleanupCapability struct     { liveValue; digest [32]byte }
```

`NewRelativePathCapability(path string) (RelativePathCapability, error)` is the
only public capability constructor. It accepts a present canonical relative
path under the exact `credentialprotocol` grammar; empty is rejected because a
`CoreFileRequest` always represents file mode. `Len() uint16` returns the exact
canonical byte length. `CopyTo(destination []byte) (int, error)` succeeds only
when `len(destination)` is exactly `Len`, copies without aliasing, and returns
that exact count. On nil, short, long, or otherwise failed destinations it
returns zero and clears `destination[:cap(destination)]`; there is no partial
success. Value copies are independent opaque copies and expose no string or
owned byte slice. Optional paths remain a manifest-codec concern: non-file
records use the zero capability, while every file record requires a nonzero
capability.

`ManifestCapability` is constructed by
`NewManifestCapability([]credentialprotocol.HelperBindingManifestRecord)
(ManifestCapability, error)` after the canonical codec validator succeeds. The
public constructor is required so trusted D4 Transport can project safe decoded
metadata; it mints no live/resource authority. It snapshots at most 16 records
into the fixed array. Its public methods are `Count() uint16`,
`Binding(index uint16) (credentialprotocol.SafeID,
credentialprotocol.DeliveryMode, RelativePathCapability, uint32, [32]byte,
bool)`, and `SHA256() [32]byte`; every return is a value copy. An out-of-range
index returns zero values and false. The core boundary then requires every
already codec-valid binding ID to pass `credentialprotocol.ValidateSafeID` and
stores that exact `SafeID`; a broader body token such as one containing `:` is
rejected before construction. Safe-ID narrowing is intentional: the generic
HL8P codec accepts a reusable body-token vocabulary, while the production job
identity and every core proof/binding ID use the narrower safe-ID grammar. The
manifest digest is still computed by the canonical helper manifest authority
over the exact accepted records.

`ExecPlanCapability` is constructed by
`NewExecPlanCapability(credentialprotocol.HelperExecPlan)
(ExecPlanCapability, error)` from an already canonical at-most-64-KiB plan. The
public constructor permits trusted D4 in-place decode to hand safe plan metadata
to the service; helper exec plans contain no credential binding bytes.
Its methods are `EncodedLength() uint32`, `SHA256() [32]byte`, and
`CopyCanonicalTo(credentialmemory.CredentialSink) error`. Copy is exact and
all-or-error; it never returns bytes. Value copies share synchronized destruction state.
`CopyCanonicalTo`, `EncodedLength`, `SHA256`, and the
service-only `destroy` transition serialize on that private mutex. `destroy` waits for any in-flight `CopyCanonicalTo` call,
then wipes the complete fixed
capacity with `clear` plus `runtime.KeepAlive`, zeros its safe metadata, and
latches destroyed. The service performs that transition after `BeginExec`
returns on every path. `EncodedLength` and `SHA256` return zero after destruction;
those accessors cannot return errors and must not retain or
disclose stale metadata. `CopyCanonicalTo` returns the stable
`ContractDestroyed` error without calling the sink. The sink call is
synchronous and the sink must not retain the borrowed slice after return.

The four core capability digests use this one exact encoding:

```text
SHA256(
  opaque16("hal/l8/guest-helper/core-capability/v1") ||
  u8(kind) || requestID[16] || identityDigest[32] || u64be(revision) ||
  opaque16(boot) || opaque16(helper) || opaque16(job) ||
  opaque16(monitor) || opaque16(mount) || opaque16(cgroup) ||
  bootNonce[32]
)
kind: preparation=1, prepared=2, execution=3, cleanup=4
```

The encoding retains all six generation positions in every kind. Preparation,
prepared, and prepare-cleanup capabilities use the partial generation tuple
and are all pre-minted from the prepare correlation:
they require boot/helper/job and encode monitor/mount/cgroup as empty
`opaque16` values. `CorePreparedResult` separately echoes and validates all six
observed generations after Commit; it does not retroactively change the
already-issued prepared-capability digest. The execution, exec-cleanup, and
revoke-cleanup capabilities require all six generations as nonempty safe IDs.

The prepared capability remains bound to its issuing Prepare correlation and
activation for that activation's lifetime. Its digest is not recomputed from a
later Exec, Renew, Revoke, or Inspect request ID or revision. Service records
the current activation entry and permits that exact prepared value to be echoed
only by those enumerated later operations. A prepared value from another
issuing Prepare correlation or activation is rejected. Prepare-cleanup remains
the internally initiated cleanup capability after Commit; the newly observed
complete generation tuple is carried in later requests but does not remint that
capability. A peer-initiated first Revoke instead mints the full-generation
revoke-cleanup capability described below.

There is no omitted suffix, delimiter, zero-ID alias,
alternate order, or kind cast. Their constructors are private to
`credentialhelper`; D4 receives and echoes them but cannot mint them. A zero,
changed, cross-kind, wrong issuing correlation under the prepared-capability
exception above, cross-generation, or cross-boot capability is rejected in
constant time before a core transition. The Service records each issuance in a
fixed lifecycle ledger; result acceptance consumes only the exact expected
entry when its lifecycle completes. These are process-local correlation
capabilities, not proof IDs, and never enter HL8P or durable state.

All redaction-safe proof labels are deterministic and nonsecret. Define
`Label(prefix, domain, payload)` as
`prefix || base64.RawURLEncoding(SHA256(opaque16(domain) || payload))`. The
prefix/domain pairs are exact:

```text
active.  / hal/l8/guest-helper/active-proof-label/v1
binding. / hal/l8/guest-helper/binding-proof-label/v1
exec.    / hal/l8/guest-helper/exec-proof-label/v1
cleanup. / hal/l8/guest-helper/cleanup-proof-label/v1
```

Thus the literal prefixes are `active.`, `binding.`, `exec.`, and `cleanup.`.
The common active/binding/exec payload is exactly
`bootNonce[32] || identityDigest[32] || u64be(revision) || opaque16(boot) ||
opaque16(helper) || opaque16(job) || opaque16(monitor) || opaque16(mount) ||
opaque16(cgroup) || i64be(expiresUnixNano) || manifestSHA256[32] ||
transactionSHA256[32]`. A binding label appends `u16be(bindingIndex) ||
opaque16(bindingID) || u8(mode)`. The cleanup payload is exactly boot nonce,
identity, revision, all six generations, `u8(revokeReason)`, manifest SHA-256,
transaction SHA-256, then the two exact bytes `authorityAbsent=1 ||
resourcesAbsent=1`; the reason byte occupies the common expiry position. No
dynamic hostname, path, PID, endpoint, secret, clock text, map order, or random
value enters a label.

An event ID is exact:

```text
eventDigest = SHA256(
  opaque16("hal/l8/guest-helper/event-id/v1") || bootNonce[32] ||
  identityDigest[32] || u64be(revision) || u8(eventCode) ||
  u32be(eventOrdinal)
)
header.requestID = eventDigest[0:16]
body.eventID = base64.RawURLEncoding(eventDigest[0:16]) // exactly 22 chars
```

The event ordinal is one Service-lifetime private nonzero monotonic `uint32`;
it never resets when identity changes and advances only when the event send
commits. There is no UUID, wall-clock, raw digest, or alternative
truncation.

The exact core request/result layouts are:

```go
type CorePrepareRequest struct {
	liveValue
	correlation     requestCorrelation
	generations     CoreGenerations // boot, helper, and job present; others zero
	expiresUnixNano int64
	fixedLimitSetID credentialprotocol.SafeID
	manifest        ManifestCapability
	manifestSHA256  [32]byte
	preparation     CorePreparationCapability
	prepared        CorePreparedCapability
	cleanup         CoreCleanupCapability
}

type CoreFileRequest struct {
	liveValue
	correlation requestCorrelation
	job         credentialprotocol.SafeID
	preparation CorePreparationCapability
	bindingID   credentialprotocol.SafeID
	bindingIndex uint16
	target      RelativePathCapability
	fileLength  uint32
	fileSHA256  [32]byte
}

type CoreCommitRequest struct {
	liveValue
	correlation      requestCorrelation
	job              credentialprotocol.SafeID
	preparation      CorePreparationCapability
	manifestSHA256   [32]byte
	transactionSHA256 [32]byte
	prepared         CorePreparedCapability
}

type CorePreparedResult struct {
	liveValue
	generations     CoreGenerations // all six present
	expiresUnixNano int64
	bindingCount    uint16
	manifestSHA256  [32]byte
	transactionSHA256 [32]byte
	prepared        CorePreparedCapability
}

type CoreExecRequest struct {
	liveValue
	correlation         requestCorrelation
	generations         CoreGenerations // all six present
	fixedLimitSetID     credentialprotocol.SafeID
	execBindingID       credentialprotocol.SafeID
	privateLength       uint32
	privateSHA256       [32]byte
	execBodyLength      uint32
	execBodySHA256      [32]byte
	plan                ExecPlanCapability
	prepared            CorePreparedCapability
	execution           CoreExecutionCapability
	cleanup             CoreCleanupCapability
}

type CoreRenewRequest struct {
	liveValue
	correlation     requestCorrelation
	generations     CoreGenerations // all six present
	expiresUnixNano int64
	prepared        CorePreparedCapability
}

type CoreRevokeRequest struct {
	liveValue
	correlation requestCorrelation
	generations CoreGenerations // all six present
	reason      credentialprotocol.RevokeReason
	prepared    CorePreparedCapability
	cleanup     CoreCleanupCapability
}

type CoreInspectRequest struct {
	liveValue
	identityDigest [32]byte
	revision       uint64
	generations    CoreGenerations // all six present
	prepared       CorePreparedCapability
}

type CoreOutputRequest struct {
	liveValue
	correlation requestCorrelation
	job         credentialprotocol.SafeID
	execution   CoreExecutionCapability
	kind        credentialprotocol.HelperExecStreamKind // stdout or stderr only
	offset      uint64
	capacity    uint32
}

type CoreOutputResult struct {
	liveValue
	execution  CoreExecutionCapability
	kind       credentialprotocol.HelperExecStreamKind
	offset     uint64
	byteCount  uint32
	sha256     [32]byte
	eof        bool
	truncated  bool
}

type CoreOutputBody interface {
	Len() uint32
	SHA256() [32]byte
	Borrow(context.Context, func(credentialmemory.BorrowedView) error) error
	Destroy(context.Context) error
}

type CoreExecutionEventKind uint8
const (
	CoreExecutionEventOutput   CoreExecutionEventKind = 1
	CoreExecutionEventComplete CoreExecutionEventKind = 2
)

type CoreExecutionEvent struct {
	liveValue
	kind     CoreExecutionEventKind
	output   CoreOutputResult
	body     CoreOutputBody
	complete CoreExecResult
}

type CoreExecExitCategory uint8
const (
	CoreExecExitExited   CoreExecExitCategory = 1
	CoreExecExitSignaled CoreExecExitCategory = 2
	CoreExecExitSetupFailed CoreExecExitCategory = 3
)

type CoreExecResult struct {
	liveValue
	execution             CoreExecutionCapability
	exitCategory          CoreExecExitCategory
	exitCode              int32
	stdinBytes            uint64
	stdinSHA256           [32]byte
	stdinTranscriptSHA256 [32]byte
	stdoutBytes           uint64
	stdoutSHA256          [32]byte
	stdoutTruncated       bool
	stderrBytes           uint64
	stderrSHA256          [32]byte
	stderrTruncated       bool
	execTransactionSHA256 [32]byte
}

func NewCoreExecutionOutputEvent(
	ctx context.Context, output CoreOutputResult, body CoreOutputBody,
) (CoreExecutionEvent, error)
func NewCoreExecutionCompleteEvent(CoreExecResult) (CoreExecutionEvent, error)
func (e CoreExecutionEvent) Kind() CoreExecutionEventKind
func (e CoreExecutionEvent) Output() (CoreOutputResult, CoreOutputBody, bool)
func (e CoreExecutionEvent) Complete() (CoreExecResult, bool)

type CoreCleanupCategory uint8
const (
	CoreCleanupComplete       CoreCleanupCategory = 1
	CoreCleanupRetryRequired  CoreCleanupCategory = 2
	CoreCleanupStopVMRequired CoreCleanupCategory = 3
)

type CoreCleanupResult struct {
	liveValue
	cleanup         CoreCleanupCapability
	category        CoreCleanupCategory
	authorityAbsent bool
	resourcesAbsent bool
}

type CoreInspectionState uint8
const (
	CoreInspectionPreparing CoreInspectionState = 1
	CoreInspectionPrepared  CoreInspectionState = 2
	CoreInspectionExecuting CoreInspectionState = 3
	CoreInspectionRevoking  CoreInspectionState = 4
	CoreInspectionAbsent    CoreInspectionState = 5
)

type CoreInspection struct {
	liveValue
	prepared          CorePreparedCapability
	state             CoreInspectionState
	generations       CoreGenerations
	expiresUnixNano   int64
	activeExecutions  uint16
	authorityPresent  bool
	resourcesPresent  bool
}
```

The exact validating constructors are `NewCorePrepareRequest`,
`NewCoreFileRequest`, `NewCoreCommitRequest`, `NewCoreExecRequest`,
`NewCoreRenewRequest`, `NewCoreRevokeRequest`, `NewCoreInspectRequest`, and
`NewCoreOutputRequest`; each takes its private fields in declaration order and
returns `(value, error)`. `NewCoreGenerations` constructs the exported opaque
projection `CoreGenerations`, whose only methods are `Boot`, `Helper`, `Job`,
`Monitor`, `Mount`, and `Cgroup`, each returning a
`credentialprotocol.SafeID` value copy. Constructors reject unused nonzero
generations and return the complete zero value on error.

```go
func NewCoreGenerations(
	boot, helper, job, monitor, mount, cgroup credentialprotocol.SafeID,
) (CoreGenerations, error)
func NewCorePrepareRequest(
	requestID [16]byte, identityDigest [32]byte, revision uint64,
	generations CoreGenerations, expiresUnixNano int64,
	fixedLimitSetID credentialprotocol.SafeID, manifest ManifestCapability,
	manifestSHA256 [32]byte, preparation CorePreparationCapability,
	prepared CorePreparedCapability, cleanup CoreCleanupCapability,
) (CorePrepareRequest, error)
func NewCoreFileRequest(
	requestID [16]byte, identityDigest [32]byte, revision uint64,
	job credentialprotocol.SafeID, preparation CorePreparationCapability,
	bindingID credentialprotocol.SafeID, bindingIndex uint16,
	target RelativePathCapability, fileLength uint32, fileSHA256 [32]byte,
) (CoreFileRequest, error)
func NewCoreCommitRequest(
	requestID [16]byte, identityDigest [32]byte, revision uint64,
	job credentialprotocol.SafeID, preparation CorePreparationCapability,
	manifestSHA256, transactionSHA256 [32]byte,
	prepared CorePreparedCapability,
) (CoreCommitRequest, error)
func NewCoreExecRequest(
	requestID [16]byte, identityDigest [32]byte, revision uint64,
	generations CoreGenerations, fixedLimitSetID, execBindingID credentialprotocol.SafeID,
	privateLength uint32, privateSHA256 [32]byte,
	execBodyLength uint32, execBodySHA256 [32]byte,
	plan ExecPlanCapability, prepared CorePreparedCapability,
	execution CoreExecutionCapability, cleanup CoreCleanupCapability,
) (CoreExecRequest, error)
func NewCoreRenewRequest(
	requestID [16]byte, identityDigest [32]byte, revision uint64,
	generations CoreGenerations, expiresUnixNano int64,
	prepared CorePreparedCapability,
) (CoreRenewRequest, error)
func NewCoreRevokeRequest(
	requestID [16]byte, identityDigest [32]byte, revision uint64,
	generations CoreGenerations, reason credentialprotocol.RevokeReason,
	prepared CorePreparedCapability, cleanup CoreCleanupCapability,
) (CoreRevokeRequest, error)
func NewCoreInspectRequest(
	identityDigest [32]byte, revision uint64, generations CoreGenerations,
	prepared CorePreparedCapability,
) (CoreInspectRequest, error)
func NewCoreOutputRequest(
	requestID [16]byte, identityDigest [32]byte, revision uint64,
	job credentialprotocol.SafeID, execution CoreExecutionCapability,
	kind credentialprotocol.HelperExecStreamKind, offset uint64, capacity uint32,
) (CoreOutputRequest, error)
```

D4 must be able to return results without gaining mint authority. The service
therefore pre-mints every nonzero `CorePreparationCapability`,
`CorePreparedCapability`, `CoreExecutionCapability`, and
`CoreCleanupCapability`, places it in the initiating request above, and records
it as issued in its private fixed lifecycle ledger. D4 obtains only value copies through
the request accessors and must return the matching value unchanged through:

```go
func NewCorePreparedResult(
	prepared CorePreparedCapability, generations CoreGenerations,
	expiresUnixNano int64, bindingCount uint16,
	manifestSHA256, transactionSHA256 [32]byte,
) (CorePreparedResult, error)
func NewCoreOutputResult(
	execution CoreExecutionCapability,
	kind credentialprotocol.HelperExecStreamKind, offset uint64,
	byteCount uint32, sha256 [32]byte, eof, truncated bool,
) (CoreOutputResult, error)
func NewCoreExecResult(
	execution CoreExecutionCapability,
	exitCategory CoreExecExitCategory, exitCode int32,
	stdinBytes uint64, stdinSHA256, stdinTranscriptSHA256 [32]byte,
	stdoutBytes uint64, stdoutSHA256 [32]byte, stdoutTruncated bool,
	stderrBytes uint64, stderrSHA256 [32]byte, stderrTruncated bool,
	execTransactionSHA256 [32]byte,
) (CoreExecResult, error)
func NewCoreCleanupResult(
	cleanup CoreCleanupCapability, category CoreCleanupCategory,
	authorityAbsent, resourcesAbsent bool,
) (CoreCleanupResult, error)
func NewCoreInspection(
	prepared CorePreparedCapability, state CoreInspectionState,
	generations CoreGenerations, expiresUnixNano int64,
	activeExecutions uint16, authorityPresent, resourcesPresent bool,
) (CoreInspection, error)
```

These public result constructors validate shape but do not mint: outside code
can construct only the zero capability or echo a nonzero capability it received
from the service. Each capability is issued once and never reassigned to another
lifecycle or correlation. It is not consumed on every valid echo. The service
accepts a mutating operation or result only
when its capability equals the exact issued value in constant time, is in the
expected transition, and has not completed its lifecycle. A zero, bit-changed,
wrong-kind, value from another issuing lifecycle/correlation, cross-generation,
or terminally consumed capability
is a contract violation. Successful commit consumes preparation; complete
execution consumes execution; complete or stop-VM cleanup consumes cleanup.
The prepared capability remains current while its prepared activation exists.

When cleanup returns `retry_required`, cleanup remains the sole live mutation
authority. The prepared capability remains as non-authoritative cleanup
correlation for repeat Revoke and Inspect; echoing it in those exact calls and
results neither reauthorizes admission nor consumes it. Multiple Inspect calls
may echo the same prepared value while the repeatable absence loop is active.
Terminal cleanup or Core Close ends both cleanup authority and that prepared
correlation. Every preparation/execution capability and every unrelated
prepared value is dead.
Rollback and Cancel return the cleanup capability retained by their owning
`CorePreparation` or `CoreExecution`. Capability digests are private
domain-separated SHA-256 values over kind, exact request correlation,
boot/helper/job generations, and boot nonce. They never enter a wire digest.

Every value has one accessor per field with the exported field spelling.
Accessors return scalar, fixed-array, or opaque value copies only. In
particular, request accessors include `RequestID`, `IdentityDigest`, `Revision`,
`Generations`, `ExpiresUnixNano`, `FixedLimitSetID`, `Manifest`,
`ManifestSHA256`, and the applicable `Preparation`, `Prepared`, `Execution`, or
`Cleanup`; field-specific accessors use the exact names in the declarations.
Result accessors similarly expose their safe scalar/digest metadata and echo
capability. No accessor returns a string, slice, pointer to internal state,
generic body, or live right.

The exact accessor method sets, in addition to `String`, `GoString`, `Format`,
and the fail-closed marshal/unmarshal methods supplied by `liveValue`, are:

```text
CoreGenerations: Boot, Helper, Job, Monitor, Mount, Cgroup -> SafeID
CorePrepareRequest: RequestID->[16]byte, IdentityDigest->[32]byte,
  Revision->uint64, Generations->CoreGenerations, ExpiresUnixNano->int64,
  FixedLimitSetID->SafeID, Manifest->ManifestCapability,
  ManifestSHA256->[32]byte, Preparation->CorePreparationCapability,
  Prepared->CorePreparedCapability, Cleanup->CoreCleanupCapability
CoreFileRequest: RequestID, IdentityDigest, Revision, Job->SafeID,
  Preparation->CorePreparationCapability, BindingID->SafeID,
  BindingIndex->uint16, Target->RelativePathCapability, FileLength->uint32,
  FileSHA256->[32]byte
CoreCommitRequest: RequestID, IdentityDigest, Revision, Job->SafeID,
  Preparation->CorePreparationCapability, ManifestSHA256->[32]byte,
  TransactionSHA256->[32]byte, Prepared->CorePreparedCapability
CorePreparedResult: Generations->CoreGenerations, ExpiresUnixNano->int64,
  BindingCount->uint16, ManifestSHA256->[32]byte,
  TransactionSHA256->[32]byte, Prepared->CorePreparedCapability
CoreExecRequest: RequestID, IdentityDigest, Revision,
  Generations->CoreGenerations, FixedLimitSetID->SafeID, ExecBindingID->SafeID,
  PrivateLength->uint32, PrivateSHA256->[32]byte, ExecBodyLength->uint32,
  ExecBodySHA256->[32]byte, Plan->ExecPlanCapability,
  Prepared->CorePreparedCapability, Execution->CoreExecutionCapability,
  Cleanup->CoreCleanupCapability
CoreRenewRequest: RequestID, IdentityDigest, Revision,
  Generations->CoreGenerations, ExpiresUnixNano->int64,
  Prepared->CorePreparedCapability
CoreRevokeRequest: RequestID, IdentityDigest, Revision,
  Generations->CoreGenerations, Reason->RevokeReason,
  Prepared->CorePreparedCapability, Cleanup->CoreCleanupCapability
CoreInspectRequest: IdentityDigest, Revision, Generations->CoreGenerations,
  Prepared->CorePreparedCapability
CoreOutputRequest: RequestID, IdentityDigest, Revision, Job->SafeID,
  Execution->CoreExecutionCapability, Kind->HelperExecStreamKind,
  Offset->uint64, Capacity->uint32
CoreOutputResult: Execution->CoreExecutionCapability,
  Kind->HelperExecStreamKind, Offset->uint64, ByteCount->uint32,
  SHA256->[32]byte, EOF->bool, Truncated->bool
CoreExecResult: Execution->CoreExecutionCapability,
  ExitCategory->CoreExecExitCategory, ExitCode->int32, StdinBytes->uint64,
  StdinSHA256->[32]byte, StdinTranscriptSHA256->[32]byte,
  StdoutBytes->uint64, StdoutSHA256->[32]byte, StdoutTruncated->bool,
  StderrBytes->uint64, StderrSHA256->[32]byte, StderrTruncated->bool,
  ExecTransactionSHA256->[32]byte
CoreCleanupResult: Cleanup->CoreCleanupCapability,
  Category->CoreCleanupCategory, AuthorityAbsent->bool, ResourcesAbsent->bool
CoreInspection: Prepared->CorePreparedCapability, State->CoreInspectionState,
  Generations->CoreGenerations, ExpiresUnixNano->int64,
  ActiveExecutions->uint16, AuthorityPresent->bool, ResourcesPresent->bool
```

Where a return type is omitted for the repeated `RequestID`, `IdentityDigest`,
or `Revision` spelling, it is exactly `[16]byte`, `[32]byte`, or `uint64`
respectively. There are no other public methods. `CorePreparedResult.Generations`
is D4-produced, validator-bounded safe observation metadata; it is not authority.
`NewCoreGenerations` merely validates safe IDs and cannot mint a core capability.
The independently service-minted `Prepared` value must be returned unchanged
and is the authority-bearing correlation checked against the fixed lifecycle ledger.

### Core value validation matrices

The constructors apply these exact shape rules before the service performs its
separate lifecycle-correlation checks for capability, request, generation, expiry, stream-continuity,
or sink-write correlation. Every request ID, identity digest, revision, safe
ID, required generation, and opaque capability is nonzero and valid. Every
content, manifest, transaction, transcript, or capability SHA-256 field is
nonzero except where an exact SHA-256 of empty bytes is required below. An
all-zero fixed digest is only the absent sentinel and is never a successful
content digest. A zero byte count uses the SHA-256 of empty bytes; a positive
byte count requires a nonzero digest. These rules do not claim that a digest is
proof: the service recomputes or correlates it at the owning transition.

`CorePreparedResult` requires all six generations, positive expiry, binding
count 1 through `credentialprotocol.MaxHelperBindings`, nonzero manifest and
transaction digests, and a nonzero prepared capability. Its generations,
expiry, count, digests, and capability must equal the exact successful commit
ledger before the result is accepted.

Core execution is a grant-driven CoreExecution event loop. Service grants one
stdout or stderr range with `GrantOutput`, concurrently supplies stdin through
`WriteStdin`, and serially consumes `Next` until the complete event. Core may
not return output without one exact outstanding grant, return completion while
a grant or stdin obligation remains, or retain a borrowed stdin view.

The CoreOutputResult matrix is exact:

| EOF | Byte count | SHA-256 | Truncated |
| --- | --- | --- | --- |
| false | 1 through `credentialprotocol.MaxHelperExecStreamPayloadBytes` | nonzero and equal to the payload bytes carried in the full `CoreOutputBody` | false only |
| true | exactly 0 | SHA-256 of empty bytes | false or true |

Every other combination is `ContractResultMatrix`. The execution capability is
nonzero and kind is stdout or stderr only. The service additionally requires
execution, kind, offset, capacity, count, digest, and event body to match the
exact outstanding `CoreOutputRequest`. `truncated=true` is carried only on the
unique EOF result after D4 drains bytes beyond the declared aggregate maximum;
the shape constructor cannot infer that maximum, so the service validates that
fact against its plan ledger.

`NewCoreExecutionOutputEvent` first rejects a nil context or a nil or typed-nil
`CoreOutputBody` before ownership transfer and before any body method call;
ownership transfers only after the non-nil context and non-nil, non-typed-nil
body preconditions pass. It then owns the full canonical `0x18` body and
requires its `Len` to be exactly `56 + CoreOutputResult.ByteCount()` and its
full-body SHA-256 to be nonzero and equal the complete canonical `0x18` body,
including all safe metadata and its payload.
It never accepts a payload-only body. The constructor uses the supplied
non-nil context to destroy that body on every validation error or panic; it
never substitutes `context.Background()`. On success the event is sole owner.
`Output` exposes the exact correlated output/body arm; wrong-arm access returns
zero/nil/false. Service calls the matching accessor once and remains responsible
for the shared body capability across event copies. Service dispatch validates
the grant, then borrows the full canonical body only long enough to send it and
destroys it on every result.

`NewCoreExecutionCompleteEvent` is metadata-only, contains exactly one valid
`CoreExecResult`, owns no body, and needs no cleanup context. `Complete`
exposes that correlated result; wrong-arm access returns zero/false. An event
cannot contain both arms or neither arm. `Kind` remains a pinned scalar. The
frozen struct has no extra owner pointer and makes no cross-copy one-shot
accessor claim.

The CoreExecResult matrix is exact: exit code is 0 through 255 for `exited`,
1 through 64 for `signaled`, and exactly 1 for `setup_failed`, which is a
stable category code rather than a raw errno. Each stdin/stdout/stderr byte
count is at most `credentialprotocol.MaxHelperExecStreamAggregateBytes`; zero
requires the SHA-256 of empty bytes and positive requires a nonzero digest. The
stdin transcript digest and exec transaction digest are always nonzero, because
the unique stdin EOF is committed even when stdin has no payload. Output
truncation booleans are shape-valid independently of the byte count; the service
accepts true only when the matching plan maximum was reached and excess output
was drained. The execution capability is nonzero. The complete event is
accepted only after the unique stdout and stderr EOF results, exact input
transaction finalization, and matching service-owned digest/count correlation.

The CoreCleanupResult matrix is exact:

| Category | Authority absent | Resources absent |
| --- | --- | --- |
| `cleanup_complete` | true | true |
| `retry_required` | true | false |
| `stop_vm_required` | false | false or true |
| `stop_vm_required` | true | false |

Thus `stop_vm_required` accepts exactly the other three boolean pairs and never
accepts true/true. `retry_required` is safe only after admission authority is
permanently absent while resources still require bounded cleanup. A nonzero
cleanup capability is mandatory. The service consumes it on complete or
stop-VM; retry leaves only that exact cleanup capability live as mutation
authority, while the exact prepared value remains available only as the
non-authoritative echo required by repeat Revoke and Inspect.

The CoreInspection matrix is exact. Every row requires the nonzero prepared
capability and all six nonzero generations from the inspect request:

| State | Expiry | Active executions | Authority present | Resources present |
| --- | --- | --- | --- | --- |
| `preparing` | positive | 0 | false | true |
| `prepared` | positive | 0 | true | true |
| `executing` | positive | 1 | true | true |
| `revoking` | positive | 0 or 1 | false | true |
| `absent` | exactly 0 | 0 | false | false |

Every other combination is `ContractResultMatrix`. A revoking observation may
still report the sole execution while cancellation is being confirmed, but it
cannot restore authority. An absent observation retains only safe correlation
generations and the echoed prepared capability; neither is live authority. The
service compares every returned generation and capability with the exact
inspect request and treats drift as terminal.

`CoreOutputRequest.capacity` is 1..64 KiB and kind is stdout or stderr; stdin is
rejected. `GrantOutput` admits exactly one range, and the subsequent output
event has at most that capacity; its payload count and digest must equal the
payload region in the owned full canonical `0x18` body. EOF has count zero and
SHA-256 of empty bytes. `WriteStdin` accepts the already-correlated execution, requires
offset continuity, accepts 1..64 KiB for non-EOF, and accepts an empty view only
for the unique EOF. The borrowed view is valid only for that call and cannot be
retained.

The `BeginExec` signature above is a deliberate correction to the prose-only
seam. Its borrowed view is the sole private HTTP-binding input and remains
excluded from `CoreExecRequest`. The interface value is nil if and only if
`privateLength` is zero and `privateSHA256` is zero. A typed-nil view is rejected
before any method call. For nonzero private length, a non-nil view whose `Len()`
exactly equals `privateLength` is mandatory and its digest was already checked
by the service. Core may synchronously call `CopyTo` or `WriteTo` only during
`BeginExec`; it must not retain or use the view after return. The service full-
capacity wipes and destroys the source on every result, including validation
and Core errors. A zero/nonzero mismatch fails before D4 can create a pipe,
child, gate, or pidfd.

The exec transcript starts from one reusable, one-shot seed in package
`credentialprotocol`:

```go
type HelperExecTransactionSeed struct {
	// exactly one private shared owner pointer
}

func NewHelperExecTransactionSeed(
	HelperExecTransactionCorrelation, HelperExecBody,
) (HelperExecTransactionSeed, error)
func (s *HelperExecTransactionSeed) Begin() (*HelperExecTransaction, error)
func (s *HelperExecTransactionSeed) BeginComparison(
	HelperExecTransactionResult,
) (*HelperExecTransaction, error)
func (s *HelperExecTransactionSeed) Close()
```

`NewHelperExecTransactionSeed` retains only safe correlation/scalars, the exact
canonical `0x15` body length and SHA-256, and a cloned initialized hash state.
It retains no string, exec plan, body, borrowed view, owned byte slice, live
handle, or resource authority. Its one temporary canonical encoding is wiped
through full capacity before constructor return. Value aliases share one mutex,
one-use state, and closed state. Exactly one of `Begin` or `BeginComparison`
may succeed across all aliases. `BeginComparison` first validates the complete
safe cached result against the seed and produces only the existing comparison-
only transaction. `Close` is idempotent, prevents either begin method, and
wipes correlation and cloned hash state. A successful begin transfers those
values into the transaction and leaves the seed consumed and empty.

### Transport packet concrete closure

Transport operates on closed capabilities, never generic datagrams:

```go
type ReceivedCapabilityKind uint8
const (
	ReceivedCapabilityAgentPIDFD ReceivedCapabilityKind = 1
	ReceivedCapabilitySSHConnection ReceivedCapabilityKind = 2
)
type ReceivedCapability interface {
	Kind() ReceivedCapabilityKind
	SHA256() [32]byte
	Close(context.Context) error
}
type ReceivedBodyCapability interface {
	Len() uint32
	SHA256() [32]byte
	Borrow(context.Context, func(credentialmemory.BorrowedView) error) error
	Destroy(context.Context) error
}
type ReceivedKernelCredential struct {
	liveValue
	pid uint32
	uid uint32
	gid uint32
}
type ReceiveRequest struct {
	liveValue
	nextSequence uint64
	maximumBodyBytes uint32
	expectedRights uint32
	state *receiveRequestState
}
type ReceivedPacket struct {
	liveValue
	header credentialprotocol.HelperPacketHeader
	arm receivedPacketArm
	credential ReceivedKernelCredential
	body ReceivedBodyCapability
	right ReceivedCapability
}
type SendPacket struct {
	liveValue
	header credentialprotocol.HelperPacketHeader
	arm sendPacketArm
	right ReceivedCapability
}
```

The only receive constructor and exact Transport accessor set are:

```go
func NewReceiveRequest(nextSequence uint64, maximumBodyBytes,
	expectedRights uint32) (ReceiveRequest, error)
func (r ReceiveRequest) NextSequence() uint64
func (r ReceiveRequest) MaximumBodyBytes() uint32
func (r ReceiveRequest) ExpectedRights() uint32
```

Maximum body is 0..72 KiB and expected rights is exactly zero or one, retained
as `uint32` so actual kernel cardinality is never narrowed. `state` is a private
one-shot atomic consumed latch; all value copies share it. Exactly one
`NewReceived<Arm>Packet` call may seal it. Reuse returns `ContractOwnership`.

D4 Transport owns one fixed-capacity anonymous locked mapping per receive slot
and passes that mapping directly to its `recvmsg` adapter as the datagram
destination. No `credentialmemory.CredentialSink`, ordinary heap `[]byte`, or
second mutable payload slot is used. After exact datagram length, truncation,
header, credentials, ancillary count, and safe metadata decode in that mapping,
D4 wraps only the body subrange of that same full-datagram mapping as
`ReceivedBodyCapability`. Its `Len`, `SHA256`, and `Borrow` address body bytes
only; no header or ancillary storage is borrowable by Core. `Borrow` supplies a scoped
`credentialmemory.BorrowedView`, and `Destroy` full-capacity overwrites,
unlocks, and unmaps exactly once. Value copies share borrow/destroy state;
destroy waits for an active borrow and later borrow/destroy returns the stable
destroyed result. The callback is a method of the private live capability, not
caller-selected request/result behavior; service supplies only its fixed
StageFile/BeginExec/WriteStdin closure. It is fixed package code, never a
caller-supplied callback, and cannot escape or retain the view. All safe
metadata parsing from the locked mapping completes before arm construction.

Configured D4 Transport is explicitly the sole trusted issuer of
`ReceivedCapability` and `ReceivedBodyCapability`. These interfaces are
publicly implementable only for that injected boundary; helper code does not
claim it can recognize an implementation from their methods. Service validates
typed nil, body bound/length/digest, closed right kind, nonzero right digest,
arm cardinality, correlation, and ownership. A malicious configured Transport
is inside the guest helper TCB.
`ReceivedCapabilityAgentPIDFD` is legal only on inbound bootstrap and never on
`SendPacket`. `ReceivedCapabilitySSHConnection` is legal only on outbound SSH
accepted and never on a received packet. Every other packet has no right.

`NewReceivedKernelCredential(pid, uid, gid uint32)
(ReceivedKernelCredential, error)` is the sole public constructor for one
kernel observation. PID is 1..`math.MaxInt32`, the positive Linux `pid_t`
range; UID/GID are exact unsigned kernel
values, including zero. It has private fields and no PID/UID/GID or generic
accessor; formatting and serialization fail closed. D4 constructs it only from
an exact-size kernel `struct ucred`. Service accesses private fields to compare
the already-pinned expected role identity and enforce exact PID1, controller,
or agent role plus distinct-role inequality. It is equality metadata, never
authority or durable identity.

Received arms are private-field non-JSON values named `ReceivedBootstrap`,
`ReceivedAgentHello`, `ReceivedPrepareBegin`, `ReceivedPrepareFile`,
`ReceivedPrepareCommit`, `ReceivedRenew`, `ReceivedRevoke`, `ReceivedExec`,
`ReceivedExecPrivate`, `ReceivedExecStream`, `ReceivedExecCredit`, and
`ReceivedCloseNotify`. They contain only the corresponding safe codec metadata;
sensitive payloads stay in the locked body capability, paths become `RelativePathCapability`,
and plans become `ExecPlanCapability`. Bootstrap numeric identity and renew
proof strings are accepted transiently and stored only as private equality
digests with no numeric/string accessor.

The two transaction-start arms reuse the existing credentialprotocol FSMs
rather than duplicating them in Service:

```go
type ReceivedPrepareBegin struct {
	liveValue
	revision      uint64
	expiryUnixNano int64
	manifest      ManifestCapability
	transaction *credentialprotocol.HelperPrepareTransaction
}

type ReceivedExec struct {
	liveValue
	revision        uint64
	execBindingID    credentialprotocol.SafeID
	privateLength    uint32
	privateSHA256    [32]byte
	plan             ExecPlanCapability
	transactionSeed credentialprotocol.HelperExecTransactionSeed
}
```

`NewReceivedPrepareBeginPacket` constructs the exact prepare transaction
correlation from the authenticated header/body and starts the existing
`credentialprotocol.HelperPrepareTransaction` while decoded metadata is in
scope. Service privately takes that pointer; there is no public transaction or
seed accessor. Prepare-file dispatch uses the existing safe
`credentialprotocol.HelperPrepareFileObservation` and
`AcceptObservedFileObservation`, while the sole private payload remains the
ReceivedPacket body. It never creates a second private-body owner or a second
prepare FSM. Replays use a fresh prepare transaction and compare the final
manifest and transaction digests with the cached result.

`NewReceivedExecPacket` verifies the canonical received bytes against the
decoded `credentialprotocol.HelperExecBody`, constructs the safe plan and
`credentialprotocol.HelperExecTransactionSeed` while that decoded body is in
scope, and then retains no decoded plan strings or body bytes. The public safe accessors are
only Revision, ExecBindingID, PrivateLength, PrivateSHA256, and Plan. After the
cache lookup, Service privately chooses seed `Begin` or `BeginComparison`; it
does not build a second exec transaction state machine.

Thus the prepare arm retains a private
`*credentialprotocol.HelperPrepareTransaction`, and the exec arm retains a
private `credentialprotocol.HelperExecTransactionSeed`; neither is exposed by a
public accessor.

Those two private equality digests have one exact encoding. They are not proof,
resource authority, or durable identity:

```text
agentIdentitySHA256 = SHA256(
  opaque16("hal/l8/guest-helper/agent-identity/v1") ||
  agentPID:u32 || agentUID:u32 || agentGID:u32)

priorProofSHA256 = SHA256(
  opaque16("hal/l8/guest-helper/renew-proof/v1") ||
  opaque16(priorProofID))
```

Every `u32` is unsigned big-endian and every `opaque16` is the common unsigned
big-endian 16-bit byte length followed by exact bytes. The bootstrap input PID
is already restricted to 1 through `math.MaxInt32`; UID and GID retain their
full unsigned kernel values. `priorProofID` must first pass the safe-ID grammar.
No other domain, scalar order, text rendering, delimiter, or normalization is
accepted.

D4 constructs the union only through:

```go
func NewReceivedBootstrapPacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	uint32, uint32, uint32, credentialprotocol.SafeID,
	credentialprotocol.SafeID, ReceivedCapability) (ReceivedPacket, error)
func NewReceivedAgentHelloPacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	[32]byte, credentialprotocol.SafeID, credentialprotocol.SafeID,
	[32]byte) (ReceivedPacket, error)
func NewReceivedPrepareBeginPacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	credentialprotocol.HelperPrepareBeginBody, ManifestCapability) (ReceivedPacket, error)
func NewReceivedPrepareFilePacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	uint64, uint16, uint32, [32]byte) (ReceivedPacket, error)
func NewReceivedPrepareCommitPacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	credentialprotocol.HelperPrepareCommitBody) (ReceivedPacket, error)
func NewReceivedRenewPacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	uint64, int64, credentialprotocol.SafeID) (ReceivedPacket, error)
func NewReceivedRevokePacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	credentialprotocol.HelperRevokeBody) (ReceivedPacket, error)
func NewReceivedExecPacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	decoded credentialprotocol.HelperExecBody, plan ExecPlanCapability) (ReceivedPacket, error)
func NewReceivedExecPrivatePacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	uint64, uint32, [32]byte) (ReceivedPacket, error)
func NewReceivedExecStreamPacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	uint64, credentialprotocol.HelperExecStreamKind,
	credentialprotocol.HelperExecStreamFlags, uint64, uint32, [32]byte) (ReceivedPacket, error)
func NewReceivedExecCreditPacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	credentialprotocol.HelperExecCreditBody) (ReceivedPacket, error)
func NewReceivedCloseNotifyPacket(context.Context, ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	credentialprotocol.HelperCloseNotifyBody) (ReceivedPacket, error)
```

There is no separate descriptor-length constructor argument for
`NewReceivedAgentHelloPacket`. The constructor reads the canonical body-owned
`descriptorLength:u16` in place, requires 1 through `MaxProcessDescriptorBytes`,
requires that it equal the exact remaining bytes, and compares SHA-256 of those
bytes with the final independently validated descriptor digest argument. This
keeps the wire length under the locked-body authority and prevents a second
caller-supplied scalar from disagreeing with it.

The last agent-hello digest is the independently validated canonical process
descriptor digest. Prepare-file, exec-private, and exec-stream constructors
bind their sensitive payload in the body capability and retain metadata only.
The first `uint32` after `ReceivedKernelCredential` is the actual credentials
record count and must be exactly one. The `uint32` after the body is actual
rights count; only bootstrap's
final argument may be a non-nil agent-pidfd right. Each constructor atomically
seals its first request and validates header/type/sequence/body length,
identity/nonce, body length/digest, actual credential/right counts, closed
fields, right kind, and cardinality. Service independently compares the private
credential with its exact pinned role before dispatch. Sensitive constructors recompute and compare exact
private payload length/digest in place before transfer. Failure destroys the
full body capability and closes the right. Success makes `ReceivedPacket` owner
of both the exact body mapping and right.

`ReceivedPacket` public methods are only `Type()
credentialprotocol.PacketType`, `Header() credentialprotocol.HelperPacketHeader`, and the
exact typed arms `Bootstrap() (ReceivedBootstrap,bool)`, `AgentHello()`,
`PrepareBegin()`, `PrepareFile()`, `PrepareCommit()`, `Renew()`, `Revoke()`,
`Exec()`, `ExecPrivate()`, `ExecStream()`, `ExecCredit()`, and `CloseNotify()`
with analogous `(Received<Arm>,bool)` results. Each arm has only value-copy
accessors corresponding in order to its constructor arguments after the
header. Wrong-arm access is zero/false. Transport owns a right until a valid
return; service owns the private credential/body/right fields thereafter. There
is no public credential, body, or right accessor; only code in
`credentialhelper` performs comparison, borrow, transfer, wipe, or close. The
service borrows a sensitive
body directly into the matching Core call, then destroys it on every success,
error, rejection, cancellation, or panic path. Non-sensitive bodies are
destroyed immediately after their safe arm is constructed. No private payload
is copied to an ordinary heap allocation.

`SendPacket` has no public constructor. Service uses only
`newHelperReadyPacket`, `newBootstrapAckPacket`, `newAgentHelloAckPacket`,
`newSSHAcceptedPacket`, `newExecCreditPacket`, `newExecStreamPacket`,
`newResponsePacket`, `newEventPacket`, and `newCloseNotifyPacket`, all delegated
through private `newSendPacket`. Its exact Transport method set is
`Type() credentialprotocol.PacketType`, `Header()
credentialprotocol.HelperPacketHeader`, `EncodedBodyLength() uint32`,
`BodySHA256() [32]byte`,
`WriteCanonicalBody(context.Context, credentialmemory.CredentialSink) error`, `RightsCount()
uint32`, and `Right() ReceivedCapability`. No generic arm or bytes are exposed.
The configured Transport is the sole consumer of `Right`; it exists only for
the D4 `sendmsg` adapter and exposes no credential-body capability to an
extension.

This is the pre-production safe-metadata transmit scratch correction. Every
non-stream send constructor first validates and takes a deep immutable snapshot
of the complete typed arm, including every pointed-to result and binding-proof
slice. It derives and pins the exact canonical length and SHA-256 from that
snapshot. A later caller mutation cannot change either value or the emitted
body. `WriteCanonicalBody` may encode that redaction-safe metadata body into
one bounded transient ordinary-heap scratch, copy it synchronously into
Transport's one fixed locked transmit slot, and overwrite the scratch through
full capacity immediately after construction, hashing, or copying on every
success and error path. Private file, opaque-exec, stdin, stdout, and stderr
payload bytes never use that scratch: their body capability is copied directly
into the locked transmit slot and destroyed under the service/Transport
ownership rule.

Transport calls `WriteCanonicalBody` exactly once for a send, passing the
operation context before drain and the one shared cleanup-budget context after
drain begins. It rejects a nil context before touching ownership. Context is
checked before and after each borrow, copy, or destroy; cancellation cannot
abandon ownership. No send constructor, validator, or write path uses
`context.Background()` or `context.TODO()`. Context-aware private send
constructors that take or borrow a live body/right also take a leading non-nil
`context.Context` and own the supplied capability on entry. The constructor
uses that exact context to clean constructor failure. A successful fill
transfers ownership of the exact encoded slot to Transport. Transport
retains that slot across a nonblocking retry and must not call
`WriteCanonicalBody` again for `EAGAIN`; it sends the same pinned body length
and SHA-256, advances sequence only after commit, and overwrites the slot
through full capacity after committed send or every terminal error. Send uses
values synchronously and retains no caller-owned alias. Service owns body/right
until nil return; error wipes and closes. Only SSH accepted has one right.
Wrong direction/sequence/identity/nonce, typed nil, unknown arm, or matrix
mismatch fails before I/O.

### Policy concrete closure

```go
type PolicyOperation uint8
const (
	PolicyOperationPrepare PolicyOperation = 1
	PolicyOperationExec    PolicyOperation = 2
	PolicyOperationRenew   PolicyOperation = 3
	PolicyOperationRevoke  PolicyOperation = 4
	PolicyOperationInspect PolicyOperation = 5
)

type PolicyRejectionCode uint8
const (
	PolicyRejectionMalformed          PolicyRejectionCode = 1
	PolicyRejectionIdentityMismatch   PolicyRejectionCode = 2
	PolicyRejectionRevisionStale      PolicyRejectionCode = 3
	PolicyRejectionExpired            PolicyRejectionCode = 4
	PolicyRejectionResourceLimit      PolicyRejectionCode = 5
	PolicyRejectionManifestMismatch   PolicyRejectionCode = 6
	PolicyRejectionGenerationMismatch PolicyRejectionCode = 7
	PolicyRejectionOperationDenied    PolicyRejectionCode = 8
)

type PolicyRequest struct {
	liveValue
	operation        PolicyOperation
	correlation      requestCorrelation
	generations      CoreGenerations
	expiresUnixNano  int64
	fixedLimitSetID  credentialprotocol.SafeID
	manifest         ManifestCapability
	manifestSHA256   [32]byte
	execBodyBytes    uint32
	execBodySHA256   [32]byte
	privateBytes     uint32
	privateSHA256    [32]byte
}

type PolicyDecision struct {
	liveValue
	allow         bool
	rejectionCode PolicyRejectionCode
}

type PolicyDescriptor struct {
	liveValue
	id     credentialprotocol.SafeID
	digest [32]byte
}
```

The exact constructor and accessor set is:

```go
func NewPolicyRequest(operation PolicyOperation, requestID [16]byte,
	identityDigest [32]byte, revision uint64, generations CoreGenerations,
	expiresUnixNano int64, fixedLimitSetID credentialprotocol.SafeID,
	manifest ManifestCapability, manifestSHA256 [32]byte,
	execBodyBytes uint32, execBodySHA256 [32]byte,
	privateBytes uint32, privateSHA256 [32]byte) (PolicyRequest, error)
func (r PolicyRequest) Operation() PolicyOperation
func (r PolicyRequest) RequestID() [16]byte
func (r PolicyRequest) IdentityDigest() [32]byte
func (r PolicyRequest) Revision() uint64
func (r PolicyRequest) Generations() CoreGenerations
func (r PolicyRequest) ExpiresUnixNano() int64
func (r PolicyRequest) FixedLimitSetID() credentialprotocol.SafeID
func (r PolicyRequest) Manifest() ManifestCapability
func (r PolicyRequest) ManifestSHA256() [32]byte
func (r PolicyRequest) ExecBodyBytes() uint32
func (r PolicyRequest) ExecBodySHA256() [32]byte
func (r PolicyRequest) PrivateBytes() uint32
func (r PolicyRequest) PrivateSHA256() [32]byte
```

Prepare requires a nonempty manifest, positive expiry and exact manifest
digest; both exec/private pairs are zero. Exec requires the exact prepared
manifest, a 1..72-KiB canonical exec body with nonzero digest, and either a
zero/zero private pair or 1..64 KiB with nonzero digest. Renew requires positive
expiry and empty manifest/body pairs. Revoke and inspect require empty expiry,
manifest, and body pairs. Packet operations require nonzero request ID and
identity; inspect requires zero request ID and nonzero identity. Every operation
requires positive revision, its operation-required safe generations, and exact
`helper-limits-v1`; unused fields are exactly zero.

`newPolicyAllowDecision()` and `newPolicyRejectionDecision(code)` are the sole
production decision constructors. Allow is exactly `allow=true, code=0`;
rejection is exactly `allow=false` plus one known nonzero code. Every other
combination is invalid. `Allowed()` and `RejectionCode()` are the only decision
accessors. The sole production implementation is returned by
`NewHelperPolicy() Policy`; it has no options and is deny-by-default. It allows
only already-correlated canonical metadata whose operation-specific shape,
manifest, body/private bounds, and fixed limit set equal `helper-limits-v1`.
Policy can return only malformed, resource-limit, manifest-mismatch, or
operation-denied. The service owns identity, next-revision, generation, and
expiry comparison before calling Policy and constructs identity-mismatch,
revision-stale, generation-mismatch, or expired decisions without a Policy
call. The first failing service check is identity, revision, generation, then
expiry; the first Policy check is closed operation, shape, fixed limits, then
manifest. Neither service nor Policy reads a clock at this seam: a later
clock-owning state-machine slice supplies the exact expiry-admitted fact.

The helper descriptor is constructed only by `newHelperPolicyDescriptor()` and
is exactly ID `helper-policy-v1` plus
`SHA256(opaque16("hal/l8/process-policy/v1") ||
opaque16("helper-policy-v1"))`. `ID()` and `SHA256()` return safe value copies.
Unknown ID, zero/wrong digest, a descriptor that changes across two reads, nil,
or typed-nil policy is constructor failure. Authorization errors never become
allow; a returned invalid decision or non-nil error is a stable policy contract
failure and closes/revokes the session.

### Core transition and failure matrices

All constructors, validators, dependency checks, return-matrix checks, and
ownership checks use this closed sanitized error catalog:

```go
type ContractErrorCode uint8
const (
	ContractInvalidArgument ContractErrorCode = 1
	ContractTypedNil       ContractErrorCode = 2
	ContractCorrelation    ContractErrorCode = 3
	ContractTransition     ContractErrorCode = 4
	ContractCapability     ContractErrorCode = 5
	ContractOwnership      ContractErrorCode = 6
	ContractResultMatrix   ContractErrorCode = 7
	ContractDependency     ContractErrorCode = 8
	ContractDestroyed      ContractErrorCode = 9
)

type ContractError struct { liveValue; code ContractErrorCode }
func (e ContractError) Code() ContractErrorCode
func (e ContractError) Error() string
```

`Error` returns only `credential helper contract <canonical-code>` where the
canonical spellings are `invalid_argument`, `typed_nil`, `correlation`,
`transition`, `capability`, `ownership`, `result_matrix`, `dependency`, and
`destroyed`. There is exactly one package sentinel `ErrContract<Spelling>` for
each code and `ContractError.Is` matches only its own sentinel/code. No error
contains an index, identifier, digest, generation, candidate type, raw cause,
or formatted value. Invalid enum/length/bound/zero-required input maps to
`invalid_argument`; any interface whose dynamic nil-capable value is nil maps
to `typed_nil`; mismatches and state errors map to the correspondingly named
codes above. Metadata-only constructors return the complete zero value with the
exact error and preserve every input. Every constructor that accepts a live
body or right has a leading non-nil `context.Context`; ownership transfers on
constructor entry, and the constructor synchronously destroys/closes the owned
capability with that supplied context on every failure or panic. It never uses
`context.Background()` or `context.TODO()` and never returns live ownership to
the caller after entry.

The service calls only these transitions:

```text
absent -> BeginPrepare -> staging
staging -> StageFile* in ascending manifest index -> Commit -> prepared
staging -> Rollback -> absent | cleanup-retry | stop-VM
prepared -> Renew -> prepared
prepared -> BeginExec -> executing
executing -> WriteStdin/GrantOutput/Next* -> complete event -> prepared
executing -> Cancel -> prepared | cleanup-retry | stop-VM
prepared/executing/staging -> Revoke -> absent | cleanup-retry | stop-VM
prepared/retrying -> Inspect -> same state or conservative cleanup escalation
any terminal service drain -> Close exactly once
```

There is one preparation and one execution at a time. A repeated identical
completed request uses service-owned safe result cache metadata and does not
call Core again. A changed request/capability, stale/gapped revision, invalid
transition, out-of-order file, stream gap, second EOF, or cross-generation
value fails before a method call. `retry_required` retains ownership and only
`Inspect`, `Revoke`, `Rollback`, or `Cancel` may retry; it never recreates.
`stop_vm_required` is terminal and cannot be downgraded.

`Core`, `Transport`, `Policy`, every returned `CorePreparation` or
`CoreExecution`, each sink, borrowed view, result builder, extension, and live
capability uses the common typed-nil rule before any method call. Interface nil
or typed nil plus nil error is a contract violation. Interface nil plus non-nil
error is an ordinary safe failure. Non-nil plus non-nil error is a contract
violation; the service invokes the narrow rollback/cancel/close operation when
callable, then preserves the stricter cleanup result. A panic is not recovered
as success. Validation/policy failures perform no Core call. Core failures map
only to the matching stable HL8P failure code; raw errors and capability values
are never formatted. Serve caller cancellation latches drain; `Serve` then
waits for bounded cleanup by conforming dependencies and returns the terminal
Service result. Caller cancellation never abandons ownership or creates an
unbounded detached cleanup task.

### Service ledgers, cleanup, and terminal result

Service state uses fixed storage only. It has a fixed 4,096-entry non-exec
ledger: entries 0..4092 admit Prepare and Renew request correlations, while the
last three slots are reserved for fresh Revoke request IDs. A
non-Revoke operation can never consume a reserved slot. It also has a separate
fixed 4,096-entry exec ledger. Neither ledger grows, evicts, wraps, reuses a
request ID, or allocates a map. Each entry records only safe request
correlation, canonical request/result digests, disposition, and the exact
lifecycle-correlation capability digests required for replay or cleanup.
Repeated exact requests use comparison-only state; a changed request with the
same ID is a conflict and never calls Core or an extension.

Cross-ledger same-ID reuse is rejected before charging; an exact replay
consumes no slot. Service charges a first-seen ID before mutation. Prepare and
Renew can admit at most 4,093 distinct non-exec IDs; Revoke never consumes
those general slots. The three reserved Revoke entries are the at-most-three
fresh peer-driven cleanup attempts. After they are exhausted cleanup is already
terminal stop-VM and no fresh request is admitted. A fresh Revoke after
`cleanup_retry` is an outer wire retry trigger: it has a new request ID for
transport, replay-cache, policy, runtime-observation, and response correlation,
but it never replaces or remints the retained cleanup capability.

The first accepted peer Revoke establishes the first internal cleanup
correlation and mints its full-generation revoke-cleanup capability. Every
later fresh-ID Revoke must have the same identity, revision, reason, and active
activation; Service charges its reserved outer ledger entry, but constructs
repeat Core Revoke and Inspect calls with that first internal cleanup
correlation, exact prepared echo, and retained cleanup capability. A duplicate
outer request replays only its cached response and runs no absence work. A
changed same-ID request, changed cleanup fields, or fourth distinct attempt is
terminal. The outer request ID is never substituted into the retained Core
capability ledger.

An internally driven cleanup episode has no outer Revoke trigger. Pre-commit
failure and prepared/post-commit failure use the retained prepare-cleanup
capability bound to the issuing Prepare; an active-exec cancellation first uses
its exec-cleanup capability and then the retained prepare-cleanup correlation
for remaining prepared-activation cleanup. Caller cancellation, dependency
failure, loss, or send ambiguity drives its bounded passes immediately and does
not consume a reserved Revoke slot or expose `cleanup_retry` to a peer.

A distinct Prepare or Exec received after its admissible capacity is exhausted
has all declared input fully consumed and drained without a Core/extension
mutation. While IPC is unambiguously usable, Service best-effort emits
`rejected/resource_limit`, then immediately enters mandatory drain and returns
`ServiceStopVMRequired` with `helper_loss` and the existing sanitized
`ContractTransition` for the mandatory exhausted-state transition unless a
stricter cleanup Contract error overrides it. Renew has no
resource-limit wire row; its overflow instead best-effort emits
`stop_vm_required/helper_unavailable`, then enters the same mandatory drain.
If cleanup or absence becomes uncertain,
`stop_vm_required/cleanup_incomplete` and its terminal reason override that
initial overflow response.

The overflow ID is the sole terminal overflow exception: it is not inserted or
cached and has no idempotent replay promise. No later job request is admitted.
It cannot create a successful operation, evict a tombstone, consume reserved
Revoke capacity, or mutate job/extension state. This is the only exception to
charging a first-seen ID before mutation and avoids pretending a 4,097th ID can
fit in a 4,096-entry ledger.

One cleanup episode uses one budget. Its exact three-pass cleanup protocol is
split into at most three repeatable absence passes followed by exactly one
one-time finalization pass. Before the first absence pass, Service denies exec,
extension accepts, publication, and every ordinary packet. A peer-driven
cleanup episode permits only the next fresh-ID Revoke after a committed
`cleanup_retry` to start new work. An exact duplicate outer Revoke remains replayable
from its cache without starting absence work; an internally driven cleanup
episode denies every packet.
Each repeatable absence pass then performs, in this exact order:

1. cancel the active `CoreExecution`, if any;
2. call `Revoke` in reverse binding order on every extension session whose
   `Prepare` call began;
3. before commit call `CorePreparation.Rollback`; after commit call
   `Core.Revoke`. A `cleanup_complete` result proves Core authority and
   resources absent and runs no Inspect. A `stop_vm_required` result is
   terminal and runs no Inspect. Thus only a `retry_required` Core Revoke result is followed by Core Inspect
   with the retained non-authoritative prepared correlation and live cleanup
   capability.

`cleanup_complete` skips that completed component in later absence passes.
`retry_required` preserves exact ownership and permits only the corresponding
Cancel, Revoke, Rollback, or Inspect work to run again; nothing is recreated.
In a peer-driven episode, attempt one is the first Revoke. After attempt one or
two reports retryable incomplete absence, Service commits the correlated
`cleanup_retry`, clears that outer outstanding request, and waits for that retry
under the same cleanup budget. Only the next fresh-ID Revoke may start the next
absence pass among first-seen IDs; an exact duplicate only replays its cached
response. In an internally driven episode, Service starts the next pass
itself without admitting a packet and never emits `cleanup_retry`. The absence
loop stops as soon as every applicable component reports complete. A third
incomplete attempt, stop-VM result, budget expiry (including while awaiting a
fresh retry), dependency nonconformance, loss, or ambiguous send makes the
episode terminal `ServiceStopVMRequired`.

After the absence loop ends in cleanup-complete or terminal escalation, and
never while a peer retry remains admissible, the one-time finalization pass
performs, in this exact order:

1. call every opened extension session `Close` in reverse open order;
2. destroy or close every Service-owned received/send packet body and right;
3. call `Core.Close` exactly once;
4. call `ServiceRuntime.Close` exactly once;
5. if IPC is still unambiguously usable, perform the correlated close-notify
   handshake described below;
6. call `Transport.Close` exactly once and last.

No repeatable absence operation runs after one-time finalization begins, and no
finalizer runs a second time. All absence passes and finalizers share the single
30-second budget. Any stop-VM result, budget expiry, dependency nonconformance,
loss, or absence that remains unknown dominates all prior retry/success results
and produces `ServiceStopVMRequired`. Finalizers still run best-effort under the
remaining shared budget so Service releases every ownership it can before D6
kill/reap. No cleanup call is placed in a detached goroutine, and no call uses
`context.Background()`.

Close correlation is exact. A close-notify header always has an all-zero
request ID and the exact boot nonce. Its identity digest is all-zero before the
first authenticated job; after a job identity is installed, it is that exact
pinned identity forever, including after cleanup. A bilateral `normal` close
is legal only after cleanup-complete. A bilateral `shutdown` close is legal
only after a clean cancellation drain. Every other reason is a terminal
one-way best-effort notification. EOF is expected only after a committed
bilateral normal/shutdown exchange; every other EOF is `helper_loss`.

The final Service result matrix is closed:

| Disposition | Close reason | Error |
| --- | --- | --- |
| `ServiceClosed` | `normal` | nil |
| `ServiceClosed` | `shutdown` | nil |
| `ServiceStopVMRequired` | `protocol_error`, `identity_drift`, `expired`, or `helper_loss` | non-nil sanitized `ContractError` |

Every other tuple is `ContractResultMatrix`. A stop-VM result is not a clean
close, and a clean result never carries an error.

The helper response-disposition matrix has this correction:

- `cleanup_retry` is Revoke-only;
- `stop_vm_required` may answer PrepareCommit, Renew, Exec, or Revoke;
- Renew and Exec add the exact `CleanupIncomplete` failure alongside their
  pre-existing operation failures;
- for non-Revoke operations, stop-VM uses only `CleanupIncomplete` when
  absence is unknown, or `HelperUnavailable` when a dependency/liveness
  failure is terminal but absence is proved and no mutation occurred;
- Revoke stop-VM may use only `RevokeFailed`, `HelperUnavailable`, or
  `CleanupIncomplete`;
- a stop-VM response is attempted only while IPC is unambiguously usable.

No PrepareBegin/PrepareFile response, accepted result, cleanup-complete result,
or unrelated error code can carry stop-VM. Failure to commit the best-effort
terminal response does not change ownership: Service still returns
`ServiceStopVMRequired` for D6 kill/reap.

### Extension contract

The helper extension API is exact:

```go
type ExtensionFactory interface {
	Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error)
}

type ExtensionOpenRequest struct {
	liveValue
	descriptor credentialprotocol.ExtensionDescriptor
	host       ExtensionHost
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
	liveValue
	identityDigest [32]byte
	revision       uint64
	expiresUnixNano int64
	bindingID      credentialprotocol.SafeID
	bindingIndex   uint16
	mode           credentialprotocol.DeliveryMode
	execBinding    ExecBindingCapability
}

type ExtensionPrepareResult struct {
	liveValue
	execBinding ExecBindingCapability
}

type ExtensionExecRequest struct {
	liveValue
	identityDigest [32]byte
	revision       uint64
	execBindingID  credentialprotocol.SafeID
	execBinding    ExecBindingCapability
}

type ExtensionExecResult struct {
	liveValue
	execBinding ExecBindingCapability
}

type ExtensionRenewRequest struct {
	liveValue
	identityDigest [32]byte
	revision       uint64
	expiresUnixNano int64
}

type ExtensionRevokeRequest struct {
	liveValue
	identityDigest [32]byte
	revision       uint64
	reason         credentialprotocol.RevokeReason
}

type SSHAgentEndpointRequest struct {
	liveValue
	identityDigest [32]byte
	revision       uint64
	bindingID      credentialprotocol.SafeID
	bindingIndex   uint16
	execBinding    ExecBindingCapability
}

type SSHAcceptedPublication struct {
	liveValue
	identityDigest   [32]byte
	revision         uint64
	bindingIndex     uint16
	ordinal          uint8
	capabilitySHA256 [32]byte
	execBinding      ExecBindingCapability
}

type ExtensionCleanupCategory uint8
const (
	ExtensionCleanupComplete      ExtensionCleanupCategory = 1
	ExtensionCleanupRetryRequired ExtensionCleanupCategory = 2
	ExtensionCleanupStopVMRequired ExtensionCleanupCategory = 3
)

type ExtensionCleanupResult struct {
	liveValue
	resourcesAbsent bool
	category        ExtensionCleanupCategory
}
```

The exact constructors and accessor sets are:

```go
func NewExtensionOpenRequest(credentialprotocol.ExtensionDescriptor, ExtensionHost) (ExtensionOpenRequest, error)
func (r ExtensionOpenRequest) Descriptor() credentialprotocol.ExtensionDescriptor
func (r ExtensionOpenRequest) Host() ExtensionHost
func NewExtensionPrepareRequest([32]byte, uint64, int64,
	credentialprotocol.SafeID, uint16, credentialprotocol.DeliveryMode,
	ExecBindingCapability) (ExtensionPrepareRequest, error)
func (r ExtensionPrepareRequest) IdentityDigest() [32]byte
func (r ExtensionPrepareRequest) Revision() uint64
func (r ExtensionPrepareRequest) ExpiresUnixNano() int64
func (r ExtensionPrepareRequest) BindingID() credentialprotocol.SafeID
func (r ExtensionPrepareRequest) BindingIndex() uint16
func (r ExtensionPrepareRequest) Mode() credentialprotocol.DeliveryMode
func (r ExtensionPrepareRequest) ExecBinding() ExecBindingCapability
func NewExtensionPrepareResult(ExecBindingCapability) (ExtensionPrepareResult, error)
func (r ExtensionPrepareResult) ExecBinding() ExecBindingCapability
func NewExtensionExecRequest([32]byte, uint64, credentialprotocol.SafeID,
	ExecBindingCapability) (ExtensionExecRequest, error)
func (r ExtensionExecRequest) IdentityDigest() [32]byte
func (r ExtensionExecRequest) Revision() uint64
func (r ExtensionExecRequest) ExecBindingID() credentialprotocol.SafeID
func (r ExtensionExecRequest) ExecBinding() ExecBindingCapability
func NewExtensionExecResult(ExecBindingCapability) (ExtensionExecResult, error)
func (r ExtensionExecResult) ExecBinding() ExecBindingCapability
func NewExtensionRenewRequest([32]byte, uint64, int64) (ExtensionRenewRequest, error)
func (r ExtensionRenewRequest) IdentityDigest() [32]byte
func (r ExtensionRenewRequest) Revision() uint64
func (r ExtensionRenewRequest) ExpiresUnixNano() int64
func NewExtensionRevokeRequest([32]byte, uint64,
	credentialprotocol.RevokeReason) (ExtensionRevokeRequest, error)
func (r ExtensionRevokeRequest) IdentityDigest() [32]byte
func (r ExtensionRevokeRequest) Revision() uint64
func (r ExtensionRevokeRequest) Reason() credentialprotocol.RevokeReason
func NewSSHAgentEndpointRequest([32]byte, uint64, credentialprotocol.SafeID,
	uint16, ExecBindingCapability) (SSHAgentEndpointRequest, error)
func (r SSHAgentEndpointRequest) IdentityDigest() [32]byte
func (r SSHAgentEndpointRequest) Revision() uint64
func (r SSHAgentEndpointRequest) BindingID() credentialprotocol.SafeID
func (r SSHAgentEndpointRequest) BindingIndex() uint16
func (r SSHAgentEndpointRequest) ExecBinding() ExecBindingCapability
func NewSSHAcceptedPublication([32]byte, uint64, uint16, uint8, [32]byte,
	ExecBindingCapability) (SSHAcceptedPublication, error)
func (r SSHAcceptedPublication) IdentityDigest() [32]byte
func (r SSHAcceptedPublication) Revision() uint64
func (r SSHAcceptedPublication) BindingIndex() uint16
func (r SSHAcceptedPublication) Ordinal() uint8
func (r SSHAcceptedPublication) CapabilitySHA256() [32]byte
func (r SSHAcceptedPublication) ExecBinding() ExecBindingCapability
func NewExtensionCleanupResult(
	resourcesAbsent bool, category ExtensionCleanupCategory,
) (ExtensionCleanupResult, error)
func (r ExtensionCleanupResult) ResourcesAbsent() bool
func (r ExtensionCleanupResult) Category() ExtensionCleanupCategory
```

All fields are private, `liveValue` is first, and constructor argument order is
field order. Constructors reject zero, unknown, noncanonical, nil, and typed-
nil values before any capability method call. Each type has static formatting,
denies JSON/text/binary marshal and unmarshal, and preserves a seeded receiver
on rejected unmarshal. Accessors return only immutable scalar/fixed copies or
the exact opaque interface; no public literal mutation is possible. Canonical
expiry is `int64` Unix nanoseconds; `time.Time` is not accepted.

`NewExtensionOpenRequest` is the one slice-bearing input exception: after
validation it deep-clones the descriptor on construction, including all three
`ExtensionDescriptor` claim slices, into
private request ownership. The caller may mutate its input immediately without
changing the request. Every `Descriptor` accessor call returns a fresh deep
clone, so an extension cannot mutate the stored request through a returned
slice. The constructor and fresh deep clone on every `Descriptor` accessor call
preserve nil-versus-explicit-empty slice shape; they use
`credentialprotocol.CloneExtensionDescriptor` and never retain or return a
shallow descriptor alias.

`ExecBindingCapability` and live endpoint/connection values have private
concrete implementations. `ExtensionCleanupResult` and `SSHIOResult` have only
private fields and validating constructors. None permits public struct-literal
construction; all use fail-closed formatting/serialization. Cleanup result
contains only the extension resource-absence boolean and retry/stop-VM category;
it can never claim whole-job cleanup. `SSHIOResult` contains only byte count,
EOF, and truncation. Shutdown direction is a closed read/write/both enum.

All extension authority crosses this seam as opaque extension values.
`ExecBindingCapability` remains an opaque interface with its existing private
marker; its sole private concrete representation is
`struct { liveValue; digest [32]byte }`. Only Service mints it, after successful
Core Commit, from this exact frozen digest:

```text
SHA256(
  opaque16("hal/l8/guest-helper/extension-exec-binding/v1") ||
  bootNonce[32] || identityDigest[32] || u64be(revision) ||
  opaque16(boot) || opaque16(helper) || opaque16(job) ||
  opaque16(monitor) || opaque16(mount) || opaque16(cgroup) ||
  i64be(expiresUnixNano) || manifestSHA256[32] || transactionSHA256[32] ||
  u16be(bindingIndex) || opaque16(bindingID) || u8(mode)
)
```

The extension factory/session, D4 endpoint, and publication code may only echo
the exact issued interface value. Service constant-time checks the same private
concrete type and digest in the Prepare result, BindExec result, endpoint's
`ExecBinding`, endpoint creation result, and accepted publication. A zero,
foreign implementation, typed-nil, changed digest, or wrong binding is
`ContractCapability`. The exact issued value may
be echoed only at its frozen lifecycle checks; that is not mint authority. The
interface has no ID, digest, bytes, formatting, or serialization accessor and
never becomes a proof label.

`ExtensionCleanupResult` remains exactly `resourcesAbsent bool` plus
`category ExtensionCleanupCategory`, with its validating constructor and those
two accessors. Its matrix is closed: Complete requires `resourcesAbsent=true`;
RetryRequired requires false; StopVMRequired requires false. An unknown
category or any other boolean/category pair is invalid. It proves only absence
of resources owned by that extension and can never prove whole-job absence.

The interface method sets do not otherwise change. `ExtensionFactory.Open`,
the five `ExtensionSession` methods, both `ExtensionHost` methods, the three
`SSHAgentEndpoint` methods, and the five `SSHAgentConnection` methods remain
exactly as declared. The endpoint request and accepted publication carry the
issued binding and the endpoint must echo it. No new host/endpoint method,
numeric handle, path, namespace, or transport authority is added.

These request/result structs are concrete, non-JSON closed types owned by
`credentialhelper`. They contain only canonical safe identity/digest/revision
metadata and opaque capabilities owned by `ExtensionHost`; they contain no
path string, raw secret, key, key fingerprint, socket address, numeric file
descriptor, PID, or generic `any`/map/body. `ExtensionHost` is the D4-owned
narrow capability backed by the authenticated mount-monitor protocol for the
already-created exact job namespace and by the core service for one
authenticated `0x16` rights publication. It exposes no namespace or root FD.
D5 cannot open outside the owned job namespace or publish another packet type.
In particular, D5 cannot add an HL8M packet type, body arm, right, sequence, or
state transition.

`CreateSSHAgentEndpoint` maps to exactly one normative HL8M
`create_ssh_endpoint` request after the core file prepare commit has succeeded
and before the outer helper prepare result is published. The matching accepted
response carries exactly one inspected listening `AF_UNIX` capability and the
frozen safe result metadata; every rejection carries no right. The D4 host
owns and closes a received capability until the complete response and state
transition commit, then transfers the opaque endpoint to the D5 session. D5
never sees the monitor namespace, a numeric descriptor, or an alternate path.

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
has one `Serve` lifetime, one activation, and one drain path. The exact
extension lifecycle is:

1. open manifest-selected extension sessions in order before `Core.BeginPrepare`;
2. on a pre-commit failure, call `CorePreparation.Rollback` before closing every
   opened session in reverse order; a retry-required Rollback is resolved by
   the repeatable absence pass before any one-time extension Close begins;
3. complete Core file staging and Core Commit, then call extension `Prepare` in
   manifest order, and only after all succeed publish the outer prepare result;
4. once any post-commit extension Prepare begins, its failure cleanup calls
   reverse `Revoke` on every session whose Prepare call began, including the
   failing session even when it returned an error; it then calls Core Revoke,
   never Rollback after commit. Every retry/unknown result enters the repeatable
   absence pass. Only after that loop ends does the one-time finalization pass
   Close all opened sessions in reverse order;
5. renew Core first and extensions in manifest order; any extension Renew
   failure revokes the whole activation through that post-commit path;
6. revoke denies new work, cancels an active execution, calls extension
   `Revoke` in reverse order, then Core Revoke. Retry/unknown results enter the
   repeatable absence pass; extension `Close` in reverse order occurs only in
   the one-time finalization pass after the absence loop ends.

The closed manifest contains at most one SSH binding, so the SSH extension may
issue one `create_ssh_endpoint` and cannot create a second `SSH_AUTH_SOCK`.
No extension call is concurrent with another transition for the same job.

Service owns each valid `Open` return for the Service/job lifetime. During the
applicable pre-commit rollback, post-commit revoke, or terminal Service teardown
it calls that session's `Close` at most once and exactly once when its teardown
step is reached. The contract does not promise that an extension Close is
idempotent. Close exactly once never substitutes for Revoke or absence proof.
Caller cancellation latches the same drain; Serve waits for the shared bounded
cleanup result.

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
	Descriptor  ClientProcessDescriptor
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

### Credential client concrete closure

The following closes the earlier client seam without adding a wire field or a
sixth Transport method. `v2control` remains the sole authority for controller
operation tokens, concrete request and response values, request IDs, identity
digests, error codes, error matrices, and canonical JSON. `credentialprotocol`
remains the sole authority for HL8P headers, packet types, bodies, limits, and
catalogs. The client types below are live ownership and dispatch wrappers over
those authorities; their numeric arm tags are private Go state and are not a
new wire ABI.

#### Construction and single-Serve lifecycle

The complete public lifecycle API is:

```go
type ClientOptions struct {
	Transport   Transport
	Policy      Policy
	Extensions *ExtensionRegistry
	Descriptor  ClientProcessDescriptor
}

type Client struct {
	liveValue
	transport        Transport
	policy           Policy
	policyDescriptor PolicyDescriptor
	extensions       []credentialprotocol.ExtensionDescriptor
	descriptorSHA256 [32]byte
	state            *clientState
}

func NewClient(ClientOptions) (*Client, error)
func (c *Client) Serve(context.Context) error
func (c *Client) Close(context.Context) error

type ClientProcessDescriptor interface {
	ContractVersion() uint8
	Role() uint8
	PolicySHA256() [32]byte
	Extensions() []credentialprotocol.ExtensionDescriptor
	EncodedLength() uint16
	SHA256() [32]byte
	WriteCanonical(credentialmemory.CredentialSink) error
}
```

`clientState` is one private synchronized owner with exactly: phase
`new|serving|draining|closed|terminal`; booleans `serveCalled`, `closeStarted`,
and `transportClosed`; next controller receive/send and helper receive/send
sequences; the optional active session identity, full immutable v2 manifest,
projected helper manifest records and helper manifest digest, revision,
expiry, proof IDs, and fixed limit-set ID; one optional outstanding request
ledger; three stream ledgers; one optional extension dispatch slot; opened
extension sessions in canonical order; the one watcher/pump wait group; the
latched sanitized terminal error; and a completion channel.
`descriptorSHA256` is the pinned digest of the D6-supplied immutable process-
descriptor snapshot. Client retains no descriptor body, source, or mapping.
The request ledger
contains only v2control operation/request ID/identity, canonical safe request
digest, the full immutable v2 manifest, the exact deep-snapshotted
`credentialprotocol.HelperPrepareBeginBody` containing the projected records,
their helper manifest digest, revision, expected helper request/response type, declared private
record count/aggregate/digest, accepted private count/aggregate, and optional
credentialprotocol prepare/exec transaction state. Each stream ledger contains
kind, next offset, maximum, EOF, and one-credit-outstanding. No state field
stores a process-descriptor payload or body capability. No state stores an
endpoint, ordinary-memory or publicly accessible
descriptor bytes, clock function, arbitrary error, or queue. `Client` has no
other exported or
unexported authority-bearing dependency.

`NewClient` rejects a nil or any constructible typed-nil Transport, Policy, or
ClientProcessDescriptor, and rejects a nil `ExtensionRegistry`. It reads
`Policy.Descriptor` twice, requires two equal
values with ID `client-policy-v1` and the exact digest already specified, and
snapshots it. It obtains two `Extensions.Descriptors` snapshots, requires byte-
equal canonical order and validity, and stores a third deep copy. The registry
may be empty at this generic seam; D6 production composition requires exactly
the locked SSH registration and rejects missing or extra registrations. Once
a constructor check fails, no new dependency method is called; only
cleanup of already-acquired live values may run. A Policy panic is a contract
failure, never an allow. A registry or descriptor snapshot can contain no live
factory, endpoint, right, body, PID, path, or secret.

`ClientProcessDescriptor` is a narrow D6-issued view over the already-frozen
`l8composition.ProcessDescriptor`; it is not another descriptor ABI. D6 builds
one immutable validated `l8composition.ProcessDescriptor` role-2 snapshot
before `credentialclient.NewClient`, then supplies the same immutable validated `l8composition.ProcessDescriptor` snapshot to both D4 bootstrap and NewClient
without changing its canonical `HL8D` bytes, and returns the
same ProcessDescriptor to its caller. `ContractVersion` and
`Role` are projections of that value's already-frozen scalar fields, not a new
catalog: D6 returns the exact existing values `1` and
`l8composition.ProcessRoleClient` (wire value 2) through the two `uint8`
accessors. `NewClient` reads every safe projection twice, requires stable
equality, exact contract version 1 and client role 2, the snapshotted Policy
digest and extension set, a
1..1,898 encoded length, and nonzero SHA-256 equal to a fresh hash of one
`WriteCanonical` through a package-private exact-capacity sink valid only
inside one newly allocated `credentialmemory.LockedMapping.Load`. The source
must write exactly `EncodedLength` bytes. NewClient hashes that exact temporary
mapping, retains only its independently checked digest, and destroys the temporary mapping before returning on success and on every constructor
failure. It never retains or calls the source again. Client never retains descriptor bytes and never sends agent hello. No raw byte getter, decoder,
ordinary-memory copy, role override, or second encoding exists.
`l8composition` remains the only producer and authority; credentialclient never
imports it.

Only after every dependency, policy, registry, and process-descriptor check
passes does `NewClient` open extension sessions in ascending canonical
descriptor order through `ExtensionFactory.Open` and an
`ExtensionOpenRequest{Descriptor: deepSnapshot}`. A first open failure stops
construction and closes every already-opened session in reverse order with the
30-second internal cleanup deadline. No later factory is called. Cleanup failure
returns `ClientContractCleanup`; otherwise the factory's raw error is replaced
by `ClientContractExtension`. Success stores exactly one session per descriptor
and transfers their closure to Client drain. The existing four-row factory
return matrix remains exact. An empty generic registry opens nothing.

Transport is constructed by D4 from the authenticated PID1 bootstrap and is
already past the secure-control Finished exchange when supplied to `NewClient`.
D4 bootstrap owns `agent_hello`: using the same D6 immutable descriptor
snapshot, the configured Transport sends it at helper send sequence 1 and
validates the exact `agent_hello_ack` at helper receive sequence 2 before
`NewClient` is called. It privately pins the
control session ID, boot nonce, controller key/session generations, helper
kernel identity, bootstrap digest, helper generation, and exact canonical
expected client-process-descriptor digest from `HL8A agent_config`. This is why
those values are not caller-selectable scalar `ClientOptions` fields.
Transport verifies bootstrap digest, generations, descriptor digest, helper
credentials, and zero request/job identity fields before construction may
proceed. The first operational helper send sequence is 2 and first operational helper receive sequence is 3; controller application receive/send both start at
secure sequence 1. Transport verifies its pinned channel facts while Client
owns only the operational counters, operation correlation, and state
transitions. D4 cannot repeat either boot packet after Client construction.

There is exactly one successful call to `Serve`. The first call atomically
moves `new` to `serving`; a concurrent or later call returns
`ClientContractServeState`, including after the first call returns. `Serve`
cannot be restarted. It owns both receive paths, the one logical outstanding
request, sequence and identity correlation, Policy calls, extension sessions,
body/right transfer, and drain. It returns only after the Client is closed and
all Client-owned live values are destroyed or after an absence-unproved cleanup
failure requiring VM stop/reap.

`Close` is safe before, during, or after `Serve`. Its context must be non-nil,
but its deadline and cancellation do not select, shorten, or abandon cleanup.
The first call atomically
denies new dispatch and starts one drain; concurrent calls join that drain.
Drain cancels receive admission, closes any Client-owned packet body/right,
closes opened extension sessions in reverse canonical registration order,
calls `Transport.Close` exactly once, and waits for the active extension loss
watcher and pump ownership handoff to settle. Every caller waits for that
latched result even if its context ends; the package deadline is the sole wait
bound. Every constructor
rollback, `Serve` terminal cleanup, and `Close` drain uses the shared L8
30-second internal cleanup deadline. It is created by package code when cleanup
starts, has no option or caller-selected clock/deadline, and is never shortened
or replaced by the caller context. Expiry latches `ClientContractCleanup` and
requires VM stop/reap; no cleanup goroutine is detached.
Once complete, later `Close` calls return the same sanitized result. No close
path calls a dependency while holding the Client state mutex.

The 30-second hard bound is a contract on conforming trusted dependencies:
every Transport, extension session, transferred-connection owner, and pump must
observe and return under the internally supplied cleanup context. Client calls
them synchronously and starts no detached cleanup goroutine. The contract does not promise an in-process forced return from an arbitrary blocking dependency;
nonconformance or absence that cannot be observed inside the bound latches
`ClientContractCleanup` and requires D6 process/VM kill and reap. D6 owns that
out-of-process escalation and absence proof. A caller-context timeout never
turns unknown cleanup into success and never grants Client another Serve or
drain attempt.

#### Controller packet unions

Controller ingress owns one private receive latch and one Transport-owned
fixed-capacity locked plaintext slot:

```go
type ControllerBodyCapability interface {
	Len() uint32
	SHA256() [32]byte
	Borrow(context.Context, func(credentialmemory.BorrowedView) error) error
	Destroy(context.Context) error
}

type ControllerReceiveRequest struct {
	liveValue
	nextSequence         uint64
	expectedIdentity     v2control.IdentityDigest
	expectedIdentitySet  bool
	maximumPlaintextBytes uint32
	state                *controllerReceiveRequestState
}

type ControllerPacket struct {
	liveValue
	sequence  uint64
	sessionID [32]byte
	arm       controllerPacketArm
	body      ControllerBodyCapability
}

type BodySegmentSink interface {
	Capacity() uint32
	WriteSegment(offset uint32, source []byte) error
}

type ControllerSendPacket struct {
	liveValue
	sequence          uint64
	sessionID         [32]byte
	arm                controllerSendArmKind
	encodedBodyLength uint32
	bodySHA256         [32]byte
	state              *controllerSendPacketState
}
type controllerSendPacketState struct {
	mu       sync.Mutex
	consumed bool
	owner    *controllerSendPacketOwner
}
type controllerSendPacketOwner struct {
	arm  controllerSendArm
	body ControllerBodyCapability
}
```

The private Client constructor creates `ControllerReceiveRequest`; Transport
only reads `NextSequence() uint64`, `ExpectedIdentity()
(v2control.IdentityDigest, bool)`, and `MaximumPlaintextBytes() uint32`.
`expectedIdentitySet=false` is legal only for readiness and the first prepare,
before a job identity is installed. Readiness still carries the exact
authenticated control-session ID pinned inside Transport; a prepare carries
its own validated nonzero `GuestCredentialSessionIdentity` digest. Renew,
revoke, exec, and every binary record set the exact active identity. Maximum
plaintext is 1 through the existing secure-control 2-MiB bound. Copies share a
one-shot atomic latch. Exactly one successful `NewController<Arm>Packet` seals
it; constructor failure destroys a supplied body and leaves the latch terminal.

Controller JSON ingress uses a two-stage, bodyless request-root inspection
authority in `v2control` before selecting an operation decoder:

```go
type InspectedRequest struct {
	state *inspectedRequestState
}
type inspectedRequestState struct {
	operationToken OperationToken
	requestID      RequestID
	identityDigest IdentityDigest
	knownOperation Operation
}

func InspectCredentialRequestRoot(wire []byte) (InspectedRequest, error)
func (r InspectedRequest) OperationToken() OperationToken
func (r InspectedRequest) RequestID() RequestID
func (r InspectedRequest) IdentityDigest() IdentityDigest
func (r InspectedRequest) KnownOperation() (Operation, bool)
func DecodeInitialCredentialPrepareRequest(sessionID [32]byte, wire []byte) (CredentialPrepareRequest, error)
```

`InspectedRequest` has private fields and is nonserializable. It contains no
body, map, `json.RawMessage`, raw byte slice, or body span, and retains
no unvalidated or raw string echo.
Its `OperationToken` owns only the validated private operation string
needed to classify and, for a safe unknown token, construct the exact response;
it never owns the input spelling outside that validated token. Root
inspection is allocation-bounded by the existing 2-MiB plaintext and JSON depth
limits. The inspector is an exact lexical root recognizer, not a permissive
JSON object decoder. It requires root keys in exact canonical order `protocolVersion,operation,requestId,identityDigest,body`, compact JSON with no insignificant whitespace, and exact colon and comma placement. The root keys and first four values use their exact canonical scalar spellings: the fixed protocol string, an unescaped validated operation token, the 22-character unpadded base64url request ID, and the 43-character unpadded base64url identity digest. All alternate scalar encodings, including JSON escapes that decode to the same text, are rejected.

Only after that exact prefix does body admission begin. The inspector token-skips exactly one syntactically complete bounded body value and then requires EOF. The result is exactly one syntactically complete bounded JSON value. A safe unknown operation leaves body schema uninterpreted: only syntactic completeness and the shared depth/scalar/size bounds apply. A known operation's concrete decoder owns body schema and canonical re-encode failures after inspection. Any wrong root order, whitespace, extra, missing, or duplicate root field; trailing data; or unusable request-ID/identity correlation closes the secure session without a response. An unsafe or unreadable operation also closes without response. Malformed root or body syntax that prevents complete inspection is likewise in that close-only class. None is a correlated malformed-known request.

A safely inspected known operation is then passed with the same wire to its
concrete decoder. The first prepare uses
`DecodeInitialCredentialPrepareRequest`: it decodes the canonical body
`JobIdentity`, derives `GuestCredentialSessionIdentity` from that identity and
the authenticated `sessionID`, requires the encoded guest-session generation
and root identity digest to match the derived value, and only then returns the
ordinary concrete prepare request.
`CredentialPrepareRequest` exposes only `JobIdentity` through `Identity()`;
it neither exposes nor retains the derived
guest-session wrapper. It never trusts a caller-supplied expected job identity.
After the decoder returns, Client independently calls
`NewGuestCredentialSessionIdentity(sessionID, request.Identity())`, then
verifies the reconstructed identity digest against the inspected root
and stores that
exact reconstructed `GuestCredentialSessionIdentity` as the active identity.
Failure of reconstruction or equality closes without a response. Later prepare
retries and renew/revoke/exec use that already-active identity and their
existing concrete decoders.

The bodyless dispatch arms and constructors are exact:

```go
type ControllerUnknownOperation struct { liveValue; inspected v2control.InspectedRequest }
type ControllerMalformedKnown struct { liveValue; inspected v2control.InspectedRequest }

func NewControllerUnknownOperationPacket(ControllerReceiveRequest, uint64, [32]byte,
	v2control.InspectedRequest) (ControllerPacket, error)
func NewControllerMalformedKnownPacket(ControllerReceiveRequest, uint64, [32]byte,
	v2control.InspectedRequest) (ControllerPacket, error)
```

`InspectedRequest`, `ControllerUnknownOperation`, and
`ControllerMalformedKnown` have static fail-closed formatting that reveals
only their type label. Their concrete types deny JSON, text, and binary marshal and unmarshal operations; in particular, they deny JSON, text, and binary marshaling on both value and pointer forms. For each of the three concrete types `T`, the exact denial method set is:

```go
func (T) MarshalJSON() ([]byte, error)
func (T) MarshalText() ([]byte, error)
func (T) MarshalBinary() ([]byte, error)
func (*T) UnmarshalJSON([]byte) error
func (*T) UnmarshalText([]byte) error
func (*T) UnmarshalBinary([]byte) error
```

Here `T` is substituted by each named concrete type; it is notation, not a
fourth type. Value-receiver marshal denials apply to value and pointer forms;
pointer-receiver unmarshal denials apply wherever mutation could occur. Every
denial returns its static type-specific contract error without parsing input.
Unmarshal tests start with seeded valid receivers and require seeded receiver nonmutation for JSON, text, and binary input; zero receivers remain zero. All value and pointer forms as applicable are covered explicitly. They expose no mutator, their
accessors return only the immutable validated operation token, request ID,
identity digest, and known-operation classification, and packet consumption
cannot mutate the inspected metadata. Tests cover formatting, every marshal
and unmarshal interface, accessor stability, copies, and attempted packet
consumption.

The unknown constructor requires a syntactically safe unknown operation, but
that shape alone is not response authority. Response eligibility exists only
after a job identity is active and the inspected root identity digest exactly
equals that active identity. In that state, a safe unknown operation receives
only `unknown_operation`; Client dispatch emits only the v2control failure for
the inspected request ID/digest and never body-decodes it. The only safe-unknown
response is `unknown_operation`. An unknown operation before identity
activation is unsafe for response and closes terminally
without mutation or response: only readiness or a known initial prepare can
establish pre-active correlation. D4 may inspect it while
`expectedIdentitySet=false`, but the Client phase check rejects the unknown arm
before construction of any response. The malformed constructor requires a known operation
whose root inspection completed. A schema or canonical concrete-decoder failure
after usable root correlation is the only malformed-known boundary;
Client dispatch emits only that operation's matrix-valid
`malformed_request` failure. Thus a malformed known request receives only `malformed_request`;
its optional error field is omitted rather than derived
from input. Neither arm exposes or retains the failed body. A decoder failure
that invalidates correlation, including an initial prepare whose derived
identity does not match the root, closes without a response.

Safe JSON request arms reuse these exact values and constructors:

```go
func NewControllerReadinessPacket(ControllerReceiveRequest, uint64, [32]byte,
	v2control.ReadinessRequest) (ControllerPacket, error)
func NewControllerPreparePacket(ControllerReceiveRequest, uint64, [32]byte,
	v2control.CredentialPrepareRequest) (ControllerPacket, error)
func NewControllerRenewPacket(ControllerReceiveRequest, uint64, [32]byte,
	v2control.CredentialRenewRequest) (ControllerPacket, error)
func NewControllerRevokePacket(ControllerReceiveRequest, uint64, [32]byte,
	v2control.CredentialRevokeRequest) (ControllerPacket, error)
func NewControllerExecPacket(ControllerReceiveRequest, uint64, [32]byte,
	v2control.CredentialExecRequest) (ControllerPacket, error)
```

The `uint64` and `[32]byte` arguments are the authenticated secure-record
sequence and session ID observed by Transport. Transport compares the session
ID to its pinned secure session before calling a constructor. Every constructor
validates only its one-shot request, exact requested sequence, nonzero session
ID, corresponding v2control value, and the ReceiveRequest identity when set.
Readiness must carry the session ID and no job; prepare must carry a valid
nonzero self-consistent identity. The constructors perform no Client-ledger validation:
they do not install an identity or inspect the outstanding operation, expected
request ID, revision, manifest, binding, stream, credit, aggregate, or phase.
No constructor accepts an `OperationToken`, generic JSON object, `[]byte`, frame
type, or caller-selected decoder.

Private and stream records retain only their exact frozen safe metadata; the
payload remains in the locked `ControllerBodyCapability`:

```go
func NewControllerPrivatePacket(ControllerReceiveRequest, uint64, [32]byte,
	credentialprotocol.PrivateRecordKind, v2control.RequestID,
	v2control.IdentityDigest, uint16, uint16, uint16, uint32, [32]byte,
	ControllerBodyCapability) (ControllerPacket, error)
func NewControllerStreamPacket(ControllerReceiveRequest, uint64, [32]byte,
	credentialprotocol.HelperExecStreamKind,
	credentialprotocol.HelperExecStreamFlags, v2control.RequestID,
	v2control.IdentityDigest, uint64, uint32, [32]byte,
	ControllerBodyCapability) (ControllerPacket, error)
func NewControllerCreditPacket(ControllerReceiveRequest, uint64, [32]byte,
	credentialprotocol.HelperExecStreamKind, v2control.RequestID,
	v2control.IdentityDigest, uint64) (ControllerPacket, error)
func NewControllerCloseNotifyPacket(ControllerReceiveRequest, uint64, [32]byte,
	credentialprotocol.CloseReason) (ControllerPacket, error)
```

The exact private fields are:

```go
type ControllerPrivateRecord struct {
	liveValue
	kind           credentialprotocol.PrivateRecordKind
	requestID      v2control.RequestID
	identityDigest v2control.IdentityDigest
	bindingIndex   uint16
	chunkIndex     uint16
	chunkCount     uint16
	payloadLength  uint32
	payloadSHA256  [32]byte
}
type ControllerStreamRecord struct {
	liveValue
	kind           credentialprotocol.HelperExecStreamKind
	flags          credentialprotocol.HelperExecStreamFlags
	requestID      v2control.RequestID
	identityDigest v2control.IdentityDigest
	offset         uint64
	payloadLength  uint32
	payloadSHA256  [32]byte
}
type ControllerCreditRecord struct {
	liveValue
	kind           credentialprotocol.HelperExecStreamKind
	requestID      v2control.RequestID
	identityDigest v2control.IdentityDigest
	nextOffset     uint64
}
```

The private-record arguments after identity are binding index, chunk index,
chunk count, payload length, and payload digest from the exact HL8B header.
Constructors require only a known file or opaque-exec kind, chunk index
zero/count one, an in-range binding index, and 1..64-KiB payload whose capability
length/digest match. Stream arguments after
identity are offset, payload length, and digest from HL8S. Stdin is the only
controller-to-guest stream; non-EOF is 1..64 KiB with nonzero matching digest;
EOF is zero bytes and the SHA-256 of empty bytes. A controller-to-guest credit
is stdout or stderr only and carries a scalar next offset. These constructors
validate direction, closed wire-field shape, ReceiveRequest sequence/identity,
and body capability only. Close construction accepts only a known close reason.
Client dispatch validates outstanding operation, request ID, revision, exact
binding index, phase-permitted close, contiguous offset, one unused credit, and
declared per-stream/aggregate limits after valid packet return and before any
borrow, send construction, state mutation, or ownership transfer. A dispatch
failure destroys the packet body and closes the session.

`ControllerPacket` public methods are only `Sequence() uint64`, `SessionID()
[32]byte`, and typed accessors `Readiness()`, `Prepare()`, `Renew()`, `Revoke()`,
`Exec()`, `UnknownOperation()`, `MalformedKnown()`, `Private()`, `Stream()`,
`Credit()`, and `CloseNotify()`, each returning the exact arm and `bool`.
Wrong-arm access is zero/false. The three binary arms
expose only value-copy accessors matching the safe metadata arguments above;
there is no public body, bytes, sink, capability, generic frame, or operation-
token accessor. Client code alone borrows and destroys the body.

The accessor result types are exact:

```go
func (p ControllerPacket) Readiness() (v2control.ReadinessRequest, bool)
func (p ControllerPacket) Prepare() (v2control.CredentialPrepareRequest, bool)
func (p ControllerPacket) Renew() (v2control.CredentialRenewRequest, bool)
func (p ControllerPacket) Revoke() (v2control.CredentialRevokeRequest, bool)
func (p ControllerPacket) Exec() (v2control.CredentialExecRequest, bool)
func (p ControllerPacket) UnknownOperation() (ControllerUnknownOperation, bool)
func (p ControllerPacket) MalformedKnown() (ControllerMalformedKnown, bool)
func (p ControllerPacket) Private() (ControllerPrivateRecord, bool)
func (p ControllerPacket) Stream() (ControllerStreamRecord, bool)
func (p ControllerPacket) Credit() (ControllerCreditRecord, bool)
func (p ControllerPacket) CloseNotify() (credentialprotocol.CloseReason, bool)
```

Controller response construction is Client-private. The response arm is
exactly one of `v2control.ReadinessSuccessResponse`,
`v2control.CredentialPrepareSuccessResponse`,
`v2control.CredentialRenewSuccessResponse`,
`v2control.CredentialRevokeSuccessResponse`,
`v2control.CredentialExecSuccessResponse`, or `v2control.FailureResponse`.
Additional send arms are one stdout/stderr HL8S record, one stdin HL8C credit,
or one close notify. There is no D2 credential-client constructor for secure
frame `control_event`: no v2control event-body authority exists, so helper
events drive the loss/failure rules below rather than inventing JSON.

`ControllerSendPacket` public methods are the exact typed arm accessors
`ReadinessResponse()`, `PrepareResponse()`, `RenewResponse()`,
`RevokeResponse()`, `ExecResponse()`, `FailureResponse()`, `Stream()`,
`Credit()`, and `CloseNotify()`, plus `Sequence()`, `SessionID()`,
`EncodedBodyLength() uint32`, `BodySHA256() [32]byte`, and
`WriteCanonicalBody(BodySegmentSink) error`. There is no raw
body or generic frame accessor. Each private send constructor deep-snapshots
every safe graph, computes and pins `encodedBodyLength` and `bodySHA256`, and
places that snapshot or the locked sensitive body in the shared owner. Every
value alias shares `state`; `WriteCanonicalBody` atomically changes unused to
consumed before touching the sink and can succeed or fail only once across all
aliases. A second call returns `ClientContractOwnership` without inspecting the
owner. The safe typed arm accessors return zero/false after consumption; before
consumption they lock the shared state and return a fresh deep snapshot without
transferring the owner. `Sequence`, `SessionID`, and `EncodedBodyLength` remain
pinned scalar metadata before and after consumption. BodySHA256 remains pinned
and returns the same digest before and after consumption. Safe metadata may use
one bounded scratch owned by the call, which is full-capacity wiped before
return. Private file, opaque-exec, and stream payloads write directly from their
locked body capability and never enter that scratch.

`BodySegmentSink` is the dedicated credentialclient transmit-fill contract; it
does not change global `credentialmemory.CredentialSink` semantics. Transport
supplies a sink whose `Capacity` is exactly `EncodedBodyLength` and whose calls
accept exact contiguous, nonoverlapping coverage only: the first segment starts
at offset zero, each next offset equals the prior covered end, addition cannot
overflow, no segment exceeds capacity, and success requires final coverage
equal to capacity. A safe canonical prefix is written at offset 0. A private
file, opaque-exec, or stream payload then writes directly from its locked
`BorrowedView` through one package-private offset `credentialmemory.CredentialSink` adapter whose base is the prefix end and
whose bound is the pinned private length. There is no combined private scratch,
payload concatenation, second payload slot, or global sink semantic change. A
segment, coverage, digest, or panic failure wipes the full Transport slot and
destroys the private capability.

The sole write transition marks the state consumed and removes `owner` under
the state mutex, then uses that owner outside the mutex. It destroys any locked
body and releases every safe graph before returning on success, sink error, or
panic, using the package-created 30-second internal cleanup deadline because
the method has no caller context. Cleanup failure returns
`ClientContractCleanup`. Thus an alias can neither observe nor reuse owner state after the write,
while the pinned outer scalar metadata remains available to Transport.

Transport calls `WriteCanonicalBody` exactly once to fill its one fixed transmit
slot. A Write error causes a full-capacity slot wipe and no send syscall. Only
after a nil Write does Transport own that filled slot and may retry a temporary
`EAGAIN` send from the retained filled slot while the `SendController` context
remains live, never by re-encoding or invoking the method again. Context end is
terminal. Transport full-capacity wipes the slot after committed send and every
terminal error and retains nothing. A nil `SendController` return commits
sequence; any error consumes the packet, destroys its owner, closes the session,
and cannot be retried by Client. Constructor failure destroys a supplied
sensitive body.

```go
func (p ControllerSendPacket) ReadinessResponse() (v2control.ReadinessSuccessResponse, bool)
func (p ControllerSendPacket) PrepareResponse() (v2control.CredentialPrepareSuccessResponse, bool)
func (p ControllerSendPacket) RenewResponse() (v2control.CredentialRenewSuccessResponse, bool)
func (p ControllerSendPacket) RevokeResponse() (v2control.CredentialRevokeSuccessResponse, bool)
func (p ControllerSendPacket) ExecResponse() (v2control.CredentialExecSuccessResponse, bool)
func (p ControllerSendPacket) FailureResponse() (v2control.FailureResponse, bool)
func (p ControllerSendPacket) Stream() (ControllerStreamRecord, bool)
func (p ControllerSendPacket) Credit() (ControllerCreditRecord, bool)
func (p ControllerSendPacket) CloseNotify() (credentialprotocol.CloseReason, bool)
```

#### Helper packet unions

The helper side follows the already-closed HL8P receive design, narrowed to the
agent direction and without duplicating its codecs:

```go
type HelperReceiveRequest struct {
	liveValue
	nextSequence         uint64
	maximumBodyBytes     uint32
	maximumRights        uint32
	expectedRequestID    [16]byte
	expectedRequestIDSet bool
	expectedIdentity     [32]byte
	state                *helperReceiveRequestState
}

type HelperPacket struct {
	liveValue
	header credentialprotocol.HelperPacketHeader
	arm   helperPacketArm
	body  HelperBodyCapability
	right SSHConnectionCapability
}

type HelperSendPacket struct {
	liveValue
	header            credentialprotocol.HelperPacketHeader
	arm               helperSendArmKind
	encodedBodyLength uint32
	bodySHA256        [32]byte
	state             *helperSendPacketState
}
type helperSendPacketState struct {
	mu       sync.Mutex
	consumed bool
	owner    *helperSendPacketOwner
}
type helperSendPacketOwner struct {
	arm  helperSendArm
	body HelperBodyCapability
}

func NewHelperReceiveRequest(nextSequence uint64, maximumBodyBytes,
	maximumRights uint32, expectedRequestID [16]byte,
	expectedRequestIDSet bool, expectedIdentity [32]byte) (HelperReceiveRequest, error)
```

`HelperBodyCapability` has the same `Len`, `SHA256`, `Borrow`, and `Destroy`
method set and synchronized destruction rules as `ControllerBodyCapability`.
Transport is its sole trusted issuer and owns a single fixed-capacity locked
HL8P datagram slot. Receive-request accessors are `NextSequence`,
`MaximumBodyBytes`, `MaximumRights`, `ExpectedRequestID() ([16]byte, bool)`,
and `ExpectedIdentityDigest`; identity returns a fixed array. Maximum body is
0..`credentialprotocol.MaxHelperPacketBodyBytes`; maximum rights is zero when
the Client state makes SSH accepted impossible and otherwise exactly one so
Transport has one bounded ancillary sink without predicting the next packet
arm. Copies share a one-shot latch.
The constructor requires a nonzero expected ID exactly when the boolean is
true and an all-zero ID exactly when false; expected identity is always
nonzero. It validates no phase claim—the Client may construct the false case
only under the idle-active-job rule below.

Transport constructs a received value only through these exact public
constructors:

```go
func NewHelperResponsePacket(HelperReceiveRequest,
	credentialprotocol.HelperPacketHeader, HelperBodyCapability,
	credentialprotocol.HelperResponseBody) (HelperPacket, error)
func NewHelperEventPacket(HelperReceiveRequest,
	credentialprotocol.HelperPacketHeader, HelperBodyCapability,
	credentialprotocol.HelperEventBody) (HelperPacket, error)
func NewHelperExecStreamPacket(HelperReceiveRequest,
	credentialprotocol.HelperPacketHeader, HelperBodyCapability,
	uint64, credentialprotocol.HelperExecStreamKind,
	credentialprotocol.HelperExecStreamFlags, uint64, uint32, [32]byte) (HelperPacket, error)
func NewHelperExecCreditPacket(HelperReceiveRequest,
	credentialprotocol.HelperPacketHeader, HelperBodyCapability,
	credentialprotocol.HelperExecCreditBody) (HelperPacket, error)
func NewHelperSSHAcceptedPacket(HelperReceiveRequest,
	credentialprotocol.HelperPacketHeader, HelperBodyCapability,
	uint64, uint16, uint8, [32]byte,
	SSHConnectionCapability) (HelperPacket, error)
func NewHelperCloseNotifyPacket(HelperReceiveRequest,
	credentialprotocol.HelperPacketHeader, HelperBodyCapability,
	credentialprotocol.HelperCloseNotifyBody) (HelperPacket, error)
```

The SSH arguments are revision, binding index, connection ordinal, and relay
capability digest from the exact `0x16` body. The receive order is exact.
Transport performs one `recvmsg` into its fixed datagram slot and a bounded rights array of capacity one, observes truncation and the kernel-reported actual
rights count, and compares that count to `MaximumRights`. If truncation occurred
or count exceeds the maximum, it rejects and closes all received rights before indexing
the array. It then parses and authenticates the fixed header, including exact
sequence/direction/body length and its pinned boot nonce. From that authenticated
packet type it requires exactly one right for `ssh_accepted_fd` and zero for
every other type; mismatch closes every received right and destroys the slot.
Only after those checks does it decode the bounded body and call the matching
constructor.

`ExpectedRequestID` is false in exactly two Client-owned phase cases:

1. an idle active job with no outstanding logical operation permits only an
   asynchronous `event` or `ssh_accepted_fd`; its authenticated header request
   ID remains nonzero and producer-owned;
2. the drain/close handshake permits only `close_notify`; its authenticated
   close-notify header request ID is exactly zero.

All ordinary response, stream, and credit packets require expected=true and
the exact outstanding nonzero ID. Only operational packets belonging to an
outstanding logical request match that ID; idle event/SSH packets use their own
nonzero IDs, close-notify uses zero, and readiness/bootstrap are separately
correlated. No asynchronous event or SSH acceptance may interleave with an
outstanding prepare, renew, revoke, exec, stream, credit, response, or cleanup
operation. ReceiveRequest intentionally carries no phase enum. The
`HelperReceiveRequest` constructor performs only shape/header checks, then
Client immediately enforces
this phase-specific arm allowlist before body borrow, state mutation, or right
transfer. After constructor return, Client validates active identity, revision,
packet type, binding, ordinal, capability/body digest, and sequence before
borrowing a body, mutating state, or transferring a right.

The constructors rely on that inspected-cardinality Transport TCB check; they
do not accept a redundant caller-selectable `actualRights` scalar. Non-SSH
constructors receive no right argument. `NewHelperSSHAcceptedPacket` receives
the sole inspected Transport-issued capability, rejects nil and every
constructible typed-nil before calling any method, and therefore represents
exactly one right. Each constructor validates the complete closed header shape,
nonzero boot nonce, exact sequence/body length, request ID, identity, packet
direction, body codec, other typed-nil dependencies, represented arm
cardinality, and closed safe shape before sealing its request.
It compares the request ID when `ExpectedRequestID` is set and always compares
the explicitly present identity in `HelperReceiveRequest`; the false-ID cases
are restricted to the idle asynchronous and drain/close arms above. It has no access to Client
phase, revision, binding,
stream, credit, aggregate, or SSH ledgers. Non-sensitive bodies are destroyed
after construction. Exec-stream body ownership stays live until its payload is
forwarded or rejected. SSH accepted shape requires exactly one Transport-issued
capability, an in-range binding index, ordinal 1..64, and a nonzero capability
digest equal to `SHA256()`. Failure destroys the body and closes the capability.
Success makes `HelperPacket` their Client-owned container.

After return and before any body borrow or SSH ownership transfer, Client
dispatch compares the typed arm against the outstanding operation, expected
response/request type, exact revision and binding, stream offsets/EOF/credit,
declared aggregates, active SSH binding, one-request rule, and lifecycle phase.
Mismatch destroys the body, closes the capability, and terminates the session.

`HelperPacket` methods are only `Type`, `Header`, and typed `Response`, `Event`,
`ExecStream`, `ExecCredit`, `SSHAccepted`, and `CloseNotify` accessors. The
non-sensitive arms return the exact `credentialprotocol` body plus `bool`;
exec stream returns only its safe metadata record while Client privately owns
the payload capability.
`SSHAccepted() (SSHAcceptedPacket, bool)` returns a private-field safe arm whose
only metadata accessors are `Revision`, `BindingIndex`, `Ordinal`,
`CapabilitySHA256`, and `Connection() SSHConnectionCapability`. There is no
generic arm, body, credential, right, FD, socket, or raw-byte accessor.

```go
type HelperExecStreamRecord struct {
	liveValue
	revision      uint64
	kind          credentialprotocol.HelperExecStreamKind
	flags         credentialprotocol.HelperExecStreamFlags
	offset        uint64
	payloadLength uint32
	payloadSHA256 [32]byte
}
func (p HelperPacket) Response() (credentialprotocol.HelperResponseBody, bool)
func (p HelperPacket) Event() (credentialprotocol.HelperEventBody, bool)
func (p HelperPacket) ExecStream() (HelperExecStreamRecord, bool)
func (p HelperPacket) ExecCredit() (credentialprotocol.HelperExecCreditBody, bool)
func (p HelperPacket) SSHAccepted() (SSHAcceptedPacket, bool)
func (p HelperPacket) CloseNotify() (credentialprotocol.HelperCloseNotifyBody, bool)
```

`HelperSendPacket` has no public constructor. Client-private constructors cover
only prepare-begin, ordered prepare-file, prepare-commit, renew, revoke, exec,
exec-private, stdin exec-stream, stdout/stderr exec-credit, and close-notify.
Their arms contain the exact corresponding `credentialprotocol` body types,
including `credentialprotocol.HelperPrepareBeginBody`; private file, private
exec, and stdin payloads remain in a one-slot body capability. Every private
constructor deep-snapshots every safe graph, pins the exact header, encoded
length, and body SHA-256, and installs the graph/body in the shared owner. Its
public methods are only `Type`, `Header`, `EncodedBodyLength`, `BodySHA256`, and
`WriteCanonicalBody(BodySegmentSink) error`. No send packet has
a right. `WriteCanonicalBody` uses the identical shared one-shot alias state,
segmented exact-coverage sink, safe-scratch wipe, locked sensitive-body direct
write through the offset adapter, and permanently pinned length/SHA rules as
`ControllerSendPacket`. Its `Type` and `Header` values are
pinned outer scalar/value metadata and remain stable after consumption; it has
no typed safe-arm accessor. The sole write removes the owner under lock and
destroys/releases it on every return exactly as on the controller side.

Transport calls `WriteCanonicalBody` exactly once, retains its filled fixed
HL8P slot across temporary `EAGAIN` after a nil Write, and retries the syscall
from that slot while the `SendHelper` context remains live, never by re-encoding.
A Write error performs no syscall; context end is terminal. Transport
full-capacity wipes the slot after commit or every terminal failure. A nil
`SendHelper` return commits sequence; an error consumes and destroys the owner,
closes the helper session, and is never retried by Client.

#### Credential client policy closure

Policy reuses the exact v2 controller catalogs rather than accepting arbitrary
HL8P types or safe strings:

```go
type PolicyDescriptor struct {
	liveValue
	id     credentialprotocol.SafeID
	digest [32]byte
}

type ClientPolicyRequest struct {
	liveValue
	operation       v2control.Operation
	requestID       v2control.RequestID
	identityDigest  v2control.IdentityDigest
	revision        uint64
	expiresUnixNano int64
	manifest        []v2control.BindingManifest
	manifestSHA256  [32]byte
	descriptors     []credentialprotocol.ExtensionDescriptor
	fixedLimitSetID credentialprotocol.SafeID
}

type ClientPolicyDecision struct {
	liveValue
	allow         bool
	rejectionCode v2control.ErrorCode
}
```

The client descriptor remains the already-frozen `client-policy-v1` value with
digest `SHA256(opaque16("hal/l8/process-policy/v1") ||
opaque16("client-policy-v1"))`. `ID() credentialprotocol.SafeID` and `SHA256()
[32]byte` are its only data accessors; private `newClientPolicyDescriptor()` is
its sole constructor. `func NewClientPolicy() Policy` has no options and returns
the sole D2 production policy. D6 must pass that Policy to `NewClient`; a fake
may be injected only by an explicit test composition. No registry entry,
request metadata, environment value, or command option selects a Policy.

The sole public request constructor is
`NewClientPolicyRequest(operation v2control.Operation, requestID
v2control.RequestID, identityDigest v2control.IdentityDigest, revision uint64,
expiresUnixNano int64, manifest []v2control.BindingManifest,
descriptors []credentialprotocol.ExtensionDescriptor,
fixedLimitSetID credentialprotocol.SafeID) (ClientPolicyRequest, error)`.
Accessors return those fields in order; slice accessors return deep snapshots.
There is no private body, plan, endpoint, right, proof authority, clock, or
generic metadata.

```go
func (r ClientPolicyRequest) Operation() v2control.Operation
func (r ClientPolicyRequest) RequestID() v2control.RequestID
func (r ClientPolicyRequest) IdentityDigest() v2control.IdentityDigest
func (r ClientPolicyRequest) Revision() uint64
func (r ClientPolicyRequest) ExpiresUnixNano() int64
func (r ClientPolicyRequest) Manifest() []v2control.BindingManifest
func (r ClientPolicyRequest) ManifestSHA256() [32]byte
func (r ClientPolicyRequest) Descriptors() []credentialprotocol.ExtensionDescriptor
func (r ClientPolicyRequest) FixedLimitSetID() credentialprotocol.SafeID
func (d ClientPolicyDecision) Allowed() bool
func (d ClientPolicyDecision) RejectionCode() v2control.ErrorCode
```

The shape matrix is exact. Readiness has a nonzero request ID and session
digest, zero revision/expiry/manifest/digest, the constructor-snapshotted
descriptor set, and `helper-limits-v1`. Prepare has a nonzero request ID/job
digest, revision 1, positive expiry, nonempty ordered v2control manifest and its
nonzero projected helper-manifest digest defined below. Renew has nonzero request ID/job digest, positive
revision and expiry, and no manifest/digest. Revoke has nonzero request ID/job
digest and positive revision, with zero expiry/manifest/digest. Exec has
nonzero request ID/job digest and positive revision, the exact prepared
full v2 manifest and projected helper-manifest digest, and zero expiry. Every operation has exactly the
constructor-snapshotted descriptor set and `helper-limits-v1`; every unused
field is zero. Unknown operations and every other combination are invalid. The
constructor itself invokes the projection below for prepare and exec and stores
its computed helper digest; callers cannot supply or override that digest. It
requires nil manifest and stores zero digest for the other three operations.

Client-private allow/reject constructors enforce allow exactly as
`allow=true,code=""` and rejection as `allow=false` plus one nonempty known
`v2control.ErrorCode`. `Allowed()` and `RejectionCode()` are the sole decision
accessors. Policy may reject only `malformed_request`, `resource_limit`, or the
operation's existing `*_failed` code (`prepare_failed`, `renew_failed`,
`revoke_failed`, or `exec_failed`); readiness uses `malformed_request` or
`helper_unavailable`. Client state constructs request-conflict,
identity-mismatch, revision-stale, expired, helper-unavailable, and cleanup-
incomplete results without a Policy call.

Client first obtains the closed token with
`v2control.OperationTokenFor(request.Operation())`, applies this exact private
policy-subset allowlist before `v2control.ValidateOperationErrorCode`, and only
then invokes that global matrix validator:

| Operation | Policy-returned codes allowed | Globally valid but policy-forbidden |
| --- | --- | --- |
| readiness | `malformed_request`, `helper_unavailable` | `request_conflict`, `identity_mismatch` |
| prepare | `malformed_request`, `resource_limit`, `prepare_failed` | `request_conflict`, `identity_mismatch`, `revision_stale`, `expired`, `helper_unavailable`, `cleanup_incomplete` |
| renew | `malformed_request`, `renew_failed` | `request_conflict`, `identity_mismatch`, `revision_stale`, `expired`, `helper_unavailable` |
| revoke | `malformed_request`, `revoke_failed` | `request_conflict`, `identity_mismatch`, `revision_stale`, `helper_unavailable`, `cleanup_incomplete` |
| exec | `malformed_request`, `resource_limit`, `exec_failed` | `request_conflict`, `identity_mismatch`, `revision_stale`, `expired`, `helper_unavailable` |

`resource_limit` is therefore a Policy result only for prepare and exec. Red
tests submit every globally valid but policy-forbidden code in this table for
its operation and require `ClientContractPolicy` before response construction.
An unknown code, policy-subset miss, globally disallowed pair,
invalid decision, panic, or `(decision,error)` other than valid decision/nil is
a policy contract failure and closes/revokes. The exact known operations are
`v2control.OperationReadiness`, credential prepare, renew, revoke, and exec;
no helper extension packet invokes Policy independently of its owning prepared
job correlation.

Manifest authority is deliberately split rather than conflated. After
v2control has validated a prepare request, Client deep-snapshots its full
ordered `[]v2control.BindingManifest` for policy and controller-result
correlation. The private pure
`projectV2ManifestToHelperRecords([]v2control.BindingManifest)
([]credentialprotocol.HelperBindingManifestRecord, [32]byte, error)` performs
this exact order-preserving conversion:

- copy `BindingID()` unchanged;
- map exact v2 mode `http_proxy`, `file_tmpfs`, or `ssh_agent` to
  `credentialprotocol.DeliveryModeHTTPProxy`, `DeliveryModeFileTmpfs`, or
  `DeliveryModeSSHAgent`, respectively, rejecting every other value;
- for `file_tmpfs`, copy `TargetPath()` and `DeclaredFileBytes()`, require the
  already-v2-valid `FileSHA256()` to be exactly 64 lowercase hexadecimal
  characters, decode it into `[32]byte`, and set those three helper fields;
- for HTTP and SSH, leave target path, file length, and file digest zero; omit
  HTTP `ServiceID()` and SSH `SSHPolicyID()`/`SSHPolicyRevision()` because no
  such fields exist in the frozen `HelperBindingManifestRecord`.

The function validates every projected record through
`credentialprotocol.ValidateHelperBindingManifestRecord` and calls
`credentialprotocol.ComputeHelperManifestSHA256` exactly once over the complete
ordered projected slice. The projected records are encoded in `credentialprotocol.HelperPrepareBeginBody.Bindings`; that body has no digest field. The computed
digest is stored with the exact deep-snapshotted begin body in the request and
active ledgers, supplied in `ClientPolicyRequest`, and sent only in `credentialprotocol.HelperPrepareCommitBody.ManifestSHA256` after every ordered file record commits. Credentialclient does not hash v2 JSON and claims no
digest authority for the full v2 manifest. The authenticated v2 job identity
and the full manifest passed to Policy continue to bind HTTP service and SSH
policy ID/revision; their deliberate omission from the helper projection does
not grant the helper or extension any policy-selection authority.

For prepare and exec, Client calls Policy with the full v2 manifest plus this
projected helper digest and requires an allow before any helper send. Policy
therefore authorizes all service/SSH-policy fields that the helper record omits.
On successful prepare, Client compares the ordered
`credentialprotocol.HelperBindingProof` results one-for-one with both retained
representations by binding count, binding ID, and mapped mode before constructing
the ordered v2control binding proofs. Proof IDs are copied only after those
checks. An order, ID, mode, count, or projection mismatch is terminal and
installs no active state.

The remaining v2/helper conversions are private pure functions with exhaustive
catalog switches and no default mapping:

```go
func projectV2ExecPlanToHelper(v2control.ExecPlan) (credentialprotocol.HelperExecPlan, error)
func decodePrivateAggregateSHA256(string) ([32]byte, error)
func projectV2RevokeReasonToHelper(v2control.CredentialRevokeReason) (credentialprotocol.RevokeReason, error)
func mapHelperPrepareSuccessToV2(v2control.CredentialPrepareRequest, credentialprotocol.HelperPacketHeader, credentialprotocol.HelperResponseBody) (v2control.CredentialPrepareSuccessResponse, error)
func mapHelperRenewSuccessToV2(v2control.CredentialRenewRequest, credentialprotocol.HelperPacketHeader, credentialprotocol.HelperResponseBody) (v2control.CredentialRenewSuccessResponse, error)
func mapHelperRevokeSuccessToV2(v2control.CredentialRevokeRequest, credentialprotocol.HelperPacketHeader, credentialprotocol.HelperResponseBody) (v2control.CredentialRevokeSuccessResponse, error)
func mapHelperExecSuccessToV2(v2control.CredentialExecRequest, credentialprotocol.HelperPacketHeader, credentialprotocol.HelperResponseBody) (v2control.CredentialExecSuccessResponse, error)
```

`projectV2ExecPlanToHelper` deep-copies arguments in order, environment entries
in order, and the exact work directory and three byte maxima. It maps
literal/inherited/generated to 1/2/3, fixes stdin/stdout/stderr mode to
`HelperExecStreamModePipe` for all three, maps timeout/deadline to 1/2, and
copies the timing value unchanged. It validates the completed helper plan with
the canonical credentialprotocol validator and rejects an unknown source,
timing kind, changed count/order/value, or bound; it never trims, sorts,
defaults, inherits, or inserts an environment value.

`decodePrivateAggregateSHA256` accepts exactly 64 lowercase hexadecimal
characters and decodes them positionally to `[32]byte`; uppercase, prefix,
alternate length, invalid nibble, or any other spelling fails. For a v2 exec
with zero private records and bytes, Client additionally requires this decoded
value to be SHA-256 of empty bytes and places the helper protocol's required
all-zero absent digest in `HelperExecBody`. For the sole nonempty private record
it places the decoded digest unchanged. No digest spelling is reformatted or
accepted by default.

`projectV2RevokeReasonToHelper` maps requested/expired/session_loss/source_revoked/worker_cancel/daemon_shutdown to 1/2/3/4/5/6 positionally and rejects every zero, empty, case alias, or future value. It does not cast between the string and numeric catalogs.

Each `mapHelper*SuccessToV2` first requires an accepted or cleanup-complete
helper response with the exact correlated request type, request ID, identity,
revision, and sole non-nil result arm. Prepare maps ordered helper proofs only
after exact count/ID/mapped-mode correlation with the retained full v2
manifest, constructs every proof through `v2control.NewBindingProof`, and then
calls `v2control.NewCredentialPrepareSuccessResponse`. Renew requires the exact
requested expiry and calls `v2control.NewCredentialRenewSuccessResponse` with
the replacement proof. Revoke requires both absence booleans and cleanup-
complete before `v2control.NewCredentialRevokeSuccessResponse`. Exec requires
exact reconciled stream counts, truncation flags, and helper digests, converts
each `[32]byte` digest to exactly 64 lowercase hexadecimal characters, and calls
`v2control.NewCredentialExecSuccessResponse`. Failure dispositions, nil/wrong
arms, extra proofs, mismatched digests, or future catalogs have no default
mapping and never construct a controller success.

Those names are the existing constants
`v2control.ErrorCodeMalformedRequest`, `v2control.ErrorCodeResourceLimit`,
`v2control.ErrorCodePrepareFailed`, `v2control.ErrorCodeRenewFailed`,
`v2control.ErrorCodeRevokeFailed`, `v2control.ErrorCodeExecFailed`,
`v2control.ErrorCodeHelperUnavailable`, `v2control.ErrorCodeRequestConflict`,
`v2control.ErrorCodeIdentityMismatch`, `v2control.ErrorCodeRevisionStale`,
`v2control.ErrorCodeExpired`, and `v2control.ErrorCodeCleanupIncomplete`. The
client defines no alias catalog.

#### SSH accepted capability and transfer

The client-side D5 child pumps through this parent-owned exact capability:

```go
type SSHIOResult struct {
	liveValue
	byteCount uint64
	eof       bool
	truncated bool
}

type SSHAcceptedPacket struct {
	liveValue
	revision         uint64
	bindingIndex     uint16
	ordinal          uint8
	capabilitySHA256 [32]byte
	connection       SSHConnectionCapability
	ownership        *sshConnectionOwnership
}

type sshConnectionOwnership struct {
	mu        sync.Mutex
	cond      *sync.Cond
	phase     sshConnectionPhase // clientOwned|transferred|closing|closed
	activeOps uint32
	digest    [32]byte
	issuer    SSHConnectionCapability
}

type sshConnectionView struct {
	ownership *sshConnectionOwnership
}

type SSHShutdownDirection uint8
const (
	SSHShutdownRead  SSHShutdownDirection = 1
	SSHShutdownWrite SSHShutdownDirection = 2
	SSHShutdownBoth  SSHShutdownDirection = 3
)

type SSHConnectionCapability interface {
	SHA256() [32]byte
	Read(context.Context, credentialmemory.CredentialSink) (SSHIOResult, error)
	Write(context.Context, credentialmemory.BorrowedView) (SSHIOResult, error)
	Shutdown(context.Context, SSHShutdownDirection) error
	Close(context.Context) error
}
```

Transport is the sole trusted issuer and part of the configured Client TCB. It
wraps only one already-inspected connected `AF_UNIX SOCK_STREAM`; D5 cannot
construct another. The interface exposes no FD, socket, address, path, peer,
PID, raw bytes, generic reader/writer, deadline, duplication, or unwrap method.
`SHA256` is the authenticated relay-capability correlation digest, not an
endpoint identity. Shutdown direction is the closed read/write/both catalog.
`SSHIOResult` has only `ByteCount`, `EOF`, and `Truncated` accessors.
`NewSSHIOResult(byteCount uint64, eof, truncated bool)
(SSHIOResult,error)` is the sole result constructor. The SSHIOResult constructor validates only intrinsic shape: `byteCount` is at most
`credentialprotocol.SSHAgentMaxFrameBytes`, and the three fields are captured
without claiming which operation, sink, or view produced them. It does not
infer Read versus Write contract, caller capacity, full consumption,
truncation, or EOF correlation.

The parent-owned connection view validates every issuer result before returning
it to D5. For `Read`, count must not exceed the supplied sink capacity; EOF
requires count zero and `truncated=false`; non-EOF requires positive count; and
`truncated=true` is valid only when count exactly fills a nonzero bounded sink.
For `Write`, EOF and truncation are both false and count exactly equals the
supplied borrowed-view length. Thus D5 wrapper validation owns the Read versus
Write contract, supplied sink/view bound, and Read-only truncation and EOF/count
matrix before accepting an issuer result. An issuer error, invalid result, or
partial Write closes the connection with `ClientContractOwnership` and exposes
no raw cause. `ValidateSSHShutdownDirection` accepts only the three constants.

The Client owns the capability from successful receive through correlation and
dispatch. Before calling `Handle`, Client registers the opened extension
session in its Serve-owned helper/control-loss fan-out; that already-running
receive/loss path is the watcher and requires no additional ExtensionSession
method. Exactly these returns are valid: nil transfers ownership to the
extension; non-nil retains Client ownership and Client closes it; panic is a
contract failure and Client closes it. Typed-nil session or capability, wrong
arm, cancellation, sequence/identity/revision/binding/ordinal/digest mismatch,
or concurrent outstanding SSH request closes before transfer. `Handle` is
serialized with every packet for the helper session and there is no queue: the
single dispatch slot is either empty or contains this one Client-owned packet.
Transport does not receive another helper packet until the slot commits or
closes.

`Connection()` returns only a `sshConnectionView`, never the Transport-issued
`issuer`. Connection methods return `ClientContractOwnership` while Client-owned
for `Read`, `Write`, `Shutdown`, and `Close`; `SHA256` instead returns only the
already-pinned correlation digest. Thus an extension may retain the view during
`Handle` but cannot start I/O, shutdown, or close before returning nil. After a
nil return, Client changes `phase` to
`transferred` under the shared mutex before freeing the dispatch slot; only
then may view operations enter and increment `activeOps`. A non-nil return,
panic, loss, or cancellation changes the phase to `closing`, denies new view
operations, closes the private issuer, waits for active operations, and ends at
`closed`. The view never exposes the issuer and every alias shares this state.

After nil return, the D5 child is sole capability owner and pumps only through
Read/Write. It permits at most one outstanding relay request per connection,
uses one bounded read sink and one scoped write view, and never retains a view.
EOF, relay loss, revoke, Client drain, or either-direction error triggers
idempotent shutdown/close. `Shutdown` and `Close` reject unknown directions,
typed-nil sinks/views, oversized results, and calls after `closed`; `Close`
atomically moves `transferred` to `closing`, denies new operations, waits for
`activeOps` under its context, calls the issuer exactly once, and latches its
sanitized result. The watcher and pump share one terminal latch so
only one path initiates close; all join bounded cleanup. Client Close waits for
the extension session to close transferred capabilities, but never calls a
transferred capability itself. An extension close that cannot prove connection
absence is cleanup-incomplete and requires VM stop/reap.

### Credential client request/result correlation matrix

| Controller input | Exact helper transaction | Controller result and commit |
| --- | --- | --- |
| readiness JSON | no operational helper packet; uses already-authenticated helper readiness/hello state | exact `v2control.ReadinessSuccessResponse`, or matrix-valid failure; cannot install a job |
| prepare JSON then its declared ordered HL8B file records | policy first authorizes the full v2 manifest; `prepare_begin` carries its exact ordered helper projection, followed by one `prepare_file` per file binding; the final `prepare_commit` carries the projected helper digest; all share one request ID/identity/revision | the sole `credentialprotocol.HelperResponseBody` has `requestType=prepare_commit`; ordered helper proofs map back by exact binding ID/mode before success atomically installs identity, both manifest representations/digest, revision, expiry and proof IDs |
| renew JSON | one `renew` and one response with the same request ID/identity/new revision | accepted result maps to exact renew success and replaces expiry/proof/revision atomically |
| revoke JSON | one `revoke` and one response | cleanup-complete maps to exact revoke success and removes authority; retry/stop-VM and cleanup-incomplete never become success |
| exec JSON, optional one HL8B exec-private record, then credited stdin HL8S | `exec`, optional `exec_private`, credited stdin `exec_stream`; helper emits stdout/stderr streams, opposite credits, then one response | stdout/stderr become credited controller HL8S; stdin credits become controller HL8C; exact accepted response is sent only after three EOFs and child exit |
| controller stdout/stderr HL8C | one matching helper `exec_credit` | consumes exactly one previously granted output credit; no JSON result |
| helper `ssh_accepted_fd` | no controller control packet; dispatch to the one registered SSH extension | ownership transfers only after `Handle` nil; helper flow remains serialized while the one request is outstanding |
| helper event or close-notify | no invented controller event body | latch loss/revoke/drain and send only an already-defined operation failure or close where its frozen matrix permits; otherwise close the secure session |

One logical controller request is outstanding. Prepare's packet group and
exec's JSON/private/three-stream group count as one request. Every helper
packet, controller private/stream/credit record, response, and extension packet
must match that request's exact nonzero request ID, identity digest, revision,
projected helper-manifest/transaction digest, and contiguous offsets where applicable.
Readiness alone has the session ID. Lower sequence, gap, changed request bytes,
response type mismatch, duplicate/missing/reordered/interleaved record, stale
revision, identity drift, unexpected EOF/credit/right, or response after close
is terminal. Counters advance only after authentication, canonical validation,
correlation, ownership transfer, and committed state transition or safe
rejection. Failed or partial send never advances.

The client retains canonical safe request metadata, both immutable manifest
representations, the helper-manifest digest, and transaction digests for the one
active request, not private bytes. An identical host retry is accepted
only from newly supplied canonical JSON/private/stream records at fresh secure
sequences and is checked against the frozen credentialprotocol transaction
state. The Client never reconstructs wiped HL8B/HL8S payloads and never retries
an ambiguous helper request. Helper loss, timeout, or response ambiguity closes
and revokes the whole VM credential session.

### Credential client validation and ownership matrices

All new constructors and lifecycle paths return `*ClientContractError`, whose
closed `ClientContractErrorCode uint8` catalog is:

```text
1 ClientContractDependency       8 ClientContractPolicy
2 ClientContractDescriptor       9 ClientContractExtension
3 ClientContractServeState      10 ClientContractOwnership
4 ClientContractPacket          11 ClientContractCleanup
5 ClientContractCorrelation     12 ClientContractSerialization
6 ClientContractSequence        13 ClientContractPanic
7 ClientContractLimit
```

Its concrete safe layout and accessor set are:

```go
type ClientContractField uint8
const (
	ClientFieldDependency ClientContractField = 1
	ClientFieldDescriptor ClientContractField = 2
	ClientFieldSequence ClientContractField = 3
	ClientFieldPacketType ClientContractField = 4
	ClientFieldRequestID ClientContractField = 5
	ClientFieldIdentity ClientContractField = 6
	ClientFieldRevision ClientContractField = 7
	ClientFieldBody ClientContractField = 8
	ClientFieldRight ClientContractField = 9
	ClientFieldPolicy ClientContractField = 10
	ClientFieldExtension ClientContractField = 11
	ClientFieldLifecycle ClientContractField = 12
)
type ClientContractIndexKind uint8
const (
	ClientIndexPacket ClientContractIndexKind = 1
	ClientIndexRecord ClientContractIndexKind = 2
	ClientIndexBinding ClientContractIndexKind = 3
	ClientIndexStream ClientContractIndexKind = 4
)
type ClientContractError struct {
	code      ClientContractErrorCode
	field     ClientContractField
	indexKind ClientContractIndexKind
	index     uint32
	hasIndex  bool
}
func (e *ClientContractError) Code() ClientContractErrorCode
func (e *ClientContractError) Field() (ClientContractField, bool)
func (e *ClientContractError) Index() (ClientContractIndexKind, uint32, bool)
func (e *ClientContractError) Error() string
```

Codes map in order to these exact messages: `credential client dependency is
invalid`, `credential client descriptor is invalid`, `credential client Serve
state is invalid`, `credential client packet is invalid`, `credential client
correlation is invalid`, `credential client sequence is invalid`, `credential
client fixed limit is exceeded`, `credential client policy contract is
invalid`, `credential client extension contract is invalid`, `credential client
ownership is invalid`, `credential client cleanup is incomplete`, `credential
client live serialization is forbidden`, and `credential client dependency
panicked`. Field zero means absent; otherwise it must be one listed constant.
Index is permitted only for Packet/Record/Binding/Stream with the corresponding
field and is never a raw sequence, request ID, FD, PID, or byte offset.

The error contains only code, one closed static field selector, and optional
packet/record/binding/stream index. Its message is a static catalog string; it
does not wrap or format a dependency error. Unknown code/field or a non-applicable
index is invalid. Errors contain no operation token from untrusted input,
request bytes, IDs beyond fixed public catalog names, body, key, path, socket,
PID, endpoint, digest text, policy message, or raw cause.

Receive ownership is exact: before a valid constructor return Transport owns
the slot/body/right; constructor failure destroys/closes them. After a valid
return Client owns them. Client destroys non-sensitive bodies immediately,
destroys sensitive bodies after the sole scoped borrow on success/error/panic,
and closes every untransferred right. For send, Client owns body state until
the sole `WriteCanonicalBody` call consumes the shared owner; Transport then
owns only its retained filled fixed write slot, wipes it before `Send*` returns,
and retains nothing afterward. A nil send commits; a returned error destroys
the consumed owner, closes the session, and cannot be retried by Client. Value
copies share one synchronized owner state. Destroy waits for any in-flight borrow; later
borrow/destroy returns the stable destroyed error. Every owned locked slot uses
`clear` plus `runtime.KeepAlive`, then unlock/unmap, for a full-capacity wipe.

The dependency/factory return matrix is exact: `(valid,nil)` is success;
`(nil,nil)` or `(typed-nil,nil)` is contract failure; `(nil,error)` returns the
sanitized operation failure; `(non-nil,error)`, including callable typed nil,
closes the value with the 30-second internal cleanup deadline and returns contract
failure. Cleanup error is joined only as `ClientContractCleanup`, never exposed
verbatim. Policy has no valid non-nil-error row. Transport receive has the same
four rows plus ownership cleanup; Transport send and Close accept only nil or a
sanitized failure. Extension `Handle` uses the ownership rule above.

Every live Client, options snapshot containing interfaces, registry,
registration, open request, transport request/packet, body/right capability,
policy request/decision/descriptor, SSH arm/result, and Client error-adjacent
live wrapper implements fail-closed `MarshalJSON`, `MarshalText`,
`MarshalBinary`, `UnmarshalJSON`, `UnmarshalText`, and `UnmarshalBinary` without
traversal. `String`, `GoString`, and `Format` return one static redacted type
label. Reflection/panic tests seed private bytes, endpoint/path text, request
data, and dependency errors and require absence. Safe reused v2control and
credentialprotocol values retain their own already-frozen serialization rules;
the wrapper never provides an alternate encoder.

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

For the agent process, D6 creates and validates one immutable client
`ProcessDescriptor` before either D4 bootstrap or credentialclient construction.
It supplies that same snapshot to D4 so D4 completes `agent_hello` sequence 1 /
`agent_hello_ack` sequence 2, and supplies the same snapshot through the narrow
`ClientProcessDescriptor` view to NewClient for independent safe projection and
canonical-digest validation. NewClient destroys its temporary exact locked
mapping during construction; the running Client owns no descriptor body and no
hello union arm.

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

### L8 D2 image-profile concrete closure

This section is the implementation contract for the D2 image/profile slice. It
closes the schema, validation, resolver, lease, and Firecracker seams before a
real L8 image exists. D2 is schema, pure validation, opaque issuance/matching, guards, and fakes only.
D6 consumes only the opaque profile and lease. D7 owns real source-lock contents, building, inspection, reproducibility, and live issuance.
No D2 test downloads a source, runs a builder, inspects an image,
opens KVM, or mints a claim from a label.

The profile identifier is exact:

```go
const ImageProfileL8ProductionCredentials = "l8-production-credentials-v1"
```

The additive schema/catalog identifiers are exact:

```go
const (
	L8ProfileContractVersionV1        = "hal-microvm-l8-profile-v1"
	L8SourceLockSchemaVersionV1       = "hal-microvm-l8-source-lock-v1"
	L8SourceLockCatalogVersionV1      = "l8-source-lock-catalog-v1"
	L8ProcessCompositionCatalogV1     = "l8-process-composition-catalog-v1"
	L8FinalInspectionSchemaVersionV1  = "hal-microvm-l8-final-inspection-v1"
	L8FinalInspectionCatalogVersionV1 = "l8-final-inspection-catalog-v1"
)
```

`DistributionManifest` gains `L8Profile *L8ProfileFacts` with tag
`json:"l8Profile,omitempty"` immediately after `GuestNetwork` and before
`Assets`. `Provenance` gains the same field and tag immediately after
`GuestNetwork` and before `Outputs`. The pointer is nil for L5 and L7. Those structs retain their current
field order and tags; therefore L5 and L7 JSON bytes remain unchanged. An L8
manifest and provenance require the pointer, while a non-L8 profile rejects
it. Both carry the same normalized value byte-for-byte under the canonical
encoding below.

The exact Go field order and JSON names are:

```go
type L8ParentL7Evidence struct {
	ImageProfile        string `json:"imageProfile"`
	ManifestSHA256      string `json:"manifestSha256"`
	ProvenanceSHA256    string `json:"provenanceSha256"`
	ChecksumsSHA256     string `json:"checksumsSha256"`
	KernelSizeBytes     int64  `json:"kernelSizeBytes"`
	KernelSHA256        string `json:"kernelSha256"`
	RootfsSizeBytes     int64  `json:"rootfsSizeBytes"`
	RootfsSHA256        string `json:"rootfsSha256"`
	EvidenceSHA256      string `json:"evidenceSha256"`
}

type L8RuntimeFacts struct {
	NodeVersion            string `json:"nodeVersion"`
	NodeSHA256             string `json:"nodeSha256"`
	PiPackage              string `json:"piPackage"`
	PiVersion              string `json:"piVersion"`
	PiLauncherSHA256       string `json:"piLauncherSha256"`
	PiDependencyTreeSHA256 string `json:"piDependencyTreeSha256"`
}

type L8ProcessCompositionFacts struct {
	CatalogVersion          string `json:"catalogVersion"`
	GuestAgentSHA256        string `json:"guestAgentSha256"`
	GuestInitSHA256         string `json:"guestInitSha256"`
	CredentialHelperSHA256  string `json:"credentialHelperSha256"`
	MountMonitorSHA256      string `json:"mountMonitorSha256"`
	WorkloadShimSHA256      string `json:"workloadShimSha256"`
	RoleBootstrapSHA256     string `json:"roleBootstrapSha256"`
	HelperDescriptorSHA256  string `json:"helperDescriptorSha256"`
	ClientDescriptorSHA256  string `json:"clientDescriptorSha256"`
	CompositionSHA256       string `json:"compositionSha256"`
	WorkloadPolicySHA256    string `json:"workloadPolicySha256"`
	RuntimePolicySHA256     string `json:"runtimePolicySha256"`
	SyscallPolicySHA256     string `json:"syscallPolicySha256"`
}

type L8ProfileFacts struct {
	ContractVersion       string                    `json:"contractVersion"`
	ParentL7              L8ParentL7Evidence        `json:"parentL7"`
	Runtime               L8RuntimeFacts            `json:"runtime"`
	ProcessComposition    L8ProcessCompositionFacts `json:"processComposition"`
	SourceLockSHA256      string                    `json:"sourceLockSha256"`
	FinalInspectionSHA256 string                    `json:"finalInspectionSha256"`
}

type L8LockedSource struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Filename  string `json:"filename"`
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
}

type L8SourceLock struct {
	SchemaVersion  string                    `json:"schemaVersion"`
	CatalogVersion string                    `json:"catalogVersion"`
	ImageProfile   string                    `json:"imageProfile"`
	ParentL7       L8ParentL7Evidence        `json:"parentL7"`
	Runtime        L8RuntimeFacts            `json:"runtime"`
	Sources        []L8LockedSource          `json:"sources"`
}

type L8InspectionCheck struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	EvidenceSHA256 string `json:"evidenceSha256"`
}

type L8FinalInspection struct {
	SchemaVersion       string                    `json:"schemaVersion"`
	CatalogVersion      string                    `json:"catalogVersion"`
	ImageProfile        string                    `json:"imageProfile"`
	RootfsSHA256        string                    `json:"rootfsSha256"`
	SourceLockSHA256    string                    `json:"sourceLockSha256"`
	ParentL7            L8ParentL7Evidence        `json:"parentL7"`
	Runtime             L8RuntimeFacts            `json:"runtime"`
	ProcessComposition  L8ProcessCompositionFacts `json:"processComposition"`
	Checks              []L8InspectionCheck       `json:"checks"`
}
```

All fields are required; none of these structs uses `omitempty`. Slices must be
non-nil. JSON decoding is bounded, rejects unknown fields and trailing values,
and never normalizes input. The source-lock and final-inspection files are each
at most 4 MiB. A safe token is 1..128 bytes of lower-case ASCII letters,
digits, `_`, `-`, or `.`. A source `Name` is either such an unscoped npm name
or a 1..214-byte lower-case `@scope/name` with exactly one slash and nonempty
safe scope/name components; filenames are 1..240-byte base names with no slash,
backslash, whitespace, `..`, control byte, URL marker, or credential marker.
Every SHA-256 is exactly 64 lower-case hexadecimal characters. An input size is
1..1,073,741,824 bytes, the source aggregate is at most 4,294,967,296 bytes,
and overflow is rejected before addition.

Runtime values are exactly Node 22.22.0 and
`@earendil-works/pi-coding-agent 0.82.1`; `PiPackage` is exactly
`@earendil-works/pi-coding-agent`. `NodeSHA256` and `PiLauncherSHA256` bind the
exact installed regular files, not their version output. The source list has 4..4096 entries. Its
first three entries, in order, have kinds `node_source`, `pi_package`, and
`pi_shrinkwrap`, names `node`, `@earendil-works/pi-coding-agent`, and
`pi-shrinkwrap`, and versions `22.22.0`, `0.82.1`, and `0.82.1`. All remaining
entries have kind `npm_archive`, are ordered by `(name, version, filename)` in
strict byte order, and have a unique filename and unique `(kind,name,version,
filename)` tuple. Empty transitive sets, duplicates, optional/native packages
not represented by an entry, floating versions, lifecycle-script outputs not
represented by an entry, and nil/empty interchange are invalid. The lock has
no URL, registry, endpoint, path, command, environment, header, credential,
token, or signature field. D7 source authenticity belongs to the D7
source-lock issuer and its reviewed offline cache acquisition; D2 does not
invent a public signing key or signature ABI.

The process facts are exact, not a general binary inventory. Their catalog is
`L8ProcessCompositionCatalogV1`; all twelve digest fields are required. The
six binary fields bind the exact installed `hal-guest-agent`, `hal-guest-init`,
`hal-guest-credential-helper`, `hal-guest-mount-monitor`,
`hal-guest-workload-shim`, and freestanding `hal-guest-role-bootstrap` bytes.
`HelperDescriptorSHA256`, `ClientDescriptorSHA256`, and
`CompositionSHA256` are the exact `HL8D` values defined above.
`WorkloadPolicySHA256`, `RuntimePolicySHA256`, and `SyscallPolicySHA256` bind,
respectively, the canonical workload-transition policy artifact, the complete
role/runtime policy artifact, and the amd64/x32 syscall-policy catalog artifact
closed by the syscall supplement. D7 produces those three canonical artifacts
from the exact phase head and embeds their digests in the guest binaries; it
independently copies the same values into `L8ProfileFacts`. A descriptor label,
binary filename, static version string, or live guest response cannot replace
any digest.

The final-inspection `Checks` slice is non-nil and has exactly these 22 records
in this order, each once, each with `status:"pass"`, and each with a distinct
nonzero evidence digest:

```text
parent_l7_profile
kernel_network_profile
guest_binary_inventory
binary_owner_mode
node_runtime
pi_runtime
pi_dependency_tree
offline_source_inventory
package_manager_state_absent
credential_material_absent
identity_layout
pid1_launch_order
process_composition
workload_policy
runtime_policy
syscall_policy
native_bootstrap
vsock_listener_table
filesystem_privilege_absent
filesystem_private_modes
kernel_tmpfs_mount_namespace
kernel_cgroup_v2_kill
```

This catalog is sufficient for profile issuance only when the typed top-level
facts also correlate. An inspection record is a safe assertion digest, not raw
debugfs/ELF/disassembly output. D7 keeps raw inspection output outside the
distribution and emits a digest over each canonical safe assertion record.
Warnings, `skip`, duplicate/reordered/extra/missing checks, a zero digest, or
an unrecognized status fail closed.

#### Parent identity and canonical fingerprints

The parent is not a label. `ParentL7.ImageProfile` is exactly
`l7-firecracker-network-v1`; its five digest/size facts are measured from one
already verified, no-follow-opened L7 bundle. Its evidence digest is:

```text
SHA256(
  opaque16("hal/l8/image-profile/parent-l7-evidence/v1") ||
  token("l7-firecracker-network-v1") ||
  digest32(manifestSha256) || digest32(provenanceSha256) ||
  digest32(checksumsSha256) ||
  uint64_be(kernelSizeBytes) || digest32(kernelSha256) ||
  uint64_be(rootfsSizeBytes) || digest32(rootfsSha256))
```

`opaque16` and `token` mean a `uint16_be` byte length followed by those bytes;
`digest32` decodes the lower-case hexadecimal input to exactly 32 bytes.
Sizes are positive and at most 1,073,741,824. No JSON encoding, map order,
platform path, timestamp, or source URL participates.

The private descriptor fingerprint supports only a validated normalized
two-asset L8 distribution descriptor. The L8 resolver constructs exact ID
`l8-production-credentials-image`, exact labels `firecracker`, `reproducible`,
`network-profile`, `production-credentials-profile` in that order, and exact
assets `vmlinux` then `rootfs.ext4`. The L8 validator rejects any other order;
the generic descriptor normalizer does not sort caller input. The fingerprint is:

```text
SHA256(
  opaque16("hal/l8/image-profile/descriptor/v1") ||
  token(descriptor.ID) || tokenList(descriptor.Labels) || uint16_be(2) ||
  for each asset:
    token(asset.ID) || token(asset.Role) || token(asset.Kind) ||
    tokenList(asset.Labels) || token(asset.Source.Type) ||
    token(asset.Source.HostPath.Role) || token(asset.Source.HostPath.Path) ||
    token(asset.Lock.Digest.Algorithm) || digest32(asset.Lock.Digest.Value) ||
    uint64_be(asset.Lock.SizeBytes) ||
    uint64_be(asset.Lock.LockedAtUnixMillis))
```

`tokenList` is `uint16_be(count)` then tokens in existing normalized order.
The exact L8 descriptor has no init config, agent config, or resources. The
private path participates so a source path and lease-owned launch-material path
cannot share a descriptor fingerprint; it is never logged or exposed.

The exact L8 distribution contains exactly seven regular files, in byte-order:
`SHA256SUMS`, `distribution-manifest.json`, `final-inspection.json`,
`provenance.json`, `rootfs.ext4`, `sources.lock.json`, and `vmlinux`.
`SHA256SUMS` contains exactly the other six names in that order. The evidence
fingerprint uses the digest and size measured from every no-follow-opened file:

```text
SHA256(
  opaque16("hal/l8/image-profile/evidence/v1") ||
  for each of the seven names in byte order:
    token(name) || uint64_be(size) || digest32(fileSha256) ||
  digest32(parentL7.evidenceSha256) ||
  digest32(sourceLockSha256) || digest32(finalInspectionSha256) ||
  digest32(nodeSha256) || digest32(piLauncherSha256) ||
  digest32(piDependencyTreeSha256) ||
  digest32(helperDescriptorSha256) || digest32(clientDescriptorSha256) ||
  digest32(compositionSha256) || digest32(workloadPolicySha256) ||
  digest32(runtimePolicySha256) || digest32(syscallPolicySha256))
```

The validator first proves that the typed manifest/provenance/source-lock/
inspection values agree and that their named file digests agree with the
checksum inventory. Consequently the fingerprint binds the manifest,
provenance, source lock, final inspection, parent L7 bundle, helper/client/
composition, and workload/runtime/syscall artifact digests. This resolves the
L7 evidence substitution weakness: L7's current profile can be recreated from
a descriptor alone during private launch-material preparation, whereas no L8
path can create or replace its evidence fingerprint from a descriptor.

#### Pure validators and precedence

The build package exports only these pure validators for the additive values:

```go
func ValidateL8DistributionManifest(DistributionManifest) error
func ValidateL8Provenance(Provenance) error
func ValidateL8ProvenanceAgainstManifest(Provenance, DistributionManifest) error
func ValidateL8SourceLock(L8SourceLock) error
func ValidateL8FinalInspection(L8FinalInspection) error
```

They return this exact safe error shape:

```go
type L8ValidationCode string

type L8ValidationError struct {
	Code  L8ValidationCode `json:"code"`
	Field string           `json:"field,omitempty"`
	Index *int             `json:"index,omitempty"`
}
```

`Index` is an optional zero-based source/check index; `Error()` is only
`"L8 image profile validation failed: <code>"`. Rejected values and wrapped parser errors never appear.
Codes are closed: `schema_invalid`, `profile_invalid`, `parent_invalid`,
`version_invalid`, `catalog_invalid`, `count_invalid`, `order_invalid`,
`field_invalid`, `digest_invalid`, and `correlation_mismatch`.

Validation returns the first error in this exact precedence: (1) schema and
profile discriminator, (2) required pointer/slice presence and count/size
bounds, (3) fixed versions and catalog identifiers, (4) parent evidence and
top-level scalar syntax, (5) ordered entry/check syntax and uniqueness, (6)
per-entry sizes/digests with ascending index, and (7) cross-document
correlation. Within a struct, fields are visited in declared order; within a
slice, indexes ascend. Cross-document correlation order is parent, runtime,
process composition, source-lock digest, final-inspection digest, rootfs,
then output/asset equality. Validation does not trim, lowercase, sort, default,
drop, or mutate. Generic L5/L7 validation remains byte/behavior compatible and
delegates to the L8 validator only for the exact L8 discriminator.

The resolver retains its existing bounded `json.Decoder` unknown/trailing-field
behavior. Resolver classification is exact: a typed build validation error is
`manifest_invalid`; missing/unreadable metadata is `file_unavailable`; wrong
entry set/type is `unsupported_file_type` or `manifest_invalid` as today;
checksum, measured digest, correlation, parent-evidence, or final-inspection
mismatch is `asset_lock_mismatch`. Public field names are only
`distributionManifest`, `provenance`, `sourceLock`, `finalInspection`,
`checksums`, `parentL7`, `l8Profile`, or `assets`; messages never contain an
input value, filename beyond those fixed public names, path, URL, or parser
text.

#### Opaque resolver proof and lease

`internal/sandboxruntime/microvm/assets/localresolver` owns these exact APIs:

```go
type VerifiedL8Profile struct { /* private seal and two private [32]byte fingerprints */ }
type VerifiedL8AssetLease struct { /* private pinned bundle and launch material */ }

type L8LaunchMaterialWriter interface {
	WriteAsset(assets.AssetRole, io.Reader) (string, error)
	Validate() error
	Close() error
}

func (VerifiedDistribution) L8Profile() (VerifiedL8Profile, bool)
func (VerifiedDistribution) AcquireL8AssetLease() (*VerifiedL8AssetLease, error)
func VerifiedL8ProfileMatches(*VerifiedL8Profile, *assets.LaunchDescriptor) bool

func (*VerifiedL8AssetLease) ConfirmCurrent(*assets.LaunchDescriptor) error
func (*VerifiedL8AssetLease) PrepareLaunch(
	*assets.LaunchDescriptor,
	L8LaunchMaterialWriter,
) (assets.LaunchDescriptor, VerifiedL8Profile, error)
func (*VerifiedL8AssetLease) Close() error
```

There is no public constructor or fingerprint accessor. The existing
`VerifyDistributionBundle(DistributionRequest)` remains the five-file L5/L7
entry point and cannot issue L8 authority. The sole L8 issuer is the separate
exact entry point:

```go
type L8DistributionRequest struct {
	DistributionRequest
	ParentL7 VerifiedDistribution
}

func VerifyL8DistributionBundle(L8DistributionRequest) (VerifiedDistribution, error)
```

The request requires a nonzero resolver-issued parent distribution whose
`L7Profile()` is valid and whose current parent asset lease can be acquired and
confirmed. A copied public manifest/provenance/descriptor without that private
parent authority is invalid. `VerifyL8DistributionBundle` is the sole opaque
`VerifiedL8Profile` issuance path. It issues only after the
exact seven-file entry/type check; bounded strict decoding; all five pure
validation/correlation checks; exact checksum inventory; current asset locks;
parent L7 evidence fingerprint; final-inspection catalog; descriptor
normalization; and both canonical fingerprints succeed. `ResolveDistribution`
may return an L8 descriptor for diagnostics but never a profile or lease.
Synthetic fakes live only in `_test.go` or explicitly fake-only files and have
no production command reachability.

The opaque value contains one active private seal, the descriptor fingerprint,
and the evidence fingerprint. `VerifiedL8ProfileMatches` validates and
normalizes the candidate and compares only against the sealed descriptor
fingerprint; the evidence fingerprint is intentionally not caller-readable.
A zero value, copied fields in an external literal, a nil pointer, a generic,
L5, or L7 descriptor, or any descriptor drift fails.

`AcquireL8AssetLease` pins the opened distribution root plus all seven current
regular files, verifies root/file identity and every digest again, and copies
both private fingerprints from the verified distribution. `ConfirmCurrent`
reopens the current root entries without following links, requires the exact
entry set and retained identities/digests, and accepts only the source
descriptor or its one lease-owned prepared descriptor. Metadata replacement,
parent evidence replacement, inspection replacement, or asset replacement
therefore fails even if a caller preserves the launch descriptor.

`PrepareLaunch` is single-use. It confirms the source before copying, streams
only the pinned kernel and rootfs into an `L8LaunchMaterialWriter`, verifies
size/digest while copying, requires distinct private destinations, normalizes
the prepared descriptor, validates sealed material, and confirms the complete
source bundle again. It then creates a new sealed profile internally whose
descriptor fingerprint is recomputed for the private descriptor and whose
evidence fingerprint is copied unchanged from the lease. No descriptor-only
constructor is called. The material and every pinned source/evidence handle
remain lease-owned until idempotent `Close`; a cleanup error is sanitized and
stable across repeated close calls.

#### Firecracker and guest boundary

The explicit L8 overlay and `BackendConfig` add these adjacent JSON-omitted
fields after their existing L7 counterparts:

```go
VerifiedL8Profile *localresolver.VerifiedL8Profile `json:"-"`
VerifiedL8Assets *localresolver.VerifiedL8AssetLease `json:"-"`
```

L7 and L8 profile/lease fields are mutually exclusive. The L8 path requires
both L8 fields, the exact L8 network mode inherited from the verified parent,
one NIC/static-network overlay, production VSOCK, and the exact current runtime
generation. Before render, immediately before process start, and after a
successful synchronous start handoff it calls the L8 lease current-asset check
and `VerifiedL8ProfileMatches` against the exact descriptor it uses. Any
failure closes the owned lease and returns a sanitized L8 live-config error.
Firecracker does not parse a source lock, final-inspection artifact, checksum
file, or label and cannot infer a capability from an image ID.

The host profile never enters the guest. D7 embeds the exact expected workload, runtime, and syscall-policy catalog digests
plus helper, client, and composition digests into the built guest binaries, and independently binds the same values
into the host `VerifiedL8Profile` evidence. PID1 compares authenticated live
process descriptors with those embedded expectations; the host separately
requires its opaque profile. Neither side accepts the other's assertion as a
substitute, and no host path, source-lock body, inspection body, or opaque
profile is sent over VSOCK.

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
