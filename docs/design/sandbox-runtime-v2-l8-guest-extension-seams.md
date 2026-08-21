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

guestagent/syscallpolicy <--------- D4 Linux consumers              D2 standard-library-only neutral leaf
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

- `guestagent/syscallpolicy` is a standard-library-only neutral leaf. D2 owns
  its canonical artifact grammar, importer/verifier, immutable copied views,
  pure decisions, exact `FilterRules` own/ancestry projection, complete
  catalog-bound `FilterProfile`, fake
  observations, fixtures, and guards. D7 alone authors and issues the complete
  role/workload/runtime/catalog artifact. D4 imports this leaf for filter compilation
  only through `FilterProfile` and consumes semantic rows only through the
  concrete two-phase `AdapterBindings` plus `AuthorizePre` permit then
  `AuthorizePost`/`CommitNoObject` adapter. Its private one-use wrapper is
  exactly `unstarted -> claimed -> executed -> finalized`. D4 creates one inert `unstarted` wrapper before `NewAdapterBindings`; the same wrapper identity is
  the sole production `BindingSource` and initially has no permit, closure, or
  live syscall authority. It alone retains the exact opaque bindings/token.
  Binding or pre-authorization failure destroys it synchronously with zero
  syscall/terminal calls and no escape. Success installs the permit and closure
  in that identity, then claims before escape. There is no replacement,
  cross-wrapper transfer, or acceptance of foreign bindings. After claim,
  pre-syscall cancellation/failure calls the phase-explicit
  `AbortPermit` with `AdapterPhasePre`, the exact same permit, and zero syscall
  calls; otherwise it makes exactly one syscall and exactly one post/commit on
  success or the phase-explicit `AbortPermit` with `AdapterPhasePost` and the
  exact same permit on syscall failure. Abort and successful-syscall terminal
  routes cannot be interchanged. All wrong-phase, duplicate, second,
  concurrent, and post-finalization calls fail closed with no retry on that
  wrapper, ticket, or permit. State/fact-narrowed rows have no
  direct/raw-syscall seam. `EnforcementPathPinnedDirect` is limited to D7's
  source-locked native child-bootstrap and pinned-Go runtime callsites; D7's
  exact complete per-role/kind binary set, external final-binary evidence, and
  identical `policySourceLockSHA256` / `policyBinaryBindingSetSHA256` /
  `pinnedCallsiteEvidenceSHA256` host-profile bindings are mandatory, and D4/D6
  cannot add or widen a pinned callsite. The scalar-only workload exception is
  limited to ordinary-catalog `RuleOriginWorkload` rows imported from the
  source-locked snapshot after final exec, with no helper pointer provenance,
  conditional/fatal authority, ticket, or adapter;
  the freestanding `rolebootstrap` source consumes generated golden data rather
  than a Go import. There is no reverse import from `syscallpolicy` to D4,
  helper, client, composition, command, runtime, worker, factory, provider, or
  live platform packages. D6 may select only a guest binary whose embedded
  artifact verified locally; it never passes a host profile or artifact through
  the guest boundary and cannot mint or mutate rows.
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

The package has one and only one private
`func newServiceResult(ServiceDisposition, credentialprotocol.CloseReason) (ServiceResult, error)`
declaration across all production files and build contexts. It is the existing
`service_values.go` issuer, not a variable, function alias, alternate build
definition, or caller-local lookalike. Its exact body first rejects an invalid
disposition or close reason with `ErrContractInvalidArgument`, admits only
`ServiceClosed` with `normal|shutdown` and `ServiceStopVMRequired` with
`protocol_error|identity_drift|expired|helper_loss`, rejects every other pair
with `ErrContractResultMatrix`, and returns the exact private disposition and
close-reason fields. The recovered-panic and body-destroy-error paths call this
same unshadowed declaration; a syntactically matching call cannot substitute a
different issuer.
The reducer must be selected in every supported build context in which the
Service is selected: Linux, Darwin, FreeBSD, and Windows on amd64 under the
repository's default non-cgo build tags. A declaration selected only on one
platform cannot satisfy another platform, while any alternate tagged duplicate
still violates the package-wide uniqueness rule.

The configured Service owner has exactly these top-level private fields, in
this order:

```go
type Service struct {
	core       Core
	transport  Transport
	policy     Policy
	extensions []extensionEntry
	host       ExtensionHost
	runtime    ServiceRuntime
	state      *serviceState
}
```

`serviceState` is the sole synchronized owner for the complete fixed Service
FSM. It contains `mu sync.Mutex`, `serveCalled bool`, and the sole
`execution CoreExecution` field derived only from a valid
`Service.core.BeginExec` return; the remaining fixed
ledgers and authority state are the fields closed by the Service-ledger
section below. No configured dependency, extension entry, latch, ledger, or
live owner is duplicated outside that state topology. `NewService` applies
`configuredDependency` separately to Core, Transport, Policy, Host, and
Runtime before calling any method. A nil Extensions pointer means the empty
set; otherwise the constructor snapshots the private `[]extensionEntry` in
canonical order through the exact private
`snapshotServiceExtensionEntries(*ExtensionRegistry) []extensionEntry`
helper. That helper allocates a new slice, retains no registry or source-slice
alias, preserves entry order and factory identity, and deep-clones every
descriptor with `credentialprotocol.CloneExtensionDescriptor`. It initializes
every one of the seven private fields and
allocates exactly one fresh empty `&serviceState{}` literal; keyed initial
state, a preexisting owner, a nonzero execution, or a pre-set latch is invalid.
It retains neither the options
value nor a caller-owned registry slice.
After construction the five configured dependency fields and the owned
extension snapshot are immutable throughout every Service method reachable
from `Serve`. They cannot be replaced directly, through a Service alias or
pointer, by assigning a field/composite, or by passing the field or its address
to a helper. Direct method invocation on the exact stored dependency remains
the only use; copying a dependency into a substitute local does not authorize
a different receiver. Thus the dependency validated by `NewService` is the
same dependency used by every dispatch and Core boundary.

`Serve` first applies the common plain-nil/typed-nil context classification and
returns that exact classification error; a syntactically present check whose
condition cannot reject or whose return suppresses the error is invalid.
A valid first call enters one exact `state.mu` critical section which checks
and sets `state.serveCalled` atomically; the check is not cached, unlocked, or
split across two critical sections. Every later call returns
`ErrContractTransition` from that same critical section without touching
Transport, Runtime, Core, Policy, Host, or an extension. The successful latch
is never reset and `state` is never replaced, including through any receiver
or state alias in a private Service method reachable from `Serve`, after caller
cancellation, panic reduction, drain, or a terminal result. Only that one Serve lifetime owns the configured
dependencies and all state transitions. The production AST guard locks the
exact constructor and Serve signatures, configured-dependency storage, fresh
state allocation, and synchronized one-Serve latch while allowing the fixed
FSM internals described below to remain privately organized.

The constructor's five `configuredDependency` results control one immediate
`ErrContractDependency` rejection before any dependency method, snapshot,
storage, or returned Service exists. Calling the helper while ignoring its
result, checking after storing a
dependency, or retaining `ExtensionRegistry.entries` directly is invalid.
Seeded negative AST fixtures lock those cases, suppressed/noncontrolling
context checks, context-after-latch, out-of-lock/distributed latch operations,
reachable receiver/state-alias reset or replacement, nonfresh state,
unrelated lookalike method and scoped-type names, wrong callback contexts,
proposal-variable substitution or ignored results, noncontrolling/AND Core
failure gates, wrong Core receivers, foreign executions, comparison fallthrough,
and Core calls in comparison.

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
	claimed       bool
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
service-only `claimAndMatch` and `destroy` transitions serialize on that private
mutex. `claimAndMatch` is the sole atomic receive-constructor claim and decoded-
plan comparison described below. `destroy` waits for any in-flight `CopyCanonicalTo` call,
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

#### D2 Service Prepare/Renew and first-seen Exec prerequisites

The helper-Service Prepare/Renew and first-seen Exec slice has three explicit
private prerequisites.
They are production AST contracts, not prose markers, and none may be replaced
by a caller-supplied `CorePrepareRequest`, `CoreCommitRequest`,
`CoreRenewRequest`, digest, capability, activation, or transaction. Exec
completion, the fixed 4,096-entry result ledger, and comparison-replay issuance
remain a separate prerequisite slice; this slice issues and installs only the
authenticated first-seen in-flight Exec dispatch.

First, the sole capability issuer is
`newServiceCoreCapabilityDigest(kind serviceCoreCapabilityKind, correlation
requestCorrelation, generations CoreGenerations, bootNonce [32]byte)
([32]byte,error)`. The private typed catalog is exactly preparation `1`,
prepared `2`, execution `3`, and cleanup `4`. Its body implements the exact
`hal/l8/guest-helper/core-capability/v1` encoding above, including every empty
partial-generation position. The declaration is unique across every supported
build context. No variable, function value, wrapper, alternate build-tag body,
or public constructor can mint these digests. The domain literal occurs only in
that issuer. Every nonzero `CorePreparationCapability`,
`CorePreparedCapability`, or Prepare-cleanup capability literal is constructed
only inside the exact `newServicePrepareCapabilities` body from that issuer's
three returned digests; a direct or aliased capability composite, conversion,
field write, copied domain encoder, or execution-capability literal is not an
alternate issuance route. That immutability proof follows capability values
through selector/index/container and pointer/parenthesized expressions,
including package or function-local named container types, method receivers,
type assertions, inferred package values, and range-derived aliases. Taking the
address of a capability digest, slicing it for `copy`, returning, passing, or
storing that writable view (directly or through an alias), assigning or
incrementing one of its indexed bytes, or mutating a nested capability field is
invalid. Provenance is attached to the exact lexical declaration and exact
field/index/range position: a copied container retains only its capability
field paths, map key and value roles are not conflated, and an unrelated sibling
field or same-spelled local value/type is not classified as a capability.
Generic instantiations substitute each exact type argument before their field
paths are followed; embedded fields, interface method results, positional
multi-results, and range-over-function yields retain the corresponding
authority only at the exact value position. Parentheses do not erase a call's
positional results, and named callback types preserve range-function yield
positions. Recursive generic definitions use a finite declaration-cycle proof;
ordinary, generic, and mutually recursive edges neither recurse without bound
nor lose an owner reachable after the cycle. A function-local
declaration that merely reuses a capability or constructor spelling remains
unrelated because the proof binds the package declaration object rather than
its text.
Ordinary copy-safe value reads remain permitted. A writable digest view may be
passed only to `ConstantTimeCompare` on the exact file import bound to
`crypto/subtle`; a local/package shadow or lookalike method with that spelling
is not the comparison primitive, while parentheses around that exact imported
function do not change its binding. The sole Core
Prepare/File/Commit/Renew and receive-request constructor call sites, plus the
two exact Core Revoke cleanup sites, are confined by declaration identity, not
merely by callee spelling; an unrelated receiver method with the same name is
not that constructor.

Every prerequisite declaration and live edge must be selected in each
supported linux, darwin, freebsd, and windows amd64 build context in which
Service is built. A sole build-tag-specific implementation, alternate body, or
duplicate declaration cannot satisfy the package contract.

Second, one private `servicePrepareAuthority`, one state-owned
`servicePreparing`, one ephemeral `servicePreparedActivationCandidate`, and
one Service-owned `servicePreparedActivation` close successful Commit transfer.
Their exact leading definitions are:

```go
type servicePrepareAuthority struct {
	header credentialprotocol.HelperPacketHeader
	bootstrap ServiceBootstrap
	observation ServiceJobObservation
	correlation credentialprotocol.HelperPrepareTransactionCorrelation
	prepare CorePrepareRequest
	transaction *credentialprotocol.HelperPrepareTransaction
}

type servicePreparing struct {
	authority servicePrepareAuthority
	preparation CorePreparation
	beginTaken bool
	fileTaken bool
	commitTaken bool
	active bool
}

type serviceState struct {
	mu sync.Mutex
	nextReceiveSequence uint64
	preparing servicePreparing
	prepared servicePreparedActivation
}
```

The authority is minted only by `newServicePrepareAuthority(ReceivedPacket,
ReceivedPrepareBegin, ServiceBootstrap, ServiceJobObservation)`. It accepts the
exact authenticated `PacketTypePrepareBegin` header and typed arm, requires the
arm's retained transaction, binds its revision, expiry, manifest and manifest
SHA-256, the configured Runtime bootstrap and complete job observation,
projects the sole exact partial tuple with
`NewCoreGenerations(boot, helper, job, "", "", "")` and immediately rejects
its error, creates the exact protocol transaction correlation, pre-mints the three partial-tuple
capabilities, and is the sole caller of `NewCorePrepareRequest`. The exact
configured `Core.BeginPrepare(ctx, authority.prepare)` result is installed once.
Before that external call, `reservePreparing` atomically rejects an existing
reservation, preparation, or activation and transfers the exact transaction
into the `beginTaken` state entry. `installPreparing` consumes only that exact
reservation and transaction under `state.mu`; neither the authority nor that
live Core owner is caller supplied. Until install succeeds, an enclosing
handler recovery closes the exact transaction and rolls back any returned
`CorePreparation`. No error, panic, typed-nil result, occupied-state race, or
received-body cleanup failure can leave either owner outside the state or the
terminal cleanup reducer.

Every configured Transport receive first issues the sole exact
`NewReceiveRequest(nextReceiveSequence,
credentialprotocol.MaxHelperPacketBodyBytes, 0)` under `state.mu`, increments
that sequence exactly once, and passes that exact request to configured
`Transport.Receive`. The main Serve loop and the private continuation use the
exact panic-isolated `receiveServicePacket`; a synchronous Receive panic is
reduced to `ErrContractOwnership` rather than escaping Service. This applies
both to the main Serve receive and to each
private/stdin continuation dispatcher: each calls the exact unshadowed
`s.newServiceReceiveRequest()`, checks its error immediately, and passes only
that returned local value. A package global, caller value, stale state copy,
foreign issuer, ignored error, or rebound request is invalid. The returned
packet is dispatched once by its exact type.
Every successful receive transfers its body and possible unexpected right to
Service: all handler, error, panic, and unknown-type paths call the one
panic-isolated `destroyServiceReceivedPacket`, bind the body `Destroy(ctx)`
error, and, when nonnil, bind the right `Close(ctx)` error. Each owner is offered
exactly one cleanup call with the same context; cleanup failure reduces to the
sanitized ownership error.
On a main-loop Receive error, exact `finishServiceReceive` synchronously converges preparing ownership
through abort, prepared ownership through
revoke, and an installed Exec through `finishExecDispatch`, then returns a
valid stop-VM result. It never returns an unknown result with a live owner.

The Serve-reachable `PacketTypePrepareFile` handler takes the matching state entry once by
setting `fileTaken` under `state.mu`; Commit rejects while it is set. Before any
Core call, `newServiceFileRequest` snapshots the retained transaction and
requires a live, noncommitted, no-pending state whose exact next binding index
equals the arm. It resolves that same manifest binding, requires `file_tmpfs`,
and binds its length, digest, target, request correlation, revision, job,
preparation capability, and binding ID into the sole `NewCoreFileRequest`.
The independently retained packet-body digest and length are checked against
the authenticated arm. Within one synchronous body `Borrow`, the exact stored
`CorePreparation.StageFile` succeeds before the retained transaction accepts
`NewHelperPrepareFileObservation(declaredDigest, observedBodyDigest)`. Only
that complete path clears `fileTaken`. Any callback error, panic, observation
failure, body cleanup failure, out-of-order file, or state race enters the
reachable precommit reducer, which atomically takes the state owner, closes the
transaction, and performs bounded `CorePreparation.Rollback` result-matrix
handling.

The Serve-reachable Commit handler receives a new exact authenticated
`PacketTypePrepareCommit` arm, uses `takePreparing` to latch the matching
Service-owned entry once, and calls the sole `newServiceCommitRequest`. That
issuer invokes the retained prepare transaction's `Commit` with the stored
correlation and exact typed commit body, then is the sole caller of
`NewCoreCommitRequest` using the stored Prepare request/capabilities and exact
transaction result. Only the retained `CorePreparation` receives that Commit
request.

The candidate stores, in order, the exact Service-owned issuing Prepare
correlation, boot nonce, expected complete generations, observed time, immutable
hard expiry, current expiry, immutable manifest, binding count, manifest digest,
transaction digest,
pre-minted prepared and cleanup capabilities, and exact active-proof ID. The activation stores,
in order, that immutable issuing correlation, separate current revision, boot
nonce, complete generations, current observed time, immutable hard expiry,
current expiry, immutable manifest and binding count, manifest and transaction
digests, prepared and cleanup capabilities, current
active-proof ID, and active latch. The prepared capability and issuing
correlation never change on Renew.
The unique private `newServiceActiveProofID` implements the already-frozen
`active.` label formula over exact correlation, complete generations, boot
nonce, expiry, manifest digest, and transaction digest; no caller supplies a
proof or digest.

```go
type servicePreparedActivationCandidate struct {
	issuingCorrelation requestCorrelation
	bootNonce [32]byte
	generations CoreGenerations
	observedUnixNano int64
	hardExpiryUnixNano int64
	expiresUnixNano int64
	manifest ManifestCapability
	bindingCount uint16
	manifestSHA256 [32]byte
	transactionSHA256 [32]byte
	prepared CorePreparedCapability
	cleanup CoreCleanupCapability
	activeProofID credentialprotocol.SafeID
}

type servicePreparedActivation struct {
	issuingCorrelation requestCorrelation
	revision uint64
	bootNonce [32]byte
	generations CoreGenerations
	observedUnixNano int64
	hardExpiryUnixNano int64
	expiresUnixNano int64
	manifest ManifestCapability
	bindingCount uint16
	manifestSHA256 [32]byte
	transactionSHA256 [32]byte
	prepared CorePreparedCapability
	cleanup CoreCleanupCapability
	activeProofID credentialprotocol.SafeID
	active bool
}

type serviceRenewAuthority struct {
	activation servicePreparedActivation
}
```

Within `serviceState`, `mu`, `nextReceiveSequence`, `preparing`, and `prepared`
occur in that exact relative order. `newServiceReceiveRequest`,
`reservePreparing`, `installPreparing`, `takePreparingFile`,
`finishPreparingFile`, `takePreparing`, `abortPreparing`,
`installPreparedActivation`, `revokeCommittedPreparation`,
`newServiceRenewRequest`, `advancePreparedActivation`,
`receiveServicePacket`, and `finishServiceReceive` are the only
functions allowed to read or mutate those owners as frozen; any alias, address,
return, helper argument, increment,
alternate assignment, function-value issuer alias, wrapper, or additional
writer is invalid, including in package free functions rather than only
`*Service` methods. This includes transitive Service-state aliases and pointers
to an aliased `prepared` or `preparing` field; storing or passing the state
owner through a global, helper, return, send, container, or conversion cannot
hide the same prohibited read, mutation, or escape. Package- or function-local
named types and aliases, pointer layers such as `**Service`, container wrappers,
conversions, and type assertions whose underlying value is `*Service` preserve
the same owner for this proof; changing a free-function parameter's spelling or
wrapping, selecting, copying, invoking a function-valued factory, and
dereferencing it does not declassify its state. The same rule applies to direct,
named, converted, or asserted `*serviceState` owners. Package-global
`*Service` and `*serviceState` values seed the same graph. Exact lexical
identity and exact field/index/range roles keep same-spelled inner bindings and
unrelated sibling or map values outside that graph.
Anonymous embedding and promoted selectors, instantiated generic fields,
interface method results, every positional function result, and
range-over-function yields preserve the exact Service/state owner position.
Function-local lookalike activation types or issuer values are unrelated; exact
candidate and activation construction is credited only to the package
declarations and their aliases.

`serviceRenewAuthority` is one ephemeral value-copy returned only with the
validated Core Renew request; it is never state, durable data, or a second live
owner. Its sole use is the exact post-Core unchanged-activation comparison.
The unique `newServicePreparedActivationCandidate` accepts only the exact taken
`servicePreparing`, authenticated Commit header, Runtime job observation,
successful `CoreCommitRequest`, and returned `CorePreparedResult`. It binds the
exact `PacketTypePrepareCommit`, request IDs,
identity, revision, boot nonce,
boot/helper generations, all six complete generations, expiry, binding count,
manifest/transaction digests, prepared-capability echoes, and the exact
`active.` proof-label derivation before returning the private value. Prepare
expiry is strictly after the Runtime observation time and no later than its
hard horizon; the latter is not conflated with current expiry.
`(*Service).installPreparedActivation(preparing, header, observation, commit,
result) error` first calls that exact issuer and then, under `state.mu`, accepts
only the live one-use preparing entry and no existing activation. It installs
one activation, clears the preparing owner, and returns. Candidate literals,
alternate issuers, caller-supplied
correlations/digests/capabilities, and every other prepared-state write are
invalid.

The cleanup capability is the exact Prepare-issued value and is retained,
unchanged, beside the prepared capability; it is never reminted. Every
precommit failure after state take runs the one `abortPreparing` consumer,
which atomically removes the exact owner, closes its transaction, and invokes
the exact returned `CorePreparation.Rollback`. Cleanup results obey the frozen
complete/retry/stop-VM matrix and are retried at most three times; panic,
foreign capability, malformed result, or exhaustion is a sanitized terminal
stop-VM error. If `CorePreparation.Commit` succeeds but candidate validation or
installation fails—or later received-packet cleanup fails—the reachable
`revokeCommittedPreparation` path uses the stored prepared and cleanup
capabilities and exact complete observation to issue `Core.Revoke`, never
Rollback. It closes the now-terminal transaction, but transaction cleanup
failure or panic cannot suppress the Core Revoke attempt; both cleanup results
are accumulated and any noncomplete outcome is reduced conservatively. It
validates the same bounded
cleanup matrix, and converges to absent or stop-VM. This prerequisite performs
no unauthorized immediate repeat Revoke: `retry_required` is validated and
conservatively escalated to the sanitized stop-VM result here; the later full
Service cleanup episode owns the frozen Revoke-then-Inspect retry protocol.
The postcommit boundary begins immediately before invoking
`CorePreparation.Commit`, because a panic or error cannot prove that Core made
no mutation. Thus no attempted Core Commit can strand an uninstalled
activation.

The call edges are live, not pasted helpers or statements after a terminal.
The public `Serve(context.Context) (ServiceResult, error)` keeps the exact
context-first one-shot latch, then runs the exact request/receive loop and a
packet-type switch. The four PrepareBegin/PrepareFile/PrepareCommit/Renew
clauses assign their exact handler result to the shared `handlerErr`, followed
by its immediate rejection gate. In this bounded composition, the only
additional clause admitted before a later boundary is the exact returned
`PacketTypeExec` edge; an arbitrary packet clause, direct Core call, or foreign
request is invalid. A later clause may be added only when its own exact boundary
is composed into this topology. In the combined satisfiability contract, the
exact returned `PacketTypeExec` edge carries the same received
packet and context to the already-guarded Exec handler, whose live returned
private/stdin and literal-nil zero-private branches remain independently exact.
An ignored result, rebound packet/context, dead clause, extra receiver helper,
or Prepare-only switch does not satisfy the combined Service topology.
Package or local named constants are evaluated in their lexical scope for this
proof, so `const prepareCommit = false` cannot make a textual Commit call live.
An assignment-form handler call after an unconditional return is equally dead.
Serve-reachable Begin and Commit handlers each obtain their exact packet from
`Service.transport.Receive`; they extract only the matching typed arm, derive
bootstrap from configured `Service.runtime`, and construct
the exact `ServiceOperationPrepare` observation request from that header,
typed-arm revision, and bootstrap generations. Only the configured Runtime's
complete result reaches the exact partial-tuple projector and issuers; monitor,
mount, or cgroup may not leak into the Prepare request. Only the exact configured
`Service.core.BeginPrepare(ctx, authority.prepare)` result may be stored, only
that stored result may receive the exact issued Commit request, and only its
successful result may reach `installPreparedActivation`. Foreign/global
CorePreparation, packet/header/arm, Runtime result, request, transaction,
authority, dead branch, or helper-only declaration does not establish
activation authority.

Renew advances only the mutable activation projection. A Serve-reachable Renew
handler receives the exact authenticated `PacketTypeRenew` arm. Before calling
Runtime, `validateServiceRenewArm` rejects a stale/gapped revision, changed
identity/boot nonce, non-increasing expiry, or wrong prior-proof digest, so an
untrusted invalid arm cannot force cleanup. The handler then derives its
`ServiceOperationRenew` observation request from that header, arm revision, and
the stored boot/helper generations. Only the configured Runtime's exact
observation may reach `(*Service).newServiceRenewRequest`; it must retain the
complete generation tuple and hard horizon, advance observed time, bind the
stored active-proof ID through the exact `renew-proof/v1` digest, use current
revision plus one, and place expiry in
`(observedUnixNano, hardExpiryUnixNano]` strictly above current expiry. The
resulting exact `CoreRenewRequest` is passed once to configured
`Service.core.Renew(ctx, request)`. Only a nil return permits
`advancePreparedActivation` to revalidate the unchanged activation under
`state.mu` and update exactly revision, observed time, expiry, and replacement
active-proof ID. Issuing correlation, boot nonce, generations, hard horizon,
manifest/binding count, manifest/transaction digests, and prepared/cleanup
capabilities are immutable. A foreign
observation/Core, stale or gapped revision, widened hard horizon, mismatched
proof, rebound request, dead handler, or unlocked/alternate write is invalid.
Once configured Runtime has been called for that prevalidated arm, a Runtime
error/panic or malformed observation drives the exact active owner into
`revokeServicePreparedActivation`. The same is true immediately before Core
Renew is called, for any subsequent error/panic/state race, and for packet
Destroy/Close failure after successful Renew. That reducer atomically takes the
current activation, uses the immutable issuing Prepare request ID and identity
plus the current activation revision/generations and retained prepared/cleanup
capabilities, and invokes one internal Core Revoke. The outer Renew request ID
never becomes cleanup correlation. If Core Renew errors or panics after it may
have mutated, Service does not guess or install the attempted revision: cleanup
uses the still-installed current revision. A mismatch or noncomplete cleanup
therefore becomes the sanitized stop-VM result. After a nil Core result and
successful state update, later packet-cleanup failure uses the newly installed
current revision. Complete reaches absent; retry/stop/panic or
malformed cleanup becomes sanitized stop-VM with no immediate repeat Revoke.

Third, the authenticated first-seen Exec path has one ephemeral
`serviceExecAuthority` and one locked in-flight dispatch entry. Its exact
leading definitions are:

```go
type serviceExecCapabilities struct {
	execution CoreExecutionCapability
	cleanup CoreCleanupCapability
}

type serviceExecAuthority struct {
	request CoreExecRequest
	plan ExecPlanCapability
	revision uint64
	transaction *credentialprotocol.HelperExecTransaction
	correlation credentialprotocol.HelperExecTransactionCorrelation
	comparison bool
}

type serviceExecPlanSink struct {
	canonical [credentialprotocol.MaxHelperExecPlanBytes]byte
	length uint32
	written bool
}
```

`newServiceExecAuthority` consumes only the exact authenticated
`PacketTypeExec` header and typed `ReceivedExec` arm plus the immutable current
prepared activation. It verifies the exact revision, request identity, boot
nonce, complete generations, and safe Exec binding. It obtains the claimed
`ExecPlanCapability`, copies its canonical bytes exactly once into the bounded
fixed-array `serviceExecPlanSink`, verifies the plan length and SHA-256, decodes
that plan, reconstructs the exact `HelperExecBody` from the arm revision,
binding, private metadata, and decoded plan, encodes it canonically, and
requires its byte length to equal the authenticated header `BodyLength` before
hashing it. Both temporary canonical buffers are wiped on every path.

Every qualifier used by this prerequisite is resolved from the declaration's
own file: `sha256` is bound to `crypto/sha256`, `subtle` to `crypto/subtle`,
`sync` to the standard `sync` package for `serviceState.mu`,
`credentialmemory` to `github.com/jywlabs/hal/internal/credentialmemory`, and
`credentialprotocol` to
`github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol`.
The `ExecPlanCapability.CopyCanonicalTo` declaration, `serviceState` mutex,
and the Exec authority, body-identity, and plan-sink declarations retain those
exact bindings. Exact-path import aliases are normalized by lexical import
object before comparison; a local package, lookalike import, shadow, or
declaration-file substitution cannot satisfy this prerequisite.
`CopyCanonicalTo` is compared as a Go function signature: parameter and result
identifiers are irrelevant, while parameter/result arity, order, variadic
shape, exact import-bound types, and error result remain exact. This
name-insensitive signature comparison does not replace the independently
frozen plan capability body, single-claim provenance, or destruction rules.

The sole `newServiceExecCapabilities` mints execution kind `3` and cleanup kind
`4` against the first-seen Exec correlation, current complete generations, and
prepared boot nonce. Only `newServiceExecAuthority` calls
`NewCoreExecRequest`, with the reconstructed body length/digest, exact claimed
plan, retained prepared capability, and those two newly minted capabilities.
It creates the exact helper Exec transaction correlation and calls the arm's
retained transaction seed `Begin` only after all request validation and
construction succeed. Until transfer, panic/error cleanup closes the seed and
destroys the claimed plan.

`installExecDispatch` accepts only that authority, requires
`comparison == false`, and under the exact `serviceState.mu` revalidates the
active prepared revision and an empty dispatch slot. It then installs, in
order, the exact request, claimed plan, revision, helper transaction,
transaction correlation, false comparison bit, and false `dispatchTaken`
latch. No caller value, global, wrapper, function-value alias, alternate Core
constructor call, unlocked write, overwritten field, dead statement, ignored
issuer error, or alternate-build declaration is accepted. The live Exec
handler extracts the typed arm, assigns the exact issuer result and propagates
its error immediately, then assigns the exact installer result. If installation
fails, the one exact panic-isolated `closeServiceExecAuthority` always closes
the transferred helper transaction and destroys the claimed plan before the
installer error is propagated; cleanup failure becomes the sanitized ownership
error. This first-seen entry is not a completion or replay
cache: it cannot set comparison true and does not claim the fixed 4,096-entry
completion/result ledger or comparison-replay path.

The private signatures are exact:

```go
func newServiceActiveProofID(requestCorrelation, CoreGenerations, [32]byte,
	int64, [32]byte, [32]byte) (credentialprotocol.SafeID, error)
func newServicePrepareAuthority(ReceivedPacket, ReceivedPrepareBegin,
	ServiceBootstrap, ServiceJobObservation) (servicePrepareAuthority, error)
func (s *Service) newServiceReceiveRequest() (ReceiveRequest, error)
func destroyServiceReceivedPacket(context.Context, ReceivedPacket) error
func (s *Service) reservePreparing(servicePrepareAuthority) error
func (s *Service) installPreparing(*credentialprotocol.HelperPrepareTransaction,
	CorePreparation) error
func closeServicePrepareTransaction(*credentialprotocol.HelperPrepareTransaction) error
func rollbackServicePreparation(context.Context, CorePreparation,
	CoreCleanupCapability) error
func (s *Service) abortPreparing(context.Context,
	*credentialprotocol.HelperPrepareTransaction, CorePreparation) error
func (s *Service) takePreparingFile(ReceivedPacket, ReceivedPrepareFile)
	(servicePreparing, error)
func (s *Service) finishPreparingFile(*credentialprotocol.HelperPrepareTransaction) error
func newServiceFileRequest(ReceivedPacket, ReceivedPrepareFile,
	servicePreparing) (CoreFileRequest, error)
func (s *Service) handlePrepareFile(context.Context, ReceivedPacket) error
func newServiceCommitRequest(ReceivedPacket, ReceivedPrepareCommit,
	servicePrepareAuthority) (CoreCommitRequest, error)
func (s *Service) revokeCommittedPreparation(context.Context, servicePreparing,
	ServiceJobObservation) error
func (s *Service) revokeServicePreparedActivation(context.Context,
	servicePreparedActivation) error
func validateServiceRenewArm(ReceivedPacket, ReceivedRenew,
	servicePreparedActivation) error
func (s *Service) newServiceRenewRequest(ReceivedPacket, ReceivedRenew,
	ServiceJobObservation) (CoreRenewRequest, serviceRenewAuthority, error)
func (s *Service) advancePreparedActivation(context.Context, ReceivedPacket,
	ServiceJobObservation) error
func newServiceExecCapabilities(requestCorrelation, CoreGenerations, [32]byte)
	(serviceExecCapabilities, error)
func newServiceExecBodyIdentity(ReceivedPacket, ReceivedExec,
	ExecPlanCapability) (uint32, [32]byte, error)
func closeServiceExecAuthority(serviceExecAuthority) error
func (s *Service) newServiceExecAuthority(ReceivedPacket, ReceivedExec)
	(serviceExecAuthority, error)
func (s *Service) installExecDispatch(serviceExecAuthority) error
```

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

The retained body wrapper threads the exact operation context through its
owner `Borrow`, the scoped view `Len`/`WriteTo`, and the destination
`MaxCredentialBytes`/`WriteCredential` calls. It checks cancellation before
and immediately after every such external callback. Once cancellation is
observed it performs no later external call, payload fill, or successful
return; it returns only `ErrContractOwnership`, never `ctx.Err()`. Plain and
typed-nil contexts are rejected before any callback. The receive and send body
destroy wrappers apply the same context precondition, but a non-nil canceled
context does not skip cleanup: they call `Destroy` exactly once with that exact
context and return `ErrContractOwnership`.

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

`NewReceivedExecPacket` first rejects a plain nil context with
`ErrContractInvalidArgument` or a typed-nil context with
`ErrContractTypedNil`. It next rejects a zero/nil-state, already destroyed, or
already claimed plan before ownership transfer and without calling any plan
capability method. A losing concurrent claim is the same pre-transfer plan
precondition failure: it returns `ErrContractOwnership` and leaves the
`ReceiveRequest`, body, and right unconsumed and caller-owned; it does not
destroy the winner-owned state. After those preconditions, it atomically claims
the `ExecPlanCapability` together with the body and right; the caller and every
alias must cease use. Under the one
plan-state mutex, that same private claim operation compares the complete
decoded plan's canonical length and SHA-256 with the claimed state. Every later
constructor error or panic destroys and full-capacity wipes the claimed plan
and body and closes the right; nil return transfers those same claimed
capabilities to the packet and Service.

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
scope, and then retains no decoded plan strings or body bytes. The complete
public `ReceivedExec` value-method set is exactly `Revision`, `ExecBindingID`,
`PrivateBindingLength`, `PrivateBindingSHA256`, `Plan`, `Format`, `GoString`,
`MarshalBinary`, `MarshalJSON`, `MarshalText`, and `String`; there is no other
public accessor. After the cache lookup, Service privately chooses seed `Begin`
or `BeginComparison`; it does not build a second exec transaction state
machine.

The private and stdin continuation packets use the same transaction without
copying their locked payload into the older heap-owning decoded body values.
`credentialprotocol` exposes these exact metadata-only observation values and
admission methods:

```go
type HelperExecPrivateObservation struct {
	owner *helperExecPrivateObservationOwner
}
type helperExecPrivateObservationOwner struct {
	mu            sync.Mutex
	revision      uint64
	privateLength uint32
	privateSHA256 [32]byte
	used          bool
}
type HelperExecStreamObservation struct {
	owner *helperExecStreamObservationOwner
}
type helperExecStreamObservationOwner struct {
	mu            sync.Mutex
	revision      uint64
	streamKind    HelperExecStreamKind
	flags         HelperExecStreamFlags
	offset        uint64
	payloadLength uint32
	payloadSHA256 [32]byte
	used          bool
}

func NewHelperExecPrivateObservation(
	revision uint64, privateLength uint32,
	privateSHA256, observedSHA256 [32]byte,
) (HelperExecPrivateObservation, error)
func NewHelperExecStreamObservation(
	revision uint64, streamKind HelperExecStreamKind,
	flags HelperExecStreamFlags, offset uint64, payloadLength uint32,
	payloadSHA256, observedSHA256 [32]byte,
) (HelperExecStreamObservation, error)
func (t *HelperExecTransaction) ProposeObservedPrivate(
	correlation HelperExecTransactionCorrelation,
	observation HelperExecPrivateObservation,
) (*HelperExecPayloadProposal, error)
func (t *HelperExecTransaction) ProposeObservedStdin(
	ctx context.Context,
	correlation HelperExecTransactionCorrelation,
	observation HelperExecStreamObservation,
	view credentialmemory.BorrowedView,
) (*HelperExecPayloadProposal, error)
```

Each observation is an opaque, copy-safe, one-use safe-metadata handle. Value
aliases share its mutex and `used` latch. It owns no payload, view, callback,
locked mapping, storage claim, or live authority; it only proves that the
canonical declared length and digest matched the independently observed digest
while the configured Transport still owned the validated packet body. It has
static redacted formatting and has no public field, metadata accessor,
fingerprint, or constructor bypass. The complete exported method set for each
value is `String`, `GoString`, `Format`, `MarshalJSON`, `MarshalText`, and
`MarshalBinary`; its pointer adds only `UnmarshalJSON`, `UnmarshalText`, and
`UnmarshalBinary`. Every marshal and unmarshal method rejects the operation.
The exact stable error catalog is:

```go
ErrHelperExecPrivateObservation = errors.New("credential protocol helper exec private observation is invalid")
ErrHelperExecPrivateObservationUsed = errors.New("credential protocol helper exec private observation is already used")
ErrHelperExecStreamObservation = errors.New("credential protocol helper exec stream observation is invalid")
ErrHelperExecStreamObservationUsed = errors.New("credential protocol helper exec stream observation is already used")
ErrHelperExecObservationSerialization = errors.New("credential protocol helper exec observation serialization is denied")
```

Those errors never contain payload, identifier, offset, digest, dynamic type,
or cause text.

The existing proposal owner gains the exact private source catalog and only
proposal-local candidate state. The exact catalog is
`helperExecProposalSourceLegacy helperExecProposalSource = 1` and
`helperExecProposalSourceObserved helperExecProposalSource = 2`. The exact
field order is below; the older `slot` remains solely for the compatible
decoded-body APIs:

```go
type helperExecProposalSource uint8

const (
	helperExecProposalSourceLegacy   helperExecProposalSource = 1
	helperExecProposalSourceObserved helperExecProposalSource = 2
)

type helperExecPayloadProposalOwner struct {
	transaction *helperExecTransactionOwner
	source      helperExecProposalSource
	kind        helperExecProposalKind
	flags       HelperExecStreamFlags
	offset      uint64
	length      uint32
	sha256      [32]byte
	slot        []byte
	candidateStdinHash      *helperExecSHA256
	candidateTranscriptHash *helperExecSHA256
	candidateStdinOffset    uint64
	candidateStdinBytes     uint64
	candidateStdinRecords   uint32
	candidateStdinEOF       bool
	observedReady           bool
	hashed                  bool
	copied                  bool
	committed               bool
	wiped                   bool
}
```

`NewHelperExecPrivateObservation` requires positive revision, length 1 through
`MaxHelperExecPrivateBytes`, a nonzero declared digest, and constant-time
equality between declared and independently observed digests.
`NewHelperExecStreamObservation` requires positive revision, stdin direction,
the exact data-or-EOF flag matrix, `offset <= math.MaxUint64 -
uint64(payloadLength)`, the 64-KiB payload
bound, and constant-time equality between declared and observed digests. Data
has positive length and nonzero digest. EOF has zero length and exactly
`SHA256(empty)`; the constructor does not replace or omit that final record.
Failed construction returns the complete zero value and retains nothing.
The values and constructors live in the exact pure production file
`credentialprotocol/helper_exec_transaction_observation.go`, so the existing
`helper_exec_transaction_*` import and live-behavior guard covers them.

Observation consumption has one exact precedence. For
`ProposeObservedStdin`, plain nil context returns `ErrHelperExecTransactionStream`.
The typed-nil context returns the same stream error. A nil or typed-nil view returns that error before either owner is touched
and before any context or view method. One shared private helper with
the exact signature `helperExecConfiguredDependencyNil(any) bool` detects
arbitrary typed-nil context and view implementations using only
`reflect.ValueOf`, `Kind`, and `IsNil` over the six nil-capable kinds: chan,
func, interface, map, pointer, and slice. The code checks plain nil before this
helper and does not call `ctx.Err`, `Done`, `Deadline`, or `Value` until all
pre-touch checks have succeeded; a typed-nil context therefore cannot panic.

After the applicable pre-touch checks, both observed methods lock the
observation owner, reject a zero or structurally malformed owner with the
operation-specific observation error, reject an already-used alias with the
operation-specific `Used` error, and otherwise set `used=true` exactly once.
Only that winner proceeds to the transaction. Thus observation structural
error precedes used error, and used error precedes transaction error; the
charge occurs before any transaction mutation. A charged observation is never
reset, even when transaction admission fails. Concurrent aliases have exactly
one charged winner; losers return the stable used error and never wipe,
commit, or otherwise change the winner's transaction or pending proposal.

Under the transaction mutex, the charged winner then applies the existing
transaction precedence: missing/terminal owner, completed owner, exact
correlation, transition/credit, observation binding, record-count exhaustion,
aggregate/offset bounds, external consumption, then post-consumption pending-
state revalidation. Request ID and identity digest correlation and every
SHA-256 comparison use `crypto/subtle.ConstantTimeCompare`; revision and all
other safe integer/catalog scalars compare exactly. Source guards bind these
comparisons to the exact `NewHelperExecPrivateObservation`,
`NewHelperExecStreamObservation`, `ProposeObservedPrivate`, and
`ProposeObservedStdin` declarations: the constructors and admission methods
must call the existing `helperExecDigestsEqual` and
`helperExecTransactionCorrelationEqual` helpers as applicable, and every such
call is an unshadowed direct call whose exact boolean result controls an
immediate nonnil-error rejection. A discarded result, dead or nested
noncontrolling branch, native equality replacement, local lookalike, or helper
call elsewhere cannot satisfy the guard. The exact helpers directly return
their closed expressions over `subtle.ConstantTimeCompare`: one digest compare,
or the two request-ID/identity-digest compares plus exact revision equality.
The guard binds every helper operand, not merely its call count. Private
construction compares the declared private digest with the observed digest;
stream construction compares the declared payload digest with the observed
digest; private admission compares the supplied correlation with the
transaction owner's correlation and the consumed observation digest with the
owner's private digest; stdin admission makes the same correlation comparison
and compares the consumed observation digest with the digest produced only by
the same method's exact borrowed view. Self, swapped, foreign, global,
shadowed, dead, discarded, or noncontrolling comparisons cannot satisfy it.
Each correlation and digest operand becomes independently protected at its own
successful gate, not at the later of the two gates. Any mutation or alias use
between those gates is therefore a rejection even if the later comparison and
proposal literal remain superficially canonical.
`ProposeObservedPrivate`
requires the supplied correlation to equal the owner's request ID, identity
digest, and revision; the observation revision, private length, and private
SHA-256 to equal `owner.correlation.revision`, `owner.privateLen`, and
`owner.privateSHA`; and the existing private transition to be admissible.
`ProposeObservedStdin` requires the same exact correlation; an outstanding
credit at the current offset; completed private input; no pending proposal or
EOF; observation revision equal to `owner.correlation.revision`; stream kind
exactly stdin; flags exactly data or EOF; offset equal to
`owner.stdinOffset`; and length, current aggregate, current record count, EOF,
and overflow state to satisfy the locked transaction limits. The data digest
is constant-time compared with the digest synchronously computed from the
view; EOF requires the unique zero length and `SHA256(empty)`. The exact
observation length, digest, flags, and offset—not caller replacements—feed the
candidate stdin and transcript hashes. A mismatch after charge returns the
existing private or stream/credit/record-count transaction error at its listed
precedence, terminally fails the transaction, and wipes pending/candidate hash
state. No observation field is trusted merely because its constructor once
validated it. Every observation scalar, revision, and digest is rebound to the
exact transaction owner and current state at admission.

After a complete canonical packet validation,
`NewReceivedExecPrivatePacket` and `NewReceivedExecStreamPacket` mint their
matching observation from the safe prefix and the retained payload body's
independently computed SHA-256. The observation is a final private field of the
corresponding received arm, after the existing safe fields, and has no public
accessor. It is never minted before header, body, credential, sequence,
identity, nonce, direction, length, and full canonical digest validation
succeed. Service privately takes it together with the sole retained body.
The complete exported accessor catalogs remain exactly `Revision`,
`PrivateBindingLength`, and `PrivateBindingSHA256` for `ReceivedExecPrivate`,
and `Revision`, `StreamKind`, `Flags`, `Offset`, `PayloadLength`, and
`PayloadSHA256` for `ReceivedExecStream`; neither catalog can reveal, copy,
replace, or remint the private observation.

The exact received continuation-arm additions are:

```go
type ReceivedExecPrivate struct {
	liveValue
	revision             uint64
	privateBindingLength uint32
	privateBindingSHA256 [32]byte
	observation credentialprotocol.HelperExecPrivateObservation
}
type ReceivedExecStream struct {
	liveValue
	revision      uint64
	streamKind    credentialprotocol.HelperExecStreamKind
	flags         credentialprotocol.HelperExecStreamFlags
	offset        uint64
	payloadLength uint32
	payloadSHA256 [32]byte
	observation credentialprotocol.HelperExecStreamObservation
}
```

`ProposeObservedPrivate` consumes exactly one observation and reserves the
existing transaction's sole `HelperExecPayloadProposal`; it never copies or
hashes private bytes because the exec seed already binds the canonical exec
body and declared private digest. Its proposal has source `observed`, kind
`private`, and `observedReady=true`, with nil slot/candidate hashes and
`copied=false`, `hashed=false`. In normal mode Service opens the sole retained
body once and, inside the same outer `ReceivedBodyCapability.Borrow` callback,
calls `ProposeObservedPrivate`, then `Core.BeginExec` with that same scoped
view, then commits only after a valid Core return. On proposal error, Core
error, cancellation, or invalid return it wipes any pending proposal before the
outer callback returns. A panic from an external call unwinds the callback
first; because a nested callback `defer` is forbidden, the immediate recovery
owned by the enclosing handler then wipes the captured proposal and invokes
the panic-isolated observed-body destroy helper. It does not claim the
impossible ordering of cleanup before the panicking callback unwinds. The
handler owns only the pending proposal and received body. It has named results,
installs its recovery before Borrow, captures the proposal only after the exact
error gate, contains one recovery Wipe, and calls exactly one checked
`destroyServiceObservedBody(ctx, body)`. Missing, duplicate, discarded,
disconnected, pre-gate, or callback-local body cleanup is invalid. The handler
returns its Borrow/cleanup error to its dispatcher; it never destroys the plan
or closes/cancels/revokes another retained owner.

On handler error the dispatcher immediately passes that outcome to the sole
`finishExecDispatch` terminal reducer. A successful private handler instead
calls the exact `continueExecDispatch`: it validates the actual transaction
snapshot, grants one stdin credit at its exact offset, constructs and sends the
authenticated credit packet, releases the dispatch latch, and enters the stdin
receive loop. The stdin dispatcher passes the authenticated arm's exact
`Offset()` and `Flags() == HelperExecStreamFlagEOF` into the one scoped
`CoreExecution.WriteStdin` call; literal zero/false substitution, a rebound arm,
or a caller-derived value is invalid. A successful non-EOF handler issues the
next credit and loops. `dispatchStdin` is the bounded continuation coordinator:
it permits at most one authenticated Receive worker, at most one stdin worker,
and at most one serial output worker. The Receive owner never calls
`WriteStdin` or `Next` inline. One stdin `WriteStdin` may therefore overlap one
stdout/stderr `Next`, while `Next` is never parallel with another `Next`. At
most one copy-safe credit from either output stream may wait behind that serial
output worker; the received metadata packet is destroyed before the credit is
queued. Offset and EOF validation occur after the active worker publishes its
ledger transition, so a causally next same-stream credit received after the
prior output becomes visible remains valid even when the local Transport
`Send` has not returned. A second queued credit is a transition failure. The exact
`serviceState` has a dedicated `sendMu sync.Mutex`. Each stdin-credit, output,
and response sender holds that mutex across send-sequence reservation, packet
construction, and configured Transport `Send`, without holding `state.mu`
across either external call. Output-header validation binds the live
revision/transaction/correlation/activation but does not depend on the
transient `dispatchTaken` latch; response headers additionally require the
terminal take. This preserves wire order even when stdin and output work
overlap. The serial output worker validates the same live correlation,
activation, and retained execution without consulting `dispatchTaken`: that
per-packet latch may already be held by the coordinator for the next
authenticated continuation while the previously authorized output worker is
starting.

The coordinator accepts authenticated stdout/stderr
`exec_credit` packets before or after stdin EOF, so a Core child blocked on
output never has to wait for all stdin. Every
private, stdin, and output-credit packet header must retain the installed Exec
request ID, identity digest, boot nonce, and revision; an otherwise valid arm
from a different request cannot advance this ledger. Observed stdin EOF does
not finish the execution or delay output already ready for credit. The
zero-private path starts Core when this is not a comparison, issues the first
credit, and enters that same loop. It cannot terminate successfully before
stdin EOF, both output EOF records, and the Core complete event. The terminal
reducer atomically takes and clears
the live exec ledger under the Service mutex, then outside the lock always
closes the helper transaction and destroys the claimed plan, cancels and
validates any retained Core execution, and revokes the prepared activation.
Only complete convergence with a nil incoming cause yields closed/normal;
every cause or cleanup failure yields stop-VM/protocol-error plus
`ErrContractOwnership`, without skipping later cleanup attempts. Before that
reducer runs, every terminal coordinator path cancels its worker context and
joins the bounded Receive, stdin, and output workers. A joined Receive result
still owns its returned packet and destroys it with a checked result; a
nil-error joined packet is an unexpected authenticated continuation and makes
an otherwise nil terminal cause fail. The coordinator reads output-ledger EOF
state only after `outputPending` is false, so the output result-channel edge
happens-before that read. Worker panic or cleanup failure promotes the cause to
`ErrContractOwnership`. A successful output result may arrive while the
overlapping stdin transaction proposal is still pending; that intermediate
`PendingPayload` state is not an output failure. Final completion remains
disabled until `stdinPending` is false, so response construction cannot race
the stdin worker's commit or deferred body cleanup. The same
reducer receives every continuation request/receive/arm/take/handler failure. Received
wrong-arm/take-failure packets are destroyed first. The initial Exec packet is
also destroyed on wrong arm or authority failure before installation, and an
install failure closes the uninstalled authority and destroys that packet.
The exact cleanup accepts a nil packet body/right as an already-clean
metadata-only receive; every configured nonnil body/right is still destroyed or
closed exactly once with panic/error reduction. This matches the landed
`NewReceivedExecPacket`, which validates and destroys its metadata body before
returning the arm. Core-output observation installs recovery before its first
panic-capable body method, including `Len`, so the caller can checked-destroy
the still-owned body. Response sending also recovers constructor/Transport
panic before coordinator join and terminal reduction. Zero-private always calls that cleanup through its
named-result recovery. In comparison mode
the proposal is committed inside that callback without calling Core. The
observation alone never proves launch or live use.
The configured Service sequencing and the Core return matrix own that assurance.
The outer `Borrow` is one direct reachable call; its returned error is bound
and propagated by the handler before terminal reduction, never discarded,
conditionally skipped, or replaced with nil. The exact proposal error is
checked and returned before comparison, Core, or Commit. Each static callback
contains exactly one matching Propose call, one normal Core call, two Commit
calls (the exclusive comparison and normal terminal paths), and one Wipe call;
the proposal authority and its error cannot be shadowed, reassigned, or
substituted, and no extra terminal call is permitted.

The Service reachability and state-stability proofs are one combined topology,
not independent marker checks. The combined canonical fixture constructs the
configured Service, claims its exact one-shot latch, and follows live returned
Service `CallExpr` edges through both matching-arm dispatchers to the private
and stdin handlers. Only an already validated exact returned handler or
dispatcher call on that Service receiver is permitted; its arguments and
returned result remain bound by the matching-arm rules above, and the target is
recursively inspected for state mutation and receiver escape. An unknown
returned Service call, returned method value, dead/nonreturned/discarded call,
receiver passed to another call, receiver stored in a composite, or any
unrecognized Service/state method invalidates the whole topology.
Trust propagates across a dispatcher edge only when that parent call directly
uses the same exact Service receiver and forwards every target parameter from
the corresponding caller parameter with identical imported type. Context or
arm/global substitution, receiver-alias reassignment or shadowing, and any
parenthesized, dereferenced, converted, asserted, interface, or other wrapped
Service receiver are rejected rather than inferred as trusted.

Scoped-interface escape analysis also covers ordinary calls in both
`credentialprotocol` and `credentialhelper`, not only fields, closures, and
direct assignments. A `BorrowedView`, `CredentialSink`, or derived alias may be
passed only to the exact synchronous consumers frozen by its owning contract:
the scoped view/sink methods, the exact body `Borrow` callback, the observed
stdin/Core calls, and the existing audited transport forwarding/validation
helpers. Passing it through an arbitrary function, method, interface,
variadic/generic call, function value, `defer`, or `go` is retention. Inter-
function dataflow propagates that scoped taint through helper parameters and
rejects helpers that store globally or return a closure, container, channel, or
interface holding it. An exact synchronous consumer is not a general-purpose
allowlist by method suffix; its receiver/argument shape and existing owner are
part of the guard.
Every consumer is bound to its exact declaration, receiver type, imported
interface type, argument positions, and context/body/transaction/Core owner.
Function-typed parameters and method-name suffixes never confer permission.
The guard resolves the actual `credentialmemory.BorrowedView` or
`credentialmemory.CredentialSink` receiver expression, import path, declared
method signature, and nonretaining result semantics; embedded, promoted,
generic, aliased-import, or user-defined lookalike methods cannot declassify a
scoped operand. `reflect.ValueOf` applied to a bound method is always an escape.
A raw scoped interface may enter `reflect.ValueOf` only transiently inside the
exact confined typed-nil helper already frozen below; its reflection value may
not leave that helper, and no other call site gains declassification authority.
That helper has one unique package declaration with the exact sink parameter
and `bool` result. Its complete body is the pure `sink == nil` fast path,
one local `reflected := reflect.ValueOf(sink)`, and one `Kind` switch whose
six nil-capable cases return `reflected.IsNil()` and whose default returns
false. The reflected result cannot be assigned outside that local, placed in a
container, passed to another helper, returned, or used by any other call or
side effect; an exact signature alone does not confer the exception.
Selecting a method from a scoped view or sink creates a bound method value
which carries that exact capability. Such a value may not be assigned to a
local or field, placed in a container or interface, returned, or passed to any
call. There is no bound-method exception: permitted scoped methods are invoked
only as direct, exact synchronous calls on their type-bound receiver.
A reflection call, custom or generic identity function, interface conversion,
container, or nested wrapper cannot declassify that bound method. Every wrapper
result remains scoped-tainted unless an exact audited nonretaining consumer is
invoked directly and returns no storable scoped value; in particular,
`reflect.ValueOf` is never a general exception to the confined typed-nil case.
The recursive expression proof covers ordinary and full slice expressions,
parentheses, index and generic-index lists, type assertions and conversions,
pointer/unary/binary expressions, keyed and unkeyed composites, and nested call
chains. No AST wrapper is a scoped-capability declassifier.
The only scoped callback invocation is the exact callback parameter of
`receivedPayloadBody.Borrow`; `withCanonicalScratch` and
`exactForwardingSink` exemptions are likewise bound to their exact existing
declarations and call-site topology.

Constant-time acceptance is bound through issuance, not merely through the
comparison branch. After the exact constructor comparison succeeds, its
revision, scalar metadata, declared digest, and observed digest cannot be
assigned, incremented, shadowed, mutated through a pointer or alias, captured
by a mutating closure, or replaced before the exact returned observation owner
is constructed from those checked values. After observed admission compares
the exact supplied correlation and observation digest against the transaction
owner/current-view digest, neither those inputs nor any owner/observation field
may be mutated or substituted before the exact observed proposal owner is
installed as that transaction owner's pending proposal and returned through
the exact `HelperExecPayloadProposal.owner`. The proposal's transaction,
source, kind, observation-derived length/digest/stream fields, candidate
owners/counters, and `observedReady` therefore come from the checked authority;
a self-check followed by a foreign or alternate composite cannot issue.
The observed proposal owner is constructed only after every relevant gate.
That exact owner is immutable thereafter; its single live, unconditional
pending assignment dominates the unique successful return, and no second
pending assignment may overwrite or clear it. That pending assignment is the
direct statement immediately before the unique successful return. The success
must be reachable in the method's live direct control flow: an earlier
unconditional return, panic, `runtime.Goexit`, constant-true terminal branch,
infinite loop, empty select, or equivalent terminal statement makes it invalid
even when the assignment and return remain textually present afterward. For stdin, each candidate hash
is derived from the matching current transaction hash and the same checked
borrowed view, and each candidate counter/EOF value is derived from the exact
current owner plus checked observation. Local names alone are not provenance.
Passing a protected value, selector, pointer, alias, composite, or captured
closure to an arbitrary helper is mutation authority and is rejected unless
the operation is an exact frozen pure consumer.
Alias discovery begins before each individual successful constant-time gate
and follows protected values recursively through pointers, dereferences,
struct fields, arrays, slices, maps, indexes, interfaces, composites, and
further aliases. A container created before the gate therefore remains
protected after it: mutating through `*holder.digest`, an indexed pointer, a
nested selector, or a helper receiving that container is equivalent to
mutating the checked operand itself.
A closure or bound callable that captures any protected root joins the same
pre-gate alias graph. Invoking or escaping it after that root's successful gate
is rejected through direct identifiers, wrappers, interfaces, or containers;
a zero-argument call cannot conceal the captured mutation authority.
Likewise, liveness analysis follows aliases and wrappers of `panic`,
`runtime.Goexit`, `Exit`, `Fatal`, and `FailNow`, plus terminal IIFEs and nested
terminal closures. A successful return textually after any such unconditional
call is dead, not an issuance path.
Callable-mutator discovery uses the same complete recursive expression graph,
including ordinary/full slices, index and generic-index lists, maps, structs,
interfaces, assertions, conversions, composites, and call wrappers. Terminal
reachability is package-wide: a fixed point follows private helper chains and
exact recursive no-return cycles as well as local aliases and containers.
The only pure callable exceptions are the exact package declarations and exact
operand-bound call sites for `cloneHelperExecSHA256` and
`newHelperExecObservedStdinSink` inside `ProposeObservedStdin`; a local,
parameter, function-value, dot-import, aliased-import, or wrapper lookalike
never receives that exception, and arguments are inspected before any call is
classified.
Compile-time boolean branches are evaluated for exact safe literal, unary,
logical, and comparable-basic-literal forms, so an unconditional constant
branch such as `1 == 1` cannot hide a terminal prefix.
Terminal identities are import- and receiver-type-qualified, include receiver
methods and functions returning terminal callables, and are accumulated as a
deterministic conservative union when alternate build-tag files declare the
same qualified helper. The fixed point follows wrappers, factories, IIFEs,
aliases, containers, exact receiver helpers, and recursive cycles; a method
suffix or lookalike `runtime`, `os`, or `testing` import is never terminal by
name alone.
It also computes, for every exact local function/method identity, which
function-valued parameter positions make the callee unconditionally
nonreturning. A call such as `invoke(runtime.Goexit)` is terminal only when the
matching live callee path invokes that exact parameter unconditionally. The
fixed point propagates these summaries through reordered parameters, generic
calls, interface assertions/conversions, and multiple wrapper hops. An unused
or conditionally invoked terminal argument does not falsely make the call
unconditional.
Function-value identity is preserved when a summarized wrapper is assigned or
reassigned, parenthesized, converted to an interface, placed in or recovered
from a slice, map, struct, generic/container composite, indexed or asserted,
returned by a helper factory, or selected as an exact receiver method value.
Local alias analysis carries the exact qualified wrapper identity rather than
only a terminal boolean, then applies that identity's parameter-position
summary at the eventual invocation. The analysis is flow-sensitive at that
invocation: it includes preceding declarations and assignments to identifiers,
selector fields, pointer/nested fields, and array, slice, or map indexes, carries
the identity through aliases of the containing storage, and resolves the exact
storage-location expression rather than only its base. Exact selector fields and
constant array, slice, or map indexes remain distinct; a dynamic index or
unresolved pointer alias conservatively unions every potentially matching
location. Constant index identity is semantic rather than source-spelling
identity: equivalent interpreted/raw strings, rune/integer forms, safe unary or
binary constant expressions, typed constants, and package/local declared
constants including `iota` resolve to one canonical representable value without
importing or executing code. Resolution is lexical and position-aware: a local
variable, parameter, or result that shadows a package constant makes that use
dynamic rather than inheriting the hidden constant. Numerically equal
representable keys such as untyped `1`, `1.0`, and a typed constant share one
identity. Exactly representable built-in constant conversions, including
modeled integer-to-string values, are evaluated without calling code, and forward package-constant references
reach an order-independent fixed point. Map keys are canonicalized only after
conversion to the exact statically resolved key type, including float precision
rounding and integer range/overflow rejection; an invalid or unresolved
conversion remains dynamic rather than inventing a value. Key-type resolution
follows local/package named map types, generic named instantiations, variable
aliases, exact receiver-method and local-function/closure sole result types,
interface assertions, and pointer-to-map normalization. Value and type-name
resolution follows the exact lexical position and Go scope. Function and
closure parameters/results, sequential block and case/communication-clause
declarations, `if`/`for`/`switch` initializers, range key/value declarations,
type-switch arm declarations, and select receive declarations hide an outer
package type only while that value binding is in scope. A type declaration in
a nested active scope can re-establish the type name there; an ended control or
clause scope and a sibling scope cannot hide it. Thus a short-declared value
that shadows a package type prevents use of the hidden type at that position.
Ambiguous or external
declaration identities remain dynamic. Any indexed storage whose key type is
unresolved or only suspected to be a map is wildcarded; the analyzer never
falls back to exact untyped-constant identity for it. Known arrays and slices
retain exact constant integer indexes. Arbitrary-magnitude
integer-to-string conversions that are not exactly modeled also remain dynamic
and conservatively union possible keys rather than creating a false distinct
identity. A containing-object
or containing-subpath alias translates each descendant selector/index path,
including pointer-normalized nested aliases, without installing the child's
identity on sibling paths. Dynamic-index ambiguity is matched independently at
every selector/index segment, so `outer[dynamic][0]` aliases `outer[1][0]`
without contaminating a statically distinct descendant or sibling. Recursive
containing aliases are represented by a finite symbolic path graph bounded by
the syntactically observable storage paths in the function. Cycles close in
that graph rather than expanding paths indefinitely, while every actually used
nested descendant remains reachable. Later assignments do not
retroactively define an earlier call; preceding ambiguous reassignments are
unioned conservatively. Named helpers and anonymous function literals may be
factories: direct or aliased closure factories, IIFEs, nested factories, and
cyclic alias/factory chains reach the same fixed point as direct calls. Multiple
or build-context-duplicate identities are also a conservative union: if any
possible identity is unconditionally terminal for the supplied position, the
successor is dead; an alias of a wrapper whose callable parameter is unused or
conditional remains a returning path.
No-return reachability covers every synchronously evaluated expression, not
only expression statements: assignment and declaration values, nested call
arguments, composite/index operands, return values, sends, and `if`, `for`,
`range`, `switch`, or type-switch initialization/condition operands. Evaluation
of a no-return wrapper makes its successor dead. Switch case expressions and
type-switch assignments are evaluated synchronously in order. Every expression-
switch case remains source-ordered even when `default` appears earlier, because
default selection occurs only after case-expression evaluation. Select entry
evaluates each receive channel and each send channel and value; a receive-
assignment destination is evaluated only after its clause is selected and is
not an unconditional entry expression. Conditional case or communication bodies
are not thereby treated as unconditional. Tagless-switch conditions use the
same lexical constant environment, so a named constant `false` cannot mask a
later unconditionally terminal case; unknown conditions remain conservative.
Function-literal bodies are not
evaluated when the literal is created; `defer` and `go` evaluate their callee and
arguments synchronously but do not synchronously execute the deferred or new
goroutine call.

`ProposeObservedStdin` consumes exactly one stream observation only after one
matching credit. It first validates transaction correlation, private
completion, stdin direction, current offset, flag, declared bounds, aggregate
limit, and record-count capacity while holding the transaction mutex. It
records the current generation/eligibility without installing a proposal,
clones the current stdin and
transcript hash states, and computes the candidate next offset, byte count, and
record count, then releases the mutex before calling any method on the supplied
view. Those candidate hashes and counters are private local state reserved only
for the eventual returned proposal; the transaction's current hashes and counters remain byte-for-byte
unchanged until that exact proposal's `Commit`. It rejects nil context and nil or typed-nil view before
consuming either owner. It checks cancellation before and after the scoped
copy, requires the view length to equal `payloadLength`, and calls `WriteTo`
exactly once with a private sink which accepts exactly one write. Duplicate,
concurrent, missing, or error-suppressing writes completed before `WriteTo`
returns latch a failure. The sink constant-time checks the observed digest and
updates only the proposal-local candidate hash states; it retains no slice or
view.

The two pure private construction seams are exact:

```go
func cloneHelperExecSHA256(*helperExecSHA256) *helperExecSHA256
func newHelperExecObservedStdinSink(
	stdin, transcript *helperExecSHA256,
) *helperExecObservedStdinSink
```

Each clone receives exactly `owner.stdinHash` or `owner.transcriptHash` and no
other input. The sink constructor receives those two exact candidates, and
the same supplied borrowed view writes to that sink exactly once. Candidate
offset is exactly `owner.stdinOffset + uint64(observation.owner.payloadLength)`,
candidate bytes uses the analogous `owner.stdinBytes` expression, candidate
records is exactly `owner.stdinRecords + 1`, and candidate EOF is exactly the
comparison of `observation.owner.flags` with `HelperExecStreamFlagEOF`.
Both helpers have exactly one package declaration across all parsed build-tag
variants. The clone has the exact pointer signature, returns nil for nil, copies
the complete `helperExecSHA256` value by value, and returns the address of that
fresh copy; it cannot return/retain/alias its input or perform any other call or
side effect. The sink constructor has the exact two-pointer signature and a
single return of a fresh `helperExecObservedStdinSink` whose only initialized
fields are `stdin: stdin` and `transcript: transcript`; it cannot retain another
owner, retain scoped memory, touch global state, call a helper, or add a second
implementation. Only after these unique bodies pass structural validation may
their exact operand-bound call sites receive the pure-call exception.

Only the calls to external `BorrowedView.Len` and `WriteTo` are enclosed by one
narrow recovery boundary. After observation consumption, context cancellation,
a length or write error, sink error, suppressed/duplicate/no write, or panic
from those calls returns only `ErrHelperExecTransactionStream`; raw error and
panic values never propagate or enter formatting. The transaction becomes
terminal and the pending proposal plus both candidate hash owners are fully
wiped. Internal invariant panics outside that narrow boundary are programming
errors and are not promised to be recovered.

After the external call returns, the method reacquires the transaction mutex.
It constructs, installs, and returns the candidate-bearing proposal only after
the digest gate succeeds and only if the exact correlation, credit, offset,
nonterminal generation, and absence of any pending proposal still match; it
still
does not install a candidate into current transaction state. Close, alias use,
a second proposal, cancellation, panic, digest mismatch, wrong length, or a
suppressed/duplicate write wipes the candidate states and pending proposal and
makes the transaction terminal. No transaction mutex is held across
`BorrowedView.Len` or `WriteTo`, so a conforming reentrant view cannot deadlock.
Service establishes one outer body-borrow callback around this operation. In
normal mode, `ProposeObservedStdin` and `Core.WriteStdin` occur sequentially
inside the same outer `ReceivedBodyCapability.Borrow` callback: Service first
passes the callback's scoped view to `ProposeObservedStdin`, then passes that
same still-scoped view to `Core.WriteStdin`, and commits only after Core returns
nil. It wipes on either error before the outer callback returns. Comparison
mode proposes and commits inside the same callback, calls no Core method, and
returns only after the body scope closes. The observed stdin proposal has
source `observed`, kind `stdin`, `observedReady=true`, nil slot, both nonnil
candidate hash pointers, and exact candidate offset/byte/record/EOF values
derived from the unchanged current state.

`HelperExecPayloadProposal.Commit` is the sole atomic installation point and
does not itself claim that Core ran. Its legacy-source predicates remain
byte-compatible: normal requires `copied`, comparison requires `hashed`.
Observed private requires source observed plus `observedReady`, and requires no
slot, copy, hash, or candidate owners. Observed stdin requires source observed,
`observedReady`, both nonnil candidate hashes, and exact next offset, byte,
record, and EOF candidates. Under the transaction mutex, Commit revalidates the
pending owner and state, fully wipes the superseded current stdin and transcript
`helperExecSHA256` owners, transfers the proposal candidate pointers into the
current owner, and nils the proposal pointers without wiping the transferred
candidates. Only then does it install candidate counters and finalize an EOF.
Retained private pointers to the superseded owners observe complete zeroization.
Commit advances exactly once. `Wipe`, Core
failure, or any other error wipes the candidates and leaves a terminal,
non-reusable transaction without installing or advancing them. The unique EOF hashes
`flags || offset || zero length || SHA256(empty)`, appends the existing
big-endian record-count trailer, and finalizes the existing stdin, transcript,
and exec digests. No second FSM, transcript implementation, payload slot, or
private-body owner exists.

`BorrowedView` and the private `CredentialSink` are strictly synchronous scoped
capabilities: neither side may retain the other, and all `WriteCredential`
calls must join before `WriteTo` returns. Concurrent duplicate calls that join
before return are synchronized and rejected. A use after return violates the
configured D4 Transport TCB and is not claimed to be retroactively detectable
by an already-returned proposal. Source guards forbid retaining either
interface in any transaction/observation struct field, following pointer,
array, map, channel, index/generic, named, alias, nested struct, and interface
types. The recursive guard resolves every `TypeSpec.TypeParams` constraint, so
`holder[T BorrowedView]` and `holder[T CredentialSink]` are forbidden even
when the constrained parameter reaches a field through a generic alias. A
retained function-valued field is also forbidden when any parameter or result
reaches a `BorrowedView` or `CredentialSink`, including through an alias,
container, or generic constraint. Top-level function and method parameters
remain permitted because they are the required synchronous scoped API and are
not retained-field roots. Tests use adversarial but scope-conforming callbacks
for the synchronized duplicate matrix plus seeded recursive no-retention guard
cases.
Package-level `ValueSpec` variables are retention roots too. The guard follows
their explicit or inferred type, cross-file aliases, arrays, maps, channels,
generic/named containers, function values and results, and closure captures;
neither a global `any` annotation nor an initializer indirection can hide a
scoped capability. This includes later assignment to a package function
variable, a locally returned closure, and assignment through an interface or
container sink. While either scoped type is lexically live, a function literal
is forbidden except for the one direct synchronous `ReceivedBodyCapability.Borrow`
callback; that callback cannot contain a nested literal, `go`, `defer`, IIFE,
or retained method value. Direct and aliased/shadowed captures are equivalent.
The no-retention proof credits only an exact `ReceivedBodyCapability` or
`CoreOutputBody` identifier declared directly in the enclosing top-level
function parameter list. It must remain unrebound and may make one immediate
inline synchronous `Borrow` call, either directly or as a direct `defer` whose
arguments and callback are evaluated in that function; the call is not inside
a `for` or `range` loop and no second `Borrow` call is present. The callback has
one named, nonblank, exact import-bound `credentialmemory.BorrowedView`
parameter. The context and callback identifiers are the exact parameter
objects, not same-spelled local shadows; that lexical-object requirement also
applies to every downstream scoped-view use inside the callback, so a local
context or view shadow cannot authorize a write or staging call. Lexical alias
propagation is range-role-sensitive: a value has the element/value type while a
slice index or unrelated map key does not become scoped merely because the
container also carries a view. Named and aliased slice/map/channel types resolve
to those same underlying roles. Any callback `go`, `defer`, or send of the view
is rejected. A bound `Borrow` method
value remains invalid. Every other apparent owner is deliberately unresolved:
assignment or comma-ok result, function result, composite, field or promoted
field, index, range or channel value, slice, pointer, address/dereference,
parenthesized or other wrapper, branch/loop join, or nested-function parameter.
Neither a direct `Borrow` call nor a bound method from any such form receives
credit. This conservative grammar avoids a general control-flow/location proof
and does not broaden the exact Prepare-file topology below.
The already-landed transport wrapper calls in exact
`receivedPayloadBody.Borrow`, `SendPacket.WriteCanonicalBody`, and
`validSendExecStreamArm` remain governed by their separate frozen transport
topology. Each has exactly one synchronous `Borrow`; its receiver/arm/stream
owner is unrebound, its owner field is not written or addressed, and the send
stream comes only from the exact unrebound `packet.sealedArm()` result. That
sealed pointer remains confined to its direct read-only field selectors and
nil gate: the only selector uses are the exact body-length comparison, the
one `written.CompareAndSwap(false, true)` gate, the exact stream assertion,
the exact configured/canonical-length/scratch arm calls, and the exact body
digest comparison through the declaration-bound `crypto/sha256` import. Each
listed occurrence is unique and outside `go`, `defer`, and loop ancestors
except for the digest read in the exact synchronous scratch callback. No
selector method, assignment, standalone stored value, or other consumer
substitutes. The pointer is never aliased,
passed, returned, stored, sent, or addressed, and no selected field is
addressed or written outside that one named atomic gate. These
calls are not a general field-owner allowance. The frozen proof compares the
complete formatted `WriteCanonicalBody` body and the complete formatted bodies
of every scoped-value helper it trusts: `configuredDependency`, `typedNil`,
`destroyTransportBody`, `isNilCoreDependency`, and `withCanonicalScratch`.
Every referenced import is resolved from the helper's own declaration file,
not the caller's spelling. The credential-protocol wrapper form of
`configuredDependency` is accepted only with the exact standard-library
`reflect`-bound `helperExecConfiguredDependencyNil` leaf. The scratch helper is
accepted only with the unique exact `wipeBytes` leaf, whose complete body calls
the predeclared `clear` over the supplied full-capacity slice before the exact
standard-library `runtime.KeepAlive`. Signature-only helpers, lookalike imports,
retaining classifier/wipe leaves, or reordered substitutes do not receive
credit.
The Prepare-file handler may first bind the exact single-assignment local
`body := packet.body`, where `packet` is the exact `ReceivedPacket` parameter,
and invoke that local's `Len`, `SHA256`, and one inline synchronous `Borrow`
callback. That local may otherwise appear only in the exact
`configuredDependency(body)` precondition: reassignment, another packet or
field owner, address-taking, return, send, helper/container storage, method
value, alias chain, or escaped callback invalidates the scoped Borrow proof.
Inside that callback the only additional scoped-view consumer for this path is
`preparing.preparation.StageFile(ctx, fileRequest, view)`; a foreign
preparation, request, context, helper, or method value is not equivalent.
Three exact execution functions receive a closed composition allowance from
this generic scoped-flow scan: the complete exact canonical
`private` handler may install only its validated `Core.BeginExec` result under
`state.mu`, and the complete exact canonical `stdin` handler may copy the
retained execution under that mutex and invoke its one synchronous
`WriteStdin` with the callback view. The exact free
`observeServiceCoreOutput` function may synchronously Borrow one
`CoreOutputBody` only to call the callback view's `WriteTo` into the
payload-digest sink. Each allowance is granted only when the entire function
signature and body are AST-identical to the independently guarded canonical
function. It is not statement-, name-, or receiver-based; any
added, removed, reordered, rebound, shadowed, asynchronous, or otherwise
modified statement loses the allowance and is evaluated by the ordinary
fail-closed scoped grammar.
Guard-required behavioral evidence is counted only from one
unique top-level exact `func TestX(t *testing.T)` AST declaration with the real
`testing` import; comments, strings, function literals, lookalike imports,
wrong signatures, and duplicate declarations do not count.

The older heap-owning `ProposePrivate` and `ProposeStdin` APIs remain byte- and
source-compatible for their existing pure codec users, but the configured
Service is forbidden from decoding or constructing a
`HelperExecPrivateBody` or `HelperExecStreamBody`. Its only continuation path
is the received observation plus the retained locked body. The transaction
implementation remains pure in-memory code: its exact additional imports are
`context`, `internal/credentialmemory`, and `reflect`; `reflect` is allowed only
in `helper_exec_transaction_observation.go` and only inside the private
`helperExecConfiguredDependencyNil(any) bool` helper above. `reflect.TypeOf`,
type-name/dynamic formatting, or reflection anywhere else is forbidden.
Network, filesystem, process,
syscall, clock, goroutine, channel, map, generic, and live-I/O dependencies
remain forbidden.

After a successful exec constructor, Service owns the exact claimed plan and
destroys it exactly once on every dispatch path. In normal execution it does so
immediately after `Core.BeginExec` returns or panics. In comparison it destroys
the plan after `BeginComparison` and cached-result validation and before any
response. Policy/cache/observation/cancellation/pre-Core denial, error, or panic
also destroys it before returning, responding, or draining the packet. No path
relies on Core having been called to discharge plan ownership. Claim, read,
copy, and destroy serialize on the one state mutex; source guards require the
latch, the exhaustive Service cleanup tests, and no second plan owner or
replacement capability.

The configured Service wiring is source-guarded, not left as prose. Service
privately takes each exec-private or exec-stream arm together with its sole
retained `ReceivedBodyCapability`; no public take method or second body owner is
added. The handler parameter is the credentialhelper package's exact
unqualified `ReceivedBodyCapability`, its callback parameter is the exact
import-bound `credentialmemory.BorrowedView`, and the exact handler context is
the first argument to `Borrow`, `ProposeObservedStdin`, `Core.BeginExec`, and
`CoreExecution.WriteStdin` as applicable; a suffix lookalike or background
context does not satisfy the guard. Its private handler carries the existing
transaction only as the exact
`*credentialprotocol.HelperExecTransaction` value; a lookalike transaction
type cannot provide the admission call. Its exact correlation and private or
stream observation parameters are the identifiers passed to Propose; zero,
foreign, package-global, or shadowed substitutes are invalid. The handler

The extraction topology is exact. A live Service dispatch method obtains
`packet, receiveErr := s.transport.Receive(ctx, request)`, immediately
propagates `receiveErr`, extracts exactly `arm, ok := packet.ExecPrivate()` or
`packet.ExecStream()` with an immediate nonnil rejection of `!ok`, then obtains
`dispatch, dispatchErr := s.takeExecDispatch(arm.Revision())` and immediately
propagates `dispatchErr`. The private value is exactly

```go
type serviceExecDispatch struct {
	transaction *credentialprotocol.HelperExecTransaction
	correlation credentialprotocol.HelperExecTransactionCorrelation
	comparison bool
}
```

and `takeExecDispatch(uint64) (serviceExecDispatch, error)` is the only
configured Service state transition that returns it. The live branch directly
returns its matching handler with exactly `ctx`, `packet.body`,
`dispatch.transaction`, `dispatch.correlation`, `arm.observation`, and
`dispatch.comparison`, in that order. The packet, arm, dispatch tuple, and
context cannot be rebound. Cross-arm, global, zero, shadowed, foreign, or
background substitutions are invalid. Every reachable private Service handler
edge from `Serve` is an actual returned `CallExpr` in a live branch. The one
state-transition edge above may instead bind its result and exact error, with
the immediately following gate propagating that error. A method value,
discarded or merely assigned result, call after return, or statically false
branch is not an edge and cannot make a handler reachable.

The synchronized state owner remains implementable by this topology. The
request, claimed plan, exec transaction, transaction correlation, comparison
bit, revision, and retained `CoreExecution` are copied or taken only while the
exact Service `state.mu` is held. `takeExecDispatch` compares its exact revision
argument with the matching exec-ledger entry, rejects an already-taken entry,
copies that entry's transaction/correlation/comparison values, and marks that
same entry taken in one lexical and control-flow-complete critical section. Its
exact `revision != state.revision || state.dispatchTaken` gate immediately
unlocks and returns an error; the success path performs the one latch write and
one unlock before returning the copied tuple. Every lock-acquired path unlocks
exactly once before leaving the critical section. A nested or aliased return,
panic, no-return call, conditional terminal, or other control transfer before
that unlock is invalid, including after `dispatchTaken=true`. A rejection
condition inside the critical section is pure—no helper call, callback,
receive, initializer, or else path may panic, block, or bypass its exact
unlock-and-return body. Critical-section assignments are limited to exact
state-field value copies/latch writes with safe local or state-field targets;
indexing, calls, conversions, indirect targets, and other panic-capable
expressions are invalid. Conditional early
unlocks, missing success-path unlocks, empty or noncontrolling gates, and
`&& false` lookalikes are invalid. The handler may similarly copy the
matching request/plan or retained execution value for the one immediate Core
call; those value copies do not transfer or duplicate the state owner. State
pointers, field addresses, and live owners never escape. Unlocked reads or
writes, arbitrary helper calls over state values, globals, cross-entry values,
wrong revisions, and duplicate take/retry paths are invalid. The guard permits
only these exact mutex-bound value-copy/take operations; it does not grant a
general state-field or helper exemption.

The execution installed into Service state is the exact result of the sole
`Service.core.BeginExec` call after the canonical Core-result rejection gate.
It is assigned exactly once under `state.mu`; before that gate the result and
every alias may appear only as the exact `configuredDependency(execution)`
operand. Assignment to a global or another owner, return, address-taking,
receiver use, helper argument, composite/container storage, or method call is
invalid. No inspection, switch/tag use, comparison, formatting, or other read
is permitted before the gate. A foreign value, pre-gate install, rebind, second write, or overwrite
cannot derive launch authority.

An Exec arm whose exact private binding length and digest are the canonical
zero/zero pair is the exact typed `ReceivedExec` arm carried by that dispatch,
obtained by the exact `arm, ok := packet.Exec()` extraction and its immediate
not-ok rejection, not a same-shaped or foreign owner. It takes no `ExecPrivate` arm and opens no
body. Its comparison branch is one direct terminal accepted result with no
Core, Borrow, body, proposal, or observed-input authority. This prohibition
includes helpers, method values, aliases, callbacks, interfaces, containers,
and other indirect calls; a syntactic absence of `BeginExec` alone is not
sufficient. Its normal branch
calls the same `Service.core.BeginExec` with the matching state-backed request
and a literal untyped `nil` third argument, applies the same exact
`coreErr != nil || !configuredDependency(execution)` rejection, and only then
installs the returned execution under `state.mu`. A typed nil, zero-length
lookalike view, global nil-like value, observed proposal, or Borrow call cannot
satisfy this path. Comparison still calls no Core. This topology is part of the
existing `TestServiceObservedInputsTakenOnceBeforeDispatch` and Service AST
contract rather than a new independent readiness marker.

The handler receiver, context, body, transaction, correlation, observation,
and comparison parameters and the callback view/proposal/proposal-error/
Core-result variables cannot be reassigned or shadowed to substitute a
lookalike owner. The sole outer Borrow is a direct reachable call, and its
bound error is returned by the handler; it cannot be discarded, swallowed, or
guarded by a false branch. The proposal error is returned before comparison,
Core, or Commit. Proposal, comparison, Core, canonical rejection, retained
execution, and final Commit are direct lexical statements of that callback
rather than markers nested under a noncontrolling branch. The normal private
path has one outer body `Borrow` callback on an exact
`ReceivedBodyCapability` containing, in order, `ProposeObservedPrivate`,
`Core.BeginExec` with that callback's scoped view, the canonical rejection
condition `coreErr != nil || !configuredDependency(execution)`, and direct
returned proposal `Commit`. On rejection the exact same proposal's no-result
`Wipe` call is immediately before the nonnil return. The valid execution is
retained only as `serviceState.execution`. The normal stdin path has one outer
body `Borrow` callback containing, in order, `ProposeObservedStdin`, the
retained execution's `WriteStdin` with the same view and the exact authenticated
`ReceivedExecStream.Offset()`/EOF flag, the exact
`coreErr != nil` rejection, and direct returned proposal `Commit`. Its same
proposal is wiped immediately before every nonnil failure return. Each callback
has exactly one matching Propose call, one normal Core call, two mutually
exclusive Commit sites, and one Wipe call. Nested function literals, IIFEs,
`defer`, `go`, method-value terminals, duplicate calls, and rebound proposal
values are invalid.

The private and stdin handlers own only pending-proposal wipe and their one
received observed body. A single outer recovery unwinds the Borrow callback,
wipes a pending proposal, and calls the exact panic-isolated
`destroyServiceObservedBody(ctx, body)` helper. That helper recovers a body
`Destroy` panic and reduces either panic or nonnil Destroy error to
`ErrContractOwnership`. The handlers do not close the helper transaction,
destroy the claimed plan, cancel the retained Core execution, revoke the
prepared activation, or construct a final Service result. They return the
Borrow/cleanup outcome to their dispatcher. A nonnil outcome immediately
returns `finishExecDispatch(ctx, handlerErr)`; a nil private outcome issues the
first stdin credit and enters `dispatchStdin`. That function is the bounded
continuation coordinator. It keeps no more than one authenticated Transport
Receive outstanding, no more than one stdin worker, and no more than one serial
output worker. The Receive owner routes either an authenticated stdin
`exec_stream` or normal-mode stdout/stderr `exec_credit` without invoking the
potentially blocking `WriteStdin` or `Next` inline. One stdin worker and one
output worker may overlap, but two `Next` calls never do; one copy-safe credit
for the other stream may be queued only after its metadata packet is destroyed.
It validates the packet header's request ID, identity digest, and boot nonce
against the installed correlation and activation after the exact revision take.
A single coordinator instance has this exact owner inventory; no channel or
pending/queued latch may be added, removed, widened, or copied to another
owner:

```go
type serviceExecReceiveResult struct {
    packet ReceivedPacket
    err    error
}

type serviceExecWorkResult struct {
    dispatch serviceExecDispatch
    err      error
}

type serviceExecCoordinator struct {
    cancel           context.CancelFunc
    receiveResults   chan serviceExecReceiveResult
    stdinResults     chan serviceExecWorkResult
    outputResults    chan serviceExecWorkResult
    receivePending   bool
    stdinPending     bool
    outputPending    bool
    creditQueued     bool
    queuedCredit     ReceivedExecCredit
    queuedDispatch   serviceExecDispatch
}
```

Only `startServiceExecReceive`, `receiveServiceExecContinuation`,
`runServiceExecStdin`, `runServiceExecOutput`,
`stopServiceExecCoordinator`, and `finishServiceExecCoordinator` may operate
these channels and latches. Every channel has capacity one. The worker result
send is deferred behind its panic recovery, so each started worker produces
exactly one join result.
A nil non-EOF stdin outcome issues the next stdin credit and repeats. A nil EOF
outcome stops issuing stdin credit but continues to accept output credit until
both output EOFs are observed. Comparison mode accepts no output credit and,
only after stdin EOF, calls `ReplayResult`, sends that completed response, and
enters the terminal reducer without any Core call.

Normal mode initializes one immutable `serviceExecOutputLedger` from the
retained execution/request/claimed plan under the Service mutex and the plan's
exact stdout/stderr maxima. Output credits may interleave with stdin before or
after stdin EOF. Each credit has the installed correlation header and revision,
stdout-or-stderr kind, and exact next offset. Service destroys the received
metadata packet, mints one `CoreOutputRequest` from the installed
correlation/job/execution and bounded remaining capacity, calls `GrantOutput`,
then the serial output worker calls `Next` once in `drainExecOutput`.
The returned output event must echo execution, kind, offset and capacity; its
owned full canonical body is synchronously borrowed to hash only its payload,
then transferred to one authenticated `exec_stream` packet. Construction/send
failure or any untransferred body is panic-safely destroyed. A leading exact
`transportContextPrecondition(ctx)` leaves the local owner latched on its
failure. After it passes, the latch is cleared immediately before the
packet-constructor call because that constructor's post-precondition contract
consumes or destroys the body on every return or panic; clearing it afterward
could double-destroy a panicking call. Exact per-stream
offsets advance until one stdout EOF and one stderr EOF; an EOF is empty, uses
the empty digest, and `truncated` is accepted only at the corresponding plan
maximum. No stream may produce after its EOF.

Only after stdin EOF and both output EOF records,
`completeServiceExecOutput` makes one final serial `Next`, which must return the
Core complete event and no body. That event is Core's child-exit/reap boundary. Its
execution capability, stdin count/digest/transcript, stdout/stderr
count/digest/truncation, and exec-transaction digest must equal the installed
request, final transaction snapshot, and independently accumulated output
ledger. Service then clears the retained execution under the mutex so terminal
cleanup cannot cancel a completed execution, completes the helper transaction
with the exact accepted response, sends that response, and only then returns to
`finishExecDispatch`. Any panic, receive/header/credit/grant/event/body/send failure,
wrong offset/result/digest, early complete, missing/duplicate EOF, response
failure, or state drift remains noncomplete and enters terminal cancellation,
transaction/plan cleanup, and prepared revocation. Every returned Core output
body is either transferred once or destroyed with a checked result; a Destroy
panic/error is promoted to `ErrContractOwnership`, never discarded behind the
primary event error. The loop is bounded by stdin and plan maxima plus their
unique EOF events; it never accepts an uncredited output or a second complete
event, and it never waits for stdin EOF before servicing output. Every terminal
path first cancels and joins all pending workers, destroys a packet returned by
a joined Receive, clears the single queued copy-safe credit, and only then
enters `finishExecDispatch`; no worker or owner survives the Serve lifetime.

The output ledger's private digest writer is exactly
`serviceExecOutputDigestSink { hasher hash.Hash; expected int; written bool }`;
its field types are part of the frozen callback proof, not a replaceable
lookalike interface. Package-wide references also confine
`NewCoreOutputRequest`, `newExecCreditPacket`, `newExecStreamPacket`, and
`newResponsePacket` to their single exact drain/continuation/send owners.
Disconnected constructor calls cannot satisfy or extend this flow.

`finishExecDispatch` is the sole terminal exec owner reducer. Under the exact
Service mutex it verifies a live exec entry, copies the retained execution,
request, plan, transaction, and prepared activation, and atomically clears the
execution/request/plan/revision/comparison entry while latching dispatch taken.
No external call occurs while locked. It then exhaustively calls the exact
panic-isolated cleanup consumers in order: `closeServiceExecAuthority` closes
the helper transaction and destroys the plan, `cancelServiceExecution`
cancels a nonnil retained Core execution and verifies the exact cleanup echo
and complete/absent result, and `revokeServicePreparedActivation` consumes the
retained prepared activation. Every cleanup attempt is made even when the
incoming cause or an earlier cleanup is nonnil. Only a nil cause plus three
successful cleanup results returns `ServiceClosed`/`normal`; every other path
returns `ServiceStopVMRequired`/`protocol_error` and
`ErrContractOwnership`. The terminal transaction pointer may remain only as a
non-live tombstone for the immutable post-Serve snapshot test; it cannot be
dispatched, committed, or closed again.

`continueExecDispatch` is the sole nonterminal handoff. It accepts only the
same live transaction/correlation/revision with private complete, no pending
proposal, no prior credit, no EOF, and matching comparison mode. It calls that
transaction's unique `GrantStdinCredit`, revalidates the ledger under the
Service mutex, reserves the send sequence, clears the take latch, builds the
exact credit packet through the unique `newExecCreditPacket`, and synchronously
calls configured Transport `Send`. Panic, construction/send failure, or state
drift is terminal-reduced.

Continuation receive-request issuance, Receive failure, arm mismatch,
dispatch-take failure, handler error, handler panic reduction, and successful
handler completion all converge on that reducer. A received wrong-arm or
failed-take packet is first destroyed through the exact received-packet
cleanup, then reduced. The initial Exec wrong-arm and authority-error paths
destroy that packet before returning; install failure closes the not-installed
authority and destroys the packet. A metadata-only packet whose constructor has
already destroyed its received body carries nil body/right fields; the cleanup
helper treats those fields as already clean, while every configured nonnil
field still requires its exact panic-isolated Destroy/Close. Cleanup after
ledger install is also checked before dispatch and converges on the same reducer
on failure.
The zero-private branch uses a named-result recovery that always destroys its
received Exec packet and converts panic or cleanup failure to the deterministic
stop-VM result. Its invalid arm/binding, Core error, and canonical Core
rejection return through `finishExecDispatch`. Valid comparison or Core
success instead issues the first credit and enters stdin dispatch; it never
directly destroys the plan. Comparison uses the exact `comparison bool` parameter
and calls no Core. Successful normal completion requires observed stdin EOF,
the exact output drain, both output EOF records, a correlated Core complete
event, helper transaction completion, and successful response send.

Tests cover private/stdin nil, error, typed-nil, panic and comparison matrices,
received-body destruction, continuation failure, zero-private convergence,
and exactly-once terminal plan/transaction/execution/prepared cleanup. The AST
guard binds both propose/Core/commit orders to one actual Borrow callback,
binds the scoped view to the Core call, and binds every live dispatch and zero
exit to the terminal reducer; disconnected cleanup or marker calls do not
satisfy the topology.

The thirteen required Service tests are executable behavioral contracts in the
exact `credentialhelper` package, not name markers in another guest-agent
package. Each is one unique top-level `func TestX(t *testing.T)`, directly
and unconditionally constructs the real Service with `NewService`, calls
`Serve` on that never-rebound returned owner (not through `go` or `defer`), and
has a later live `Fatal`, `Fatalf`, `Error`,
or `Errorf` assertion over the exact promised fake-field selector, not a local
constant or same-named marker. Empty/no-op tests,
`Skip`/`SkipNow`/`FailNow`/`runtime.Goexit`, a return before exercise,
comment/string/dead-branch markers, a shadow constructor, a rebound owner, a foreign Serve
receiver, an assertion before exercise, or calls without observable assertions
are invalid. The exact per-test observable catalog is: claimed-plan cleanup
across success, invalid Core, panic, stdin failure, and multi-record output
through actual plan state plus `planDestroyCalls`; causal same-stream output
after peer-visible send; Receive error/panic convergence across preparing,
prepared, and installed Exec; constructor/one-shot `dependencyCalls`, `ownedSnapshotEntries`,
`serveCalls`; context precedence `dependencyCalls`, `serveCalls`; dispatch take
`takeCalls`; private matrix `beginExecCalls`, `commitCalls`,
`bodyDestroyCalls`, `planDestroyCalls`; private-return gate
`beginExecCalls`, `commitCalls`, `wipeCalls`; stdin matrix
`writeStdinCalls`, `commitCalls`, `bodyDestroyCalls`; stdin-return gate
`writeStdinCalls`, `commitCalls`, `wipeCalls`; comparison no-Core
`beginExecCalls`, `writeStdinCalls`, `commitCalls`; body lifetime
`bodyDestroyCalls`; and failure/panic cleanup `wipeCalls`,
`bodyDestroyCalls`, `planDestroyCalls`.

The credited mismatch body contains exactly one direct call to the original
unshadowed test owner's `Fatal`, `Fatalf`, `Error`, or `Errorf`. A return,
skip, Goexit, panic, helper, deferred/goroutine call, or any other statement
before that failure is not evidence; a terminal helper used while evaluating
the failure arguments is rejected too. Credited failure arguments contain no
`CallExpr`, function literal, or channel receive; canonical literals,
identifiers, and selectors are sufficient for the required assertions. This
also closes terminal package function values, closure aliases, and channel-
transported callables without a second interprocedural provenance graph. A
syntactically present but unreachable failure cannot satisfy the contract.

Each test must be selected and runnable in every supported build context in
which Service is selected; a Windows-only test does not satisfy Linux. The
constructor and Serve call are direct live top-level statements, not hidden by
short-circuiting, a conditional, loop, switch, select, goroutine, deferred call,
or an early-terminating helper. Termination analysis spans all active package
test files and binds only the real imported `testing.T` and `runtime` terminal
operations. The returned Service owner is a one-assignment local and cannot be
addressed, returned, sent, captured, converted, put in a container or
interface, passed to a helper, used as a method value, or otherwise escape
before the one direct Serve call.

That direct-live topology applies to the original direct-Serve tests. The
claimed-plan, causal-credit, and Receive-convergence tests instead use their
exact table/channel/state-backed causal matrices. The comparison no-Core test
constructs one real Service, one completed normal transaction, and one exact
comparison transaction, directly invokes the private and stdin handlers with
`comparison=true`, replays the cached result, and requires both Core call
counters to remain zero; it does not falsely exercise normal Serve.
Before NewService, setup consists only of direct assignments and
value/constant declarations whose evaluated expressions contain no call,
function literal, or channel receive, except an exact unshadowed predeclared
`int(raw-integer-literal)` conversion. Between NewService and Serve, only the
matching captured constructor-error gate `if err != nil { t.Fatal(err) }` may
appear. From Serve through the last credited evidence clause, statements are
limited to the matching captured Serve-error gate and the credited top-level
assertions themselves. A runtime-true but analyzer-unknown conditional return
before construction, between construction and Serve, or before any evidence
is therefore invalid for fake and Service-owned observables alike. Supplemental
tables remain permitted only after the direct credited evidence. Credited
evidence conditions themselves contain no `CallExpr`, function literal, or
channel receive. Non-exercise result fields and inert table data may be
inspected only after the required direct evidence; the supplemental tail is
recursively call-free and cannot invoke an accessor, helper, constructor,
deferred call, goroutine, or channel operation. Every credited assertion has
nil `Init` and nil `Else`; an alternate return, skip, Goexit, panic, or other
terminal branch cannot bypass later evidence in a multi-evidence test. The
supplemental tail is data-only with respect to the exercise: it contains no use
of the returned Service owner, no function literal, call expression, send, or
receive, and no `NewService` identifier. Across the whole test the sole `NewService` identifier
is the exact constructor `CallExpr.Fun`; prebound aliases and package-helper
construction cannot substitute. Consequently the full test still has exactly
one construction and one Serve. A supplemental `range` is permitted only over
a provably inert direct string/integer/array/slice/map value or a local
single-assignment alias recursively initialized from one. Channel, function,
unknown, and reassigned range operands are rejected, closing implicit receive
and range-over-function invocation without rejecting inert table loops. Range
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

Except for the Service-owned snapshot count called out below, every promised
observable is an exact field on a fake initialized before and causally supplied
to `NewService` through the Service options/dependency graph.
The fake begins at the canonical zero value: keyed zero fields are allowed, but
a nonzero/positional seed, helper-issued value, alias/container/pointer write,
or arbitrary call with the fake is not. Its complete alias graph remains
unmodified except by the exact configured Service lifetime. That fake owner
remains single-assignment and the test never writes the tracked field itself.
Alias transport through array, slice, map, or nested-container `range`
keys/values, through channel send/receive, or through package-global storage is
part of the same causal graph: the guard either follows every subsequent alias
or rejects the transfer conservatively. Unrelated ranges and nested tables
which do not carry the configured fake remain valid test structure.
Only a live post-Serve `observed != expected` clause against an integer literal
or independently defined immutable constant with an explicit exact `int`
`ValueSpec.Type` which drives `Fatal`,
`Fatalf`, `Error`, or `Errorf` on the original unshadowed `t` counts. The
constant is fixed before NewService and its initializer AST is exactly a raw
integer literal or `int(raw-integer-literal)` with no parenthesized wrapper; it
cannot be untyped, use an integer alias or another numeric/string type, or
derive through another value or constant. An active package-scope declaration
or explicit/default file import binding named `int` which shadows the
predeclared identifier invalidates the named form in every supported build
context. A dot import never shadows lowercase `int`, because it exposes only
exported identifiers. Unaliased import bindings are resolved from the actual
declared package name in the applicable build context (including module-local
active production package clauses), never guessed from the import-path
basename. `_test.go`, external-test packages, and other non-importable test
variants never participate in that package-name consensus. Resolution uses the
effective module graph, including local `replace`, vendor mode, and available
cached dependencies, through a bounded analysis-local, success-only cached `go
list`. Module mode is exactly `readonly` unless an existing vendor manifest
selects `vendor`; `GO111MODULE=on`, `GOENV=off`, empty `GOFLAGS`, `GOWORK=off`,
`GOPROXY=off`, `GOSUMDB=off`, empty `GOPRIVATE`/`GOINSECURE`,
`GONOPROXY=none`, `GONOSUMDB=none`, `GOVCS=*:off`, `GOTOOLCHAIN=local`, exact
GOOS/GOARCH, and `CGO_ENABLED=0` are forced exactly once after inherited
duplicates are removed. The source directory and target module-root working
directory are made absolute, cleaned, and canonicalized with symlinks resolved
before discovery or execution; broken or cyclic links fail unresolved. A
module-local fallback package directory must remain within that canonical
root. It cannot write `go.mod`/`go.sum`, access the network or direct/vanity
resolution, reuse failures/timeouts, or retain success across analyzer
invocations/source mutations. Module-local parsing is the deterministic
fallback. An unresolved unrelated
import does not itself invalidate the grammar. A
package-level const is definitionally before
the test construction regardless of source-file size/order; a function-local
const must be in that same function and structurally precede NewService. Raw
`token.Pos` values from separately parsed files are never compared.
Constant evaluation follows named constants and conversions for masking only.
A constant-false
conjunction, constant-true disjunction, inverted/equality condition, foreign
selector, self-comparison, indirect expected value, manual field write,
pre-exercise assertion, or fake/rebound testing owner does not.

`ownedSnapshotEntries` is the sole non-fake observable in that catalog. It is
an exact live post-Serve `len(service.extensions) != positiveExpected` check on
the one Service owner returned by the test's exact `NewService` call. The
expected count follows the same canonical integer-literal or explicitly typed
`int` constant grammar above and must be positive. `len` is the exact
unshadowed predeclared builtin in the test file and package across every
applicable build context; a local, file-import, or cross-file package
declaration named `len` invalidates the evidence. A caller-registry counter,
`len(registry.entries)`, a foreign or rebound Service, a zero expected count,
or a pre-Serve check cannot satisfy this evidence. The returned Service owner
and its `extensions` selector have no other use except the one exact direct
Serve call recorded as the required exercise and this one length observation:
an additional expression, deferred, goroutine, or indirect Serve call, direct
or aliased replacement, append, index/field mutation, helper passing, or any
other test-authored snapshot change is rejected. This behavioral observation
is a direct top-level path: the length assertion immediately follows the Serve
assignment, except that a captured non-blank Serve error may be checked by the
sole exact intervening `if serveErr != nil { t.Fatal(serveErr) }` gate. No
other credited fake-field assertion may intervene: in the multi-evidence
constructor/one-shot test, the owned snapshot is the first credited statement
after that optional gate. No other assignment, call, conditional, return, loop,
switch, select, defer, or goroutine may intervene, so a runtime-true but
analyzer-unknown return cannot make the observation vacuous. Before NewService,
setup is limited to direct
assignments and value/constant declarations whose evaluated expressions
contain no call, function literal, or channel receive. Between the exact
NewService assignment and Serve, the matching captured constructor-error gate
`if err != nil { t.Fatal(err) }` is required. A test that credits
`commitCalls` or `wipeCalls` then performs exactly one direct
`transport.service = service` assignment. That Transport already feeds
`ServiceOptions.Transport`; the test-only link permits read-only observation
of the installed transaction and no other Service escape. Control flow
before construction, between construction and Serve, or between Serve and the
observation therefore cannot hide a passing early exit. This behavioral
observation is paired with the production structural proof that
`snapshotServiceExtensionEntries` allocates a distinct slice and deep-clones
every descriptor while preserving order and factory identity. This rule does
not add mutable instrumentation to the caller-owned immutable
`ExtensionRegistry`.

Observable provenance is field-specific, causal, and not a recursive name
occurrence anywhere in `ServiceOptions`. `beginExecCalls`,
`writeStdinCalls`, and `planDestroyCalls` come from `Core`; `takeCalls`,
`commitCalls`, and `bodyDestroyCalls` come from `Transport`; `wipeCalls` comes
from Transport for a verified failed proposal transition or from Core for the
recovered-panic cleanup path. Before the embedded exact
`transportTestBody.Borrow`, the exact test body reads the real installed
transaction from the bound Service under its mutex, retains that same pointer
for panic observation, snapshots it, and snapshots the exact Core counters.
After Borrow returns it snapshots the same transaction again. `commitCalls` is
credited only for a nil result plus the exact private-complete or stdin-record
transition and matching one-call Core delta (or zero Core delta in comparison
mode). Normal `wipeCalls` requires a nonnil result, an actual
nonterminal-to-terminal transition, and the matching one-call Core delta.
`planDestroyCalls`
is credited only when exact Core revoke observes the scenario's actual claimed
plan state as destroyed; the panic wipe counter is credited only when that
retained transaction is terminal, the panic mode is exact, and the Core call
occurred. The base transport body must invoke its callback once with the
actual retained region/view. A synthesized result or snapshot, skipped
callback, foreign transaction, missing exact Service observer binding,
unrelated body, constant Core delta, or constant plan state is not evidence.
`ownedSnapshotEntries` comes only from the returned
Service's owned private extension slice under the rule above;
`dependencyCalls` comes from one of Core, Transport, Policy, Host, or Runtime;
and `serveCalls` comes from Transport or Runtime. The Go-checked exact
`ServiceOptions` field type is part of this binding. Supplying the same fake in
an unrelated field or nested container cannot prove the boundary.
Supplemental table checks are permitted after this direct causal exercise but
cannot replace it.

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

Bootstrap correlation has one shared lower-level digest primitive in
`credentialprotocol`:

```go
func ComputeCanonicalHelperBootstrapSHA256(
	header HelperPacketHeader, canonicalBody []byte,
) ([32]byte, error)
```

The input body is already-validated canonical safe bootstrap metadata, not a
credential payload. The function requires bootstrap type, sequence zero,
canonical bootstrap header semantics, a nonzero body length at most
`MaxHelperPacketBodyBytes`, and exact equality between `header.BodyLength` and
`len(canonicalBody)`. It calls `EncodeHelperPacketHeader`, never mutates or
retains the body, and computes exactly:

```text
SHA256(
  opaque16("hal/l8/guest-helper/bootstrap/v1") ||
  canonicalHeader[100] || canonicalBody)
```

Wrong type, sequence, request-ID/identity/nonce semantics, length, or header
encoding returns the zero digest and the stable
`credentialprotocol.ErrHelperBootstrapCanonicalDigest`; the error does not
contain header or body data. The primitive deliberately does not decode or
semantically validate `canonicalBody`, because doing so would duplicate the
owning package's already-completed validation.
The primitive and its domain constant live in the exact pure production file
`credentialprotocol/helper_bootstrap_digest.go`; that file imports exactly
`crypto/sha256`, `encoding/binary`, and `errors`, and no higher-level guest
package.

`l8composition.ComputeHelperBootstrapSHA256` remains public and byte-compatible.
It retains all existing `HelperBootstrapBody` and `HelperBootstrapExpected`
semantic checks, canonically encodes the body, then delegates the final header
and body hashing to `ComputeCanonicalHelperBootstrapSHA256`. Existing vectors
and error precedence remain unchanged. `credentialhelper` cannot import
`l8composition`; after `NewReceivedBootstrapPacket` validates its decoded
scalar arguments against the exact retained canonical body, it delegates to
the same lower primitive before destroying that body.

The exact received bootstrap arm therefore becomes:

```go
type ReceivedBootstrap struct {
	liveValue
	agentIdentitySHA256 [32]byte
	bootGeneration      credentialprotocol.SafeID
	helperGeneration    credentialprotocol.SafeID
	bootstrapSHA256     [32]byte
}
```

The digest is computed from the authenticated header and the exact body owned
by the constructor; no caller-supplied digest argument is added. It is stored
only after the canonical body validator and shared digest primitive both
succeed, remains private with no public accessor, and is used by Service for
bootstrap-ack, agent-hello comparison, and `BindAgent` correlation. Every
failure or panic still destroys the body and closes the pidfd right under the
constructor's leading context. Mutation vectors cover every header field and
every canonical body byte, and cross-package vectors require the wrapper,
primitive, and received arm to agree exactly.


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
final argument may be a non-nil agent-pidfd right. After the context
precondition and, for Exec, the plan precondition pass, each constructor
atomically seals its first request and validates header/type/sequence/body length,
identity/nonce, body length/digest, actual credential/right counts, closed
fields, right kind, and cardinality. Service independently compares the private
credential with its exact pinned role before dispatch. Sensitive constructors recompute and compare exact
private payload length/digest in place before transfer. Post-transfer failure
destroys the full body capability and closes the right. Success makes
`ReceivedPacket` owner of both the exact body mapping and right.

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
drain begins. It rejects a plain nil context with
`ErrContractInvalidArgument` or a typed-nil context with
`ErrContractTypedNil` before touching ownership, the one-shot latch, or any
capability method. Context is checked before and after each borrow, copy, or
destroy; cancellation cannot abandon ownership. No send constructor,
validator, or write path uses
`context.Background()` or `context.TODO()`. Context-aware private send
constructors that take or borrow a live body/right also take a leading
`context.Context`. After its plain/typed-nil context precondition passes, each
owns the supplied capability on entry. The constructor uses that exact context
to clean post-transfer constructor failure. A successful fill
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
exact error and preserve every input. Every receive or private-send transport
constructor that accepts a live body or right has a leading `context.Context`.
It first rejects a plain nil context with `ErrContractInvalidArgument` or a
typed-nil context with
`ErrContractTypedNil`, before ownership transfer, request consumption, a
one-shot latch, or any body/right method; all supplied live inputs remain
caller-owned in those pre-transfer cases. `NewReceivedExecPacket` next rejects
a zero/nil-state, destroyed, or already claimed plan, including a losing
concurrent claim, before transfer and leaves its `ReceiveRequest`, body, and
right unconsumed and caller-owned. After these preconditions, ownership of
every supplied non-nil live body or right transfers atomically on constructor
entry, and the constructor synchronously destroys/closes the owned capability
with that supplied context on every failure or panic. Capability validation
precedence is context, then the applicable Exec-plan precondition, then body,
then right; a typed-nil capability is never called. It never uses
`context.Background()` or `context.TODO()` and never returns live ownership to
the caller after transfer.

Only a plain nil or typed-nil context is the global context pre-transfer
failure. Exec has the additional plan precondition above. Any other context,
including one already done, follows the normal atomic live-input ownership
transfer. Constructors
never return or wrap `ctx.Err()`: cancellation observed before a borrow/copy or
immediately after an external callback prevents success, all mandatory
destroy/close calls are still attempted exactly once with that same context,
and the result is `ErrContractOwnership`. Cancellation observed before or after
destroy/close is recorded but never skips cleanup. For `WriteCanonicalBody`, a
plain or typed-nil context is rejected before the one-shot latch; cancellation
after the latch consumes the write, performs no further fill when already
observed, and returns
`ErrContractOwnership`. Safe metadata-only send constructors likewise return
`ErrContractOwnership` for a non-nil already-done context before success.
Post-transfer cleanup isolates each body `Destroy` and right `Close`: if either
trusted callback panics, the panic is recovered and reduced to
`ErrContractOwnership`, without raw panic text, while every other live owner is
still synchronously offered its one mandatory cleanup call. A cleanup panic
never skips another owner and never escapes the transport constructor.

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
	Host      credentialhelper.ExtensionHost
	Runtime   credentialhelper.ServiceRuntime
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

`HelperOptions.Host` and `HelperOptions.Runtime` are explicit, independent,
mandatory service dependencies. `HelperOptions.Core` is accepted only as
`credentialhelper.Core` and supplies neither dependency. The Host and Runtime
fields are the sole sources of `credentialhelper.ExtensionHost` and
`credentialhelper.ServiceRuntime`; `NewHelper` validates them independently and
passes those exact values directly to `credentialhelper.NewService`. `SSH` is
only an extension registration and cannot replace either service dependency.

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

The inherited `GuestAgent` shape has an L8-specific exact value rather than a
false v1 claim:

```go
const L8GuestAgentProtocolV2 = "guest-agent-v2"
```

For an L8 manifest and provenance, `GuestAgent.Protocol` is exactly that
constant and `GuestAgent.Features` is exactly this order with no omissions,
duplicates, aliases, or additions: `"copy_in", "copy_out", "credential_delivery_v2"`,
then `"exec", "readiness", "ssh_agent_relay_v1"`. `ValidateL8DistributionManifest`
and `ValidateL8Provenance` apply the stable common
architecture/version/network/asset checks through an L8-aware internal
validator; the generic L5/L7 validator is not called on an L8 value because
its exact v1 protocol predicate must remain unchanged. L5/L7 continue to
require their existing `guest-agent-v1` and four-feature sequence. The
manifest and provenance GuestAgent values must match exactly before L8
profile-fact correlation. Both L8 documents also require the exact unchanged
L7 `static_proxy` guest-network value and ordered L7 network feature catalog;
the parent evidence and descriptor must agree with it. Any protocol, feature,
order, count, case, network, or manifest/provenance mutation is
`version_invalid` at the declared GuestAgent field.

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
	CatalogVersion                   string `json:"catalogVersion"`
	GuestAgentSHA256                 string `json:"guestAgentSha256"`
	GuestInitSHA256                  string `json:"guestInitSha256"`
	CredentialHelperSHA256           string `json:"credentialHelperSha256"`
	MountMonitorSHA256               string `json:"mountMonitorSha256"`
	WorkloadShimSHA256               string `json:"workloadShimSha256"`
	RoleBootstrapSHA256              string `json:"roleBootstrapSha256"`
	HelperDescriptorSHA256           string `json:"helperDescriptorSha256"`
	ClientDescriptorSHA256           string `json:"clientDescriptorSha256"`
	CompositionSHA256                string `json:"compositionSha256"`
	WorkloadSnapshotSHA256           string `json:"workloadSnapshotSha256"`
	RuntimeProfileSHA256             string `json:"runtimeProfileSha256"`
	PolicyArtifactSHA256             string `json:"policyArtifactSha256"`
	PolicySourceLockSHA256           string `json:"policySourceLockSha256"`
	PolicyBinaryBindingSetSHA256     string `json:"policyBinaryBindingSetSha256"`
	PinnedCallsiteEvidenceSHA256     string `json:"pinnedCallsiteEvidenceSha256"`
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

The only ASCII bytes permitted in a source filename are printable bytes
`0x21..0x7e`; the slash, backslash, and every character rejected above remain
excluded. Bytes `0x80..0xff`, UTF-8 multibyte sequences, DEL, and every control
or space byte are rejected before marker checks. The validator iterates bytes,
not Unicode code points.

The filename URL/credential checks are one exact case-insensitive
URL/credential-marker algorithm over an ASCII-lowercased copy; they never
normalize the stored filename. A URL marker is either substring `://` or one
of the prefixes `http:`, `https:`, `ssh:`, `tcp:`, `udp:`, `grpc:`, `file:`.
A credential marker is any occurrence in this exact catalog:
`"authorization", "bearer", "token", "secret"`; `"credential", "password",
"api_key", "apikey"`; or `"access_key", "private_key", "ghp_", "github_pat_",
"sk-"`. Matching is byte-oriented;
non-ASCII filenames are already rejected by the basename grammar. Tests mutate
every marker's case, prefix position, and one adjacent byte and require the
closed accept/reject result.

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

`PiDependencyTreeSHA256` is not a package-manager-dependent installed-tree
walk. It is the lower-case hex encoding of this canonical digest, computed
only after the source list is validated and with `npmArchiveCount =
len(Sources)-3`:

```text
SHA256(
  opaque16("hal/l8/pi-dependency-tree/v1") ||
  token(piPackage.kind) || token(piPackage.name) || token(piPackage.version) ||
  token(piPackage.filename) ||
  uint64_be(piPackage.sizeBytes) || digest32(piPackage.sha256) ||
  token(piShrinkwrap.kind) || token(piShrinkwrap.name) || token(piShrinkwrap.version) ||
  token(piShrinkwrap.filename) ||
  uint64_be(piShrinkwrap.sizeBytes) || digest32(piShrinkwrap.sha256) ||
  uint32_be(npmArchiveCount) ||
  for each npm_archive in the already validated source-lock order:
    token(kind) || token(name) || token(version) || token(filename) ||
    uint64_be(sizeBytes) || digest32(sha256))
```

`opaque16`, `token`, and `digest32` retain their definitions below and all
integers are big-endian. The manifest, provenance, source lock, and final
inspection must carry this exact value; final inspection independently
recomputes it from the validated lock and also proves the offline installed Pi
tree contains no package/archive outside that lock. Shrinkwrap file bytes and
every archive digest are bound directly, so traversal order, filesystem
metadata, npm output, JSON map order, and a host cache path never participate.

The process facts are exact, not a general binary inventory. Their catalog is
`L8ProcessCompositionCatalogV1`; all fifteen digest fields are required. The
six binary fields bind the exact installed `hal-guest-agent`, `hal-guest-init`,
`hal-guest-credential-helper`, `hal-guest-mount-monitor`,
`hal-guest-workload-shim`, and freestanding `hal-guest-role-bootstrap` bytes.
`HelperDescriptorSHA256`, `ClientDescriptorSHA256`, and
`CompositionSHA256` are the exact `HL8D` values defined above. The final six
fields bind one canonical HL8Q artifact and its external HL8E evidence, in this
exact order: `WorkloadSnapshotSHA256`, `RuntimeProfileSHA256`,
`PolicyArtifactSHA256`, `PolicySourceLockSHA256`,
`PolicyBinaryBindingSetSHA256`, and `PinnedCallsiteEvidenceSHA256`. The first two fields are immutable views derived from the sole HL8Q artifact, never
separate artifacts or issuer authority. The latter four are the host authority
bindings independently correlated by the HL8E importer. D7 produces the single
HL8Q plus external HL8E from the exact phase head, embeds the HL8Q expectation
in the guest binaries, and independently copies these six values into
`L8ProfileFacts`. A descriptor label,
binary filename, static version string, or live guest response cannot replace
any digest.
Manifest, provenance, and final inspection carry all six fields in this exact
order, and the evidence fingerprint binds all six in the same exact order.

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
workload_snapshot
runtime_profile
policy_artifact
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
each of the five metadata files is nonempty and at most 4 MiB, and each of
`vmlinux` and `rootfs.ext4` is nonempty and at most 1 GiB. Size is checked from
the opened regular file before hashing and an extra trailing byte is rejected,
so an oversized installed file cannot force an unbounded digest pass.

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
  digest32(compositionSha256) || digest32(workloadSnapshotSha256) ||
  digest32(runtimeProfileSha256) || digest32(policyArtifactSha256) ||
  digest32(policySourceLockSha256) ||
  digest32(policyBinaryBindingSetSha256) ||
  digest32(pinnedCallsiteEvidenceSha256))
```

The validator first proves that the typed manifest/provenance/source-lock/
inspection values agree and that their named file digests agree with the
checksum inventory. Consequently the fingerprint binds the manifest,
provenance, source lock, final inspection, parent L7 bundle, helper/client/
composition, and all six HL8Q-view/policy/HL8E digests in their declared order.
This resolves the
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
type verifiedL8PolicyAuthorityBindings struct {
	policyArtifactSHA256         [32]byte
	policySourceLockSHA256       [32]byte
	policyBinaryBindingSetSHA256 [32]byte
	pinnedCallsiteEvidenceSHA256 [32]byte
	imageSHA256                  [32]byte
}

type verifiedL8ProfileCorrelation struct {
	descriptorFingerprint [32]byte
	evidenceFingerprint   [32]byte
	policyAuthority       verifiedL8PolicyAuthorityBindings
}

type verifiedL8LeaseCorrelation struct {
	sourceDescriptorFingerprint   [32]byte
	preparedDescriptorFingerprint [32]byte
	hasPreparedDescriptor          bool
	evidenceFingerprint           [32]byte
	policyAuthority               verifiedL8PolicyAuthorityBindings
}

type VerifiedL8Profile struct {
	seal        verifiedL8ProfileSeal
	correlation verifiedL8ProfileCorrelation
}

type VerifiedL8AssetLease struct {
	state       *verifiedL8AssetLeaseState
	correlation verifiedL8LeaseCorrelation
}

type L8LaunchMaterialWriter interface {
	WriteAsset(assets.AssetRole, io.Reader) (string, error)
	Validate() error
	Close() error
}

func (VerifiedDistribution) L8Profile() (VerifiedL8Profile, bool)
func (VerifiedDistribution) AcquireL8AssetLease() (*VerifiedL8AssetLease, error)
func VerifiedL8ProfileMatches(*VerifiedL8Profile, *assets.LaunchDescriptor) bool
func VerifiedL8ProfileMatchesLease(*VerifiedL8Profile, *VerifiedL8AssetLease) bool

func (*VerifiedL8AssetLease) ConfirmCurrent(*assets.LaunchDescriptor) error
func (*VerifiedL8AssetLease) PrepareLaunch(
	*assets.LaunchDescriptor,
	L8LaunchMaterialWriter,
) (assets.LaunchDescriptor, VerifiedL8Profile, error)
func (*VerifiedL8AssetLease) Close() error
```

The private `verifiedL8AssetLeaseState` owns the mutex, pinned bundle, launch
material, and lifecycle state; it never owns a second correlation record. The
exact nested field on both correlation records is
`policyAuthority verifiedL8PolicyAuthorityBindings`; it is private and has no
accessor.

There is no public constructor or fingerprint accessor. The existing
`VerifyDistributionBundle(DistributionRequest)` remains the five-file L5/L7
entry point and cannot issue L8 authority. The sole L8 issuer is the separate
exact entry point:

```go
type L8DistributionRequest struct {
	DistributionRequest
	ParentL7 VerifiedDistribution
	PinnedCallsiteEvidence []byte
}

func VerifyL8DistributionBundle(L8DistributionRequest) (VerifiedDistribution, error)
```

The final request field is exact. `PinnedCallsiteEvidence` must be non-nil,
nonempty, and at most 16 MiB (`16777216` bytes). The resolver checks that
bound before allocating the snapshot, then deep-snapshots
`PinnedCallsiteEvidence` before hashing or import, so caller mutation cannot
affect verification, a returned value, or an error. It obtains the sole policy
authority only from `syscallpolicy.EmbeddedVerifiedPolicyArtifact()` and the
sole expected evidence issuer only from
`syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()`. It checks that
issuer's separate error before passing the returned exact expectation to
`syscallpolicy.ImportPinnedCallsiteEvidence` with the copied snapshot and
artifact. The issuer has mutually exclusive leaf declarations: the exact
default `syscallpolicy/pinned_evidence_default.go` declaration is constrained
by `!l8_verified_pinned_callsite_evidence`, while a future D7-generated
`syscallpolicy/pinned_callsite_evidence_expected_d7_gen.go` declaration is
constrained by `l8_verified_pinned_callsite_evidence`. The generated sibling is
absent until D7 possesses real final-binary authority; once present, exactly
one declaration is active in each complementary build context. A missing default
embedded artifact/issuer, zero or oversized evidence, or any import mismatch
fails before profile issuance. No caller can supply an expected digest or
artifact issuer. After sealing the four host-authority digests, the resolver
destroys the temporary copy and retains no caller slice or imported evidence
graph after sealing. D7 passes the fixed `verified-pinned-callsites.hl8e` output
bytes in this field. The seven-file distribution remains unchanged: HL8E is an
explicit bounded verification input, not an eighth distribution file.
The resolver retains no caller slice or imported evidence graph after sealing.

Policy composition correlation is derived, never copied from a document. After
`EmbeddedVerifiedPolicyArtifact` succeeds and the copied request bytes have
successfully passed `ImportPinnedCallsiteEvidence`, but before any profile or
lease issuance, `localresolver` constructs this exact private value in declared
field order:

```go
type l8VerifiedPolicyCompositionDigests struct {
	workloadSnapshotSHA256       [32]byte
	runtimeProfileSHA256         [32]byte
	policyArtifactSHA256         [32]byte
	policySourceLockSHA256       [32]byte
	policyBinaryBindingSetSHA256 [32]byte
	pinnedCallsiteEvidenceSHA256 [32]byte
}

func deriveL8PolicyCompositionDigests(
	artifact syscallpolicy.VerifiedPolicyArtifact,
	evidence syscallpolicy.PinnedCallsiteEvidenceSet,
) l8VerifiedPolicyCompositionDigests
func l8PolicyCompositionDigestsEqual(
	left, right l8VerifiedPolicyCompositionDigests,
) bool
func validateL8PolicyCompositionCorrelation(
	derived, manifest, provenance, finalInspection l8VerifiedPolicyCompositionDigests,
) error
```

`deriveL8PolicyCompositionDigests` has one direct composite return whose six
expressions, in order, are exactly:

```go
artifact.Workload().SHA256()
artifact.Runtime().SHA256()
artifact.SHA256()
artifact.SourceLockSHA256()
evidence.BinaryBindings().SHA256()
evidence.SHA256()
```

No document field, cached string, profile field, alternative artifact/view, or
caller value may supply one of those expressions. The already-imported
artifact and evidence remain the exact receiver values. All six results are
nonzero by their successful import invariants. The struct and three functions
live together in exact private production file
`localresolver/l8_policy_composition_correlation.go`, which imports the
standard `crypto/subtle`, exact `assets/build` as `assetbuild`, and exact
neutral `guestagent/syscallpolicy` package; aliases, lookalike local types,
and cross-file marker substitutes do not satisfy the guard. Its final exact
constructor is:

```go
func l8PolicyCompositionCorrelationMismatch() error {
	return &assetbuild.L8ValidationError{
		Code:  assetbuild.L8ValidationCode("correlation_mismatch"),
		Field: "processComposition",
	}
}
```

`Index` is therefore nil and `Error()` is exactly
`L8 image profile validation failed: correlation_mismatch`; there is no
digest, parser cause, document value, or variable text.

Once ordinary field validation has decoded the six lower-case hex fields from
each manifest, provenance, and final-inspection `ProcessComposition` into an
independent `l8VerifiedPolicyCompositionDigests`, the resolver compares the
derived value against manifest first, provenance second, and final inspection third.
Each comparison invokes `l8PolicyCompositionDigestsEqual`. That helper
starts one integer accumulator at one, applies exactly six ordered
`crypto/subtle.ConstantTimeCompare` operations with `&=`, and returns only
whether the final accumulator remains one; it has no field-dependent early
return, and the final inspection independently repeats the complete six-field
equality against the derived value. It is not accepted merely because its
value equals manifest or provenance, nor because an earlier cross-document
validator compared the documents to each other.

Digest syntax/zero failures retain the existing internal `digest_invalid`
validation result at the first field in declared order. After syntax succeeds,
the first helper mismatch uses only internal typed code `correlation_mismatch`
and field `processComposition`, in document order manifest, provenance, then
final inspection; no value, digest, document contents, or parser cause enters
the error. The sole issuer then maps it to the closed resolver result specified
below. No profile seal, evidence
fingerprint, lease, or returned distribution exists before all three complete
comparisons succeed. The `VerifyL8DistributionBundle` package-test matrix
mutates each of the six fields in each of the three documents and requires the same closed mismatch result while leaving all
other fields valid. The AST guard locks the receiver chain, composite field
order, direct accumulator, six concrete slice comparisons, and final result;
mere disconnected accessor or comparison marker calls do not satisfy it.

The helper shape is not sufficient by itself. The real sole issuer lives in
the exact production file
`localresolver/l8_distribution_verifier.go`. Its top-level
`VerifyL8DistributionBundle(request L8DistributionRequest)
(VerifiedDistribution, error)` body owns these protected one-assignment values:
`manifest`, `provenance`, `sourceLock`, `finalInspection`,
`descriptor`, `rootDir`,
`pinnedCallsiteEvidenceBytes`, `artifact`, `expectedEvidence`, `evidence`,
`manifestPolicyComposition`, `provenancePolicyComposition`,
`finalInspectionPolicyComposition`, `derivedPolicyComposition`,
`evidenceFingerprint`, and `verifiedL8Profile`.
The four exact bounded decoder/error pairs form an ordered prelude, not the
closed authority block. Their assignments and immediately following matching
error returns are ordered, while all existing pure document, parent, checksum,
catalog, and final-inspection validation occurs after those decodes and before
the authority block. That validation produces one normalized `descriptor` and
one validated, clean `rootDir`; both are protected one-assignment values. It may
not reassign a protected value, branch around an
anchor, or construct or return L8 authority before correlation succeeds.

The prelude obtains `manifest`, `provenance`, `sourceLock`, and
`finalInspection` with, respectively, `decodeL8DistributionManifest`,
`decodeL8Provenance`, `decodeL8SourceLock`, and `decodeL8FinalInspection` over
`request.DistributionRequest`; each assignment has an immediately following
nonnil-error return through its matching `classifyL8*Error`. After all other
required validation succeeds, the following statements form one closed,
contiguous, ordered top-level authority block; each import/process-composition
decode is followed immediately by its nonnil-error return:

```go
pinnedCallsiteEvidenceBytes, err := snapshotL8PinnedCallsiteEvidence(
	request.PinnedCallsiteEvidence,
)
if err != nil { return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceError(err) }
defer wipeL8PinnedEvidence(pinnedCallsiteEvidenceBytes)
artifact, err := syscallpolicy.EmbeddedVerifiedPolicyArtifact()
if err != nil { return VerifiedDistribution{}, classifyL8PolicyArtifactError(err) }
expectedEvidence, err := syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()
if err != nil { return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceExpectationError(err) }
evidence, err := syscallpolicy.ImportPinnedCallsiteEvidence(
	pinnedCallsiteEvidenceBytes,
	artifact,
	expectedEvidence,
)
if err != nil { return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceError(err) }
manifestPolicyComposition, err := decodeL8PolicyCompositionDigests(manifest.L8Profile.ProcessComposition)
if err != nil { return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err) }
provenancePolicyComposition, err := decodeL8PolicyCompositionDigests(provenance.L8Profile.ProcessComposition)
if err != nil { return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err) }
finalInspectionPolicyComposition, err := decodeL8PolicyCompositionDigests(finalInspection.ProcessComposition)
if err != nil { return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err) }
derivedPolicyComposition := deriveL8PolicyCompositionDigests(artifact, evidence)
if err := validateL8PolicyCompositionCorrelation(
	derivedPolicyComposition,
	manifestPolicyComposition,
	provenancePolicyComposition,
	finalInspectionPolicyComposition,
); err != nil {
	return VerifiedDistribution{}, classifyL8PolicyCompositionCorrelationError(err)
}
```

The exact classifier is in the issuer file and deliberately retains no input
error or cause:

```go
func classifyL8PolicyCompositionCorrelationError(_ error) error {
	return newResolverError(
		ErrorCodeAssetLockMismatch,
		"processComposition",
		"",
		"L8 policy composition correlation mismatch",
		ErrAssetLockMismatch,
	)
}
```

The public result is therefore exact resolver code `asset_lock_mismatch`, field
`processComposition`, empty role, static message
`L8 policy composition correlation mismatch`, and only the static
`ErrAssetLockMismatch` unwrap. Its complete `Error()` string is
`local asset resolver failed (asset_lock_mismatch) field=processComposition:
L8 policy composition correlation mismatch`. The internal typed build error's
`correlation_mismatch` code never escapes this sole issuance boundary.

That controlling top-level validation must precede the first
`buildL8EvidenceFingerprint`, `sealVerifiedL8Profile`,
or `sealVerifiedL8Distribution` call and every successful
`(VerifiedDistribution, nil)` return. The derived value is passed to the
fingerprint builder. That builder returns the evidence fingerprint and the
independently measured rootfs `imageSHA256`; it receives only the already
validated `parentL7EvidenceSHA256`, never the parent distribution authority.
The exact profile seal is
`sealVerifiedL8Profile(descriptorFingerprint, evidenceFingerprint,
imageSHA256, derivedPolicyComposition)`, where `descriptorFingerprint` is
computed once from the already normalized descriptor and protected from
reassignment.
The profile, fingerprint, and derived authority are passed to the sole
successful distribution seal together with the already validated manifest,
provenance, descriptor, and clean root directory:
`sealVerifiedL8Distribution(verifiedL8Profile, evidenceFingerprint,
derivedPolicyComposition, manifest, provenance, descriptor, rootDir)`. This is
the only point that installs the public bundle projection and private lease
source state; no package cache or later path rediscovery supplies them. The verifier does not
mint a `VerifiedL8AssetLease`: only a successfully returned verified
distribution can later service `AcquireL8AssetLease`, so correlation failure
transitively makes lease issuance unreachable. Discarding the error, placing validation in unreachable or
noncontrolling code, using a lookalike import/result, aliasing two document
records, deriving from any other artifact/evidence, reassigning a protected
value, or issuing before validation fails the AST guard.
The package-wide parsed production reference guard has no basename-wide
allowlist. It parses every production declaration and function in
`localresolver`. The only references to `buildL8EvidenceFingerprint`,
`sealVerifiedL8Profile`, `sealVerifiedL8Distribution`, and
`classifyL8PolicyCompositionCorrelationError` are their exact direct calls in
the real top-level `VerifyL8DistributionBundle`, with exactly one of each and
with the controlling correlation validation first. Same-file or alternate-
file helpers, wrappers, methods, closures, `defer`, `go`, function values,
aliases, and exact-name shadows are not exceptions. A transitive wrapper is
rejected at its protected terminal reference. The verifier may not call or
retain `AcquireL8AssetLease`, `PrepareLaunch`, or any case-insensitive
`mint`, `new`, `create`, `construct`, `make`, `build`, `issue`, `seal`,
`acquire`, `prepare`, or `remint`-prefixed API whose name contains
`VerifiedL8Profile`, `VerifiedDistribution`, or `VerifiedL8AssetLease`.
The guard treats `VerifiedL8Profile`, `VerifiedL8AssetLease`, `verifiedL8ProfileSeal`,
`verifiedL8PolicyAuthorityBindings`, `verifiedL8ProfileCorrelation`,
`verifiedL8LeaseCorrelation`, and `verifiedL8AssetLeaseState` as the closed
authority-owner graph. Exact signature-locked profile/distribution sealers and
`(VerifiedDistribution).AcquireL8AssetLease` may construct only their matching
single direct returned result. They cannot stage, copy, alias, cache, or assign
an authority value or nested owner; store one in a package/global/interface/
map/slice/generic container/channel; pass one to an arbitrary helper; capture
one in a closure or function value; or return one from a factory, alternate
function, or getter. Exact profile/lease matcher and lifecycle calls are the
only non-construction consumers. Authority type aliases and derived types are
forbidden. The verifier therefore returns the sealed distribution but never
mints, acquires, prepares, or remints a lease.
The guard computes the recursive authority-containing named-type closure over
every localresolver Go file and build context. Struct fields, pointers, arrays,
maps, generic instantiations, and named nesting remain tainted through selector
extraction, copy, assignment, accessor return, and arbitrary-helper passage;
an additional containing wrapper outside the closed graph is rejected at its
declaration. Exactly one all-build-context declaration with the frozen
signature/receiver is allowed for each profile sealer, distribution sealer,
and lease acquirer. Alternate-file or build-tagged duplicate definitions fail
even when the ordinary build would select only one.
Collection preserves every definition for each named type across all files and
mutually exclusive build tags; it never performs a last-writer overwrite by
source/map iteration.
The deterministic fixed point sorts paths and names, unions definitions
conservatively, and marks a name authority-containing when any definition can
reach authority. Cyclic, aliased, and generic-instantiated definitions converge
under the same rule, so a benign alternate definition cannot mask an
authority-bearing one in another build context.
The pre-existing generic `VerifiedDistribution` carrier remains usable by its
L5/L7 verifier and resolver paths: it becomes L8 authority only when a keyed
literal installs one of its private `l8Profile`, `l8EvidenceFingerprint`, or
`l8PolicyComposition` fields. Unkeyed literals are rejected. Zero and ordinary
L5/L7 keyed `VerifiedDistribution` values remain non-authority, so the L8 guard
does not break the already-landed lower-profile verifier while still confining
the sole L8 distribution seal.

The complete runtime regression is exact file
`localresolver/l8_distribution_verifier_test.go`. The sole runnable test owns
one function-local `[18]struct { document string; field string }` value named
`l8PolicyCompositionMutationCases`; there is no package type, variable,
slice, init hook, or externally addressable mutation table. Its document order
is `manifest`, `provenance`, `finalInspection`, each with field order
`workloadSnapshotSha256`, `runtimeProfileSha256`, `policyArtifactSha256`,
`policySourceLockSha256`, `policyBinaryBindingSetSha256`, and
`pinnedCallsiteEvidenceSha256`. The top-level runnable
`TestVerifyL8DistributionBundleRejectsPolicyCompositionMutations` first builds
an exact `validL8DistributionRequest` and requires the real
`VerifyL8DistributionBundle` to succeed before any mutation. It then ranges
the exact 3x6 table. For each tuple a fresh request also must succeed through
the real verifier before mutation. The test snapshots the 18 fields by
independently decoding manifest, provenance, and final inspection and hashes
the canonical JSON semantics of each document after zeroing only its complete
`ProcessComposition`; it passes both tuple fields to the exact mutator and
snapshots again. It proves only the selected array index changed, the
replacement is the different valid lower-case digest consisting of 32 `0x01`
bytes, all other 17 fields remain identical, and all three non-policy document
semantic hashes remain identical. Only then does it
invoke the real verifier, assert the exact sanitized mismatch above, and
increment one local counter after each successful exact
assertion, and requires the executed count to equal exactly 18. Its complete
body and exact builder/mutator/snapshot/change-assertion helper declarations
are parsed. An already-invalid baseline, missing/ignored baseline check,
no-op/fixed-field/alternate mutator, lying/aliased snapshot, missing/wrong-index
or missing non-policy change proof, comment/string markers, a dead or
cleared table, missing/duplicate/reordered/wrong tuples, ignored tuple fields,
alternate issuers, skips, continues, zero increments, and weak count/error
assertions do not satisfy it. Package/test source guards reject `unsafe`,
`go:linkname`, assembly, reflection-based aliases to the cases, package or
alternate init mutation, and every reference to the cases outside that exact
local test body; normal unrelated test reflection is not mutation authority.

The underlying implementations are confined to exact file
`localresolver/l8_distribution_policy_composition_fixture_test.go`, with one
all-build-context declaration each of
`materializeValidL8DistributionRequestFixture(*testing.T)
L8DistributionRequest` and
`replaceL8DistributionPolicyCompositionField(DistributionRequest, string,
string, string) error`. The parsed builder materializes the complete request,
requires real `VerifyL8DistributionBundle` success, and only then returns it;
the parsed mutator passes the exact request, document, field, and replacement
to the sole exact rewrite primitive. Lookalikes, fixed fields, missing
arguments, no-ops, `Skip`, `Skipf`, `SkipNow`, `runtime.Goexit`, and alternate
build-tagged declarations fail. Initial/per-case real verification and the
selected-only, other-17, and three non-policy semantic checks prove the helpers
non-vacuous at runtime.

While D2 product code is absent, `syscallpolicy`, the exact correlation-helper
file, exact issuer file, exact mutation-test file, and exact underlying fixture
file may all be absent and this product guard remains green. Once any one
appears all five must appear together and satisfy their parsed guards. Thus a
dead helper or partially
landed product stays fail-closed.

The request also requires a nonzero resolver-issued parent distribution whose
`L7Profile()` is valid and whose current parent asset lease can be acquired and
confirmed. A copied public manifest/provenance/descriptor without that private
parent authority is invalid. `VerifyL8DistributionBundle` is the sole opaque
`VerifiedL8Profile` issuance path. It issues only after the
exact seven-file entry/type check; bounded copied HL8E import; bounded strict
decoding; all five pure
validation/correlation checks; exact checksum inventory; current asset locks;
parent L7 evidence fingerprint; final-inspection catalog; descriptor
normalization; and both canonical fingerprints succeed. `ResolveDistribution`
may return an L8 descriptor for diagnostics but never a profile or lease.
Synthetic fakes live only in `_test.go` or explicitly fake-only files and have
no production command reachability.

The resolver owns the temporary parent L7 lease immediately after a successful
acquire. It closes that lease exactly once on every later success, validation
failure, panic-recovery, or return path and never places it in the returned L8
distribution. L8 issuance occurs only after parent confirmation and that close
both succeed. A close failure is sanitized, joined with any earlier primary
error without replacing it, and blocks issuance because parent-handle absence
is uncertain.

The opaque value contains one active private seal and the exact
`verifiedL8ProfileCorrelation` above. The policy authority record contains the
four host-only authority bindings plus the measured rootfs image digest; every
member is nonzero. `imageSHA256` is the measured rootfs image digest returned
separately from the evidence fingerprint after no-follow opening
`rootfs.ext4`, not a manifest-only claim. There is no public
digest accessor. `VerifiedL8ProfileMatches` validates and
normalizes the candidate and compares only against the sealed descriptor
fingerprint; the evidence fingerprint is intentionally not caller-readable.
A zero value, copied fields in an external literal, a nil pointer, a generic,
L5, or L7 descriptor, or any descriptor drift fails.

`VerifiedL8ProfileMatchesLease` is the sole profile/lease pair-correlation
check. Under the lease mutex it requires both private seals active, the exact
same evidence fingerprint, constant-time equality of all five private policy
authority fields, and the profile descriptor fingerprint to equal
either the lease's source descriptor fingerprint or its single prepared-
material descriptor fingerprint, as applicable. It never exposes either
fingerprint and performs no path lookup. A profile and lease issued from
different bundles therefore fail even when their public descriptors and asset
locks are byte-identical. The check is required wherever both values cross an
ownership boundary and before every current-asset confirmation.

`AcquireL8AssetLease` pins the opened distribution root plus all seven current
regular files, verifies root/file identity and every digest again, and copies
both private fingerprints plus the complete private policy authority record
from the verified distribution. `ConfirmCurrent`
reopens the current root entries without following links, requires the exact
entry set and retained identities/digests, and accepts only the source
descriptor or its one lease-owned prepared descriptor. Metadata replacement,
parent evidence replacement, inspection replacement, or asset replacement
therefore fails even if a caller preserves the launch descriptor.

Successful `PrepareLaunch` is single-use. It confirms the source before copying, streams
only the pinned kernel and rootfs into an `L8LaunchMaterialWriter`, verifies
size/digest while copying, requires distinct private destinations, normalizes
the prepared descriptor, validates sealed material, and confirms the complete
source bundle again. It then creates a new sealed profile internally whose
descriptor fingerprint is recomputed for the private descriptor and whose
evidence fingerprint, four host-authority bindings, and measured image digest
are copied unchanged from the lease. The evidence fingerprint is copied unchanged while none of the five private authority fields can be reminted. No descriptor-only
constructor is called. After the atomic success transfer, the material and
every pinned source/evidence handle remain lease-owned until idempotent
`Close`; a cleanup error is sanitized and stable across repeated close calls.

Writer ownership is exact. The caller owns a non-nil, non-typed-nil writer on
entry. Any failure from initial correlation/currentness, either ordered
`WriteAsset`, private-path validation, descriptor validation, writer
`Validate`, or the final source confirmation returns zero descriptor/profile
plus a sanitized error and does not call `Close`; failure leaves writer
ownership with the caller.
A failed call does not consume the successful single-use latch;
the caller may retry only with a new writer after closing the failed writer.
Every `L8LaunchMaterialWriter` callback is panic-contained. A `WriteAsset` panic
is a sanitized file-unavailable failure, a `Validate` panic is an asset-lock
mismatch, and a `Close` panic is retained as sanitized cleanup failure while
the lease continues closing every pinned source handle.
The Firecracker caller closes the failed writer exactly once and joins the sanitized
close error with the primary error without replacing it. Only after
all validation and final confirmation succeed does `PrepareLaunch` latch the
material, and success atomically transfers writer ownership to the lease. From
that point only the lease's idempotent `Close` closes it, exactly once; the
caller must not close it. Concurrent attempts serialize on the lease and at
most one success transfers ownership.

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
and both `VerifiedL8ProfileMatches` and `VerifiedL8ProfileMatchesLease` against
the exact descriptor, profile, and lease it uses. Any
failure closes the owned lease and returns a sanitized L8 live-config error.
If the final check after a successful synchronous start handoff fails, Backend
first invokes its exact process stop/reap authority, waits for proved process
absence, closes the lease, and only then returns the sanitized error without a
live handle. Merely closing the asset lease cannot authorize a started process
to remain alive.
Firecracker does not parse a source lock, final-inspection artifact, checksum
file, or label and cannot infer a capability from an image ID.

The explicit D6-to-Firecracker live overlay API is exact and separate from the
existing L7 provider:

```go
type L8LiveBootConfigRequest struct {
	RuntimeGenerationID string `json:"runtimeGenerationId"`
}

type L8LiveBootConfigOverlay struct {
	RuntimeGenerationID string                              `json:"runtimeGenerationId"`
	LaunchDescriptor    *assets.LaunchDescriptor            `json:"-"`
	VerifiedL8Profile   *localresolver.VerifiedL8Profile    `json:"-"`
	VerifiedL8Assets    *localresolver.VerifiedL8AssetLease `json:"-"`
	NetworkMode         microvm.NetworkMode                 `json:"networkMode"`
	NetworkInterfaces   []NetworkInterfaceConfig            `json:"-"`
	StaticNetwork       *StaticNetworkBootConfig            `json:"-"`
	AssetChildFDStart   int                                 `json:"-"`
}

type L8LiveBootConfigProvider interface {
	ProvideL8LiveBootConfig(context.Context, L8LiveBootConfigRequest) (L8LiveBootConfigOverlay, error)
}
```

`BackendOptions` adds `L8LiveConfigProvider L8LiveBootConfigProvider`
immediately after its existing `L7LiveConfigProvider` field, and `Backend`
stores the corresponding private interface immediately after the private L7
field. Because `NewBackend` has no error result, it performs no provider call;
the first explicit live-start validation rejects a nil or typed-nil L8 provider
when L8 is selected and rejects L7 plus L8 providers configured together before
calling either one. Planning-only/default paths remain inert and never call a
provider.

The request contains only the exact safe nonempty runtime generation copied
from the base config. A nil or typed-nil provider is rejected before a call.
The common interface-result matrix applies: on any non-nil provider error the
provider retains ownership of every returned value; nonzero output with error
is a contract violation and Backend uses none of it. On nil error, provisional
ownership of every non-nil lease immediately transfers to Backend before any
field validation; Backend closes it exactly once on every rejection. The
provider must not mutate or access any nil-error output after return. The overlay
must echo the exact runtime generation and contain a non-nil descriptor,
profile, and lease, the exact inherited L7 proxy network mode, exactly one
interface, non-nil static network, and the fixed namespace asset-FD start.
Backend snapshots every caller-mutable safe field before validation: it
deep-copies the interface/static-network metadata and recursively deep-copies
the launch descriptor and every nested slice/pointer while preserving
nil-versus-empty shape, and copies the opaque profile by value into Backend-owned storage.
It validates and uses only those snapshots, calls
`VerifiedL8ProfileMatchesLease`, and confirms current assets before ownership of
the exact non-nil L8 lease transfers to Backend permanently. The earlier
provisional transfer exists solely to make cleanup unambiguous. Backend never
closes a lease on the provider-error path. The overlay cannot replace
executable, jailer, CPU, memory, path, runtime-generation, VSOCK, or lifecycle
fields from the base config. L7 and L8 providers cannot both be configured for
one start.

The host profile never enters the guest. D7 embeds the sole canonical HL8Q
bytes plus only the expected `policyArtifactSHA256` and
`policySourceLockSHA256` in the built guest binaries, alongside the helper,
client, and composition expectations. `WorkloadSnapshotSHA256` and
`RuntimeProfileSHA256` are immutable views derived from that imported HL8Q,
never separately embedded artifacts or authority. The complete binary-binding
set and external HL8E evidence remain host-side; neither
`PolicyBinaryBindingSetSHA256` nor `PinnedCallsiteEvidenceSHA256` enters a guest
protocol or becomes guest-minted authority. PID1 compares authenticated live
process descriptors with the embedded expectations, the guest importer verifies
the embedded HL8Q, and the host separately requires its opaque profile. Neither
side accepts the other's assertion as a substitute, and no host path,
source-lock body, inspection body, opaque profile, binary-binding set, or HL8E
evidence is sent over VSOCK.

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
  descriptor correlation all validate. For L8 it additionally requires the
  host asset manifest's policy-artifact digest to equal the digest independently
  embedded in every locked guest binary, plus the artifact source-lock and
  generator-output identities, and requires a complete external
  pinned-callsite evidence set correlated to the same source lock and exact
  complete per-role/kind final binary/executable-text set. The profile privately
  retains `policyArtifactSHA256`, `policySourceLockSHA256`,
  `policyBinaryBindingSetSHA256`, and `pinnedCallsiteEvidenceSHA256`; sealed
  profile/lease matching compares those four bindings in constant time together
  with the measured image digest. It exposes no digest accessor, digest value,
  rule graph, or evidence record.
  The zero value and external literal are invalid.
  `VerifiedL8ProfileMatches` binds every artifact digest to the exact normalized
  launch descriptor.
- `internal/sandboxruntime/microvm/firecracker` consumes the opaque profile and
  rejects L8 boot material without a matching verified profile. It does not
  parse source locks or infer L8 from a label.
- `firecrackerhost` D6 composition requires that verified profile before
  advertising v2 credential capability. `cmd` may select an already verified
  distribution but cannot mint, weaken, or project the profile.

Production source guards use a per-marker production allowlist: the L8 profile
constant and literal are confined to `assets/build` plus the localresolver
issuer; opaque profile/lease type names are additionally allowed in the exact
Firecracker and firecrackerhost consumers. A separate AST-level issuer identifier guard
rejects every reference to `VerifyL8DistributionBundle` outside localresolver,
including selector, method-value, alias, and call use.

Sequencing is fixed. D2 lands this ownership and red guards. D4 lands the native
role bootstrap, controller, PID1 supervisor, mount monitor, workload shim,
tmpfs, and guest cleanup code
with fake syscall tests but no image claim.
D5 lands guest/host SSH relay code and fake connection tests but no image claim.
D6 lands the explicit production composition, opaque profile requirement, and
worker/runtime cleanup wiring; all defaults remain off. D4/D6 composition
rejects a missing or mismatched `VerifiedPolicyArtifact`. D7 is the only phase
allowed to invoke the local resolver's `VerifiedL8Profile` issuance path. D7 creates and locks
`tools/microvm/l8`, builds twice offline, installs the exact D4/D5/D6 phase-head
binaries plus locked Node 22.22.0 and Pi 0.82.1, source-locks the role FSM,
workload, runtime, catalog, and generator inputs, embeds the sole artifact,
resolves the per-role/kind final-binary pinned callsites, binds the identical
artifact, source-lock, complete binary-set, and evidence-set digests into the
host profile, issues the verified profile,
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
