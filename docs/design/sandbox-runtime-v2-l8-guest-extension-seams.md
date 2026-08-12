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

The four core capability digests are domain-separated SHA-256 values over the
exact request correlation, boot/helper/job generations, and helper boot nonce.
Their constructors are private to `credentialhelper`; D4 receives and echoes
them but cannot mint them. A zero, changed, cross-request, or cross-generation
capability is rejected before a core transition. They are process-local
correlation capabilities, not proof IDs and never enter HL8P or durable state.

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
it as issued in its private one-shot ledger. D4 obtains only value copies through
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
from the service. The service accepts a result only when the capability equals
the exact issued value in constant time, is in the expected transition, and is
still unconsumed. A zero, bit-changed, wrong-kind, cross-request,
cross-generation, or already-consumed capability is a contract violation. A
successful commit, wait, complete cleanup, or inspection consumes the exact
one-shot ledger entry as appropriate; `retry_required` leaves only its cleanup
capability live for the next reinspection and every other capability is dead.
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
and is the authority-bearing correlation checked against the one-shot ledger.

### Core value validation matrices

The constructors apply these exact shape rules before the service performs its
separate one-shot capability, request, generation, expiry, stream-continuity,
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

The CoreOutputResult matrix is exact:

| EOF | Byte count | SHA-256 | Truncated |
| --- | --- | --- | --- |
| false | 1 through `credentialprotocol.MaxHelperExecStreamPayloadBytes` | nonzero and equal to the bytes written to the sink | false only |
| true | exactly 0 | SHA-256 of empty bytes | false or true |

Every other combination is `ContractResultMatrix`. The execution capability is
nonzero and kind is stdout or stderr only. The service additionally requires
execution, kind, offset, capacity, count, digest, and sink write to match the
exact outstanding `CoreOutputRequest`. `truncated=true` is carried only on the
unique EOF result after D4 drains bytes beyond the declared aggregate maximum;
the shape constructor cannot infer that maximum, so the service validates that
fact against its plan ledger.

The CoreExecResult matrix is exact: exit code is 0 through 255 for `exited`,
1 through 64 for `signaled`, and exactly 1 for `setup_failed`, which is a
stable category code rather than a raw errno. Each stdin/stdout/stderr byte
count is at most `credentialprotocol.MaxHelperExecStreamAggregateBytes`; zero
requires the SHA-256 of empty bytes and positive requires a nonzero digest. The
stdin transcript digest and exec transaction digest are always nonzero, because
the unique stdin EOF is committed even when stdin has no payload. Output
truncation booleans are shape-valid independently of the byte count; the service
accepts true only when the matching plan maximum was reached and excess output
was drained. The execution capability is nonzero. Wait is accepted only after
the unique stdout and stderr EOF results, exact input transaction finalization,
and matching service-owned digest/count correlation.

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
stop-VM; retry leaves only that exact cleanup capability live.

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
rejected. `ReadOutput` writes at most that exact capacity into the supplied sink
and `byteCount` must equal the sink write. EOF has count zero and SHA-256 of
empty bytes. `WriteStdin` accepts the already-correlated execution, requires
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
func NewReceivedBootstrapPacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	uint32, uint32, uint32, credentialprotocol.SafeID,
	credentialprotocol.SafeID, ReceivedCapability) (ReceivedPacket, error)
func NewReceivedAgentHelloPacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	[32]byte, credentialprotocol.SafeID, credentialprotocol.SafeID,
	[32]byte) (ReceivedPacket, error)
func NewReceivedPrepareBeginPacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	credentialprotocol.HelperPrepareBeginBody, ManifestCapability) (ReceivedPacket, error)
func NewReceivedPrepareFilePacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	uint64, uint16, uint32, [32]byte) (ReceivedPacket, error)
func NewReceivedPrepareCommitPacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	credentialprotocol.HelperPrepareCommitBody) (ReceivedPacket, error)
func NewReceivedRenewPacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	uint64, int64, credentialprotocol.SafeID) (ReceivedPacket, error)
func NewReceivedRevokePacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	credentialprotocol.HelperRevokeBody) (ReceivedPacket, error)
func NewReceivedExecPacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	uint64, credentialprotocol.SafeID, uint32, [32]byte,
	ExecPlanCapability) (ReceivedPacket, error)
func NewReceivedExecPrivatePacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	uint64, uint32, [32]byte) (ReceivedPacket, error)
func NewReceivedExecStreamPacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	uint64, credentialprotocol.HelperExecStreamKind,
	credentialprotocol.HelperExecStreamFlags, uint64, uint32, [32]byte) (ReceivedPacket, error)
func NewReceivedExecCreditPacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
	ReceivedKernelCredential, uint32, ReceivedBodyCapability, uint32,
	credentialprotocol.HelperExecCreditBody) (ReceivedPacket, error)
func NewReceivedCloseNotifyPacket(ReceiveRequest, credentialprotocol.HelperPacketHeader,
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
`WriteCanonicalBody(credentialmemory.CredentialSink) error`, `RightsCount()
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

Transport calls `WriteCanonicalBody` exactly once for a send. A successful
fill transfers ownership of the exact encoded slot to Transport. Transport
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
codes above. Constructors always return the complete zero value with the exact
error and do not consume an input capability.

The service calls only these transitions:

```text
absent -> BeginPrepare -> staging
staging -> StageFile* in ascending manifest index -> Commit -> prepared
staging -> Rollback -> absent | cleanup-retry | stop-VM
prepared -> Renew -> prepared
prepared -> BeginExec -> executing
executing -> WriteStdin/ReadOutput* -> Wait -> prepared
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
are never formatted. Context cancellation stops the caller wait but ownership
continues under the bounded service cleanup context.

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
has one `Serve` lifetime and one drain path. For a prepare transaction it opens
only the extensions named by the sealed manifest, in manifest order. It calls
`Prepare` only after core file commit exists and before outer helper
publication. The closed manifest contains at most one SSH binding, so the SSH
extension may issue one `create_ssh_endpoint` and cannot create a second
`SSH_AUTH_SOCK`. On failure it
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
