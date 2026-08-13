# Sandbox Runtime v2 L8 Helper Syscall Policy

## Authority and scope

This document closes the D2 syscall-policy architecture left open by
`sandbox-runtime-v2-l8-production-credential-delivery-architecture.md`. That
architecture remains authoritative for protocol, identity, resource, mount,
cgroup, execution, and cleanup semantics. This file narrows those semantics
into one normative Linux amd64 helper policy; it does not expand them.
In particular, the architecture's normative HL8M controller-monitor ABI is the
sole authority for monitor packet bodies, sequences, credentials, rights,
ownership transfer, state/correlation decisions, and digest domains.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.
The policy applies to the single-threaded native `hal-guest-role-bootstrap`,
L8 PID1 launch supervisor, unprivileged service agent,
`hal-guest-credential-helper` controller, per-job
`hal-guest-mount-monitor`, and one-shot `hal-guest-workload-shim`. It does not
replace the frozen L4 workload execution contract or the L7 workload network
policy.

D2 adds no live implementation. In particular, it does not mount, create a
cgroup, launch a process, open a socket, install seccomp, or change a production
command. A platform other than Linux amd64 is unsupported and fails before
helper readiness.

## Closed policy model

The policy is deny-by-default. A syscall is permitted only when its role,
syscall name, scalar arguments, descriptor role, object provenance, and current
state match a rule below. A syscall name appearing in a family is not a general
allow: all stated restrictions remain mandatory.

The roles are `launch-bootstrap`, `launch-base`, `controller-bootstrap`,
`steady-controller`, `agent-bootstrap`, `steady-agent`, `monitor-bootstrap`, `steady-monitor`,
`workload-transition`, and `workload`. The repository baseline contains no
L4/L7 workload seccomp artifact. The `workload` role is therefore
production-constructible only from the mandatory verified snapshot described
below. Transitions are
one-way:

```text
PID1 launch-bootstrap -> launch-base
PID1 launch-base -> controller-bootstrap -> steady-controller
PID1 launch-base -> agent-bootstrap      -> steady-agent
PID1 launch-base -> monitor-bootstrap    -> steady-monitor
PID1 launch-base -> workload-transition -> workload -> execveat
```

Linux seccomp filters are inherited and cannot be relaxed. The native role
bootstrap establishes each role's per-thread capability/identity state before
any Go runtime starts. PID1 then installs the reviewed `launch-base` ancestor
filter, whose allow set is the union mechanically required by its four
image-pinned descendants. Native child modes do not install another filter:
the native bootstrap commits role state, not a child role filter. Each Go child
stacks its narrower role filter before protocol input. The steady controller never launches a
process, and neither does the steady agent; monitors and workload shims are
direct PID1 children and never inherit either steady service filter. A monitor
cannot clone or exec. A workload shim cannot return to PID1 or a service role.
It stacks the policy derived from the verified L4/L7 `WorkloadSnapshot` before
its final exec; an absent or unverified snapshot blocks construction rather
than producing an empty or permissive table.

PID1 is the one explicit launch TCB. Its private authenticated protocol accepts
only create-job, launch-shim, terminate-job, and destroy-job closed records plus
the exact inspected FD matrices below. It accepts no caller path, arbitrary
clone flag, argv, environment, or credential body. There is no unmediated or
general-purpose launcher. An ordinary helper-child inherited-filter design is
nonconforming; no metadata or fake policy result can substitute for the filter
ancestry above.

Every installed filter MUST validate `AUDIT_ARCH_X86_64`, reject the x32
syscall bit, and compare native amd64 syscall numbers. There is no audit-only,
trace, log, or permissive production mode.

## Pure D2 artifact, verifier, and decision ABI

The standard-library-only neutral leaf package is
`internal/sandboxruntime/microvm/guestagent/syscallpolicy`. D2 owns the exact
canonical artifact grammar, pure importer/verifier, immutable copied views,
scalar decision engine, adapter-observation engine, deterministic fixtures,
opacity, and guards. D2 does not author or claim semantic completeness of the
rule rows. D7 is the sole rule-table author and artifact issuer. D4 consumes
the verified rows for filter compilation and implements concrete Linux
observers; D6 composes only an embedded verified artifact. There is no reverse
or live import into this leaf.

### Exact exported catalogs

Zero is invalid. Every validator below returns a redaction-safe
`ContractError`, and every `String` method returns `"unknown"` for zero or an
unknown value.

```go
type Role uint8
const (
    RoleLaunchBootstrap Role = 1; RoleLaunchBase Role = 2
    RoleControllerBootstrap Role = 3; RoleSteadyController Role = 4
    RoleAgentBootstrap Role = 5; RoleSteadyAgent Role = 6
    RoleMonitorBootstrap Role = 7; RoleSteadyMonitor Role = 8
    RoleWorkloadTransition Role = 9; RoleWorkload Role = 10
)
func ValidateRole(Role) error

type Stage uint8
const (
    StageNativeBootstrap Stage = 1; StageGoBootstrap Stage = 2
    StagePreAdmission Stage = 3; StageActive Stage = 4
    StagePreparing Stage = 5; StagePrepared Stage = 6
    StageLaunching Stage = 7; StageRunning Stage = 8
    StageRevoking Stage = 9; StageCleaning Stage = 10
    StageClosed Stage = 11; StageNativePreSetns Stage = 12
    StageNativePostSetns Stage = 13; StageGoPreGate Stage = 14
    StageGoPostGate Stage = 15; StageFinalWorkload Stage = 16
)
func ValidateStage(Stage) error

type StateFact uint64
const (
    StateFactFilterCommitted StateFact = 1 << 0
    StateFactCompositionAccepted StateFact = 1 << 1
    StateFactProtocolInputStarted StateFact = 1 << 2
    StateFactAgentAttested StateFact = 1 << 3
    StateFactJobOwned StateFact = 1 << 4
    StateFactMonitorReady StateFact = 1 << 5
    StateFactPrepared StateFact = 1 << 6
    StateFactUmaskCommitted StateFact = 1 << 7
    StateFactGateReleased StateFact = 1 << 8
    StateFactIdentityDropped StateFact = 1 << 9
    StateFactWorkloadFilterCommitted StateFact = 1 << 10
    StateFactCleanupStarted StateFact = 1 << 11
    StateFactClosed StateFact = 1 << 12
)
func ValidateStateFacts(StateFact) error

type Action uint32
const (
    ActionKillProcess Action = 0x80000000
    ActionErrnoEPERM Action = 0x00050001
    ActionAllow Action = 0x7fff0000
)
func ValidateAction(Action) error

type Reason uint8
const (
    ReasonExactRule Reason = 1; ReasonForeignArchitecture Reason = 2
    ReasonX32Encoding Reason = 3; ReasonUnknownSyscall Reason = 4
    ReasonForbiddenAuthority Reason = 5; ReasonForbiddenSocketFamily Reason = 6
    ReasonArbitraryNamespace Reason = 7; ReasonImpossibleTransition Reason = 8
    ReasonKnownUnlisted Reason = 9; ReasonWrongRole Reason = 10
    ReasonStateMismatch Reason = 11; ReasonScalarMismatch Reason = 12
    ReasonFDMismatch Reason = 13
)
func ValidateReason(Reason) error

type DescriptorKind uint8
const (
    DescriptorKindInert DescriptorKind = 1; DescriptorKindRegular DescriptorKind = 2
    DescriptorKindDirectory DescriptorKind = 3; DescriptorKindPipeRead DescriptorKind = 4
    DescriptorKindPipeWrite DescriptorKind = 5; DescriptorKindPIDFD DescriptorKind = 6
    DescriptorKindMount DescriptorKind = 7; DescriptorKindFSContext DescriptorKind = 8
    DescriptorKindUnixConnected DescriptorKind = 9; DescriptorKindUnixListening DescriptorKind = 10
    DescriptorKindVSOCKConnected DescriptorKind = 11; DescriptorKindVSOCKListening DescriptorKind = 12
    DescriptorKindSeqpacket DescriptorKind = 13; DescriptorKindNamespace DescriptorKind = 14
    DescriptorKindExecutable DescriptorKind = 15; DescriptorKindSealedConfig DescriptorKind = 16
    DescriptorKindCgroupRoot DescriptorKind = 17; DescriptorKindCgroupLeaf DescriptorKind = 18
    DescriptorKindProcRoot DescriptorKind = 19; DescriptorKindMountTarget DescriptorKind = 20
    DescriptorKindGateRead DescriptorKind = 21
)
func ValidateDescriptorKind(DescriptorKind) error

type DescriptorAccess uint8
const (
    DescriptorAccessRead DescriptorAccess = 1; DescriptorAccessWrite DescriptorAccess = 2
    DescriptorAccessReadWrite DescriptorAccess = 3; DescriptorAccessOPath DescriptorAccess = 4
    DescriptorAccessExecute DescriptorAccess = 5
)
func ValidateDescriptorAccess(DescriptorAccess) error

type Check uint8
const (
    CheckBoundedPointer Check = 1; CheckImmutablePointer Check = 2
    CheckReservedZero Check = 3; CheckCanonicalPath Check = 4
    CheckContainedBeneath Check = 5; CheckFDKind Check = 6
    CheckFDAccess Check = 7; CheckFDGeneration Check = 8
    CheckObjectIdentity Check = 9; CheckMountIdentity Check = 10
    CheckNamespaceIdentity Check = 11; CheckCgroupIdentity Check = 12
    CheckSocketIdentity Check = 13; CheckAncillaryShape Check = 14
    CheckProcessIdentity Check = 15; CheckRuntimeMapping Check = 16
    CheckOutputBounds Check = 17; CheckPostSuccessReinspection Check = 18
    CheckFixedArgvEnv Check = 19; CheckCompiledConstant Check = 20
)
func ValidateCheck(Check) error
```

`CheckSet` has private `uint32` bits. `NewCheckSet(checks ...Check)
(CheckSet, error)` rejects duplicate/unknown checks; `Contains(Check) bool` and
`Values() []Check` return deterministic ascending values.

`PointerClass` is a `uint8`: `PointerClassNone=1`,
`PointerClassFixedImage=2`, `PointerClassBoundedMutable=3`,
`PointerClassBoundedReadOnly=4`, `PointerClassRuntimeStack=5`,
`PointerClassRuntimeTLS=6`, `PointerClassCanonicalRelativePath=7`,
`PointerClassCompiledPath=8`, `PointerClassOpenHow=9`,
`PointerClassCloneArgs=10`, `PointerClassMessageHeader=11`,
`PointerClassSocketAddress=12`, `PointerClassMountAttributes=13`,
`PointerClassCapabilityData=14`, `PointerClassSeccompProgram=15`,
`PointerClassArgvEnv=16`, `PointerClassTimespec=17`, and
`PointerClassSignalSet=18`. `ValidatePointerClass` is exact.

`AdapterOutcome` is a `uint8`: `AdapterOutcomeProceed=1`,
`AdapterOutcomeRejectCleanup=2`, `AdapterOutcomeStopVM=3`.
`AdapterReason` is a `uint8`: `AdapterReasonExact=1`,
`AdapterReasonStateMismatch=2`, `AdapterReasonFDMismatch=3`,
`AdapterReasonPointerMismatch=4`, `AdapterReasonObjectMismatch=5`, and
`AdapterReasonObserverFailure=6`, `AdapterReasonSyscallFailure=7`, and
`AdapterReasonPreSyscallAbort=8`.
`AdapterPhase` is a `uint8`: `AdapterPhasePre=1` and `AdapterPhasePost=2`.
`ValidateAdapterOutcome`, `ValidateAdapterReason`, and `ValidateAdapterPhase`
reject every other value. The safe string token for
`AdapterReasonPreSyscallAbort` is exactly `pre-syscall-abort`.

`ErrorCode` is a `uint8`: `ErrorCodeInvalidArgument=1`,
`ErrorCodeTypedNil=2`, `ErrorCodeBounds=3`, `ErrorCodeDigestMismatch=4`,
`ErrorCodeEncoding=5`, `ErrorCodeCatalog=6`, `ErrorCodeMissingSection=7`,
`ErrorCodeDuplicate=8`, `ErrorCodeContradiction=9`,
`ErrorCodeUnsafeWidening=10`, `ErrorCodeFatalAllow=11`,
`ErrorCodeInvalidAncestry=12`, `ErrorCodeObservation=13`,
`ErrorCodeOwnership=14`, and `ErrorCodeTransition=15`.
`ValidateErrorCode` is exact. `type ContractError struct { code ErrorCode }`
has one private `ErrorCode` and
implements `Error`, `Is`, and `Code`; it contains no dynamic input.
`Error()` is exactly `"syscall policy contract rejected: " + code.String()`;
`Code() ErrorCode` returns the value; `Is(target error) bool` is true only for
a nonnil `*ContractError` with the same code. A nil receiver returns the fixed
invalid-argument string, zero, and false respectively. There is no unwrap.

### Canonical D7-issued artifact

There is one artifact, not independently assembled D2 tables:

```go
const (
    MaxVerifiedPolicyArtifactBytes = 4194304
    MaxPolicyCatalogEntries = 512
    MaxPolicyRules = 8192
    MaxPolicyRulesPerRole = 2048
    MaxPolicyStagesPerRole = 16
    MaxPolicyTransitionsPerRole = 64
    MaxPolicyScalarClausesPerRule = 6
    MaxPolicyDescriptorRequirementsPerRule = 6
    MaxPolicyPointerRequirementsPerRule = 6
    MaxPolicyObjectRequirementsPerRule = 6
    MaxPinnedCallsiteRequirementsPerRule = 6
    MaxPinnedCallsiteEvidenceBytes = 16777216
    MaxPinnedCallsiteEvidenceRecords = 49152
    MaxPinnedBinaryBindings = 32
    MaxPolicyScalarValuesPerClause = 8
    MaxPolicyNameBytes = 64
    MaxScalarPredicateSearchStates = 4194304
    MaxAdapterBindings = 32
)

type ExpectedPolicyArtifact struct { sha256 [32]byte; issuer expectedIssuer }
type VerifiedPolicyArtifact struct { sha256 [32]byte; artifact *verifiedArtifact }
type WorkloadSnapshot struct { sha256, sourceLock, l4, l7 [32]byte; rules []WorkloadRuleView }
type WorkloadRuleView struct { rule RuleView }
type RuntimeProfileView struct { goVersion string; sha256, source, sourceLock [32]byte; rules []RuleView }
type CatalogEntryView struct { entry *catalogEntry }
type RuleView struct { rule *verifiedRule }
type ScalarClauseView struct { clause *scalarClause }
type DescriptorRequirementView struct { requirement *descriptorRequirement }
type PointerRequirementView struct { requirement *pointerRequirement }
type ObjectRequirementView struct { requirement *objectRequirement }
type TransitionView struct { transition *verifiedTransition }
type FilterRuleView struct { rule *filterRule }
type FilterProfile struct { profile *filterProfile }
type FilterDecision struct { action Action; reason Reason; ruleSHA256 [32]byte }
type PinnedCallsiteRequirementView struct { requirement *pinnedCallsiteRequirement }
type PinnedBinaryBindingView struct { binding *pinnedBinaryBinding }
type PinnedBinaryBindingSet struct { sha256 [32]byte; bindings []PinnedBinaryBindingView; owner *evidenceOwner }
type PinnedCallsiteEvidenceView struct { evidence *pinnedCallsiteEvidence }
type ExpectedPinnedCallsiteEvidence struct { sha256 [32]byte; issuer expectedEvidenceIssuer }
type PinnedCallsiteEvidenceSet struct {
    sha256, artifactSHA256, sourceLockSHA256 [32]byte
    binaries PinnedBinaryBindingSet
    evidence []PinnedCallsiteEvidenceView
    owner *evidenceOwner
}

func ImportPinnedCallsiteEvidence(encoded []byte, artifact VerifiedPolicyArtifact, expected ExpectedPinnedCallsiteEvidence) (PinnedCallsiteEvidenceSet, error)
func EmbeddedExpectedPinnedCallsiteEvidence() (ExpectedPinnedCallsiteEvidence, error)

func ImportVerifiedPolicyArtifact(encoded []byte, expected ExpectedPolicyArtifact) (VerifiedPolicyArtifact, error)
func EmbeddedVerifiedPolicyArtifact() (VerifiedPolicyArtifact, error)
```

These are the exact exported layouts; the pointed-to types are package-private,
deep-copied during import, never returned, and have no mutator. A zero or nil
private pointer makes the value invalid. `WorkloadSnapshot` and
`RuntimeProfileView` are constructed only while importing that copied graph;
callers receive copies whose slice accessors allocate fresh backing arrays.

`ExpectedPolicyArtifact` has no exported constructor. Its zero value is
invalid. Default D2 source is compiled under `!l8_verified_policy_artifact` and
`EmbeddedVerifiedPolicyArtifact` returns `ErrorCodeMissingSection`. D7 alone
generates `artifact_expected_d7_gen.go` under build tag
`l8_verified_policy_artifact`; that file contains the bounded canonical bytes,
their nonzero expected digest, and the private issuer marker. D4/D6 cannot mint
the marker. Package-internal tests use a `_test.go` issuer only.

`ExpectedPinnedCallsiteEvidence` likewise has no exported constructor and its
zero value is invalid. Default source is compiled under
`!l8_verified_pinned_callsite_evidence` and
`EmbeddedExpectedPinnedCallsiteEvidence` returns `ErrorCodeMissingSection`.
D7's host-only generated sibling is compiled under
`l8_verified_pinned_callsite_evidence`, contains only the expected nonzero HL8E
digest and private issuer marker, and is excluded from every guest binary.

The exact artifact digest is
`SHA256(u16be(len(domain)) || domain || canonicalArtifactBytes)`, where domain
is `hal/l8/verified-syscall-policy/linux-amd64/v1`. A rule fingerprint uses the
same framing with `hal/l8/syscall-rule/linux-amd64/v1` and one complete
canonical rule. A role fingerprint uses
`hal/l8/syscall-role/linux-amd64/v1` and the complete canonical role section.
All multibyte values are big-endian.

The artifact envelope and section order are exact:

```text
magic[4] = "HL8Q" | version:u8=1 | abi:u8=1 | reserved:u16=0
kernelMajor:u16=6 | kernelMinor:u16=1 | kernelPatch:u16=178
sectionCount:u16=6 | bodyLength:u32
catalogSourceSHA256:[32]byte | sourceLockSHA256:[32]byte
sections in type order 1..6:
  type:u8 | reserved:u8=0 | itemCount:u16 | byteLength:u32
  sectionSHA256:[32]byte | body:byteLength bytes
```

The six required sections are: `1 catalog`, `2 roles`, `3 ancestry`,
`4 workload`, `5 runtime`, and `6 provenance`. Each section digest is
SHA-256 of its body without a domain. Both header digests and every section
digest are nonzero. Total bytes include the header and may not exceed
`MaxVerifiedPolicyArtifactBytes`; every count also satisfies the constants
above. No optional or unknown section exists.

The header `sourceLockSHA256` is not an unexplained issuer label. The
provenance section supplies its exact preimage: eight nonzero digests in this
order, `phaseHeadSourceSHA256`, `roleFSMSourceSHA256`,
`workloadInputLockSHA256`, `runtimeSourceLockSHA256`,
`catalogSourceLockSHA256`, `generatorSourceSHA256`,
`generatorExecutableSHA256`, and `guestToolchainSHA256`. The value is
`SHA256(u16be(len(domain)) || domain || those 8*32 bytes)`, with domain
`hal/l8/verified-policy-source-lock/linux-amd64/v1`. D2 recomputes it before
accepting the artifact. No artifact digest, generated artifact bytes, guest
binary digest, or pinned-callsite evidence digest enters this preimage, so the
lock is cycle-free. `VerifiedPolicyArtifact.SourceLockSHA256()` returns this
exact header value.

The catalog body begins
`moduleNameLength:u8, sourcePathLength:u8, reserved:u16=0,
kernelCeiling:u32, moduleName:ASCII, sourcePath:ASCII`, followed by the section
header's `itemCount` ascending unique records
`number:u32, class:u8, nameLength:u8, mandatoryEvidenceCount:u8,
reserved:u8=0, name:ASCII`, followed by that many mandatory-evidence records
`evidenceKind:u8, reserved:u8=0, attachmentIndex:u16, requiredChecks:u32`.
The module and path are exactly
`golang.org/x/sys@v0.41.0` and `unix/zsysnum_linux_amd64.go`; the source
SHA-256 is
`d12bc509fbe79afd804a66297c7517076eea6f3c8d82780630cd07f561b043b6`,
and kernel ceiling:u32=450. Module/path lengths are their exact byte lengths;
names match `^[a-z][a-z0-9_]{0,63}$`. D7 derives the catalog from that pinned module source, never
host headers, including every and only `SYS_*` assignment whose number is at
most 450 and converting its suffix to lowercase. Constants above 450 are source
evidence for the closed ceiling but are not catalog rows. D2 verifies grammar, order, uniqueness, bounds, source identity,
and that every rule number has exactly one catalog row; D2 does not claim a
pre-D7 catalog row count or output digest.

```go
type SyscallNumber uint32
type SyscallClass uint8
type EvidenceKind uint8
type MandatoryEvidenceView struct { evidence *mandatoryEvidence }
const (
    SyscallClassOrdinary SyscallClass = 1
    SyscallClassFatal SyscallClass = 2
    SyscallClassConditional SyscallClass = 3
)
func ValidateSyscallClass(SyscallClass) error
func ValidateEvidenceKind(EvidenceKind) error
```

`CatalogEntryView` accessors are `Number() SyscallNumber`, `Name() string`,
`Class() SyscallClass`, and `MandatoryEvidence() []MandatoryEvidenceView`. A
fatal row has zero mandatory evidence and can never be referenced by a rule. An
ordinary row has zero mandatory evidence. A conditional row has one or more
mandatory-evidence records. `EvidenceKindState=1`, `EvidenceKindDescriptor=2`,
`EvidenceKindPointer=3`, `EvidenceKindArgumentObject=4`,
`EvidenceKindReturnObject=5`, and `EvidenceKindPinnedCallsite=6` are exact.
State index is zero; descriptor/pointer/argument-object index is 0..5; return
object index is 255; pinned index is its callsite ordinal. Records sort by kind
then index and are unique. Each rule for the syscall must have the exact named
attachment and that single attachment's checks must cover the complete record.
A check cannot be split across attachments or substituted by another evidence
kind. A class/check contradiction, conditional row without evidence, or rule
that omits one is an unsafe conditional syscall and returns
`ErrorCodeUnsafeWidening`; a rule referencing a fatal row returns
`ErrorCodeFatalAllow`.

D2 deliberately does not carry a second semantic name/class table. D7 derives
every number/name pair from the pinned x/sys source and authors the reviewed
fatal/conditional/ordinary classification in the sole artifact. The expected
issuer marker binds that review. D2 can verify source identity, number/name
grammar, ceiling, ordering, class/check consistency, and rule references, but
cannot claim the class assignment is semantically complete independently of
D7.

```go
type RuleOrigin uint8
const (
    RuleOriginRole RuleOrigin = 1
    RuleOriginWorkload RuleOrigin = 2
    RuleOriginRuntime RuleOrigin = 3
)
func ValidateRuleOrigin(RuleOrigin) error

type ScalarOperation uint8
const (
    ScalarEqual ScalarOperation = 1
    ScalarMaskedEqual ScalarOperation = 2
    ScalarOneOf ScalarOperation = 3
    ScalarUnsignedRange ScalarOperation = 4
    ScalarZero ScalarOperation = 5
    ScalarNonzero ScalarOperation = 6
)
func ValidateScalarOperation(ScalarOperation) error

type ObjectSource uint8
const (
    ObjectSourceArgument ObjectSource = 1
    ObjectSourceReturn ObjectSource = 2
)
func ValidateObjectSource(ObjectSource) error

type QueryKind uint8
const (
    QueryKindState QueryKind = 1
    QueryKindFD QueryKind = 2
    QueryKindPointer QueryKind = 3
    QueryKindObject QueryKind = 4
)
func ValidateQueryKind(QueryKind) error

type EnforcementPath uint8
const (
    EnforcementPathDirect EnforcementPath = 1
    EnforcementPathAdapter EnforcementPath = 2
    EnforcementPathPinnedDirect EnforcementPath = 3
)
func ValidateEnforcementPath(EnforcementPath) error

type GenerationMode uint8
const (
    GenerationModeStaticExact GenerationMode = 1
    GenerationModeLiveBound GenerationMode = 2
    GenerationModeFreshReturn GenerationMode = 3
)
func ValidateGenerationMode(GenerationMode) error
```

The roles section header has `itemCount=10`. Its body contains exactly ten
ascending role sections. Each begins
`role:u8, stageCount:u8, transitionCount:u16, ruleCount:u32`, followed by
ascending unique stages, transitions, and canonical rules. A stage row is `stage:u8, reserved:[7]byte,
requiredFacts:u64, prohibitedFacts:u64`; required/prohibited bits must be
known and disjoint. A transition row is `fromStage:u8, toRole:u8, toStage:u8,
reserved:u8=0, requiredFacts:u64, prohibitedFacts:u64, setFacts:u64,
clearFacts:u64`; all masks are known, required/prohibited and set/clear are
pairwise disjoint, and it cannot self-loop. The enclosing role is the from-role. The artifact contains the exact one-way cross-role graph in
the closed policy model above and D7's complete within-role FSM; D2 rejects a missing/extra
cross-role edge and any within-role cycle. A canonical rule is:

```text
role:u8 | stage:u8 | origin:u8 | enforcementPath:u8 | adapterFailure:u8
pinnedCallsiteCount:u8 | reserved:u16=0
requiredFacts:u64 | prohibitedFacts:u64 | syscallNumber:u32
stateCheckBits:u32
scalarClauseCount:u8 | descriptorRequirementCount:u8
pointerRequirementCount:u8 | objectRequirementCount:u8
scalar clauses, descriptor requirements, pointer requirements, object
requirements, then pinned-callsite requirements
```

One scalar clause is `argumentIndex:u8, operation:u8, valueCount:u8,
reserved:u8=0, mismatchAction:u32, mismatchReason:u8, reserved:[3]byte,
mask:u64, values:[8]u64`; unused values are zero. `mismatchAction` is exactly
`ActionKillProcess` or `ActionErrnoEPERM`, never allow, and its reason is a
known non-exact denial reason; scalar argument indexes are unique within a rule,
so at most six clauses exist. `ScalarEqual` has count one and zero mask;
`ScalarMaskedEqual` has count one, nonzero mask, and its canonical value has no
bits outside the mask; `ScalarOneOf` has count
2..8, zero mask, and strictly ascending unique values; `ScalarUnsignedRange`
has count two, zero mask, and low <= high; `ScalarZero` and `ScalarNonzero`
have count zero, zero mask, and all-zero values.

One descriptor requirement is
`argumentIndex:u8, kind:u8, access:u8, fixed:u8, generationMode:u8,
bindingSlot:u8, reserved:u16=0, requiredChecks:u32,
generationSHA256:[32]byte`. One pointer requirement is `argumentIndex:u8, class:u8,
reserved:u16=0, minimumBytes:u32, maximumBytes:u32, requiredChecks:u32`;
`1 <= minimumBytes <= maximumBytes <= 1048576`. One object requirement is
`source:u8, argumentIndex:u8, kind:u8, access:u8, fixed:u8,
generationMode:u8, bindingSlot:u8, reserved:u8=0, requiredChecks:u32,
generationSHA256:[32]byte`. Fixed bits are zero or one. Argument indexes are
0..5; argument indexes within each requirement family are unique and every
requirement has a nonempty known check set appropriate to its kind.
There are no free-floating `preCheckBits` or `postCheckBits`. Every `Check` bit
is attached to exactly one state, descriptor, pointer, or object requirement
and is proved only by that requirement's bound observation. A repeated check
across requirements must be proved separately for each query; no global bit
can satisfy it.

#### Check admissibility and mandatory matrix

Each row below is exact: `mandatory` bits must all be present, `additional`
bits are the only optional bits, and every other bit is category-inappropriate.
Import and observation constructors reject missing mandatory, extra, or
inappropriate bits. No check bit is fungible across rows or requirements.

| Evidence kind | Mandatory | Additional allowed |
|---|---|---|
| state | `ProcessIdentity` | `RuntimeMapping`, `CompiledConstant` |
| descriptor `Inert`, `PipeRead`, `PipeWrite`, `GateRead` | `FDKind,FDAccess,FDGeneration` | none |
| descriptor `Regular`, `Directory`, `Executable`, `SealedConfig`, `ProcRoot` | `FDKind,FDAccess,FDGeneration,ObjectIdentity` | `ContainedBeneath` for `Regular`/`Directory`/`ProcRoot` only |
| descriptor `PIDFD` | `FDKind,FDAccess,FDGeneration,ProcessIdentity` | none |
| descriptor `Mount`, `FSContext`, `MountTarget` | `FDKind,FDAccess,FDGeneration,MountIdentity` | `ObjectIdentity` |
| descriptor `UnixConnected`, `UnixListening`, `VSOCKConnected`, `VSOCKListening` | `FDKind,FDAccess,FDGeneration,SocketIdentity` | none |
| descriptor `Seqpacket` | `FDKind,FDAccess,FDGeneration,SocketIdentity` | `AncillaryShape` |
| descriptor `Namespace` | `FDKind,FDAccess,FDGeneration,NamespaceIdentity` | none |
| descriptor `CgroupRoot`, `CgroupLeaf` | `FDKind,FDAccess,FDGeneration,CgroupIdentity` | `ContainedBeneath` |
| pointer `None` | invalid requirement | none |
| pointer `FixedImage` | `BoundedPointer,ImmutablePointer,CompiledConstant` | none |
| pointer `BoundedMutable` | `BoundedPointer,OutputBounds` | `ReservedZero` |
| pointer `BoundedReadOnly` | `BoundedPointer,ImmutablePointer` | `ReservedZero` |
| pointer `RuntimeStack`, `RuntimeTLS` | `BoundedPointer,RuntimeMapping` | `ImmutablePointer` |
| pointer `CanonicalRelativePath` | `BoundedPointer,ImmutablePointer,CanonicalPath,ContainedBeneath` | none |
| pointer `CompiledPath` | `BoundedPointer,ImmutablePointer,CanonicalPath,CompiledConstant` | `ContainedBeneath` |
| pointer `OpenHow`, `CloneArgs`, `MountAttributes` | `BoundedPointer,ImmutablePointer,ReservedZero` | `CompiledConstant` |
| pointer `MessageHeader` | `BoundedPointer,ImmutablePointer,ReservedZero,AncillaryShape` | `OutputBounds` |
| pointer `SocketAddress` | `BoundedPointer,ImmutablePointer,ReservedZero,SocketIdentity` | `OutputBounds` |
| pointer `CapabilityData` | `BoundedPointer,ImmutablePointer,ReservedZero,ProcessIdentity` | none |
| pointer `SeccompProgram` | `BoundedPointer,ImmutablePointer,ReservedZero,CompiledConstant` | none |
| pointer `ArgvEnv` | `BoundedPointer,ImmutablePointer,FixedArgvEnv` | `CompiledConstant` |
| pointer `Timespec`, `SignalSet` | `BoundedPointer,ImmutablePointer,ReservedZero` | none |
| argument object, every descriptor kind | descriptor row's mandatory/allowed set plus mandatory `ObjectIdentity` | only that descriptor row's additional bits |
| return object, every descriptor kind | argument-object row plus mandatory `PostSuccessReinspection` | only that descriptor row's additional bits; `OutputBounds` is forbidden |
| pinned native callsite | `CompiledConstant` | none |
| pinned Go-runtime callsite | `CompiledConstant,RuntimeMapping` | none |

An argument/return object's descriptor-kind row is selected by its exact
`DescriptorKind`; adding `ObjectIdentity` or post reinspection never authorizes
a bit excluded by that row. A catalog mandatory-evidence record is checked
against its exact attachment only after this matrix passes, so descriptor
evidence cannot satisfy pointer evidence, one FD cannot satisfy another, and a
pinned proof cannot replace a live adapter observation.
`CheckOutputBounds` belongs only to a bounded pointer requirement and its
pointer observation. It is category-inappropriate for descriptor and object
requirements, including returned objects; returned-object metadata has no byte
count field on which that check could operate.
For every descriptor requirement and `ObjectSourceArgument` requirement, the scalar clause on the same
argument must accept only values in `0..math.MaxInt32`; range and one-of values
above that ceiling and masked/nonzero clauses that could admit one are invalid.
The verifier proves the subset with the same exact predicate search against
`[math.MaxInt32+1, math.MaxUint64]`; any intersection rejects the artifact, so a
full-mask `ScalarMaskedEqual` may pass while a partially constrained high word
cannot.
A descriptor with `fixed=true` additionally requires one `ScalarEqual` clause naming its exact fixed descriptor number. For `ObjectSourceArgument`, the same
width rule applies and `fixed=true` likewise requires `ScalarEqual`; this
prevents any uint64-to-int32 narrowing. `ObjectSourceReturn` uses the exact
sentinel `argumentIndex=255`, has no input-scalar clause or narrowing, and
binds only the post-syscall object's kind/access/generation/fixed identity.
Any other source/index pairing is `ErrorCodeEncoding`. This explicit return
source is the chosen object-identity model; D2 never treats a returned FD as an input argument.

Generation encoding is exact. `GenerationModeStaticExact` requires a nonzero
artifact generation digest and `bindingSlot=0`; it is used for image/static
objects only. `GenerationModeLiveBound` requires an all-zero artifact digest
and `bindingSlot` 1..32; it is valid only for descriptor or argument-object
requirements and resolves through the operation-scoped binding snapshot below.
`GenerationModeFreshReturn` requires an all-zero artifact digest and slot zero;
it is valid only for `ObjectSourceReturn`. Any other combination rejects with
`ErrorCodeEncoding`. Static-exact observations equal the artifact digest;
live-bound observations equal the permit-copied binding generation; fresh-return
observations carry a nonzero D4-minted generation not present before the call.

A pinned-callsite requirement is distinct from every live pointer observation:

```text
callsiteOrdinal:u16 | pointerClass:u8 | reserved:u8=0
minimumBytes:u32 | maximumBytes:u32 | requiredChecks:u32
instructionLength:u16 | reserved:u16=0
sourceUnitSHA256:[32]byte | argumentTemplateSHA256:[32]byte
instructionTemplateSHA256:[32]byte | toolchainSHA256:[32]byte
```

Ordinals are ascending and unique; all four digests are nonzero; byte bounds
follow the pointer bounds; instruction length is 1..4096; and toolchain digest
equals the source lock's `guestToolchainSHA256`. Its fingerprint uses domain
`hal/l8/pinned-callsite/linux-amd64/v1` and the complete record. It represents
one source-locked compiler/native callsite with fixed pointer provenance, never
a runtime observation or caller pointer.

The binary binding catalog is exact:

```go
type BinaryBindingKind uint8
const (
    BinaryBindingKindNativeBootstrap BinaryBindingKind = 1
    BinaryBindingKindPinnedGoRuntime BinaryBindingKind = 2
)
func ValidateBinaryBindingKind(BinaryBindingKind) error
```

One canonical binary binding record is:

```text
role:u8 | binaryKind:u8 | reserved:u16=0 | textLength:u64
sourceLockSHA256:[32]byte | toolchainSHA256:[32]byte
binarySHA256:[32]byte | executableTextSHA256:[32]byte
```

All four digests and text length are nonzero. The source lock equals the
artifact header and the toolchain equals the pinned requirement. Its digest is
`SHA256(u16be(len(domain)) || domain || completeRecord)` with domain
`hal/l8/pinned-binary-binding/linux-amd64/v1`. The canonical binding set
contains exactly one record for every unique `(role,binaryKind)` referenced by
a pinned requirement: `RuleOriginRole` selects native-bootstrap and
`RuleOriginRuntime` selects pinned-Go-runtime. Records sort by role then kind;
missing, extra, duplicate, or reordered records reject. The set digest uses
domain `hal/l8/pinned-binary-binding-set/linux-amd64/v1` and exact preimage
`bindingCount:u16 || reserved:u16=0 || completeCanonicalRecords`.

D7 supplies this exact matching external evidence record:

```text
callsiteSHA256:[32]byte | binaryBindingSHA256:[32]byte
observedInstructionSHA256:[32]byte | instructionOffset:u64
```

The callsite digest is the requirement fingerprint; binding digest selects the
one exact role/kind record; observed instruction digest is nonzero and equals
the requirement's instruction-template digest; and checked addition proves
`instructionOffset + instructionLength <= binding.TextLength()`. A record
digest is exactly `SHA256(u16be(len(domain)) || domain || completeRecord)` with
domain `hal/l8/pinned-callsite-evidence-record/linux-amd64/v1`.
`PinnedCallsiteEvidenceView.SHA256()` returns exactly that record digest and has
no alternate preimage, implicit binary lookup field, or host-dependent byte.

The external evidence envelope is:

```text
magic[4]="HL8E" | version:u8=1 | reserved:u8=0
binaryBindingCount:u16 | evidenceCount:u16 | reserved:u16=0
artifactSHA256:[32]byte | sourceLockSHA256:[32]byte
binaryBindingSetSHA256:[32]byte
complete canonical binary-binding records, then canonical evidence records
```

Evidence records sort by callsite digest then binary-binding digest then
instruction offset; missing, extra, duplicate, or reordered records reject.
The complete envelope digest is
`SHA256(u16be(len(domain)) || domain || completeCanonicalEnvelope)` with domain
`hal/l8/pinned-callsite-evidence/linux-amd64/v1`. The expected evidence
type has no public constructor; D7 generates its host-only private issuer only
after the final binary exists. Import requires the exact verified artifact,
nonzero expected digest, the exact complete expected per-role/kind binding set,
one evidence record per pinned requirement and no extra, the equalities and
bounds above, and unique callsite/binding/offset tuples. It recomputes every
record/set/envelope digest and copies all bytes. D7's source-locked resolver
hashes every complete final role binary and its executable text, identifies the
approved symbol and callsite in the record selected by role and kind, hashes
exactly the instruction-length bytes at the recorded offset, and emits the
evidence only when those bytes equal the source-derived instruction template.
This external form deliberately avoids embedding the final binary or text
digest inside that same binary. The binary-binding-set digest is recorded as
`policyBinaryBindingSetSHA256`; both that digest and the evidence-set digest
are bound into the D7 image manifest, host asset manifest, and
`VerifiedL8Profile`. The guest binds the artifact and requirements, while the
host independently binds the exact complete binary set and final evidence.
Encoded evidence is nonempty and at most
`MaxPinnedCallsiteEvidenceBytes`; binary-binding count is nonzero and at most
`MaxPinnedBinaryBindings`, and evidence count is nonzero and at most
`MaxPinnedCallsiteEvidenceRecords`. Its importer failure precedence is expected
marker/digest then artifact ownership, byte/count bounds, envelope/record
digest mismatch, encoding/order/reserved grammar, catalog/enum validation,
duplicate tuple, and artifact/source-lock/callsite contradiction. The exact
codes are respectively `ErrorCodeOwnership`, `ErrorCodeOwnership`,
`ErrorCodeBounds`, `ErrorCodeDigestMismatch`, `ErrorCodeEncoding`,
`ErrorCodeCatalog`, `ErrorCodeDuplicate`, and `ErrorCodeContradiction`.
`CheckPostSuccessReinspection` is valid only on `ObjectSourceReturn` and is
mandatory there; it is invalid on state, FD, pointer, or argument-object
requirements. A rule with no return object has no post query and must finalize
only through `CommitNoObject`; D2 does not invent a post observation or live
call for it.

An `EnforcementPathDirect` row has zero required/prohibited facts, zero state
checks, no descriptor/pointer/object/pinned-callsite requirements, and
`adapterFailure=AdapterOutcomeProceed`. Its stage is provenance grouping only;
`Policy.Decide` treats it as all-stage and D7 must review its scalar authority
as safe for the entire effective role lifetime. An `EnforcementPathAdapter` row
always performs the bound state query even when its fact masks are zero and has
failure outcome reject-cleanup or stop-VM. Every rule whose stage or facts are
materially narrower than its effective role lifetime must be adapter-gated.
D2 rejects a narrowed direct row structurally; D7 issuance additionally proves
by call-graph/source guards that every adapter row reaches the sole D4 adapter
and has no raw-syscall bypass. `Policy.Decide` wrong-state results for adapter
rows are oracle/golden evidence for that adapter boundary, never a claim that
raw seccomp BPF observes stage or facts.
Within one effective `FilterProfile`, a direct row may not overlap any adapter
row for the same syscall under the exact scalar intersection proof, including
identical filter bytes. Otherwise the direct call site could exercise
adapter-scoped authority and import rejects `ErrorCodeUnsafeWidening`.

`EnforcementPathPinnedDirect` is the only non-adapter pointer path. It is valid
only for `RuleOriginRole` in exactly `RoleLaunchBootstrap`,
`RoleControllerBootstrap`, `RoleAgentBootstrap`, `RoleMonitorBootstrap`, or
`RoleWorkloadTransition`; those five roles select
`BinaryBindingKindNativeBootstrap`. It is valid for `RuleOriginRuntime` in
exactly `RoleLaunchBase`, `RoleControllerBootstrap`, `RoleSteadyController`,
`RoleAgentBootstrap`, `RoleSteadyAgent`, `RoleMonitorBootstrap`,
`RoleSteadyMonitor`, or `RoleWorkloadTransition`. It is invalid for
`RoleWorkload`. Its catalog row is ordinary, or conditional with an exact
`EvidenceKindPinnedCallsite` mandatory record; it is never fatal. It has one or more
pinned-callsite requirements and no state/FD/live-pointer/object requirement.
Role-origin pinned records require exactly `CheckCompiledConstant`; runtime-
origin records require exactly `CheckCompiledConstant|CheckRuntimeMapping`.
They are scalar/all-stage like direct rows and obey the same no-overlap rule.
Their `FilterProfile` behavior is ordinary scalar allow/deny; the pinned proof
does not alter BPF. D7 must source-lock each source unit/compiler, match the
argument-template and instruction digest, prove the callsite lies at the exact
offset in the bound guest binary text, and emit the matching
`PinnedCallsiteEvidenceView`. Its final-binary disassembly and call-graph guard
also proves that no unlisted callsite can reach the pinned rule's scalar allow.
D4/D6 may consume that evidence only as an opaque
verified profile binding and cannot add a callsite or reinterpret it as a live
pointer check. A missing/mismatched evidence record disables the guest/profile.
Pointer-bearing pinned Go runtime sites are always
`RuleOriginRuntime`/`EnforcementPathPinnedDirect`; D7 source plus final-binary
evidence is authoritative and D4 trace is verification evidence only, never
admission or a source of an added rule.
Ordinary `EnforcementPathDirect` still forbids every requirement. Adapter is
still the only path that accepts live observations; no patched Go runtime is
required. D7's source and final-binary call-graph proof rejects any
pointer-bearing syscall callsite classified as ordinary direct: every such
helper callsite must resolve to one exact adapter rule or one exact pinned-
direct evidence record. The scalar-only workload exception below is explicitly
outside this helper pointer-callsite guard and makes no pointer provenance
claim. D4/D6 source guards forbid raw helper pointer syscalls outside the two
helper paths.

`RoleWorkload` has no D4 adapter after final exec and therefore never uses
pinned-direct or adapter rows. Its sole narrow exception is a
`RuleOriginWorkload`/`EnforcementPathDirect` scalar-only workload exception
imported from the source-locked L4/L7 `WorkloadSnapshot`. Such a row is valid
only in `RoleWorkload`, all-stage, with no state/descriptor/pointer/object/
pinned requirement, and only for a catalog-ordinary syscall. It contributes
only its syscall number and scalar clauses to the final workload filter; it is
not helper pointer-callsite authority and makes no pointer provenance,
reinspection, or adapter claim. It can never name a fatal or conditional
catalog row, appear in a helper role, overlap a helper-origin row, or widen a
helper/ancestry projection; any attempt rejects `ErrorCodeUnsafeWidening` (or
`ErrorCodeFatalAllow` for fatal). `RuleOriginWorkload` rows are never helper pointer-callsite authority.

`ScalarClauseView` accessors are `ArgumentIndex() uint8`,
`Operation() ScalarOperation`, `Mask() uint64`, `Values() []uint64`,
`MismatchAction() Action`, and `MismatchReason() Reason`.
`DescriptorRequirementView` accessors are `ArgumentIndex() uint8`,
`Kind() DescriptorKind`, `Access() DescriptorAccess`, `Fixed() bool`,
`RequiredChecks() CheckSet`, and `GenerationSHA256() [32]byte`.
`PointerRequirementView` accessors are `ArgumentIndex() uint8`,
`Class() PointerClass`, `MinimumBytes() uint32`, `MaximumBytes() uint32`, and
`RequiredChecks() CheckSet`. `ObjectRequirementView` has the descriptor-view
accessors plus `Source() ObjectSource` and `RequiredChecks() CheckSet`.
`TransitionView` accessors are
`Role() Role`, `From() Stage`, `ToRole() Role`, `To() Stage`, `RequiredFacts() StateFact`,
`ProhibitedFacts() StateFact`, `SetFacts() StateFact`, `ClearFacts() StateFact`,
and `SHA256() [32]byte`.
`TransitionView.SHA256` is the standard length-framed digest with domain
`hal/l8/syscall-transition/linux-amd64/v1` and exactly the enclosing from-role
plus the complete canonical transition row as its preimage.

For an adapter rule, effective required facts are the union of its stage row's
required facts and its rule required facts; effective prohibited facts are the union
of its stage row's prohibited facts and its rule prohibited facts. Any
intersection rejects import. `StateQuery` carries exactly those effective
masks, and `Policy.Decide` step 3 evaluates them. Direct and pinned-direct rows
are all-stage as constrained above and do not consume stage facts.

`ValidateTransition(from,to)` validates in this order: both states/catalogs;
source facts against the from-stage invariant; the exact from-role/stage to
to-role/stage edge; transition source required/prohibited masks; deterministic
`expectedDestinationFacts = (from.Facts() | setFacts) &^ clearFacts`; equality
of `to.Facts()` to that expected value; then destination facts against the
to-stage required/prohibited invariant. Any failure returns
kill/impossible-transition with zero ticket; exact success returns allow/exact
with zero rule/ticket. It never silently supplies or drops a destination fact.

Rows sort by role, stage, syscall number,
then complete canonical rule bytes; duplicate bytes and two rows with identical
match input but different outcome are contradictions. After exact filter-byte
deduplication, every same-syscall alternative within each effective
`FilterRules` projection must be disjoint under the closed scalar grammar. This
crosses stage and descendant boundaries because seccomp cannot inspect D2 state.
Scalar clauses
are predicates over one unsigned 64-bit word. D2 decides pairwise intersection
exactly with a fixed MSB-to-LSB Boolean search: at each bit it explores zero
then one, carries each clause's equal/mask/range/finite-set feasibility state,
memoizes `(bit, left-state, right-state)`, and succeeds at bit 64 only when both
predicates accept. Missing argument clauses are the all-values predicate. Two
rules overlap iff this search finds an intersection independently for all six
arguments. An overlapping pair is `ErrorCodeContradiction`; there is no row
order or unproved-disjoint fallback. Exceeding
`MaxScalarPredicateSearchStates` returns `ErrorCodeBounds` and rejects import;
it never counts as disjoint.

Every rule has one canonical positive input. The state uses the role/stage and
the union of stage/rule required facts with every prohibited fact absent;
contradictory stage/rule facts reject import. Unconstrained arguments are zero.
For each clause the lowest satisfying value is exact: `ScalarEqual` and
`ScalarMaskedEqual` use their sole canonical value; `ScalarOneOf` uses its first
value; `ScalarUnsignedRange` uses its low endpoint; `ScalarZero` uses zero; and
`ScalarNonzero` uses one. The importer runs `Policy.Decide` over every positive
after constructing the copied graph and rejects unless it selects that exact
rule with allow/exact. This also detects shadowing or an inconsistent positive.

The ancestry section has `itemCount=2`; each record is
`ancestorRole:u8, descendantCount:u8, reserved:u16=0,
unionSHA256:[32]byte, descendants:descendantCount*u8`. Records and descendants
are ascending and unique. `launch-base` names the
complete ordered descendant section set controller-bootstrap,
steady-controller, agent-bootstrap, steady-agent, monitor-bootstrap,
steady-monitor, workload-transition, workload. `workload-transition` names
workload. The union digest is the standard domain framing with domain
`hal/l8/syscall-filter-projection/linux-amd64/v1`, then `filterRuleCount:u32`
and the sorted, byte-deduplicated complete filter-rule bytes for the ancestor's
own rows plus every named descendant. D2 recomputes the returned
`FilterRules` projection without wildcard or semantic merging and rejects
omission, extra ancestry, conflicting duplicate, or union digest mismatch.

The workload body is exactly `sourceLockSHA256:[32]byte, l4SHA256:[32]byte,
l7SHA256:[32]byte, ruleIndexes:itemCount*u32`. Its header `itemCount` is nonzero
and at most `MaxPolicyRulesPerRole`; each index is ascending, unique, in range,
and resolves to every and only `RoleWorkload`/`RuleOriginWorkload` rule. All
three digests are nonzero. `WorkloadSnapshot.SHA256`, `SourceLockSHA256`,
`L4SHA256`, `L7SHA256`, and `Rules() []WorkloadRuleView` are defensive views;
`WorkloadRuleView.Rule() RuleView` returns a copy. `WorkloadSnapshot.SHA256`
is the standard length-framed digest with domain
`hal/l8/syscall-workload-snapshot/linux-amd64/v1` and the complete workload
section body above as its sole preimage.
Every resolved workload row must satisfy the scalar-only workload exception
above; the cross-section verifier rejects a non-workload role/origin, non-direct
path, conditional/fatal catalog class, fact/check/resource/pinned requirement,
or helper-row overlap before accepting `WorkloadSnapshot`.
The workload source-lock digest is independently recomputed with domain
`hal/l8/syscall-workload-source-lock/linux-amd64/v1` and exact preimage
`l4SHA256 || l7SHA256 || roleFSMSourceSHA256 || generatorSourceSHA256`; it must
equal both the workload field and the provenance
`workloadInputLockSHA256`.

The runtime body is exactly `goVersionLength:u8, reserved:[3]byte=0,
sourceSHA256:[32]byte, sourceLockSHA256:[32]byte,
goVersion:goVersionLength*ASCII, ruleIndexes:itemCount*u32`. The version is
exact ASCII `go1.25.7`; `goVersionLength=8`; both digests are nonzero; indexes
are ascending, unique, in range, and resolve to every and only
`RuleOriginRuntime` rule. `RuntimeProfileView.GoVersion`, `SHA256`, `SourceSHA256`,
`SourceLockSHA256`, and `Rules() []RuleView` return safe copies. D2 does not
ship placeholder runtime rows; D7 authors these rows from the pinned source and
the approved role FSM. `RuntimeProfileView.SHA256` is the standard
length-framed digest with domain
`hal/l8/syscall-runtime-profile/linux-amd64/v1` and the complete runtime section
body above as its sole preimage. Trace remains verification evidence only.
The runtime source-lock digest is independently recomputed with domain
`hal/l8/syscall-runtime-source-lock/linux-amd64/v1` and exact preimage
`u8(goVersionLength) || goVersion || sourceSHA256 || roleFSMSourceSHA256 ||
generatorSourceSHA256`; it must equal both the runtime field and the provenance
`runtimeSourceLockSHA256`.

The provenance section has `itemCount=11`. Its first eight digests are the
ordered source-lock preimage frozen above. Its final three are the workload,
runtime, and catalog section digests in that order. D2 recomputes the header
source-lock digest, checks the workload/runtime source-lock formulae, checks
the final three cross-section equalities, and checks the catalog source-lock
digest with domain `hal/l8/syscall-catalog-source-lock/linux-amd64/v1` and exact
preimage `u8(moduleNameLength) || moduleName || u8(sourcePathLength) ||
sourcePath || kernelCeiling:u32 || catalogSourceSHA256 ||
generatorSourceSHA256`. The final artifact output digest and all final role
binary digests are deliberately external to this body to avoid a digest cycle. D2
cannot claim semantic completeness beyond the opaque expected issuer marker.

The verifier rejects, in order: invalid/zero expected authority; encoded size
zero or above the maximum; expected artifact digest mismatch; bad
magic/version/ABI/kernel/reserved/header length; truncation/trailing bytes;
section order/count/digest/bounds errors; unknown catalog or enum values;
missing role/stage/required section; duplicate/noncanonical rows;
contradictory clauses or state facts; wildcard/empty widening; any rule that
references a catalog-fatal syscall; a conditional-danger row with no scalar or
adapter restriction; invalid ancestry/union digest; cross-section provenance
mismatch. It copies `encoded` before hashing and retains no caller slice.

The verifier returns the code for the first category reached: expected marker
or zero digest `ErrorCodeOwnership`; zero/oversize/count/length
`ErrorCodeBounds`; expected, section, or cross-section digest mismatch
`ErrorCodeDigestMismatch`; header/reserved/order/truncation/trailing-byte
grammar `ErrorCodeEncoding`; unknown source/catalog/enum
`ErrorCodeCatalog`; absent required section/role/stage/origin
`ErrorCodeMissingSection`; duplicate `ErrorCodeDuplicate`; conflicting fact,
clause, transition, or row `ErrorCodeContradiction`; wildcard/conditional-check
widening `ErrorCodeUnsafeWidening`; a fatal rule `ErrorCodeFatalAllow`; and
ancestry edge/union errors `ErrorCodeInvalidAncestry`. Error text contains only
the code string.

The artifact catalog marks each syscall ordinary, fatal, or conditional.
Fatal rows cannot appear in any allow rule. Conditional socket, namespace,
clone, privilege, mount, seccomp, signal, and pathname-exec rows require at
least one non-wildcard scalar clause and every artifact-declared mandatory
evidence record. Coverage is checked independently for each exact state,
descriptor, pointer, argument-object, return-object, or pinned-callsite
attachment against the admissible/mandatory matrix; there is no union, global,
or out-of-band check source. Each exact check set must be returned by its bound
phase observation, and a post-only record requires an
`ObjectSourceReturn` requirement. D2 validates those structural anti-widening
properties, but the
D7 issuer is authoritative for the complete per-role semantic table.

### Exact Go construction and views

```go
type State struct { role Role; stage Stage; facts StateFact; valid bool }
type FilterInput struct {
    state State
    auditArchitecture uint32
    rawSyscallNumber uint32
    arguments [6]uint64
    valid bool
}
type Classification struct { abi ABIClass; number SyscallNumber; known bool }
type Policy struct { artifact *verifiedArtifact; owner *policyOwner }
type AdapterTicket struct { ticket *adapterTicket; owner *policyOwner }
type AdapterPermit struct { permit *adapterPermit; owner *policyOwner; operation *adapterBindingOwner }
type AdapterBindings struct { bindings *adapterBindings; owner *policyOwner; operation *adapterBindingOwner }
type AdapterBindingView struct { binding *adapterBinding }
type Decision struct { action Action; reason Reason; ruleSHA256 [32]byte; ticket AdapterTicket }
type AdapterDecision struct {
    outcome AdapterOutcome
    reason AdapterReason
    phase AdapterPhase
    final bool
    ruleSHA256 [32]byte
}

func NewPolicy(artifact VerifiedPolicyArtifact) (*Policy, error)
func NewState(role Role, stage Stage, facts StateFact) (State, error)
func NewFilterInput(state State, auditArchitecture uint32, rawSyscallNumber uint32, arguments [6]uint64) (FilterInput, error)

func (policy *Policy) Decide(input FilterInput) Decision
func (policy *Policy) NewAdapterBindings(ticket AdapterTicket, source BindingSource) (AdapterBindings, error)
func (policy *Policy) AuthorizePre(ticket AdapterTicket, bindings AdapterBindings, source PreObservationSource) (AdapterPermit, AdapterDecision, error)
func (policy *Policy) AuthorizePost(permit AdapterPermit, source PostObservationSource) (AdapterDecision, error)
func (policy *Policy) CommitNoObject(permit AdapterPermit) (AdapterDecision, error)
func (policy *Policy) AbortPermit(permit AdapterPermit, phase AdapterPhase) (AdapterDecision, error)
func (policy *Policy) ValidateTransition(from, to State) Decision
func (policy *Policy) Fingerprint(role Role) ([32]byte, error)
func (policy *Policy) Rules(role Role) ([]RuleView, error)
func (policy *Policy) FilterRules(role Role) ([]FilterRuleView, error)
func (policy *Policy) FilterProfile(role Role) (FilterProfile, error)
func (policy *Policy) GoldenCases() []GoldenCase
```

`NewPolicy` accepts only a nonzero `VerifiedPolicyArtifact` returned by the
importer and deep-copies its immutable rows; production `NewPolicy` rejects the
zero value, decoded-but-unverified bytes, or a value from another package.
`NewState` validates only the closed catalogs/fact bits; the policy artifact
decides role-stage/fact compatibility. `NewFilterInput` rejects only an invalid
state and retains any architecture, raw number, and all six scalar words so
`Decide` can return the required kill classification. `State` accessors are
`Role() Role`, `Stage() Stage`, and `Facts() StateFact`. `FilterInput` accessors
are `State() State`, `AuditArchitecture() uint32`,
`RawSyscallNumber() uint32`, and `Argument(uint8) (uint64, error)`.
`FilterInput.SHA256()` returns the complete input digest frozen below.

```go
func (state State) Role() Role
func (state State) Stage() Stage
func (state State) Facts() StateFact
func (input FilterInput) State() State
func (input FilterInput) AuditArchitecture() uint32
func (input FilterInput) RawSyscallNumber() uint32
func (input FilterInput) Argument(index uint8) (uint64, error)
func (input FilterInput) SHA256() [32]byte
```

`RuleView` accessors are `Role() Role`, `Stage() Stage`,
`Origin() RuleOrigin`, `EnforcementPath() EnforcementPath`, `RequiredFacts() StateFact`,
`ProhibitedFacts`, `SyscallNumber`, `ScalarClauses`,
`DescriptorRequirements`, `PointerRequirements`, `ObjectRequirements`,
`StateChecks`, `AdapterFailure`, and `SHA256`; every omitted return
type is the matching named catalog/view type and slice accessors deep-copy.
`VerifiedPolicyArtifact` accessors are `SHA256() [32]byte`,
`Catalog() []CatalogEntryView`, `Rules() []RuleView`,
`Transitions() []TransitionView`, `Workload() WorkloadSnapshot`, and
`Runtime() RuntimeProfileView`; all return values or defensive copies.
`ExpectedPolicyArtifact`, `VerifiedPolicyArtifact`,
`Policy`, `State`, `FilterInput`, `FilterProfile`, `AdapterTicket`,
`AdapterPermit`, queries, and observations
have private fields and no literal-construction authority.

The complete remaining view signatures are:

```go
func (expected ExpectedPolicyArtifact) SHA256() [32]byte
func (artifact VerifiedPolicyArtifact) SHA256() [32]byte
func (artifact VerifiedPolicyArtifact) Catalog() []CatalogEntryView
func (artifact VerifiedPolicyArtifact) Rules() []RuleView
func (artifact VerifiedPolicyArtifact) Transitions() []TransitionView
func (artifact VerifiedPolicyArtifact) Workload() WorkloadSnapshot
func (artifact VerifiedPolicyArtifact) Runtime() RuntimeProfileView
func (artifact VerifiedPolicyArtifact) SourceLockSHA256() [32]byte
func (entry CatalogEntryView) Number() SyscallNumber
func (entry CatalogEntryView) Name() string
func (entry CatalogEntryView) Class() SyscallClass
func (entry CatalogEntryView) MandatoryEvidence() []MandatoryEvidenceView
func (evidence MandatoryEvidenceView) Kind() EvidenceKind
func (evidence MandatoryEvidenceView) AttachmentIndex() uint16
func (evidence MandatoryEvidenceView) RequiredChecks() CheckSet
func (rule RuleView) Role() Role
func (rule RuleView) Stage() Stage
func (rule RuleView) Origin() RuleOrigin
func (rule RuleView) EnforcementPath() EnforcementPath
func (rule RuleView) RequiredFacts() StateFact
func (rule RuleView) ProhibitedFacts() StateFact
func (rule RuleView) StateChecks() CheckSet
func (rule RuleView) SyscallNumber() SyscallNumber
func (rule RuleView) ScalarClauses() []ScalarClauseView
func (rule RuleView) DescriptorRequirements() []DescriptorRequirementView
func (rule RuleView) PointerRequirements() []PointerRequirementView
func (rule RuleView) ObjectRequirements() []ObjectRequirementView
func (rule RuleView) PinnedCallsiteRequirements() []PinnedCallsiteRequirementView
func (rule RuleView) AdapterFailure() AdapterOutcome
func (rule RuleView) SHA256() [32]byte
func (snapshot WorkloadSnapshot) SHA256() [32]byte
func (snapshot WorkloadSnapshot) SourceLockSHA256() [32]byte
func (snapshot WorkloadSnapshot) L4SHA256() [32]byte
func (snapshot WorkloadSnapshot) L7SHA256() [32]byte
func (snapshot WorkloadSnapshot) Rules() []WorkloadRuleView
func (rule WorkloadRuleView) Rule() RuleView
func (profile RuntimeProfileView) GoVersion() string
func (profile RuntimeProfileView) SHA256() [32]byte
func (profile RuntimeProfileView) SourceSHA256() [32]byte
func (profile RuntimeProfileView) SourceLockSHA256() [32]byte
func (profile RuntimeProfileView) Rules() []RuleView
func (clause ScalarClauseView) ArgumentIndex() uint8
func (clause ScalarClauseView) Operation() ScalarOperation
func (clause ScalarClauseView) Mask() uint64
func (clause ScalarClauseView) Values() []uint64
func (clause ScalarClauseView) MismatchAction() Action
func (clause ScalarClauseView) MismatchReason() Reason
func (requirement DescriptorRequirementView) ArgumentIndex() uint8
func (requirement DescriptorRequirementView) Kind() DescriptorKind
func (requirement DescriptorRequirementView) Access() DescriptorAccess
func (requirement DescriptorRequirementView) Fixed() bool
func (requirement DescriptorRequirementView) RequiredChecks() CheckSet
func (requirement DescriptorRequirementView) GenerationSHA256() [32]byte
func (requirement DescriptorRequirementView) GenerationMode() GenerationMode
func (requirement DescriptorRequirementView) BindingSlot() uint8
func (requirement PointerRequirementView) ArgumentIndex() uint8
func (requirement PointerRequirementView) Class() PointerClass
func (requirement PointerRequirementView) MinimumBytes() uint32
func (requirement PointerRequirementView) MaximumBytes() uint32
func (requirement PointerRequirementView) RequiredChecks() CheckSet
func (requirement ObjectRequirementView) ArgumentIndex() uint8
func (requirement ObjectRequirementView) Source() ObjectSource
func (requirement ObjectRequirementView) Kind() DescriptorKind
func (requirement ObjectRequirementView) Access() DescriptorAccess
func (requirement ObjectRequirementView) Fixed() bool
func (requirement ObjectRequirementView) RequiredChecks() CheckSet
func (requirement ObjectRequirementView) GenerationSHA256() [32]byte
func (requirement ObjectRequirementView) GenerationMode() GenerationMode
func (requirement ObjectRequirementView) BindingSlot() uint8
func (transition TransitionView) Role() Role
func (transition TransitionView) From() Stage
func (transition TransitionView) ToRole() Role
func (transition TransitionView) To() Stage
func (transition TransitionView) RequiredFacts() StateFact
func (transition TransitionView) ProhibitedFacts() StateFact
func (transition TransitionView) SetFacts() StateFact
func (transition TransitionView) ClearFacts() StateFact
func (transition TransitionView) SHA256() [32]byte
func (rule FilterRuleView) SyscallNumber() SyscallNumber
func (rule FilterRuleView) ScalarClauses() []ScalarClauseView
func (rule FilterRuleView) SHA256() [32]byte
func (profile FilterProfile) Role() Role
func (profile FilterProfile) KernelCeiling() SyscallNumber
func (profile FilterProfile) Catalog() []CatalogEntryView
func (profile FilterProfile) Rules() []FilterRuleView
func (profile FilterProfile) SHA256() [32]byte
func (profile FilterProfile) Decide(auditArchitecture uint32, rawSyscallNumber uint32, arguments [6]uint64) FilterDecision
func (decision FilterDecision) Action() Action
func (decision FilterDecision) Reason() Reason
func (decision FilterDecision) Allowed() bool
func (decision FilterDecision) RuleSHA256() [32]byte
func (requirement PinnedCallsiteRequirementView) CallsiteOrdinal() uint16
func (requirement PinnedCallsiteRequirementView) PointerClass() PointerClass
func (requirement PinnedCallsiteRequirementView) MinimumBytes() uint32
func (requirement PinnedCallsiteRequirementView) MaximumBytes() uint32
func (requirement PinnedCallsiteRequirementView) RequiredChecks() CheckSet
func (requirement PinnedCallsiteRequirementView) InstructionLength() uint16
func (requirement PinnedCallsiteRequirementView) SourceUnitSHA256() [32]byte
func (requirement PinnedCallsiteRequirementView) ArgumentTemplateSHA256() [32]byte
func (requirement PinnedCallsiteRequirementView) InstructionTemplateSHA256() [32]byte
func (requirement PinnedCallsiteRequirementView) ToolchainSHA256() [32]byte
func (requirement PinnedCallsiteRequirementView) SHA256() [32]byte
func (binding PinnedBinaryBindingView) Role() Role
func (binding PinnedBinaryBindingView) Kind() BinaryBindingKind
func (binding PinnedBinaryBindingView) TextLength() uint64
func (binding PinnedBinaryBindingView) SourceLockSHA256() [32]byte
func (binding PinnedBinaryBindingView) ToolchainSHA256() [32]byte
func (binding PinnedBinaryBindingView) BinarySHA256() [32]byte
func (binding PinnedBinaryBindingView) ExecutableTextSHA256() [32]byte
func (binding PinnedBinaryBindingView) SHA256() [32]byte
func (bindings PinnedBinaryBindingSet) SHA256() [32]byte
func (bindings PinnedBinaryBindingSet) Bindings() []PinnedBinaryBindingView
func (evidence PinnedCallsiteEvidenceView) CallsiteSHA256() [32]byte
func (evidence PinnedCallsiteEvidenceView) BinaryBindingSHA256() [32]byte
func (evidence PinnedCallsiteEvidenceView) ObservedInstructionSHA256() [32]byte
func (evidence PinnedCallsiteEvidenceView) InstructionOffset() uint64
func (evidence PinnedCallsiteEvidenceView) SHA256() [32]byte
func (expected ExpectedPinnedCallsiteEvidence) SHA256() [32]byte
func (set PinnedCallsiteEvidenceSet) SHA256() [32]byte
func (set PinnedCallsiteEvidenceSet) ArtifactSHA256() [32]byte
func (set PinnedCallsiteEvidenceSet) SourceLockSHA256() [32]byte
func (set PinnedCallsiteEvidenceSet) BinaryBindings() PinnedBinaryBindingSet
func (set PinnedCallsiteEvidenceSet) Evidence() []PinnedCallsiteEvidenceView
```

`Rules(role)` returns only that role's complete immutable semantic rows and is
for decision/adapter inspection. `FilterRules(role)` contains scalar-filter fields only: syscall number, scalar clauses,
and their frozen mismatch actions/reasons. It strips state facts,
origin, adapter requirements/failure, ticket authority, and every pointer or
object field. For ordinary roles it returns own-role rows. For
`RoleLaunchBase` and `RoleWorkloadTransition` it returns the exact set union of
own rows and the ancestry record's descendants, deduplicated only by identical
canonical scalar filter bytes and sorted by syscall number then complete filter
bytes. A repeated match predicate with different mismatch metadata is a
contradiction. No wildcard or semantic merge is permitted. During import D2 recomputes
this projection and its domain-framed digest
`hal/l8/syscall-filter-projection/linux-amd64/v1`; that exact digest is the
ancestry record's `unionSHA256`. `FilterRules` independently recomputes and
compares it before returning a defensive copy, otherwise
`ErrorCodeInvalidAncestry`. D4 cannot compile from `Rules` or invent an
effective union.

`FilterProfile(role)` is D4's sole compiler input. It defensively contains the
complete verified pinned catalog through ceiling 450 plus that role's exact
`FilterRules` projection. Its digest uses the standard framing and domain
`hal/l8/syscall-filter-profile/linux-amd64/v1` over artifact digest, role,
kernel ceiling, catalog section digest, and filter-projection digest. D4
compilation uses only this profile: foreign architecture and x32 kill first;
raw number above ceiling or absent from the complete catalog kills; a catalog
fatal row kills; a known ordinary/conditional row with no matching filter rule
returns EPERM; scalar mismatch applies the rule's frozen kill-before-EPERM
precedence; exact match allows. D4 never imports host headers or x/sys and never
infers known/fatal membership outside this profile. Import and
`FilterProfile` recompute its digest; mismatch is `ErrorCodeDigestMismatch`.
`FilterProfile.Decide` implements exactly that raw-filter precedence without a
state, ticket, observer, or adapter claim. Its result is D4's compiler golden;
the compiled BPF must match it for every generated case. `Policy.Decide` is the
role/stage/fact semantic oracle that issues adapter tickets and may therefore
be narrower than an ancestor's effective raw-filter result.

For a known nonfatal syscall, `FilterProfile.Decide` evaluates every canonical
filter rule for that number. Any exact predicate match wins and returns
allow/exact with that rule's digest. If none exactly matches, it collects every failing clause from every candidate rule. It chooses kill if any collected clause has kill action; otherwise it chooses EPERM. It then selects the
lexicographically first canonical filter rule containing a failing clause with
that chosen action, followed by the lowest argument-index failing clause of
that action in the selected rule, and returns that clause's frozen reason and
the selected rule digest. It never discards a later kill clause merely because
an earlier clause in that rule failed with EPERM. A known row with no filter rule is
EPERM/known-unlisted with zero rule digest. A zero or invalid `FilterProfile`
returns kill/impossible-transition with zero rule digest and never panics.
`FilterRules` and `FilterProfile` use this failure precedence: nil/foreign
policy is `ErrorCodeOwnership`; unknown role is `ErrorCodeCatalog`; invalid
ancestry graph or projection is `ErrorCodeInvalidAncestry`; copied catalog,
projection, or profile digest mismatch is `ErrorCodeDigestMismatch`.
Every D7 filter fixture set includes a dual-action failure fixture in which one
input fails both an EPERM clause and a later kill clause; both the pure profile
and compiled filter must return that kill clause's reason and rule digest.

Canonical filter-rule bytes are `syscallNumber:u32, scalarClauseCount:u8,
reserved:[3]byte=0`, followed by the complete clauses in argument-index order.
`FilterRuleView.SHA256` uses the standard framing and domain
`hal/l8/syscall-filter-rule/linux-amd64/v1`. A role with no ancestry record has
the same sorted byte-deduplicated projection over its own rows; it is never an
empty implicit allow and an empty projection rejects the required role section.

`ABIClass` is a `uint8`: `ABIClassNativeAMD64=1`, `ABIClassX32=2`, and
`ABIClassForeign=3`; `ValidateABIClass` rejects every other value.
`Classification` has private `ABIClass`, normalized `SyscallNumber`, and known
bit. `func (policy *Policy) Classify(auditArchitecture uint32,
rawSyscallNumber uint32) Classification` checks
`AUDIT_ARCH_X86_64 = 0xc000003e` and
`X32SyscallBit = 0x40000000`; accessors are `ABI() ABIClass`,
`Number() SyscallNumber`, and `Known() bool`. Native amd64 clears no bits and
is known only on exact catalog membership; x32 preserves the raw number and is
never known or normalized; foreign preserves the raw number and is never known.

```go
func (classification Classification) ABI() ABIClass
func (classification Classification) Number() SyscallNumber
func (classification Classification) Known() bool
func (decision Decision) Action() Action
func (decision Decision) Reason() Reason
func (decision Decision) Allowed() bool
func (decision Decision) RuleSHA256() [32]byte
func (decision Decision) Ticket() (AdapterTicket, error)
func (ticket AdapterTicket) ArtifactSHA256() [32]byte
func (ticket AdapterTicket) RuleSHA256() [32]byte
func (ticket AdapterTicket) InputSHA256() [32]byte
func (ticket AdapterTicket) SHA256() [32]byte
func (decision AdapterDecision) Outcome() AdapterOutcome
func (decision AdapterDecision) Reason() AdapterReason
func (decision AdapterDecision) Phase() AdapterPhase
func (decision AdapterDecision) Ready() bool
func (decision AdapterDecision) Final() bool
func (decision AdapterDecision) Authorized() bool
func (decision AdapterDecision) RuleSHA256() [32]byte
func (permit AdapterPermit) RuleSHA256() [32]byte
func (permit AdapterPermit) TicketSHA256() [32]byte
func (permit AdapterPermit) InputSHA256() [32]byte
func (permit AdapterPermit) PermitCorrelationSHA256() [32]byte
func (permit AdapterPermit) RequiresPost() bool
func (permit AdapterPermit) SHA256() [32]byte
func (bindings AdapterBindings) TicketSHA256() [32]byte
func (bindings AdapterBindings) PermitCorrelationSHA256() [32]byte
func (bindings AdapterBindings) SHA256() [32]byte
func (bindings AdapterBindings) Bindings() []AdapterBindingView
func (binding AdapterBindingView) Slot() uint8
func (binding AdapterBindingView) Kind() DescriptorKind
func (binding AdapterBindingView) Access() DescriptorAccess
func (binding AdapterBindingView) GenerationSHA256() [32]byte
func (binding AdapterBindingView) PermitCorrelationSHA256() [32]byte
func (binding AdapterBindingView) SHA256() [32]byte
```

`Decision` accessors are `Action() Action`, `Reason() Reason`, `Allowed() bool`,
`RuleSHA256() [32]byte`, and `Ticket() (AdapterTicket, error)`; `Ticket` returns
`ErrorCodeOwnership` unless the decision has allow/exact, a nonzero rule
digest, an adapter-path rule, and a nonzero `Policy.Decide`-issued ticket. Ticket succeeds only for a nonzero `Policy.Decide`-issued ticket. A direct, pinned-direct, or scalar-only workload allow has its nonzero rule digest but a zero ticket; transition allow has a zero rule digest and zero ticket. All return ownership from `Ticket`.
`AdapterTicket` binds the
policy owner, artifact, role, rule, complete state, architecture, raw syscall,
and all six scalar words by private copies and digests. It cannot be used with
another policy or input, but same-ticket authorization is pure and repeatable;
D2 owns no consumption state. D4 owns any one-shot execution discipline.
Its four accessors return the bound artifact, rule, complete-input, and ticket
digests exactly; none exposes the copied input graph.

`AdapterDecision.Ready` is true only for nonfinal pre/proceed/exact;
`Authorized` is true only for final post/proceed/exact. A pre failure and every
post result are final. The rule failure outcome is exactly its canonical
reject-cleanup or stop-VM; no caller chooses it.

`AuthorizePre` returns:

| Condition | Permit | Decision | Error |
|---|---|---|---|
| nil or typed-nil `PreObservationSource` | zero | zero | `ErrorCodeTypedNil` |
| zero/foreign/mismatched ticket | zero | zero | `ErrorCodeOwnership` |
| zero/foreign/mismatched bindings | zero | zero | `ErrorCodeOwnership` |
| unresolved/incorrect live descriptor or argument-object binding | zero | final pre/rule-failure/matching FD/object reason | nil |
| pre observer error | zero | final pre/rule-failure/observer-failure | `ErrorCodeObservation` |
| state/FD/pointer/input-object mismatch | zero | final pre/rule-failure/matching reason | nil |
| every pre observation matches | nonzero | nonfinal pre/proceed/exact | nil |

Its observer order is state, FD by argument, pointer by argument, then
`ObjectSourceArgument` by argument. It stops at the first error or mismatch and
never emits a permit on failure. The permit binds policy owner, artifact,
ticket, rule, complete filter input, failure outcome, and the exact ordered
post-query set. It has `RuleSHA256() [32]byte`, `InputSHA256() [32]byte`,
`PermitCorrelationSHA256() [32]byte`, `RequiresPost() bool`, and
`SHA256() [32]byte` accessors. The complete input digest uses domain
`hal/l8/filter-input/linux-amd64/v1` over
`role:u8, stage:u8, reserved:u16=0, facts:u64, auditArchitecture:u32,
rawSyscallNumber:u32, arguments:[6]u64`. The ticket digest uses domain
`hal/l8/adapter-ticket/linux-amd64/v1` over artifact digest, rule digest, and
that complete input digest.

The independent nonzero `permitCorrelationSHA256` uses domain
`hal/l8/adapter-permit-correlation/linux-amd64/v1` over artifact digest, ticket
digest, rule digest, complete input digest, and failure outcome. It contains no
query or permit digest. Every pre/post query exposes and binds this correlation
plus its zero-based ordinal in that phase.
The permit digest uses standard length framing with domain
`hal/l8/adapter-permit/linux-amd64/v1` over the correlation, binding-snapshot
digest, post-query count, and ordered post-query digests. Thus no permit/query
hash cycle exists. The private owner pointer is not in the bytes.

D4 executes exactly one live syscall only after `Ready()` and a nonzero permit.
D2 never executes or observes the live syscall. On syscall success, D4 calls
`AuthorizePost` when `RequiresPost` is true or `CommitNoObject` when false; it
never omits that final call. `AuthorizePost` returns:

D4's private post source is constructed only as
`newPostObservationSource(permit AdapterPermit, returnedObjectFD int32)` after
the syscall wrapper receives a nonnegative returned FD. It rejects a permit
without post requirements and captures that one FD immutably. Its
`ReinspectObject` accepts only a query whose correlation equals the captured
permit correlation and whose ordinal is the next exact post ordinal; it then
accepts only that permit-bound `ObjectSourceReturn` query and
reinspects the captured FD; it has no caller-selected FD, arguments, path, or
alternate live operation. For `GenerationModeFreshReturn`, this D4 source mints
a nonzero operation-scoped generation only after successful return, includes
it in the observation, and publishes it to the trusted ledger only after
`AuthorizePost` returns final proceed/exact; denial closes the FD and discards
the generation. Static-exact and live-bound return modes are invalid. Syscalls with no returned object never construct the
source. The `ObjectQuery` therefore carries expected metadata and the return
source sentinel, while the D4 source supplies the exact live return value.

| Condition | Decision | Error |
|---|---|---|
| nil or typed-nil `PostObservationSource` | zero | `ErrorCodeTypedNil` |
| zero/foreign/mismatched permit | zero | `ErrorCodeOwnership` |
| permit has no returned-object query | zero | `ErrorCodeInvalidArgument` |
| post observer error | final post/rule-failure/observer-failure | `ErrorCodeObservation` |
| returned-object mismatch | final post/rule-failure/object-mismatch | nil |
| every returned-object observation matches | final post/proceed/exact | nil |

Post order is only `ObjectSourceReturn` in canonical record order. It never
repeats state, FD, pointer, or input-object observations. `CommitNoObject`
accepts only a same-policy permit with zero post queries and returns final
post/proceed/exact; a permit with post queries is invalid argument.
If cancellation or a wrapper failure occurs after claim but before the syscall,
D4 calls `AbortPermit(permit, AdapterPhasePre)`. If the syscall itself fails or
panics, D4 calls `AbortPermit(permit, AdapterPhasePost)`. Both calls use the exact same nonzero permit returned by `AuthorizePre`; D4 does not mint, copy
from exposed fields, or substitute a permit. D2 performs no observation in
either abort phase. D4 closes any kernel-returned object and performs the rule
cleanup before exposing a post failure.

#### Exact terminal API and phase matrix

The terminal abort API is exactly:

```go
func (policy *Policy) AbortPermit(permit AdapterPermit, phase AdapterPhase) (AdapterDecision, error)
```

The explicit phase describes whether the sole D4 wrapper has invoked its
syscall closure. It is not caller-selected authority: the wrapper derives
`AdapterPhasePre` only from `claimed` with zero syscall-closure calls and
`AdapterPhasePost` only from `executed` after exactly one syscall-closure call.
Permit ownership is checked before phase validation. The complete pure-D2
ownership/error/return matrix is:

| D2 terminal call condition | Decision | Error |
|---|---|---|
| nil policy, or zero/foreign/mismatched commit or abort permit | zero | `ErrorCodeOwnership` |
| exact owned abort permit with zero or unknown phase | zero | `ErrorCodeCatalog` |
| exact owned commit permit with post queries | zero | `ErrorCodeInvalidArgument` |
| exact owned commit permit with zero post queries | final post/proceed/exact | nil |
| `AbortPermit(permit, AdapterPhasePre)` with exact owned permit | final pre/rule-failure/pre-syscall-abort | nil |
| `AbortPermit(permit, AdapterPhasePost)` with exact owned permit | final post/rule-failure/syscall-failure | nil |

`AdapterReasonPreSyscallAbort` is returned only by the exact pre abort row;
`AdapterReasonSyscallFailure` is returned only by the exact post abort row.
Both use the rule's frozen reject-cleanup or stop-VM outcome and rule digest.
The phase-explicit D2 result cannot prove D4 state or call counts; those are
enforced by the sole private wrapper and its next matrix. Pure-D2 same-permit
calls remain repeatable only for deterministic tests and confer no additional
live authority.

The D4 wrong-phase, reuse, and duplicate terminal matrix is exhaustive:

| Wrapper state/event | D2 call | Wrapper result and state |
|---|---|---|
| inert `unstarted`, any terminal request | none | sanitized ownership failure; construction synchronously destroys/discards the identity; no escape |
| `claimed`, cancellation/wrapper failure before syscall | exactly one `AbortPermit(permit, AdapterPhasePre)` using the exact same permit | store final pre/rule-failure/pre-syscall-abort; `claimed -> finalized` |
| `claimed`, post-phase abort, `AuthorizePost`, or `CommitNoObject` | none | sanitized ownership failure; remain `claimed` |
| `executed`, syscall error/panic | exactly one `AbortPermit(permit, AdapterPhasePost)` using the exact same permit | store final post/rule-failure/syscall-failure; `executed -> finalized` |
| `executed`, pre-phase abort | none | sanitized ownership failure; remain `executed` |
| `executed`, successful syscall with returned-object queries | exactly one `AuthorizePost` using the exact same permit | store its result; `executed -> finalized` |
| `executed`, successful syscall without returned-object queries | exactly one `CommitNoObject` using the exact same permit | store its result; `executed -> finalized` |
| `executed`, success terminal inconsistent with `RequiresPost` | none | sanitized ownership failure; remain `executed` |
| `finalized`, any terminal request, reuse, or duplicate | none | return stored sanitized ownership failure; remain `finalized` |

The wrapper never calls `AuthorizePost` or `CommitNoObject` on an abort route
and never calls `AbortPermit` on a successful-syscall route. Once the syscall
result is known, exactly one matrix row is eligible; there is no fallback to an
alternate terminal method if that sole D2 call returns an error. A wrong-phase,
reused, or duplicate request never reaches D2, an observer, or the syscall
closure.

The D2 permit is immutable and repeatable for deterministic tests; D2 owns no
live execution counter. Live one-use authority belongs only to the sole D4
adapter wrapper. Its exact private catalog and numeric values are:

```go
type wrapperState uint8

const (
	wrapperStateUnstarted wrapperState = 1
	wrapperStateClaimed   wrapperState = 2
	wrapperStateExecuted  wrapperState = 3
	wrapperStateFinalized wrapperState = 4
)
```

#### Exact inert-wrapper construction and ownership matrix

D4 allocates one private inert `unstarted` wrapper identity before `NewAdapterBindings`. That exact identity is the sole production `BindingSource`. Its identity is its private allocation and lifetime, not a
caller value, digest, string, or serializable field. While inert it retains the
Decide-issued ticket and a private immutable trusted-ledger view needed to
answer binding queries, but has no permit, syscall closure, or live syscall authority and cannot escape its constructing function.

D4 calls `NewAdapterBindings(ticket, wrapper)` exactly once. On success the
same wrapper owns the exact `AdapterBindings` snapshot and its private operation token by exclusively retaining that opaque comparable Go value; the token
is not exposed or reconstructed. D4 compares opaque value identity, not
`SHA256`, before any internal handoff. Separately constructed snapshots with
identical canonical bytes remain unequal because their private operation-owner
pointers differ. The wrapper then calls `AuthorizePre` exactly once with its
original ticket and exact stored bindings. Its private pre-observation source
is owned by the same wrapper construction and cannot accept a caller source or
bindings value.

The complete construction matrix is:

| Construction point/result | Stored authority | Calls and disposition |
|---|---|---|
| allocate private wrapper | `unstarted`; original ticket and trusted binding-source view only | no D2 call, no permit/closure, no escape |
| `NewAdapterBindings` succeeds | exact returned bindings snapshot plus its opaque operation token | remain inert `unstarted`; no permit/closure or escape |
| `NewAdapterBindings` returns an error | none | synchronously destroys and discards the inert identity; preserve the sanitized D2 error; zero binding or authorization authority, zero syscall-closure calls, and zero terminal D2 calls |
| binding construction returns zero/foreign bindings or a snapshot other than this wrapper's exact return | none | sanitized ownership failure; synchronously destroy/discard; do not call `AuthorizePre` |
| `AuthorizePre` returns a final denial or error | none | preserve that exact D2 decision/error; synchronously destroys and discards the inert identity; zero binding or authorization authority, zero syscall-closure calls, and zero terminal D2 calls |
| `AuthorizePre` returns a zero/foreign permit or a decision other than nonfinal pre/proceed/exact | none | sanitized ownership failure; synchronously destroy/discard; zero syscall and terminal calls |
| `AuthorizePre` returns the exact nonzero permit | exact bindings/token and permit | under the same private lock, install the permit and sole syscall closure in this identity, then atomically `unstarted -> claimed`; only the fully claimed wrapper may escape |

On the sole success path, successful `AuthorizePre` installs the permit into that same wrapper identity and atomically transitions `unstarted -> claimed` before escape. No replacement wrapper, cross-wrapper transfer, or foreign bindings are accepted. The wrapper
never exposes its ticket, bindings, token, permit, trusted view, or closure.
Every failed construction path zeroes those private references before making
the identity unreachable; it invokes no abort because no claimed wrapper owns
a permit.

Seeded construction-order negatives use two inert identities. They pass wrapper A's bindings into wrapper B, replace A after binding construction, inject a
zero/foreign snapshot, return a zero/foreign permit, invoke authorization before
binding storage, attempt to install the closure before permit success, and
attempt escape before claim. Each must preserve `unstarted`, return only the
sanitized ownership failure (or the exact earlier D2 failure), synchronously
destroy the affected inert identity, and observe zero syscall-closure and zero
terminal D2 calls. No seed may transfer a snapshot/token, permit, trusted view,
or authority to the other wrapper.

The only legal lifecycle is `unstarted -> claimed -> executed -> finalized`,
with the pre-syscall abort edge `claimed -> finalized`. The construction matrix
above is the only route into `claimed`; an inert failure is destruction, not a
state transition. The same wrapper owns the bindings token and permit from
claim onward. Its private mutex serializes construction, state, syscall closure,
terminal D2 call, and stored terminal result; no intermediate `finalizing` state,
replacement identity, or caller-visible binding/permit exists.

The exact D4 transition/call matrix is:

| Current state and event | Next state | Syscall closure | Sole terminal D2 call | Result |
|---|---|---:|---|---|
| same inert `unstarted` identity, successful pre permit installed | `claimed` | 0 | 0 | bindings/token/permit ownership established; wrapper may escape |
| `claimed`, cancellation or wrapper failure before syscall | `finalized` | 0 | exactly one `AbortPermit(permit, AdapterPhasePre)` | final pre-syscall-abort decision/error |
| `claimed`, execution begins | `executed` | exactly 1 | 0 during the call | retain returned result or recovered panic |
| `executed`, syscall succeeds and `RequiresPost=true` | `finalized` | total remains 1 | exactly one `AuthorizePost` | store its final result/error |
| `executed`, syscall succeeds and `RequiresPost=false` | `finalized` | total remains 1 | exactly one `CommitNoObject` | store its final result/error |
| `executed`, syscall fails or panics | `finalized` | total remains 1 | exactly one `AbortPermit(permit, AdapterPhasePost)` | store final syscall-failure result/error |

Thus pre-syscall cancellation or wrapper failure transitions `claimed -> finalized`
through exactly one phase-explicit `AbortPermit` with `AdapterPhasePre` and zero
syscall-closure calls. The normal path's exactly one syscall-closure call transitions `claimed -> executed`.
A successful syscall is finalized by exactly one `AuthorizePost` or `CommitNoObject`;
a failed syscall is finalized by exactly one phase-explicit `AbortPermit` with
`AdapterPhasePost`;
each is the sole `executed -> finalized` edge. The wrapper attempts its one
terminal D2 call exactly once even when that call returns an error, records the
sanitized result, performs required D4 cleanup, and never substitutes another
terminal call.

The wrapper forbids `unstarted -> executed`, `unstarted -> finalized`, claimed-state reuse,
multiple syscall-closure calls, retry, and every method call after `finalized`.
Every forbidden, concurrent, reentrant, second-execute, alternate-terminal, or
post-finalization operation returns the stable sanitized ownership failure and
does not call `AuthorizePre`, `AbortPermit`, `AuthorizePost`, `CommitNoObject`,
an observer, or the syscall closure. There is no live retry on the same wrapper,
ticket, or permit; a higher-level retry is a distinct operation with a newly
issued ticket, successful pre authorization, and newly claimed wrapper. Pure D2
tests may reevaluate the immutable permit, but that never authorizes a live
syscall. D4 source guards forbid permit storage, return, serialization, or a
syscall outside this wrapper.

State matches only when role/stage equal, every required fact is present, every
prohibited fact is absent, and its check set exactly equals `StateChecks`. FD
and argument-object matches require equal number where applicable, kind,
access, fixed bit, the generation comparison selected below, and exact query
check set. Return-object matches require kind/access/fixed and exact checks;
the return number is the live result rather than a query equality. Generation
matching is mode-specific: `GenerationModeStaticExact` and
`GenerationModeLiveBound` require observation generation equal to the query's
nonzero expected generation. `GenerationModeFreshReturn` requires
`ObjectSourceReturn`, an all-zero query expected generation, and a nonzero
newly minted observation generation; FreshReturn never compares the query's zero generation for equality.
That generation is only eligible for ledger publication after the complete
post authorization succeeds. Pointer matches require equal class, observed
bytes within inclusive minimum and maximum, and exact query
check set. Observation constructors reject a missing, category-inappropriate,
or extra check; no evidence can compensate for another attachment's check.

### Exact observer boundary and opacity

```go
type BindingSource interface {
    ObserveBinding(BindingQuery) (BindingObservation, error)
}
type PreObservationSource interface {
    ObserveState(StateQuery) (StateObservation, error)
    ObserveFD(FDQuery) (FDObservation, error)
    ObservePointer(PointerQuery) (PointerObservation, error)
    ObserveObject(ObjectQuery) (ObjectObservation, error)
}
type PostObservationSource interface {
    ReinspectObject(ObjectQuery) (ObjectObservation, error)
}

type StateQuery struct { query *stateQuery; owner *policyOwner }
type FDQuery struct { query *fdQuery; owner *policyOwner }
type PointerQuery struct { query *pointerQuery; owner *policyOwner }
type ObjectQuery struct { query *objectQuery; owner *policyOwner }
type StateObservation struct { observation *stateObservation; owner *policyOwner }
type FDObservation struct { observation *fdObservation; owner *policyOwner }
type PointerObservation struct { observation *pointerObservation; owner *policyOwner }
type ObjectObservation struct { observation *objectObservation; owner *policyOwner }
type BindingQuery struct { query *bindingQuery; owner *policyOwner }
type BindingObservation struct { observation *bindingObservation; owner *policyOwner }

func NewStateObservation(StateQuery, State, CheckSet) (StateObservation, error)
func NewFDObservation(FDQuery, int32, DescriptorKind, DescriptorAccess, [32]byte, bool, CheckSet) (FDObservation, error)
func NewPointerObservation(PointerQuery, PointerClass, uint32, CheckSet) (PointerObservation, error)
func NewObjectObservation(ObjectQuery, int32, DescriptorKind, DescriptorAccess, [32]byte, CheckSet, bool) (ObjectObservation, error)
func NewBindingObservation(BindingQuery, DescriptorKind, DescriptorAccess, [32]byte) (BindingObservation, error)
```

`NewAdapterBindings` is the only constructor. It rejects nil/typed-nil source
before ticket ownership, emits one query per ascending unique live-bound slot,
and stops on the first error. Requirements sharing a slot must have identical
kind/access or import rejects contradiction. `BindingQuery` exposes `Slot`,
`ExpectedKind`, `ExpectedAccess`, `TicketSHA256`,
`PermitCorrelationSHA256`, and `SHA256`.
`BindingObservation` exposes `Slot`, `Kind`, `Access`, nonzero
`GenerationSHA256`, `PermitCorrelationSHA256`, and `QuerySHA256`; its
constructor accepts well-formed
mismatch evidence but rejects zero generation. Every exact observation is
copied into an immutable record. A zero/foreign observation or wrong query
digest is `ErrorCodeObservation`; source error is sanitized likewise. A
well-formed kind/access mismatch is retained as negative evidence so
`AuthorizePre` returns the rule failure decision with nil error. Zero bindings are
valid only when the ticket has no live-bound requirement and return a nonzero
ticket-owned empty snapshot.

Each successful constructor allocates one private `adapterBindingOwner` token,
stores it in the snapshot, and later copies it into the permit. The token participates only in exact opaque ownership identity checks by D2 and the sole D4 wrapper. It never enters canonical or semantic rule equality, a digest or preimage, formatter, view, serialization, or decision outcome. A failed identity check returns zero decision plus
`ErrorCodeOwnership` before semantic evaluation; it does not select or alter a
rule result. Two
separately constructed snapshots over identical observations therefore have
identical canonical bytes and decisions but distinct unforgeable operation
ownership. D2 validates policy/ticket/snapshot ownership; the sole D4 wrapper
retains the snapshot and its token for one operation and never accepts a
snapshot produced by another wrapper. This is the operation boundary; no
caller-supplied operation ID or proof claim exists.

| `NewAdapterBindings` condition | Bindings | Error |
|---|---|---|
| nil or typed-nil `BindingSource` | zero | `ErrorCodeTypedNil` |
| zero/foreign/mismatched ticket | zero | `ErrorCodeOwnership` |
| source error or zero/foreign/wrong-query observation | zero | `ErrorCodeObservation` |
| every returned observation is well formed, including mismatch evidence | nonzero immutable snapshot | nil |

Each binding-query digest uses domain
`hal/l8/adapter-binding-query/linux-amd64/v1` over artifact digest, ticket
digest, permit correlation, slot, expected kind, and expected access. The
`AdapterBindingView.SHA256` digest uses domain
`hal/l8/adapter-binding/linux-amd64/v1` over permit correlation and the complete
record. Its correlation accessor equals the enclosing snapshot and permit.
The
snapshot digest uses domain `hal/l8/adapter-bindings/linux-amd64/v1` over
artifact digest, ticket digest, permit correlation, record count, and ascending complete records
`slot:u8, kind:u8, access:u8, reserved:u8=0, generationSHA256:[32]byte`.
`AuthorizePre` requires the same-policy/ticket snapshot even when empty, copies
resolved generations into the permit, and compares each live-bound observation
against its slot. A snapshot cannot be used for another ticket or policy; its
private operation owner is copied into the permit and is kept inside the one
D4 wrapper that constructed it. D4 allocates that private inert `unstarted`
wrapper before `NewAdapterBindings`; the wrapper is the sole production
`BindingSource`, derives generations from its trusted operation-scoped ledger
snapshot, and exclusively retains the exact returned opaque bindings value.
It never accepts a caller generation, proof claim, replacement wrapper,
cross-wrapper snapshot, or foreign bindings. Binding or pre-authorization
failure synchronously destroys the inert identity; successful pre authorization
copies the binding owner into the permit installed in the same identity before
claim. Package tests may use fakes;
D4/D6 import/source guards forbid any second production source or durable
serialization.

Queries are minted only by `AuthorizePre` or `AuthorizePost` and bind the
independent permit correlation, phase, and ordinal. They never contain the
permit digest. Pre can mint only state, FD,
pointer, and argument-object queries; post can mint only return-object queries.
`StateQuery` accessors are `ExpectedRole`, `ExpectedStage`,
`RequiredFacts`, `ProhibitedFacts`, `RequiredChecks`, and `RuleSHA256`. `FDQuery` adds
`ArgumentIndex`, `FDNumber`, `ExpectedKind`, `ExpectedAccess`,
`ExpectedGenerationSHA256`, `GenerationMode`, `BindingSlot`, `Fixed`, and
`RequiredChecks`. `PointerQuery` adds
`ArgumentIndex`, `ExpectedClass`, `MinimumBytes`, `MaximumBytes`, and `RequiredChecks`.
`ObjectQuery` adds `ArgumentIndex`, `ExpectedKind`, `ExpectedAccess`,
`Source`, `ExpectedNumber`, `ExpectedGenerationSHA256`, `GenerationMode`,
`BindingSlot`, `Fixed`, and `RequiredChecks`. Every query also has
`Kind() QueryKind` and `SHA256() [32]byte`; the latter is the domain-framed
digest of the exact canonical bytes below. Every query also has
`PermitCorrelationSHA256() [32]byte`, `Phase() AdapterPhase`, and
`Ordinal() uint16`. The private
owner pointer is checked separately and never enters canonical bytes.
Every canonical query starts with
`permitCorrelationSHA256:[32]byte, phase:u8, queryKind:u8, ordinal:u16,
ruleSHA256:[32]byte`. Its kind-specific suffix and digest domain are exact:

| Kind/domain | Canonical suffix |
|---|---|
| State / `hal/l8/adapter-state-query/linux-amd64/v1` | `expectedRole:u8, expectedStage:u8, reserved:u16=0, requiredFacts:u64, prohibitedFacts:u64, requiredChecks:u32, reserved:u32=0` |
| FD / `hal/l8/adapter-fd-query/linux-amd64/v1` | `argumentIndex:u8, expectedKind:u8, expectedAccess:u8, fixed:u8, fdNumber:i32, generationMode:u8, bindingSlot:u8, reserved:u16=0, requiredChecks:u32, expectedGenerationSHA256:[32]byte` |
| Pointer / `hal/l8/adapter-pointer-query/linux-amd64/v1` | `argumentIndex:u8, expectedClass:u8, reserved:u16=0, minimumBytes:u32, maximumBytes:u32, requiredChecks:u32` |
| Object / `hal/l8/adapter-object-query/linux-amd64/v1` | `source:u8, argumentIndex:u8, expectedKind:u8, expectedAccess:u8, fixed:u8, generationMode:u8, bindingSlot:u8, reserved:u8=0, expectedNumber:i32, requiredChecks:u32, expectedGenerationSHA256:[32]byte` |

The digest is `SHA256(u16be(len(domain)) || domain || canonicalQueryBytes)`.
All fields are big-endian. State, FD, pointer, and argument-object queries have
phase pre; return-object queries have phase post. ObjectSourceReturn uses `argumentIndex=255` and `expectedNumber=-1`; every other negative number or source/index/phase combination is invalid. A fresh-return object query has mode
fresh-return, slot zero, and zero expected generation; static/live queries use
their exact nonzero generation semantics. Query ordinal is zero-based within
its phase and canonical observer order. The exact layouts and distinct domains
prevent cross-kind reinterpretation.

```go
func (query StateQuery) ExpectedRole() Role
func (query StateQuery) ExpectedStage() Stage
func (query StateQuery) RequiredFacts() StateFact
func (query StateQuery) ProhibitedFacts() StateFact
func (query StateQuery) RequiredChecks() CheckSet
func (query StateQuery) RuleSHA256() [32]byte
func (query StateQuery) Kind() QueryKind
func (query StateQuery) PermitCorrelationSHA256() [32]byte
func (query StateQuery) Phase() AdapterPhase
func (query StateQuery) Ordinal() uint16
func (query StateQuery) SHA256() [32]byte
func (query FDQuery) ArgumentIndex() uint8
func (query FDQuery) RuleSHA256() [32]byte
func (query FDQuery) FDNumber() int32
func (query FDQuery) ExpectedKind() DescriptorKind
func (query FDQuery) ExpectedAccess() DescriptorAccess
func (query FDQuery) ExpectedGenerationSHA256() [32]byte
func (query FDQuery) GenerationMode() GenerationMode
func (query FDQuery) BindingSlot() uint8
func (query FDQuery) Fixed() bool
func (query FDQuery) RequiredChecks() CheckSet
func (query FDQuery) Kind() QueryKind
func (query FDQuery) PermitCorrelationSHA256() [32]byte
func (query FDQuery) Phase() AdapterPhase
func (query FDQuery) Ordinal() uint16
func (query FDQuery) SHA256() [32]byte
func (query PointerQuery) ArgumentIndex() uint8
func (query PointerQuery) RuleSHA256() [32]byte
func (query PointerQuery) ExpectedClass() PointerClass
func (query PointerQuery) MinimumBytes() uint32
func (query PointerQuery) MaximumBytes() uint32
func (query PointerQuery) RequiredChecks() CheckSet
func (query PointerQuery) Kind() QueryKind
func (query PointerQuery) PermitCorrelationSHA256() [32]byte
func (query PointerQuery) Phase() AdapterPhase
func (query PointerQuery) Ordinal() uint16
func (query PointerQuery) SHA256() [32]byte
func (query ObjectQuery) ArgumentIndex() uint8
func (query ObjectQuery) RuleSHA256() [32]byte
func (query ObjectQuery) Source() ObjectSource
func (query ObjectQuery) ExpectedNumber() (int32, error)
func (query ObjectQuery) ExpectedKind() DescriptorKind
func (query ObjectQuery) ExpectedAccess() DescriptorAccess
func (query ObjectQuery) ExpectedGenerationSHA256() [32]byte
func (query ObjectQuery) GenerationMode() GenerationMode
func (query ObjectQuery) BindingSlot() uint8
func (query ObjectQuery) Fixed() bool
func (query ObjectQuery) RequiredChecks() CheckSet
func (query ObjectQuery) Kind() QueryKind
func (query ObjectQuery) PermitCorrelationSHA256() [32]byte
func (query ObjectQuery) Phase() AdapterPhase
func (query ObjectQuery) Ordinal() uint16
func (query ObjectQuery) SHA256() [32]byte
func (query BindingQuery) Slot() uint8
func (query BindingQuery) ExpectedKind() DescriptorKind
func (query BindingQuery) ExpectedAccess() DescriptorAccess
func (query BindingQuery) TicketSHA256() [32]byte
func (query BindingQuery) PermitCorrelationSHA256() [32]byte
func (query BindingQuery) SHA256() [32]byte
```

The observation accessors are exact. `StateObservation` has `Actual() State`,
`Checks() CheckSet`, and `QuerySHA256() [32]byte`. `FDObservation` has `Number() int32`,
`Kind() DescriptorKind`, `Access() DescriptorAccess`,
`GenerationSHA256() [32]byte`, `Fixed() bool`, `Checks() CheckSet`, and
`QuerySHA256() [32]byte`. `PointerObservation` has `Class() PointerClass`,
`Bytes() uint32`, `Checks() CheckSet`, and `QuerySHA256() [32]byte`.
`ObjectObservation` has `Number() int32`, `Kind() DescriptorKind`,
`Access() DescriptorAccess`, `GenerationSHA256() [32]byte`, `Fixed() bool`,
`Checks() CheckSet`, and `QuerySHA256() [32]byte`.
`ObjectQuery.ExpectedNumber` returns the verified scalar-converted nonnegative
number for `ObjectSourceArgument` and the exact `-1` sentinel for
`ObjectSourceReturn`, both with nil error. It returns
`ErrorCodeInvalidArgument` only for an invalid/zero query. The sentinel never
matches an observation number; the returned nonnegative number exists only
after the syscall and is supplied by the captured D4 post source.

```go
func (observation StateObservation) Actual() State
func (observation StateObservation) Checks() CheckSet
func (observation StateObservation) QuerySHA256() [32]byte
func (observation FDObservation) Number() int32
func (observation FDObservation) Kind() DescriptorKind
func (observation FDObservation) Access() DescriptorAccess
func (observation FDObservation) GenerationSHA256() [32]byte
func (observation FDObservation) Fixed() bool
func (observation FDObservation) Checks() CheckSet
func (observation FDObservation) QuerySHA256() [32]byte
func (observation PointerObservation) Class() PointerClass
func (observation PointerObservation) Bytes() uint32
func (observation PointerObservation) Checks() CheckSet
func (observation PointerObservation) QuerySHA256() [32]byte
func (observation ObjectObservation) Kind() DescriptorKind
func (observation ObjectObservation) Number() int32
func (observation ObjectObservation) Access() DescriptorAccess
func (observation ObjectObservation) GenerationSHA256() [32]byte
func (observation ObjectObservation) Fixed() bool
func (observation ObjectObservation) Checks() CheckSet
func (observation ObjectObservation) QuerySHA256() [32]byte
func (observation BindingObservation) Slot() uint8
func (observation BindingObservation) Kind() DescriptorKind
func (observation BindingObservation) Access() DescriptorAccess
func (observation BindingObservation) GenerationSHA256() [32]byte
func (observation BindingObservation) PermitCorrelationSHA256() [32]byte
func (observation BindingObservation) QuerySHA256() [32]byte
```

Each observation constructor rejects a zero/foreign query, invalid actual
state, a negative FD, unknown enum, a zero observation generation for every FD
or object query, an unknown check bit, or a check set that is missing mandatory bits or contains
an extra/category-inappropriate bit. Unknown enum/check returns
`ErrorCodeCatalog`; missing/extra/inappropriate checks return
`ErrorCodeInvalidArgument`. For a static/live FD or object query it requires a
nonzero observation generation (a mismatch remains valid negative evidence).
For a fresh-return object query it requires source return, zero query expected
generation, and nonzero observation generation. Pointer byte count is already a bounded `uint32`; the
constructor accepts zero and values outside the query interval as well-formed
negative evidence. It does not
reject a well-formed mismatch: mismatch observations are required negative
evidence for the matching authorization phase. It copies the actual scalar metadata, preserves the
query owner and digest, and cannot attach to another query. Both authorization phases reject
a zero/foreign observation or query-digest mismatch as
`ErrorCodeObservation`; a valid mismatch returns the rule's failure outcome
with nil error. Observations expose only the safe accessors above; they never
expose a path, pointer, payload, argv/environment, credential, PID authority,
or live handle. D4 can inspect a query and mint a bound observation, but cannot
mint a query, ticket, or permit.

The complete opaque set is `CheckSet`, `ExpectedPolicyArtifact`,
`VerifiedPolicyArtifact`, `WorkloadSnapshot`, `WorkloadRuleView`,
`RuntimeProfileView`, `CatalogEntryView`, `MandatoryEvidenceView`, `RuleView`,
`FilterRuleView`, `FilterProfile`, `ScalarClauseView`,
`DescriptorRequirementView`, `PointerRequirementView`,
`ObjectRequirementView`, `TransitionView`, `PinnedCallsiteRequirementView`,
`ExpectedPinnedCallsiteEvidence`, `PinnedBinaryBindingView`,
`PinnedBinaryBindingSet`, `PinnedCallsiteEvidenceSet`,
`PinnedCallsiteEvidenceView`, `Policy`, `State`, `FilterInput`,
`Classification`, `FilterDecision`, `Decision`, `AdapterDecision`,
`AdapterTicket`, `AdapterPermit`, `AdapterBindings`, `AdapterBindingView`, every
binding/state/FD/pointer/object query, every corresponding observation,
`AdapterFixtureView`, and `GoldenCase`. Every one defines this exact
value-receiver method set:

```go
String() string
GoString() string
Format(fmt.State, rune)
MarshalJSON() ([]byte, error)
MarshalText() ([]byte, error)
MarshalBinary() ([]byte, error)
```

and this exact pointer-receiver method set:

```go
UnmarshalJSON([]byte) error
UnmarshalText([]byte) error
UnmarshalBinary([]byte) error
```

For a value or nonnil pointer, all formatting verbs emit only
`syscallpolicy.live[redacted]`, ignoring width, precision, flags, and verb.
Every marshal/unmarshal method returns `ErrorCodeInvalidArgument`, returns no
bytes, and does not mutate. As fixed Go standard-library behavior, formatting a nil pointer emits the static token `<nil>` and `encoding/json` marshals it as `null` without calling the value method; both contain no graph data. Public D2
APIs reject typed-nil inputs before any method call. Direct invocation of a
value-receiver method through a nil pointer is outside the API because Go
panics before method entry; tests guard the supported fmt/json behavior and all
nonnil methods explicitly.

The closed scalar types `Role`, `Stage`, `StateFact`, `Action`, `Reason`,
`DescriptorKind`, `DescriptorAccess`, `Check`, `PointerClass`,
`AdapterOutcome`, `AdapterReason`, `AdapterPhase`, `ErrorCode`, `SyscallNumber`,
`SyscallClass`, `EvidenceKind`, `RuleOrigin`, `ScalarOperation`, `ABIClass`,
`ObjectSource`, `QueryKind`, `EnforcementPath`, `GenerationMode`,
`BinaryBindingKind`, `GoldenKind`, `GoldenExpectation`, and `MutationKind` have
exact safe `String`, `GoString`, and `Format` methods.
Known values use the lowercase identifier token frozen by their catalog;
unknown values use `"unknown"`; pointers format identically and nil pointers
use `<nil>`. `StateFact` joins a valid combination's set-bit tokens with `|` in
bit order. `SyscallNumber` formats every value as unsigned base-10 because
catalog membership is policy-scoped, not global. These numeric types expose no
custom JSON/text/binary codec: `encoding/json` uses the underlying unsigned
number (and `null` for a nil pointer), numeric JSON unmarshal uses Go's standard
range checks, and they do not implement `encoding.TextMarshaler`,
`encoding.TextUnmarshaler`, `encoding.BinaryMarshaler`, or
`encoding.BinaryUnmarshaler`; callers must run the named validator afterward.
`ContractError` has only
its error methods plus the same redacted formatting and marshal rejection as
the opaque set. No formatter or error embeds an underlying observer error.
Constructors copy slices before validation. Unknown, duplicate, nil, and
typed-nil inputs fail without mutation or observer calls.

### Decisions, fingerprints, and generated cases

`Policy.Decide` never calls an observer. A nil policy, invalid input, or state
that names no artifact role/stage returns kill/impossible-transition. It then
classifies foreign, x32, unknown/unassigned/above-ceiling, and catalog-fatal in
that order and returns the corresponding kill reason. For a known nonfatal
number it applies these exact steps:

1. if no artifact rule for the number exists, return errno/known-unlisted;
2. if rules exist but none in the input role, return errno/wrong-role;
3. retain every direct or pinned-direct row in the role regardless of input
   stage/facts; retain an adapter row only in its exact stage with every
   effective stage-plus-rule required fact present and every effective
   stage-plus-rule prohibited fact absent; if neither remains, return
   errno/state-mismatch;
4. evaluate all remaining rules without observer calls; an exact scalar match
   wins over every mismatch and returns allow/exact, plus a bound ticket only
   for an adapter-path rule;
5. if none matches, collect every failing clause from every remaining candidate;
   choose kill if any collected clause has kill action, otherwise errno; then
   choose the lexicographically first canonical rule containing a failing
   clause of that action and its lowest argument-index failing clause of that
   action. Return that clause's frozen reason and selected rule digest. A
   fixed-FD scalar mismatch uses `ReasonFDMismatch`; every other scalar mismatch
   uses its canonical reason.

The three denial authorities are separate. Raw `FilterProfile.Decide` has no
state or ticket and follows only architecture/x32/catalog/scalar precedence.
Semantic `Policy.Decide` adds role/stage/fact selection and issues a nonzero
ticket only for an exact `EnforcementPathAdapter` allow. Exact direct,
pinned-direct, and scalar-only workload allows have a nonzero rule digest and
zero ticket; their `Decision.Ticket` returns ownership. Pointer observation
mutations leave the raw filter result unchanged and deny through adapter
authorization; pinned-callsite mutations fail HL8E import/readiness instead;
scalar-only workload rows make no provenance claim. Transition authority is
only `ValidateTransition`: it evaluates state/FSM invariants, returns no rule
digest or ticket, and never applies raw-filter mismatch precedence or mutates
state.

The constructor failure precedence is exact. `NewPolicy` checks nonnil imported
graph, nonzero artifact digest, the package-private verified marker, then the
copied-graph digest.
`NewState` checks role, stage, then unknown fact bits. `NewFilterInput` checks
state validity only. `NewCheckSet` scans caller order and reports the first
unknown check before the first duplicate. Observation constructors check query
validity/ownership, scalar bounds, enum validity, generation/check-set grammar,
then bind a copy. `Fingerprint` and `Rules` check nil/foreign policy before
role. `AuthorizePre` checks nil or typed-nil source before ticket ownership;
`AuthorizePost` checks nil or typed-nil source before permit ownership;
commit/abort check permit ownership first, and abort validates its phase only
after ownership succeeds. Each then
uses its fixed phase observer order above. No failure invokes a later check, mutates
state, or returns dynamic input in its error.
On a nil policy, `Decide` and `ValidateTransition` return
kill/impossible-transition, `Classify` reports the architecture but `Known`
false, `GoldenCases` returns a nonnil empty slice, and the error-returning
methods return `ErrorCodeOwnership`.

| Constructor/accessor failure | Error code |
|---|---|
| `NewPolicy` zero/foreign graph or verified marker | `ErrorCodeOwnership` |
| `NewPolicy` copied digest mismatch | `ErrorCodeDigestMismatch` |
| `NewState` unknown role/stage/fact bit | `ErrorCodeCatalog` |
| `NewFilterInput` invalid state | `ErrorCodeInvalidArgument` |
| `FilterInput.Argument` index > 5 | `ErrorCodeBounds` |
| `NewCheckSet` unknown check / duplicate | `ErrorCodeCatalog` / `ErrorCodeDuplicate` |
| observation zero/foreign query | `ErrorCodeOwnership` |
| observation negative FD | `ErrorCodeBounds` |
| observation unknown enum/check | `ErrorCodeCatalog` |
| observation missing/extra/category-inappropriate check | `ErrorCodeInvalidArgument` |
| observation invalid generation for query mode or invalid state | `ErrorCodeInvalidArgument` |
| `Rules`/`Fingerprint` nil policy / unknown role | `ErrorCodeOwnership` / `ErrorCodeCatalog` |
| `Decision.Ticket` without a nonzero Decide-issued ticket | `ErrorCodeOwnership` |

```go
type MutationKind uint8
type GoldenKind uint8
type GoldenExpectation uint8
const (
    GoldenKindSemantic GoldenKind = 1
    GoldenKindFilter GoldenKind = 2
    GoldenExpectationDecision GoldenExpectation = 1
    GoldenExpectationConstructorError GoldenExpectation = 2
)
func ValidateGoldenKind(GoldenKind) error
func ValidateGoldenExpectation(GoldenExpectation) error
type GoldenCase struct { golden *goldenCase }
type AdapterFixtureView struct { fixture *adapterFixture }
func ValidateMutationKind(MutationKind) error
func (golden GoldenCase) SHA256() [32]byte
func (golden GoldenCase) Positive() bool
func (golden GoldenCase) Kind() GoldenKind
func (golden GoldenCase) Expectation() GoldenExpectation
func (golden GoldenCase) Mutation() MutationKind
func (golden GoldenCase) Input() FilterInput
func (golden GoldenCase) AdapterFixture() AdapterFixtureView
func (golden GoldenCase) SyscallName() string
func (golden GoldenCase) RuleSHA256() [32]byte
func (golden GoldenCase) Action() Action
func (golden GoldenCase) Reason() Reason
func (golden GoldenCase) AdapterOutcome() AdapterOutcome
func (golden GoldenCase) AdapterReason() AdapterReason
func (golden GoldenCase) AdapterPhase() AdapterPhase
func (golden GoldenCase) AdapterFinal() bool
func (golden GoldenCase) ExpectedErrorCode() (ErrorCode, error)
func (golden GoldenCase) RequiredChecks() []Check
func (golden GoldenCase) CanonicalBinary() []byte
func (golden GoldenCase) TSV() string
func (fixture AdapterFixtureView) CanonicalBinary() []byte
```

`GoldenCase` is a safe immutable view. Its canonical binary v2 is exactly
`"HL8G", version:u8=2, kind:u8, mutation:u8, role:u8, stage:u8,
auditArchitecture:u32, rawSyscallNumber:u32, arguments:[6]u64,
ruleSHA256:[32]byte, action:u32, reason:u8, adapterOutcome:u8,
adapterReason:u8, adapterPhase:u8, adapterFinal:u8, positive:u8,
expectation:u8, expectedErrorCode:u8, requiredCheckBits:u32,
adapterFixtureLength:u16, reserved:u16=0`, followed by the fixture bytes; all
multibyte values are big-endian. `positive` is zero or one. A positive has
`mutation=0`; `ValidateMutationKind` still rejects zero because it validates a
mutation request, while `Positive()` is the authoritative discriminator.
`GoldenExpectationDecision` requires zero expected-error code and carries the
decision fields. `GoldenExpectationConstructorError` requires a known nonzero
expected-error code and zero action/reason/adapter fields; it means the named
observation constructor rejects before an observation exists.
`ExpectedErrorCode()` succeeds only for constructor-error expectation and
otherwise returns `ErrorCodeInvalidArgument` as its Go error.
Semantic cases use the exact rule state and may carry adapter fixtures. Filter
cases use the profile role, `stage=0`, no adapter fixture, and the
`FilterProfile.Decide` action/reason; stage zero is an absent fixture field,
not a valid `Stage`.
For a direct or pinned-direct rule case the adapter outcome, reason,
required-check bits, and fixture length are all zero and no adapter mutation is
generated. Zero is an
absent golden-field sentinel here, not a valid `AdapterOutcome` or
`AdapterReason`. Adapter-rule positives store the final post/proceed/exact
decision (including the synthetic post phase returned by `CommitNoObject`) and
the fixture below; generation separately proves prerequisite pre/proceed/exact
readiness.

Adapter fixture bytes are exact: state is `role:u8, stage:u8, reserved:u16=0,
facts:u64, checks:u32`; then
`bindingCount:u8, fdCount:u8, pointerCount:u8, objectCount:u8`.
Binding records are `slot:u8, kind:u8, access:u8, reserved:u8=0,
generationSHA256:[32]byte`.
FD records are `argumentIndex:u8, kind:u8, access:u8, fixed:u8,
generationMode:u8, bindingSlot:u8, reserved:u16=0, number:i32, checks:u32,
generationSHA256:[32]byte`; pointer records are
`argumentIndex:u8, class:u8, reserved:u16=0, bytes:u32, checks:u32`; object
records are `source:u8, argumentIndex:u8, kind:u8, access:u8, fixed:u8,
generationMode:u8, bindingSlot:u8, reserved:u8=0, number:i32, checks:u32,
generationSHA256:[32]byte`. Counts are each at
most six and records sort by source/argument. The positive fixture exactly
satisfies every query: expected state, exact FD scalar/kind/access/fixed/
generation/checks, minimum pointer bytes with exact class/checks, and exact object
metadata/checks. Static-exact fixture generations equal the artifact row;
live-bound fixture generations are first supplied by the binding record and
then copied into the matching pre observation; fresh-return generations exist
only in the return-object post observation. Synthetic non-static fixture
generations use the standard framing with domain
`hal/l8/golden-generation/linux-amd64/v1` over artifact digest, rule digest,
generation mode, evidence kind, and attachment index. A mutation changes one field in these bytes, making adapter
diff cardinality mechanically checkable.

`SHA256` uses the standard length framing with domain
`hal/l8/syscall-golden/linux-amd64/v1` and those bytes; it is not included in
the bytes. The human-readable TSV is exactly the lowercase-hex case digest,
mutation decimal, expectation string, expected-error string or `none`, role
string, stage string, syscall name, syscall number decimal, action string,
reason string, adapter outcome string, adapter reason string, and comma-joined
ascending check strings, separated by one tab and terminated by LF. It contains
no raw pointer, payload, path, credential, PID, or live observation.

`MutationKind` values are
`MutationSyscall=1`, `MutationArchitecture=2`, `MutationX32=3`,
`MutationRole=4`, `MutationState=5`, `MutationFixedFD=6`,
`MutationTransientKind=7`, `MutationGeneration=8`, `MutationFlagBit=9`,
`MutationEnum=10`, `MutationCloneField=11`, `MutationMountCommand=12`,
`MutationSocketFamilyType=13`, `MutationSignal=14`,
`MutationWaitOption=15`, `MutationPathClass=16`, `MutationBounds=17`,
`MutationReservedByte=18`, `MutationSequence=19`, and
`MutationReinspection=20`, and `MutationStage=21`.

The catalog endpoints are exactly `MutationSyscall MutationKind = 1` and
`MutationStage MutationKind = 21`; the intervening values are the contiguous
catalog above.

`Policy.GoldenCases` returns one positive per canonical rule in rule order.
`GeneratePlusOne(VerifiedPolicyArtifact) ([]GoldenCase, error)` emits each
semantic positive followed by applicable mutations in numeric `MutationKind`
order, then the effective `FilterProfile` positives/mutations in role and
filter-rule order. A semantic filter-input mutation searches until the first candidate for which `Policy.Decide` denies; an effective compiler mutation
searches until `FilterProfile.Decide` denies. Each changes exactly one named
input field and uses closed candidates in ascending canonical order. Syscall candidates are every pinned catalog
number then ceiling+1; architecture candidates are foreign zero then native
x32; role candidates are all other roles; state candidates are every known
13-bit fact mask except the positive; all are ascending after the explicitly
ordered architecture pair.

For each rule containing both kill and EPERM clauses, the generator uses the
same exact predicate solver to select the lexicographically lowest complete
input that fails at least one clause of each action and is not accepted by an
alternative rule. It emits a dual-action failure fixture whose expected result
is the globally selected kill clause. If no production rule has both actions,
the package test artifact must contain one disjoint synthetic rule solely to
lock this precedence; it cannot enter embedded production bytes.

For one scalar argument, D2 finds the lowest unsigned value different from the
positive for which no same-role/stage/state alternative rule accepts the
complete six-word input. It uses the same exact memoized MSB-to-LSB predicate
search as overlap proof with an additional `different` bit and chooses zero
before one. Named scalar mutation kinds constrain that search to their semantic
category. In particular, `MutationFlagBit` first tries, from low to high, each
bit material to the clause predicate; for `ScalarMaskedEqual` it flips the lowest set bit of the clause mask, never an excluded bit. Enum/clone/mount/
socket/signal/wait mutations exclude the allowed finite set; bounds searches
outside the inclusive range; fixed-FD searches `0..math.MaxInt32` excluding the
fixed value. If an alternate rule accepts a candidate, search continues rather
than emitting a false negative.

Adapter mutations change exactly one observation field for the Decide-issued
ticket in exactly one phase and require `AuthorizePre` or `AuthorizePost` to
return a final denial: pre kinds use the ascending closed enum,
generation flips digest bits from 0 through 255, path class uses the ascending
closed enum, bounds tries `minimumBytes-1` then `maximumBytes+1` without
under/overflow, and reserved/sequence remove the named pre check/fact.
Live-bound binding mutations first change one binding kind/access field and
require `AuthorizePre` to deny before any observer; observation-generation
mutations retain the positive binding snapshot and change only the observed
generation. A fresh-return mutation changes only the post-observed generation;
it never publishes a generation to the ledger on denial.
Reinspection is a post mutation removing
`CheckPostSuccessReinspection`; post generation/kind/object mutations call
`AuthorizePost` with the unchanged pre permit. A positive always proves
`AuthorizePre.Ready`, then either `AuthorizePost.Authorized` or
`CommitNoObject.Authorized`; no-object rules invent no post source or live call.
Mandatory-check removal and every extra/category-inappropriate check are not
negative observations: the exact observation constructor rejects them with
`ErrorCodeInvalidArgument`, so their golden cases use
`GoldenExpectationConstructorError`. A well-formed kind, access, generation,
state, pointer-byte, or object mismatch constructs successfully and uses
`GoldenExpectationDecision` with the exact authorization denial. The generator
fails if the observed result/error channel differs from the declared
expectation.

D4's wrapper lifecycle plus-one matrix is a separate deterministic fake-only
gate over the exact four-state catalog. Its positives are: pre-syscall cancel
and pre-syscall wrapper failure each visit `unstarted,claimed,finalized`, call
`AbortPermit(permit, AdapterPhasePre)` once with the exact same permit, and call
the syscall closure zero times; returned-object
success visits all four states and calls the closure then `AuthorizePost` once;
no-object success visits all four states and calls the closure then
`CommitNoObject` once; syscall error and recovered syscall panic visit all four
states and call the closure then `AbortPermit(permit, AdapterPhasePost)` once
with the exact same permit. Every positive asserts no
other terminal D2 call and an exact stored final result.

The lifecycle plus-one negatives independently attempt execute and finalize
from `unstarted`; a second claim; cancellation, failure, execute, or execute
again after `claimed` has been consumed; a second syscall closure; retry after
syscall failure; pre abort from `executed`; post abort from `claimed`;
post/commit/abort in the wrong phase; every alternate terminal
call after one terminal call; and every public or private wrapper method after
`finalized`. A concurrent barrier case races every operation at `claimed` and
at `executed`. Each negative must return only the sanitized ownership failure,
leave the last legal state unchanged, keep syscall calls at zero before execute
or exactly one afterward, and keep the selected terminal-call count at zero or
exactly one. Tests fail if `unstarted -> executed`, `unstarted -> finalized`, a
retry, a second closure call, a second terminal call, observer activity, or a
permit escape is observed. These tests exercise only D4 fakes; they perform no
live syscall.

`MutationStage` is generated for every adapter rule whose exact stage is a
semantic gate. It searches every other declared stage for that role in numeric
order while keeping facts and scalars at the positive values and emits the
first `Policy.Decide` state denial. `MutationState` separately changes one fact
bit. Either mutation is omitted only after exhaustive declared-stage or known-
fact search proves no one-field denying candidate; a facts-only mutation never
stands in for a stage-only gate.
Because authorization targets one bound rule rather than
reselecting alternatives, those finite candidates are exhaustive. A mutation
kind is omitted only after its exact filter predicate search or finite adapter
candidate set proves no one-field denying value exists; search exhaustion is
not treated as success. Generation fails on resource-bound exhaustion, absent
positive, or any emitted accepted mutation; canonical diff cardinality is exactly one,
meaning one named semantic field. D2 derives cases only from verified rows;
it does not synthesize missing semantics or add a row.

Pinned-direct proof is not a live adapter fixture and does not pretend to be a
`Policy.Decide` input mutation. D7 must run the D2 HL8E importer over one
positive complete evidence set and one-at-a-time mutations of absent/extra
binding or evidence record, order, artifact digest, source-lock digest,
per-role binary digest, executable-text digest, binding-set digest, instruction
digest, text length, offset, duplicate tuple, and expected-set digest. The positive imports; every mutation rejects with the
first error category frozen by the evidence-import matrix above. D7 also runs
the emitted final-binary disassembly guard that proves there is no unlisted raw
callsite for the scalar allow. A missing evidence mutation is never reported as
a semantic golden allow.

### D7 guest/host digest handoff

The image/profile schema has one canonical HL8Q artifact and its external HL8E
evidence. Its `L8ProcessCompositionFacts` final six digest fields are exactly,
in order, `WorkloadSnapshotSHA256`, `RuntimeProfileSHA256`,
`PolicyArtifactSHA256`, `PolicySourceLockSHA256`,
`PolicyBinaryBindingSetSHA256`, and `PinnedCallsiteEvidenceSHA256`. The first two fields are immutable views derived from the sole HL8Q artifact, never
separate artifacts or independent authority. Manifest, provenance, final
inspection, and the evidence-fingerprint preimage carry all six in that order.
The host profile and lease additionally keep the latter four host-authority
bindings plus the measured rootfs image digest in their private
`policyAuthority verifiedL8PolicyAuthorityBindings`; profile/lease matching and
`PrepareLaunch` preservation compare or copy them internally, with no public
digest accessor.
The exact private field is `policyAuthority verifiedL8PolicyAuthorityBindings`.

The local-resolver `L8DistributionRequest` has final field
`PinnedCallsiteEvidence []byte`. It must be non-nil, nonempty, and at most 16
MiB. The resolver deep-snapshots `PinnedCallsiteEvidence` before hashing or
import, so caller mutation cannot affect verification. It imports only against
`EmbeddedVerifiedPolicyArtifact` and
`EmbeddedExpectedPinnedCallsiteEvidence`, retains no caller slice or imported
evidence graph after sealing, and accepts no caller-minted expectation. D7
passes its fixed HL8E output bytes. The seven-file distribution remains
unchanged.
The resolver retains no caller slice or imported evidence graph after sealing.

The host resolver does not trust the six process-composition strings as the
policy authority. After `EmbeddedVerifiedPolicyArtifact` and the copied
`ImportPinnedCallsiteEvidence` input succeed, it constructs the exact private
record in declared order:

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

Its six direct extraction expressions are
`artifact.Workload().SHA256()`, `artifact.Runtime().SHA256()`,
`artifact.SHA256()`, `artifact.SourceLockSHA256()`,
`evidence.BinaryBindings().SHA256()`, and `evidence.SHA256()`. It then decodes
and constant-time compares that full derived value against manifest, provenance, and final-inspection `ProcessComposition`, in that document order,
before issuance; final inspection independently repeats the complete six-field equality
against the derived value; document-to-document equality cannot
substitute for it. Digest syntax precedes correlation, and the first valid-
syntax mismatch returns the closed internal typed `correlation_mismatch`
without a digest or cause. `VerifyL8DistributionBundle` maps that result to
the exact sanitized resolver `asset_lock_mismatch` with field
`processComposition`, static message, and only `ErrAssetLockMismatch` unwrap.
Its tests mutate each of the six
fields in each of the three documents. The image-profile AST guard fixes every accessor receiver chain and
order plus all six accumulated `crypto/subtle.ConstantTimeCompare` calls;
mere disconnected accessor or comparison marker calls do not satisfy it.

The correlation helper also imports `assets/build` as `assetbuild` and its
exact `l8PolicyCompositionCorrelationMismatch` returns only an
`*assetbuild.L8ValidationError` with code `correlation_mismatch`, field
`processComposition`, nil index, and static internal error text. The helper is wired,
not merely present: the separately parsed exact issuer file
`localresolver/l8_distribution_verifier.go` contains the real
`VerifyL8DistributionBundle` and one contiguous top-level authority block. The
four document decoders and their immediate error returns are an ordered
prelude, allowing every existing pure document/parent/catalog/final-inspection
validation to finish before that block. The
success results from `EmbeddedVerifiedPolicyArtifact` and
`EmbeddedExpectedPinnedCallsiteEvidence` are checked separately; that exact
expected value is passed with the copied bytes and artifact to
`ImportPinnedCallsiteEvidence`. The resulting artifact and evidence are the exact receivers of
`deriveL8PolicyCompositionDigests`; the independently decoded manifest,
provenance, and final-inspection values are the exact validation operands; and
the controlling nonnil validation return passes through the exact
`classifyL8PolicyCompositionCorrelationError` and precedes every fingerprint, profile
seal, distribution seal, and successful return. The verifier mints no lease;
without a successful verified distribution, later `AcquireL8AssetLease` is
unreachable. Protected values are assigned once. Dead, unreachable, discarded, aliased, reassigned,
lookalike, or post-issuance validation fails the AST guard.
Package-wide parsed reference guards have no basename-wide allowlist: they
parse every production declaration and permit each protected fingerprint,
profile-seal, distribution-seal, and correlation-classifier reference only as
its one exact direct call in `VerifyL8DistributionBundle` after controlling
validation. Same-file/alternate-file helpers, wrappers, methods, closures,
`defer`, `go`, function values, shadows, aliases, and transitive calls fail at
the protected reference. The closed case-insensitive authority verb family is
`mint`, `new`, `create`, `construct`, `make`, `build`, `issue`, `seal`,
`acquire`, `prepare`, and `remint` when paired in one API name with a verified
L8 profile/distribution/lease type. That verifier cannot invoke any such API
or directly construct profile/distribution/lease authority. The closed owner
graph includes the exported profile/distribution/lease and their private
seal/policy-binding/profile-correlation/lease-correlation/lease-state owners.
Exact signature-locked seal/acquisition functions may construct only one
matching direct returned result; they cannot stage/copy/alias/cache/assign it,
place it in package/global/interface/container/channel/generic state, pass it
to an arbitrary helper, capture it in a closure/function value, or expose it
from a factory/alternate getter. Authority aliases and derived types are
forbidden.
The guard computes recursive authority-containing named-type/field closure
across every package file and build context. Pointers, arrays, maps, generic
containers, nested selectors, copies, returns, and arbitrary-helper arguments
retain taint; an added containing wrapper is outside the closed graph. Exactly
one all-build-context declaration with the frozen signature/receiver is
allowed for each designated profile sealer, distribution sealer, and lease
acquirer.
All definitions for each named type are retained across files and build tags;
mutually exclusive definitions are never collapsed.
Sorted deterministic fixed point analysis
conservatively unions them: any authority-bearing definition taints the name,
including through cycles, aliases, and generic instantiations. There is no
last-writer overwrite by map/source iteration.

The exact `localresolver/l8_distribution_verifier_test.go` product test owns a
parsed ordered 3x6 mutation table as a function-local
`[18]struct { document string; field string }`, not raw marker prose or a
package variable. Manifest, provenance, and final inspection are crossed with
the six declared fields in exact order. Before the loop, an exact valid fixture
must succeed through the real issuer, and every fresh per-tuple fixture must
succeed again before mutation. Every tuple independently decodes the three
documents into an exact ordered `[18]string` before/after snapshot and hashes
their canonical JSON semantics after zeroing only complete
`ProcessComposition` values, mutates the selected document/field to a
different valid 32-byte `0x01` digest, proves that selected index alone changed,
all other 17 remain identical, and all three non-policy semantic hashes remain
identical, calls the real issuer, asserts the exact mismatch, increments after that
assertion, and the executed count must equal exactly 18. Exact body/declaration
parsing rejects comments/strings, dead/cleared/missing/duplicate/wrong tables,
ignored dimensions, invalid/unchecked baseline, no-op/fixed/alternate mutator,
lying snapshot, missing/wrong-index/non-policy change proof, alternate issuer calls,
skip/continue, zero increments, and weak assertions. `unsafe`, `go:linkname`, assembly, reflection-based case
aliases, init mutation, and external case references cannot mutate or disable
the local array. Product absence remains allowed only while the
`syscallpolicy` package, exact correlation helper, exact issuer/test files, and
exact underlying fixture file are all absent; partial landing is closed. The
image-profile supplement freezes the complete exact anchor and mutation
topology.
The exact companion
`localresolver/l8_distribution_policy_composition_fixture_test.go` owns the
only all-build-context definitions of the underlying builder and mutator. The
builder materializes a complete request and requires real verifier success;
the mutator passes the exact request/document/field/replacement tuple to the
sole rewrite primitive. Parsed bodies and package-wide test-source guards
reject skip/`runtime.Goexit`, no-op, fixed-field, lookalike, argument-drop, and
build-tag duplicate bypasses. Initial/per-case success plus selected-only,
other-17, and
non-policy semantic equality make the proof non-vacuous.

D7 owns these exact repository paths:

```text
tools/microvm/l8/policy/roles-v1.yaml
tools/microvm/l8/policy/workload-v1.lock
tools/microvm/l8/policy/runtime-go1.25.7.lock
tools/microvm/l8/policy/catalog-xsys-v0.41.0.lock
tools/microvm/l8/policy/verified-syscall-policy.hl8q
tools/microvm/l8/policy/verified-syscall-policy.hl8q.sha256
tools/microvm/l8/policy/verified-syscall-policy.source-lock.sha256
tools/microvm/l8/policy/verified-pinned-callsites.hl8e
tools/microvm/l8/policy/verified-pinned-callsites.hl8e.sha256
internal/sandboxruntime/microvm/guestagent/syscallpolicy/artifact_expected_d7_gen.go
internal/sandboxruntime/microvm/guestagent/syscallpolicy/pinned_callsite_evidence_expected_d7_gen.go
```

Each `.sha256` file is exactly 64 lowercase hexadecimal bytes plus LF and no
filename: respectively the artifact, source-lock, and evidence-set digest.
`roles-v1.yaml` is D7's reviewed canonical role/FSM
and rule source; the three lock files bind the approved L4/L7 inputs, pinned Go
source, pinned x/sys source, and generator inputs without copying secret or
host data. D7 source-locks those files and the artifact generator. It writes
the canonical artifact and its two digests, generates the tagged guest source,
and builds all L8 guest binaries from phase-head source plus that single
source-locked artifact file. The guest generated source contains constants named
`embeddedVerifiedPolicyArtifactBytes` and
`embeddedVerifiedPolicyArtifactSHA256` and
`embeddedVerifiedPolicySourceLockSHA256`; the latter must equal the imported
artifact header. After the final binary exists, D7's source-locked resolver
produces the HL8E evidence and the host-only tagged expected-evidence source;
that source contains only `expectedPinnedCallsiteEvidenceSHA256` plus the
private issuer marker and is excluded from every guest binary. The D7 host
asset manifest and `VerifiedL8Profile` record exact fields
`policyArtifactSHA256`, `policySourceLockSHA256`,
`policyBinaryBindingSetSHA256`, `pinnedCallsiteEvidenceSHA256`, and
`imageSHA256`. The image manifest independently records the identical binary-
binding-set digest over every installed role binary; a singular generic guest
binary digest is not a substitute.
The guest binary does not receive or decode a host
`VerifiedL8Profile`; it verifies its embedded artifact against its independently
embedded expected artifact and source-lock digests before helper readiness.

The local resolver imports the evidence with the host-only expected marker,
checks its artifact/source-lock/binary correlation, and binds all five exact
fields above with the parent-profile and launch-descriptor digests when it
issues the opaque host `VerifiedL8Profile`. D4 guest startup and D6 host
composition remain disabled unless the embedded guest artifact is present and
the host profile independently matches the artifact, source-lock, complete
binary-binding-set, and evidence-set digests, and unless every pinned callsite
has matching final-binary evidence. Neither
side transmits the profile, artifact, or evidence over a guest protocol. A D2
default build, hand-authored digest, fake profile, missing generated source,
missing pinned evidence, or host/guest/image mismatch fails before readiness.

The neutral package and its default cross-platform test files have no `syscall`, `unsafe`, or
`golang.org/x/sys/unix` production import. The D7 generator parses the pinned
module source as data; neither the importer nor decision engine reads a file,
environment variable, clock, network, process, or host runtime.

## Descriptor roles

Descriptor authority is process-specific and fixed. Closing a fixed descriptor
does not authorize reusing its number for another object in that role.

| FD | PID1 launch supervisor | Controller | Service agent | Mount monitor | Workload shim |
|---:|---|---|---|---|---|
| 0-2 | Image-owned inert console/sinks. | Inert sinks. | Inert sinks. | Inert sinks. | Inspected stdin-read, stdout-write, stderr-write pipes after remap. |
| 3 | Controller supervisor endpoint. | Agent control endpoint. | Controller control endpoint. | Controller-monitor endpoint. | Native-only monitor namespace FD, closed before Go starts. |
| 4 | Delegated cgroup-v2 root. | PID1 supervisor endpoint. | Agent-supervisor seqpacket endpoint. | `verified_proc_root_fd`, revalidated procfs. | Reinspected workdir FD. |
| 5 | Pinned mount-monitor executable. | Minimal controller root. | Preopened v1 VSOCK listener, port 1024. | Fixed job mount-target `O_PATH|O_DIRECTORY`. | Pinned workload executable FD. |
| 6 | Pinned workload-shim executable. | Sealed bootstrap config, closed at commit. | Preopened v2 control VSOCK listener, port 1025. | Sealed monitor config, closed at commit. | Sealed controller-to-shim launch-block read FD; this is the complete shim config. |
| 7 | Verified proc root. | Agent pidfd after bootstrap. | Preopened v2 SSH-relay VSOCK listener, port 1026. | Self mount-namespace FD after exact lookup. | Supervisor start-gate read FD. |
| 8 | Fixed monitor mount-target root. | Active monitor endpoint or closed. | Closed. | Active tmpfs root or closed. | Closed. |
| 9 | Active job cgroup or closed. | Active monitor namespace or closed. | Closed. | Launch-only long-lived controller peer; sent once during readiness, then permanently closed. | Closed. |
| 10 | Active monitor pidfd or closed. | Closed. | Closed. | Launch-only PID1 bootstrap endpoint; one readiness send, then permanently closed. | Closed. |
| 11 | Closed; workload pidfds occupy recorded transient slots. | Closed. | Closed. | Closed. | Pinned executable after final remap for `execveat(11, "", ..., AT_EMPTY_PATH)`. |
| 12 | Preopened v1 VSOCK listener until agent transfer. | Closed. | Closed. | Closed. | Closed. |
| 13 | Preopened v2 control VSOCK listener until agent transfer. | Closed. | Closed. | Closed. | Closed. |
| 14 | Preopened v2 SSH-relay VSOCK listener until agent transfer. | Closed. | Closed. | Closed. | Closed. |
| 15 | Closed. | Closed. | Closed. | Closed. | Closed. |

Transient FDs are 16 through 255, consistent with the frozen maximum of 256
descriptors per role. A newly returned lower-numbered FD MUST be moved
with `dup3(..., O_CLOEXEC)` into an unused transient slot and the original
closed before it can enter helper state. Each transient slot has one recorded
kind and generation: regular file, directory, pipe end, pidfd, mount FD,
filesystem-context FD, connected/listening Unix socket, or connected/listening
VSOCK.
It is revalidated
after creation or receipt and immediately before every authority-bearing use.
Active fixed slots are populated only by a validated transient FD and are
cleared on rollback. No fixed or transient FD except 0, 1, 2, and the frozen L4
interpreter-script executable descriptor survives workload exec.

## Allowed syscall families

### PID1 launch bootstrap

`launch-bootstrap` is PID1 mode of the native role bootstrap. It runs before
any Go runtime, controller, agent, monitor, shim, or protocol input. Starting
from the image verifier's exact PID1 identity and protected L4/L7 base, its
closed native syscall loop may use fixed-descriptor operations plus `capget`,
`capset`, `prctl`, and the exact listener operations below only to:

1. drop every bounding capability outside the frozen six;
2. set permitted, effective, and inheritable sets to exactly those six;
3. raise exactly those same six ambient bits while the permitted/inheritable
   invariant holds;
4. set and lock `SECBIT_NOROOT` and `SECBIT_NO_CAP_AMBIENT_RAISE`, lock
   `SECBIT_KEEP_CAPS` and `SECBIT_NO_SETUID_FIXUP` off, set
   `PR_SET_DUMPABLE=0` and `PR_SET_NO_NEW_PRIVS=1`; and
5. create, bind, listen on, and reinspect exactly three nonblocking
   `AF_VSOCK/SOCK_STREAM|SOCK_CLOEXEC` listeners at CID any, fixed ports
   1024/1025/1026, fixed backlogs 64/1/4, and fixed PID1 FDs 12/13/14, then
   clear close-on-exec only for the immediate PID1 target handoff; and
6. read back every UID/GID, capability set, securebit, limit, listener property,
   and hardening property before stacking the exact `launch-base` filter and
   `execve`ing the fixed `hal-guest-init` target in the same PID.

Listener setup uses only native `socket`, `bind`, `listen`, `getsockopt`, and
`getsockname` with compiled structures and no caller input. The bootstrap never
connects, accepts, sends, or receives. A partial listener set is closed and boot
fails. After `launch-base` commits, no PID1 or child role can create or bind an
`AF_VSOCK` socket; only service-agent FDs 5, 6, and 7 can accept after the
agent's steady filter and composition commit.

After native commit and exec, `hal-guest-init` constructs and reinspects the
frozen descriptor table, anonymous seqpacket pairs, sealed config pipes,
workload gate pipes, delegated cgroup root, verified proc root, fixed mount
target, inherited VSOCK listeners, and image-profile-pinned executable identities
before readiness. Go PID1 immediately reinspects FDs 12..14 and restores
`FD_CLOEXEC` before any child launch. Only its exact agent `ForkExec` maps
copies to child FDs 5..7; the native agent retains them through its fixed second
exec and Go agent adds `FD_CLOEXEC` before admission. No credential body or
protocol/job-derived value exists at this point.
The bootstrap is one native thread and allocates no heap, starts no thread,
loads no dynamic object, and reads no external input. `hal-guest-init` starts
under the committed filter with every thread inheriting the same exact six
sets, verifies the state, and never changes a capability or securebit,
widens/replaces its filter, creates an unlisted FD kind, or returns to
`launch-bootstrap`. Failure exits the microVM before readiness.

### Controller bootstrap only

Controller mode of the native role bootstrap permits only the following
operations; after target exec the inherited `launch-base` admits the common Go
runtime family below only until Go main commits `steady-controller` before any
protocol read:

- `getsockopt(3..4, SOL_SOCKET, SO_TYPE|SO_DOMAIN|SO_PROTOCOL|SO_PASSCRED, ...)`
  and `setsockopt(3..4, SOL_SOCKET, SO_PASSCRED, one)`; all returned values are
  checked against the two fixed seqpacket roles;
- `fcntl(3..6, F_GETFD|F_SETFD|F_GETFL|F_DUPFD_CLOEXEC, ...)`, where `F_SETFD`
  may only add `FD_CLOEXEC`, and `dup3`/`close_range` only establish the table
  above and remove unrelated FDs;
- `getuid`, `geteuid`, `getgid`, and `getegid` only to verify the expected
  bootstrap identity, `prlimit64` only to read and confirm `RLIMIT_CORE=0`, and
  `capget`/`capset` only to verify the inherited six-bit launch sets and clear
  every controller permitted/effective/inheritable capability before readiness;
- `prctl` only for `PR_SET_DUMPABLE=0`, exact locked securebits,
  `PR_SET_NO_NEW_PRIVS=1`, `PR_CAPBSET_READ`, exact six-bit
  `PR_CAP_AMBIENT_LOWER`/`PR_CAP_AMBIENT_CLEAR_ALL`, exact bounding-set drops,
  and read-back of those
  properties;
- `fchdir(5)`, one `pivot_root` using the fixed minimal-root staging names,
  `chdir("/")`, one normal `umount2` of the fixed old-root staging mount with
  flags zero, and exact `unlinkat(..., AT_REMOVEDIR)` removal of that empty
  staging directory;
- one Go-main
  `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, steadyProgram)`
  before any receive/send; and
- only after that steady commit, `sendmsg(4, ...)` for the canonical controller
  attestation followed by `sendmsg(3, ...)` for sequence-zero `helper_ready`.

The path pointers used by `pivot_root`, `chdir`, and `umount2` are fixed image
constants, never protocol/config values. Native bootstrap reinspects and
retains sealed config FD 6 through target exec while closing every unrelated
descriptor and requiring FD 7 initially closed. The Go controller
reads/validates then closes FD 6 before readiness; only the later authenticated
PID1 bootstrap may install the received agent pidfd at FD 7. The native
bootstrap performs the pivot, drops all six bounding bits,
clears ambient then permitted/effective/inheritable sets, verifies every set is
empty, and execs the Go controller. Go verifies the empty state and only then
commits `steady-controller`. Any bootstrap failure exits; it cannot continue
with a partial root, capability set, descriptor table, or filter.

After `steady-controller` commits, `pivot_root`, `chdir`, bootstrap
`setsockopt`, `capget`, `capset`, and any seccomp filter replacement are
forbidden to the controller.

### Agent bootstrap only

Agent mode of the native role bootstrap begins as UID/GID 0 with the inherited
exact six-bit bounding/permitted/effective/inheritable/ambient sets. Its
`agent-bootstrap` state admits no external input; after target exec the inherited
`launch-base` admits the common Go runtime family only until Go main commits
`steady-agent`. Neither process can read a job request before authenticated
`composition_accepted`. The native bootstrap permits only:

- native fixed-FD/socket reinspection with no socket I/O, including exact
  listening VSOCK identity at FDs 5, 6, and 7; after Go commits the steady
  filter, FD 4 permits agent-config receive and direct PID1 attestation, while
  FD 3 permits property inspection only and no I/O before accepted;
- `setgroups(0, NULL)`, exact bounding-set drops for all six bits,
  `setresgid(998,998,998)`, and `setresuid(998,998,998)` in that order;
- `capget`/`capset` solely to verify the UID transition cleared
  permitted/effective/ambient sets and then clear the inherited set;
- `prctl` only for the inherited locked-securebits read-back,
  `PR_SET_DUMPABLE=0`, `PR_SET_NO_NEW_PRIVS=1`, capability-set read-back, and
  `PR_CAP_AMBIENT_CLEAR_ALL`; and
- fixed target `execve`; Go main then stacks `steady-agent` with TSYNC before
  the direct PID1 descriptor attestation.

`SECBIT_NO_SETUID_FIXUP` is unset and locked off, so the root-to-998 transition
performs the kernel's normal capability clearing. The native bootstrap verifies
UID/GID 998, no supplementary groups, empty bounding/permitted/effective/
inheritable/ambient sets and `no_new_privs` before exec. Go verifies the same
state, stacks the steady filter, and sends its descriptor directly to PID1 on
FD 4. The steady agent retains FDs 3 through 7 until authenticated
`composition_accepted`, then closes FD 4, performs the controller hello, and
begins accepting on exact listeners 5 through 7. It has no capability, process
clone, mount, cgroup, namespace, pathname exec, raw filesystem, socket creation,
bind, listen, connect, or arbitrary accept authority. Bootstrap failure exits
and forces PID1 whole-VM cleanup; it never releases admission.

### Common bounded runtime

The common runtime family is exact:

```text
read write readv writev close close_range dup3 fcntl lseek
fstat statx fstatfs getdents64
mmap mprotect munmap madvise brk mlock munlock
clock_gettime clock_nanosleep ppoll
futex sched_yield
rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack
getpid gettid getrandom
exit exit_group
```

These calls are for helper-owned memory, clocks, signals, and recorded FDs only.
The following restrictions apply:

- `mmap` is anonymous/private data or a read-only sealed image mapping; it may
  never create an executable writable mapping. `mprotect` cannot add execute
  permission and cannot make credential memory readable after wipe.
- `madvise` is limited to `MADV_DONTDUMP`, `MADV_DONTFORK`,
  `MADV_WIPEONFORK`, `MADV_DONTNEED` on pinned-runtime noncredential pages or
  post-wipe helper mappings, and `MADV_NOHUGEPAGE` on pinned-runtime
  noncredential pages. `MADV_FREE`, `MADV_HUGEPAGE`, and `MADV_COLLAPSE` are
  forbidden.
- `mlock`/`munlock` apply only to bounded helper-owned mutable mappings. Full
  capacity is overwritten before `munlock`/`munmap`.
- `getrandom` accepts only a bounded mutable destination and flags zero; it may
  create nonces or safe opaque IDs, never replace authenticated generations.
- `clock_gettime` uses only `CLOCK_MONOTONIC`, `CLOCK_BOOTTIME`, or
  `CLOCK_REALTIME`. Sleeps use an absolute monotonic deadline and cannot extend
  the 35-minute activation or 30-second cleanup limits.
- `ppoll` watches only recorded control, pipe, pidfd, cgroup-event, inherited
  VSOCK listener/accepted-stream, and Unix relay FDs with a bounded timeout.
  Signal-mask and timespec pointers are
  helper-owned.
- `fcntl` is limited to `F_GETFD`, `F_SETFD` adding `FD_CLOEXEC`, `F_GETFL`,
  `F_SETFL` changing only `O_NONBLOCK`, and `F_DUPFD_CLOEXEC` into 16..255.
  Native launch-bootstrap may clear `FD_CLOEXEC` only on verified listener FDs
  12..14 immediately before its one exec; Go PID1 restores it before creating a
  child. `ForkExec` maps only agent copies to 5..7 without close-on-exec for the
  two fixed role execs, and Go agent adds it before admission.
  The sole clearing exception is shim FD 11 for an already detected and
  pinned L4 interpreter script immediately before `execveat`.
- `statx` is limited to `AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW` reinspection of a
  recorded FD; it is not a pathname lookup. `fstatfs` and `getdents64` apply
  only to a recorded mount, cgroup, or directory FD.
- `close_range` may only close a validated inclusive range; it never uses
  `CLOSE_RANGE_UNSHARE` or `CLOSE_RANGE_CLOEXEC` as proof that an individual
  authority was closed.
- signal disposition calls may install only the construction-time fixed
  handlers. The policy does not allow `kill` or `tkill`; `tgkill` has only the
  pinned Go-runtime exception below.

An implementation whose language runtime needs another syscall does not gain
an implied exception. It must remove that dependency or amend this D2 contract
before D4 can claim conformance.

### Native role-bootstrap envelope

`hal-guest-role-bootstrap` is one freestanding static Linux-amd64 ELF `_start`
using reviewed raw syscall stubs. It has no libc, dynamic loader, Go runtime,
allocator, TLS, signal handler, thread creation, plugin, environment lookup,
network client, or filesystem search. Its union is limited to fixed-FD `read`,
`write`, `close`,
`close_range`, `dup3`, `fcntl`, `fstat`, `statx`, `fstatfs`, `getsockopt`,
`getsockname`, `getuid`, `geteuid`, `getgid`, `getegid`, read-only `prlimit64`, `capget`,
`capset`, exact `prctl`, exact
`setgroups`/`setresgid`/`setresuid`, controller-only `fchdir`/`pivot_root`/
`chdir`/`umount2`/`unlinkat`, shim-only `ioctl`/`setns`, PID1-only exact
`socket`/`bind`/`listen`, PID1-mode `seccomp`, exact target `execve`, and
`exit_group`. All pointers address fixed read-only image data or bounded
stack objects; the native source has no mutable global or general path/argv/env
parameter. PID1 mode is entered only as the immutable image init; child modes
are selected only by the supervisor adapter's closed enum. D2 fake decisions
and D4 normalized strace/golden disassembly must make the per-role subsets,
arguments, and instruction bytes exact.

### Pinned Go 1.25.7 runtime envelope

The five L8 production entrypoints are the repository's exact static
`CGO_ENABLED=0` Go 1.25.7 builds, not a generic language runtime. PID1 supplies
the sealed runtime settings `GOMAXPROCS=1` and
`GODEBUG=madvdontneed=1,disablethp=1,decoratemappings=0`; every process confirms
them before readiness or transition and never inherits caller-controlled Go
settings. Each role filter adds only these ordinary runtime calls:

```text
clone arch_prctl tgkill
```

This `clone` rule is only a same-process runtime thread with exactly
`CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_SYSVSEM|CLONE_THREAD` plus
optional `CLONE_SETTLS`; its exit signal, parent-TID pointer, child-TID pointer,
and every namespace/privilege flag are zero. The stack and optional TLS pointer
must fall within the pinned runtime's own noncredential mappings. It cannot
create a process, namespace, pidfd, cgroup placement, or different file table;
PID1 process start instead uses the separately matched exact service/monitor
`clone` and shim `clone3` templates.
`arch_prctl` is only `ARCH_SET_FS` to that runtime-owned TLS pointer.
`tgkill` embeds the already inspected helper TGID in the filter, targets a
thread in that same thread group, and permits only `SIGURG` for Go asynchronous
preemption. Profiling, cgo, plugins, `os/signal`, generic network polling, and
runtime-created application sockets are absent from the service binaries.

Bootstrap may additionally use `sched_getaffinity(0, boundedMaskBytes, ...)`
and `mincore` only while a pinned Go runtime initializes, before capability,
descriptor, and role-filter commit. The committed role policies forbid both.
`decoratemappings=0` is mandatory because the pinned runtime otherwise calls
`prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)`, which no steady role admits.
D4's safe normalized strace fixtures must prove this exact runtime envelope for
each locked binary digest; a toolchain or runtime-dependency change is a
contract change, never an automatically learned syscall.

### Authenticated local IPC

The service agent, controller, PID1 supervisor, and monitor may use:

```text
recvmsg sendmsg getsockopt
```

Agent-controller traffic is only agent FD 3/controller FD 3, agent-supervisor
traffic only agent FD 4/PID1's recorded boot endpoint, controller-supervisor
traffic only controller FD 4/PID1 FD 3, monitor bootstrap traffic only monitor
FD 10 to PID1's recorded transient bootstrap peer before readiness commit, and
steady direct monitor traffic only monitor FD 3/controller FD 8. PID1 FD 10
remains the monitor pidfd and is never a protocol endpoint; descriptor numbers
are role-local. The sole PID1 bootstrap relay is the normative HL8M exception:
the
monitor sends sequence-zero `monitor_ready` on FD 10 to the PID1-held recorded
transient bootstrap peer with exactly two rights ordered controller peer
endpoint then inspected mount namespace. PID1 authenticates and reinspects both, transfers those same two
rights in HL8L `job_created`, and closes its duplicates only after successful
atomic transfer. After the ready send the monitor permanently closes FDs 9 and
10, retaining direct FD 3 and namespace FD 7; PID1 closes its bootstrap peer
after relay or failure. Neither side reuses a closed bootstrap descriptor. PID1
neither forwards the ready body nor sends or receives a later HL8M packet. All
credential bodies then travel directly from controller-owned locked
buffers to the authenticated monitor FD 3. The controller begins the inherited
logical monitor receive sequence at one because PID1 consumed monitor sequence
zero on the separate bootstrap pair; its independent send sequence starts at
zero. Receive flags are exactly
`MSG_CMSG_CLOEXEC` plus optional `MSG_DONTWAIT`; send flags are zero or
`MSG_NOSIGNAL`. Each role allocates the fixed bounded control and ancillary
buffers before the call. It rejects truncation and reinspects the complete
`msghdr`, one kernel credentials record, rights cardinality, and every received
FD as required by the architecture. `getsockopt` is limited to read-only
reinspection of those fixed socket properties and accepted Unix peers.

`sendto`, `recvfrom`, `sendmmsg`, `recvmmsg`, and generic `ioctl` are not
substitutes.

### Preopened guest VSOCK acceptance

PID1 preopens the three fixed `AF_VSOCK` listeners in native
`launch-bootstrap`, passes them as service-agent FDs 5, 6, and 7, and closes
its FDs 12, 13, and 14 only after authenticated agent composition. The agent
revalidates `SO_DOMAIN=AF_VSOCK`, `SO_TYPE=SOCK_STREAM`, `SO_ACCEPTCONN=1`,
nonblocking/close-on-exec state, CID any, and exact port before admission.

After `steady-agent` and `composition_accepted`, `accept4` is permitted only on
FDs 5 through 7 with `SOCK_CLOEXEC|SOCK_NONBLOCK`. The returned transient FD
and exact kernel peer `SockaddrVM` are validated before any read: v2 requires
`VMADDR_CID_HOST`, while the listener's revalidated local port and sealed
generation supply the channel identity; v1 retains the existing port-1024 peer
behavior. Port 1025 admits one active control stream and port 1026 at
most four relay streams. Duplicate control, over-cap relay, wrong CID/port,
truncation, or listener replacement closes the accepted FD without protocol
decode. `shutdown` applies only to a recorded accepted VSOCK or D5 Unix relay
FD. Agent loss closes all three listeners and accepted streams; there is no
listener recreation in-place.

### Descriptor-relative monitor filesystem and PID1 cgroup operations

The steady monitor may use:

```text
openat2 mkdirat unlinkat renameat2
fchmod fchown fchownat ftruncate fsync fdatasync
```

PID1 `launch-base` may use only `openat2`, `mkdirat`, and
`unlinkat(..., AT_REMOVEDIR)` from that list, solely for the exact active
cgroup leaf beneath its revalidated delegated-root FD. It cannot use the
monitor's rename, ownership, mode, size, or durability operations.

`open`, `openat`, and `creat` are never permitted. Contained-path `openat2`
begins only at monitor FD 8 or an already revalidated descendant directory.
Every contained directory open uses exactly
`O_PATH|O_DIRECTORY|O_CLOEXEC`. A staging credential-file creation uses exactly
`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` and mode `0600`. PID1 opens
`cgroup.kill` with exactly `O_WRONLY|O_CLOEXEC`. It opens `cgroup.events` with exactly `O_RDONLY|O_CLOEXEC`.
Those are the complete cgroup control-file catalog for this closure. Every
contained-path request uses an exact-size `open_how` and:

```text
RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
```

The only exception is monitor bootstrap's namespace-self call:

```c
struct open_how how = {
    .flags = O_RDONLY | O_CLOEXEC,
    .mode = 0,
    .resolve = 0,
};
openat2(verified_proc_root_fd, "self/ns/mnt", &how, OPEN_HOW_SIZE_VER0);
```

`verified_proc_root_fd` is monitor FD 4, revalidated as procfs before this exact
compiled-constant lookup. `O_NOFOLLOW`, `RESOLVE_BENEATH`,
`RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_XDEV` are
forbidden for this exception because the namespace handle is a proc magic link.
The result is accepted only after exact monitor credentials/pidfd liveness,
`NSFS_MAGIC`, `NS_GET_NSTYPE == CLONE_NEWNS`, expected device/inode, and
inequality from PID1's namespace are proved. No other exception exists.

`O_CREAT` additionally requires `O_EXCL|O_NOFOLLOW`; every traversed credential
directory is root-owned mode 0711, and credential files are regular, mode 0600,
single-link, fixed UID/GID 1000. A D5 Unix socket entry is mode 0600 and fixed
UID/GID 1000 beneath those non-listable, non-writable directories. PID1 opens cgroup control
files only beneath its active FD 9 with fixed names and expected cgroup-v2
filesystem identity. `mkdirat`, `unlinkat`, and `renameat2` operate only beneath
the monitor credential root or PID1 delegated cgroup root on a canonical safe
generation/component name. `unlinkat` uses zero or `AT_REMOVEDIR` as required;
`renameat2` uses `RENAME_NOREPLACE` for publication. There is no exchange,
whiteout, caller-selected overwrite, hard link, symlink, node, FIFO, or device
creation.

The pinned Linux 6.1.178 guest kernel requires the D5 pathname socket mode to
be fixed at creation. After every required directory and regular-file creation
and immediately before the sole D5 bind, the monitor makes the one-way
`umask(0177)` transition. It never restores the process-wide umask, creates no
later directory, and permits no concurrent creator. The bind therefore creates
the pathname socket at exact mode 0600. The monitor reinspects the root-owned,
mode-0711 parent directory, sealed leaf name, socket FD, local address, mount,
device, and inode before calling
`fchownat(parentDirFD, sealedLeaf, 1000, 1000, AT_SYMLINK_NOFOLLOW)` with
ownership last. The non-writable parent and closed monitor state machine forbid
create, unlink, or rename from bind through the final same-mount/device/inode
reinspection. It sets mode 0600 before changing the D5 socket to fixed UID/GID 1000,
with ownership last. `fchownat` never receives an empty, absolute,
caller-selected, or multi-component path and never changes a directory owner
or mode.

Monitor writes are permitted only to an inspected staging regular file. Each
HL8M `prepare_file` decodes directly into one fixed 64-KiB locked receive slot;
the monitor authenticates metadata before exposure, writes through a borrowed
view, and overwrites the slot through full capacity before another packet or
any return path. No body-owning slice/string, second slot, generic formatter,
PID1 copy, or durable value exists. PID1 writes only the cataloged
`cgroup.kill`; the cgroup kill body is exactly `1`. Reads of
`cgroup.events` are bounded and accept cleanup proof only after parsing the
exact `populated 0` record. `fsync`/`fdatasync`, ownership, mode, size, inode,
link count, mount ID, and filesystem type are reinspected at the architecture's
publication and cleanup boundaries.

### Monitor mount and namespace operations

Only the steady monitor may use:

```text
fsopen fsconfig fsmount open_tree move_mount mount_setattr umount2
```

The monitor is already executing in the job mount namespace created by PID1;
it never calls `setns`. The only filesystem created is `tmpfs`. `fsopen` uses
`FSOPEN_CLOEXEC`; `fsconfig` accepts only `size=4194304`, `nr_inodes=65536`, and
`mode=0711`, followed once by `FSCONFIG_CMD_CREATE`. The tmpfs root remains
root-owned and is searchable but neither listable nor writable by UID 1000. `fsmount` uses
`FSMOUNT_CLOEXEC`; `open_tree` uses `OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC`;
`move_mount` attaches only the inspected tmpfs object to monitor FD 5 in the
monitor's current namespace with the two empty-path flags; and `mount_setattr`
uses `AT_EMPTY_PATH`, the kernel ABI size, zero user/group mappings, and only
`MOUNT_ATTR_NODEV|MOUNT_ATTR_NOSUID|MOUNT_ATTR_NOEXEC` plus private
propagation. No caller supplies filesystem type, option, target, propagation,
or flags.

The monitor retains `CAP_SYS_ADMIN|CAP_CHOWN` through cleanup. `umount2` is a
normal flags-zero unmount of the one compiled fixed target after mount identity
reinspection. It then proves the target has no mounted tmpfs and calls
`exit_group`; it does not attempt a per-thread capability transition inside the
multi-threaded Go process. The controller and PID1 never attach or unmount that
target, and a namespace FD is never treated as a mountpoint FD. `MNT_DETACH`,
recursive attributes, shared/slave propagation, bind mounts from caller paths,
classic `mount`, and arbitrary namespace entry are forbidden. Normal unmount
failure follows bounded retry/stop-VM handling and is never converted to
success by lazy unmount.

### PID1 process creation, supervision, and cleanup

Only PID1's launch adapter may call pinned Go 1.25.7 `syscall.ForkExec`. Using
`os.StartProcess`, `os/exec`, or another wrapper is forbidden because its
implicit pidfd capability probe creates an extra unowned child. The boot-only
controller/agent service launch uses exact `clone` flags
`CLONE_VFORK|CLONE_VM|CLONE_PIDFD|SIGCHLD`, no namespace or cgroup flag, and the
pidfd pointer in the pinned amd64 argument position. The monitor uses exact `clone`
flags `CLONE_VFORK|CLONE_VM|CLONE_NEWNS|CLONE_PIDFD|SIGCHLD`, with the
pidfd pointer in the pinned amd64 argument position. The shim uses exact `clone3`
flags
`CLONE_VFORK|CLONE_VM|CLONE_PIDFD|CLONE_INTO_CGROUP`,
`exit_signal=SIGCHLD`, `cgroup=9`, and every other optional field zero. The
temporary `CLONE_VFORK|CLONE_VM` sharing is the pinned Go pre-exec mechanism;
the parent remains suspended until child exec/exit and no protocol goroutine or
mutable credential buffer is reachable from the child path.

The shim `clone_args` size is the pinned Go 1.25.7 toolchain ABI size. Unknown
tail bytes and fallback sizes are rejected. Zero `Cloneflags`, a non-nil
`PidFD`, and `UseCgroupFD=false` are mandatory for the boot-only controller and
agent starts. `Cloneflags=CLONE_NEWNS`, a non-nil
`PidFD`, and `UseCgroupFD=false` are mandatory for the monitor.
`UseCgroupFD=true`, exact `CgroupFD=9`, zero `Cloneflags`, and a non-nil `PidFD`
are mandatory for the shim. A returned pidfd below zero is failure before any
gate release. The launch adapter validates the exact `syscall.ForkExec` path as
the image-profile-pinned `hal-guest-role-bootstrap` and supplies only the frozen
closed role argv/environment; the controller protocol cannot invoke either
boot-only start and the private launch protocol can select no binary or
argument. There is no process creation by the controller or monitor, arbitrary
command, `fork`, caller-selected clone flag, alternate `clone3` size, or
spawn-then-write-`cgroup.procs` fallback.

Every `ProcAttr` has empty `Dir`, nil `Credential`, exact fixed `Files`, and no
chroot, controlling TTY, session/process-group, parent-death signal, user-ID
mapping, ambient-capability request, or other `SysProcAttr` option. The pinned
pre-exec path may add `prlimit64(0, RLIMIT_NOFILE, ...)` only for Go's cached
limit recheck, fixed-FD `dup3`/`fcntl`/`close`, the exact child `execve`, and an
error-pipe write/exit. If exec fails, PID1 may use
`wait4(exactReturnedPID, ..., 0, NULL)` only inside `ForkExec`'s synchronous
failure cleanup, then closes the returned pidfd and converges through the
owned role cleanup. Normal authority and cleanup use pidfds plus `waitid`; a
PID from this internal failure path is never accepted from a protocol or used
after `ForkExec` returns.

The `ForkExec` pre-exec child may call pathname `execve` only for the compiled
role-bootstrap path. That native bootstrap may perform exactly one second
pathname `execve` to its role's compiled, image-profile-pinned controller,
agent, monitor, or shim target after committing the exact native role state.
The inherited `launch-base` remains the only installed filter until the Go
target commits its steady or transition filter before protocol input. Both
argv/environment sets contain no protocol or job field and are
validated in immutable adapter-owned storage before `clone`; `CLONE_VFORK`
suspends the only mutator until first exec/exit. The sole PID1 launch adapter
admits no other pathname exec request, and every steady child role filter
rejects pathname exec. The agent stacks its existing unprivileged service filter
before admission release; the controller and monitor stack the role filters
above, and the shim is the sole service binary that later uses pinned-FD
`execveat` for a workload.

PID1 and the controller may create only the exact `pipe2` and unnamed
`AF_UNIX/SOCK_SEQPACKET|SOCK_CLOEXEC` pairs required by the closed launch and
stream protocols, with `SO_PASSCRED` on protocol endpoints. Before monitor
launch PID1 creates a temporary PID1-monitor bootstrap pair and a distinct
long-lived controller-monitor pair. The monitor receives the long-lived
monitor endpoint at fixed FD 3, the long-lived controller peer at launch-only
FD 9, and its bootstrap endpoint at launch-only FD 10. PID1 keeps the other
bootstrap peer in a recorded transient slot; PID1 fixed FD 10 remains the
monitor pidfd. The monitor creates no socketpair. It opens and reinspects its
namespace as FD 7 using the exact `verified_proc_root_fd` exception above, then
its sequence-zero `HL8M monitor_ready` sends exactly two rights over FD 10 to
PID1 in this order: FD 9, the long-lived controller peer, then FD 7, the live
namespace capability. It retains fixed FD 3 and FD 7 and closes FD 9 and FD 10
permanently after the authenticated send. The ready body carries the exact
pending revision,
controller-minted job/monitor/mount/cgroup generations, `helper-limits-v1`,
`createJobSHA256`, and canonical `monitorReadySHA256`. PID1 requires exact
equality, recomputes the ready digest, requires the expected monitor
pidfd/PID/UID/GID, and reinspects both rights before relaying them in the same
order through `HL8L job_created` with that same ready digest; it then closes
its bootstrap peer and transferred duplicates. The controller owns the direct
endpoint and namespace authority after that commit. Any discrepancy closes
every transient right,
kills/reaps the monitor, and rolls back.

`pipe2` uses `O_CLOEXEC` plus optional `O_NONBLOCK`; each pair is immediately
type/direction inspected. `waitid(P_PIDFD, ...)` is PID1-only for monitor and
workload processes. The controller proves agent liveness by pidfd polling only;
it lacks signal permission for UID 998 and never calls `pidfd_send_signal`.
PID1 may use `pidfd_send_signal` with signal zero or `SIGKILL`, null siginfo,
and flags zero only for its same-UID-0 monitor. PID1 never signals a UID-1000 workload;
after shim start, every stop path writes exact `1` to the owned job cgroup's
`cgroup.kill`, observes `populated 0`, and reaps each workload pidfd with
`WEXITED`, optional bounded `WNOHANG`, and a final wait without `WNOWAIT`.
PID numbers, process groups, and ambient `/proc` lookups are not authority. The
still-capable monitor remains alive for normal unmount after workload absence.
`setsid` and `setpgid` descendants remain covered by cgroup kill.

### Unix SSH relay extension

Only a D5-enabled monitor may add
`umask socket bind getsockname listen`; only the matching controller extension
may add `accept4 shutdown`:

```text
umask socket bind getsockname listen | accept4 shutdown
```

`socket` is exactly `AF_UNIX`, `SOCK_STREAM|SOCK_CLOEXEC` with optional
`SOCK_NONBLOCK`, protocol zero. `accept4` adds `SOCK_CLOEXEC` and optional
`SOCK_NONBLOCK`. `bind` uses only the monitor-owned job relay address under the
fixed credential root; abstract names, unnamed caller sockets, and
any network or vsock family are rejected. The pointer is copied and validated
before the syscall. `umask` is the exact one-way `0177` transition above and is
permitted only immediately before the sole D5 bind. The monitor-only `getsockname`
rule applies only to its recorded D5 listener, uses a fixed-size
zeroed `sockaddr_un` and initialized length, and after bind must return exact
`AF_UNIX`, length, and sealed canonical pathname bytes. After the exact
parent-FD-relative ownership-last transition, the monitor calls `listen` with
backlog 1 through 4 and repeats `getsockname`; read-only `getsockopt` must prove
the exact domain, type, protocol, and `SO_ACCEPTCONN` listening state. It also
reinspects the same filesystem mount/device/inode, fixed UID/GID 1000, mode
0600, ownership, and generation before publication. A listener has no peer or
connected-state claim. The controller validates accepted peer identity only after `accept4`
on the resulting connected FD. Before rights publication or any stream read,
exact `getsockopt(SOL_SOCKET, SO_PEERCRED)` must return an accepted `struct ucred`
at its exact kernel ABI size with positive PID and fixed UID/GID 1000. The PID is
ephemeral check metadata, never durable identity or authority. A mismatch or
wrong result length closes the connected FD without publication. `shutdown` is
`SHUT_RD`, `SHUT_WR`, or `SHUT_RDWR` on a recorded relay FD only.

D7 owns the policy rule; D2 owns its pure decision and fake-observation
semantics. The monitor sends the one inspected
listener capability to the controller through the exact D5 monitor response:
the normative HL8M `create_ssh_endpoint` accepted response carries exactly one
inspected listening `AF_UNIX` capability from a recorded transient slot. Fixed
FD 9 is never reused for it after the bootstrap handoff. The monitor
then closes its original only after the authenticated atomic send succeeds;
the controller owns
and accepts on the published listener and never binds in another mount
namespace. On revoke the controller closes every published listener and
accepted connection before the monitor unlinks the socket entry. D5 owns live
acceptance, descriptor passing, peer validation, and pumping. D4 alone MUST NOT
enable this extension.

## Monitor and workload transitions

Monitor mode of the native role bootstrap begins already inside the cloned job
mount namespace. Before any Go runtime starts, it clears supplementary groups,
reduces bounding/permitted/effective/inheritable/ambient sets to exactly
`CAP_SYS_ADMIN|CAP_CHOWN`, verifies inherited securebits/`no_new_privs`, and
execs the fixed monitor target. Go verifies that state and fixed FDs, then
stacks `steady-monitor` with TSYNC before the
exact namespace-self `openat2`/`sendmsg` handoff. It performs only the closed
prepare, optional SSH-endpoint, revoke, and absence protocol in its current
namespace. It never clones, performs pathname exec, or enters another
namespace. After successful absence proof it calls `exit_group`; monitor exits
the entire process, so no privileged runtime thread survives.

The handoff and later operations obey the architecture's HL8M FSM rather than
being inferred from syscall success: ready revision is exactly one; one
begin/file/commit transaction is the sole logical outstanding prepare request;
the optional endpoint is created only after commit; cleanup-complete reports
entry/socket/mount absence only. The monitor cannot claim its own process
absence while sending. The controller alone drives revoke over direct FD 3,
receives cleanup-complete, and completes the exact bilateral normal
`close_notify` handshake before monitor FD 3 closes and the monitor exits. The
controller observes the expected EOF, then closes its direct endpoint and
namespace duplicate. Only afterward does it send HL8L `destroy_job`; PID1 never
requests HL8M cleanup and then separately reaps the monitor pidfd and proves
process/cgroup/directory absence. Any non-normal close, wrong-state close,
close-send failure, or EOF before the committed handshake requires stop-VM.

Shim mode of the native role bootstrap verifies the exact six inherited sets,
fixed FDs, securebits, cgroup placement, and `no_new_privs`. The single-threaded
native shim enters the mount namespace before any Go runtime starts: it
revalidates FD 3 as the exact monitor namespace, calls
`setns(3, CLONE_NEWNS)` while holding `CAP_SYS_ADMIN|CAP_SYS_CHROOT`, and closes
FD 3. It then drops `CAP_SYS_ADMIN`, `CAP_SYS_CHROOT`, and `CAP_CHOWN` from the
bounding/permitted/effective/inheritable/ambient sets, verifies the remaining
sets are exactly `CAP_SETUID|CAP_SETGID|CAP_SETPCAP`, and execs the fixed Go
shim without reading the launch block or gate. The child was created without
`CLONE_FS`; native namespace entry therefore cannot share filesystem state with
another process. Go starts inside the job namespace and immediately stacks
`workload-transition` with TSYNC before either read; no transition policy is
learned from input. It later stacks the final verified
`WorkloadSnapshot`-derived filter.

A workload shim transition may call only:

```text
read close close_range dup3 fcntl fchdir
setgroups setresgid setresuid getresuid getresgid getgroups capget capset prctl
seccomp execveat exit exit_group rt_sigreturn
```

The exact sequence is:

1. validate fixed FDs 0..2 and 4..7, require native FD 3 is closed after
   namespace entry, require FD 8 is closed, and close every unrelated
   descriptor;
2. read and authenticate the bounded launch block from FD 6 directly into
   locked memory, construct the sealed `ExecPlan`/binding, wipe the input slot,
   and close FD 6;
3. revalidate already mapped pipe directions at 0, 1, and 2;
4. `fchdir` to workdir FD 4 and close it;
5. consume gate FD 7 only after PID1 committed cgroup/namespace/FD correlation,
   then close it;
6. drop each of the remaining three bounding bits with `PR_CAPBSET_DROP` while
   `CAP_SETPCAP` remains effective;
7. `setgroups(0, NULL)`, `setresgid(1000,1000,1000)`, and
   `setresuid(1000,1000,1000)`; require the normal UID transition to clear
   permitted/effective/ambient state, clear the inherited set with `capset`,
   use exact `getresuid`, `getresgid`, `getgroups`, `capget`, and bounding/
   ambient `prctl` reads to verify UID/GID 1000, no groups, and all five sets
   empty, set `PR_SET_DUMPABLE=0`, and reconfirm `PR_SET_NO_NEW_PRIVS=1`;
8. stack the verified `WorkloadSnapshot`-derived seccomp policy; and
9. move pinned executable FD 5 to FD 11 and call
   `execveat(11, "", argv, envp, AT_EMPTY_PATH)`. FD 11 remains close-on-exec
   for a native executable. For an already detected and pinned interpreter
   script only, the child clears `FD_CLOEXEC` immediately before `execveat` so
   the kernel interpreter handoff can use the same inode, exactly preserving
   the frozen L4 child-only descriptor behavior.

The shim does not use pathname `execve`, ambient `PATH`, `chdir`, or a
request-derived `open*`/`/proc/self/fd` lookup. The monitor namespace constant
and frozen L4 kernel interpreter handoff are the only exceptions. `argv` and
`envp` are constructed solely from the
validated bounded `ExecPlan` plus authenticated prepared bindings; their
pointers are not seccomp-inspectable. Failure at any step wipes private memory,
closes pipes/gate, and exits without a second launch attempt. PID1 kills the
owned job cgroup, reaps the recorded pidfd, and continues cgroup cleanup.

The final workload policy is not broadened here. It MUST retain the existing
L4 execution semantics and L7 network confinement and MUST deny at least the
forbidden process-inspection and privilege syscalls below. A child cannot use
`SECCOMP_FILTER_FLAG_NEW_LISTENER`, `TSYNC`, `LOG`, or a permissive transition.

## Capability and identity invariants

At PID1 launch-supervisor commit, the bounding, permitted, effective,
inheritable, and ambient sets are exactly:

```text
CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN
```

PID1 raises the six ambient bits only after proving they are already permitted
and inheritable, then locks `SECBIT_NOROOT` and
`SECBIT_NO_CAP_AMBIENT_RAISE` on. `SECBIT_KEEP_CAPS` and
`SECBIT_NO_SETUID_FIXUP` remain off and are locked off with their companion
locked bits. PID1 is non-dumpable and cannot raise or gain any capability
outside the six-bit bounding set. The ambient set exists solely so an exact
image-profile-pinned nonprivileged controller/agent/monitor/shim exec retains the
six transition capabilities despite `SECBIT_NOROOT`; no file capability or
setuid/setgid bit supplies privilege.
No file capability, setuid/setgid binary, user namespace, keyring, or ambient
raise can restore authority.

The service agent reaches UID/GID 998 with all five capability sets empty
before descriptor hello or admission release. The steady
controller is UID/GID 0 with locked `SECBIT_NOROOT` and every capability set
empty. The monitor is UID/GID 0, has no supplementary groups, and retains only
`CAP_SYS_ADMIN|CAP_CHOWN` until normal unmount/absence, then exits its entire
process. The workload is UID/GID 1000, has no supplementary groups, has every
capability set empty, and has `no_new_privs` before exec. The native workload
shim has the six-bit set only through namespace entry; `CAP_SYS_CHROOT` is
present solely so exact mount-namespace `setns` can succeed. The Go shim starts
with exactly `CAP_SETUID|CAP_SETGID|CAP_SETPCAP` and no namespace FD. Any mismatch blocks
readiness or gate release; it is never downgraded to a warning.

## Forbidden syscall catalog

The following are forbidden except for the exact role rule above and forbidden
to workloads where applicable:

- arbitrary path and mutation: `open`, `openat`, `creat`, `mount`, `chroot`,
  `name_to_handle_at`, `open_by_handle_at`, `link`, `linkat`, `symlink`,
  `symlinkat`, `mknod`, `mknodat`, `mkfifo`, and `pivot_root` after bootstrap;
- arbitrary namespace or privilege: `unshare`, arbitrary `setns`,
  `setuid`, `setgid`, `setreuid`, `setregid`, `setfsuid`, `setfsgid`,
  `personality`, `uselib`, and seccomp listener creation;
- device, kernel, or key authority: every `ioctl` except exact monitor or native
  shim `ioctl(7|3, NS_GET_NSTYPE)`, `iopl`, `ioperm`, `kexec_load`,
  `kexec_file_load`, `init_module`, `finit_module`, `delete_module`,
  `reboot`, `swapon`, `swapoff`, `quotactl`, `syslog`, `acct`,
  `add_key`, `request_key`, and `keyctl`;
- process inspection or cross-process memory: `ptrace`, `process_vm_readv`,
  `process_vm_writev`, `pidfd_getfd`, `kcmp`, `perf_event_open`, `bpf`,
  `userfaultfd`, and `membarrier` registration;
- uncontrolled process/signal authority: `fork`, `vfork`, every `clone` and
  `tgkill` outside the pinned Go-runtime envelope, `kill`, `tkill`, and
  every `clone3` outside PID1's single exact shim template;
- network/vsock authority: every `socket` family except PID1 native bootstrap's
  exact three `AF_VSOCK` listeners and the exact D5 `AF_UNIX` rule, plus
  `socketpair`, `accept`, `connect`, `sendto`, `recvfrom`, `sendmmsg`, `recvmmsg`,
  and `setsockopt` after bootstrap, except the exact local protocols, steady-agent
  `accept4`, and D5 monitor/controller split above; and
- asynchronous or opaque kernel execution: `io_uring_setup`,
  `io_uring_enter`, `io_uring_register`, `fanotify_init`, `inotify_init`,
  `inotify_init1`, `epoll_create`, `epoll_create1`, and `restart_syscall`.

Unknown syscalls are forbidden even when a newer kernel implements them. There
is no `ENOSYS` compatibility fallback to an older, broader syscall.

## Pointer arguments and reinspection

Classic seccomp BPF can inspect syscall numbers and scalar argument words; it
cannot safely dereference pointers. Therefore the filter alone does not prove
any pathname, `open_how`, `clone_args`, `msghdr`/control message, `sockaddr`,
mount option, `timespec`, capability data, seccomp program, argv, envp, or
mutable I/O buffer restriction in this document.

The same sole adapter is mandatory for every `EnforcementPathAdapter` row,
including a scalar-only call narrowed by stage or facts. Only a structurally
all-stage `EnforcementPathDirect` row may invoke its raw syscall path without a
state observation. The compiled `FilterProfile` is a ceiling, never evidence
that a narrowed adapter row is safe to call directly.

D4 MUST put every non-pinned pointer-bearing call behind the sole syscall
adapter for that operation. `EnforcementPathPinnedDirect` callsites instead
require the exact D7 source-lock and final-binary evidence above and cannot be
added or widened by D4/D6. For an adapter call, D4 follows only this exact
order: allocate the inert identity, build and store bindings through that same identity, call `AuthorizePre`, install the returned permit and sole closure in that identity, atomically claim, and only then invoke the closure. This is the exact
`unstarted -> claimed -> executed -> finalized` wrapper; it invokes its one-use
syscall closure exactly once. A pre-syscall cancellation or failure
calls the phase-explicit `AbortPermit(permit, AdapterPhasePre)` once with the
exact same permit and makes zero syscall calls. After a successful syscall
the wrapper calls `AuthorizePost` for returned objects or `CommitNoObject` when
the verified rule has none. On syscall failure it calls the phase-explicit
`AbortPermit(permit, AdapterPhasePost)` with the exact same permit; there is
no post observation of a nonexistent return, no retry, and no method after
finalization. Before the syscall, the adapter copies variable input into bounded
helper-owned memory, validates the closed union and every reserved byte, and
prevents concurrent mutation. After success it reinspects the returned kernel
object before recording authority:

- files/directories: type, mode, UID/GID, link count, device/inode, mount ID,
  filesystem type, access mode, and containment beneath the fixed dirfd;
- pipes: pipe type and exact read/write direction;
- pidfds: pidfd type, expected generation/liveness, and poll state; signal
  permission is never inferred from pidfd ownership;
- namespaces/mounts: namespace type, mount ID, parent/root relation, tmpfs
  type, exact attributes, propagation, and generation;
- cgroups: cgroup-v2 filesystem, delegated-root descent, exact leaf identity,
  and `populated` observation;
- sockets: domain, type, protocol, local/peer identity, connected/listening
  state, ownership, and generation; and
- ancillary messages: truncation flags, exactly one credentials record,
  exact rights count, and every received FD kind.

Failure to reinspect is a failed operation, not an unsupported optimization.
The object is closed, unpublished staging is rolled back, mutable buffers are
wiped, and cleanup proceeds. Tests and documentation MUST distinguish scalar
checks enforced by seccomp from pointer and provenance checks enforced by the
adapter; neither may be reported as the other.

## Denial actions

There is no collapsed generated-decision precedence. The three exported
decision surfaces remain separate and defer exactly to their authoritative
definitions above:

On the two filter-facing surfaces, kill is exactly
`SECCOMP_RET_KILL_PROCESS`, EPERM is exactly
`SECCOMP_RET_ERRNO | EPERM`, and ALLOW is exactly `SECCOMP_RET_ALLOW`; these are
the `ActionKillProcess`, `ActionErrnoEPERM`, and `ActionAllow` values frozen
above. Transition decisions use the same named action values without claiming
that a transition itself installs or executes a seccomp return.

### Surface 1 — raw `FilterProfile.Decide`

This surface has no state, transition, observer, permit, or ticket. It applies
the already-frozen raw precedence: foreign architecture, x32, an unknown, unassigned, or newer-than-6.1 syscall number, and catalog-fatal classification
kill; a known nonfatal row
with no matching filter rule returns EPERM; an exact scalar match permits
ALLOW; otherwise it collects every failing clause globally, chooses kill if
any failing clause has kill action and EPERM otherwise, then applies the exact
canonical rule/clause tie-break. The returned `FilterDecision` never contains
an adapter ticket or claims pointer/provenance enforcement.

### Surface 2 — semantic `Policy.Decide`

This surface first applies its already-frozen architecture/catalog precedence,
then role and effective stage/fact selection, then the same global scalar
failure selection among retained semantic rows. An exact matching rule permits
ALLOW. However, only `EnforcementPathAdapter` returns a nonzero adapter ticket.
Direct, PinnedDirect, and scalar-only workload allows return zero tickets and
`Decision.Ticket()` returns `ErrorCodeOwnership` for them. A pointer/FD/object
mutation is handled later only by the adapter authorization surface; a pinned-
callsite mutation fails evidence import/readiness; the scalar-only workload
exception makes no pointer claim. None changes raw filter precedence.

### Surface 3 — `ValidateTransition`

This surface applies only the source-stage invariant, exact declared edge,
transition masks and set/clear formula, exact destination facts, and
destination-stage invariant already frozen above. Exact transition success
returns ALLOW with zero rule digest and zero ticket; failure returns
kill/impossible-transition with zero rule digest and zero ticket. It never
classifies a syscall, performs scalar tie-breaking, or issues adapter authority.

Descriptor kind/generation, pointer content, and returned-object provenance
remain the independent two-phase adapter checks above. They cannot weaken or
strengthen the raw scalar action and are never reported as filter enforcement.

The filter never returns `TRACE`, `TRAP`, `LOG`, `USER_NOTIF`, or unconditional
allow. A `KILL_PROCESS` outcome in PID1, controller, agent, monitor, or shim is
permanent role loss. The agent invalidates readiness and active proofs; the guest cannot claim local
cleanup complete. D6 stops/reaps the exact microVM and inspects host-owned
absence.

## Kill, reap, and cleanup convergence

Before shim gate release, any authentication, descriptor, private-binding,
policy, or setup failure closes the gate and pipes and wipes buffers. If a shim
has started, PID1 uses the owned cgroup-kill/zero-population path and then reaps
its recorded pidfd; it never relies on signal permission after the UID drop.
Unstarted state rolls back without a kill.

After gate release, cancel, timeout, protocol/session/role loss, malformed
stream, output failure, expiry, or revoke denies new exec and converges through
the exact job cgroup. On the recoverable normal path the controller initiates
each protocol step; PID1 never originates an HL8M cleanup request:

1. the controller denies new exec/accept and sends HL8L `terminate_job`; PID1
   writes exactly `1` to `cgroup.kill` beneath its fixed FD 9;
2. PID1 parses bounded `cgroup.events` until exact `populated 0`;
3. PID1 reaps all recorded workload shims/leaders with `waitid(P_PIDFD, ...)`;
4. PID1 returns `job_terminated`; the controller closes pipes and wipes private
   buffers;
5. the controller closes every published listener and accepted connection;
   through direct monitor FD 3 it drives HL8M revoke/cleanup, and the
   still-capable monitor unlinks files/socket entries, normally unmounts in its
   current namespace, and proves mount/file absence;
6. the monitor returns `cleanup_complete` directly to the controller, calls
   `exit_group` only after bilateral normal HL8M close commits, and the
   controller observes monitor exit before closing its direct endpoint and
   namespace duplicate;
7. only then the controller sends HL8L `destroy_job`; PID1 never contacts the
   monitor, whose bootstrap channel is permanently closed, but confirms/reaps
   the monitor with its FD 10 pidfd; and
8. PID1 performs any still-needed cgroup kill/zero confirmation, removes and
   reinspects the generation directory and cgroup, and returns `job_destroyed`.

An early `destroy_job` before the monitor cleanup/exit precondition returns only
the canonical correlated cleanup retry or stop-VM result; PID1 does not attempt
to recreate a bootstrap link or operate a controller-owned capability.

There are at most three idempotent attempts inside one 30-second total
deadline. A retry begins with reinspection and never recreates a resource.
Process-group signals, leader pidfd death, descriptor closure, and role exit
are not descendant-absence proof. Missing cgroup kill/inspection, unknown
ownership, nonzero population, normal-unmount failure, monitor-reap failure,
PID1/controller/agent/monitor loss, or policy-kill yields `stop_vm_required`. Only D6's exact
Firecracker stop/reap plus host absence inspection can then produce the root
cleanup proof.

## Required D2, D7, and D4 tests

D2 owns the pure artifact grammar/importer/verifier, immutable views,
validators, decision engines, fake syscall observers, and fixtures. D7 owns the
input rows. D2 default tests MUST be Linux-independent, use only a bounded
package-internal synthetic artifact issued by the `_test.go` marker, and
perform no live syscall. They include:

- one positive decision for every synthetic rule and every represented exact
  allowed flag/command/FD variant;
- generated “plus one” negatives changing one represented dimension at a time: syscall
  number, architecture/x32 bit, role, fixed FD, transient kind/generation,
  flag bit, enum, clone field, mount command, socket family/type, signal,
  wait option, path class, bounds, reserved byte, or sequence;
- pointer-blindness tests proving the seccomp decision does not claim to inspect
  pointed-to data and the fake adapter independently rejects mutated
  `open_how`, `clone_args`, paths, ancillary data, mount options, sockaddr,
  argv/env, and object reinspection;
- decision goldens proving exact `ALLOW`, `ERRNO(EPERM)`, and
  `KILL_PROCESS` decisions, amd64 arch check, x32 rejection, no permissive
  action, and stable synthetic syscall-name/number mapping; and
- all importer bounds, digest, grammar, fatal-row, conditional check,
  overlap, ancestry, provenance, ownership, typed-nil, defensive-copy, opacity,
  constructor precedence, and observer result/error matrices above.

D7 issuance tests run the same engine and generator against the sole issued
artifact, not the synthetic D2 fixture. They require one positive and every
applicable plus-one case for every issued rule, stable syscall-name/number
mapping, exact rule/role/artifact digests, and the launch-base ancestry,
capability/securebits/UID/GID, fixed-FD transition, VSOCK handoff, protocol,
credit, cgroup, descendant, unmount, and cleanup matrices specified below.
Their no-skip output is the semantic-completeness evidence D2 cannot supply.

D4 owns the Linux implementation and adds:

- subprocess probes for every `KILL_PROCESS` class and representative
  `ERRNO(EPERM)` classes, asserting the process disposition and absence of a
  performed side effect;
- positive kernel tests for fixed-FD bootstrap, filesystem/mount/cgroup,
  VSOCK inherited-listener acceptance, canonical service/monitor `clone` and
  shim `clone3`, native shim setns before any Go thread, shim identity/capability drop, and
  kill/reap ordering through injected syscall fakes before any prepared-host
  test;
- one normalized, committed strace fixture for each bootstrap, prepare,
  exec-success, exec-failure, revoke, and cleanup path. The fixture contains
  syscall names and safe scalar categories only—never paths, payloads,
  arguments, environment values, nonces, socket names, or credentials. The set
  difference `observed - policy` and `policy-required - observed` MUST both be
  empty, except explicitly enumerated state-dependent alternatives already in
  the D7-issued artifact; and
- a role-composition regression proving the steady controller cannot launch,
  mount, create network/vsock sockets, or use workload authority; the monitor
  alone mounts/unmounts in its current namespace; the workload is not trapped by
  controller seccomp; and PID1 accepts no general-purpose launch request; and
- a small-`SO_SNDBUF` seqpacket test proving withheld stdout credit does not
  prevent credited stderr progress (and vice versa), while a peer-wide read
  stall reaches the bounded session-loss cleanup path.

Strace is test evidence, not an allowlist generator. An observed extra syscall
fails the test; it is never automatically added. Kernel tests remain behind an
explicit D4 integration tag and prepared prerequisite checks. A skip cannot
become selected live evidence.

## Ownership and non-goals

D2 owns this immutable policy vocabulary, exact canonical artifact schema,
importer/verifier, fake decisions, pointer/provenance validators, the pure
normative HL8M codec/FSM, supervisor/monitor protocol contracts, test fixtures,
and source/import guards. D7 owns complete policy row authoring and issuance.
D4 owns the live PID1/controller/monitor/shim/agent role composition,
filter compilation and
installation, direct syscalls, namespaces, tmpfs, cgroups, workload launch,
and guest cleanup retries. D5 owns live SSH Unix sockets and relay I/O under the
optional extension. D6 owns role-loss and whole-VM stop/reap composition.

This closure does not add a service binary, syscall wrapper, BPF program,
listener, mount, namespace, cgroup, process, command wiring, guest image, live
test, capability claim, active proof, or cleanup proof. It does not alter v1,
the D2 packet/exec codecs, L4 workload behavior, L7 network enforcement, or the
existing D2/D4/D5/D6 ownership split.
