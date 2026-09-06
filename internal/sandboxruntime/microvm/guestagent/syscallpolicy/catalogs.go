package syscallpolicy

// Role is one closed guest process policy role.
type Role uint8

const (
	RoleLaunchBootstrap Role = 1 + iota
	RoleLaunchBase
	RoleControllerBootstrap
	RoleSteadyController
	RoleAgentBootstrap
	RoleSteadyAgent
	RoleMonitorBootstrap
	RoleSteadyMonitor
	RoleWorkloadTransition
	RoleWorkload
)

func ValidateRole(value Role) error {
	if value < RoleLaunchBootstrap || value > RoleWorkload {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

func (value Role) String() string {
	switch value {
	case RoleLaunchBootstrap:
		return "launch-bootstrap"
	case RoleLaunchBase:
		return "launch-base"
	case RoleControllerBootstrap:
		return "controller-bootstrap"
	case RoleSteadyController:
		return "steady-controller"
	case RoleAgentBootstrap:
		return "agent-bootstrap"
	case RoleSteadyAgent:
		return "steady-agent"
	case RoleMonitorBootstrap:
		return "monitor-bootstrap"
	case RoleSteadyMonitor:
		return "steady-monitor"
	case RoleWorkloadTransition:
		return "workload-transition"
	case RoleWorkload:
		return "workload"
	default:
		return "unknown"
	}
}

// Stage is one closed process lifecycle stage.
type Stage uint8

const (
	StageNativeBootstrap Stage = 1 + iota
	StageGoBootstrap
	StagePreAdmission
	StageActive
	StagePreparing
	StagePrepared
	StageLaunching
	StageRunning
	StageRevoking
	StageCleaning
	StageClosed
	StageNativePreSetns
	StageNativePostSetns
	StageGoPreGate
	StageGoPostGate
	StageFinalWorkload
)

func ValidateStage(value Stage) error {
	if value < StageNativeBootstrap || value > StageFinalWorkload {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

func (value Stage) String() string {
	switch value {
	case StageNativeBootstrap:
		return "native-bootstrap"
	case StageGoBootstrap:
		return "go-bootstrap"
	case StagePreAdmission:
		return "pre-admission"
	case StageActive:
		return "active"
	case StagePreparing:
		return "preparing"
	case StagePrepared:
		return "prepared"
	case StageLaunching:
		return "launching"
	case StageRunning:
		return "running"
	case StageRevoking:
		return "revoking"
	case StageCleaning:
		return "cleaning"
	case StageClosed:
		return "closed"
	case StageNativePreSetns:
		return "native-pre-setns"
	case StageNativePostSetns:
		return "native-post-setns"
	case StageGoPreGate:
		return "go-pre-gate"
	case StageGoPostGate:
		return "go-post-gate"
	case StageFinalWorkload:
		return "final-workload"
	default:
		return "unknown"
	}
}

// StateFact is a closed bit set of monotonic or explicitly transitioned state.
type StateFact uint64

const (
	StateFactFilterCommitted StateFact = 1 << iota
	StateFactCompositionAccepted
	StateFactProtocolInputStarted
	StateFactAgentAttested
	StateFactJobOwned
	StateFactMonitorReady
	StateFactPrepared
	StateFactUmaskCommitted
	StateFactGateReleased
	StateFactIdentityDropped
	StateFactWorkloadFilterCommitted
	StateFactCleanupStarted
	StateFactClosed
)

const knownStateFacts = StateFactFilterCommitted | StateFactCompositionAccepted | StateFactProtocolInputStarted | StateFactAgentAttested | StateFactJobOwned | StateFactMonitorReady | StateFactPrepared | StateFactUmaskCommitted | StateFactGateReleased | StateFactIdentityDropped | StateFactWorkloadFilterCommitted | StateFactCleanupStarted | StateFactClosed

func ValidateStateFacts(value StateFact) error {
	if value&^knownStateFacts != 0 {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

// Action is the exact seccomp return action.
type Action uint32

const (
	ActionKillProcess Action = 0x80000000
	ActionErrnoEPERM  Action = 0x00050001
	ActionAllow       Action = 0x7fff0000
)

func ValidateAction(value Action) error {
	switch value {
	case ActionKillProcess, ActionErrnoEPERM, ActionAllow:
		return nil
	default:
		return contractError(ErrorCodeInvalidArgument)
	}
}

func (value Action) String() string {
	switch value {
	case ActionKillProcess:
		return "kill-process"
	case ActionErrnoEPERM:
		return "errno-eperm"
	case ActionAllow:
		return "allow"
	default:
		return "unknown"
	}
}

// Reason is one safe pure-decision reason.
type Reason uint8

const (
	ReasonExactRule Reason = 1 + iota
	ReasonForeignArchitecture
	ReasonX32Encoding
	ReasonUnknownSyscall
	ReasonForbiddenAuthority
	ReasonForbiddenSocketFamily
	ReasonArbitraryNamespace
	ReasonImpossibleTransition
	ReasonKnownUnlisted
	ReasonWrongRole
	ReasonStateMismatch
	ReasonScalarMismatch
	ReasonFDMismatch
)

func ValidateReason(value Reason) error {
	if value < ReasonExactRule || value > ReasonFDMismatch {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

func (value Reason) String() string {
	switch value {
	case ReasonExactRule:
		return "exact-rule"
	case ReasonForeignArchitecture:
		return "foreign-architecture"
	case ReasonX32Encoding:
		return "x32-encoding"
	case ReasonUnknownSyscall:
		return "unknown-syscall"
	case ReasonForbiddenAuthority:
		return "forbidden-authority"
	case ReasonForbiddenSocketFamily:
		return "forbidden-socket-family"
	case ReasonArbitraryNamespace:
		return "arbitrary-namespace"
	case ReasonImpossibleTransition:
		return "impossible-transition"
	case ReasonKnownUnlisted:
		return "known-unlisted"
	case ReasonWrongRole:
		return "wrong-role"
	case ReasonStateMismatch:
		return "state-mismatch"
	case ReasonScalarMismatch:
		return "scalar-mismatch"
	case ReasonFDMismatch:
		return "fd-mismatch"
	default:
		return "unknown"
	}
}

// DescriptorKind is one inspected descriptor authority class.
type DescriptorKind uint8

const (
	DescriptorKindInert DescriptorKind = 1 + iota
	DescriptorKindRegular
	DescriptorKindDirectory
	DescriptorKindPipeRead
	DescriptorKindPipeWrite
	DescriptorKindPIDFD
	DescriptorKindMount
	DescriptorKindFSContext
	DescriptorKindUnixConnected
	DescriptorKindUnixListening
	DescriptorKindVSOCKConnected
	DescriptorKindVSOCKListening
	DescriptorKindSeqpacket
	DescriptorKindNamespace
	DescriptorKindExecutable
	DescriptorKindSealedConfig
	DescriptorKindCgroupRoot
	DescriptorKindCgroupLeaf
	DescriptorKindProcRoot
	DescriptorKindMountTarget
	DescriptorKindGateRead
)

func ValidateDescriptorKind(value DescriptorKind) error {
	if value < DescriptorKindInert || value > DescriptorKindGateRead {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

// DescriptorAccess is one inspected access mode.
type DescriptorAccess uint8

const (
	DescriptorAccessRead DescriptorAccess = 1 + iota
	DescriptorAccessWrite
	DescriptorAccessReadWrite
	DescriptorAccessOPath
	DescriptorAccessExecute
)

func ValidateDescriptorAccess(value DescriptorAccess) error {
	if value < DescriptorAccessRead || value > DescriptorAccessExecute {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

// Check is one closed observer check capability.
type Check uint8

const (
	CheckBoundedPointer Check = 1 + iota
	CheckImmutablePointer
	CheckReservedZero
	CheckCanonicalPath
	CheckContainedBeneath
	CheckFDKind
	CheckFDAccess
	CheckFDGeneration
	CheckObjectIdentity
	CheckMountIdentity
	CheckNamespaceIdentity
	CheckCgroupIdentity
	CheckSocketIdentity
	CheckAncillaryShape
	CheckProcessIdentity
	CheckRuntimeMapping
	CheckOutputBounds
	CheckPostSuccessReinspection
	CheckFixedArgvEnv
	CheckCompiledConstant
)

func ValidateCheck(value Check) error {
	if value < CheckBoundedPointer || value > CheckCompiledConstant {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

// CheckSet is an immutable closed set of checks.
type CheckSet struct{ bits uint32 }

func NewCheckSet(checks ...Check) (CheckSet, error) {
	var result CheckSet
	for _, check := range checks {
		if ValidateCheck(check) != nil {
			return CheckSet{}, contractError(ErrorCodeCatalog)
		}
		bit := uint32(1) << (check - 1)
		if result.bits&bit != 0 {
			return CheckSet{}, contractError(ErrorCodeDuplicate)
		}
		result.bits |= bit
	}
	return result, nil
}

func (set CheckSet) Contains(check Check) bool {
	if ValidateCheck(check) != nil {
		return false
	}
	return set.bits&(uint32(1)<<(check-1)) != 0
}

func (set CheckSet) Values() []Check {
	result := make([]Check, 0, CheckCompiledConstant)
	for check := CheckBoundedPointer; check <= CheckCompiledConstant; check++ {
		if set.Contains(check) {
			result = append(result, check)
		}
	}
	return result
}

// PointerClass is one closed pointer provenance class.
type PointerClass uint8

const (
	PointerClassNone PointerClass = 1 + iota
	PointerClassFixedImage
	PointerClassBoundedMutable
	PointerClassBoundedReadOnly
	PointerClassRuntimeStack
	PointerClassRuntimeTLS
	PointerClassCanonicalRelativePath
	PointerClassCompiledPath
	PointerClassOpenHow
	PointerClassCloneArgs
	PointerClassMessageHeader
	PointerClassSocketAddress
	PointerClassMountAttributes
	PointerClassCapabilityData
	PointerClassSeccompProgram
	PointerClassArgvEnv
	PointerClassTimespec
	PointerClassSignalSet
)

func ValidatePointerClass(value PointerClass) error {
	if value < PointerClassNone || value > PointerClassSignalSet {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

type AdapterOutcome uint8

const (
	AdapterOutcomeProceed AdapterOutcome = 1 + iota
	AdapterOutcomeRejectCleanup
	AdapterOutcomeStopVM
)

func ValidateAdapterOutcome(value AdapterOutcome) error {
	if value < AdapterOutcomeProceed || value > AdapterOutcomeStopVM {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

type AdapterReason uint8

const (
	AdapterReasonExact AdapterReason = 1 + iota
	AdapterReasonStateMismatch
	AdapterReasonFDMismatch
	AdapterReasonPointerMismatch
	AdapterReasonObjectMismatch
	AdapterReasonObserverFailure
	AdapterReasonSyscallFailure
	AdapterReasonPreSyscallAbort
)

func ValidateAdapterReason(value AdapterReason) error {
	if value < AdapterReasonExact || value > AdapterReasonPreSyscallAbort {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

func (value AdapterReason) String() string {
	switch value {
	case AdapterReasonExact:
		return "exact"
	case AdapterReasonStateMismatch:
		return "state-mismatch"
	case AdapterReasonFDMismatch:
		return "fd-mismatch"
	case AdapterReasonPointerMismatch:
		return "pointer-mismatch"
	case AdapterReasonObjectMismatch:
		return "object-mismatch"
	case AdapterReasonObserverFailure:
		return "observer-failure"
	case AdapterReasonSyscallFailure:
		return "syscall-failure"
	case AdapterReasonPreSyscallAbort:
		return "pre-syscall-abort"
	default:
		return "unknown"
	}
}

type AdapterPhase uint8

const (
	AdapterPhasePre AdapterPhase = 1 + iota
	AdapterPhasePost
)

func ValidateAdapterPhase(value AdapterPhase) error {
	if value < AdapterPhasePre || value > AdapterPhasePost {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

type SyscallNumber uint32

type SyscallClass uint8

const (
	SyscallClassOrdinary SyscallClass = 1 + iota
	SyscallClassFatal
	SyscallClassConditional
)

func ValidateSyscallClass(value SyscallClass) error {
	if value < SyscallClassOrdinary || value > SyscallClassConditional {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

type EvidenceKind uint8

const (
	EvidenceKindState EvidenceKind = 1 + iota
	EvidenceKindDescriptor
	EvidenceKindPointer
	EvidenceKindArgumentObject
	EvidenceKindReturnObject
	EvidenceKindPinnedCallsite
)

func ValidateEvidenceKind(value EvidenceKind) error {
	if value < EvidenceKindState || value > EvidenceKindPinnedCallsite {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

type RuleOrigin uint8

const (
	RuleOriginRole RuleOrigin = 1 + iota
	RuleOriginWorkload
	RuleOriginRuntime
)

func ValidateRuleOrigin(value RuleOrigin) error {
	if value < RuleOriginRole || value > RuleOriginRuntime {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

type ScalarOperation uint8

const (
	ScalarEqual ScalarOperation = 1 + iota
	ScalarMaskedEqual
	ScalarOneOf
	ScalarUnsignedRange
	ScalarZero
	ScalarNonzero
)

func ValidateScalarOperation(value ScalarOperation) error {
	if value < ScalarEqual || value > ScalarNonzero {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

type ObjectSource uint8

const (
	ObjectSourceArgument ObjectSource = 1 + iota
	ObjectSourceReturn
)

func ValidateObjectSource(value ObjectSource) error {
	if value < ObjectSourceArgument || value > ObjectSourceReturn {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

type QueryKind uint8

const (
	QueryKindState QueryKind = 1 + iota
	QueryKindFD
	QueryKindPointer
	QueryKindObject
)

func ValidateQueryKind(value QueryKind) error {
	if value < QueryKindState || value > QueryKindObject {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

type EnforcementPath uint8

const (
	EnforcementPathDirect EnforcementPath = 1 + iota
	EnforcementPathAdapter
	EnforcementPathPinnedDirect
)

func ValidateEnforcementPath(value EnforcementPath) error {
	if value < EnforcementPathDirect || value > EnforcementPathPinnedDirect {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

type GenerationMode uint8

const (
	GenerationModeStaticExact GenerationMode = 1 + iota
	GenerationModeLiveBound
	GenerationModeFreshReturn
)

func ValidateGenerationMode(value GenerationMode) error {
	if value < GenerationModeStaticExact || value > GenerationModeFreshReturn {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

type BinaryBindingKind uint8

const (
	BinaryBindingKindNativeBootstrap BinaryBindingKind = 1 + iota
	BinaryBindingKindPinnedGoRuntime
)

func ValidateBinaryBindingKind(value BinaryBindingKind) error {
	if value < BinaryBindingKindNativeBootstrap || value > BinaryBindingKindPinnedGoRuntime {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

// ABIClass is the closed syscall ABI classification.
type ABIClass uint8

const (
	ABIClassNativeAMD64 ABIClass = 1 + iota
	ABIClassX32
	ABIClassForeign
)

func ValidateABIClass(value ABIClass) error {
	if value < ABIClassNativeAMD64 || value > ABIClassForeign {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}
