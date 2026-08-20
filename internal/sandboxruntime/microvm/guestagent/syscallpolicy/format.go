package syscallpolicy

import (
	"fmt"
	"strconv"
	"strings"
)

func writeScalar(state fmt.State, token string) { _, _ = state.Write([]byte(token)) }

func (value Role) GoString() string                        { return value.String() }
func (value Role) Format(state fmt.State, _ rune)          { writeScalar(state, value.String()) }
func (value Stage) GoString() string                       { return value.String() }
func (value Stage) Format(state fmt.State, _ rune)         { writeScalar(state, value.String()) }
func (value Action) GoString() string                      { return value.String() }
func (value Action) Format(state fmt.State, _ rune)        { writeScalar(state, value.String()) }
func (value Reason) GoString() string                      { return value.String() }
func (value Reason) Format(state fmt.State, _ rune)        { writeScalar(state, value.String()) }
func (value AdapterReason) GoString() string               { return value.String() }
func (value AdapterReason) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value ErrorCode) GoString() string                   { return value.String() }
func (value ErrorCode) Format(state fmt.State, _ rune)     { writeScalar(state, value.String()) }

func (value StateFact) String() string {
	if ValidateStateFacts(value) != nil || value == 0 {
		return "unknown"
	}
	result := make([]string, 0, 13)
	for _, entry := range []struct {
		fact  StateFact
		token string
	}{
		{StateFactFilterCommitted, "filter-committed"},
		{StateFactCompositionAccepted, "composition-accepted"},
		{StateFactProtocolInputStarted, "protocol-input-started"},
		{StateFactAgentAttested, "agent-attested"},
		{StateFactJobOwned, "job-owned"},
		{StateFactMonitorReady, "monitor-ready"},
		{StateFactPrepared, "prepared"},
		{StateFactUmaskCommitted, "umask-committed"},
		{StateFactGateReleased, "gate-released"},
		{StateFactIdentityDropped, "identity-dropped"},
		{StateFactWorkloadFilterCommitted, "workload-filter-committed"},
		{StateFactCleanupStarted, "cleanup-started"},
		{StateFactClosed, "closed"},
	} {
		if value&entry.fact != 0 {
			result = append(result, entry.token)
		}
	}
	return strings.Join(result, "|")
}
func (value StateFact) GoString() string               { return value.String() }
func (value StateFact) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }

func (value DescriptorKind) String() string {
	switch value {
	case DescriptorKindInert:
		return "inert"
	case DescriptorKindRegular:
		return "regular"
	case DescriptorKindDirectory:
		return "directory"
	case DescriptorKindPipeRead:
		return "pipe-read"
	case DescriptorKindPipeWrite:
		return "pipe-write"
	case DescriptorKindPIDFD:
		return "pidfd"
	case DescriptorKindMount:
		return "mount"
	case DescriptorKindFSContext:
		return "fs-context"
	case DescriptorKindUnixConnected:
		return "unix-connected"
	case DescriptorKindUnixListening:
		return "unix-listening"
	case DescriptorKindVSOCKConnected:
		return "vsock-connected"
	case DescriptorKindVSOCKListening:
		return "vsock-listening"
	case DescriptorKindSeqpacket:
		return "seqpacket"
	case DescriptorKindNamespace:
		return "namespace"
	case DescriptorKindExecutable:
		return "executable"
	case DescriptorKindSealedConfig:
		return "sealed-config"
	case DescriptorKindCgroupRoot:
		return "cgroup-root"
	case DescriptorKindCgroupLeaf:
		return "cgroup-leaf"
	case DescriptorKindProcRoot:
		return "proc-root"
	case DescriptorKindMountTarget:
		return "mount-target"
	case DescriptorKindGateRead:
		return "gate-read"
	default:
		return "unknown"
	}
}
func (value DescriptorKind) GoString() string               { return value.String() }
func (value DescriptorKind) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }

func (value DescriptorAccess) String() string {
	switch value {
	case DescriptorAccessRead:
		return "read"
	case DescriptorAccessWrite:
		return "write"
	case DescriptorAccessReadWrite:
		return "read-write"
	case DescriptorAccessOPath:
		return "o-path"
	case DescriptorAccessExecute:
		return "execute"
	default:
		return "unknown"
	}
}
func (value DescriptorAccess) GoString() string               { return value.String() }
func (value DescriptorAccess) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }

func (value Check) String() string {
	switch value {
	case CheckBoundedPointer:
		return "bounded-pointer"
	case CheckImmutablePointer:
		return "immutable-pointer"
	case CheckReservedZero:
		return "reserved-zero"
	case CheckCanonicalPath:
		return "canonical-path"
	case CheckContainedBeneath:
		return "contained-beneath"
	case CheckFDKind:
		return "fd-kind"
	case CheckFDAccess:
		return "fd-access"
	case CheckFDGeneration:
		return "fd-generation"
	case CheckObjectIdentity:
		return "object-identity"
	case CheckMountIdentity:
		return "mount-identity"
	case CheckNamespaceIdentity:
		return "namespace-identity"
	case CheckCgroupIdentity:
		return "cgroup-identity"
	case CheckSocketIdentity:
		return "socket-identity"
	case CheckAncillaryShape:
		return "ancillary-shape"
	case CheckProcessIdentity:
		return "process-identity"
	case CheckRuntimeMapping:
		return "runtime-mapping"
	case CheckOutputBounds:
		return "output-bounds"
	case CheckPostSuccessReinspection:
		return "post-success-reinspection"
	case CheckFixedArgvEnv:
		return "fixed-argv-env"
	case CheckCompiledConstant:
		return "compiled-constant"
	default:
		return "unknown"
	}
}
func (value Check) GoString() string               { return value.String() }
func (value Check) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }

func (value PointerClass) String() string {
	switch value {
	case PointerClassNone:
		return "none"
	case PointerClassFixedImage:
		return "fixed-image"
	case PointerClassBoundedMutable:
		return "bounded-mutable"
	case PointerClassBoundedReadOnly:
		return "bounded-read-only"
	case PointerClassRuntimeStack:
		return "runtime-stack"
	case PointerClassRuntimeTLS:
		return "runtime-tls"
	case PointerClassCanonicalRelativePath:
		return "canonical-relative-path"
	case PointerClassCompiledPath:
		return "compiled-path"
	case PointerClassOpenHow:
		return "open-how"
	case PointerClassCloneArgs:
		return "clone-args"
	case PointerClassMessageHeader:
		return "message-header"
	case PointerClassSocketAddress:
		return "socket-address"
	case PointerClassMountAttributes:
		return "mount-attributes"
	case PointerClassCapabilityData:
		return "capability-data"
	case PointerClassSeccompProgram:
		return "seccomp-program"
	case PointerClassArgvEnv:
		return "argv-env"
	case PointerClassTimespec:
		return "timespec"
	case PointerClassSignalSet:
		return "signal-set"
	default:
		return "unknown"
	}
}
func (value PointerClass) GoString() string               { return value.String() }
func (value PointerClass) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }

func (value AdapterOutcome) String() string {
	switch value {
	case AdapterOutcomeProceed:
		return "proceed"
	case AdapterOutcomeRejectCleanup:
		return "reject-cleanup"
	case AdapterOutcomeStopVM:
		return "stop-vm"
	default:
		return "unknown"
	}
}
func (value AdapterOutcome) GoString() string               { return value.String() }
func (value AdapterOutcome) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value AdapterPhase) String() string {
	if value == AdapterPhasePre {
		return "pre"
	}
	if value == AdapterPhasePost {
		return "post"
	}
	return "unknown"
}
func (value AdapterPhase) GoString() string               { return value.String() }
func (value AdapterPhase) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }

func (value SyscallNumber) String() string                 { return strconv.FormatUint(uint64(value), 10) }
func (value SyscallNumber) GoString() string               { return value.String() }
func (value SyscallNumber) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value SyscallClass) String() string {
	switch value {
	case SyscallClassOrdinary:
		return "ordinary"
	case SyscallClassFatal:
		return "fatal"
	case SyscallClassConditional:
		return "conditional"
	default:
		return "unknown"
	}
}
func (value SyscallClass) GoString() string               { return value.String() }
func (value SyscallClass) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value EvidenceKind) String() string {
	switch value {
	case EvidenceKindState:
		return "state"
	case EvidenceKindDescriptor:
		return "descriptor"
	case EvidenceKindPointer:
		return "pointer"
	case EvidenceKindArgumentObject:
		return "argument-object"
	case EvidenceKindReturnObject:
		return "return-object"
	case EvidenceKindPinnedCallsite:
		return "pinned-callsite"
	default:
		return "unknown"
	}
}
func (value EvidenceKind) GoString() string               { return value.String() }
func (value EvidenceKind) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value RuleOrigin) String() string {
	switch value {
	case RuleOriginRole:
		return "role"
	case RuleOriginWorkload:
		return "workload"
	case RuleOriginRuntime:
		return "runtime"
	default:
		return "unknown"
	}
}
func (value RuleOrigin) GoString() string               { return value.String() }
func (value RuleOrigin) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value ScalarOperation) String() string {
	switch value {
	case ScalarEqual:
		return "equal"
	case ScalarMaskedEqual:
		return "masked-equal"
	case ScalarOneOf:
		return "one-of"
	case ScalarUnsignedRange:
		return "unsigned-range"
	case ScalarZero:
		return "zero"
	case ScalarNonzero:
		return "nonzero"
	default:
		return "unknown"
	}
}
func (value ScalarOperation) GoString() string               { return value.String() }
func (value ScalarOperation) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value ObjectSource) String() string {
	if value == ObjectSourceArgument {
		return "argument"
	}
	if value == ObjectSourceReturn {
		return "return"
	}
	return "unknown"
}
func (value ObjectSource) GoString() string               { return value.String() }
func (value ObjectSource) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value QueryKind) String() string {
	switch value {
	case QueryKindState:
		return "state"
	case QueryKindFD:
		return "fd"
	case QueryKindPointer:
		return "pointer"
	case QueryKindObject:
		return "object"
	default:
		return "unknown"
	}
}
func (value QueryKind) GoString() string               { return value.String() }
func (value QueryKind) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value EnforcementPath) String() string {
	switch value {
	case EnforcementPathDirect:
		return "direct"
	case EnforcementPathAdapter:
		return "adapter"
	case EnforcementPathPinnedDirect:
		return "pinned-direct"
	default:
		return "unknown"
	}
}
func (value EnforcementPath) GoString() string               { return value.String() }
func (value EnforcementPath) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value GenerationMode) String() string {
	switch value {
	case GenerationModeStaticExact:
		return "static-exact"
	case GenerationModeLiveBound:
		return "live-bound"
	case GenerationModeFreshReturn:
		return "fresh-return"
	default:
		return "unknown"
	}
}
func (value GenerationMode) GoString() string               { return value.String() }
func (value GenerationMode) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value BinaryBindingKind) String() string {
	if value == BinaryBindingKindNativeBootstrap {
		return "native-bootstrap"
	}
	if value == BinaryBindingKindPinnedGoRuntime {
		return "pinned-go-runtime"
	}
	return "unknown"
}
func (value BinaryBindingKind) GoString() string               { return value.String() }
func (value BinaryBindingKind) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
func (value ABIClass) String() string {
	switch value {
	case ABIClassNativeAMD64:
		return "native-amd64"
	case ABIClassX32:
		return "x32"
	case ABIClassForeign:
		return "foreign"
	default:
		return "unknown"
	}
}
func (value ABIClass) GoString() string               { return value.String() }
func (value ABIClass) Format(state fmt.State, _ rune) { writeScalar(state, value.String()) }
