package l8composition

import (
	"crypto/sha256"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	ControllerSupervisorMagic   = "HL8L"
	ControllerSupervisorVersion = 1
	ControllerSupervisorFlags   = 0

	ControllerSupervisorHeaderBytes            = 68
	MaxControllerSupervisorBodyBytes           = 8 * 1024
	MaxControllerSupervisorDatagramBytes       = ControllerSupervisorHeaderBytes + MaxControllerSupervisorBodyBytes
	MaxControllerSupervisorPacketsPerDirection = uint64(1) << 32
	MaxControllerSupervisorRights              = 8
	MaxControllerSupervisorLaunches            = 4096
	ControllerSupervisorLimitSetID             = "helper-limits-v1"
)

var (
	ErrControllerSupervisorSerialization        = errors.New("L8 controller-supervisor serialization is denied")
	ErrControllerSupervisorPacketType           = errors.New("L8 controller-supervisor packet type is invalid")
	ErrControllerSupervisorDirection            = errors.New("L8 controller-supervisor direction is invalid")
	ErrControllerSupervisorPacketDirection      = errors.New("L8 controller-supervisor packet direction is invalid")
	ErrControllerSupervisorRightKind            = errors.New("L8 controller-supervisor right kind is invalid")
	ErrControllerSupervisorRightAccess          = errors.New("L8 controller-supervisor right access is invalid")
	ErrControllerSupervisorRightMetadata        = errors.New("L8 controller-supervisor right metadata is invalid")
	ErrControllerSupervisorRights               = errors.New("L8 controller-supervisor ancillary rights are invalid")
	ErrControllerSupervisorCredentialCount      = errors.New("L8 controller-supervisor kernel credential count is invalid")
	ErrControllerSupervisorKernelCredential     = errors.New("L8 controller-supervisor kernel credential does not match")
	ErrControllerSupervisorRoleIdentityAlias    = errors.New("L8 controller-supervisor role identities alias")
	ErrControllerSupervisorTruncated            = errors.New("L8 controller-supervisor receive metadata reports truncation")
	ErrControllerSupervisorHeaderLength         = errors.New("L8 controller-supervisor header length is invalid")
	ErrControllerSupervisorMagic                = errors.New("L8 controller-supervisor magic is invalid")
	ErrControllerSupervisorVersion              = errors.New("L8 controller-supervisor version is invalid")
	ErrControllerSupervisorFlags                = errors.New("L8 controller-supervisor flags are invalid")
	ErrControllerSupervisorBodyLength           = errors.New("L8 controller-supervisor body length is invalid")
	ErrControllerSupervisorSequence             = errors.New("L8 controller-supervisor packet sequence is invalid")
	ErrControllerSupervisorDatagramLength       = errors.New("L8 controller-supervisor datagram is truncated")
	ErrControllerSupervisorDatagramTrailingData = errors.New("L8 controller-supervisor datagram has trailing data")
	ErrControllerSupervisorRequestID            = errors.New("L8 controller-supervisor request ID semantics are invalid")
	ErrControllerSupervisorJobIdentity          = errors.New("L8 controller-supervisor job identity semantics are invalid")
	ErrControllerSupervisorBody                 = errors.New("L8 controller-supervisor body is invalid")
	ErrControllerSupervisorBodyTruncated        = errors.New("L8 controller-supervisor body is truncated")
	ErrControllerSupervisorBodyTrailingData     = errors.New("L8 controller-supervisor body has trailing data")
	ErrControllerSupervisorDigestZero           = errors.New("L8 controller-supervisor digest is zero")
	ErrControllerSupervisorRevision             = errors.New("L8 controller-supervisor revision is invalid")
	ErrControllerSupervisorLimitSet             = errors.New("L8 controller-supervisor limit set is invalid")
	ErrControllerSupervisorLaunchID             = errors.New("L8 controller-supervisor launch ID is invalid")
	ErrControllerSupervisorReason               = errors.New("L8 controller-supervisor reason is invalid")
	ErrControllerSupervisorEventCode            = errors.New("L8 controller-supervisor event code is invalid")
	ErrControllerSupervisorFailureCode          = errors.New("L8 controller-supervisor failure code is invalid")
	ErrControllerSupervisorFailureCorrelation   = errors.New("L8 controller-supervisor failure correlation is invalid")
	ErrControllerSupervisorExitCategory         = errors.New("L8 controller-supervisor exit category is invalid")
	ErrControllerSupervisorExitCode             = errors.New("L8 controller-supervisor exit code is invalid")
	ErrControllerSupervisorMonitorState         = errors.New("L8 controller-supervisor monitor state is invalid")
	ErrControllerSupervisorCleanupCategory      = errors.New("L8 controller-supervisor cleanup category is invalid")
	ErrControllerSupervisorEventUnion           = errors.New("L8 controller-supervisor event union is invalid")
	ErrControllerSupervisorReserved             = errors.New("L8 controller-supervisor reserved field is nonzero")
	ErrControllerSupervisorDescriptorLength     = errors.New("L8 controller-supervisor descriptor length is invalid")
	ErrControllerSupervisorDescriptorRole       = errors.New("L8 controller-supervisor descriptor role is invalid")
	ErrControllerSupervisorDescriptorDigest     = errors.New("L8 controller-supervisor descriptor digest is invalid")
)

type ControllerSupervisorPacketType uint8

const (
	ControllerSupervisorPacketTypeSupervisorReady       ControllerSupervisorPacketType = 0x01
	ControllerSupervisorPacketTypeCreateJob             ControllerSupervisorPacketType = 0x02
	ControllerSupervisorPacketTypeJobCreated            ControllerSupervisorPacketType = 0x03
	ControllerSupervisorPacketTypeLaunchShim            ControllerSupervisorPacketType = 0x04
	ControllerSupervisorPacketTypeShimStarted           ControllerSupervisorPacketType = 0x05
	ControllerSupervisorPacketTypeTerminateJob          ControllerSupervisorPacketType = 0x06
	ControllerSupervisorPacketTypeDestroyJob            ControllerSupervisorPacketType = 0x07
	ControllerSupervisorPacketTypeSupervisorEvent       ControllerSupervisorPacketType = 0x08
	ControllerSupervisorPacketTypeControllerAttestation ControllerSupervisorPacketType = 0x09
	ControllerSupervisorPacketTypeCompositionAccepted   ControllerSupervisorPacketType = 0x0a
	ControllerSupervisorPacketTypeCloseNotify           ControllerSupervisorPacketType = 0x7f
)

type ControllerSupervisorDirection uint8

const (
	ControllerSupervisorDirectionPID1ToController ControllerSupervisorDirection = 1
	ControllerSupervisorDirectionControllerToPID1 ControllerSupervisorDirection = 2
)

type ControllerSupervisorRightKind uint8

const (
	ControllerSupervisorRightMonitorEndpoint  ControllerSupervisorRightKind = 1
	ControllerSupervisorRightMonitorNamespace ControllerSupervisorRightKind = 2
	ControllerSupervisorRightWorkdir          ControllerSupervisorRightKind = 3
	ControllerSupervisorRightExecutable       ControllerSupervisorRightKind = 4
	ControllerSupervisorRightStdinRead        ControllerSupervisorRightKind = 5
	ControllerSupervisorRightStdoutWrite      ControllerSupervisorRightKind = 6
	ControllerSupervisorRightStderrWrite      ControllerSupervisorRightKind = 7
	ControllerSupervisorRightStartGateRead    ControllerSupervisorRightKind = 8
	ControllerSupervisorRightLaunchBlockRead  ControllerSupervisorRightKind = 9
)

type ControllerSupervisorRightAccess uint8

const (
	ControllerSupervisorAccessDuplexSeqpacket ControllerSupervisorRightAccess = 1
	ControllerSupervisorAccessNamespaceEnter  ControllerSupervisorRightAccess = 2
	ControllerSupervisorAccessDirectoryChdir  ControllerSupervisorRightAccess = 3
	ControllerSupervisorAccessExecutableRead  ControllerSupervisorRightAccess = 4
	ControllerSupervisorAccessPipeRead        ControllerSupervisorRightAccess = 5
	ControllerSupervisorAccessPipeWrite       ControllerSupervisorRightAccess = 6
	ControllerSupervisorAccessSealedPipeRead  ControllerSupervisorRightAccess = 7
)

type ControllerSupervisorReason uint8

const (
	ControllerSupervisorReasonRequested      ControllerSupervisorReason = 1
	ControllerSupervisorReasonExpired        ControllerSupervisorReason = 2
	ControllerSupervisorReasonSessionLoss    ControllerSupervisorReason = 3
	ControllerSupervisorReasonSourceRevoked  ControllerSupervisorReason = 4
	ControllerSupervisorReasonWorkerCancel   ControllerSupervisorReason = 5
	ControllerSupervisorReasonDaemonShutdown ControllerSupervisorReason = 6
	ControllerSupervisorReasonLaunchFailed   ControllerSupervisorReason = 7
	ControllerSupervisorReasonExecFailed     ControllerSupervisorReason = 8
)

type ControllerSupervisorEventCode uint8

const (
	ControllerSupervisorEventShimExited      ControllerSupervisorEventCode = 1
	ControllerSupervisorEventOperationFailed ControllerSupervisorEventCode = 2
	ControllerSupervisorEventJobTerminated   ControllerSupervisorEventCode = 3
	ControllerSupervisorEventJobDestroyed    ControllerSupervisorEventCode = 4
	ControllerSupervisorEventCleanupObserved ControllerSupervisorEventCode = 5
)

type ControllerSupervisorFailureCode uint8

const (
	ControllerSupervisorFailureNone                          ControllerSupervisorFailureCode = 0
	ControllerSupervisorFailureResourceLimit                 ControllerSupervisorFailureCode = 1
	ControllerSupervisorFailureCreateFailed                  ControllerSupervisorFailureCode = 2
	ControllerSupervisorFailureLaunchFailed                  ControllerSupervisorFailureCode = 3
	ControllerSupervisorFailureTerminateFailed               ControllerSupervisorFailureCode = 4
	ControllerSupervisorFailureDestroyFailed                 ControllerSupervisorFailureCode = 5
	ControllerSupervisorFailureCleanupIncomplete             ControllerSupervisorFailureCode = 6
	ControllerSupervisorFailureMonitorUnavailable            ControllerSupervisorFailureCode = 7
	ControllerSupervisorFailureCgroupUnavailable             ControllerSupervisorFailureCode = 8
	ControllerSupervisorFailureProcessTerminationUnconfirmed ControllerSupervisorFailureCode = 9
)

type ControllerSupervisorExitCategory uint8

const (
	ControllerSupervisorExitNotApplicable          ControllerSupervisorExitCategory = 0
	ControllerSupervisorExitExited                 ControllerSupervisorExitCategory = 1
	ControllerSupervisorExitSignaled               ControllerSupervisorExitCategory = 2
	ControllerSupervisorExitLaunchTransitionFailed ControllerSupervisorExitCategory = 3
	ControllerSupervisorExitUnknown                ControllerSupervisorExitCategory = 4
)

type ControllerSupervisorMonitorState uint8

const (
	ControllerSupervisorMonitorNotApplicable  ControllerSupervisorMonitorState = 0
	ControllerSupervisorMonitorStarting       ControllerSupervisorMonitorState = 1
	ControllerSupervisorMonitorReady          ControllerSupervisorMonitorState = 2
	ControllerSupervisorMonitorCleanupPending ControllerSupervisorMonitorState = 3
	ControllerSupervisorMonitorAbsent         ControllerSupervisorMonitorState = 4
	ControllerSupervisorMonitorLost           ControllerSupervisorMonitorState = 5
)

type ControllerSupervisorCleanupCategory uint8

const (
	ControllerSupervisorCleanupNotApplicable  ControllerSupervisorCleanupCategory = 1
	ControllerSupervisorCleanupComplete       ControllerSupervisorCleanupCategory = 2
	ControllerSupervisorCleanupRetryRequired  ControllerSupervisorCleanupCategory = 3
	ControllerSupervisorCleanupStopVMRequired ControllerSupervisorCleanupCategory = 4
)

type ControllerSupervisorHeader struct {
	Type              ControllerSupervisorPacketType
	Sequence          uint64
	RequestID         [16]byte
	JobIdentityDigest [sha256.Size]byte
	BodyLength        uint32
}

type ControllerSupervisorKernelCredential struct {
	PID uint32
	UID uint32
	GID uint32
}

type ControllerSupervisorRightMetadata struct {
	Kind       ControllerSupervisorRightKind
	Access     ControllerSupervisorRightAccess
	Generation credentialprotocol.SafeID
	SHA256     [sha256.Size]byte
}

type ControllerSupervisorReceiveMetadata struct {
	Direction        ControllerSupervisorDirection
	Credential       ControllerSupervisorKernelCredential
	CredentialCount  uint32
	RightsCount      uint32
	Rights           [MaxControllerSupervisorRights]ControllerSupervisorRightMetadata
	MessageTruncated bool
	ControlTruncated bool
}

func ValidateControllerSupervisorPacketType(value ControllerSupervisorPacketType) error {
	switch value {
	case ControllerSupervisorPacketTypeSupervisorReady, ControllerSupervisorPacketTypeCreateJob,
		ControllerSupervisorPacketTypeJobCreated, ControllerSupervisorPacketTypeLaunchShim,
		ControllerSupervisorPacketTypeShimStarted, ControllerSupervisorPacketTypeTerminateJob,
		ControllerSupervisorPacketTypeDestroyJob, ControllerSupervisorPacketTypeSupervisorEvent,
		ControllerSupervisorPacketTypeControllerAttestation, ControllerSupervisorPacketTypeCompositionAccepted,
		ControllerSupervisorPacketTypeCloseNotify:
		return nil
	default:
		return ErrControllerSupervisorPacketType
	}
}

func ValidateControllerSupervisorDirection(value ControllerSupervisorDirection) error {
	if value != ControllerSupervisorDirectionPID1ToController && value != ControllerSupervisorDirectionControllerToPID1 {
		return ErrControllerSupervisorDirection
	}
	return nil
}

func ValidateControllerSupervisorRightKind(value ControllerSupervisorRightKind) error {
	if value < ControllerSupervisorRightMonitorEndpoint || value > ControllerSupervisorRightLaunchBlockRead {
		return ErrControllerSupervisorRightKind
	}
	return nil
}

func ValidateControllerSupervisorRightAccess(value ControllerSupervisorRightAccess) error {
	if value < ControllerSupervisorAccessDuplexSeqpacket || value > ControllerSupervisorAccessSealedPipeRead {
		return ErrControllerSupervisorRightAccess
	}
	return nil
}

func ValidateControllerSupervisorReason(value ControllerSupervisorReason) error {
	if value < ControllerSupervisorReasonRequested || value > ControllerSupervisorReasonExecFailed {
		return ErrControllerSupervisorReason
	}
	return nil
}
func ValidateControllerSupervisorEventCode(value ControllerSupervisorEventCode) error {
	if value < ControllerSupervisorEventShimExited || value > ControllerSupervisorEventCleanupObserved {
		return ErrControllerSupervisorEventCode
	}
	return nil
}
func ValidateControllerSupervisorFailureCode(value ControllerSupervisorFailureCode) error {
	if value > ControllerSupervisorFailureProcessTerminationUnconfirmed {
		return ErrControllerSupervisorFailureCode
	}
	return nil
}
func ValidateControllerSupervisorExitCategory(value ControllerSupervisorExitCategory) error {
	if value > ControllerSupervisorExitUnknown {
		return ErrControllerSupervisorExitCategory
	}
	return nil
}
func ValidateControllerSupervisorMonitorState(value ControllerSupervisorMonitorState) error {
	if value > ControllerSupervisorMonitorLost {
		return ErrControllerSupervisorMonitorState
	}
	return nil
}
func ValidateControllerSupervisorCleanupCategory(value ControllerSupervisorCleanupCategory) error {
	if value < ControllerSupervisorCleanupNotApplicable || value > ControllerSupervisorCleanupStopVMRequired {
		return ErrControllerSupervisorCleanupCategory
	}
	return nil
}

func controllerSupervisorZero16(value [16]byte) bool { return value == [16]byte{} }
func controllerSupervisorZero32(value [32]byte) bool { return value == [32]byte{} }
