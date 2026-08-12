package l8composition

import (
	"crypto/sha256"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	ControllerMonitorMagic   = "HL8M"
	ControllerMonitorVersion = 1
	ControllerMonitorFlags   = 0

	ControllerMonitorHeaderBytes                   = 68
	MaxControllerMonitorBodyBytes                  = 73728
	MaxControllerMonitorDatagramBytes              = ControllerMonitorHeaderBytes + MaxControllerMonitorBodyBytes
	MaxControllerMonitorPacketsPerDirection uint64 = 1 << 32

	ControllerMonitorLimitSetID = "helper-limits-v1"
)

var (
	ErrControllerMonitorHeaderLength         = errors.New("L8 controller-monitor header length is invalid")
	ErrControllerMonitorMagic                = errors.New("L8 controller-monitor magic is invalid")
	ErrControllerMonitorVersion              = errors.New("L8 controller-monitor version is invalid")
	ErrControllerMonitorFlags                = errors.New("L8 controller-monitor flags are invalid")
	ErrControllerMonitorPacketType           = errors.New("L8 controller-monitor packet type is invalid")
	ErrControllerMonitorDirection            = errors.New("L8 controller-monitor direction is invalid")
	ErrControllerMonitorPacketDirection      = errors.New("L8 controller-monitor packet direction is invalid")
	ErrControllerMonitorRequestIdentity      = errors.New("L8 controller-monitor request identity is invalid")
	ErrControllerMonitorJobIdentity          = errors.New("L8 controller-monitor job identity is invalid")
	ErrControllerMonitorBodyLength           = errors.New("L8 controller-monitor body length is invalid")
	ErrControllerMonitorDatagramLength       = errors.New("L8 controller-monitor datagram is truncated")
	ErrControllerMonitorDatagramTrailingData = errors.New("L8 controller-monitor datagram has trailing data")
	ErrControllerMonitorBody                 = errors.New("L8 controller-monitor packet body is invalid")
	ErrControllerMonitorRevision             = errors.New("L8 controller-monitor revision is invalid")
	ErrControllerMonitorDigest               = errors.New("L8 controller-monitor digest is invalid")
	ErrControllerMonitorGeneration           = errors.New("L8 controller-monitor generation is invalid")
	ErrControllerMonitorLimitSet             = errors.New("L8 controller-monitor limit set is invalid")
	ErrControllerMonitorResponse             = errors.New("L8 controller-monitor response is invalid")
	ErrControllerMonitorResponseResult       = errors.New("L8 controller-monitor response result is invalid")
	ErrControllerMonitorFailureCode          = errors.New("L8 controller-monitor failure code is invalid")
	ErrControllerMonitorEventCode            = errors.New("L8 controller-monitor event code is invalid")
	ErrControllerMonitorCleanupCategory      = errors.New("L8 controller-monitor cleanup category is invalid")
	ErrControllerMonitorEvent                = errors.New("L8 controller-monitor event is invalid")
	ErrControllerMonitorBoolean              = errors.New("L8 controller-monitor boolean is invalid")
	ErrControllerMonitorRights               = errors.New("L8 controller-monitor ancillary rights are invalid")
	ErrControllerMonitorRightKind            = errors.New("L8 controller-monitor ancillary right kind is invalid")
	ErrControllerMonitorRightAccess          = errors.New("L8 controller-monitor ancillary right access is invalid")
	ErrControllerMonitorTruncated            = errors.New("L8 controller-monitor receive metadata reports truncation")
	ErrControllerMonitorCredentialCount      = errors.New("L8 controller-monitor kernel credential count is invalid")
	ErrControllerMonitorKernelCredential     = errors.New("L8 controller-monitor kernel credential does not match")
	ErrControllerMonitorRoleIdentityAlias    = errors.New("L8 controller-monitor role identities alias")
	ErrControllerMonitorSerialization        = errors.New("L8 controller-monitor serialization is denied")
)

type ControllerMonitorPacketType uint8

const (
	ControllerMonitorPacketTypeMonitorReady      ControllerMonitorPacketType = 0x01
	ControllerMonitorPacketTypePrepareBegin      ControllerMonitorPacketType = 0x10
	ControllerMonitorPacketTypePrepareFile       ControllerMonitorPacketType = 0x11
	ControllerMonitorPacketTypePrepareCommit     ControllerMonitorPacketType = 0x12
	ControllerMonitorPacketTypeCreateSSHEndpoint ControllerMonitorPacketType = 0x13
	ControllerMonitorPacketTypeRevoke            ControllerMonitorPacketType = 0x14
	ControllerMonitorPacketTypeResponse          ControllerMonitorPacketType = 0x20
	ControllerMonitorPacketTypeMonitorEvent      ControllerMonitorPacketType = 0x21
	ControllerMonitorPacketTypeCloseNotify       ControllerMonitorPacketType = 0x7f
)

type ControllerMonitorDirection uint8

const (
	ControllerMonitorDirectionMonitorToPID1       ControllerMonitorDirection = 1
	ControllerMonitorDirectionControllerToMonitor ControllerMonitorDirection = 2
	ControllerMonitorDirectionMonitorToController ControllerMonitorDirection = 3
)

type ControllerMonitorRightKind uint8

const (
	ControllerMonitorRightControllerEndpoint ControllerMonitorRightKind = 1
	ControllerMonitorRightMountNamespace     ControllerMonitorRightKind = 2
	ControllerMonitorRightSSHListener        ControllerMonitorRightKind = 3
)

type ControllerMonitorRightAccess uint8

const (
	ControllerMonitorRightDuplexSeqpacket ControllerMonitorRightAccess = 1
	ControllerMonitorRightNamespaceEnter  ControllerMonitorRightAccess = 2
	ControllerMonitorRightListenStream    ControllerMonitorRightAccess = 3
)

type ControllerMonitorFailureCode uint8

const (
	ControllerMonitorFailureNone              ControllerMonitorFailureCode = 0
	ControllerMonitorFailureResourceLimit     ControllerMonitorFailureCode = 1
	ControllerMonitorFailurePrepareFailed     ControllerMonitorFailureCode = 2
	ControllerMonitorFailureSSHEndpointFailed ControllerMonitorFailureCode = 3
	ControllerMonitorFailureRevokeFailed      ControllerMonitorFailureCode = 4
	ControllerMonitorFailureInspectionFailed  ControllerMonitorFailureCode = 5
	ControllerMonitorFailureCleanupIncomplete ControllerMonitorFailureCode = 6
	ControllerMonitorFailureOperationDenied   ControllerMonitorFailureCode = 7
)

type ControllerMonitorEventCode uint8

const (
	ControllerMonitorEventExpired         ControllerMonitorEventCode = 1
	ControllerMonitorEventMountDrift      ControllerMonitorEventCode = 2
	ControllerMonitorEventEndpointDrift   ControllerMonitorEventCode = 3
	ControllerMonitorEventCleanupRequired ControllerMonitorEventCode = 4
)

type ControllerMonitorCleanupCategory uint8

const (
	ControllerMonitorCleanupNotApplicable  ControllerMonitorCleanupCategory = 1
	ControllerMonitorCleanupComplete       ControllerMonitorCleanupCategory = 2
	ControllerMonitorCleanupRetryRequired  ControllerMonitorCleanupCategory = 3
	ControllerMonitorCleanupStopVMRequired ControllerMonitorCleanupCategory = 4
)

type ControllerMonitorHeader struct {
	Type              ControllerMonitorPacketType
	Sequence          uint64
	RequestID         [16]byte
	JobIdentityDigest [sha256.Size]byte
	BodyLength        uint32
}

type ControllerMonitorKernelCredential struct {
	PID uint32
	UID uint32
	GID uint32
}

type ControllerMonitorRightMetadata struct {
	Index             uint32
	Kind              ControllerMonitorRightKind
	Access            ControllerMonitorRightAccess
	Generation        string
	CorrelationSHA256 [sha256.Size]byte
}

type ControllerMonitorReceiveMetadata struct {
	Direction        ControllerMonitorDirection
	CredentialCount  uint32
	Credential       ControllerMonitorKernelCredential
	RightsCount      uint32
	Rights           [2]ControllerMonitorRightMetadata
	MessageTruncated bool
	ControlTruncated bool
}

func ValidateControllerMonitorPacketType(value ControllerMonitorPacketType) error {
	switch value {
	case ControllerMonitorPacketTypeMonitorReady, ControllerMonitorPacketTypePrepareBegin,
		ControllerMonitorPacketTypePrepareFile, ControllerMonitorPacketTypePrepareCommit,
		ControllerMonitorPacketTypeCreateSSHEndpoint, ControllerMonitorPacketTypeRevoke,
		ControllerMonitorPacketTypeResponse, ControllerMonitorPacketTypeMonitorEvent,
		ControllerMonitorPacketTypeCloseNotify:
		return nil
	default:
		return ErrControllerMonitorPacketType
	}
}

func ValidateControllerMonitorDirection(value ControllerMonitorDirection) error {
	switch value {
	case ControllerMonitorDirectionMonitorToPID1, ControllerMonitorDirectionControllerToMonitor, ControllerMonitorDirectionMonitorToController:
		return nil
	default:
		return ErrControllerMonitorDirection
	}
}

func ValidateControllerMonitorRightKind(value ControllerMonitorRightKind) error {
	if value < ControllerMonitorRightControllerEndpoint || value > ControllerMonitorRightSSHListener {
		return ErrControllerMonitorRightKind
	}
	return nil
}

func ValidateControllerMonitorRightAccess(value ControllerMonitorRightAccess) error {
	if value < ControllerMonitorRightDuplexSeqpacket || value > ControllerMonitorRightListenStream {
		return ErrControllerMonitorRightAccess
	}
	return nil
}

func ValidateControllerMonitorFailureCode(value ControllerMonitorFailureCode) error {
	if value > ControllerMonitorFailureOperationDenied {
		return ErrControllerMonitorFailureCode
	}
	return nil
}

func ValidateControllerMonitorEventCode(value ControllerMonitorEventCode) error {
	if value < ControllerMonitorEventExpired || value > ControllerMonitorEventCleanupRequired {
		return ErrControllerMonitorEventCode
	}
	return nil
}

func ValidateControllerMonitorCleanupCategory(value ControllerMonitorCleanupCategory) error {
	if value < ControllerMonitorCleanupNotApplicable || value > ControllerMonitorCleanupStopVMRequired {
		return ErrControllerMonitorCleanupCategory
	}
	return nil
}

func validControllerMonitorPID(value uint32) bool { return value >= 2 && value <= 1<<31-1 }

func validControllerMonitorRootCredential(value ControllerMonitorKernelCredential) bool {
	return validControllerMonitorPID(value.PID) && value.UID == 0 && value.GID == 0
}

func validControllerMonitorSafeID(value string) bool {
	return credentialprotocol.ValidateBodyToken(value) == nil && credentialprotocol.ValidateSafeID(credentialprotocol.SafeID(value)) == nil
}

func controllerMonitorZero16(value [16]byte) bool { return value == [16]byte{} }
func controllerMonitorZero32(value [32]byte) bool { return value == [32]byte{} }
