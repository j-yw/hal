package credentialprotocol

import "errors"

const (
	// MaxSafeIDBytes is the cross-phase bound for redaction-safe identifiers.
	MaxSafeIDBytes = 128
	// MaxExtensionIDBytes is the tighter canonical process-descriptor ID bound.
	MaxExtensionIDBytes = 64
	// MaxExtensionCatalogEntries bounds each descriptor catalog slice.
	MaxExtensionCatalogEntries = 16
	// MaxExtensions bounds one matching process extension set.
	MaxExtensions = 16
)

var (
	ErrInvalidSafeID       = errors.New("credential protocol safe ID is invalid")
	ErrUnknownDeliveryMode = errors.New("credential protocol delivery mode is unknown")
	ErrUnknownPacketType   = errors.New("credential protocol packet type is unknown")
	ErrInvalidExtensionID  = errors.New("credential protocol extension ID is invalid")
)

// SafeID is a nonempty redaction-safe identifier in the shared L8 vocabulary.
type SafeID string

// ValidateSafeID accepts only 1..128 ASCII bytes from [A-Za-z0-9._-]. It does
// not trim, normalize, or case-fold its input.
func ValidateSafeID(id SafeID) error {
	value := string(id)
	if len(value) == 0 || len(value) > MaxSafeIDBytes {
		return ErrInvalidSafeID
	}
	for index := 0; index < len(value); index++ {
		if !isSafeIDByte(value[index]) {
			return ErrInvalidSafeID
		}
	}
	return nil
}

func isSafeIDByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '.' || value == '_' || value == '-'
}

// DeliveryMode is the one-byte HL8P binding-mode catalog.
type DeliveryMode uint8

const (
	DeliveryModeHTTPProxy DeliveryMode = 1
	DeliveryModeFileTmpfs DeliveryMode = 2
	DeliveryModeSSHAgent  DeliveryMode = 3
)

// ValidateDeliveryMode rejects the typed zero and every value outside the
// closed HL8P catalog.
func ValidateDeliveryMode(mode DeliveryMode) error {
	switch mode {
	case DeliveryModeHTTPProxy, DeliveryModeFileTmpfs, DeliveryModeSSHAgent:
		return nil
	default:
		return ErrUnknownDeliveryMode
	}
}

// String returns the canonical metadata spelling or "unknown" for values
// outside the closed catalog.
func (mode DeliveryMode) String() string {
	switch mode {
	case DeliveryModeHTTPProxy:
		return "http_proxy"
	case DeliveryModeFileTmpfs:
		return "file_tmpfs"
	case DeliveryModeSSHAgent:
		return "ssh_agent"
	default:
		return "unknown"
	}
}

// PacketType is the one-byte HL8P packet-type catalog.
type PacketType uint8

const (
	PacketTypeHelperReady   PacketType = 0x01
	PacketTypeBootstrap     PacketType = 0x02
	PacketTypeBootstrapAck  PacketType = 0x03
	PacketTypeAgentHello    PacketType = 0x04
	PacketTypeAgentHelloAck PacketType = 0x05

	PacketTypePrepareBegin  PacketType = 0x10
	PacketTypePrepareFile   PacketType = 0x11
	PacketTypePrepareCommit PacketType = 0x12
	PacketTypeRenew         PacketType = 0x13
	PacketTypeRevoke        PacketType = 0x14
	PacketTypeExec          PacketType = 0x15
	PacketTypeSSHAcceptedFD PacketType = 0x16
	PacketTypeExecPrivate   PacketType = 0x17
	PacketTypeExecStream    PacketType = 0x18
	PacketTypeExecCredit    PacketType = 0x19

	PacketTypeResponse    PacketType = 0x20
	PacketTypeEvent       PacketType = 0x21
	PacketTypeCloseNotify PacketType = 0x7f
)

// ValidatePacketType rejects the typed zero, gaps, and every value outside the
// closed HL8P catalog.
func ValidatePacketType(packetType PacketType) error {
	switch packetType {
	case PacketTypeHelperReady,
		PacketTypeBootstrap,
		PacketTypeBootstrapAck,
		PacketTypeAgentHello,
		PacketTypeAgentHelloAck,
		PacketTypePrepareBegin,
		PacketTypePrepareFile,
		PacketTypePrepareCommit,
		PacketTypeRenew,
		PacketTypeRevoke,
		PacketTypeExec,
		PacketTypeSSHAcceptedFD,
		PacketTypeExecPrivate,
		PacketTypeExecStream,
		PacketTypeExecCredit,
		PacketTypeResponse,
		PacketTypeEvent,
		PacketTypeCloseNotify:
		return nil
	default:
		return ErrUnknownPacketType
	}
}

// IsExtension reports whether the packet type is owned by the D5 extension
// seam. Unknown packet types are neither extension nor core types.
func (packetType PacketType) IsExtension() bool {
	return packetType == PacketTypeSSHAcceptedFD
}

// IsCore reports whether the packet type is a known core HL8P type.
func (packetType PacketType) IsCore() bool {
	return ValidatePacketType(packetType) == nil && !packetType.IsExtension()
}

// String returns the canonical wire-catalog name or "unknown" for values
// outside the closed catalog.
func (packetType PacketType) String() string {
	switch packetType {
	case PacketTypeHelperReady:
		return "helper_ready"
	case PacketTypeBootstrap:
		return "bootstrap"
	case PacketTypeBootstrapAck:
		return "bootstrap_ack"
	case PacketTypeAgentHello:
		return "agent_hello"
	case PacketTypeAgentHelloAck:
		return "agent_hello_ack"
	case PacketTypePrepareBegin:
		return "prepare_begin"
	case PacketTypePrepareFile:
		return "prepare_file"
	case PacketTypePrepareCommit:
		return "prepare_commit"
	case PacketTypeRenew:
		return "renew"
	case PacketTypeRevoke:
		return "revoke"
	case PacketTypeExec:
		return "exec"
	case PacketTypeSSHAcceptedFD:
		return "ssh_accepted_fd"
	case PacketTypeExecPrivate:
		return "exec_private"
	case PacketTypeExecStream:
		return "exec_stream"
	case PacketTypeExecCredit:
		return "exec_credit"
	case PacketTypeResponse:
		return "response"
	case PacketTypeEvent:
		return "event"
	case PacketTypeCloseNotify:
		return "close_notify"
	default:
		return "unknown"
	}
}

// ExtensionID is a canonical, redaction-safe D2 extension identifier.
type ExtensionID string

const ExtensionIDSSHRelayV1 ExtensionID = "ssh-relay-v1"

// ValidateExtensionID applies the safe-ID grammar and the tighter 64-byte
// process-descriptor bound. It does not trim or normalize future static IDs.
func ValidateExtensionID(id ExtensionID) error {
	if len(id) == 0 || len(id) > MaxExtensionIDBytes || ValidateSafeID(SafeID(id)) != nil {
		return ErrInvalidExtensionID
	}
	return nil
}
