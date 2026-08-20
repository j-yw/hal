package credentialclient

import "fmt"

// ClientContractErrorCode is the closed credential-client failure catalog.
type ClientContractErrorCode uint8

const (
	ClientContractDependency ClientContractErrorCode = 1 + iota
	ClientContractDescriptor
	ClientContractServeState
	ClientContractPacket
	ClientContractCorrelation
	ClientContractSequence
	ClientContractLimit
	ClientContractPolicy
	ClientContractExtension
	ClientContractOwnership
	ClientContractCleanup
	ClientContractSerialization
	ClientContractPanic
)

// ClientContractField identifies one static contract area without retaining
// caller-controlled input.
type ClientContractField uint8

const (
	ClientFieldDependency ClientContractField = 1 + iota
	ClientFieldDescriptor
	ClientFieldSequence
	ClientFieldPacketType
	ClientFieldRequestID
	ClientFieldIdentity
	ClientFieldRevision
	ClientFieldBody
	ClientFieldRight
	ClientFieldPolicy
	ClientFieldExtension
	ClientFieldLifecycle
)

// ClientContractIndexKind selects one bounded safe index category.
type ClientContractIndexKind uint8

const (
	ClientIndexPacket ClientContractIndexKind = 1 + iota
	ClientIndexRecord
	ClientIndexBinding
	ClientIndexStream
)

// ClientContractError contains only closed catalog values. It never wraps or
// formats a dependency error.
type ClientContractError struct {
	code      ClientContractErrorCode
	field     ClientContractField
	indexKind ClientContractIndexKind
	index     uint32
	hasIndex  bool
}

// Code returns the closed error code.
func (failure *ClientContractError) Code() ClientContractErrorCode {
	if failure == nil {
		return 0
	}
	return failure.code
}

// Field returns the optional closed field selector.
func (failure *ClientContractError) Field() (ClientContractField, bool) {
	if failure == nil || failure.field == 0 {
		return 0, false
	}
	return failure.field, true
}

// Index returns the optional safe bounded index.
func (failure *ClientContractError) Index() (ClientContractIndexKind, uint32, bool) {
	if failure == nil || !failure.hasIndex {
		return 0, 0, false
	}
	return failure.indexKind, failure.index, true
}

func (failure *ClientContractError) Error() string {
	if failure == nil {
		return "credential client dependency is invalid"
	}
	switch failure.code {
	case ClientContractDependency:
		return "credential client dependency is invalid"
	case ClientContractDescriptor:
		return "credential client descriptor is invalid"
	case ClientContractServeState:
		return "credential client Serve state is invalid"
	case ClientContractPacket:
		return "credential client packet is invalid"
	case ClientContractCorrelation:
		return "credential client correlation is invalid"
	case ClientContractSequence:
		return "credential client sequence is invalid"
	case ClientContractLimit:
		return "credential client fixed limit is exceeded"
	case ClientContractPolicy:
		return "credential client policy contract is invalid"
	case ClientContractExtension:
		return "credential client extension contract is invalid"
	case ClientContractOwnership:
		return "credential client ownership is invalid"
	case ClientContractCleanup:
		return "credential client cleanup is incomplete"
	case ClientContractSerialization:
		return "credential client live serialization is forbidden"
	case ClientContractPanic:
		return "credential client dependency panicked"
	default:
		return "credential client dependency is invalid"
	}
}

func (*ClientContractError) MarshalJSON() ([]byte, error) {
	return nil, clientError(ClientContractSerialization, 0)
}

func (*ClientContractError) MarshalText() ([]byte, error) {
	return nil, clientError(ClientContractSerialization, 0)
}

func (*ClientContractError) MarshalBinary() ([]byte, error) {
	return nil, clientError(ClientContractSerialization, 0)
}

func (*ClientContractError) UnmarshalJSON([]byte) error {
	return clientError(ClientContractSerialization, 0)
}

func (*ClientContractError) UnmarshalText([]byte) error {
	return clientError(ClientContractSerialization, 0)
}

func (*ClientContractError) UnmarshalBinary([]byte) error {
	return clientError(ClientContractSerialization, 0)
}

func (*ClientContractError) String() string   { return "credentialclient.live[redacted]" }
func (*ClientContractError) GoString() string { return "credentialclient.live[redacted]" }
func (*ClientContractError) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialclient.live[redacted]"))
}

func clientError(code ClientContractErrorCode, field ClientContractField) *ClientContractError {
	return &ClientContractError{code: code, field: field}
}
