package v2control

import (
	"errors"
	"fmt"
)

var (
	// ErrCredentialRequestInspectionDependencyUnaccepted records the precise
	// RED boundary: the normative two-stage root inspector is not implemented.
	ErrCredentialRequestInspectionDependencyUnaccepted = errors.New("guest agent v2 credential request inspection dependency is unaccepted")
	ErrCredentialRequestInspectionSerialization        = errors.New("guest agent v2 credential request inspection serialization is denied")
)

// InspectedRequest is the nonserializable, bodyless result of inspecting one
// complete canonical credential request root. Production inspection behavior
// is frozen by the D6 RED contract and intentionally remains unimplemented.
type InspectedRequest struct {
	state *inspectedRequestState
}

type inspectedRequestState struct {
	operationToken OperationToken
	requestID      RequestID
	identityDigest IdentityDigest
	knownOperation Operation
}

// InspectCredentialRequestRoot is the sole future two-stage request-root
// entrypoint. It must never retain the body or caller-owned wire bytes.
func InspectCredentialRequestRoot([]byte) (InspectedRequest, error) {
	return InspectedRequest{}, ErrCredentialRequestInspectionDependencyUnaccepted
}

// DecodeInitialCredentialPrepareRequest is the sole future decoder permitted
// to derive the initial job identity from the authenticated session ID.
func DecodeInitialCredentialPrepareRequest([32]byte, []byte) (CredentialPrepareRequest, error) {
	return CredentialPrepareRequest{}, ErrCredentialRequestInspectionDependencyUnaccepted
}

func (request InspectedRequest) OperationToken() OperationToken {
	if request.state == nil {
		return OperationToken{}
	}
	return request.state.operationToken
}

func (request InspectedRequest) RequestID() RequestID {
	if request.state == nil {
		return RequestID{}
	}
	return request.state.requestID
}

func (request InspectedRequest) IdentityDigest() IdentityDigest {
	if request.state == nil {
		return IdentityDigest{}
	}
	return request.state.identityDigest
}

func (request InspectedRequest) KnownOperation() (Operation, bool) {
	if request.state == nil {
		return Operation(""), false
	}
	return request.state.knownOperation, validKnownOperation(request.state.knownOperation)
}

func (InspectedRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialRequestInspectionSerialization
}
func (InspectedRequest) MarshalText() ([]byte, error) {
	return nil, ErrCredentialRequestInspectionSerialization
}
func (InspectedRequest) MarshalBinary() ([]byte, error) {
	return nil, ErrCredentialRequestInspectionSerialization
}
func (*InspectedRequest) UnmarshalJSON([]byte) error {
	return ErrCredentialRequestInspectionSerialization
}
func (*InspectedRequest) UnmarshalText([]byte) error {
	return ErrCredentialRequestInspectionSerialization
}
func (*InspectedRequest) UnmarshalBinary([]byte) error {
	return ErrCredentialRequestInspectionSerialization
}
func (InspectedRequest) String() string   { return "<v2control.InspectedRequest>" }
func (InspectedRequest) GoString() string { return "<v2control.InspectedRequest>" }
func (InspectedRequest) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("<v2control.InspectedRequest>"))
}
