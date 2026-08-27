package v2control

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

var (
	// ErrCredentialRequestInspectionDependencyUnaccepted records the former
	// RED boundary retained as a stable sentinel.
	ErrCredentialRequestInspectionDependencyUnaccepted = errors.New("guest agent v2 credential request inspection dependency is unaccepted")
	ErrCredentialRequestInspectionSerialization        = errors.New("guest agent v2 credential request inspection serialization is denied")
	ErrInvalidCredentialRequestRootJSON                = errors.New("guest agent v2 credential request root JSON is invalid")
)

const maxCredentialRequestRootJSONDepth = 5

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

// InspectCredentialRequestRoot is the sole two-stage request-root entrypoint.
// It never retains the body or caller-owned wire bytes.
func InspectCredentialRequestRoot(wire []byte) (InspectedRequest, error) {
	request, _, err := inspectCredentialRequestRoot(wire)
	return request, err
}

// DecodeInitialCredentialPrepareRequest is the sole decoder permitted to
// derive the initial job identity from the authenticated session ID.
func DecodeInitialCredentialPrepareRequest(sessionID [32]byte, wire []byte) (CredentialPrepareRequest, error) {
	inspected, body, err := inspectCredentialRequestRoot(wire)
	if err != nil {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	operation, known := inspected.KnownOperation()
	if !known || operation != OperationCredentialPrepare {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	identityJSON, ok := inspectPrepareIdentityJSON(body)
	if !ok {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	identity, err := DecodeJobIdentity(identityJSON)
	if err != nil {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	sessionIdentity, err := NewGuestCredentialSessionIdentity(sessionID, identity)
	if err != nil {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	request, err := DecodeCredentialPrepareRequest(sessionIdentity, wire)
	if err != nil {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	if request.IdentityDigest() != inspected.IdentityDigest() {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	return request, nil
}

func inspectCredentialRequestRoot(wire []byte) (InspectedRequest, []byte, error) {
	if len(wire) == 0 || len(wire) > maxReadinessJSONBytes || !utf8.Valid(wire) {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	rest, ok := consumeExactBytes(wire, `{"protocolVersion":"`+ProtocolVersion+`","operation":"`)
	if !ok {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	operationText, rest, ok := consumeUnescapedJSONStringContent(rest)
	if !ok {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	token, err := ParseOperationToken(operationText)
	if err != nil {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	rest, ok = consumeExactBytes(rest, `","requestId":"`)
	if !ok {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	requestIDText, rest, ok := consumeUnescapedJSONStringContent(rest)
	if !ok {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	requestID, err := ParseRequestID(requestIDText)
	if err != nil {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	rest, ok = consumeExactBytes(rest, `","identityDigest":"`)
	if !ok {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	digestText, rest, ok := consumeUnescapedJSONStringContent(rest)
	if !ok {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	digest, err := ParseIdentityDigest(digestText)
	if err != nil {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	rest, ok = consumeExactBytes(rest, `","body":`)
	if !ok {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	bodyStart := rest
	rest, ok = skipCanonicalJSONValue(rest, 0)
	if !ok {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	body := bodyStart[:len(bodyStart)-len(rest)]
	rest, ok = consumeExactBytes(rest, `}`)
	if !ok || len(rest) != 0 {
		return InspectedRequest{}, nil, ErrInvalidCredentialRequestRootJSON
	}
	return InspectedRequest{state: &inspectedRequestState{
		operationToken: token,
		requestID:      requestID,
		identityDigest: digest,
		knownOperation: token.operation,
	}}, body, nil
}

func inspectPrepareIdentityJSON(body []byte) ([]byte, bool) {
	rest, ok := consumeExactBytes(body, `{"identity":`)
	if !ok {
		return nil, false
	}
	start := rest
	rest, ok = skipCanonicalJSONValue(rest, 0)
	if !ok {
		return nil, false
	}
	identityJSON := start[:len(start)-len(rest)]
	return identityJSON, len(identityJSON) > 0
}

func consumeExactBytes(wire []byte, literal string) ([]byte, bool) {
	if len(literal) == 0 || len(wire) < len(literal) || string(wire[:len(literal)]) != literal {
		return nil, false
	}
	return wire[len(literal):], true
}

func consumeUnescapedJSONStringContent(wire []byte) (string, []byte, bool) {
	for index := 0; index < len(wire); index++ {
		character := wire[index]
		if character == '\\' || character < 0x20 {
			return "", nil, false
		}
		if character == '"' {
			return string(wire[:index]), wire[index:], true
		}
	}
	return "", nil, false
}

func skipCanonicalJSONValue(wire []byte, depth int) ([]byte, bool) {
	if depth > maxCredentialRequestRootJSONDepth || len(wire) == 0 {
		return nil, false
	}
	switch wire[0] {
	case '{':
		rest := wire[1:]
		if len(rest) > 0 && rest[0] == '}' {
			return rest[1:], true
		}
		for {
			if len(rest) == 0 || rest[0] != '"' {
				return nil, false
			}
			var ok bool
			rest, ok = skipCanonicalJSONString(rest)
			if !ok {
				return nil, false
			}
			rest, ok = consumeExactBytes(rest, `:`)
			if !ok {
				return nil, false
			}
			rest, ok = skipCanonicalJSONValue(rest, depth+1)
			if !ok {
				return nil, false
			}
			if len(rest) == 0 {
				return nil, false
			}
			if rest[0] == ',' {
				rest = rest[1:]
				continue
			}
			if rest[0] == '}' {
				return rest[1:], true
			}
			return nil, false
		}
	case '[':
		rest := wire[1:]
		if len(rest) > 0 && rest[0] == ']' {
			return rest[1:], true
		}
		for {
			var ok bool
			rest, ok = skipCanonicalJSONValue(rest, depth+1)
			if !ok || len(rest) == 0 {
				return nil, false
			}
			if rest[0] == ',' {
				rest = rest[1:]
				continue
			}
			if rest[0] == ']' {
				return rest[1:], true
			}
			return nil, false
		}
	case '"':
		return skipCanonicalJSONString(wire)
	case 't':
		return consumeExactBytes(wire, "true")
	case 'f':
		return consumeExactBytes(wire, "false")
	case 'n':
		return consumeExactBytes(wire, "null")
	default:
		return skipCanonicalJSONNumber(wire)
	}
}

func skipCanonicalJSONString(wire []byte) ([]byte, bool) {
	if len(wire) == 0 || wire[0] != '"' {
		return nil, false
	}
	escaped := false
	for index := 1; index < len(wire); index++ {
		character := wire[index]
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			return wire[index+1:], true
		}
		if character < 0x20 {
			return nil, false
		}
	}
	return nil, false
}

func skipCanonicalJSONNumber(wire []byte) ([]byte, bool) {
	index := 0
	if index < len(wire) && wire[index] == '-' {
		index++
	}
	if index >= len(wire) || wire[index] < '0' || wire[index] > '9' {
		return nil, false
	}
	if wire[index] == '0' {
		index++
	} else {
		for index < len(wire) && wire[index] >= '0' && wire[index] <= '9' {
			index++
		}
	}
	if index < len(wire) && wire[index] == '.' {
		index++
		if index >= len(wire) || wire[index] < '0' || wire[index] > '9' {
			return nil, false
		}
		for index < len(wire) && wire[index] >= '0' && wire[index] <= '9' {
			index++
		}
	}
	if index < len(wire) && (wire[index] == 'e' || wire[index] == 'E') {
		index++
		if index < len(wire) && (wire[index] == '+' || wire[index] == '-') {
			index++
		}
		if index >= len(wire) || wire[index] < '0' || wire[index] > '9' {
			return nil, false
		}
		for index < len(wire) && wire[index] >= '0' && wire[index] <= '9' {
			index++
		}
	}
	return wire[index:], true
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
