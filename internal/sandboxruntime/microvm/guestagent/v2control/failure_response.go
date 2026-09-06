package v2control

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

const (
	maxFailureJSONBytes        = 2 * 1024 * 1024
	maxFailureJSONDepth        = 3
	maxFailureJSONObjectFields = 16
)

// FailureResponse owns one complete canonical failure envelope. Correlation
// and failure metadata remain opaque and can only be serialized explicitly.
type FailureResponse struct {
	state *failureResponseState
}

type failureResponseState struct {
	protocolVersion string
	operation       OperationToken
	requestID       RequestID
	identityDigest  IdentityDigest
	ok              bool
	controlError    ControlError
}

type failureResponseJSON struct {
	ProtocolVersion string           `json:"protocolVersion"`
	Operation       string           `json:"operation"`
	RequestID       string           `json:"requestId"`
	IdentityDigest  string           `json:"identityDigest"`
	OK              bool             `json:"ok"`
	Error           failureErrorJSON `json:"error"`
}

type failureErrorJSON struct {
	Code    string `json:"code"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// NewFailureResponse constructs a response whose operation is derived from a
// validated control error rather than accepted as separate caller input.
func NewFailureResponse(requestID RequestID, identityDigest IdentityDigest, controlError ControlError) (FailureResponse, error) {
	response := FailureResponse{state: &failureResponseState{
		protocolVersion: ProtocolVersion,
		operation:       controlError.operation,
		requestID:       requestID,
		identityDigest:  identityDigest,
		ok:              false,
		controlError:    controlError,
	}}
	if err := ValidateFailureResponse(response); err != nil {
		return FailureResponse{}, err
	}
	return response, nil
}

// ValidateFailureResponse validates the complete opaque envelope and its
// closed operation/error relationship.
func ValidateFailureResponse(response FailureResponse) error {
	if response.state == nil || response.state.protocolVersion != ProtocolVersion || response.state.ok {
		return ErrInvalidFailureResponse
	}
	if _, err := EncodeOperationToken(response.state.operation); err != nil {
		return ErrInvalidFailureResponse
	}
	if _, err := EncodeRequestID(response.state.requestID); err != nil {
		return ErrInvalidFailureResponse
	}
	if ValidateControlError(response.state.controlError) != nil ||
		response.state.controlError.operation != response.state.operation {
		return ErrInvalidFailureResponse
	}
	return nil
}

// EncodeFailureResponse returns the sole canonical compact JSON encoding.
func EncodeFailureResponse(response FailureResponse) ([]byte, error) {
	if err := ValidateFailureResponse(response); err != nil {
		return nil, err
	}
	operation, err := EncodeOperationToken(response.state.operation)
	if err != nil {
		return nil, ErrInvalidFailureResponse
	}
	requestID, err := EncodeRequestID(response.state.requestID)
	if err != nil {
		return nil, ErrInvalidFailureResponse
	}
	code, err := EncodeErrorCode(response.state.controlError.code)
	if err != nil {
		return nil, ErrInvalidFailureResponse
	}
	message, err := ErrorCodeMessage(response.state.controlError.code)
	if err != nil {
		return nil, ErrInvalidFailureResponse
	}
	field, _ := response.state.controlError.Field()
	wire, err := json.Marshal(failureResponseJSON{
		ProtocolVersion: response.state.protocolVersion,
		Operation:       operation,
		RequestID:       requestID,
		IdentityDigest:  EncodeIdentityDigest(response.state.identityDigest),
		OK:              response.state.ok,
		Error: failureErrorJSON{
			Code:    code,
			Field:   field,
			Message: message,
		},
	})
	if err != nil {
		return nil, ErrInvalidFailureResponse
	}
	return wire, nil
}

// DecodeFailureResponse accepts only a canonical response whose operation,
// request ID, and identity digest all exactly match the expected correlation.
func DecodeFailureResponse(expectedOperation OperationToken, expectedRequestID RequestID, expectedIdentity IdentityDigest, wire []byte) (FailureResponse, error) {
	if _, err := EncodeOperationToken(expectedOperation); err != nil {
		return FailureResponse{}, ErrInvalidFailureResponse
	}
	if _, err := EncodeRequestID(expectedRequestID); err != nil {
		return FailureResponse{}, ErrInvalidFailureResponse
	}
	if !validFailureJSONInput(wire) {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var decoded failureResponseJSON
	if err := decoder.Decode(&decoded); err != nil || requireFailureJSONEOF(decoder) != nil {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	if decoded.ProtocolVersion != ProtocolVersion || decoded.OK {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	operation, err := ParseOperationToken(decoded.Operation)
	if err != nil {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	requestID, err := ParseRequestID(decoded.RequestID)
	if err != nil {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	identityDigest, err := ParseIdentityDigest(decoded.IdentityDigest)
	if err != nil {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	code, err := ParseErrorCode(decoded.Error.Code)
	if err != nil {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	message, err := ErrorCodeMessage(code)
	if err != nil || decoded.Error.Message != message {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	field, ok := parseFailureSchemaField(decoded.Error.Field)
	if decoded.Error.Field != "" && !ok {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	controlError := ControlError{operation: operation, code: code, field: field}
	if ValidateControlError(controlError) != nil {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	response, err := NewFailureResponse(requestID, identityDigest, controlError)
	if err != nil {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	if operation != expectedOperation || requestID != expectedRequestID || identityDigest != expectedIdentity {
		return FailureResponse{}, ErrFailureCorrelationMismatch
	}
	canonical, err := EncodeFailureResponse(response)
	if err != nil || !bytes.Equal(canonical, wire) {
		return FailureResponse{}, ErrInvalidFailureResponseJSON
	}
	return response, nil
}

// OperationToken returns the validated known or safe unknown operation.
func (response FailureResponse) OperationToken() OperationToken {
	if response.state == nil {
		return OperationToken{}
	}
	return response.state.operation
}

// RequestID returns the opaque request correlation scalar.
func (response FailureResponse) RequestID() RequestID {
	if response.state == nil {
		return RequestID{}
	}
	return response.state.requestID
}

// IdentityDigest returns the opaque identity correlation scalar.
func (response FailureResponse) IdentityDigest() IdentityDigest {
	if response.state == nil {
		return IdentityDigest{}
	}
	return response.state.identityDigest
}

// ControlError returns the validated static failure metadata.
func (response FailureResponse) ControlError() ControlError {
	if response.state == nil {
		return ControlError{}
	}
	return response.state.controlError
}

func parseFailureSchemaField(value string) (schemaField, bool) {
	if value == "" {
		return 0, true
	}
	for field := schemaFieldProtocolVersion; field <= schemaFieldBody; field++ {
		if candidate, ok := schemaFieldString(field); ok && candidate == value {
			return field, true
		}
	}
	return 0, false
}

func validFailureJSONInput(wire []byte) bool {
	if len(wire) == 0 || len(wire) > maxFailureJSONBytes || !utf8.Valid(wire) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	if !scanFailureJSONValue(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func scanFailureJSONValue(decoder *json.Decoder, depth int) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	nestedDepth := depth + 1
	if nestedDepth > maxFailureJSONDepth {
		return false
	}
	switch delimiter {
	case '{':
		var keys [maxFailureJSONObjectFields]string
		keyCount := 0
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, isString := keyToken.(string)
			if keyErr != nil || !isString || keyCount == len(keys) {
				return false
			}
			for index := 0; index < keyCount; index++ {
				if keys[index] == key {
					return false
				}
			}
			keys[keyCount] = key
			keyCount++
			if !scanFailureJSONValue(decoder, nestedDepth) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !scanFailureJSONValue(decoder, nestedDepth) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim(']')
	default:
		return false
	}
}

func requireFailureJSONEOF(decoder *json.Decoder) error {
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrInvalidFailureResponseJSON
	}
	return nil
}
