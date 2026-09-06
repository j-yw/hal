package v2control

import (
	"encoding/json"
	"fmt"
)

// schemaField is a closed same-package catalog. Later concrete decoders add
// only architecture-defined constants rather than preserving caller text.
type schemaField uint8

const (
	schemaFieldProtocolVersion schemaField = iota + 1
	schemaFieldOperation
	schemaFieldRequestID
	schemaFieldIdentityDigest
	schemaFieldBody
)

// ControlError is the concrete safe failure object for one classified
// operation. Its message and optional field are derived from closed catalogs.
type ControlError struct {
	operation OperationToken
	code      ErrorCode
	field     schemaField
}

// NewControlError constructs one fieldless matrix-valid control failure.
func NewControlError(operation OperationToken, code ErrorCode) (ControlError, error) {
	controlError := ControlError{operation: operation, code: code}
	if err := ValidateControlError(controlError); err != nil {
		return ControlError{}, err
	}
	return controlError, nil
}

func newMalformedControlErrorForField(operation OperationToken, field schemaField) (ControlError, error) {
	controlError := ControlError{
		operation: operation,
		code:      ErrorCodeMalformedRequest,
		field:     field,
	}
	if err := ValidateControlError(controlError); err != nil {
		return ControlError{}, err
	}
	return controlError, nil
}

// ValidateControlError validates the code/message source, operation matrix,
// and private optional field catalog.
func ValidateControlError(controlError ControlError) error {
	if err := ValidateOperationErrorCode(controlError.operation, controlError.code); err != nil {
		return ErrInvalidControlError
	}
	if controlError.field == 0 {
		return nil
	}
	if controlError.code != ErrorCodeMalformedRequest {
		return ErrInvalidControlError
	}
	if _, ok := schemaFieldString(controlError.field); !ok {
		return ErrInvalidControlError
	}
	return nil
}

// Code returns the closed failure code.
func (controlError ControlError) Code() ErrorCode {
	return controlError.code
}

// Field returns a static schema path when the concrete decoder supplied one.
func (controlError ControlError) Field() (string, bool) {
	return schemaFieldString(controlError.field)
}

// Message returns only the static message paired with the closed code.
func (controlError ControlError) Message() string {
	message, err := ErrorCodeMessage(controlError.code)
	if err != nil {
		return "guest agent v2 control error is invalid"
	}
	return message
}

// Error implements error without wrapping or exposing a cause.
func (controlError ControlError) Error() string {
	return controlError.Message()
}

// MarshalJSON emits only the canonical safe error object.
func (controlError ControlError) MarshalJSON() ([]byte, error) {
	if err := ValidateControlError(controlError); err != nil {
		return nil, err
	}
	code, err := EncodeErrorCode(controlError.code)
	if err != nil {
		return nil, ErrInvalidControlError
	}
	field, _ := controlError.Field()
	return json.Marshal(struct {
		Code    string `json:"code"`
		Field   string `json:"field,omitempty"`
		Message string `json:"message"`
	}{
		Code: code, Field: field, Message: controlError.Message(),
	})
}

func (controlError ControlError) GoString() string {
	return controlError.Message()
}

func (controlError ControlError) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, controlError.Message())
}

func schemaFieldString(field schemaField) (string, bool) {
	switch field {
	case schemaFieldProtocolVersion:
		return "protocolVersion", true
	case schemaFieldOperation:
		return "operation", true
	case schemaFieldRequestID:
		return "requestId", true
	case schemaFieldIdentityDigest:
		return "identityDigest", true
	case schemaFieldBody:
		return "body", true
	default:
		return "", false
	}
}
