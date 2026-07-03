package guestagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var ErrProtocolValidation = errors.New("guest agent protocol validation failed")

var (
	protocolEndpointPattern         = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s'"<>]+`)
	protocolHeaderPattern           = regexp.MustCompile(`(?i)\b(?:authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*[^\s,;]+`)
	protocolSecretAssignmentPattern = regexp.MustCompile(`(?i)\b(?:token|secret|password|api[_-]?key|credential|authorization|cookie|body)\s*=\s*[^\s,;]+`)
	protocolJSONSecretPattern       = regexp.MustCompile(`(?i)"(?:token|secret|password|api[_-]?key|credential|authorization|cookie|body)"\s*:\s*"[^"]*"`)
	protocolAbsolutePathPattern     = regexp.MustCompile(`(^|[\s"'=:(])(/[A-Za-z0-9._~@%+-][^\s:'",)]*)`)
	protocolIPPortPattern           = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`)
	protocolHostPortPattern         = regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9.-]*\.(?:test|local|internal|example|com|net|org|io|dev)(?::\d+)?\b`)
	protocolSecretValuePattern      = regexp.MustCompile(`(?i)(^|[\s"'=:/])(?:ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]+|[A-Za-z0-9._-]*(?:hunter2|secret)[A-Za-z0-9._-]*)`)
)

const maxProtocolErrorMessageBytes = 384

// ProtocolError is the redaction-safe public error shape for guest-agent
// validation and dispatch boundaries. Err is never serialized.
type ProtocolError struct {
	Code      ErrorCode `json:"code"`
	Operation Operation `json:"operation,omitempty"`
	Field     string    `json:"field,omitempty"`
	Message   string    `json:"message,omitempty"`
	Err       error     `json:"-"`
}

func NewProtocolError(code ErrorCode, operation Operation, field string, err error) *ProtocolError {
	if err == nil {
		err = ErrProtocolValidation
	}
	return &ProtocolError{
		Code:      normalizeErrorCode(code),
		Operation: sanitizeOperation(operation),
		Field:     sanitizeFieldName(field),
		Message:   sanitizeProtocolErrorMessage(err.Error()),
		Err:       err,
	}
}

func (err *ProtocolError) Error() string {
	if err == nil {
		return ""
	}
	code := normalizeErrorCode(err.Code)
	message := "guest agent protocol error"
	if operation := sanitizeOperation(err.Operation); operation != "" {
		message = fmt.Sprintf("guest agent %s protocol error", operation)
	}
	message += fmt.Sprintf(" (%s)", code)
	if field := sanitizeFieldName(err.Field); field != "" {
		message += " field=" + field
	}
	if detail := err.safeMessage(); detail != "" {
		message += ": " + detail
	}
	return message
}

func (err *ProtocolError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func (err *ProtocolError) MarshalJSON() ([]byte, error) {
	if err == nil {
		return []byte("null"), nil
	}
	return json.Marshal(struct {
		Code      ErrorCode `json:"code"`
		Operation Operation `json:"operation,omitempty"`
		Field     string    `json:"field,omitempty"`
		Message   string    `json:"message,omitempty"`
	}{
		Code:      normalizeErrorCode(err.Code),
		Operation: sanitizeOperation(err.Operation),
		Field:     sanitizeFieldName(err.Field),
		Message:   err.safeMessage(),
	})
}

func (err *ProtocolError) safeMessage() string {
	if err == nil {
		return ""
	}
	if strings.TrimSpace(err.Message) != "" {
		return sanitizeProtocolErrorMessage(err.Message)
	}
	if err.Err != nil {
		return sanitizeProtocolErrorMessage(err.Err.Error())
	}
	return ""
}

func newValidationError(code ErrorCode, operation Operation, field, message string) *ProtocolError {
	return &ProtocolError{
		Code:      normalizeErrorCode(code),
		Operation: sanitizeOperation(operation),
		Field:     sanitizeFieldName(field),
		Message:   sanitizeProtocolErrorMessage(message),
		Err:       ErrProtocolValidation,
	}
}

func normalizeErrorCode(code ErrorCode) ErrorCode {
	switch code {
	case ErrorCodeUnsupportedProtocolVersion,
		ErrorCodeUnknownOperation,
		ErrorCodeOperationMismatch,
		ErrorCodeMissingRequiredField,
		ErrorCodeMalformedPath,
		ErrorCodeInvalidTimeout,
		ErrorCodeInvalidDeadline,
		ErrorCodeOversizedPayloadMetadata,
		ErrorCodeInvalidMetadata,
		ErrorCodeMalformedResponse,
		ErrorCodeOversizedRequest,
		ErrorCodeOversizedResponse,
		ErrorCodeRequestCanceled,
		ErrorCodeRequestTimeout,
		ErrorCodeTransportFailure:
		return code
	default:
		return ErrorCodeInvalidMetadata
	}
}

func sanitizeOperation(operation Operation) Operation {
	switch Operation(strings.TrimSpace(string(operation))) {
	case OperationReadiness:
		return OperationReadiness
	case OperationExec:
		return OperationExec
	case OperationCopyIn:
		return OperationCopyIn
	case OperationCopyOut:
		return OperationCopyOut
	default:
		return ""
	}
}

func sanitizeFieldName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 96 {
		return ""
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_' || r == '-' || r == '.' || r == '[' || r == ']':
			builder.WriteRune(r)
		default:
			return ""
		}
	}
	return builder.String()
}

func sanitizeProtocolErrorMessage(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	message = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		default:
			return r
		}
	}, message)
	message = strings.Join(strings.Fields(message), " ")
	message = protocolHeaderPattern.ReplaceAllString(message, "[redacted]")
	message = protocolJSONSecretPattern.ReplaceAllString(message, "[redacted]")
	message = protocolSecretAssignmentPattern.ReplaceAllString(message, "[redacted]")
	message = protocolEndpointPattern.ReplaceAllString(message, "[redacted-endpoint]")
	message = protocolAbsolutePathPattern.ReplaceAllString(message, "$1[redacted-path]")
	message = protocolIPPortPattern.ReplaceAllString(message, "[redacted-endpoint]")
	message = protocolHostPortPattern.ReplaceAllString(message, "[redacted-endpoint]")
	message = protocolSecretValuePattern.ReplaceAllString(message, "$1[redacted]")
	if len(message) > maxProtocolErrorMessageBytes {
		message = strings.TrimSpace(message[:maxProtocolErrorMessageBytes]) + "..."
	}
	return message
}
