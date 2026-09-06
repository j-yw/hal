package v2control

// ProtocolVersion is the exact v2 control protocol version.
const ProtocolVersion = "guest-agent-v2"

// Operation is the closed known-operation string catalog.
type Operation string

const (
	OperationReadiness         Operation = "readiness"
	OperationCredentialPrepare Operation = "credential_prepare"
	OperationCredentialRenew   Operation = "credential_renew"
	OperationCredentialRevoke  Operation = "credential_revoke"
	OperationExec              Operation = "exec"
)

// OperationToken is a validated known or syntactically safe unknown token.
// Its representation is private so unsafe input cannot be echoed.
type OperationToken struct {
	value     string
	operation Operation
}

// OperationTokenFor constructs a token from the closed known catalog.
func OperationTokenFor(operation Operation) (OperationToken, error) {
	if !validKnownOperation(operation) {
		return OperationToken{}, ErrInvalidOperation
	}
	return OperationToken{value: string(operation), operation: operation}, nil
}

// ParseOperationToken validates a root operation token and classifies known
// values without rejecting a syntactically safe future token.
func ParseOperationToken(value string) (OperationToken, error) {
	if !validOperationSyntax(value) {
		return OperationToken{}, ErrInvalidOperationToken
	}
	return OperationToken{value: value, operation: knownOperation(value)}, nil
}

// EncodeOperationToken returns the exact validated token for canonical codecs.
func EncodeOperationToken(token OperationToken) (string, error) {
	if !validOperationSyntax(token.value) {
		return "", ErrInvalidOperationToken
	}
	operation := knownOperation(token.value)
	if operation != token.operation {
		return "", ErrInvalidOperationToken
	}
	return token.value, nil
}

// KnownOperation reports the closed catalog value for a known token.
func KnownOperation(token OperationToken) (Operation, bool) {
	if _, err := EncodeOperationToken(token); err != nil || token.operation == "" {
		return "", false
	}
	return token.operation, true
}

func validKnownOperation(operation Operation) bool {
	switch operation {
	case OperationReadiness,
		OperationCredentialPrepare,
		OperationCredentialRenew,
		OperationCredentialRevoke,
		OperationExec:
		return true
	default:
		return false
	}
}

func knownOperation(value string) Operation {
	operation := Operation(value)
	if validKnownOperation(operation) {
		return operation
	}
	return ""
}

func validOperationSyntax(value string) bool {
	if len(value) < 1 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

// ErrorCode is the closed v2 control failure string catalog.
type ErrorCode string

const (
	ErrorCodeMalformedRequest  ErrorCode = "malformed_request"
	ErrorCodeUnknownOperation  ErrorCode = "unknown_operation"
	ErrorCodeRequestConflict   ErrorCode = "request_conflict"
	ErrorCodeIdentityMismatch  ErrorCode = "identity_mismatch"
	ErrorCodeRevisionStale     ErrorCode = "revision_stale"
	ErrorCodeExpired           ErrorCode = "expired"
	ErrorCodeResourceLimit     ErrorCode = "resource_limit"
	ErrorCodePrepareFailed     ErrorCode = "prepare_failed"
	ErrorCodeRenewFailed       ErrorCode = "renew_failed"
	ErrorCodeRevokeFailed      ErrorCode = "revoke_failed"
	ErrorCodeExecFailed        ErrorCode = "exec_failed"
	ErrorCodeHelperUnavailable ErrorCode = "helper_unavailable"
	ErrorCodeCleanupIncomplete ErrorCode = "cleanup_incomplete"
)

// EncodeErrorCode returns the exact canonical code string.
func EncodeErrorCode(code ErrorCode) (string, error) {
	value, _, ok := errorCodePair(code)
	if !ok {
		return "", ErrInvalidErrorCode
	}
	return value, nil
}

// ParseErrorCode accepts only an exact member of the closed code catalog.
func ParseErrorCode(value string) (ErrorCode, error) {
	code := ErrorCode(value)
	if _, _, ok := errorCodePair(code); ok {
		return code, nil
	}
	return "", ErrInvalidErrorCode
}

// ErrorCodeMessage returns the exact static message paired with code.
func ErrorCodeMessage(code ErrorCode) (string, error) {
	_, message, ok := errorCodePair(code)
	if !ok {
		return "", ErrInvalidErrorCode
	}
	return message, nil
}

func errorCodePair(code ErrorCode) (string, string, bool) {
	switch code {
	case ErrorCodeMalformedRequest:
		return string(code), "credential request is malformed", true
	case ErrorCodeUnknownOperation:
		return string(code), "credential operation is unsupported", true
	case ErrorCodeRequestConflict:
		return string(code), "credential request conflicts with prior state", true
	case ErrorCodeIdentityMismatch:
		return string(code), "credential identity does not match", true
	case ErrorCodeRevisionStale:
		return string(code), "credential revision is stale", true
	case ErrorCodeExpired:
		return string(code), "credential request is expired", true
	case ErrorCodeResourceLimit:
		return string(code), "credential request exceeds a fixed limit", true
	case ErrorCodePrepareFailed:
		return string(code), "credential preparation failed", true
	case ErrorCodeRenewFailed:
		return string(code), "credential renewal failed", true
	case ErrorCodeRevokeFailed:
		return string(code), "credential revocation failed", true
	case ErrorCodeExecFailed:
		return string(code), "credential execution failed", true
	case ErrorCodeHelperUnavailable:
		return string(code), "credential helper is unavailable", true
	case ErrorCodeCleanupIncomplete:
		return string(code), "credential cleanup is incomplete", true
	default:
		return "", "", false
	}
}

// ValidateOperationErrorCode enforces the closed operation/code matrix.
func ValidateOperationErrorCode(operation OperationToken, code ErrorCode) error {
	if _, err := EncodeOperationToken(operation); err != nil {
		return ErrInvalidOperationErrorCode
	}
	if _, _, ok := errorCodePair(code); !ok {
		return ErrInvalidOperationErrorCode
	}
	if operation.operation == "" {
		if code == ErrorCodeUnknownOperation {
			return nil
		}
		return ErrInvalidOperationErrorCode
	}
	if operationAllowsError(operation.operation, code) {
		return nil
	}
	return ErrInvalidOperationErrorCode
}

func operationAllowsError(operation Operation, code ErrorCode) bool {
	switch operation {
	case OperationReadiness:
		return code == ErrorCodeMalformedRequest ||
			code == ErrorCodeRequestConflict ||
			code == ErrorCodeIdentityMismatch ||
			code == ErrorCodeHelperUnavailable
	case OperationCredentialPrepare:
		return code == ErrorCodeMalformedRequest ||
			code == ErrorCodeRequestConflict ||
			code == ErrorCodeIdentityMismatch ||
			code == ErrorCodeRevisionStale ||
			code == ErrorCodeExpired ||
			code == ErrorCodeResourceLimit ||
			code == ErrorCodePrepareFailed ||
			code == ErrorCodeHelperUnavailable ||
			code == ErrorCodeCleanupIncomplete
	case OperationCredentialRenew:
		return code == ErrorCodeMalformedRequest ||
			code == ErrorCodeRequestConflict ||
			code == ErrorCodeIdentityMismatch ||
			code == ErrorCodeRevisionStale ||
			code == ErrorCodeExpired ||
			code == ErrorCodeRenewFailed ||
			code == ErrorCodeHelperUnavailable
	case OperationCredentialRevoke:
		return code == ErrorCodeMalformedRequest ||
			code == ErrorCodeRequestConflict ||
			code == ErrorCodeIdentityMismatch ||
			code == ErrorCodeRevisionStale ||
			code == ErrorCodeRevokeFailed ||
			code == ErrorCodeHelperUnavailable ||
			code == ErrorCodeCleanupIncomplete
	case OperationExec:
		return code == ErrorCodeMalformedRequest ||
			code == ErrorCodeRequestConflict ||
			code == ErrorCodeIdentityMismatch ||
			code == ErrorCodeRevisionStale ||
			code == ErrorCodeExpired ||
			code == ErrorCodeResourceLimit ||
			code == ErrorCodeExecFailed ||
			code == ErrorCodeHelperUnavailable
	default:
		return false
	}
}
