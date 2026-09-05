package syscallpolicy

// ErrorCode is the closed redaction-safe policy contract error catalog.
type ErrorCode uint8

const (
	ErrorCodeInvalidArgument ErrorCode = 1 + iota
	ErrorCodeTypedNil
	ErrorCodeBounds
	ErrorCodeDigestMismatch
	ErrorCodeEncoding
	ErrorCodeCatalog
	ErrorCodeMissingSection
	ErrorCodeDuplicate
	ErrorCodeContradiction
	ErrorCodeUnsafeWidening
	ErrorCodeFatalAllow
	ErrorCodeInvalidAncestry
	ErrorCodeObservation
	ErrorCodeOwnership
	ErrorCodeTransition
)

func ValidateErrorCode(value ErrorCode) error {
	if value < ErrorCodeInvalidArgument || value > ErrorCodeTransition {
		return contractError(ErrorCodeInvalidArgument)
	}
	return nil
}

func (value ErrorCode) String() string {
	switch value {
	case ErrorCodeInvalidArgument:
		return "invalid-argument"
	case ErrorCodeTypedNil:
		return "typed-nil"
	case ErrorCodeBounds:
		return "bounds"
	case ErrorCodeDigestMismatch:
		return "digest-mismatch"
	case ErrorCodeEncoding:
		return "encoding"
	case ErrorCodeCatalog:
		return "catalog"
	case ErrorCodeMissingSection:
		return "missing-section"
	case ErrorCodeDuplicate:
		return "duplicate"
	case ErrorCodeContradiction:
		return "contradiction"
	case ErrorCodeUnsafeWidening:
		return "unsafe-widening"
	case ErrorCodeFatalAllow:
		return "fatal-allow"
	case ErrorCodeInvalidAncestry:
		return "invalid-ancestry"
	case ErrorCodeObservation:
		return "observation"
	case ErrorCodeOwnership:
		return "ownership"
	case ErrorCodeTransition:
		return "transition"
	default:
		return "unknown"
	}
}

// ContractError carries no dynamic input or wrapped cause.
type ContractError struct{ code ErrorCode }

func (failure *ContractError) Error() string {
	if failure == nil {
		return "syscall policy contract rejected: invalid-argument"
	}
	return "syscall policy contract rejected: " + failure.code.String()
}

func (failure *ContractError) Code() ErrorCode {
	if failure == nil {
		return 0
	}
	return failure.code
}

func (failure *ContractError) Is(target error) bool {
	wanted, ok := target.(*ContractError)
	return ok && failure != nil && wanted != nil && failure.code == wanted.code
}

func contractError(code ErrorCode) *ContractError { return &ContractError{code: code} }
