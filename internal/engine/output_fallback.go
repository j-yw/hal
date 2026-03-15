package engine

import (
	"errors"
	"fmt"
)

// OutputFallbackRequiredError indicates the engine reported terminal success
// without any streamed text, so callers must verify an expected output file
// instead of treating the prompt as a normal text response.
type OutputFallbackRequiredError struct {
	cause error
}

func (e *OutputFallbackRequiredError) Error() string {
	if e == nil || e.cause == nil {
		return "prompt produced no streamed response; output file fallback required"
	}
	return fmt.Sprintf("prompt produced no streamed response; output file fallback required: %v", e.cause)
}

func (e *OutputFallbackRequiredError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// NewOutputFallbackRequiredError wraps an engine failure that should only be
// treated as recoverable by callers with an explicit output-file fallback.
func NewOutputFallbackRequiredError(cause error) error {
	return &OutputFallbackRequiredError{cause: cause}
}

// RequiresOutputFallback reports whether err indicates the caller must verify a
// direct-write output file instead of using a streamed text response.
func RequiresOutputFallback(err error) bool {
	var target *OutputFallbackRequiredError
	return errors.As(err, &target)
}
