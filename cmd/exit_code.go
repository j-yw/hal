package cmd

import "fmt"

const (
	// ExitCodeValidation is returned for validation-style expected failures.
	ExitCodeValidation = 2
	// ExitCodeAnalyzeNoReportsJSON is returned when analyze JSON mode has no reports.
	ExitCodeAnalyzeNoReportsJSON = 3
	// ExitCodeExpectedNonZero is reserved for generic expected non-zero exits.
	ExitCodeExpectedNonZero = 4
)

// ExitCodeError carries an explicit process exit code.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit code %d", e.Code)
}

func (e *ExitCodeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
