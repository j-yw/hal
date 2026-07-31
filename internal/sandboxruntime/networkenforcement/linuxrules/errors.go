package linuxrules

import "errors"

var (
	ErrInvalidConfiguration = errors.New("linux rule configuration invalid")
	ErrUnsupported          = errors.New("linux rules unsupported")
	ErrTableNotFound        = errors.New("linux rule table absent")
	ErrBatchTooLarge        = errors.New("linux rule batch too large")
	ErrInspectionTooLarge   = errors.New("linux rule inspection too large")
	ErrApplyFailed          = errors.New("linux rule apply failed")
	ErrInspectionFailed     = errors.New("linux rule inspection failed")
	ErrQuarantineFailed     = errors.New("linux rule quarantine failed")
	ErrCleanupFailed        = errors.New("linux rule cleanup failed")
	ErrStaleGeneration      = errors.New("linux rule generation stale")
)

type operationError struct {
	err error
}

func (e operationError) Error() string { return e.err.Error() }
func (e operationError) Unwrap() error { return e.err }

func safeError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{
		ErrInvalidConfiguration,
		ErrUnsupported,
		ErrTableNotFound,
		ErrBatchTooLarge,
		ErrInspectionTooLarge,
		ErrApplyFailed,
		ErrInspectionFailed,
		ErrQuarantineFailed,
		ErrCleanupFailed,
		ErrStaleGeneration,
	} {
		if errors.Is(err, known) {
			return operationError{err: known}
		}
	}
	return operationError{err: ErrInspectionFailed}
}
