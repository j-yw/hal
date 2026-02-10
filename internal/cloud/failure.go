package cloud

// FailureCode identifies the reason a run attempt failed.
// The classifier maps each code to a retryable or terminal outcome
// so retry decisions are consistent across the system.
type FailureCode string

const (
	FailureBootstrapFailed FailureCode = "bootstrap_failed"
	FailureAuthInvalid     FailureCode = "auth_invalid"
	FailurePolicyBlocked   FailureCode = "policy_blocked"
	FailureStaleAttempt    FailureCode = "stale_attempt"
	FailureRunTimeout      FailureCode = "run_timeout"
	FailureNonRetryable    FailureCode = "non_retryable"
)

// validFailureCodes is the exhaustive set of known failure codes.
var validFailureCodes = map[FailureCode]bool{
	FailureBootstrapFailed: true,
	FailureAuthInvalid:     true,
	FailurePolicyBlocked:   true,
	FailureStaleAttempt:    true,
	FailureRunTimeout:      true,
	FailureNonRetryable:    true,
}

// IsValid reports whether f is a known failure code.
func (f FailureCode) IsValid() bool {
	return validFailureCodes[f]
}

// retryableCodes maps each failure code to whether it should be retried.
// Retryable failures allow the scheduler to re-queue the run (up to max_attempts).
// Terminal failures keep the run in a failed state permanently.
var retryableCodes = map[FailureCode]bool{
	FailureBootstrapFailed: true,  // transient infra issue, retry may succeed
	FailureAuthInvalid:     false, // credentials are bad, retrying won't help
	FailurePolicyBlocked:   false, // policy rejection is deterministic
	FailureStaleAttempt:    true,  // lease expired, fresh attempt may succeed
	FailureRunTimeout:      false, // deadline exceeded, same work will timeout again
	FailureNonRetryable:    false, // explicitly non-retryable
}

// ClassifyFailure returns whether the given failure code is retryable.
// Unknown codes are treated as non-retryable to fail safe.
func ClassifyFailure(code FailureCode) (retryable bool) {
	r, known := retryableCodes[code]
	if !known {
		return false
	}
	return r
}
