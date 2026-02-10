package cloud

import "testing"

func TestFailureCodeIsValid(t *testing.T) {
	tests := []struct {
		name  string
		code  FailureCode
		valid bool
	}{
		{name: "bootstrap_failed is valid", code: FailureBootstrapFailed, valid: true},
		{name: "auth_invalid is valid", code: FailureAuthInvalid, valid: true},
		{name: "policy_blocked is valid", code: FailurePolicyBlocked, valid: true},
		{name: "stale_attempt is valid", code: FailureStaleAttempt, valid: true},
		{name: "run_timeout is valid", code: FailureRunTimeout, valid: true},
		{name: "non_retryable is valid", code: FailureNonRetryable, valid: true},
		{name: "empty string is invalid", code: "", valid: false},
		{name: "unknown code is invalid", code: "unknown_failure", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.code.IsValid(); got != tt.valid {
				t.Errorf("FailureCode(%q).IsValid() = %v, want %v", tt.code, got, tt.valid)
			}
		})
	}
}

func TestClassifyFailure(t *testing.T) {
	tests := []struct {
		name      string
		code      FailureCode
		retryable bool
	}{
		{
			name:      "bootstrap_failed is retryable",
			code:      FailureBootstrapFailed,
			retryable: true,
		},
		{
			name:      "auth_invalid is terminal",
			code:      FailureAuthInvalid,
			retryable: false,
		},
		{
			name:      "policy_blocked is terminal",
			code:      FailurePolicyBlocked,
			retryable: false,
		},
		{
			name:      "stale_attempt is retryable",
			code:      FailureStaleAttempt,
			retryable: true,
		},
		{
			name:      "run_timeout is terminal",
			code:      FailureRunTimeout,
			retryable: false,
		},
		{
			name:      "non_retryable is terminal",
			code:      FailureNonRetryable,
			retryable: false,
		},
		{
			name:      "unknown code defaults to non-retryable",
			code:      "unknown_failure",
			retryable: false,
		},
		{
			name:      "empty code defaults to non-retryable",
			code:      "",
			retryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyFailure(tt.code); got != tt.retryable {
				t.Errorf("ClassifyFailure(%q) = %v, want %v", tt.code, got, tt.retryable)
			}
		})
	}
}

func TestAllValidCodesAreClassified(t *testing.T) {
	// Every valid failure code must have an entry in the retryable map.
	for code := range validFailureCodes {
		t.Run(string(code), func(t *testing.T) {
			if _, known := retryableCodes[code]; !known {
				t.Errorf("FailureCode %q is valid but missing from retryableCodes map", code)
			}
		})
	}
}

func TestRetryableCodesAreAllValid(t *testing.T) {
	// Every code in the retryable map must be a valid failure code.
	for code := range retryableCodes {
		t.Run(string(code), func(t *testing.T) {
			if !code.IsValid() {
				t.Errorf("retryableCodes contains %q which is not a valid FailureCode", code)
			}
		})
	}
}
