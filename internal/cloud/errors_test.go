package cloud

import (
	"fmt"
	"testing"
)

func TestDomainErrors(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		checker func(error) bool
		message string
	}{
		{
			name:    "ErrNotFound matches IsNotFound",
			err:     ErrNotFound,
			checker: IsNotFound,
			message: "not_found",
		},
		{
			name:    "ErrConflict matches IsConflict",
			err:     ErrConflict,
			checker: IsConflict,
			message: "conflict",
		},
		{
			name:    "ErrDuplicateKey matches IsDuplicateKey",
			err:     ErrDuplicateKey,
			checker: IsDuplicateKey,
			message: "duplicate_key",
		},
		{
			name:    "ErrLeaseExpired matches IsLeaseExpired",
			err:     ErrLeaseExpired,
			checker: IsLeaseExpired,
			message: "lease_expired",
		},
		{
			name:    "ErrInvalidTransition matches IsInvalidTransition",
			err:     ErrInvalidTransition,
			checker: IsInvalidTransition,
			message: "invalid_transition",
		},
		{
			name:    "ErrProfileRevoked matches IsProfileRevoked",
			err:     ErrProfileRevoked,
			checker: IsProfileRevoked,
			message: "profile_revoked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.checker(tt.err) {
				t.Errorf("checker returned false for its own sentinel error")
			}
			if tt.err.Error() != tt.message {
				t.Errorf("error message = %q, want %q", tt.err.Error(), tt.message)
			}
		})
	}
}

func TestDomainErrorsNonMatch(t *testing.T) {
	other := fmt.Errorf("some other error")

	tests := []struct {
		name    string
		checker func(error) bool
	}{
		{"IsNotFound rejects other", IsNotFound},
		{"IsConflict rejects other", IsConflict},
		{"IsDuplicateKey rejects other", IsDuplicateKey},
		{"IsLeaseExpired rejects other", IsLeaseExpired},
		{"IsInvalidTransition rejects other", IsInvalidTransition},
		{"IsProfileRevoked rejects other", IsProfileRevoked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.checker(other) {
				t.Errorf("checker returned true for unrelated error")
			}
			if tt.checker(nil) {
				t.Errorf("checker returned true for nil error")
			}
		})
	}
}
