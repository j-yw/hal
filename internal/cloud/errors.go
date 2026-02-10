package cloud

import "fmt"

// Domain errors for the Store interface. Each error represents a specific
// persistence-level failure that callers can match to drive control flow.

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = fmt.Errorf("not_found")

// ErrConflict is returned when a write conflicts with existing state
// (e.g., concurrent claim on the same run).
var ErrConflict = fmt.Errorf("conflict")

// ErrLeaseExpired is returned when a heartbeat or renew targets a lease
// that has already expired.
var ErrLeaseExpired = fmt.Errorf("lease_expired")

// ErrInvalidTransition is returned when a status transition violates
// the allowed state machine (e.g., queued → succeeded without claiming first).
var ErrInvalidTransition = fmt.Errorf("invalid_transition")

// ErrProfileRevoked is returned when an operation targets an auth profile
// that has been revoked. Workers receiving this error should mark the
// attempt as failed and release the auth lock.
var ErrProfileRevoked = fmt.Errorf("profile_revoked")

// ErrBundleHashMismatch is returned when a submitted bundle's manifest hash
// does not match the recomputed hash of its records.
var ErrBundleHashMismatch = fmt.Errorf("bundle_hash_mismatch")

// IsNotFound reports whether err is the not_found domain error.
func IsNotFound(err error) bool {
	return err == ErrNotFound
}

// IsConflict reports whether err is the conflict domain error.
func IsConflict(err error) bool {
	return err == ErrConflict
}

// IsLeaseExpired reports whether err is the lease_expired domain error.
func IsLeaseExpired(err error) bool {
	return err == ErrLeaseExpired
}

// IsInvalidTransition reports whether err is the invalid_transition domain error.
func IsInvalidTransition(err error) bool {
	return err == ErrInvalidTransition
}

// IsProfileRevoked reports whether err is the profile_revoked domain error.
func IsProfileRevoked(err error) bool {
	return err == ErrProfileRevoked
}

// IsBundleHashMismatch reports whether err is the bundle_hash_mismatch domain error.
func IsBundleHashMismatch(err error) bool {
	return err == ErrBundleHashMismatch
}
