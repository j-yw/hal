package v2control

import "errors"

var (
	ErrInvalidJobIdentity                          = errors.New("guest credential job identity is invalid")
	ErrInvalidJobIdentityJSON                      = errors.New("guest credential job identity JSON is invalid")
	ErrSessionIdentityMismatch                     = errors.New("guest credential session identity does not match")
	ErrGuestCredentialSessionIdentitySerialization = errors.New("guest credential session identity serialization is denied")
)
