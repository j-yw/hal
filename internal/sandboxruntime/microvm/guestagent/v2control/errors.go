package v2control

import "errors"

var (
	ErrInvalidJobIdentity                          = errors.New("guest credential job identity is invalid")
	ErrInvalidJobIdentityJSON                      = errors.New("guest credential job identity JSON is invalid")
	ErrSessionIdentityMismatch                     = errors.New("guest credential session identity does not match")
	ErrGuestCredentialSessionIdentitySerialization = errors.New("guest credential session identity serialization is denied")
	ErrInvalidOperation                            = errors.New("guest agent v2 control operation is invalid")
	ErrInvalidOperationToken                       = errors.New("guest agent v2 control operation token is invalid")
	ErrInvalidErrorCode                            = errors.New("guest agent v2 control error code is invalid")
	ErrInvalidOperationErrorCode                   = errors.New("guest agent v2 control operation error code is invalid")
	ErrInvalidControlError                         = errors.New("guest agent v2 control error is invalid")
	ErrInvalidRequestID                            = errors.New("guest agent v2 control request ID is invalid")
	ErrInvalidIdentityDigest                       = errors.New("guest agent v2 control identity digest is invalid")
	ErrControlScalarSerialization                  = errors.New("guest agent v2 control scalar serialization is denied")
)
