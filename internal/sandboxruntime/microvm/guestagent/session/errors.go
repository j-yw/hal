package session

import "errors"

var (
	ErrMalformedHandshake = errors.New("guest session handshake is malformed")
	ErrIdentityMismatch   = errors.New("guest session identity does not match")
	ErrAuthentication     = errors.New("guest session authentication failed")
	ErrHandshakeTimeout   = errors.New("guest session handshake timed out")
	ErrInvalidState       = errors.New("guest session state is invalid")
	ErrInvalidFrame       = errors.New("guest session frame is invalid")
	ErrUnexpectedFrame    = errors.New("guest session frame is unexpected")
	ErrRecordTooLarge     = errors.New("guest session record exceeds limit")
	ErrReplay             = errors.New("guest session replay detected")
	ErrSequenceGap        = errors.New("guest session sequence gap detected")
	ErrSequenceExhausted  = errors.New("guest session record limit reached")
	ErrSemanticValidation = errors.New("guest session payload is invalid")
	ErrSessionRevoked     = errors.New("guest session is revoked")
	ErrPartialWrite       = errors.New("guest session record write failed")
	ErrAlreadyActive      = errors.New("guest session generation is already active")
	ErrReconnectRejected  = errors.New("guest session reconnect is rejected")
	ErrPreAuthExhausted   = errors.New("guest session pre-authentication limit reached")
	ErrCredentialLifetime = errors.New("guest credential lifetime exceeds session limit")
)
