package v2control

import "encoding/base64"

const (
	requestIDEncodedLength      = 22
	identityDigestEncodedLength = 43
)

// RequestID is one private fixed-size nonzero request correlation value.
type RequestID struct {
	value [16]byte
}

// NewRequestID validates and defensively constructs a request ID.
func NewRequestID(value [16]byte) (RequestID, error) {
	if value == [16]byte{} {
		return RequestID{}, ErrInvalidRequestID
	}
	return RequestID{value: value}, nil
}

// ParseRequestID accepts only the exact unpadded base64url scalar.
func ParseRequestID(encoded string) (RequestID, error) {
	if len(encoded) != requestIDEncodedLength {
		return RequestID{}, ErrInvalidRequestID
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != 16 ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return RequestID{}, ErrInvalidRequestID
	}
	var value [16]byte
	copy(value[:], decoded)
	return NewRequestID(value)
}

// EncodeRequestID returns the canonical scalar for an explicit control codec.
func EncodeRequestID(requestID RequestID) (string, error) {
	if requestID.value == [16]byte{} {
		return "", ErrInvalidRequestID
	}
	return base64.RawURLEncoding.EncodeToString(requestID.value[:]), nil
}

// Bytes returns the fixed-size request ID by value.
func (requestID RequestID) Bytes() [16]byte {
	return requestID.value
}

// IdentityDigest is one private fixed-size identity correlation digest.
type IdentityDigest struct {
	value [32]byte
}

// NewIdentityDigest defensively constructs a fixed-size digest.
func NewIdentityDigest(value [32]byte) IdentityDigest {
	return IdentityDigest{value: value}
}

// ParseIdentityDigest accepts only the exact unpadded base64url scalar.
func ParseIdentityDigest(encoded string) (IdentityDigest, error) {
	if len(encoded) != identityDigestEncodedLength {
		return IdentityDigest{}, ErrInvalidIdentityDigest
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return IdentityDigest{}, ErrInvalidIdentityDigest
	}
	var value [32]byte
	copy(value[:], decoded)
	return NewIdentityDigest(value), nil
}

// EncodeIdentityDigest returns the canonical scalar for an explicit codec.
func EncodeIdentityDigest(digest IdentityDigest) string {
	return base64.RawURLEncoding.EncodeToString(digest.value[:])
}

// Bytes returns the fixed-size digest by value.
func (digest IdentityDigest) Bytes() [32]byte {
	return digest.value
}
