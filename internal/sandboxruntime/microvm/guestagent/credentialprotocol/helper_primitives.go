package credentialprotocol

import (
	"encoding/binary"
	"errors"
)

const (
	// MaxBodyTokenBytes is the exact HL8P body-token byte bound.
	MaxBodyTokenBytes = 128
	// MaxRelativePathBytes is the exact optional relative-path byte bound.
	MaxRelativePathBytes = 4096
	// MaxRelativePathComponentBytes is the exact component byte bound.
	MaxRelativePathComponentBytes = 255
)

var (
	ErrInvalidBodyToken         = errors.New("credential protocol body token is invalid")
	ErrBodyTokenEncoding        = errors.New("credential protocol body token encoding is invalid")
	ErrBodyTokenTrailingData    = errors.New("credential protocol body token has trailing data")
	ErrInvalidRelativePath      = errors.New("credential protocol relative path is invalid")
	ErrRelativePathEncoding     = errors.New("credential protocol relative path encoding is invalid")
	ErrRelativePathTrailingData = errors.New("credential protocol relative path has trailing data")
)

// ValidateBodyToken accepts exactly 1..128 ASCII bytes matching
// [A-Za-z0-9][A-Za-z0-9._:-]{0,127}. It performs no normalization.
func ValidateBodyToken(token string) error {
	if len(token) == 0 || len(token) > MaxBodyTokenBytes || !isBodyTokenFirstByte(token[0]) {
		return ErrInvalidBodyToken
	}
	for index := 1; index < len(token); index++ {
		if !isBodyTokenByte(token[index]) {
			return ErrInvalidBodyToken
		}
	}
	return nil
}

// EncodeBodyToken returns uint16_be(length) followed by canonical ASCII bytes.
func EncodeBodyToken(token string) ([]byte, error) {
	if err := ValidateBodyToken(token); err != nil {
		return nil, err
	}
	encoded := make([]byte, 2+len(token))
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(token)))
	copy(encoded[2:], token)
	return encoded, nil
}

// DecodeBodyToken decodes one complete token and rejects trailing bytes.
func DecodeBodyToken(encoded []byte) (string, error) {
	token, consumed, err := DecodeBodyTokenPrefix(encoded)
	if err != nil {
		return "", err
	}
	if consumed != len(encoded) {
		return "", ErrBodyTokenTrailingData
	}
	return token, nil
}

// DecodeBodyTokenPrefix decodes one token from the start of a larger
// type-specific body. It validates the declared bound before copying bytes.
func DecodeBodyTokenPrefix(encoded []byte) (string, int, error) {
	if len(encoded) < 2 {
		return "", 0, ErrBodyTokenEncoding
	}
	length := int(binary.BigEndian.Uint16(encoded[:2]))
	if length < 1 || length > MaxBodyTokenBytes {
		return "", 0, ErrInvalidBodyToken
	}
	consumed := 2 + length
	if len(encoded) < consumed {
		return "", 0, ErrBodyTokenEncoding
	}
	token := string(encoded[2:consumed])
	if err := ValidateBodyToken(token); err != nil {
		return "", 0, err
	}
	return token, consumed, nil
}

func isBodyTokenFirstByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9'
}

func isBodyTokenByte(value byte) bool {
	return isBodyTokenFirstByte(value) || value == '.' || value == '_' || value == ':' || value == '-'
}

// ValidateOptionalRelativePath accepts absence as the empty string. Present
// paths are canonical 1..4096-byte printable ASCII relative paths with 1..255
// byte components and no dot, dot-dot, empty, slash-edge, or backslash form.
func ValidateOptionalRelativePath(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > MaxRelativePathBytes || value[0] == '/' || value[len(value)-1] == '/' {
		return ErrInvalidRelativePath
	}
	componentStart := 0
	for index := 0; index <= len(value); index++ {
		if index < len(value) {
			current := value[index]
			if current == '\\' || current < 0x20 || current > 0x7e {
				return ErrInvalidRelativePath
			}
			if current != '/' {
				continue
			}
		}
		component := value[componentStart:index]
		if len(component) == 0 || len(component) > MaxRelativePathComponentBytes || component == "." || component == ".." {
			return ErrInvalidRelativePath
		}
		componentStart = index + 1
	}
	return nil
}

// EncodeOptionalRelativePath returns uint16_be(length) and canonical path
// bytes; an absent path is exactly a zero length with no bytes.
func EncodeOptionalRelativePath(value string) ([]byte, error) {
	if err := ValidateOptionalRelativePath(value); err != nil {
		return nil, err
	}
	encoded := make([]byte, 2+len(value))
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(value)))
	copy(encoded[2:], value)
	return encoded, nil
}

// DecodeOptionalRelativePath decodes one complete optional path and rejects
// trailing bytes.
func DecodeOptionalRelativePath(encoded []byte) (string, error) {
	value, consumed, err := DecodeOptionalRelativePathPrefix(encoded)
	if err != nil {
		return "", err
	}
	if consumed != len(encoded) {
		return "", ErrRelativePathTrailingData
	}
	return value, nil
}

// DecodeOptionalRelativePathPrefix decodes one optional path from the start of
// a larger type-specific body. Bounds are checked before copying bytes.
func DecodeOptionalRelativePathPrefix(encoded []byte) (string, int, error) {
	if len(encoded) < 2 {
		return "", 0, ErrRelativePathEncoding
	}
	length := int(binary.BigEndian.Uint16(encoded[:2]))
	if length > MaxRelativePathBytes {
		return "", 0, ErrInvalidRelativePath
	}
	consumed := 2 + length
	if len(encoded) < consumed {
		return "", 0, ErrRelativePathEncoding
	}
	value := string(encoded[2:consumed])
	if err := ValidateOptionalRelativePath(value); err != nil {
		return "", 0, err
	}
	return value, consumed, nil
}
