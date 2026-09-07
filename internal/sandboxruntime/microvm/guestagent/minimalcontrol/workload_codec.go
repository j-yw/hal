package minimalcontrol

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

const (
	MaxWorkloadPayloadBytes = 1 << 20
	MaxWorkloadMessageBytes = 1398401
)

// EncodeWorkload returns an owned canonical envelope. The caller owns session
// authentication and ordinal progression; encoding grants no work authority.
func (binding Binding) EncodeWorkload(payload []byte, ordinal uint64, sessionID [32]byte) ([]byte, error) {
	if len(payload) > MaxWorkloadPayloadBytes {
		return nil, ErrInvalid
	}
	prefix, suffix, err := binding.workloadEnvelope(ordinal, sessionID)
	if err != nil {
		return nil, err
	}
	encodedSize := base64.StdEncoding.EncodedLen(len(payload))
	wire := make([]byte, len(prefix)+encodedSize+len(suffix))
	copy(wire, prefix)
	base64.StdEncoding.Encode(wire[len(prefix):len(prefix)+encodedSize], payload)
	copy(wire[len(prefix)+encodedSize:], suffix)
	return wire, nil
}

// DecodeWorkloadRequest validates a request against the caller's exact expected
// tuple/session/ordinal. Inner v1 bytes remain opaque to this codec.
func (binding Binding) DecodeWorkloadRequest(kind session.FrameType, payload []byte, ordinal uint64, sessionID [32]byte) ([]byte, error) {
	if kind != session.FrameTypeControlRequest {
		return nil, ErrInvalid
	}
	return binding.decodeWorkload(payload, ordinal, sessionID)
}

// DecodeWorkloadResponse is the corresponding response-direction check.
func (binding Binding) DecodeWorkloadResponse(kind session.FrameType, payload []byte, ordinal uint64, sessionID [32]byte) ([]byte, error) {
	if kind != session.FrameTypeControlResponse {
		return nil, ErrInvalid
	}
	return binding.decodeWorkload(payload, ordinal, sessionID)
}

func (binding Binding) workloadEnvelope(ordinal uint64, sessionID [32]byte) (string, string, error) {
	if ordinal == 0 {
		return "", "", ErrInvalid
	}
	digest, err := binding.Digest(sessionID)
	if err != nil {
		return "", "", ErrInvalid
	}
	prefix := `{"body":{"bindingDigest":"` + digest + `","guestSessionGeneration":"` + base64.RawURLEncoding.EncodeToString(sessionID[:]) + `","payload":"`
	suffix := `"},"operation":"workload","protocolVersion":"` + ProtocolVersion + `","requestId":"` + fmt.Sprintf("%032x", ordinal) + `"}`
	return prefix, suffix, nil
}

func (binding Binding) decodeWorkload(payload []byte, ordinal uint64, sessionID [32]byte) ([]byte, error) {
	if len(payload) > MaxWorkloadMessageBytes {
		return nil, ErrInvalid
	}
	prefix, suffix, err := binding.workloadEnvelope(ordinal, sessionID)
	if err != nil || len(payload) < len(prefix)+len(suffix) || !bytes.HasPrefix(payload, []byte(prefix)) || !bytes.HasSuffix(payload, []byte(suffix)) {
		return nil, ErrInvalid
	}
	encoded := payload[len(prefix) : len(payload)-len(suffix)]
	if len(encoded)%4 != 0 {
		return nil, ErrInvalid
	}
	padding := 0
	for padding < 2 && padding < len(encoded) && encoded[len(encoded)-1-padding] == '=' {
		padding++
	}
	decodedSize := len(encoded)/4*3 - padding
	if decodedSize > MaxWorkloadPayloadBytes {
		return nil, ErrInvalid
	}
	// Go's Strict decoder still ignores CR/LF. Enforce the exact alphabet and
	// terminal padding before allocating; no JSON escapes/keys can hide here.
	for _, ch := range encoded[:len(encoded)-padding] {
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '+' || ch == '/') {
			return nil, ErrInvalid
		}
	}
	decoded := make([]byte, decodedSize)
	n, err := base64.StdEncoding.Strict().Decode(decoded, encoded)
	if err != nil || n != decodedSize {
		clear(decoded)
		return nil, ErrInvalid
	}
	return decoded, nil
}
