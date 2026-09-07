package minimalcontrol

import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"

const (
	MaxWorkloadPayloadBytes = 1 << 20
	MaxWorkloadMessageBytes = 1398401
)

// These unselected compiling RED methods remain unavailable. The inner bytes
// belong to the existing v1 endpoints, not a second operation interpreter.
func (binding Binding) EncodeWorkload(payload []byte, ordinal uint64, sessionID [32]byte) ([]byte, error) {
	return nil, ErrInvalid
}

func (binding Binding) DecodeWorkloadRequest(kind session.FrameType, payload []byte, ordinal uint64, sessionID [32]byte) ([]byte, error) {
	return nil, ErrInvalid
}

func (binding Binding) DecodeWorkloadResponse(kind session.FrameType, payload []byte, ordinal uint64, sessionID [32]byte) ([]byte, error) {
	return nil, ErrInvalid
}
