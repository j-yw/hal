//go:build !linux

package server

import (
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

// NewLinuxIsolationVerifier fails closed when Linux process and raw-socket
// semantics cannot be inspected locally.
func NewLinuxIsolationVerifier(LinuxIsolationVerifierOptions) (IsolationVerifier, error) {
	const message = "Linux guest isolation verifier is unsupported on this platform"
	return nil, &guestagent.ProtocolError{
		Code:    guestagent.ErrorCodeUnsupportedPlatform,
		Field:   "isolationProof",
		Message: message,
		Err:     errors.New(message),
	}
}
