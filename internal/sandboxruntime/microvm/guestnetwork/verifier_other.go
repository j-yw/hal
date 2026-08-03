//go:build !linux

package guestnetwork

import (
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

// NewLinuxNetworkIsolationVerifier fails closed away from Linux.
func NewLinuxNetworkIsolationVerifier(LinuxNetworkIsolationVerifierOptions) (NetworkIsolationVerifier, error) {
	const message = "Linux guest network isolation verifier is unsupported on this platform"
	return nil, &guestagent.ProtocolError{
		Code: guestagent.ErrorCodeUnsupportedPlatform, Field: "isolationProof.network", Message: message, Err: errors.New(message),
	}
}
