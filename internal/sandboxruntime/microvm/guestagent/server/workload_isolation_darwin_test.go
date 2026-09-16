package server

import (
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestWorkloadLinuxIsolationUnsupportedPlatform(t *testing.T) {
	verifier, err := NewLinuxWorkloadIsolationVerifier(LinuxIsolationVerifierOptions{})
	var protocolErr *guestagent.ProtocolError
	if verifier != nil || !errors.As(err, &protocolErr) || protocolErr.Code != guestagent.ErrorCodeUnsupportedPlatform || protocolErr.Field != "isolationProof" {
		t.Fatal("non-Linux constructor did not fail closed with unsupported platform")
	}
}
