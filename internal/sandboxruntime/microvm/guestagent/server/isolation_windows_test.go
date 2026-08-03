package server

import (
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestL7LinuxIsolationVerifierFailsClosedOnNonLinux(t *testing.T) {
	verifier, err := NewLinuxIsolationVerifier(LinuxIsolationVerifierOptions{})
	if verifier != nil || err == nil {
		t.Fatalf("NewLinuxIsolationVerifier() = %#v, %v, want fail-closed unsupported platform", verifier, err)
	}
	var protocolErr *guestagent.ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Code != guestagent.ErrorCodeUnsupportedPlatform {
		t.Fatalf("error = %v, want unsupported platform protocol error", err)
	}
}
