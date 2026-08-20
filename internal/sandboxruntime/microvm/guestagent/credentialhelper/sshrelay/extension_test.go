package sshrelay

import (
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestNewHelperExtensionReturnsExactSideEffectFreeRegistration(t *testing.T) {
	registration, err := NewHelperExtension(HelperOptions{})
	if err != nil {
		t.Fatalf("NewHelperExtension(): %v", err)
	}
	if !credentialprotocol.ExtensionDescriptorEqual(registration.Descriptor, credentialprotocol.SSHRelayV1ExtensionDescriptor()) {
		t.Fatal("NewHelperExtension() returned a noncanonical descriptor")
	}
	if registration.Factory == nil {
		t.Fatal("NewHelperExtension() returned a nil factory")
	}
}
