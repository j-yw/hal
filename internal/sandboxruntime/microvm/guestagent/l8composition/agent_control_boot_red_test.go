package l8composition

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

func TestL8D6GuestControlBootIdentityCorrelatesIndependentAuthorities(t *testing.T) {
	fixture := agentSupervisorFixture(t)
	control := testAgentControlSessionIdentity()
	control.BootGeneration = fixture.config.BootGeneration
	control.VsockGeneration = fixture.config.VSockGeneration
	var publicKey [ed25519.PublicKeySize]byte
	for index := range publicKey {
		publicKey[index] = byte(index + 1)
	}

	identity, err := NewAgentControlBootIdentity(fixture.config, control, publicKey)
	if err != nil {
		t.Fatalf("NewAgentControlBootIdentity() error = %v", err)
	}
	if identity.SessionIdentity() != control || identity.ControllerPublicKey() != publicKey || identity.HelperGeneration() != credentialprotocol.SafeID(fixture.config.HelperGeneration) {
		t.Fatal("control boot identity did not retain exact correlated authority")
	}
	if identity.SessionIdentity().GuestBootNonce == fixture.config.BootNonce {
		t.Fatal("control session reused the helper-local boot nonce")
	}
}

func TestL8D6GuestControlBootIdentityRejectsEveryCrossAuthorityMismatch(t *testing.T) {
	fixture := agentSupervisorFixture(t)
	control := testAgentControlSessionIdentity()
	control.BootGeneration = fixture.config.BootGeneration
	control.VsockGeneration = fixture.config.VSockGeneration
	var publicKey [ed25519.PublicKeySize]byte
	publicKey[0] = 1

	for _, mutate := range []func(*session.Identity){
		func(value *session.Identity) { value.Channel = session.ChannelSSHRelay },
		func(value *session.Identity) { value.GuestCID++ },
		func(value *session.Identity) { value.GuestPort++ },
		func(value *session.Identity) { value.BootGeneration = "other-boot" },
		func(value *session.Identity) { value.VsockGeneration = "other-vsock" },
	} {
		candidate := control
		mutate(&candidate)
		if _, err := NewAgentControlBootIdentity(fixture.config, candidate, publicKey); err == nil || errors.Is(err, ErrAgentControlBootDependencyUnaccepted) {
			t.Fatalf("mismatched control identity error = %v; want implemented static rejection", err)
		}
	}
}

func testAgentControlSessionIdentity() session.Identity {
	var nonce, image [32]byte
	for index := range nonce {
		nonce[index] = byte(index + 81)
		image[index] = byte(index + 121)
	}
	return session.Identity{
		Channel:                      session.ChannelControl,
		GuestBootNonce:               nonce,
		GuestCID:                     session.GuestCID,
		GuestPort:                    session.ControlPort,
		ControllerKeyGeneration:      "controller-key-gen-1",
		RuntimeID:                    "runtime-1",
		RuntimeGeneration:            "runtime-gen-1",
		FirecrackerProcessGeneration: "process-gen-1",
		VsockGeneration:              "vsock-gen-1",
		BootGeneration:               "boot-gen-1",
		ImageGeneration:              "image-gen-1",
		ImageSHA256:                  image,
	}
}
