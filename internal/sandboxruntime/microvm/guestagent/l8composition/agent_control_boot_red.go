package l8composition

import (
	"crypto/ed25519"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

var (
	ErrAgentControlBootDependencyUnaccepted = errors.New("L8 agent control boot identity dependency is unaccepted")
	ErrInvalidAgentControlBootIdentity      = errors.New("L8 agent control boot identity is invalid")
)

// AgentControlBootIdentity is the immutable process-local join between the
// authenticated PID1 agent config and runtime-owned control-session config.
// It is not evidence, a durable value, or a proof constructor.
type AgentControlBootIdentity struct {
	compositionLiveValue
	identity            session.Identity
	controllerPublicKey [ed25519.PublicKeySize]byte
	helperGeneration    credentialprotocol.SafeID
}

func NewAgentControlBootIdentity(
	config AgentSupervisorAgentConfigBody,
	identity session.Identity,
	controllerPublicKey [ed25519.PublicKeySize]byte,
) (AgentControlBootIdentity, error) {
	if controllerPublicKey == ([ed25519.PublicKeySize]byte{}) ||
		identity.Channel != session.ChannelControl ||
		identity.GuestCID != session.GuestCID ||
		identity.GuestPort != session.ControlPort ||
		identity.BootGeneration != config.BootGeneration ||
		identity.VsockGeneration != config.VSockGeneration ||
		identity.GuestBootNonce == config.BootNonce ||
		identity.GuestBootNonce == ([32]byte{}) ||
		credentialprotocol.ValidateSafeID(credentialprotocol.SafeID(config.HelperGeneration)) != nil {
		return AgentControlBootIdentity{}, ErrInvalidAgentControlBootIdentity
	}
	return AgentControlBootIdentity{
		identity:            identity,
		controllerPublicKey: controllerPublicKey,
		helperGeneration:    credentialprotocol.SafeID(config.HelperGeneration),
	}, nil
}

func (identity AgentControlBootIdentity) SessionIdentity() session.Identity {
	return identity.identity
}

func (identity AgentControlBootIdentity) ControllerPublicKey() [ed25519.PublicKeySize]byte {
	return identity.controllerPublicKey
}

func (identity AgentControlBootIdentity) HelperGeneration() credentialprotocol.SafeID {
	return identity.helperGeneration
}
