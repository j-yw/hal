package l8composition

import (
	"crypto/ed25519"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

var ErrAgentControlBootDependencyUnaccepted = errors.New("L8 agent control boot identity dependency is unaccepted")

// AgentControlBootIdentity is the immutable process-local join between the
// authenticated PID1 agent config and runtime-owned control-session config.
// It is not evidence, a durable value, or a proof constructor.
type AgentControlBootIdentity struct {
	compositionLiveValue
	identity            session.Identity
	controllerPublicKey [ed25519.PublicKeySize]byte
	helperGeneration    credentialprotocol.SafeID
}

// NewAgentControlBootIdentity is frozen as a RED contract. The future
// implementation must correlate the runtime-owned identity with the accepted
// AgentSupervisorAgentConfigBody and must not reuse its helper-local nonce as
// the distinct guest-session boot nonce.
func NewAgentControlBootIdentity(
	AgentSupervisorAgentConfigBody,
	session.Identity,
	[ed25519.PublicKeySize]byte,
) (AgentControlBootIdentity, error) {
	return AgentControlBootIdentity{}, ErrAgentControlBootDependencyUnaccepted
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
