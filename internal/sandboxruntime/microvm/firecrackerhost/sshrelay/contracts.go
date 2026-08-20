// Package sshrelay owns the daemon-local host SSH-agent registry and relay.
package sshrelay

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var errRegistryUnavailable = errors.New("host SSH relay registry is unavailable")

type ConfigIdentity struct{}
type PolicyIdentity struct{}
type AcquireRequest struct{}
type PeerProof struct{}

type PolicyRule struct {
	Fingerprint  string
	KeyAlgorithm credentialprotocol.SSHAgentKeyAlgorithm
	Flags        []credentialprotocol.SSHAgentRSAFlags
}

type LivePolicy interface {
	Identity() PolicyIdentity
}

type AgentConnection interface {
	RoundTrip(context.Context, []byte) ([]byte, error)
	Close(context.Context) error
}

type VerifiedAgentConnection interface {
	RoundTrip(context.Context, []byte) ([]byte, error)
	Close(context.Context) error
}

type LiveHostAgentEntry interface {
	Identity() ConfigIdentity
	Open(context.Context) (AgentConnection, error)
	VerifyPeer(context.Context, AgentConnection) (PeerProof, error)
	Policy() LivePolicy
}

type RegistryOptions struct {
	DaemonGeneration string
	Entries          []LiveHostAgentEntry
}

type Lease interface {
	Identity() ConfigIdentity
	PolicyIdentity() PolicyIdentity
	OpenVerifiedConnection(context.Context) (VerifiedAgentConnection, error)
	Close(context.Context) error
}

func NewConfigIdentity(credentialprotocol.SafeID, credentialprotocol.SafeID, credentialprotocol.SafeID, uint64) (ConfigIdentity, error) {
	return ConfigIdentity{}, errRegistryUnavailable
}

func NewPolicyIdentity(credentialprotocol.SafeID, uint64) (PolicyIdentity, error) {
	return PolicyIdentity{}, errRegistryUnavailable
}

func NewAcquireRequest(ConfigIdentity, credentialprotocol.SafeID, credentialprotocol.SafeID, credentialprotocol.SafeID, credentialprotocol.SafeID, credentialprotocol.SafeID, credentialprotocol.SafeID) (AcquireRequest, error) {
	return AcquireRequest{}, errRegistryUnavailable
}

func NewLivePolicy(PolicyIdentity, []PolicyRule) (LivePolicy, error) {
	return nil, errRegistryUnavailable
}

func NewPeerProof(ConfigIdentity, AgentConnection) (PeerProof, error) {
	return PeerProof{}, errRegistryUnavailable
}
