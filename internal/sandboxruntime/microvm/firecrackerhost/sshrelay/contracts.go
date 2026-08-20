// Package sshrelay owns the daemon-local host SSH-agent registry and relay.
package sshrelay

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var (
	ErrInvalidArgument    = errors.New("host SSH relay argument is invalid")
	ErrDependencyRequired = errors.New("host SSH relay dependency is required")
	ErrDuplicateEntry     = errors.New("host SSH relay entry is duplicated")
	ErrIdentityMismatch   = errors.New("host SSH relay identity does not match")
	ErrPolicyInvalid      = errors.New("host SSH relay policy is invalid")
	ErrRegistryClosed     = errors.New("host SSH relay registry is closed")
	ErrLeaseClosed        = errors.New("host SSH relay lease is closed")
	ErrLeaseExpired       = errors.New("host SSH relay lease is expired")
	ErrConnectionClosed   = errors.New("host SSH relay connection is closed")
	ErrPeerProof          = errors.New("host SSH relay peer proof is invalid")
	ErrAgentOpen          = errors.New("host SSH relay agent open failed")
	ErrAgentPeer          = errors.New("host SSH relay agent peer validation failed")
	ErrAgentIO            = errors.New("host SSH relay agent operation failed")
	ErrCleanupIncomplete  = errors.New("host SSH relay cleanup is incomplete")
	ErrSerialization      = errors.New("host SSH relay serialization is denied")
	ErrRequestRejected    = errors.New("host SSH relay request is rejected")
	ErrConnectionLimit    = errors.New("host SSH relay connection limit reached")
)

type liveValue struct{}

func (liveValue) MarshalJSON() ([]byte, error)   { return nil, ErrSerialization }
func (liveValue) MarshalText() ([]byte, error)   { return nil, ErrSerialization }
func (liveValue) MarshalBinary() ([]byte, error) { return nil, ErrSerialization }
func (liveValue) UnmarshalJSON([]byte) error     { return ErrSerialization }
func (liveValue) UnmarshalText([]byte) error     { return ErrSerialization }
func (liveValue) UnmarshalBinary([]byte) error   { return ErrSerialization }
func (liveValue) String() string                 { return "sshrelay.live[redacted]" }
func (liveValue) GoString() string               { return "sshrelay.live[redacted]" }
func (liveValue) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sshrelay.live[redacted]"))
}

type ConfigIdentity struct {
	liveValue
	entryID          credentialprotocol.SafeID
	daemonGeneration credentialprotocol.SafeID
	entryGeneration  credentialprotocol.SafeID
	revision         uint64
}

func (identity ConfigIdentity) EntryID() credentialprotocol.SafeID { return identity.entryID }
func (identity ConfigIdentity) DaemonGeneration() credentialprotocol.SafeID {
	return identity.daemonGeneration
}
func (identity ConfigIdentity) EntryGeneration() credentialprotocol.SafeID {
	return identity.entryGeneration
}
func (identity ConfigIdentity) Revision() uint64 { return identity.revision }

func ConfigIdentityEqual(left, right ConfigIdentity) bool {
	return left.entryID == right.entryID &&
		left.daemonGeneration == right.daemonGeneration &&
		left.entryGeneration == right.entryGeneration &&
		left.revision == right.revision && validConfigIdentity(left) && validConfigIdentity(right)
}

type PolicyIdentity struct {
	liveValue
	id       credentialprotocol.SafeID
	revision uint64
}

func (identity PolicyIdentity) ID() credentialprotocol.SafeID { return identity.id }
func (identity PolicyIdentity) Revision() uint64              { return identity.revision }

func PolicyIdentityEqual(left, right PolicyIdentity) bool {
	return left.id == right.id && left.revision == right.revision &&
		validPolicyIdentity(left) && validPolicyIdentity(right)
}

type AcquireRequest struct {
	liveValue
	config               ConfigIdentity
	runtimeGeneration    credentialprotocol.SafeID
	processGeneration    credentialprotocol.SafeID
	vsockGeneration      credentialprotocol.SafeID
	workerJobGeneration  credentialprotocol.SafeID
	activationGeneration credentialprotocol.SafeID
	relayGeneration      credentialprotocol.SafeID
}

func (request AcquireRequest) ConfigIdentity() ConfigIdentity { return request.config }
func (request AcquireRequest) RuntimeGeneration() credentialprotocol.SafeID {
	return request.runtimeGeneration
}
func (request AcquireRequest) ProcessGeneration() credentialprotocol.SafeID {
	return request.processGeneration
}
func (request AcquireRequest) VsockGeneration() credentialprotocol.SafeID {
	return request.vsockGeneration
}
func (request AcquireRequest) WorkerJobGeneration() credentialprotocol.SafeID {
	return request.workerJobGeneration
}
func (request AcquireRequest) ActivationGeneration() credentialprotocol.SafeID {
	return request.activationGeneration
}
func (request AcquireRequest) RelayGeneration() credentialprotocol.SafeID {
	return request.relayGeneration
}

type PeerProof struct {
	liveValue
	state *peerProofState
}

type peerProofState struct {
	mu         sync.Mutex
	config     ConfigIdentity
	connection uintptr
	issuer     AgentConnection
	consumed   bool
}

type PolicyRule struct {
	liveValue
	Fingerprint  string
	KeyAlgorithm credentialprotocol.SSHAgentKeyAlgorithm
	Flags        []credentialprotocol.SSHAgentRSAFlags
}

type LivePolicy interface {
	Identity() PolicyIdentity
	FilterIdentities([]credentialprotocol.SSHAgentIdentity) ([]credentialprotocol.SSHAgentIdentity, error)
	AuthorizeSign(*credentialprotocol.SSHAgentSignRequest) error
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
	liveValue
	DaemonGeneration string
	Entries          []LiveHostAgentEntry
}

type Lease interface {
	Identity() ConfigIdentity
	PolicyIdentity() PolicyIdentity
	OpenVerifiedConnection(context.Context) (VerifiedAgentConnection, error)
	Close(context.Context) error
}

// AgentDialer and PeerVerifier are the sole live open and connected-peer
// inspection authorities admitted by a production host-agent entry.
type AgentDialer interface {
	Open(context.Context) (AgentConnection, error)
}

type PeerVerifier interface {
	Verify(context.Context, AgentConnection, ConfigIdentity) (PeerProof, error)
}

type LiveHostAgentOptions struct {
	liveValue
	Identity ConfigIdentity
	Policy   LivePolicy
	Dialer   AgentDialer
	Verifier PeerVerifier
}

func NewConfigIdentity(entryID, daemonGeneration, entryGeneration credentialprotocol.SafeID, revision uint64) (ConfigIdentity, error) {
	identity := ConfigIdentity{
		entryID:          entryID,
		daemonGeneration: daemonGeneration,
		entryGeneration:  entryGeneration,
		revision:         revision,
	}
	if !validConfigIdentity(identity) {
		return ConfigIdentity{}, ErrInvalidArgument
	}
	return identity, nil
}

func NewPolicyIdentity(id credentialprotocol.SafeID, revision uint64) (PolicyIdentity, error) {
	identity := PolicyIdentity{id: id, revision: revision}
	if !validPolicyIdentity(identity) {
		return PolicyIdentity{}, ErrInvalidArgument
	}
	return identity, nil
}

func NewAcquireRequest(config ConfigIdentity, runtimeGeneration, processGeneration, vsockGeneration, workerJobGeneration, activationGeneration, relayGeneration credentialprotocol.SafeID) (AcquireRequest, error) {
	request := AcquireRequest{
		config:               config,
		runtimeGeneration:    runtimeGeneration,
		processGeneration:    processGeneration,
		vsockGeneration:      vsockGeneration,
		workerJobGeneration:  workerJobGeneration,
		activationGeneration: activationGeneration,
		relayGeneration:      relayGeneration,
	}
	if !validAcquireRequest(request) {
		return AcquireRequest{}, ErrInvalidArgument
	}
	return request, nil
}

func NewPeerProof(config ConfigIdentity, connection AgentConnection) (PeerProof, error) {
	key, ok := liveConnectionKey(connection)
	if !validConfigIdentity(config) || !ok {
		return PeerProof{}, ErrPeerProof
	}
	return PeerProof{state: &peerProofState{config: config, connection: key, issuer: connection}}, nil
}

func consumePeerProof(proof PeerProof, config ConfigIdentity, connection AgentConnection) error {
	key, ok := liveConnectionKey(connection)
	if proof.state == nil || !ok {
		return ErrPeerProof
	}
	proof.state.mu.Lock()
	defer proof.state.mu.Unlock()
	if proof.state.consumed || proof.state.connection != key || !ConfigIdentityEqual(proof.state.config, config) {
		return ErrPeerProof
	}
	proof.state.consumed = true
	proof.state.issuer = nil
	return nil
}

func validConfigIdentity(identity ConfigIdentity) bool {
	return credentialprotocol.ValidateSafeID(identity.entryID) == nil &&
		credentialprotocol.ValidateSafeID(identity.daemonGeneration) == nil &&
		credentialprotocol.ValidateSafeID(identity.entryGeneration) == nil &&
		identity.revision > 0
}

func validPolicyIdentity(identity PolicyIdentity) bool {
	return credentialprotocol.ValidateSafeID(identity.id) == nil && identity.revision > 0
}

func validAcquireRequest(request AcquireRequest) bool {
	if !validConfigIdentity(request.config) {
		return false
	}
	for _, generation := range [...]credentialprotocol.SafeID{
		request.runtimeGeneration,
		request.processGeneration,
		request.vsockGeneration,
		request.workerJobGeneration,
		request.activationGeneration,
		request.relayGeneration,
	} {
		if credentialprotocol.ValidateSafeID(generation) != nil {
			return false
		}
	}
	return true
}

func configuredDependency(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !reflected.IsNil()
	default:
		return true
	}
}

func liveConnectionKey(connection AgentConnection) (uintptr, bool) {
	if !configuredDependency(connection) {
		return 0, false
	}
	reflected := reflect.ValueOf(connection)
	if reflected.Kind() != reflect.Pointer {
		return 0, false
	}
	key := reflected.Pointer()
	return key, key != 0
}
