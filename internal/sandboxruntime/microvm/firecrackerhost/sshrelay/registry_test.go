package sshrelay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type redAgentConnection struct {
	mu             sync.Mutex
	closed         int
	closeFailures  int
	roundTrips     int
	response       []byte
	roundTripError error
	roundTripFunc  func(context.Context, []byte) ([]byte, error)
}

func (connection *redAgentConnection) RoundTrip(ctx context.Context, request []byte) ([]byte, error) {
	connection.mu.Lock()
	connection.roundTrips++
	callback := connection.roundTripFunc
	response := append([]byte(nil), connection.response...)
	err := connection.roundTripError
	connection.mu.Unlock()
	if callback != nil {
		return callback(ctx, request)
	}
	return response, err
}
func (connection *redAgentConnection) Close(context.Context) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.closed++
	if connection.closeFailures > 0 {
		connection.closeFailures--
		return errors.New("raw close canary")
	}
	return nil
}

type redEntry struct {
	identity ConfigIdentity
	policy   LivePolicy
	opens    int
	opened   []*redAgentConnection
	verify   func(AgentConnection) (PeerProof, error)
	newAgent func() *redAgentConnection
	openFunc func(context.Context) (AgentConnection, error)
}

type invalidLivePolicy struct{ identity PolicyIdentity }

func (policy *invalidLivePolicy) Identity() PolicyIdentity { return policy.identity }
func (*invalidLivePolicy) FilterIdentities([]credentialprotocol.SSHAgentIdentity) ([]credentialprotocol.SSHAgentIdentity, error) {
	return nil, nil
}
func (*invalidLivePolicy) AuthorizeSign(*credentialprotocol.SSHAgentSignRequest) error { return nil }

func (entry *redEntry) Identity() ConfigIdentity { return entry.identity }
func (entry *redEntry) Policy() LivePolicy       { return entry.policy }
func (entry *redEntry) Open(ctx context.Context) (AgentConnection, error) {
	entry.opens++
	if entry.openFunc != nil {
		return entry.openFunc(ctx)
	}
	connection := &redAgentConnection{}
	if entry.newAgent != nil {
		connection = entry.newAgent()
	}
	entry.opened = append(entry.opened, connection)
	return connection, nil
}
func (entry *redEntry) VerifyPeer(_ context.Context, connection AgentConnection) (PeerProof, error) {
	if entry.verify != nil {
		return entry.verify(connection)
	}
	return NewPeerProof(entry.identity, connection)
}

func TestRegistryAcquiresExactIdentityAndFreshVerifiedConnection(t *testing.T) {
	config, err := NewConfigIdentity("entry-a", "daemon-a", "entry-generation-a", 1)
	if err != nil {
		t.Fatalf("NewConfigIdentity(): %v", err)
	}
	policyIdentity, err := NewPolicyIdentity("policy-a", 1)
	if err != nil {
		t.Fatalf("NewPolicyIdentity(): %v", err)
	}
	policy, err := NewLivePolicy(policyIdentity, []PolicyRule{{
		Fingerprint:  "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		KeyAlgorithm: credentialprotocol.SSHAgentKeyAlgorithmED25519,
		Flags:        []credentialprotocol.SSHAgentRSAFlags{0},
	}})
	if err != nil {
		t.Fatalf("NewLivePolicy(): %v", err)
	}
	entry := &redEntry{identity: config, policy: policy}
	registry, err := NewRegistry(RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{entry}})
	if err != nil {
		t.Fatalf("NewRegistry(): %v", err)
	}
	request, err := NewAcquireRequest(config, "runtime-a", "process-a", "vsock-a", "job-a", "activation-a", "relay-a")
	if err != nil {
		t.Fatalf("NewAcquireRequest(): %v", err)
	}
	lease, err := registry.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire(): %v", err)
	}
	first, err := lease.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("first OpenVerifiedConnection(): %v", err)
	}
	second, err := lease.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("second OpenVerifiedConnection(): %v", err)
	}
	if first == second || entry.opens != 2 {
		t.Fatalf("fresh connections: first==second %v, opens=%d", first == second, entry.opens)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close(): %v", err)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Registry.Close(): %v", err)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("second Registry.Close(): %v", err)
	}
}

func TestRegistryRejectsInvalidFrozenConfiguration(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	policy := mustPolicy(t, "policy-a", 1)
	entry := &redEntry{identity: config, policy: policy}
	policyIdentity, err := NewPolicyIdentity("policy-b", 1)
	if err != nil {
		t.Fatalf("NewPolicyIdentity(): %v", err)
	}
	invalidPolicyEntry := &redEntry{identity: config, policy: &invalidLivePolicy{identity: policyIdentity}}
	typedNil := (*redEntry)(nil)

	tests := []struct {
		name    string
		options RegistryOptions
		want    error
	}{
		{name: "invalid daemon", options: RegistryOptions{DaemonGeneration: "not safe", Entries: []LiveHostAgentEntry{entry}}, want: ErrInvalidArgument},
		{name: "generation mismatch", options: RegistryOptions{DaemonGeneration: "daemon-b", Entries: []LiveHostAgentEntry{entry}}, want: ErrIdentityMismatch},
		{name: "typed nil", options: RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{typedNil}}, want: ErrDependencyRequired},
		{name: "unissued empty policy", options: RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{invalidPolicyEntry}}, want: ErrPolicyInvalid},
		{name: "duplicate entry", options: RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{entry, entry}}, want: ErrDuplicateEntry},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry, err := NewRegistry(test.options)
			if registry != nil || !errors.Is(err, test.want) {
				t.Fatalf("NewRegistry() = (%v, %v), want nil, %v", registry, err, test.want)
			}
		})
	}
}

func TestRegistryRejectsCachedAndCrossConnectionPeerProofs(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{identity: config, policy: mustPolicy(t, "policy-a", 1)}
	var cached PeerProof
	entry.verify = func(connection AgentConnection) (PeerProof, error) {
		if cached.state == nil {
			cached, _ = NewPeerProof(config, connection)
		}
		return cached, nil
	}
	registry := mustRegistry(t, entry)
	lease := mustLease(t, registry, config)
	first, err := lease.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("first OpenVerifiedConnection(): %v", err)
	}
	if _, err := lease.OpenVerifiedConnection(context.Background()); !errors.Is(err, ErrAgentPeer) {
		t.Fatalf("second OpenVerifiedConnection() error = %v, want %v", err, ErrAgentPeer)
	}
	if entry.opened[1].closed != 1 {
		t.Fatalf("rejected cross-proof connection close count = %d, want 1", entry.opened[1].closed)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatalf("first.Close(): %v", err)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("lease.Close(): %v", err)
	}
}

func TestLeaseEnforcesConcurrentAndLifetimeConnectionLimits(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{identity: config, policy: mustPolicy(t, "policy-a", 1)}
	registry := mustRegistry(t, entry)
	lease := mustLease(t, registry, config)

	active := make([]VerifiedAgentConnection, 0, credentialprotocol.SSHAgentRelayMaxConcurrentConnections)
	for index := 0; index < credentialprotocol.SSHAgentRelayMaxConcurrentConnections; index++ {
		connection, err := lease.OpenVerifiedConnection(context.Background())
		if err != nil {
			t.Fatalf("OpenVerifiedConnection(%d): %v", index, err)
		}
		active = append(active, connection)
	}
	if _, err := lease.OpenVerifiedConnection(context.Background()); !errors.Is(err, ErrConnectionLimit) {
		t.Fatalf("concurrent plus one error = %v, want %v", err, ErrConnectionLimit)
	}
	for _, connection := range active {
		if err := connection.Close(context.Background()); err != nil {
			t.Fatalf("active Close(): %v", err)
		}
	}
	for index := len(active); index < credentialprotocol.SSHAgentRelayMaxLifetimeConnections; index++ {
		connection, err := lease.OpenVerifiedConnection(context.Background())
		if err != nil {
			t.Fatalf("lifetime OpenVerifiedConnection(%d): %v", index, err)
		}
		if err := connection.Close(context.Background()); err != nil {
			t.Fatalf("lifetime Close(%d): %v", index, err)
		}
	}
	if _, err := lease.OpenVerifiedConnection(context.Background()); !errors.Is(err, ErrConnectionLimit) {
		t.Fatalf("lifetime plus one error = %v, want %v", err, ErrConnectionLimit)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("lease.Close(): %v", err)
	}
}

func TestLeaseCloseRetainsFailedConnectionForRetry(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agent := &redAgentConnection{closeFailures: 1}
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		newAgent: func() *redAgentConnection { return agent },
	}
	registry := mustRegistry(t, entry)
	lease := mustLease(t, registry, config)
	if _, err := lease.OpenVerifiedConnection(context.Background()); err != nil {
		t.Fatalf("OpenVerifiedConnection(): %v", err)
	}
	if err := lease.Close(context.Background()); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("first Close() error = %v, want %v", err, ErrCleanupIncomplete)
	}
	if agent.closed != 1 {
		t.Fatalf("first close calls = %d, want 1", agent.closed)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("retry Close(): %v", err)
	}
	if agent.closed != 2 {
		t.Fatalf("retry close calls = %d, want 2", agent.closed)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Registry.Close(): %v", err)
	}
}

func TestVerifiedConnectionFiltersIdentitiesAndRejectsUnauthorizedSigning(t *testing.T) {
	allowedKey := testED25519Key(0x11)
	blockedKey := testED25519Key(0x22)
	allowedIdentity, err := credentialprotocol.NewSSHAgentIdentity(allowedKey)
	if err != nil {
		t.Fatalf("NewSSHAgentIdentity(allowed): %v", err)
	}
	blockedIdentity, err := credentialprotocol.NewSSHAgentIdentity(blockedKey)
	if err != nil {
		t.Fatalf("NewSSHAgentIdentity(blocked): %v", err)
	}
	hostAnswer, err := credentialprotocol.EncodeSSHAgentIdentitiesAnswer([]credentialprotocol.SSHAgentIdentity{blockedIdentity, allowedIdentity})
	if err != nil {
		t.Fatalf("EncodeSSHAgentIdentitiesAnswer(): %v", err)
	}
	defer credentialprotocol.WipeSSHAgentBytes(hostAnswer)

	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agent := &redAgentConnection{response: hostAnswer}
	entry := &redEntry{
		identity: config,
		policy:   mustPolicyForKey(t, "policy-a", allowedKey),
		newAgent: func() *redAgentConnection { return agent },
	}
	connection := mustVerifiedConnection(t, entry)
	response, err := connection.RoundTrip(context.Background(), []byte{0, 0, 0, 1, byte(credentialprotocol.SSHAgentMessageRequestIdentities)})
	if err != nil {
		t.Fatalf("identities RoundTrip(): %v", err)
	}
	identities, err := credentialprotocol.DecodeSSHAgentIdentitiesAnswer(response)
	if err != nil {
		t.Fatalf("DecodeSSHAgentIdentitiesAnswer(): %v", err)
	}
	defer credentialprotocol.WipeSSHAgentIdentities(identities)
	if len(identities) != 1 || identities[0].KeyAlgorithm() != credentialprotocol.SSHAgentKeyAlgorithmED25519 {
		t.Fatalf("filtered identities = %#v, want one allowed ED25519 identity", identities)
	}

	unauthorized := testSignRequest(blockedKey, []byte("challenge"), 0)
	response, err = connection.RoundTrip(context.Background(), unauthorized)
	credentialprotocol.WipeSSHAgentBytes(unauthorized)
	if err != nil {
		t.Fatalf("unauthorized RoundTrip(): %v", err)
	}
	if string(response) != string(credentialprotocol.EncodeSSHAgentFailure()) {
		t.Fatalf("unauthorized response = %v, want canonical failure", response)
	}
	if agent.roundTrips != 1 {
		t.Fatalf("host agent round trips = %d, want identities only", agent.roundTrips)
	}
	if err := connection.Close(context.Background()); err != nil {
		t.Fatalf("connection.Close(): %v", err)
	}
}

func mustConfigIdentity(t *testing.T, entry, daemon, generation credentialprotocol.SafeID, revision uint64) ConfigIdentity {
	t.Helper()
	identity, err := NewConfigIdentity(entry, daemon, generation, revision)
	if err != nil {
		t.Fatalf("NewConfigIdentity(): %v", err)
	}
	return identity
}

func mustPolicy(t *testing.T, id credentialprotocol.SafeID, revision uint64) LivePolicy {
	t.Helper()
	identity, err := NewPolicyIdentity(id, revision)
	if err != nil {
		t.Fatalf("NewPolicyIdentity(): %v", err)
	}
	policy, err := NewLivePolicy(identity, []PolicyRule{{
		Fingerprint:  "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		KeyAlgorithm: credentialprotocol.SSHAgentKeyAlgorithmED25519,
		Flags:        []credentialprotocol.SSHAgentRSAFlags{0},
	}})
	if err != nil {
		t.Fatalf("NewLivePolicy(): %v", err)
	}
	return policy
}

func mustPolicyForKey(t *testing.T, id credentialprotocol.SafeID, key []byte) LivePolicy {
	t.Helper()
	digest := sha256.Sum256(key)
	identity, err := NewPolicyIdentity(id, 1)
	if err != nil {
		t.Fatalf("NewPolicyIdentity(): %v", err)
	}
	policy, err := NewLivePolicy(identity, []PolicyRule{{
		Fingerprint:  "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:]),
		KeyAlgorithm: credentialprotocol.SSHAgentKeyAlgorithmED25519,
		Flags:        []credentialprotocol.SSHAgentRSAFlags{0},
	}})
	if err != nil {
		t.Fatalf("NewLivePolicy(): %v", err)
	}
	return policy
}

func mustRegistry(t *testing.T, entry *redEntry) *Registry {
	t.Helper()
	registry, err := NewRegistry(RegistryOptions{DaemonGeneration: string(entry.identity.DaemonGeneration()), Entries: []LiveHostAgentEntry{entry}})
	if err != nil {
		t.Fatalf("NewRegistry(): %v", err)
	}
	return registry
}

func mustLease(t *testing.T, registry *Registry, config ConfigIdentity) Lease {
	t.Helper()
	request, err := NewAcquireRequest(config, "runtime-a", "process-a", "vsock-a", "job-a", "activation-a", "relay-a")
	if err != nil {
		t.Fatalf("NewAcquireRequest(): %v", err)
	}
	lease, err := registry.Acquire(context.Background(), request)
	if err != nil {
		t.Fatalf("Acquire(): %v", err)
	}
	return lease
}

func mustVerifiedConnection(t *testing.T, entry *redEntry) VerifiedAgentConnection {
	t.Helper()
	registry := mustRegistry(t, entry)
	lease := mustLease(t, registry, entry.identity)
	connection, err := lease.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("OpenVerifiedConnection(): %v", err)
	}
	t.Cleanup(func() {
		_ = connection.Close(context.Background())
		_ = lease.Close(context.Background())
		_ = registry.Close(context.Background())
	})
	return connection
}

func testED25519Key(fill byte) []byte {
	algorithm := []byte(credentialprotocol.SSHAgentKeyAlgorithmED25519)
	key := make([]byte, 0, 4+len(algorithm)+4+32)
	key = appendSSHString(key, algorithm)
	key = appendSSHString(key, bytesOf(32, fill))
	return key
}

func testSignRequest(key, challenge []byte, flags credentialprotocol.SSHAgentRSAFlags) []byte {
	payload := []byte{byte(credentialprotocol.SSHAgentMessageSignRequest)}
	payload = appendSSHString(payload, key)
	payload = appendSSHString(payload, challenge)
	var scalar [4]byte
	binary.BigEndian.PutUint32(scalar[:], uint32(flags))
	payload = append(payload, scalar[:]...)
	frame := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	frame = append(frame, payload...)
	credentialprotocol.WipeSSHAgentBytes(payload)
	return frame
}

func appendSSHString(target, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	target = append(target, length[:]...)
	return append(target, value...)
}

func bytesOf(length int, value byte) []byte {
	buffer := make([]byte, length)
	for index := range buffer {
		buffer[index] = value
	}
	return buffer
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}
