package sshrelay

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type redAgentConnection struct{ closed int }

func (*redAgentConnection) RoundTrip(context.Context, []byte) ([]byte, error) { return nil, nil }
func (connection *redAgentConnection) Close(context.Context) error {
	connection.closed++
	return nil
}

type redEntry struct {
	identity ConfigIdentity
	policy   LivePolicy
	opens    int
}

func (entry *redEntry) Identity() ConfigIdentity { return entry.identity }
func (entry *redEntry) Policy() LivePolicy       { return entry.policy }
func (entry *redEntry) Open(context.Context) (AgentConnection, error) {
	entry.opens++
	return &redAgentConnection{}, nil
}
func (entry *redEntry) VerifyPeer(_ context.Context, connection AgentConnection) (PeerProof, error) {
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
