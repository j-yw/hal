package sshrelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestVerifiedConnectionOperationIdleAndHardLimits(t *testing.T) {
	start := time.Now()
	clock := &fakeClock{now: start}
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{identity: config, policy: mustPolicy(t, "policy-a", 1)}
	registry, err := newRegistry(RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{entry}}, clock)
	if err != nil {
		t.Fatalf("newRegistry(): %v", err)
	}
	lease := mustLease(t, registry, config)
	connection, err := lease.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("OpenVerifiedConnection(): %v", err)
	}
	malformed := []byte{0, 0, 0, 1, 0xff}
	for attempt := 0; attempt < credentialprotocol.SSHAgentRelayMaxAttemptedOperations; attempt++ {
		response, roundTripErr := connection.RoundTrip(context.Background(), malformed)
		if roundTripErr != nil || string(response) != string(credentialprotocol.EncodeSSHAgentFailure()) {
			t.Fatalf("RoundTrip(%d) = (%v, %v)", attempt, response, roundTripErr)
		}
	}
	if _, err := connection.RoundTrip(context.Background(), malformed); !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("operation plus one error = %v, want %v", err, ErrRequestRejected)
	}
	if err := connection.Close(context.Background()); err != nil {
		t.Fatalf("connection.Close(): %v", err)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("lease.Close(): %v", err)
	}

	idleLease := mustLease(t, registry, config)
	idleConnection, err := idleLease.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("idle OpenVerifiedConnection(): %v", err)
	}
	clock.now = start.Add(credentialprotocol.SSHAgentRelayIdleTimeout)
	if _, err := idleConnection.RoundTrip(context.Background(), malformed); !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("idle boundary error = %v, want %v", err, ErrRequestRejected)
	}
	_ = idleConnection.Close(context.Background())
	_ = idleLease.Close(context.Background())

	hardLease := mustLease(t, registry, config)
	clock.now = clock.now.Add(credentialprotocol.SSHAgentRelayHardLifetime)
	if _, err := hardLease.OpenVerifiedConnection(context.Background()); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("hard boundary open error = %v, want %v", err, ErrLeaseExpired)
	}
	_ = hardLease.Close(context.Background())
	_ = registry.Close(context.Background())
}

func TestVerifiedConnectionAdmitsAuthorizedCanonicalSignature(t *testing.T) {
	key := testED25519Key(0x33)
	signature, err := credentialprotocol.NewSSHAgentSignature(credentialprotocol.SSHAgentSignatureAlgorithmED25519, bytesOf(64, 0x44))
	if err != nil {
		t.Fatalf("NewSSHAgentSignature(): %v", err)
	}
	hostResponse, err := credentialprotocol.EncodeSSHAgentSignResponse(signature)
	if err != nil {
		t.Fatalf("EncodeSSHAgentSignResponse(): %v", err)
	}
	defer credentialprotocol.WipeSSHAgentBytes(hostResponse)
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agent := &redAgentConnection{response: hostResponse}
	entry := &redEntry{
		identity: config,
		policy:   mustPolicyForKey(t, "policy-a", key),
		newAgent: func() *redAgentConnection { return agent },
	}
	connection := mustVerifiedConnection(t, entry)
	request := testSignRequest(key, []byte("challenge"), 0)
	response, err := connection.RoundTrip(context.Background(), request)
	credentialprotocol.WipeSSHAgentBytes(request)
	if err != nil {
		t.Fatalf("RoundTrip(): %v", err)
	}
	decoded, err := credentialprotocol.DecodeSSHAgentSignResponse(response)
	credentialprotocol.WipeSSHAgentBytes(response)
	if err != nil {
		t.Fatalf("DecodeSSHAgentSignResponse(): %v", err)
	}
	defer decoded.Wipe()
	if decoded.Algorithm() != credentialprotocol.SSHAgentSignatureAlgorithmED25519 || agent.roundTrips != 1 {
		t.Fatalf("signature algorithm/roundtrips = %s/%d", decoded.Algorithm(), agent.roundTrips)
	}
}

type fakeDialer struct {
	connection AgentConnection
	endpoint   string
}

func (dialer *fakeDialer) Open(context.Context) (AgentConnection, error) {
	return dialer.connection, nil
}

type fakeVerifier struct{}

func (*fakeVerifier) Verify(_ context.Context, connection AgentConnection, identity ConfigIdentity) (PeerProof, error) {
	return NewPeerProof(identity, connection)
}

func TestProductionEntryUsesOnlyInjectedDialAndPeerAuthorities(t *testing.T) {
	identity := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agent := &redAgentConnection{}
	entry, err := NewLiveHostAgentEntry(LiveHostAgentOptions{
		Identity: identity,
		Policy:   mustPolicy(t, "policy-a", 1),
		Dialer:   &fakeDialer{connection: agent},
		Verifier: &fakeVerifier{},
	})
	if err != nil {
		t.Fatalf("NewLiveHostAgentEntry(): %v", err)
	}
	opened, err := entry.Open(context.Background())
	if err != nil || opened != agent {
		t.Fatalf("entry.Open() = (%v, %v)", opened, err)
	}
	proof, err := entry.VerifyPeer(context.Background(), opened)
	if err != nil || consumePeerProof(proof, identity, opened) != nil {
		t.Fatalf("entry.VerifyPeer() = (%v, %v)", proof, err)
	}
}

func TestRegistryConcurrentAcquireAndClose(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{identity: config, policy: mustPolicy(t, "policy-a", 1)}
	registry := mustRegistry(t, entry)
	request, err := NewAcquireRequest(config, "runtime-a", "process-a", "vsock-a", "job-a", "activation-a", "relay-a")
	if err != nil {
		t.Fatalf("NewAcquireRequest(): %v", err)
	}
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			lease, acquireErr := registry.Acquire(context.Background(), request)
			if acquireErr == nil {
				_ = lease.Close(context.Background())
			}
		}()
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Registry.Close(): %v", err)
	}
	wait.Wait()
	if _, err := registry.Acquire(context.Background(), request); !errors.Is(err, ErrRegistryClosed) {
		t.Fatalf("Acquire(after close) error = %v, want %v", err, ErrRegistryClosed)
	}
}

func TestLiveValuesAndErrorsRedactHostConfiguration(t *testing.T) {
	seeds := []string{
		"/run/user/1000/agent.sock",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"public-key-blob-canary",
		"signature-canary",
		"challenge-canary",
		"raw-error-canary",
	}
	rule := PolicyRule{
		Fingerprint:  seeds[1],
		KeyAlgorithm: credentialprotocol.SSHAgentKeyAlgorithmED25519,
		Flags:        []credentialprotocol.SSHAgentRSAFlags{0},
	}
	values := []any{
		rule,
		RegistryOptions{DaemonGeneration: "daemon-a"},
		LiveHostAgentOptions{Dialer: &fakeDialer{connection: &redAgentConnection{response: []byte(seeds[2])}, endpoint: seeds[0]}},
		PeerProof{},
		&Registry{},
		&lease{},
		&verifiedConnection{},
		fmt.Errorf("%w", ErrAgentIO),
	}
	for _, value := range values {
		rendered := fmt.Sprintf("%v %#v %+v", value, value, value)
		for _, seed := range seeds {
			if strings.Contains(rendered, seed) {
				t.Fatalf("format exposed %q in %q", seed, rendered)
			}
		}
		encoded, _ := json.Marshal(value)
		for _, seed := range seeds {
			if strings.Contains(string(encoded), seed) {
				t.Fatalf("JSON exposed %q in %q", seed, encoded)
			}
		}
	}
}
