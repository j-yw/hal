package sshrelay

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type reservationEntry struct {
	identity ConfigIdentity
	policy   LivePolicy
	retained *redAgentConnection
	started  chan struct{}
	release  chan struct{}

	mu    sync.Mutex
	opens int
}

func (entry *reservationEntry) Identity() ConfigIdentity { return entry.identity }
func (entry *reservationEntry) Policy() LivePolicy       { return entry.policy }

func (entry *reservationEntry) Open(ctx context.Context) (AgentConnection, error) {
	entry.mu.Lock()
	entry.opens++
	open := entry.opens
	entry.mu.Unlock()
	if open == 1 {
		return entry.retained, nil
	}
	select {
	case entry.started <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-entry.release:
		return &redAgentConnection{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (entry *reservationEntry) VerifyPeer(_ context.Context, connection AgentConnection) (PeerProof, error) {
	return NewPeerProof(entry.identity, connection)
}

func (entry *reservationEntry) openCount() int {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.opens
}

func TestConcurrentOpenReservationsIncludeCleanupRetainedConnections(t *testing.T) {
	start := time.Now()
	clock := &fakeClock{now: start}
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &reservationEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		retained: &redAgentConnection{closeFailures: 1},
		started:  make(chan struct{}, credentialprotocol.SSHAgentRelayMaxConcurrentConnections),
		release:  make(chan struct{}),
	}
	registry, err := newRegistry(RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{entry}}, clock)
	if err != nil {
		t.Fatalf("newRegistry(): %v", err)
	}
	leaseValue := mustLease(t, registry, config)
	t.Cleanup(func() {
		_ = leaseValue.Close(context.Background())
		_ = registry.Close(context.Background())
	})
	connection, err := leaseValue.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("initial OpenVerifiedConnection(): %v", err)
	}
	clock.mu.Lock()
	clock.now = start.Add(credentialprotocol.SSHAgentRelayIdleTimeout)
	clock.mu.Unlock()
	if response, err := connection.RoundTrip(context.Background(), malformedRequest()); response != nil ||
		!errors.Is(err, ErrRequestRejected) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("RoundTrip(idle) = (%v, %v), want request+cleanup failure", response, err)
	}

	type openResult struct {
		connection VerifiedAgentConnection
		err        error
	}
	results := make(chan openResult, credentialprotocol.SSHAgentRelayMaxConcurrentConnections)
	for attempt := 0; attempt < credentialprotocol.SSHAgentRelayMaxConcurrentConnections; attempt++ {
		go func() {
			opened, openErr := leaseValue.OpenVerifiedConnection(context.Background())
			results <- openResult{connection: opened, err: openErr}
		}()
	}
	for attempt := 0; attempt < credentialprotocol.SSHAgentRelayMaxConcurrentConnections-1; attempt++ {
		select {
		case <-entry.started:
		case <-time.After(time.Second):
			t.Fatal("three admitted open reservations did not reach the agent entry")
		}
	}

	var early *openResult
	var overbooked bool
	select {
	case <-entry.started:
		overbooked = true
	case result := <-results:
		early = &result
	case <-time.After(time.Second):
		t.Fatal("fourth concurrent open neither rejected nor entered the agent entry")
	}
	close(entry.release)
	collected := make([]openResult, 0, credentialprotocol.SSHAgentRelayMaxConcurrentConnections)
	if early != nil {
		collected = append(collected, *early)
	}
	for len(collected) < credentialprotocol.SSHAgentRelayMaxConcurrentConnections {
		collected = append(collected, <-results)
	}
	if overbooked {
		t.Fatalf("fourth concurrent reservation reached the agent entry; opens=%d, want retained+inflight capped at %d", entry.openCount(), credentialprotocol.SSHAgentRelayMaxConcurrentConnections)
	}
	var opened, limited int
	for _, result := range collected {
		switch {
		case result.err == nil && result.connection != nil:
			opened++
		case result.connection == nil && errors.Is(result.err, ErrConnectionLimit):
			limited++
		default:
			t.Errorf("concurrent OpenVerifiedConnection() = (%v, %v)", result.connection, result.err)
		}
	}
	if opened != credentialprotocol.SSHAgentRelayMaxConcurrentConnections-1 || limited != 1 {
		t.Errorf("concurrent results = opened:%d limited:%d, want %d/1", opened, limited, credentialprotocol.SSHAgentRelayMaxConcurrentConnections-1)
	}
	if entry.openCount() != credentialprotocol.SSHAgentRelayMaxConcurrentConnections {
		t.Errorf("total agent opens = %d, want retained plus three new", entry.openCount())
	}
	if err := leaseValue.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close(): %v", err)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Registry.Close(): %v", err)
	}
}

type cleanupErrorDialer struct {
	mu          sync.Mutex
	connections []AgentConnection
}

func (dialer *cleanupErrorDialer) Open(context.Context) (AgentConnection, error) {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if len(dialer.connections) == 0 {
		return nil, errors.Join(ErrCleanupIncomplete, errors.New("raw dialer cleanup canary"))
	}
	connection := dialer.connections[0]
	dialer.connections = dialer.connections[1:]
	return connection, errors.Join(ErrCleanupIncomplete, errors.New("raw dialer cleanup canary"))
}

func TestProductionEntryPreservesSanitizedDialerCleanupFailure(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	directAgent := &redAgentConnection{}
	leaseAgent := &redAgentConnection{}
	entry, err := NewLiveHostAgentEntry(LiveHostAgentOptions{
		Identity: config,
		Policy:   mustPolicy(t, "policy-a", 1),
		Dialer:   &cleanupErrorDialer{connections: []AgentConnection{directAgent, leaseAgent}},
		Verifier: &fakeVerifier{},
	})
	if err != nil {
		t.Fatalf("NewLiveHostAgentEntry(): %v", err)
	}
	opened, err := entry.Open(context.Background())
	if opened != directAgent || !errors.Is(err, ErrAgentOpen) || !errors.Is(err, ErrCleanupIncomplete) || strings.Contains(err.Error(), "raw") {
		t.Fatalf("entry.Open() = (%v, %v), want live value plus sanitized open+cleanup failure", opened, err)
	}
	if err := opened.Close(context.Background()); err != nil {
		t.Fatalf("direct returned connection Close(): %v", err)
	}

	registry, err := NewRegistry(RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{entry}})
	if err != nil {
		t.Fatalf("NewRegistry(): %v", err)
	}
	leaseValue := mustLease(t, registry, config)
	connection, err := leaseValue.OpenVerifiedConnection(context.Background())
	if connection != nil || !errors.Is(err, ErrAgentOpen) || !errors.Is(err, ErrCleanupIncomplete) || strings.Contains(err.Error(), "raw") {
		t.Fatalf("OpenVerifiedConnection() = (%v, %v), want sanitized open+cleanup failure", connection, err)
	}
	if leaseAgent.closed != 1 {
		t.Fatalf("lease-owned agent close calls = %d, want 1", leaseAgent.closed)
	}
	if err := leaseValue.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close(): %v", err)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Registry.Close(): %v", err)
	}
}
