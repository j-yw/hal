package sshrelay

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestPermitIdleRejectionTerminalizesAndPreservesLiveCardinality(t *testing.T) {
	start := time.Now()
	clock := &fakeClock{now: start}
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agents := make([]*redAgentConnection, 0, credentialprotocol.SSHAgentRelayMaxConcurrentConnections)
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		newAgent: func() *redAgentConnection {
			agent := &redAgentConnection{closeFailures: 1}
			agents = append(agents, agent)
			return agent
		},
	}
	registry, err := newRegistry(RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{entry}}, clock)
	if err != nil {
		t.Fatalf("newRegistry(): %v", err)
	}
	leaseValue := mustLease(t, registry, config)
	concrete := leaseValue.(*lease)
	connections := make([]VerifiedAgentConnection, 0, credentialprotocol.SSHAgentRelayMaxConcurrentConnections)
	for index := 0; index < credentialprotocol.SSHAgentRelayMaxConcurrentConnections; index++ {
		connection, err := leaseValue.OpenVerifiedConnection(context.Background())
		if err != nil {
			t.Fatalf("OpenVerifiedConnection(%d): %v", index, err)
		}
		connections = append(connections, connection)
	}
	clock.mu.Lock()
	clock.now = start.Add(credentialprotocol.SSHAgentRelayIdleTimeout)
	clock.mu.Unlock()
	for index, connection := range connections {
		response, err := connection.RoundTrip(context.Background(), malformedRequest())
		if response != nil || !errors.Is(err, ErrRequestRejected) || !errors.Is(err, ErrCleanupIncomplete) {
			t.Errorf("RoundTrip(idle %d) = (%v, %v), want request+cleanup failure", index, response, err)
		}
	}
	if snapshot := concrete.state.Snapshot(); snapshot.ActiveConnections != 0 {
		t.Fatalf("D2 active connections after idle rejection = %d, want 0", snapshot.ActiveConnections)
	}
	if connection, err := leaseValue.OpenVerifiedConnection(context.Background()); connection != nil || !errors.Is(err, ErrConnectionLimit) {
		if connection != nil {
			_ = connection.Close(context.Background())
		}
		t.Errorf("fifth live OpenVerifiedConnection() = (%v, %v), want connection limit", connection, err)
	}
	if len(agents) != credentialprotocol.SSHAgentRelayMaxConcurrentConnections {
		t.Errorf("live agent opens = %d, want %d", len(agents), credentialprotocol.SSHAgentRelayMaxConcurrentConnections)
	}
	if err := leaseValue.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close() cleanup retry: %v", err)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Registry.Close(): %v", err)
	}
}

func TestPermitHardLifetimeRejectionTerminalizesConnection(t *testing.T) {
	start := time.Now()
	clock := &fakeClock{now: start}
	agent := &redAgentConnection{closeFailures: 1}
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{identity: config, policy: mustPolicy(t, "policy-a", 1), newAgent: func() *redAgentConnection { return agent }}
	registry, err := newRegistry(RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{entry}}, clock)
	if err != nil {
		t.Fatalf("newRegistry(): %v", err)
	}
	leaseValue := mustLease(t, registry, config)
	connection, err := leaseValue.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("OpenVerifiedConnection(): %v", err)
	}
	clock.mu.Lock()
	clock.now = start.Add(credentialprotocol.SSHAgentRelayHardLifetime)
	clock.mu.Unlock()
	response, err := connection.RoundTrip(context.Background(), malformedRequest())
	if response != nil || !errors.Is(err, ErrRequestRejected) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("RoundTrip(hard lifetime) = (%v, %v), want request+cleanup failure", response, err)
	}
	if response, err := connection.RoundTrip(context.Background(), malformedRequest()); response != nil || !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("RoundTrip(after hard lifetime) = (%v, %v), want closed", response, err)
	}
	if err := leaseValue.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close() cleanup retry: %v", err)
	}
	_ = registry.Close(context.Background())
}

func TestCompleteRequestRejectionTerminalizesConnection(t *testing.T) {
	start := time.Now()
	clock := &fakeClock{now: start}
	hostResponse, err := credentialprotocol.EncodeSSHAgentIdentitiesAnswer(nil)
	if err != nil {
		t.Fatalf("EncodeSSHAgentIdentitiesAnswer(): %v", err)
	}
	defer credentialprotocol.WipeSSHAgentBytes(hostResponse)
	agent := &redAgentConnection{
		closeFailures: 1,
		roundTripFunc: func(context.Context, []byte) ([]byte, error) {
			clock.mu.Lock()
			clock.now = start.Add(credentialprotocol.SSHAgentRelayIdleTimeout)
			clock.mu.Unlock()
			return append([]byte(nil), hostResponse...), nil
		},
	}
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{identity: config, policy: mustPolicy(t, "policy-a", 1), newAgent: func() *redAgentConnection { return agent }}
	registry, err := newRegistry(RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{entry}}, clock)
	if err != nil {
		t.Fatalf("newRegistry(): %v", err)
	}
	leaseValue := mustLease(t, registry, config)
	connection, err := leaseValue.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("OpenVerifiedConnection(): %v", err)
	}
	response, err := connection.RoundTrip(context.Background(), identitiesRequest())
	if response != nil || !errors.Is(err, ErrRequestRejected) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("RoundTrip(completion idle) = (%v, %v), want request+cleanup failure", response, err)
	}
	if response, err := connection.RoundTrip(context.Background(), identitiesRequest()); response != nil || !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("RoundTrip(after completion rejection) = (%v, %v), want closed", response, err)
	}
	if err := leaseValue.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close() cleanup retry: %v", err)
	}
	_ = registry.Close(context.Background())
}

func TestOperationLimitRejectionTerminalizesConnection(t *testing.T) {
	agent := &redAgentConnection{closeFailures: 1}
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{identity: config, policy: mustPolicy(t, "policy-a", 1), newAgent: func() *redAgentConnection { return agent }}
	registry := mustRegistry(t, entry)
	leaseValue := mustLease(t, registry, config)
	connection, err := leaseValue.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("OpenVerifiedConnection(): %v", err)
	}
	for attempt := 0; attempt < credentialprotocol.SSHAgentRelayMaxAttemptedOperations; attempt++ {
		response, err := connection.RoundTrip(context.Background(), malformedRequest())
		if err != nil || string(response) != string(credentialprotocol.EncodeSSHAgentFailure()) {
			t.Fatalf("RoundTrip(%d) = (%v, %v)", attempt, response, err)
		}
	}
	response, err := connection.RoundTrip(context.Background(), malformedRequest())
	if response != nil || !errors.Is(err, ErrRequestRejected) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("RoundTrip(operation limit) = (%v, %v), want request+cleanup failure", response, err)
	}
	if response, err := connection.RoundTrip(context.Background(), malformedRequest()); response != nil || !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("RoundTrip(after operation limit) = (%v, %v), want closed", response, err)
	}
	if err := leaseValue.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close() cleanup retry: %v", err)
	}
	_ = registry.Close(context.Background())
}

func TestTerminalLatchPrecedesOperationUnlock(t *testing.T) {
	source, err := os.ReadFile("relay.go")
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	text := string(source)
	deferStart := strings.Index(text, "defer func() {")
	if deferStart < 0 {
		t.Fatal("RoundTrip terminal defer not found")
	}
	deferEnd := strings.Index(text[deferStart:], "\n\t}()")
	if deferEnd < 0 {
		t.Fatal("RoundTrip terminal defer not found")
	}
	deferred := text[deferStart : deferStart+deferEnd]
	latch := strings.Index(deferred, "latchTerminal")
	unlock := strings.Index(deferred, "operationMu.Unlock()")
	if latch < 0 || unlock < 0 || latch > unlock {
		t.Fatalf("terminal latch/unlock order = %d/%d, want latch first", latch, unlock)
	}
}

func TestAgentPartialIOErrorTerminalizesConnectionAndLeaseRetriesCleanup(t *testing.T) {
	partial := []byte{0, 0, 0, 5, byte(credentialprotocol.SSHAgentMessageIdentitiesAnswer), 1, 2, 3, 4}
	agent := &redAgentConnection{
		closeFailures: 1,
		roundTripFunc: func(context.Context, []byte) ([]byte, error) {
			return partial, errors.New("raw partial I/O canary")
		},
	}
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		newAgent: func() *redAgentConnection { return agent },
	}
	registry := mustRegistry(t, entry)
	lease := mustLease(t, registry, config)
	connection, err := lease.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("OpenVerifiedConnection(): %v", err)
	}
	request := identitiesRequest()
	response, err := connection.RoundTrip(context.Background(), request)
	if response != nil || !errors.Is(err, ErrAgentIO) || !errors.Is(err, ErrCleanupIncomplete) || strings.Contains(err.Error(), "raw") {
		t.Fatalf("RoundTrip(partial error) = (%v, %v), want sanitized agent+cleanup failure", response, err)
	}
	if !allZero(partial) {
		t.Fatalf("partial agent response was not wiped: %v", partial)
	}
	if response, err := connection.RoundTrip(context.Background(), request); response != nil || !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("RoundTrip(after terminal error) = (%v, %v), want closed", response, err)
	}
	if agent.roundTrips != 1 || agent.closed != 1 {
		t.Fatalf("terminal calls = roundtrip:%d close:%d, want 1/1", agent.roundTrips, agent.closed)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close() cleanup retry: %v", err)
	}
	if agent.closed != 2 {
		t.Fatalf("lease cleanup close calls = %d, want 2", agent.closed)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Registry.Close(): %v", err)
	}
}

func TestAgentPanicTerminalizesConnectionAndRegistryRetriesCleanup(t *testing.T) {
	agent := &redAgentConnection{
		closeFailures: 1,
		roundTripFunc: func(context.Context, []byte) ([]byte, error) {
			panic("raw agent panic canary")
		},
	}
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		newAgent: func() *redAgentConnection { return agent },
	}
	registry := mustRegistry(t, entry)
	lease := mustLease(t, registry, config)
	connection, err := lease.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("OpenVerifiedConnection(): %v", err)
	}
	response, err := connection.RoundTrip(context.Background(), identitiesRequest())
	if response != nil || !errors.Is(err, ErrAgentIO) || !errors.Is(err, ErrCleanupIncomplete) || strings.Contains(err.Error(), "raw") {
		t.Fatalf("RoundTrip(panic) = (%v, %v), want sanitized agent+cleanup failure", response, err)
	}
	if response, err := connection.RoundTrip(context.Background(), identitiesRequest()); response != nil || !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("RoundTrip(after panic) = (%v, %v), want closed", response, err)
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatalf("Registry.Close() cleanup retry: %v", err)
	}
	if agent.roundTrips != 1 || agent.closed != 2 {
		t.Fatalf("panic terminal calls = roundtrip:%d close:%d, want 1/2", agent.roundTrips, agent.closed)
	}
}

func TestOpenErrorRetainsActiveRelaySlotsUntilAgentCleanup(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agents := make([]*redAgentConnection, 0, credentialprotocol.SSHAgentRelayMaxConcurrentConnections)
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
	}
	entry.openFunc = func(context.Context) (AgentConnection, error) {
		if len(agents) < credentialprotocol.SSHAgentRelayMaxConcurrentConnections {
			agent := &redAgentConnection{closeFailures: 1}
			agents = append(agents, agent)
			return agent, errors.New("raw open canary")
		}
		return &redAgentConnection{}, nil
	}
	registry := mustRegistry(t, entry)
	leaseValue := mustLease(t, registry, config)
	concrete := leaseValue.(*lease)
	t.Cleanup(func() {
		_ = leaseValue.Close(context.Background())
		_ = registry.Close(context.Background())
	})
	for attempt := 0; attempt < credentialprotocol.SSHAgentRelayMaxConcurrentConnections; attempt++ {
		connection, err := leaseValue.OpenVerifiedConnection(context.Background())
		if connection != nil || !errors.Is(err, ErrAgentOpen) || !errors.Is(err, ErrCleanupIncomplete) || strings.Contains(err.Error(), "raw") {
			t.Fatalf("OpenVerifiedConnection(%d) = (%v, %v), want sanitized open+cleanup failure", attempt, connection, err)
		}
	}
	if snapshot := concrete.state.Snapshot(); snapshot.ActiveConnections != credentialprotocol.SSHAgentRelayMaxConcurrentConnections {
		t.Fatalf("failed-open active slots = %d, want %d", snapshot.ActiveConnections, credentialprotocol.SSHAgentRelayMaxConcurrentConnections)
	}
	if connection, err := leaseValue.OpenVerifiedConnection(context.Background()); connection != nil || !errors.Is(err, ErrConnectionLimit) {
		if connection != nil {
			_ = connection.Close(context.Background())
		}
		t.Fatalf("fifth OpenVerifiedConnection() = (%v, %v), want connection limit", connection, err)
	}
	if entry.opens != credentialprotocol.SSHAgentRelayMaxConcurrentConnections {
		t.Fatalf("agent opens after fifth attempt = %d, want %d", entry.opens, credentialprotocol.SSHAgentRelayMaxConcurrentConnections)
	}
	concrete.mu.Lock()
	retained := make([]*verifiedConnection, 0, len(concrete.connections))
	for connection := range concrete.connections {
		retained = append(retained, connection)
	}
	concrete.mu.Unlock()
	for _, connection := range retained {
		if err := connection.Close(context.Background()); err != nil {
			t.Fatalf("retained connection Close(): %v", err)
		}
	}
	if snapshot := concrete.state.Snapshot(); snapshot.ActiveConnections != 0 {
		t.Fatalf("active slots after cleanup retry = %d, want 0", snapshot.ActiveConnections)
	}
	connection, err := leaseValue.OpenVerifiedConnection(context.Background())
	if err != nil || connection == nil {
		t.Fatalf("OpenVerifiedConnection(after cleanup) = (%v, %v)", connection, err)
	}
	if err := connection.Close(context.Background()); err != nil {
		t.Fatalf("successful connection Close(): %v", err)
	}
}

type stagedCloseAgent struct {
	mu           sync.Mutex
	closeCalls   int
	closeStarted chan struct{}
	releaseClose chan struct{}
}

func (*stagedCloseAgent) RoundTrip(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("unused")
}

func (agent *stagedCloseAgent) Close(context.Context) error {
	agent.mu.Lock()
	agent.closeCalls++
	call := agent.closeCalls
	agent.mu.Unlock()
	if call == 1 {
		close(agent.closeStarted)
		<-agent.releaseClose
		return errors.New("raw staged close canary")
	}
	return nil
}

func TestOpenErrorConcurrentLeaseCloseRetriesOwnedAgent(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agent := &stagedCloseAgent{closeStarted: make(chan struct{}), releaseClose: make(chan struct{})}
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		openFunc: func(context.Context) (AgentConnection, error) {
			return agent, errors.New("raw open canary")
		},
	}
	leaseValue := mustLease(t, mustRegistry(t, entry), config)
	concrete := leaseValue.(*lease)
	openResult := make(chan error, 1)
	go func() {
		_, err := leaseValue.OpenVerifiedConnection(context.Background())
		openResult <- err
	}()
	<-agent.closeStarted
	closeResult := make(chan error, 1)
	go func() { closeResult <- leaseValue.Close(context.Background()) }()
	waitForLeaseClosed(t, concrete)
	close(agent.releaseClose)
	if err := <-openResult; !errors.Is(err, ErrAgentOpen) || !errors.Is(err, ErrCleanupIncomplete) || strings.Contains(err.Error(), "raw") {
		t.Fatalf("racing open error = %v, want sanitized open+cleanup failure", err)
	}
	if err := <-closeResult; err != nil {
		t.Fatalf("racing Lease.Close(): %v", err)
	}
	agent.mu.Lock()
	closeCalls := agent.closeCalls
	agent.mu.Unlock()
	if closeCalls != 2 {
		t.Fatalf("racing close calls = %d, want 2", closeCalls)
	}
}

func identitiesRequest() []byte {
	return []byte{0, 0, 0, 1, byte(credentialprotocol.SSHAgentMessageRequestIdentities)}
}

func malformedRequest() []byte {
	return []byte{0, 0, 0, 1, 0xff}
}

func allZero(value []byte) bool {
	for _, candidate := range value {
		if candidate != 0 {
			return false
		}
	}
	return true
}
