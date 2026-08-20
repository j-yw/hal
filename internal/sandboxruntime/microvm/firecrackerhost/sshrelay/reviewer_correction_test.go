package sshrelay

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestOpenVerificationCleanupFailureIsPropagatedAndRetried(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agent := &redAgentConnection{closeFailures: 1}
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		newAgent: func() *redAgentConnection { return agent },
		verify: func(AgentConnection) (PeerProof, error) {
			return PeerProof{}, errors.New("raw verify canary")
		},
	}
	registry := mustRegistry(t, entry)
	lease := mustLease(t, registry, config)
	if connection, err := lease.OpenVerifiedConnection(context.Background()); connection != nil ||
		!errors.Is(err, ErrAgentPeer) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("OpenVerifiedConnection() = (%v, %v), want peer+cleanup failure", connection, err)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close() retry: %v", err)
	}
	if agent.closed != 2 {
		t.Fatalf("agent close calls = %d, want retained retry count 2", agent.closed)
	}
}

func TestOpenCloseRaceRetainsAndPropagatesFailedCleanup(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agent := &redAgentConnection{closeFailures: 1}
	openStarted := make(chan struct{})
	releaseOpen := make(chan struct{})
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		openFunc: func(context.Context) (AgentConnection, error) {
			close(openStarted)
			<-releaseOpen
			return agent, nil
		},
	}
	registry := mustRegistry(t, entry)
	leaseValue := mustLease(t, registry, config)
	concrete := leaseValue.(*lease)
	openResult := make(chan error, 1)
	go func() {
		_, err := leaseValue.OpenVerifiedConnection(context.Background())
		openResult <- err
	}()
	<-openStarted
	closeResult := make(chan error, 1)
	go func() { closeResult <- leaseValue.Close(context.Background()) }()
	waitForLeaseClosed(t, concrete)
	close(releaseOpen)
	openErr := <-openResult
	closeErr := <-closeResult
	if !errors.Is(openErr, ErrLeaseClosed) || !errors.Is(openErr, ErrCleanupIncomplete) {
		t.Fatalf("racing open error = %v, want lease+cleanup failure", openErr)
	}
	if closeErr != nil {
		t.Fatalf("racing Close() retry error: %v", closeErr)
	}
	if agent.closed != 2 {
		t.Fatalf("racing agent close calls = %d, want 2", agent.closed)
	}
}

func TestOpenChecksCancellationAfterDependencyAndCleansConnection(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agent := &redAgentConnection{}
	ctx, cancel := context.WithCancel(context.Background())
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		openFunc: func(context.Context) (AgentConnection, error) {
			cancel()
			return agent, nil
		},
	}
	lease := mustLease(t, mustRegistry(t, entry), config)
	if connection, err := lease.OpenVerifiedConnection(ctx); connection != nil || !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("OpenVerifiedConnection(cancelled after open) = (%v, %v)", connection, err)
	}
	if agent.closed != 1 {
		t.Fatalf("cancelled open close calls = %d, want 1", agent.closed)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close(): %v", err)
	}
}

func TestVerifiedRoundTripDerivesIdleDeadlineAndCancelsOperationContext(t *testing.T) {
	start := time.Now().Add(time.Minute)
	clock := &fakeClock{now: start}
	response, err := credentialprotocol.EncodeSSHAgentIdentitiesAnswer(nil)
	if err != nil {
		t.Fatalf("EncodeSSHAgentIdentitiesAnswer(): %v", err)
	}
	defer credentialprotocol.WipeSSHAgentBytes(response)
	var operationCtx context.Context
	agent := &redAgentConnection{roundTripFunc: func(ctx context.Context, _ []byte) ([]byte, error) {
		operationCtx = ctx
		return append([]byte(nil), response...), nil
	}}
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{identity: config, policy: mustPolicy(t, "policy-a", 1), newAgent: func() *redAgentConnection { return agent }}
	registry, err := newRegistry(RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{entry}}, clock)
	if err != nil {
		t.Fatalf("newRegistry(): %v", err)
	}
	connection, err := mustLease(t, registry, config).OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("OpenVerifiedConnection(): %v", err)
	}
	request := []byte{0, 0, 0, 1, byte(credentialprotocol.SSHAgentMessageRequestIdentities)}
	if _, err := connection.RoundTrip(context.Background(), request); err != nil {
		t.Fatalf("RoundTrip(): %v", err)
	}
	deadline, ok := operationCtx.Deadline()
	if !ok || !deadline.Equal(start.Add(credentialprotocol.SSHAgentRelayIdleTimeout)) {
		t.Fatalf("operation deadline = (%v, %v), want idle horizon %v", deadline, ok, start.Add(credentialprotocol.SSHAgentRelayIdleTimeout))
	}
	select {
	case <-operationCtx.Done():
	default:
		t.Fatal("operation context was not cancelled and joined before return")
	}
	_ = connection.Close(context.Background())
	_ = registry.Close(context.Background())
}

func TestVerifiedRoundTripChecksPostIOCancellationAndCleansConnection(t *testing.T) {
	response, err := credentialprotocol.EncodeSSHAgentIdentitiesAnswer(nil)
	if err != nil {
		t.Fatalf("EncodeSSHAgentIdentitiesAnswer(): %v", err)
	}
	defer credentialprotocol.WipeSSHAgentBytes(response)
	ctx, cancel := context.WithCancel(context.Background())
	agent := &redAgentConnection{roundTripFunc: func(context.Context, []byte) ([]byte, error) {
		cancel()
		return append([]byte(nil), response...), nil
	}}
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{identity: config, policy: mustPolicy(t, "policy-a", 1), newAgent: func() *redAgentConnection { return agent }}
	connection := mustVerifiedConnection(t, entry)
	request := []byte{0, 0, 0, 1, byte(credentialprotocol.SSHAgentMessageRequestIdentities)}
	if response, err := connection.RoundTrip(ctx, request); response != nil || !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("RoundTrip(cancelled after I/O) = (%v, %v)", response, err)
	}
	if agent.closed != 1 {
		t.Fatalf("cancelled I/O close calls = %d, want 1", agent.closed)
	}
}

func TestPolicyBoundsFlagCardinalityBeforeCloneAndSort(t *testing.T) {
	source, err := os.ReadFile("policy.go")
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	bound := strings.Index(string(source), "len(rule.Flags) >")
	clone := strings.Index(string(source), "append([]credentialprotocol.SSHAgentRSAFlags(nil), rule.Flags...)")
	if bound < 0 || clone < 0 || bound > clone {
		t.Fatalf("flag bound/clone order = %d/%d, want bound before clone", bound, clone)
	}
}

func waitForLeaseClosed(t *testing.T, value *lease) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		value.mu.Lock()
		closed := value.closed
		value.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("lease did not enter closed state")
}
