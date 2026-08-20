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

func TestOpenPropagatesDependencyCleanupFailureAfterOwnedRetrySucceeds(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agent := &redAgentConnection{}
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		openFunc: func(context.Context) (AgentConnection, error) {
			return agent, errors.Join(ErrAgentOpen, ErrCleanupIncomplete, errors.New("raw open canary"))
		},
	}
	lease := mustLease(t, mustRegistry(t, entry), config)
	connection, err := lease.OpenVerifiedConnection(context.Background())
	if connection != nil || !errors.Is(err, ErrAgentOpen) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("OpenVerifiedConnection() = (%v, %v), want open+cleanup failure", connection, err)
	}
	if strings.Contains(err.Error(), "raw open canary") {
		t.Fatalf("OpenVerifiedConnection() exposed raw dependency error: %v", err)
	}
	if agent.closed != 1 {
		t.Fatalf("owned cleanup retry calls = %d, want 1", agent.closed)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close(): %v", err)
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

func TestOpenRejectsPreCancelledContextWithoutOpeningAgent(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	entry := &redEntry{identity: config, policy: mustPolicy(t, "policy-a", 1)}
	lease := mustLease(t, mustRegistry(t, entry), config)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if connection, err := lease.OpenVerifiedConnection(ctx); connection != nil || !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("OpenVerifiedConnection(pre-cancelled) = (%v, %v)", connection, err)
	}
	if entry.opens != 0 {
		t.Fatalf("pre-cancelled open calls = %d, want 0", entry.opens)
	}
	if err := lease.Close(context.Background()); err != nil {
		t.Fatalf("Lease.Close(): %v", err)
	}
}

func TestOpenDerivesDeadlineAndJoinsOperationContext(t *testing.T) {
	start := time.Now().Add(time.Minute)
	clock := &fakeClock{now: start}
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agent := &redAgentConnection{}
	var operationCtx context.Context
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		openFunc: func(ctx context.Context) (AgentConnection, error) {
			operationCtx = ctx
			return agent, nil
		},
	}
	registry, err := newRegistry(RegistryOptions{DaemonGeneration: "daemon-a", Entries: []LiveHostAgentEntry{entry}}, clock)
	if err != nil {
		t.Fatalf("newRegistry(): %v", err)
	}
	lease := mustLease(t, registry, config)
	connection, err := lease.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("OpenVerifiedConnection(): %v", err)
	}
	deadline, ok := operationCtx.Deadline()
	want := start.Add(credentialprotocol.SSHAgentRelayIdleTimeout)
	if !ok || !deadline.Equal(want) {
		t.Fatalf("open deadline = (%v, %v), want %v", deadline, ok, want)
	}
	select {
	case <-operationCtx.Done():
	default:
		t.Fatal("open operation context was not cancelled and joined before return")
	}
	_ = connection.Close(context.Background())
	_ = lease.Close(context.Background())
	_ = registry.Close(context.Background())
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

func TestVerifiedRoundTripCapsDeadlineAtLeaseHardHorizon(t *testing.T) {
	start := time.Now()
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
	lease := mustLease(t, registry, config)
	clock.now = start.Add(credentialprotocol.SSHAgentRelayHardLifetime - time.Minute)
	connection, err := lease.OpenVerifiedConnection(context.Background())
	if err != nil {
		t.Fatalf("OpenVerifiedConnection(): %v", err)
	}
	request := []byte{0, 0, 0, 1, byte(credentialprotocol.SSHAgentMessageRequestIdentities)}
	if _, err := connection.RoundTrip(context.Background(), request); err != nil {
		t.Fatalf("RoundTrip(): %v", err)
	}
	deadline, ok := operationCtx.Deadline()
	want := start.Add(credentialprotocol.SSHAgentRelayHardLifetime)
	if !ok || !deadline.Equal(want) {
		t.Fatalf("operation deadline = (%v, %v), want hard horizon %v", deadline, ok, want)
	}
	_ = connection.Close(context.Background())
	_ = lease.Close(context.Background())
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

func TestVerifiedRoundTripChecksPreIOCancellationAndCleansConnection(t *testing.T) {
	config := mustConfigIdentity(t, "entry-a", "daemon-a", "entry-generation-a", 1)
	agent := &redAgentConnection{}
	entry := &redEntry{
		identity: config,
		policy:   mustPolicy(t, "policy-a", 1),
		newAgent: func() *redAgentConnection { return agent },
	}
	connection := mustVerifiedConnection(t, entry)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := []byte{0, 0, 0, 1, byte(credentialprotocol.SSHAgentMessageRequestIdentities)}
	if response, err := connection.RoundTrip(ctx, request); response != nil || !errors.Is(err, ErrRequestRejected) {
		t.Fatalf("RoundTrip(pre-cancelled) = (%v, %v)", response, err)
	}
	if agent.closed != 1 || agent.roundTrips != 0 {
		t.Fatalf("pre-cancelled agent calls = close:%d roundtrip:%d, want 1/0", agent.closed, agent.roundTrips)
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

func TestPolicyAcceptsExactRSAFlagCardinalityAndRejectsPlusOne(t *testing.T) {
	identity, err := NewPolicyIdentity("policy-a", 1)
	if err != nil {
		t.Fatalf("NewPolicyIdentity(): %v", err)
	}
	base := PolicyRule{
		Fingerprint:  "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		KeyAlgorithm: credentialprotocol.SSHAgentKeyAlgorithmRSA,
		Flags: []credentialprotocol.SSHAgentRSAFlags{
			credentialprotocol.SSHAgentRSAFlagSHA256,
			credentialprotocol.SSHAgentRSAFlagSHA512,
		},
	}
	if policy, err := NewLivePolicy(identity, []PolicyRule{base}); err != nil || policy == nil {
		t.Fatalf("NewLivePolicy(exact flags) = (%v, %v)", policy, err)
	}
	base.Flags = append(base.Flags, credentialprotocol.SSHAgentRSAFlagSHA256)
	if policy, err := NewLivePolicy(identity, []PolicyRule{base}); policy != nil || !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("NewLivePolicy(plus-one flags) = (%v, %v), want nil/%v", policy, err, ErrPolicyInvalid)
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
