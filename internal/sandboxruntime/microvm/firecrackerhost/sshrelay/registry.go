package sshrelay

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

type Registry struct {
	liveValue
	mu      sync.Mutex
	clock   clock
	entries map[credentialprotocol.SafeID]registryEntry
	leases  map[*lease]struct{}
	closed  bool
}

type registryEntry struct {
	identity       ConfigIdentity
	policyIdentity PolicyIdentity
	policy         LivePolicy
	entry          LiveHostAgentEntry
}

type liveHostAgentEntry struct {
	liveValue
	identity ConfigIdentity
	policy   LivePolicy
	dialer   AgentDialer
	verifier PeerVerifier
}

func NewLiveHostAgentEntry(options LiveHostAgentOptions) (LiveHostAgentEntry, error) {
	if !validConfigIdentity(options.Identity) || !configuredDependency(options.Dialer) || !configuredDependency(options.Verifier) {
		return nil, ErrInvalidArgument
	}
	if _, err := validateLivePolicy(options.Policy); err != nil {
		return nil, ErrPolicyInvalid
	}
	return &liveHostAgentEntry{
		identity: options.Identity,
		policy:   options.Policy,
		dialer:   options.Dialer,
		verifier: options.Verifier,
	}, nil
}

func (entry *liveHostAgentEntry) Identity() ConfigIdentity {
	if entry == nil {
		return ConfigIdentity{}
	}
	return entry.identity
}

func (entry *liveHostAgentEntry) Policy() LivePolicy {
	if entry == nil {
		return nil
	}
	return entry.policy
}

func (entry *liveHostAgentEntry) Open(ctx context.Context) (AgentConnection, error) {
	if entry == nil || ctx == nil {
		return nil, ErrAgentOpen
	}
	connection, err := entry.dialer.Open(ctx)
	if err != nil || !configuredDependency(connection) {
		if configuredDependency(connection) {
			_ = safeAgentClose(ctx, connection)
		}
		return nil, ErrAgentOpen
	}
	return connection, nil
}

func (entry *liveHostAgentEntry) VerifyPeer(ctx context.Context, connection AgentConnection) (PeerProof, error) {
	if entry == nil || ctx == nil || !configuredDependency(connection) {
		return PeerProof{}, ErrAgentPeer
	}
	proof, err := entry.verifier.Verify(ctx, connection, entry.identity)
	if err != nil {
		return PeerProof{}, ErrAgentPeer
	}
	return proof, nil
}

func NewRegistry(options RegistryOptions) (*Registry, error) {
	return newRegistry(options, wallClock{})
}

func newRegistry(options RegistryOptions, source clock) (*Registry, error) {
	daemonGeneration := credentialprotocol.SafeID(options.DaemonGeneration)
	if credentialprotocol.ValidateSafeID(daemonGeneration) != nil || !configuredDependency(source) {
		return nil, ErrInvalidArgument
	}
	entries := make(map[credentialprotocol.SafeID]registryEntry, len(options.Entries))
	configs := make([]ConfigIdentity, 0, len(options.Entries))
	policies := make([]PolicyIdentity, 0, len(options.Entries))
	for _, candidate := range options.Entries {
		if !configuredDependency(candidate) {
			return nil, ErrDependencyRequired
		}
		identity, policy, policyIdentity, err := inspectEntry(candidate)
		if err != nil || identity.daemonGeneration != daemonGeneration {
			return nil, ErrIdentityMismatch
		}
		if _, duplicate := entries[identity.entryID]; duplicate {
			return nil, ErrDuplicateEntry
		}
		for index := range configs {
			if ConfigIdentityEqual(configs[index], identity) || PolicyIdentityEqual(policies[index], policyIdentity) {
				return nil, ErrDuplicateEntry
			}
		}
		entries[identity.entryID] = registryEntry{
			identity:       identity,
			policyIdentity: policyIdentity,
			policy:         policy,
			entry:          candidate,
		}
		configs = append(configs, identity)
		policies = append(policies, policyIdentity)
	}
	return &Registry{
		clock:   source,
		entries: entries,
		leases:  make(map[*lease]struct{}),
	}, nil
}

func (registry *Registry) Acquire(ctx context.Context, request AcquireRequest) (Lease, error) {
	if registry == nil || ctx == nil || !validAcquireRequest(request) {
		return nil, ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrRegistryClosed
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed {
		return nil, ErrRegistryClosed
	}
	entry, ok := registry.entries[request.config.entryID]
	if !ok || !ConfigIdentityEqual(entry.identity, request.config) {
		return nil, ErrIdentityMismatch
	}
	startedAt := registry.clock.Now()
	state, err := credentialprotocol.NewSSHAgentRelayState(startedAt)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	lifetimeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	value := &lease{
		registry:     registry,
		identity:     entry.identity,
		policyID:     entry.policyIdentity,
		policy:       entry.policy,
		entry:        entry.entry,
		clock:        registry.clock,
		state:        state,
		request:      request,
		lifetimeCtx:  lifetimeCtx,
		cancel:       cancel,
		connections:  make(map[*verifiedConnection]struct{}),
		inflightZero: closedSignal(),
	}
	registry.leases[value] = struct{}{}
	return value, nil
}

func (registry *Registry) Close(ctx context.Context) error {
	if registry == nil || ctx == nil {
		return ErrInvalidArgument
	}
	registry.mu.Lock()
	registry.closed = true
	leases := make([]*lease, 0, len(registry.leases))
	for value := range registry.leases {
		leases = append(leases, value)
	}
	registry.mu.Unlock()

	var incomplete bool
	for _, value := range leases {
		if err := value.Close(ctx); err != nil {
			incomplete = true
		}
	}
	registry.mu.Lock()
	remaining := len(registry.leases)
	registry.mu.Unlock()
	if incomplete || remaining != 0 {
		return ErrCleanupIncomplete
	}
	return nil
}

func (registry *Registry) releaseLease(value *lease) {
	registry.mu.Lock()
	delete(registry.leases, value)
	registry.mu.Unlock()
}

type lease struct {
	liveValue
	registry *Registry
	identity ConfigIdentity
	policyID PolicyIdentity
	policy   LivePolicy
	entry    LiveHostAgentEntry
	clock    clock
	state    *credentialprotocol.SSHAgentRelayState
	request  AcquireRequest

	closeMu         sync.Mutex
	mu              sync.Mutex
	lifetimeCtx     context.Context
	cancel          context.CancelFunc
	connections     map[*verifiedConnection]struct{}
	inflightOpens   int
	inflightZero    chan struct{}
	closed          bool
	cleanupComplete bool
}

func (value *lease) Identity() ConfigIdentity {
	if value == nil {
		return ConfigIdentity{}
	}
	return value.identity
}

func (value *lease) PolicyIdentity() PolicyIdentity {
	if value == nil {
		return PolicyIdentity{}
	}
	return value.policyID
}

func (value *lease) OpenVerifiedConnection(ctx context.Context) (VerifiedAgentConnection, error) {
	if value == nil || ctx == nil {
		return nil, ErrInvalidArgument
	}
	if err := value.beginOpen(); err != nil {
		return nil, err
	}
	defer value.endOpen()

	relayConnection, err := value.state.OpenConnection(value.clock.Now())
	if err != nil {
		if errors.Is(err, credentialprotocol.ErrSSHAgentRelayHardLifetime) {
			return nil, ErrLeaseExpired
		}
		return nil, ErrConnectionLimit
	}
	opCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(value.lifetimeCtx, cancel)
	defer func() {
		stop()
		cancel()
	}()

	agent, openErr := safeEntryOpen(opCtx, value.entry)
	if openErr != nil || !configuredDependency(agent) {
		relayConnection.Close()
		if configuredDependency(agent) {
			_ = safeAgentClose(opCtx, agent)
		}
		return nil, ErrAgentOpen
	}
	proof, proofErr := safeEntryVerifyPeer(opCtx, value.entry, agent)
	if proofErr != nil || consumePeerProof(proof, value.identity, agent) != nil {
		relayConnection.Close()
		_ = safeAgentClose(opCtx, agent)
		return nil, ErrAgentPeer
	}

	connection := &verifiedConnection{
		lease:        value,
		agent:        agent,
		policy:       value.policy,
		clock:        value.clock,
		relay:        relayConnection,
		inflightZero: closedSignal(),
	}
	value.mu.Lock()
	if value.closed {
		value.mu.Unlock()
		_ = connection.Close(opCtx)
		return nil, ErrLeaseClosed
	}
	value.connections[connection] = struct{}{}
	value.mu.Unlock()
	return connection, nil
}

func (value *lease) beginOpen() error {
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.closed {
		return ErrLeaseClosed
	}
	if value.inflightOpens == 0 {
		value.inflightZero = make(chan struct{})
	}
	value.inflightOpens++
	return nil
}

func (value *lease) endOpen() {
	value.mu.Lock()
	value.inflightOpens--
	if value.inflightOpens == 0 {
		close(value.inflightZero)
	}
	value.mu.Unlock()
}

func (value *lease) Close(ctx context.Context) error {
	if value == nil || ctx == nil {
		return ErrInvalidArgument
	}
	value.closeMu.Lock()
	defer value.closeMu.Unlock()
	value.mu.Lock()
	if value.cleanupComplete {
		value.mu.Unlock()
		return nil
	}
	if !value.closed {
		value.closed = true
		value.cancel()
		value.state.Close()
	}
	inflightZero := value.inflightZero
	connections := make([]*verifiedConnection, 0, len(value.connections))
	for connection := range value.connections {
		connections = append(connections, connection)
	}
	value.mu.Unlock()

	var incomplete bool
	for _, connection := range connections {
		if err := connection.Close(ctx); err != nil {
			incomplete = true
		}
	}
	select {
	case <-inflightZero:
	case <-ctx.Done():
		return ErrCleanupIncomplete
	}

	value.mu.Lock()
	absent := value.inflightOpens == 0 && len(value.connections) == 0
	if absent && !incomplete {
		value.cleanupComplete = true
	}
	complete := value.cleanupComplete
	value.mu.Unlock()
	if !complete {
		return ErrCleanupIncomplete
	}
	value.registry.releaseLease(value)
	return nil
}

func (value *lease) releaseConnection(connection *verifiedConnection) {
	value.mu.Lock()
	delete(value.connections, connection)
	value.mu.Unlock()
}

func closedSignal() chan struct{} {
	channel := make(chan struct{})
	close(channel)
	return channel
}

func inspectEntry(entry LiveHostAgentEntry) (identity ConfigIdentity, policy LivePolicy, policyIdentity PolicyIdentity, err error) {
	defer func() {
		if recover() != nil {
			identity = ConfigIdentity{}
			policy = nil
			policyIdentity = PolicyIdentity{}
			err = ErrDependencyRequired
		}
	}()
	identity = entry.Identity()
	policy = entry.Policy()
	if !validConfigIdentity(identity) {
		return ConfigIdentity{}, nil, PolicyIdentity{}, ErrIdentityMismatch
	}
	policyIdentity, err = validateLivePolicy(policy)
	return identity, policy, policyIdentity, err
}

func safeEntryOpen(ctx context.Context, entry LiveHostAgentEntry) (connection AgentConnection, err error) {
	defer func() {
		if recover() != nil {
			connection = nil
			err = ErrAgentOpen
		}
	}()
	return entry.Open(ctx)
}

func safeEntryVerifyPeer(ctx context.Context, entry LiveHostAgentEntry, connection AgentConnection) (proof PeerProof, err error) {
	defer func() {
		if recover() != nil {
			proof = PeerProof{}
			err = ErrAgentPeer
		}
	}()
	return entry.VerifyPeer(ctx, connection)
}

func safeAgentClose(ctx context.Context, connection AgentConnection) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrCleanupIncomplete
		}
	}()
	if !configuredDependency(connection) {
		return nil
	}
	if closeErr := connection.Close(ctx); closeErr != nil {
		return ErrCleanupIncomplete
	}
	return nil
}

var _ Lease = (*lease)(nil)
var _ LiveHostAgentEntry = (*liveHostAgentEntry)(nil)
