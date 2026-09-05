package credentialprotocol

import (
	"errors"
	"sync"
	"time"
)

const (
	// SSHAgentRelayMaxConcurrentConnections is the per-job active limit.
	SSHAgentRelayMaxConcurrentConnections = 4
	// SSHAgentRelayMaxLifetimeConnections is the per-job accepted-open limit.
	SSHAgentRelayMaxLifetimeConnections = 64
	// SSHAgentRelayMaxAttemptedOperations is shared by every job connection.
	SSHAgentRelayMaxAttemptedOperations = 4096
	// SSHAgentRelayIdleTimeout is the maximum span without lifecycle progress.
	SSHAgentRelayIdleTimeout = 5 * time.Minute
	// SSHAgentRelayHardLifetime is measured from creation of the job state.
	SSHAgentRelayHardLifetime = 35 * time.Minute
)

var (
	ErrSSHAgentRelayStateInvalid              = errors.New("credential protocol SSH-agent relay state is invalid")
	ErrSSHAgentRelayConnectionInvalid         = errors.New("credential protocol SSH-agent relay connection is invalid")
	ErrSSHAgentRelayClosed                    = errors.New("credential protocol SSH-agent relay is closed")
	ErrSSHAgentRelayConnectionClosed          = errors.New("credential protocol SSH-agent relay connection is closed")
	ErrSSHAgentRelayTimestamp                 = errors.New("credential protocol SSH-agent relay timestamp is invalid")
	ErrSSHAgentRelayConcurrentConnectionLimit = errors.New("credential protocol SSH-agent relay concurrent connection limit reached")
	ErrSSHAgentRelayLifetimeConnectionLimit   = errors.New("credential protocol SSH-agent relay lifetime connection limit reached")
	ErrSSHAgentRelayOperationLimit            = errors.New("credential protocol SSH-agent relay operation limit reached")
	ErrSSHAgentRelayRequestOutstanding        = errors.New("credential protocol SSH-agent relay request is outstanding")
	ErrSSHAgentRelayNoRequestOutstanding      = errors.New("credential protocol SSH-agent relay request is not outstanding")
	ErrSSHAgentRelayIdleTimeout               = errors.New("credential protocol SSH-agent relay idle deadline reached")
	ErrSSHAgentRelayHardLifetime              = errors.New("credential protocol SSH-agent relay hard lifetime reached")
)

// SSHAgentRelayState owns bounded admission counters for one job.
type SSHAgentRelayState struct {
	owner *sshAgentRelayStateOwner
}

type sshAgentRelayStateOwner struct {
	mu                  sync.Mutex
	startedAt           time.Time
	lastObserved        time.Time
	activeConnections   int
	lifetimeConnections int
	attemptedOperations int
	initialized         bool
	closed              bool
	hardExpired         bool
}

// SSHAgentRelayConnection owns the request lifecycle for one accepted open.
type SSHAgentRelayConnection struct {
	owner *sshAgentRelayConnectionOwner
}

type sshAgentRelayConnectionOwner struct {
	state         *sshAgentRelayStateOwner
	openedAt      time.Time
	lastActivity  time.Time
	requestActive bool
	active        bool
}

// SSHAgentRelaySnapshot exposes only safe bounded counters.
type SSHAgentRelaySnapshot struct {
	ActiveConnections   int
	LifetimeConnections int
	AttemptedOperations int
}

// NewSSHAgentRelayState creates one job state from a caller-supplied start.
func NewSSHAgentRelayState(startedAt time.Time) (*SSHAgentRelayState, error) {
	if startedAt.IsZero() {
		return nil, ErrSSHAgentRelayTimestamp
	}
	return &SSHAgentRelayState{owner: &sshAgentRelayStateOwner{
		startedAt:    startedAt,
		lastObserved: startedAt,
		initialized:  true,
	}}, nil
}

// OpenConnection admits one connection without opening any transport.
func (state *SSHAgentRelayState) OpenConnection(now time.Time) (*SSHAgentRelayConnection, error) {
	owner, err := state.stateOwner()
	if err != nil {
		return nil, ErrSSHAgentRelayStateInvalid
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()

	if !owner.initialized {
		return nil, ErrSSHAgentRelayStateInvalid
	}
	if owner.closed {
		return nil, ErrSSHAgentRelayClosed
	}
	if err := owner.observeJobTime(now); err != nil {
		return nil, err
	}
	if owner.activeConnections >= SSHAgentRelayMaxConcurrentConnections {
		return nil, ErrSSHAgentRelayConcurrentConnectionLimit
	}
	if owner.lifetimeConnections >= SSHAgentRelayMaxLifetimeConnections {
		return nil, ErrSSHAgentRelayLifetimeConnectionLimit
	}

	owner.activeConnections++
	owner.lifetimeConnections++
	return &SSHAgentRelayConnection{
		owner: &sshAgentRelayConnectionOwner{
			state:        owner,
			openedAt:     now,
			lastActivity: now,
			active:       true,
		},
	}, nil
}

// PermitRead reserves exactly one attempted operation before a caller reads.
// The reservation remains outstanding until CompleteRequest or Close.
func (connection *SSHAgentRelayConnection) PermitRead(now time.Time) error {
	connectionOwner, stateOwner, err := connection.owners()
	if err != nil {
		return err
	}
	stateOwner.mu.Lock()
	defer stateOwner.mu.Unlock()

	if !stateOwner.initialized {
		return ErrSSHAgentRelayStateInvalid
	}
	if stateOwner.closed {
		return ErrSSHAgentRelayClosed
	}
	if !connectionOwner.active {
		return ErrSSHAgentRelayConnectionClosed
	}
	if err := stateOwner.observeJobTime(now); err != nil {
		if errors.Is(err, ErrSSHAgentRelayHardLifetime) {
			stateOwner.deactivate(connectionOwner)
		}
		return err
	}
	if now.Before(connectionOwner.openedAt) || now.Before(connectionOwner.lastActivity) {
		return ErrSSHAgentRelayTimestamp
	}
	if !now.Before(connectionOwner.lastActivity.Add(SSHAgentRelayIdleTimeout)) {
		stateOwner.deactivate(connectionOwner)
		return ErrSSHAgentRelayIdleTimeout
	}
	if connectionOwner.requestActive {
		return ErrSSHAgentRelayRequestOutstanding
	}
	if stateOwner.attemptedOperations >= SSHAgentRelayMaxAttemptedOperations {
		return ErrSSHAgentRelayOperationLimit
	}

	stateOwner.attemptedOperations++
	connectionOwner.requestActive = true
	connectionOwner.lastActivity = now
	return nil
}

// CompleteRequest permits a later read after one response is complete.
func (connection *SSHAgentRelayConnection) CompleteRequest(now time.Time) error {
	connectionOwner, stateOwner, err := connection.owners()
	if err != nil {
		return err
	}
	stateOwner.mu.Lock()
	defer stateOwner.mu.Unlock()

	if !stateOwner.initialized {
		return ErrSSHAgentRelayStateInvalid
	}
	if stateOwner.closed {
		return ErrSSHAgentRelayClosed
	}
	if !connectionOwner.active {
		return ErrSSHAgentRelayConnectionClosed
	}
	if err := stateOwner.observeJobTime(now); err != nil {
		if errors.Is(err, ErrSSHAgentRelayHardLifetime) {
			stateOwner.deactivate(connectionOwner)
		}
		return err
	}
	if now.Before(connectionOwner.openedAt) || now.Before(connectionOwner.lastActivity) {
		return ErrSSHAgentRelayTimestamp
	}
	if !now.Before(connectionOwner.lastActivity.Add(SSHAgentRelayIdleTimeout)) {
		stateOwner.deactivate(connectionOwner)
		return ErrSSHAgentRelayIdleTimeout
	}
	if !connectionOwner.requestActive {
		return ErrSSHAgentRelayNoRequestOutstanding
	}

	connectionOwner.requestActive = false
	connectionOwner.lastActivity = now
	return nil
}

// Close releases one active slot. It is idempotent.
func (connection *SSHAgentRelayConnection) Close() {
	connectionOwner, stateOwner, err := connection.owners()
	if err != nil {
		return
	}
	stateOwner.mu.Lock()
	defer stateOwner.mu.Unlock()
	stateOwner.deactivate(connectionOwner)
}

// Close denies all later admission. It is idempotent.
func (state *SSHAgentRelayState) Close() {
	owner, err := state.stateOwner()
	if err != nil {
		return
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	owner.closed = true
	owner.activeConnections = 0
}

// Snapshot returns one consistent safe counter projection.
func (state *SSHAgentRelayState) Snapshot() SSHAgentRelaySnapshot {
	owner, err := state.stateOwner()
	if err != nil {
		return SSHAgentRelaySnapshot{}
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return SSHAgentRelaySnapshot{
		ActiveConnections:   owner.activeConnections,
		LifetimeConnections: owner.lifetimeConnections,
		AttemptedOperations: owner.attemptedOperations,
	}
}

func (state *SSHAgentRelayState) stateOwner() (*sshAgentRelayStateOwner, error) {
	if state == nil || state.owner == nil {
		return nil, ErrSSHAgentRelayStateInvalid
	}
	return state.owner, nil
}

func (connection *SSHAgentRelayConnection) owners() (*sshAgentRelayConnectionOwner, *sshAgentRelayStateOwner, error) {
	if connection == nil || connection.owner == nil || connection.owner.state == nil {
		return nil, nil, ErrSSHAgentRelayConnectionInvalid
	}
	return connection.owner, connection.owner.state, nil
}

func (state *sshAgentRelayStateOwner) observeJobTime(now time.Time) error {
	if state.hardExpired {
		return ErrSSHAgentRelayHardLifetime
	}
	if now.IsZero() || now.Before(state.startedAt) || now.Before(state.lastObserved) {
		return ErrSSHAgentRelayTimestamp
	}
	if !now.Before(state.startedAt.Add(SSHAgentRelayHardLifetime)) {
		state.lastObserved = now
		state.hardExpired = true
		state.activeConnections = 0
		return ErrSSHAgentRelayHardLifetime
	}
	state.lastObserved = now
	return nil
}

func (state *sshAgentRelayStateOwner) deactivate(connection *sshAgentRelayConnectionOwner) {
	if !connection.active {
		return
	}
	connection.active = false
	connection.requestActive = false
	if !state.closed && state.activeConnections > 0 {
		state.activeConnections--
	}
}
