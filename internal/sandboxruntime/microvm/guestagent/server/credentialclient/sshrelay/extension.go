package sshrelay

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient"
)

const clientRelayCleanupTimeout = 30 * time.Second

// NewClientExtension returns the immutable client-side ssh-relay-v1
// registration. Construction performs no I/O and installs no global state.
func NewClientExtension(options ClientOptions) (credentialclient.ExtensionRegistration, error) {
	if !configured(options.Relay) {
		return credentialclient.ExtensionRegistration{}, ErrInvalidArgument
	}
	return credentialclient.ExtensionRegistration{
		Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(),
		Factory:    clientFactory{relay: options.Relay},
	}, nil
}

type clientFactory struct {
	relay Relay
}

func (factory clientFactory) Open(ctx context.Context, request credentialclient.ExtensionOpenRequest) (result credentialclient.ExtensionSession, resultErr error) {
	var cancel context.CancelFunc
	defer func() {
		if recover() != nil {
			if cancel != nil {
				cancel()
			}
			result = nil
			resultErr = ErrInvalidArgument
		}
	}()
	if !validContext(ctx) || !configured(factory.relay) ||
		!credentialprotocol.ExtensionDescriptorEqual(request.Descriptor, credentialprotocol.SSHRelayV1ExtensionDescriptor()) {
		return nil, ErrInvalidArgument
	}
	lifetimeCtx, lifetimeCancel := context.WithCancel(context.WithoutCancel(ctx))
	cancel = lifetimeCancel
	if !validContext(ctx) {
		cancel()
		return nil, ErrInvalidArgument
	}
	return &clientSession{
		relay:            factory.relay,
		lifetimeCtx:      lifetimeCtx,
		cancel:           cancel,
		pumps:            make(map[*clientPump]struct{}),
		drainStarted:     make(chan struct{}),
		ownershipTimeout: clientRelayCleanupTimeout,
	}, nil
}

type clientSession struct {
	liveValue
	relay       Relay
	lifetimeCtx context.Context
	cancel      context.CancelFunc

	handleMu         sync.Mutex
	closeMu          sync.Mutex
	mu               sync.Mutex
	pumps            map[*clientPump]struct{}
	retained         []RelayConnection
	drainStarted     chan struct{}
	ownershipTimeout time.Duration
	closing          bool
	closed           bool
	fatal            bool
}

func (session *clientSession) Handle(ctx context.Context, packet credentialclient.ExtensionPacket) error {
	if session == nil || packet.Type() != credentialprotocol.PacketTypeSSHAcceptedFD {
		return ErrInvalidArgument
	}
	accepted, ok := packet.SSHAccepted()
	if !ok {
		return ErrInvalidArgument
	}
	return session.handleAccepted(ctx, accepted)
}

type acceptedPacket interface {
	Revision() uint64
	BindingIndex() uint16
	Ordinal() uint8
	CapabilitySHA256() [32]byte
	Connection() credentialclient.SSHConnectionCapability
	WaitTransferred(context.Context) error
}

type acceptedSnapshot struct {
	request    RelayOpenRequest
	connection credentialclient.SSHConnectionCapability
}

func (session *clientSession) handleAccepted(ctx context.Context, accepted acceptedPacket) error {
	if session == nil || !validContext(ctx) || !configured(accepted) {
		return ErrInvalidArgument
	}
	snapshot, ok := snapshotAccepted(accepted)
	if !ok {
		return ErrInvalidArgument
	}

	session.handleMu.Lock()
	defer session.handleMu.Unlock()
	session.mu.Lock()
	if session.closing || session.closed || !configured(session.relay) {
		session.mu.Unlock()
		return ErrLifecycle
	}
	session.mu.Unlock()

	relayConnection, openErr := safeRelayOpen(ctx, session.relay, snapshot.request)
	if openErr != nil || !configured(relayConnection) || !validContext(ctx) {
		cleanupErr := session.rejectRelayConnection(relayConnection)
		return errors.Join(ErrDependency, cleanupErr)
	}

	pumpCtx, pumpCancel := context.WithCancel(session.lifetimeCtx)
	ownershipTimeout := session.ownershipTimeout
	if ownershipTimeout <= 0 || ownershipTimeout > clientRelayCleanupTimeout {
		ownershipTimeout = clientRelayCleanupTimeout
	}
	ownershipCtx, ownershipCancel := context.WithTimeout(context.Background(), ownershipTimeout)
	pump := &clientPump{
		session:         session,
		accepted:        accepted,
		guest:           snapshot.connection,
		relay:           relayConnection,
		ctx:             pumpCtx,
		cancel:          pumpCancel,
		ownershipCtx:    ownershipCtx,
		ownershipCancel: ownershipCancel,
		started:         make(chan struct{}),
		done:            make(chan struct{}),
	}
	session.mu.Lock()
	if session.closing || session.closed || !validContext(ctx) {
		session.mu.Unlock()
		pumpCancel()
		ownershipCancel()
		return errors.Join(ErrLifecycle, session.rejectRelayConnection(relayConnection))
	}
	session.pumps[pump] = struct{}{}
	session.mu.Unlock()
	go pump.run()
	<-pump.started

	if !validContext(ctx) {
		pumpCancel()
		return ErrLifecycle
	}
	return nil
}

func (session *clientSession) Close(ctx context.Context) error {
	done, _, contextValid := contextSnapshot(ctx)
	if session == nil || !contextValid {
		return ErrInvalidArgument
	}
	session.closeMu.Lock()
	defer session.closeMu.Unlock()

	session.handleMu.Lock()
	session.mu.Lock()
	if session.closed {
		session.mu.Unlock()
		session.handleMu.Unlock()
		return nil
	}
	if !session.closing {
		session.closing = true
		session.cancel()
		close(session.drainStarted)
	}
	pumps := make([]*clientPump, 0, len(session.pumps))
	for pump := range session.pumps {
		pumps = append(pumps, pump)
		pump.cancel()
	}
	session.mu.Unlock()
	session.handleMu.Unlock()

	for _, pump := range pumps {
		select {
		case <-pump.done:
		case <-done:
			return ErrCleanupIncomplete
		}
	}

	session.mu.Lock()
	retained := append([]RelayConnection(nil), session.retained...)
	session.mu.Unlock()
	remaining := make([]RelayConnection, 0, len(retained))
	for _, connection := range retained {
		if safeRelayClose(ctx, connection) != nil {
			remaining = append(remaining, connection)
		}
	}
	session.mu.Lock()
	session.retained = remaining
	_, canceled, contextStillValid := contextSnapshot(ctx)
	complete := len(session.pumps) == 0 && len(session.retained) == 0 && !session.fatal && contextStillValid && !canceled
	if complete {
		session.closed = true
		session.relay = nil
	}
	session.mu.Unlock()
	if !complete {
		return ErrCleanupIncomplete
	}
	return nil
}

func (session *clientSession) rejectRelayConnection(connection RelayConnection) error {
	if !configured(connection) {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), clientRelayCleanupTimeout)
	err := safeRelayClose(cleanupCtx, connection)
	cancel()
	if err == nil {
		return nil
	}
	session.mu.Lock()
	session.retained = append(session.retained, connection)
	session.mu.Unlock()
	return ErrCleanupIncomplete
}

func (session *clientSession) finishPump(pump *clientPump, retain RelayConnection, fatal bool) {
	session.mu.Lock()
	delete(session.pumps, pump)
	if configured(retain) {
		session.retained = append(session.retained, retain)
	}
	if fatal {
		session.fatal = true
	}
	session.mu.Unlock()
	close(pump.done)
}

func snapshotAccepted(packet acceptedPacket) (snapshot acceptedSnapshot, valid bool) {
	defer func() {
		if recover() != nil {
			snapshot = acceptedSnapshot{}
			valid = false
		}
	}()
	request := RelayOpenRequest{
		revision:         packet.Revision(),
		bindingIndex:     packet.BindingIndex(),
		ordinal:          packet.Ordinal(),
		capabilitySHA256: packet.CapabilitySHA256(),
	}
	connection := packet.Connection()
	if !validRelayOpenRequest(request) || !configured(connection) || connection.SHA256() != request.capabilitySHA256 {
		return acceptedSnapshot{}, false
	}
	return acceptedSnapshot{request: request, connection: connection}, true
}

func safeRelayOpen(ctx context.Context, relay Relay, request RelayOpenRequest) (connection RelayConnection, err error) {
	defer func() {
		if recover() != nil {
			connection = nil
			err = ErrDependency
		}
	}()
	connection, err = relay.Open(ctx, request)
	if err != nil {
		return connection, ErrDependency
	}
	return connection, nil
}

func safeRelayClose(ctx context.Context, connection RelayConnection) (err error) {
	if !configured(connection) {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = ErrCleanupIncomplete
		}
	}()
	if connection.Close(ctx) != nil {
		return ErrCleanupIncomplete
	}
	return nil
}

func safeWaitTransferred(ctx context.Context, packet acceptedPacket) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrDependency
		}
	}()
	if packet.WaitTransferred(ctx) != nil {
		return ErrLifecycle
	}
	return nil
}

func configured(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	for reflected.IsValid() && reflected.Kind() == reflect.Interface {
		if reflected.IsNil() {
			return false
		}
		reflected = reflected.Elem()
	}
	if !reflected.IsValid() {
		return false
	}
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return !reflected.IsNil()
	default:
		return true
	}
}

func validContext(ctx context.Context) (valid bool) {
	_, canceled, valid := contextSnapshot(ctx)
	return valid && !canceled
}

func contextSnapshot(ctx context.Context) (done <-chan struct{}, canceled bool, valid bool) {
	if !configured(ctx) {
		return nil, false, false
	}
	defer func() {
		if recover() != nil {
			done = nil
			canceled = false
			valid = false
		}
	}()
	done = ctx.Done()
	canceled = ctx.Err() != nil
	return done, canceled, true
}

var _ credentialclient.ExtensionFactory = clientFactory{}
var _ credentialclient.ExtensionSession = (*clientSession)(nil)
