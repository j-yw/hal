// Package sshrelay owns the production guest helper SSH-agent extension.
package sshrelay

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var (
	ErrInvalidArgument   = errors.New("guest helper SSH relay argument is invalid")
	ErrLifecycle         = errors.New("guest helper SSH relay lifecycle is invalid")
	ErrDependency        = errors.New("guest helper SSH relay dependency failed")
	ErrCleanupIncomplete = errors.New("guest helper SSH relay cleanup is incomplete")
)

// HelperOptions is intentionally empty: live host authority arrives only in
// credentialhelper.ExtensionOpenRequest.
type HelperOptions struct{}

// NewHelperExtension constructs a side-effect-free process-local registration.
func NewHelperExtension(HelperOptions) (credentialhelper.ExtensionRegistration, error) {
	return credentialhelper.ExtensionRegistration{
		Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(),
		Factory:    helperFactory{},
	}, nil
}

type helperFactory struct{}

func (helperFactory) Open(ctx context.Context, request credentialhelper.ExtensionOpenRequest) (credentialhelper.ExtensionSession, error) {
	if !configured(ctx) || ctx.Err() != nil || !credentialprotocol.ExtensionDescriptorEqual(request.Descriptor(), credentialprotocol.SSHRelayV1ExtensionDescriptor()) || !configured(request.Host()) {
		return nil, ErrInvalidArgument
	}
	lifetimeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	if ctx.Err() != nil {
		cancel()
		return nil, ErrInvalidArgument
	}
	return &helperSession{
		host:        request.Host(),
		lifetimeCtx: lifetimeCtx,
		cancel:      cancel,
		acceptDone:  closedSignal(),
	}, nil
}

type helperSession struct {
	host        credentialhelper.ExtensionHost
	lifetimeCtx context.Context
	cancel      context.CancelFunc

	operationMu        sync.Mutex
	mu                 sync.Mutex
	endpoint           credentialhelper.SSHAgentEndpoint
	identity           [32]byte
	revision           uint64
	expires            int64
	bindingID          credentialprotocol.SafeID
	bindingIndex       uint16
	execBinding        credentialhelper.ExecBindingCapability
	ordinal            uint8
	acceptDone         chan struct{}
	prepared           bool
	revoked            bool
	closed             bool
	cleanupComplete    bool
	acceptFailed       bool
	cleanupEndpoints   []credentialhelper.SSHAgentEndpoint
	cleanupConnections []credentialhelper.SSHAgentConnection
}

func (session *helperSession) Prepare(ctx context.Context, request credentialhelper.ExtensionPrepareRequest) (credentialhelper.ExtensionPrepareResult, error) {
	if session == nil || !configured(ctx) || ctx.Err() != nil || request.Mode() != credentialprotocol.DeliveryModeSSHAgent ||
		request.IdentityDigest() == ([32]byte{}) || request.Revision() == 0 || request.ExpiresUnixNano() <= 0 ||
		credentialprotocol.ValidateSafeID(request.BindingID()) != nil || request.BindingIndex() >= credentialprotocol.MaxHelperBindings || request.ExecBinding() == nil {
		return credentialhelper.ExtensionPrepareResult{}, ErrInvalidArgument
	}
	session.operationMu.Lock()
	defer session.operationMu.Unlock()
	session.mu.Lock()
	if session.prepared || session.revoked || session.closed || len(session.cleanupEndpoints) != 0 || len(session.cleanupConnections) != 0 {
		session.mu.Unlock()
		return credentialhelper.ExtensionPrepareResult{}, ErrLifecycle
	}
	session.mu.Unlock()

	endpointRequest, err := credentialhelper.NewSSHAgentEndpointRequest(
		request.IdentityDigest(), request.Revision(), request.BindingID(), request.BindingIndex(), request.ExecBinding(),
	)
	if err != nil {
		return credentialhelper.ExtensionPrepareResult{}, ErrInvalidArgument
	}
	endpoint, err := safeCreateEndpoint(ctx, session.host, endpointRequest)
	if err != nil || !configured(endpoint) {
		if configured(endpoint) {
			return credentialhelper.ExtensionPrepareResult{}, errors.Join(ErrDependency, session.rejectEndpoint(ctx, endpoint))
		}
		return credentialhelper.ExtensionPrepareResult{}, ErrDependency
	}
	if ctx.Err() != nil {
		return credentialhelper.ExtensionPrepareResult{}, errors.Join(ErrLifecycle, session.rejectEndpoint(ctx, endpoint))
	}
	if !sameExecBinding(safeEndpointExecBinding(endpoint), request.ExecBinding()) {
		return credentialhelper.ExtensionPrepareResult{}, errors.Join(ErrDependency, session.rejectEndpoint(ctx, endpoint))
	}
	if ctx.Err() != nil {
		return credentialhelper.ExtensionPrepareResult{}, errors.Join(ErrLifecycle, session.rejectEndpoint(ctx, endpoint))
	}
	result, err := credentialhelper.NewExtensionPrepareResult(request.ExecBinding())
	if err != nil {
		return credentialhelper.ExtensionPrepareResult{}, errors.Join(ErrInvalidArgument, session.rejectEndpoint(ctx, endpoint))
	}

	session.mu.Lock()
	if ctx.Err() != nil || session.closed || session.revoked || session.prepared {
		session.mu.Unlock()
		return credentialhelper.ExtensionPrepareResult{}, errors.Join(ErrLifecycle, session.rejectEndpoint(ctx, endpoint))
	}
	session.endpoint = endpoint
	session.identity = request.IdentityDigest()
	session.revision = request.Revision()
	session.expires = request.ExpiresUnixNano()
	session.bindingID = request.BindingID()
	session.bindingIndex = request.BindingIndex()
	session.execBinding = request.ExecBinding()
	session.prepared = true
	session.acceptDone = make(chan struct{})
	session.mu.Unlock()
	go session.acceptLoop(endpoint)
	return result, nil
}

func (session *helperSession) BindExec(ctx context.Context, request credentialhelper.ExtensionExecRequest) (credentialhelper.ExtensionExecResult, error) {
	if session == nil || !configured(ctx) || ctx.Err() != nil {
		return credentialhelper.ExtensionExecResult{}, ErrInvalidArgument
	}
	session.operationMu.Lock()
	defer session.operationMu.Unlock()
	session.mu.Lock()
	valid := session.prepared && !session.revoked && !session.closed && !session.acceptFailed &&
		request.IdentityDigest() == session.identity && request.Revision() == session.revision &&
		request.ExecBindingID() == session.bindingID && sameExecBinding(request.ExecBinding(), session.execBinding)
	binding := session.execBinding
	session.mu.Unlock()
	if !valid {
		return credentialhelper.ExtensionExecResult{}, ErrLifecycle
	}
	result, err := credentialhelper.NewExtensionExecResult(binding)
	if err != nil {
		return credentialhelper.ExtensionExecResult{}, ErrInvalidArgument
	}
	if ctx.Err() != nil {
		return credentialhelper.ExtensionExecResult{}, ErrLifecycle
	}
	return result, nil
}

func (session *helperSession) Renew(ctx context.Context, request credentialhelper.ExtensionRenewRequest) error {
	if session == nil || !configured(ctx) || ctx.Err() != nil {
		return ErrInvalidArgument
	}
	session.operationMu.Lock()
	defer session.operationMu.Unlock()
	session.mu.Lock()
	defer session.mu.Unlock()
	if ctx.Err() != nil || !session.prepared || session.revoked || session.closed || session.acceptFailed || request.IdentityDigest() != session.identity ||
		request.Revision() != session.revision+1 || request.ExpiresUnixNano() <= 0 {
		return ErrLifecycle
	}
	session.revision = request.Revision()
	session.expires = request.ExpiresUnixNano()
	return nil
}

func (session *helperSession) Revoke(ctx context.Context, request credentialhelper.ExtensionRevokeRequest) (credentialhelper.ExtensionCleanupResult, error) {
	if session == nil || !configured(ctx) {
		return credentialhelper.ExtensionCleanupResult{}, ErrInvalidArgument
	}
	session.operationMu.Lock()
	defer session.operationMu.Unlock()
	session.mu.Lock()
	if session.closed || !session.prepared || request.IdentityDigest() != session.identity || request.Revision() != session.revision {
		session.mu.Unlock()
		return credentialhelper.ExtensionCleanupResult{}, ErrLifecycle
	}
	if !session.revoked {
		session.revoked = true
		session.cancel()
	}
	endpoint := session.endpoint
	done := session.acceptDone
	session.mu.Unlock()

	result, endpointComplete := closeEndpoint(ctx, endpoint)
	if endpointComplete {
		session.mu.Lock()
		session.endpoint = nil
		session.mu.Unlock()
	}
	select {
	case <-done:
	case <-ctx.Done():
		return credentialhelper.ExtensionCleanupResult{}, ErrCleanupIncomplete
	}
	connectionsComplete := session.closeRetainedConnections(ctx)
	if !endpointComplete || !connectionsComplete {
		return result, ErrCleanupIncomplete
	}
	session.mu.Lock()
	session.execBinding = nil
	session.identity = [32]byte{}
	session.bindingID = ""
	session.mu.Unlock()
	return result, nil
}

func (session *helperSession) Close(ctx context.Context) error {
	if session == nil || !configured(ctx) {
		return ErrInvalidArgument
	}
	session.operationMu.Lock()
	defer session.operationMu.Unlock()
	session.mu.Lock()
	if session.cleanupComplete {
		session.mu.Unlock()
		return nil
	}
	if !session.closed {
		session.closed = true
		session.cancel()
	}
	endpoint := session.endpoint
	done := session.acceptDone
	cleanupEndpoints := append([]credentialhelper.SSHAgentEndpoint(nil), session.cleanupEndpoints...)
	session.mu.Unlock()

	endpointComplete := true
	if configured(endpoint) {
		_, endpointComplete = closeEndpoint(ctx, endpoint)
	}
	remainingEndpoints := make([]credentialhelper.SSHAgentEndpoint, 0, len(cleanupEndpoints))
	for _, cleanupEndpoint := range cleanupEndpoints {
		if _, complete := closeEndpoint(ctx, cleanupEndpoint); !complete {
			remainingEndpoints = append(remainingEndpoints, cleanupEndpoint)
		}
	}
	session.mu.Lock()
	session.cleanupEndpoints = remainingEndpoints
	if endpointComplete {
		session.endpoint = nil
	}
	session.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return ErrCleanupIncomplete
	}
	connectionsComplete := session.closeRetainedConnections(ctx)
	session.mu.Lock()
	complete := endpointComplete && connectionsComplete && len(session.cleanupEndpoints) == 0 && len(session.cleanupConnections) == 0
	if complete {
		session.execBinding = nil
		session.identity = [32]byte{}
		session.bindingID = ""
		session.host = nil
		session.cleanupComplete = true
	}
	session.mu.Unlock()
	if !complete {
		return ErrCleanupIncomplete
	}
	return nil
}

func (session *helperSession) acceptLoop(endpoint credentialhelper.SSHAgentEndpoint) {
	defer close(session.acceptDone)
	for {
		connection, err := safeEndpointAccept(session.lifetimeCtx, endpoint)
		if err != nil {
			if configured(connection) {
				session.closeOrRetainConnection(connection)
			}
			if session.lifetimeCtx.Err() == nil {
				session.mu.Lock()
				session.acceptFailed = true
				session.mu.Unlock()
			}
			return
		}
		if !configured(connection) {
			session.mu.Lock()
			session.acceptFailed = true
			session.mu.Unlock()
			return
		}
		session.mu.Lock()
		if session.ordinal == credentialprotocol.SSHAgentRelayMaxLifetimeConnections || session.revoked || session.closed {
			session.mu.Unlock()
			session.closeOrRetainConnection(connection)
			return
		}
		session.ordinal++
		ordinal := session.ordinal
		identity := session.identity
		revision := session.revision
		bindingIndex := session.bindingIndex
		binding := session.execBinding
		session.mu.Unlock()

		digest := relayCapabilityDigest(identity, revision, bindingIndex, ordinal)
		publication, publicationErr := credentialhelper.NewSSHAcceptedPublication(identity, revision, bindingIndex, ordinal, digest, binding)
		if publicationErr != nil || safePublishConnection(session.lifetimeCtx, session.host, publication, connection) != nil {
			session.closeOrRetainConnection(connection)
			if publicationErr != nil || session.lifetimeCtx.Err() == nil {
				session.mu.Lock()
				session.acceptFailed = true
				session.mu.Unlock()
			}
			return
		}
	}
}

func (session *helperSession) rejectEndpoint(ctx context.Context, endpoint credentialhelper.SSHAgentEndpoint) error {
	_, complete := closeEndpoint(ctx, endpoint)
	if complete {
		return nil
	}
	session.mu.Lock()
	session.cleanupEndpoints = append(session.cleanupEndpoints, endpoint)
	session.mu.Unlock()
	return ErrCleanupIncomplete
}

func (session *helperSession) closeOrRetainConnection(connection credentialhelper.SSHAgentConnection) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(session.lifetimeCtx), credentialprotocol.SSHAgentRelayIdleTimeout)
	err := safeConnectionClose(cleanupCtx, connection)
	cancel()
	if err == nil {
		return
	}
	session.mu.Lock()
	session.cleanupConnections = append(session.cleanupConnections, connection)
	session.mu.Unlock()
}

func (session *helperSession) closeRetainedConnections(ctx context.Context) bool {
	session.mu.Lock()
	connections := append([]credentialhelper.SSHAgentConnection(nil), session.cleanupConnections...)
	session.mu.Unlock()
	remaining := make([]credentialhelper.SSHAgentConnection, 0, len(connections))
	for _, connection := range connections {
		if err := safeConnectionClose(ctx, connection); err != nil {
			remaining = append(remaining, connection)
		}
	}
	session.mu.Lock()
	session.cleanupConnections = remaining
	session.mu.Unlock()
	return len(remaining) == 0
}

func closeEndpoint(ctx context.Context, endpoint credentialhelper.SSHAgentEndpoint) (credentialhelper.ExtensionCleanupResult, bool) {
	result, err := safeEndpointClose(ctx, endpoint)
	return result, err == nil && result.ResourcesAbsent() && result.Category() == credentialhelper.ExtensionCleanupComplete
}

func relayCapabilityDigest(identity [32]byte, revision uint64, bindingIndex uint16, ordinal uint8) [32]byte {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("hal/l8/guest-helper/ssh-relay-capability/v1"))
	_, _ = hasher.Write(identity[:])
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], revision)
	_, _ = hasher.Write(scalar[:])
	var index [2]byte
	binary.BigEndian.PutUint16(index[:], bindingIndex)
	_, _ = hasher.Write(index[:])
	_, _ = hasher.Write([]byte{ordinal})
	var digest [32]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

func configured(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !reflected.IsNil()
	default:
		return true
	}
}

func sameExecBinding(left, right credentialhelper.ExecBindingCapability) (same bool) {
	defer func() { _ = recover() }()
	if !configured(left) || !configured(right) || reflect.TypeOf(left) != reflect.TypeOf(right) || !reflect.TypeOf(left).Comparable() {
		return false
	}
	return left == right
}

func safeCreateEndpoint(ctx context.Context, host credentialhelper.ExtensionHost, request credentialhelper.SSHAgentEndpointRequest) (endpoint credentialhelper.SSHAgentEndpoint, err error) {
	defer func() {
		if recover() != nil {
			endpoint = nil
			err = ErrDependency
		}
	}()
	return host.CreateSSHAgentEndpoint(ctx, request)
}

func safeEndpointExecBinding(endpoint credentialhelper.SSHAgentEndpoint) (binding credentialhelper.ExecBindingCapability) {
	defer func() {
		if recover() != nil {
			binding = nil
		}
	}()
	return endpoint.ExecBinding()
}

func safeEndpointAccept(ctx context.Context, endpoint credentialhelper.SSHAgentEndpoint) (connection credentialhelper.SSHAgentConnection, err error) {
	defer func() {
		if recover() != nil {
			connection = nil
			err = ErrDependency
		}
	}()
	return endpoint.Accept(ctx)
}

func safeEndpointClose(ctx context.Context, endpoint credentialhelper.SSHAgentEndpoint) (result credentialhelper.ExtensionCleanupResult, err error) {
	defer func() {
		if recover() != nil {
			result = credentialhelper.ExtensionCleanupResult{}
			err = ErrCleanupIncomplete
		}
	}()
	if !configured(endpoint) {
		return credentialhelper.NewExtensionCleanupResult(true, credentialhelper.ExtensionCleanupComplete)
	}
	return endpoint.Close(ctx)
}

func safePublishConnection(ctx context.Context, host credentialhelper.ExtensionHost, publication credentialhelper.SSHAcceptedPublication, connection credentialhelper.SSHAgentConnection) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrDependency
		}
	}()
	return host.PublishSSHAcceptedConnection(ctx, publication, connection)
}

func safeConnectionClose(ctx context.Context, connection credentialhelper.SSHAgentConnection) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrCleanupIncomplete
		}
	}()
	if !configured(connection) {
		return nil
	}
	if closeErr := connection.Close(ctx); closeErr != nil {
		return ErrCleanupIncomplete
	}
	return nil
}

func closedSignal() chan struct{} {
	channel := make(chan struct{})
	close(channel)
	return channel
}

var _ credentialhelper.ExtensionFactory = helperFactory{}
var _ credentialhelper.ExtensionSession = (*helperSession)(nil)
