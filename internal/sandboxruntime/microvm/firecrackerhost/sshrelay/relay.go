package sshrelay

import (
	"context"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type verifiedConnection struct {
	liveValue
	lease  *lease
	agent  AgentConnection
	policy LivePolicy
	clock  clock
	relay  *credentialprotocol.SSHAgentRelayConnection

	operationMu  sync.Mutex
	closeMu      sync.Mutex
	mu           sync.Mutex
	inflight     int
	inflightZero chan struct{}
	closing      bool
	agentClosed  bool
	closed       bool
}

func (connection *verifiedConnection) RoundTrip(ctx context.Context, request []byte) ([]byte, error) {
	if connection == nil || !configuredDependency(ctx) {
		return nil, ErrInvalidArgument
	}
	connection.operationMu.Lock()
	defer connection.operationMu.Unlock()
	if err := connection.beginOperation(); err != nil {
		return nil, err
	}
	defer connection.endOperation()
	if err := connection.relay.PermitRead(connection.clock.Now()); err != nil {
		return nil, ErrRequestRejected
	}
	metadata, err := credentialprotocol.ValidateSSHAgentOuterFrame(request)
	var response []byte
	if err != nil || metadata.Class != credentialprotocol.SSHAgentMessageClassClientRequest {
		response = credentialprotocol.EncodeSSHAgentFailure()
		return connection.completeRequest(response, nil)
	}
	switch metadata.MessageType {
	case credentialprotocol.SSHAgentMessageRequestIdentities:
		if credentialprotocol.ValidateSSHAgentIdentitiesRequest(request) != nil {
			response = credentialprotocol.EncodeSSHAgentFailure()
			return connection.completeRequest(response, nil)
		}
		response, err = connection.identities(ctx, request)
	case credentialprotocol.SSHAgentMessageSignRequest:
		response, err = connection.sign(ctx, request)
	default:
		response = credentialprotocol.EncodeSSHAgentFailure()
	}
	return connection.completeRequest(response, err)
}

func (connection *verifiedConnection) completeRequest(response []byte, operationErr error) ([]byte, error) {
	if err := connection.relay.CompleteRequest(connection.clock.Now()); err != nil {
		credentialprotocol.WipeSSHAgentBytes(response)
		return nil, ErrRequestRejected
	}
	return response, operationErr
}

func (connection *verifiedConnection) identities(ctx context.Context, request []byte) ([]byte, error) {
	response, err := connection.agentRoundTrip(ctx, request)
	if err != nil {
		return nil, err
	}
	defer credentialprotocol.WipeSSHAgentBytes(response)
	metadata, err := credentialprotocol.ValidateSSHAgentOuterFrame(response)
	if err != nil {
		return nil, ErrAgentIO
	}
	if metadata.MessageType == credentialprotocol.SSHAgentMessageFailure {
		return credentialprotocol.EncodeSSHAgentFailure(), nil
	}
	if metadata.MessageType != credentialprotocol.SSHAgentMessageIdentitiesAnswer {
		return nil, ErrAgentIO
	}
	identities, err := credentialprotocol.DecodeSSHAgentIdentitiesAnswer(response)
	if err != nil {
		return nil, ErrAgentIO
	}
	defer credentialprotocol.WipeSSHAgentIdentities(identities)
	filtered, err := connection.policy.FilterIdentities(identities)
	if err != nil {
		return nil, ErrPolicyInvalid
	}
	defer credentialprotocol.WipeSSHAgentIdentities(filtered)
	encoded, err := credentialprotocol.EncodeSSHAgentIdentitiesAnswer(filtered)
	if err != nil {
		return nil, ErrAgentIO
	}
	return encoded, nil
}

func (connection *verifiedConnection) sign(ctx context.Context, frame []byte) ([]byte, error) {
	request, err := credentialprotocol.DecodeSSHAgentSignRequest(frame)
	if err != nil {
		return credentialprotocol.EncodeSSHAgentFailure(), nil
	}
	defer request.Wipe()
	if err := connection.policy.AuthorizeSign(request); err != nil {
		return credentialprotocol.EncodeSSHAgentFailure(), nil
	}
	response, err := connection.agentRoundTrip(ctx, frame)
	if err != nil {
		return nil, err
	}
	defer credentialprotocol.WipeSSHAgentBytes(response)
	metadata, err := credentialprotocol.ValidateSSHAgentOuterFrame(response)
	if err != nil {
		return nil, ErrAgentIO
	}
	if metadata.MessageType == credentialprotocol.SSHAgentMessageFailure {
		return credentialprotocol.EncodeSSHAgentFailure(), nil
	}
	if metadata.MessageType != credentialprotocol.SSHAgentMessageSignResponse {
		return nil, ErrAgentIO
	}
	signature, err := credentialprotocol.DecodeSSHAgentSignResponse(response)
	if err != nil {
		return nil, ErrAgentIO
	}
	defer signature.Wipe()
	if err := credentialprotocol.ValidateSSHAgentSignatureForRequest(request, *signature); err != nil {
		return nil, ErrAgentIO
	}
	encoded, err := credentialprotocol.EncodeSSHAgentSignResponse(*signature)
	if err != nil {
		return nil, ErrAgentIO
	}
	return encoded, nil
}

func (connection *verifiedConnection) agentRoundTrip(ctx context.Context, frame []byte) (response []byte, err error) {
	request := append([]byte(nil), frame...)
	defer credentialprotocol.WipeSSHAgentBytes(request)
	defer func() {
		if recover() != nil {
			credentialprotocol.WipeSSHAgentBytes(response)
			response = nil
			err = ErrAgentIO
		}
	}()
	response, err = connection.agent.RoundTrip(ctx, request)
	if err != nil {
		credentialprotocol.WipeSSHAgentBytes(response)
		return nil, ErrAgentIO
	}
	return response, nil
}

func (connection *verifiedConnection) beginOperation() error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.closing || connection.closed {
		return ErrConnectionClosed
	}
	if connection.inflight == 0 {
		connection.inflightZero = make(chan struct{})
	}
	connection.inflight++
	return nil
}

func (connection *verifiedConnection) endOperation() {
	connection.mu.Lock()
	connection.inflight--
	if connection.inflight == 0 {
		close(connection.inflightZero)
	}
	connection.mu.Unlock()
}

func (connection *verifiedConnection) Close(ctx context.Context) error {
	if connection == nil || !configuredDependency(ctx) {
		return ErrInvalidArgument
	}
	connection.closeMu.Lock()
	defer connection.closeMu.Unlock()
	connection.mu.Lock()
	if connection.closed {
		connection.mu.Unlock()
		return nil
	}
	connection.closing = true
	inflightZero := connection.inflightZero
	agentClosed := connection.agentClosed
	connection.mu.Unlock()

	if !agentClosed {
		if err := safeAgentClose(ctx, connection.agent); err != nil {
			return ErrCleanupIncomplete
		}
		connection.mu.Lock()
		connection.agentClosed = true
		connection.mu.Unlock()
	}
	select {
	case <-inflightZero:
	case <-ctx.Done():
		return ErrCleanupIncomplete
	}
	connection.mu.Lock()
	connection.closed = true
	connection.agent = nil
	connection.policy = nil
	connection.mu.Unlock()
	connection.relay.Close()
	connection.lease.releaseConnection(connection)
	return nil
}

var _ VerifiedAgentConnection = (*verifiedConnection)(nil)
