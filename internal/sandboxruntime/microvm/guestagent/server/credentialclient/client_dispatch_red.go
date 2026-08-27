package credentialclient

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

func (client *Client) serveCredentialLifecycle(ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = clientError(ClientContractPanic, ClientFieldLifecycle)
		}
	}()
	if ctx == nil || client == nil || client.state == nil {
		return clientError(ClientContractDependency, ClientFieldLifecycle)
	}
	authenticated, ok := client.transport.(authenticatedTransport)
	if !ok {
		return clientError(ClientContractDependency, ClientFieldDependency)
	}
	identity := authenticated.Identity()
	if identity.sessionIDValue() == ([32]byte{}) || !validControlSessionIdentity(identity.sessionIdentity()) ||
		identity.hardExpiryValue().IsZero() || credentialprotocol.ValidateSafeID(identity.helperGenerationValue()) != nil {
		return clientError(ClientContractDependency, ClientFieldDependency)
	}
	nextSequence := uint64(1)
	for {
		if client.drainStarted() {
			return nil
		}
		receive, receiveErr := newControlReceiveRequest(nextSequence, v2control.NewIdentityDigest(identity.sessionIDValue()), true, session.MaxControlPlaintextBytes)
		if receiveErr != nil {
			return clientError(ClientContractPacket, ClientFieldPacketType)
		}
		packet, dispatchErr, panicked := client.receiveControllerPacket(ctx, receive)
		if panicked {
			return clientError(ClientContractPanic, ClientFieldPacketType)
		}
		if dispatchErr != nil {
			if client.drainStarted() || ctx.Err() != nil {
				return nil
			}
			return clientError(ClientContractPacket, ClientFieldPacketType)
		}
		if packet.sessionIDValue() != identity.sessionIDValue() {
			return clientError(ClientContractPacket, ClientFieldPacketType)
		}
		nextSequence++
		if readiness, ready := packet.readinessValue(); ready {
			if sendErr := client.dispatchReadinessResponse(ctx, identity, packet, readiness); sendErr != nil {
				return sendErr
			}
			continue
		}
		if client.drainStarted() || ctx.Err() != nil {
			return nil
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
}

func (client *Client) dispatchReadinessResponse(ctx context.Context, identity transportIdentity, packet ControllerPacket, readiness v2control.ReadinessRequest) error {
	response, err := v2control.NewReadinessSuccessResponse(readiness, string(identity.helperGenerationValue()))
	if err != nil {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	send, err := newControllerReadinessSendPacket(packet.sequenceValue(), packet.sessionIDValue(), response)
	if err != nil {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if sendErr := client.transport.SendController(ctx, send); sendErr != nil {
		if client.drainStarted() || ctx.Err() != nil {
			return nil
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return nil
}

func (client *Client) receiveControllerPacket(ctx context.Context, request ControllerReceiveRequest) (packet ControllerPacket, err error, panicked bool) {
	if !client.beginAdmittedReceive() {
		return ControllerPacket{}, errInvalidControlReceiveRequest, false
	}
	defer client.endAdmittedReceive()
	defer func() {
		if recover() != nil {
			packet = ControllerPacket{}
			err = nil
			panicked = true
		}
	}()
	packet, err = client.transport.ReceiveController(ctx, request)
	return packet, err, false
}

func (client *Client) beginAdmittedReceive() bool {
	state := client.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closeStarted {
		return false
	}
	state.admittedReceives.Add(1)
	return true
}

func (client *Client) endAdmittedReceive() {
	client.state.admittedReceives.Done()
}

func (client *Client) drainStarted() bool {
	client.state.mu.Lock()
	defer client.state.mu.Unlock()
	return client.state.closeStarted
}
