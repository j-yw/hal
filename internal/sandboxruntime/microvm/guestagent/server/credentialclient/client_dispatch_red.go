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
	var expectedIdentity v2control.IdentityDigest
	expectedIdentitySet := false
	for {
		if client.drainStarted() {
			return nil
		}
		receive, receiveErr := newControlReceiveRequest(nextSequence, expectedIdentity, expectedIdentitySet, session.MaxControlPlaintextBytes)
		if receiveErr != nil {
			return clientError(ClientContractPacket, ClientFieldPacketType)
		}
		packet, dispatchErr, panicked := client.receiveControllerPacket(ctx, receive)
		if panicked {
			return clientError(ClientContractPanic, ClientFieldPacketType)
		}
		bodyPresent, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return clientError(ClientContractCleanup, ClientFieldBody)
		}
		if bodyPresent {
			return clientError(ClientContractPacket, ClientFieldBody)
		}
		if dispatchErr != nil {
			if client.drainStarted() || ctx.Err() != nil {
				return nil
			}
			return clientError(ClientContractPacket, ClientFieldPacketType)
		}
		if packet.sequenceValue() != nextSequence || packet.sessionIDValue() != identity.sessionIDValue() {
			return clientError(ClientContractPacket, ClientFieldPacketType)
		}
		nextSequence++
		if readiness, ready := packet.readinessValue(); ready {
			if expectedIdentitySet {
				return clientError(ClientContractPacket, ClientFieldIdentity)
			}
			if sendErr := client.dispatchReadinessResponse(ctx, identity, packet, readiness); sendErr != nil {
				return sendErr
			}
			continue
		}
		if prepare, ok := packet.prepareValue(); ok {
			digest, digestErr := acceptControllerPrepareIdentity(identity.sessionIDValue(), identity.hardExpiryValue().UnixNano(), prepare, expectedIdentity, expectedIdentitySet)
			if digestErr != nil {
				return digestErr
			}
			expectedIdentity = digest
			expectedIdentitySet = true
			if sendErr := client.dispatchHelperPrepareBegin(ctx, identity, prepare, digest); sendErr != nil {
				return sendErr
			}
			return helperPacketDependencyUnaccepted(expectedIdentity)
		}
		if renew, ok := packet.renewValue(); ok {
			if err := requirePinnedCredentialIdentity(expectedIdentitySet, expectedIdentity, renew.IdentityDigest()); err != nil {
				return err
			}
			return helperPacketDependencyUnaccepted(expectedIdentity)
		}
		if revoke, ok := packet.revokeValue(); ok {
			if err := requirePinnedCredentialIdentity(expectedIdentitySet, expectedIdentity, revoke.IdentityDigest()); err != nil {
				return err
			}
			return helperPacketDependencyUnaccepted(expectedIdentity)
		}
		if exec, ok := packet.execValue(); ok {
			if err := requirePinnedCredentialIdentity(expectedIdentitySet, expectedIdentity, exec.IdentityDigest()); err != nil {
				return err
			}
			return helperPacketDependencyUnaccepted(expectedIdentity)
		}
		if client.drainStarted() || ctx.Err() != nil {
			return nil
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
}

// rejectControllerPacketBody closes the current default-off boundary: no
// controller payload arm has a live consumer yet. Future payload forwarding
// must explicitly transfer and clear this owner before dispatch continues.
func rejectControllerPacketBody(packet *ControllerPacket) (present bool, cleanupErr error) {
	if packet == nil || packet.body == nil {
		return false, nil
	}
	body := packet.body
	packet.body = nil
	if !configuredDependency(body) {
		return true, nil
	}
	return true, destroyControllerBody(body)
}

func acceptControllerPrepareIdentity(sessionID [32]byte, hardExpiryUnixNano int64, prepare v2control.CredentialPrepareRequest, expectedIdentity v2control.IdentityDigest, expectedIdentitySet bool) (v2control.IdentityDigest, error) {
	if expectedIdentitySet {
		if prepare.IdentityDigest() != expectedIdentity {
			return v2control.IdentityDigest{}, clientError(ClientContractPacket, ClientFieldIdentity)
		}
		return expectedIdentity, nil
	}
	wire, err := v2control.EncodeCredentialPrepareRequest(prepare)
	if err != nil {
		return v2control.IdentityDigest{}, clientError(ClientContractPacket, ClientFieldIdentity)
	}
	decoded, err := v2control.DecodeInitialCredentialPrepareRequest(sessionID, wire)
	if err != nil {
		return v2control.IdentityDigest{}, clientError(ClientContractPacket, ClientFieldIdentity)
	}
	if v2control.ValidateCredentialPrepareRequestExpiry(decoded, hardExpiryUnixNano) != nil {
		return v2control.IdentityDigest{}, clientError(ClientContractPacket, ClientFieldIdentity)
	}
	reconstructed, err := v2control.NewGuestCredentialSessionIdentity(sessionID, decoded.Identity())
	if err != nil {
		return v2control.IdentityDigest{}, clientError(ClientContractPacket, ClientFieldIdentity)
	}
	digestBytes, err := v2control.GuestCredentialSessionIdentityDigest(reconstructed)
	if err != nil {
		return v2control.IdentityDigest{}, clientError(ClientContractPacket, ClientFieldIdentity)
	}
	digest := v2control.NewIdentityDigest(digestBytes)
	if digest != decoded.IdentityDigest() || digest == v2control.NewIdentityDigest(sessionID) {
		return v2control.IdentityDigest{}, clientError(ClientContractPacket, ClientFieldIdentity)
	}
	return digest, nil
}

func requirePinnedCredentialIdentity(expectedIdentitySet bool, expected, observed v2control.IdentityDigest) error {
	if !expectedIdentitySet || expected == (v2control.IdentityDigest{}) || observed != expected {
		return clientError(ClientContractPacket, ClientFieldIdentity)
	}
	return nil
}

func helperPacketDependencyUnaccepted(identity v2control.IdentityDigest) error {
	// Helper receive and metadata-only helper send constructors exist. An
	// injected HelperConnectionOwner may send prepare-begin. Payload-bearing
	// helper send, SCM_RIGHTS SSH send, and JobCredential proofs remain
	// unaccepted; do not mint proofs.
	_, err := newHelperControlReceiveRequest(1, credentialprotocol.MaxHelperPacketBodyBytes, 0, [16]byte{}, false, identity.Bytes())
	if err != nil {
		return err
	}
	return ErrClientControlDependencyUnaccepted
}

func (client *Client) dispatchHelperPrepareBegin(
	ctx context.Context,
	identity transportIdentity,
	prepare v2control.CredentialPrepareRequest,
	digest v2control.IdentityDigest,
) error {
	if !configuredDependency(client.helper) {
		return nil
	}
	expectation, err := newHelperAcceptExpectation(
		identity.sessionIDValue(),
		digest.Bytes(),
		identity.helperGenerationValue(),
		identity.sessionIdentity().GuestBootNonce,
	)
	if err != nil {
		return clientError(ClientContractDependency, ClientFieldDependency)
	}
	stream, acceptErr := client.helper.AcceptVerified(ctx, expectation)
	if acceptErr != nil || !configuredDependency(stream) {
		if client.drainStarted() || ctx.Err() != nil {
			return nil
		}
		return clientError(ClientContractDependency, ClientFieldDependency)
	}
	body, bodyErr := helperPrepareBeginBodyFromPrepare(prepare)
	if bodyErr != nil {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	header := credentialprotocol.HelperPacketHeader{
		Sequence:                      firstInjectedHelperSendSequence,
		RequestID:                     prepare.RequestID().Bytes(),
		GuestCredentialIdentityDigest: digest.Bytes(),
		BootNonce:                     identity.sessionIdentity().GuestBootNonce,
	}
	send, sendErr := newHelperPrepareBeginSendPacket(header, body)
	if sendErr != nil {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if helperErr := client.transport.SendHelper(ctx, send); helperErr != nil {
		if client.drainStarted() || ctx.Err() != nil {
			return nil
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if helperSendPacketUnconsumed(send) {
		if writeErr := writeHelperSendPacket(ctx, stream, send); writeErr != nil {
			if client.drainStarted() || ctx.Err() != nil {
				return nil
			}
			return clientError(ClientContractPacket, ClientFieldPacketType)
		}
	}
	return nil
}

func (client *Client) dispatchReadinessResponse(ctx context.Context, identity transportIdentity, packet ControllerPacket, readiness v2control.ReadinessRequest) error {
	response, err := v2control.NewReadinessSuccessResponse(readiness, string(identity.helperGenerationValue()))
	if err != nil {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	send, err := newControllerReadinessSendPacket(packet, response)
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
