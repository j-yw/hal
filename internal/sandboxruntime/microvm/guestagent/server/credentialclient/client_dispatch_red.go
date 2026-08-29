package credentialclient

import (
	"context"
	"errors"

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
	nextHelperSequence := firstInjectedHelperSendSequence
	nextHelperReceiveSequence := firstInjectedHelperSendSequence
	var expectedIdentity v2control.IdentityDigest
	expectedIdentitySet := false
	var helperStream VerifiedHelperStream
	var ledger *helperActiveLedger
	for {
		if client.drainStarted() {
			return nil
		}
		if ledger != nil && configuredDependency(helperStream) {
			nextReceive, sshErr := client.drainIdleHelperSSHAccepted(ctx, helperStream, expectedIdentity, ledger, nextHelperReceiveSequence)
			if sshErr != nil {
				return sshErr
			}
			nextHelperReceiveSequence = nextReceive
			if client.drainStarted() || ctx.Err() != nil {
				return nil
			}
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
		if ledger != nil && configuredDependency(helperStream) {
			nextReceive, sshErr := client.drainIdleHelperSSHAccepted(ctx, helperStream, expectedIdentity, ledger, nextHelperReceiveSequence)
			if sshErr != nil {
				return sshErr
			}
			nextHelperReceiveSequence = nextReceive
			if client.drainStarted() || ctx.Err() != nil {
				return nil
			}
		}
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
			if expectedIdentitySet || ledger != nil {
				return clientError(ClientContractCorrelation, ClientFieldRequestID)
			}
			digest, digestErr := acceptControllerPrepareIdentity(identity.sessionIDValue(), identity.hardExpiryValue().UnixNano(), prepare, expectedIdentity, expectedIdentitySet)
			if digestErr != nil {
				return digestErr
			}
			expectedIdentity = digest
			expectedIdentitySet = true
			if authErr := client.authorizeHelperSend(credentialprotocol.PacketTypePrepareBegin, digest, prepare.Revision(), prepare.Bindings()); authErr != nil {
				return authErr
			}
			stream, sendErr := client.dispatchHelperPrepareBegin(ctx, identity, prepare, digest, nextHelperSequence)
			if sendErr != nil {
				return sendErr
			}
			if !configuredDependency(stream) {
				if client.drainStarted() || ctx.Err() != nil {
					return nil
				}
				return helperPacketDependencyUnaccepted(expectedIdentity)
			}
			if client.drainStarted() || ctx.Err() != nil {
				return nil
			}
			nextHelperSequence++
			sendSequence := nextHelperSequence
			var fileErr error
			sendSequence, nextSequence, fileErr = client.dispatchHelperPrepareFiles(
				ctx, stream, prepare, identity, digest, sendSequence, nextSequence,
			)
			if fileErr != nil {
				return fileErr
			}
			if client.drainStarted() || ctx.Err() != nil {
				return nil
			}
			installed, nextSend, nextReceive, commitErr := client.dispatchMetadataOnlyPrepareCommit(
				ctx, stream, packet, prepare, identity, digest, sendSequence, nextHelperReceiveSequence,
			)
			if commitErr != nil {
				return commitErr
			}
			if client.drainStarted() || ctx.Err() != nil {
				return nil
			}
			if installed == nil {
				return helperPacketDependencyUnaccepted(expectedIdentity)
			}
			helperStream = stream
			ledger = installed
			nextHelperSequence = nextSend
			nextHelperReceiveSequence = nextReceive
			continue
		}
		if renew, ok := packet.renewValue(); ok {
			if err := requirePinnedCredentialIdentity(expectedIdentitySet, expectedIdentity, renew.IdentityDigest()); err != nil {
				return err
			}
			if ledger == nil || !configuredDependency(helperStream) {
				return helperPacketDependencyUnaccepted(expectedIdentity)
			}
			nextSend, nextReceive, renewErr := client.dispatchHelperRenew(
				ctx, helperStream, packet, renew, identity, expectedIdentity, ledger, nextHelperSequence, nextHelperReceiveSequence,
			)
			if renewErr != nil {
				return renewErr
			}
			if client.drainStarted() || ctx.Err() != nil {
				return nil
			}
			nextHelperSequence = nextSend
			nextHelperReceiveSequence = nextReceive
			continue
		}
		if revoke, ok := packet.revokeValue(); ok {
			if err := requirePinnedCredentialIdentity(expectedIdentitySet, expectedIdentity, revoke.IdentityDigest()); err != nil {
				return err
			}
			if ledger == nil || !configuredDependency(helperStream) {
				return helperPacketDependencyUnaccepted(expectedIdentity)
			}
			nextSend, nextReceive, revokeErr := client.dispatchHelperRevoke(
				ctx, helperStream, packet, revoke, identity, expectedIdentity, ledger, nextHelperSequence, nextHelperReceiveSequence,
			)
			if revokeErr != nil {
				return revokeErr
			}
			if client.drainStarted() || ctx.Err() != nil {
				return nil
			}
			ledger = nil
			nextHelperSequence = nextSend
			nextHelperReceiveSequence = nextReceive
			continue
		}
		if exec, ok := packet.execValue(); ok {
			if err := requirePinnedCredentialIdentity(expectedIdentitySet, expectedIdentity, exec.IdentityDigest()); err != nil {
				return err
			}
			if ledger == nil || !configuredDependency(helperStream) {
				return helperPacketDependencyUnaccepted(expectedIdentity)
			}
			nextSend, nextReceive, nextCtrl, execErr := client.dispatchHelperExec(
				ctx, helperStream, packet, exec, identity, expectedIdentity, ledger,
				nextHelperSequence, nextHelperReceiveSequence, nextSequence,
			)
			if execErr != nil {
				return execErr
			}
			if client.drainStarted() || ctx.Err() != nil {
				return nil
			}
			nextHelperSequence = nextSend
			nextHelperReceiveSequence = nextReceive
			nextSequence = nextCtrl
			continue
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
	// Mismatched prepare-file, exec-private, or exec-stream payload,
	// helper-to-agent packets that are not an authenticated SCM_RIGHTS
	// SSH accepted FD, JobCredential proof minting, and a nil
	// HelperConnectionOwner stay unaccepted.
	_, err := newHelperControlReceiveRequest(1, credentialprotocol.MaxHelperPacketBodyBytes, 0, [16]byte{}, false, identity.Bytes())
	if err != nil {
		return err
	}
	return ErrClientControlDependencyUnaccepted
}

func (client *Client) drainIdleHelperSSHAccepted(
	ctx context.Context,
	stream VerifiedHelperStream,
	digest v2control.IdentityDigest,
	ledger *helperActiveLedger,
	receiveSequence uint64,
) (uint64, error) {
	if !configuredDependency(stream) || ledger == nil {
		return receiveSequence, helperPacketDependencyUnaccepted(digest)
	}
	if client.drainStarted() || ctx.Err() != nil {
		return receiveSequence, nil
	}
	request, err := newHelperControlReceiveRequest(
		receiveSequence,
		credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength(),
		1,
		[16]byte{},
		false,
		digest.Bytes(),
	)
	if err != nil {
		return receiveSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if !client.beginAdmittedOperation() {
		return receiveSequence, nil
	}
	packet, received, readErr := tryReadHelperSSHAcceptedPacket(ctx, stream, request)
	if readErr != nil {
		client.endAdmittedOperation()
		closeErr := closeHelperSSHAccepted(packet)
		if client.drainStarted() || ctx.Err() != nil {
			return receiveSequence, nil
		}
		if closeErr != nil {
			return receiveSequence, clientError(ClientContractCleanup, ClientFieldRight)
		}
		if errors.Is(readErr, ErrClientControlDependencyUnaccepted) {
			return receiveSequence, helperPacketDependencyUnaccepted(digest)
		}
		return receiveSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if !received {
		client.endAdmittedOperation()
		return receiveSequence, nil
	}
	dispatchErr := client.dispatchHelperSSHAccepted(ctx, packet, digest, ledger)
	client.endAdmittedOperation()
	if dispatchErr != nil {
		return receiveSequence, dispatchErr
	}
	return receiveSequence + 1, nil
}

func (client *Client) dispatchHelperSSHAccepted(
	ctx context.Context,
	packet HelperPacket,
	digest v2control.IdentityDigest,
	ledger *helperActiveLedger,
) (err error) {
	extension, converted := extensionPacketFromHelperSSH(packet, digest)
	defer func() {
		if recover() != nil {
			if closeErr := closeOwnedExtensionPacket(ctx, extension); closeErr != nil {
				err = clientError(ClientContractCleanup, ClientFieldRight)
				return
			}
			err = clientError(ClientContractPanic, ClientFieldExtension)
		}
	}()
	if !converted {
		if closeErr := closeHelperSSHAccepted(packet); closeErr != nil {
			return clientError(ClientContractCleanup, ClientFieldRight)
		}
		return helperPacketDependencyUnaccepted(digest)
	}
	if ledger == nil || ledger.identityDigest != digest ||
		packet.headerValue().GuestCredentialIdentityDigest != digest.Bytes() ||
		packet.headerValue().Sequence == 0 {
		if closeErr := closeOwnedExtensionPacket(ctx, extension); closeErr != nil {
			return clientError(ClientContractCleanup, ClientFieldRight)
		}
		return helperPacketDependencyUnaccepted(digest)
	}
	accepted, ok := extension.SSHAccepted()
	if !ok || accepted.Revision() != ledger.revision {
		if closeErr := closeOwnedExtensionPacket(ctx, extension); closeErr != nil {
			return clientError(ClientContractCleanup, ClientFieldRight)
		}
		return helperPacketDependencyUnaccepted(digest)
	}
	if int(accepted.BindingIndex()) >= len(ledger.records) ||
		ledger.records[accepted.BindingIndex()].Mode != credentialprotocol.DeliveryModeSSHAgent {
		if closeErr := closeOwnedExtensionPacket(ctx, extension); closeErr != nil {
			return clientError(ClientContractCleanup, ClientFieldRight)
		}
		return helperPacketDependencyUnaccepted(digest)
	}
	session, found := client.sshExtensionSession()
	if !found || !configuredDependency(session) {
		if closeErr := closeOwnedExtensionPacket(ctx, extension); closeErr != nil {
			return clientError(ClientContractCleanup, ClientFieldRight)
		}
		return helperPacketDependencyUnaccepted(digest)
	}
	handleErr := session.Handle(ctx, extension)
	if handleErr != nil {
		if closeErr := closeOwnedExtensionPacket(ctx, extension); closeErr != nil {
			return clientError(ClientContractCleanup, ClientFieldRight)
		}
		return helperPacketDependencyUnaccepted(digest)
	}
	if commitErr := commitExtensionPacketOwnership(extension); commitErr != nil {
		if closeErr := closeOwnedExtensionPacket(ctx, extension); closeErr != nil {
			return clientError(ClientContractCleanup, ClientFieldRight)
		}
		return clientError(ClientContractOwnership, ClientFieldRight)
	}
	return nil
}

func extensionPacketFromHelperSSH(packet HelperPacket, digest v2control.IdentityDigest) (ExtensionPacket, bool) {
	accepted, ok := packet.sshAcceptedValue()
	if !ok || accepted.ownership == nil {
		return ExtensionPacket{}, false
	}
	return ExtensionPacket{
		packetType: credentialprotocol.PacketTypeSSHAcceptedFD,
		metadata: extensionPacketMetadata{
			identityDigest:   digest.Bytes(),
			revision:         accepted.Revision(),
			bindingIndex:     accepted.BindingIndex(),
			ordinal:          accepted.Ordinal(),
			capabilitySHA256: accepted.CapabilitySHA256(),
		},
		ownership: accepted.ownership,
	}, true
}

func closeHelperSSHAccepted(packet HelperPacket) error {
	accepted, ok := packet.sshAcceptedValue()
	if !ok || accepted.ownership == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), sshConnectionCleanupTimeout)
	defer cancel()
	return closeOwnedExtensionPacket(ctx, ExtensionPacket{ownership: accepted.ownership})
}

func (client *Client) sshExtensionSession() (ExtensionSession, bool) {
	if client == nil || client.state == nil {
		return nil, false
	}
	client.state.mu.Lock()
	defer client.state.mu.Unlock()
	for _, opened := range client.state.opened {
		for _, packetType := range opened.descriptor.HelperToAgentPacketTypes {
			if packetType == credentialprotocol.PacketTypeSSHAcceptedFD && configuredDependency(opened.session) {
				return opened.session, true
			}
		}
	}
	return nil, false
}

func (client *Client) dispatchHelperPrepareFiles(
	ctx context.Context,
	stream VerifiedHelperStream,
	prepare v2control.CredentialPrepareRequest,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	sendSequence, controllerSequence uint64,
) (uint64, uint64, error) {
	records, _, err := projectV2ManifestToHelperRecords(prepare.Bindings())
	if err != nil {
		return sendSequence, controllerSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	indexes, aggregate, aggErr := helperOrderedFileTmpfsIndexes(records)
	if aggErr != nil {
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	if uint32(len(indexes)) != prepare.PrivateRecordCount() || aggregate != prepare.PrivateAggregateBytes() {
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	if len(indexes) == 0 {
		return sendSequence, controllerSequence, nil
	}
	if !configuredDependency(stream) {
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	var running uint64
	for _, bindingIndex := range indexes {
		if client.drainStarted() || ctx.Err() != nil {
			return sendSequence, controllerSequence, nil
		}
		if int(bindingIndex) >= len(records) {
			return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
		}
		record := records[bindingIndex]
		if record.Mode != credentialprotocol.DeliveryModeFileTmpfs {
			return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
		}
		if running > credentialprotocol.MaxHelperFileAggregateBytes-uint64(record.DeclaredFileBytes) {
			return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
		}
		running += uint64(record.DeclaredFileBytes)
		nextSend, nextCtrl, sendErr := client.dispatchOneHelperPrepareFile(
			ctx, stream, prepare, identity, digest, record, bindingIndex, sendSequence, controllerSequence,
		)
		if sendErr != nil {
			return sendSequence, controllerSequence, sendErr
		}
		sendSequence = nextSend
		controllerSequence = nextCtrl
	}
	if running != prepare.PrivateAggregateBytes() || running > credentialprotocol.MaxHelperFileAggregateBytes {
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	return sendSequence, controllerSequence, nil
}

func (client *Client) dispatchOneHelperPrepareFile(
	ctx context.Context,
	stream VerifiedHelperStream,
	prepare v2control.CredentialPrepareRequest,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	record credentialprotocol.HelperBindingManifestRecord,
	bindingIndex uint16,
	sendSequence, controllerSequence uint64,
) (nextSendSequence, nextControllerSequence uint64, returnErr error) {
	if !configuredDependency(stream) {
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	receive, receiveErr := newControlReceiveRequest(controllerSequence, digest, true, session.MaxControlPlaintextBytes)
	if receiveErr != nil {
		return sendSequence, controllerSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	packet, dispatchErr, panicked := client.receiveControllerPacket(ctx, receive)
	if panicked {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, clientError(ClientContractPanic, ClientFieldPacketType)
	}
	if dispatchErr != nil {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		if client.drainStarted() || ctx.Err() != nil {
			return sendSequence, controllerSequence, nil
		}
		return sendSequence, controllerSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if packet.sequenceValue() != controllerSequence || packet.sessionIDValue() != identity.sessionIDValue() {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	controllerSequence++
	if _, isPrepare := packet.prepareValue(); isPrepare {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	if _, isStream := packet.streamValue(); isStream {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	private, ok := packet.privateValue()
	if !ok {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	body := packet.body
	packet.body = nil
	defer func() {
		if cleanupErr := destroyControllerBody(body); cleanupErr != nil {
			returnErr = clientError(ClientContractCleanup, ClientFieldBody)
		}
	}()
	if private.kind != credentialprotocol.PrivateRecordKindFileBytes ||
		private.kind == credentialprotocol.PrivateRecordKindOpaqueExecBinding ||
		private.requestID != prepare.RequestID() ||
		private.identityDigest != digest ||
		private.bindingIndex != bindingIndex ||
		private.chunkIndex != 0 ||
		private.chunkCount != 1 ||
		record.Mode != credentialprotocol.DeliveryModeFileTmpfs ||
		private.payloadLength != record.DeclaredFileBytes ||
		private.payloadSHA256 != record.FileSHA256 {
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	owner, copyErr := copyControllerPrepareFileOwner(ctx, body, prepare.Revision(), bindingIndex, record.FileSHA256, record.DeclaredFileBytes)
	if copyErr != nil {
		wipeHelperPrepareFileOwner(owner)
		if client.drainStarted() || ctx.Err() != nil {
			return sendSequence, controllerSequence, nil
		}
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	defer wipeHelperPrepareFileOwner(owner)
	if client.drainStarted() || ctx.Err() != nil {
		return sendSequence, controllerSequence, nil
	}
	if writeErr := client.writePinnedHelperPrepareFile(ctx, stream, sendSequence, identity, digest, prepare.RequestID().Bytes(), owner); writeErr != nil {
		return sendSequence, controllerSequence, writeErr
	}
	return sendSequence + 1, controllerSequence, nil
}

func (client *Client) writePinnedHelperPrepareFile(
	ctx context.Context,
	stream VerifiedHelperStream,
	sequence uint64,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	requestID [16]byte,
	owner *helperPrepareFileOwner,
) error {
	if !configuredDependency(stream) || owner == nil || owner.body == nil {
		return helperPacketDependencyUnaccepted(digest)
	}
	if sequence == 0 || sequence > uint64(^uint32(0)) {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if !client.beginAdmittedOperation() {
		return nil
	}
	defer client.endAdmittedOperation()
	send, sendErr := newHelperPrepareFileSendPacket(injectedHelperSendHeader(sequence, requestID, digest, identity.sessionIdentity().GuestBootNonce), owner)
	if sendErr != nil {
		if errors.Is(sendErr, ErrClientControlDependencyUnaccepted) {
			return helperPacketDependencyUnaccepted(digest)
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if writeErr := writeHelperSendPacket(ctx, stream, send); writeErr != nil {
		if client.drainStarted() || ctx.Err() != nil {
			return nil
		}
		if errors.Is(writeErr, ErrClientControlDependencyUnaccepted) {
			return helperPacketDependencyUnaccepted(digest)
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return nil
}

func (client *Client) dispatchHelperPrepareBegin(
	ctx context.Context,
	identity transportIdentity,
	prepare v2control.CredentialPrepareRequest,
	digest v2control.IdentityDigest,
	sequence uint64,
) (VerifiedHelperStream, error) {
	if !configuredDependency(client.helper) {
		return nil, nil
	}
	if !client.beginAdmittedOperation() {
		return nil, nil
	}
	defer client.endAdmittedOperation()
	expectation, err := newHelperAcceptExpectation(
		identity.sessionIDValue(),
		digest.Bytes(),
		identity.helperGenerationValue(),
		identity.sessionIdentity().GuestBootNonce,
	)
	if err != nil {
		return nil, clientError(ClientContractDependency, ClientFieldDependency)
	}
	stream, acceptErr := client.helper.AcceptVerified(ctx, expectation)
	if acceptErr != nil || !configuredDependency(stream) {
		if client.drainStarted() || ctx.Err() != nil {
			return nil, nil
		}
		return nil, clientError(ClientContractDependency, ClientFieldDependency)
	}
	body, bodyErr := helperPrepareBeginBodyFromPrepare(prepare)
	if bodyErr != nil {
		return nil, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	send, sendErr := newHelperPrepareBeginSendPacket(injectedHelperSendHeader(sequence, prepare.RequestID().Bytes(), digest, identity.sessionIdentity().GuestBootNonce), body)
	if sendErr != nil {
		return nil, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if writeErr := writeHelperSendPacket(ctx, stream, send); writeErr != nil {
		if client.drainStarted() || ctx.Err() != nil {
			return nil, nil
		}
		return nil, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return stream, nil
}

func (client *Client) dispatchMetadataOnlyPrepareCommit(
	ctx context.Context,
	stream VerifiedHelperStream,
	controllerPacket ControllerPacket,
	prepare v2control.CredentialPrepareRequest,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	sendSequence, receiveSequence uint64,
) (*helperActiveLedger, uint64, uint64, error) {
	records, manifestSHA256, projectErr := projectV2ManifestToHelperRecords(prepare.Bindings())
	if projectErr != nil {
		return nil, sendSequence, receiveSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if writeErr := client.writePinnedHelperMetadata(ctx, stream, sendSequence, identity, digest, prepare.RequestID().Bytes(), func(header credentialprotocol.HelperPacketHeader) (HelperSendPacket, error) {
		body, err := helperPrepareCommitBodyFromPrepare(prepare)
		if err != nil {
			return HelperSendPacket{}, err
		}
		return newHelperPrepareCommitSendPacket(header, body)
	}); writeErr != nil {
		return nil, sendSequence, receiveSequence, writeErr
	}
	if client.drainStarted() || ctx.Err() != nil {
		return nil, sendSequence, receiveSequence, nil
	}
	helperPacket, receiveErr := client.receiveHelperResponse(ctx, stream, receiveSequence, prepare.RequestID().Bytes(), digest.Bytes())
	if receiveErr != nil {
		return nil, sendSequence, receiveSequence, receiveErr
	}
	if client.drainStarted() || ctx.Err() != nil {
		return nil, sendSequence, receiveSequence, nil
	}
	response, ok := helperPacket.responseValue()
	if !ok || response.RequestType != credentialprotocol.PacketTypePrepareCommit || response.Prepare == nil {
		return nil, sendSequence, receiveSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if !helperProofsMatchProjectedRecords(response.Prepare.BindingProofs, records) {
		return nil, sendSequence, receiveSequence, clientError(ClientContractCorrelation, ClientFieldBody)
	}
	mapped, mapErr := mapHelperPrepareSuccessToV2(prepare, helperPacket.headerValue(), response)
	if mapErr != nil {
		return nil, sendSequence, receiveSequence, clientError(ClientContractCorrelation, ClientFieldBody)
	}
	installed, installErr := newHelperActiveLedger(
		digest,
		prepare.RequestID().Bytes(),
		identity.helperGenerationValue(),
		manifestSHA256,
		prepare.Revision(),
		prepare.ExpiresAtUnixNano(),
		response.Prepare.BindingProofs,
		records,
		prepare.Bindings(),
		response.Prepare.ActiveProofID,
		response.Prepare.ExecBindingID,
	)
	if installErr != nil {
		return nil, sendSequence, receiveSequence, clientError(ClientContractCorrelation, ClientFieldBody)
	}
	if sendErr := client.sendControllerPrepareSuccess(ctx, controllerPacket, mapped); sendErr != nil {
		return nil, sendSequence, receiveSequence, sendErr
	}
	return installed, sendSequence + 1, receiveSequence + 1, nil
}

func (client *Client) dispatchHelperRenew(
	ctx context.Context,
	stream VerifiedHelperStream,
	controllerPacket ControllerPacket,
	renew v2control.CredentialRenewRequest,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	ledger *helperActiveLedger,
	sendSequence, receiveSequence uint64,
) (uint64, uint64, error) {
	if ledger == nil || renew.Revision() != ledger.revision+1 || renew.PriorProofID() != ledger.activeProofID {
		return sendSequence, receiveSequence, clientError(ClientContractCorrelation, ClientFieldRevision)
	}
	if authErr := client.authorizeHelperSend(credentialprotocol.PacketTypeRenew, digest, renew.Revision(), nil); authErr != nil {
		return sendSequence, receiveSequence, authErr
	}
	if writeErr := client.writePinnedHelperMetadata(ctx, stream, sendSequence, identity, digest, renew.RequestID().Bytes(), func(header credentialprotocol.HelperPacketHeader) (HelperSendPacket, error) {
		body, err := helperRenewBodyFromRenew(renew)
		if err != nil {
			return HelperSendPacket{}, err
		}
		return newHelperRenewSendPacket(header, body)
	}); writeErr != nil {
		return sendSequence, receiveSequence, writeErr
	}
	if client.drainStarted() || ctx.Err() != nil {
		return sendSequence, receiveSequence, nil
	}
	helperPacket, receiveErr := client.receiveHelperResponse(ctx, stream, receiveSequence, renew.RequestID().Bytes(), digest.Bytes())
	if receiveErr != nil {
		return sendSequence, receiveSequence, receiveErr
	}
	if client.drainStarted() || ctx.Err() != nil {
		return sendSequence, receiveSequence, nil
	}
	response, ok := helperPacket.responseValue()
	if !ok {
		return sendSequence, receiveSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	mapped, mapErr := mapHelperRenewSuccessToV2(renew, helperPacket.headerValue(), response)
	if mapErr != nil {
		return sendSequence, receiveSequence, clientError(ClientContractCorrelation, ClientFieldBody)
	}
	if sendErr := client.sendControllerRenewSuccess(ctx, controllerPacket, mapped); sendErr != nil {
		return sendSequence, receiveSequence, sendErr
	}
	ledger.revision = renew.Revision()
	ledger.expiryUnixNano = renew.ExpiresAtUnixNano()
	ledger.activeProofID = mapped.ReplacementActiveProofID()
	return sendSequence + 1, receiveSequence + 1, nil
}

func (client *Client) dispatchHelperRevoke(
	ctx context.Context,
	stream VerifiedHelperStream,
	controllerPacket ControllerPacket,
	revoke v2control.CredentialRevokeRequest,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	ledger *helperActiveLedger,
	sendSequence, receiveSequence uint64,
) (uint64, uint64, error) {
	if ledger == nil || revoke.Revision() != ledger.revision {
		return sendSequence, receiveSequence, clientError(ClientContractCorrelation, ClientFieldRevision)
	}
	if authErr := client.authorizeHelperSend(credentialprotocol.PacketTypeRevoke, digest, revoke.Revision(), nil); authErr != nil {
		return sendSequence, receiveSequence, authErr
	}
	if writeErr := client.writePinnedHelperMetadata(ctx, stream, sendSequence, identity, digest, revoke.RequestID().Bytes(), func(header credentialprotocol.HelperPacketHeader) (HelperSendPacket, error) {
		body, err := helperRevokeBodyFromRevoke(revoke)
		if err != nil {
			return HelperSendPacket{}, err
		}
		return newHelperRevokeSendPacket(header, body)
	}); writeErr != nil {
		return sendSequence, receiveSequence, writeErr
	}
	if client.drainStarted() || ctx.Err() != nil {
		return sendSequence, receiveSequence, nil
	}
	helperPacket, receiveErr := client.receiveHelperResponse(ctx, stream, receiveSequence, revoke.RequestID().Bytes(), digest.Bytes())
	if receiveErr != nil {
		return sendSequence, receiveSequence, receiveErr
	}
	if client.drainStarted() || ctx.Err() != nil {
		return sendSequence, receiveSequence, nil
	}
	response, ok := helperPacket.responseValue()
	if !ok {
		return sendSequence, receiveSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	mapped, mapErr := mapHelperRevokeSuccessToV2(revoke, helperPacket.headerValue(), response)
	if mapErr != nil {
		return sendSequence, receiveSequence, clientError(ClientContractCorrelation, ClientFieldBody)
	}
	if sendErr := client.sendControllerRevokeSuccess(ctx, controllerPacket, mapped); sendErr != nil {
		return sendSequence, receiveSequence, sendErr
	}
	return sendSequence + 1, receiveSequence + 1, nil
}

func (client *Client) dispatchHelperExec(
	ctx context.Context,
	stream VerifiedHelperStream,
	controllerPacket ControllerPacket,
	exec v2control.CredentialExecRequest,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	ledger *helperActiveLedger,
	sendSequence, receiveSequence, controllerSequence uint64,
) (uint64, uint64, uint64, error) {
	if ledger == nil || exec.Revision() != ledger.revision || exec.ExecBindingID() != ledger.execBindingID {
		return sendSequence, receiveSequence, controllerSequence, clientError(ClientContractCorrelation, ClientFieldRevision)
	}
	if authErr := client.authorizeHelperSend(credentialprotocol.PacketTypeExec, digest, exec.Revision(), ledger.bindings); authErr != nil {
		return sendSequence, receiveSequence, controllerSequence, authErr
	}
	privateLength, privateDigest, admitted := helperExecPrivateAdmission(exec)
	if !admitted {
		return sendSequence, receiveSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	if writeErr := client.writePinnedHelperMetadata(ctx, stream, sendSequence, identity, digest, exec.RequestID().Bytes(), func(header credentialprotocol.HelperPacketHeader) (HelperSendPacket, error) {
		body, err := helperExecBodyFromExec(exec)
		if err != nil {
			return HelperSendPacket{}, err
		}
		return newHelperExecSendPacket(header, body)
	}); writeErr != nil {
		return sendSequence, receiveSequence, controllerSequence, writeErr
	}
	nextSend := sendSequence + 1
	if client.drainStarted() || ctx.Err() != nil {
		return nextSend, receiveSequence, controllerSequence, nil
	}
	if privateLength > 0 {
		nextPrivateSend, nextCtrl, privateErr := client.dispatchOneHelperExecPrivate(
			ctx, stream, exec, identity, digest, privateLength, privateDigest, nextSend, controllerSequence,
		)
		if privateErr != nil {
			return sendSequence, receiveSequence, controllerSequence, privateErr
		}
		nextSend = nextPrivateSend
		controllerSequence = nextCtrl
		if client.drainStarted() || ctx.Err() != nil {
			return nextSend, receiveSequence, controllerSequence, nil
		}
	}
	nextStreamSend, nextStreamReceive, nextCtrl, streamErr := client.dispatchHelperExecStreams(
		ctx, stream, exec, identity, digest, nextSend, receiveSequence, controllerSequence,
	)
	if streamErr != nil {
		return sendSequence, receiveSequence, controllerSequence, streamErr
	}
	nextSend = nextStreamSend
	receiveSequence = nextStreamReceive
	controllerSequence = nextCtrl
	if client.drainStarted() || ctx.Err() != nil {
		return nextSend, receiveSequence, controllerSequence, nil
	}
	helperPacket, receiveErr := client.receiveHelperResponse(ctx, stream, receiveSequence, exec.RequestID().Bytes(), digest.Bytes())
	if receiveErr != nil {
		return nextSend, receiveSequence, controllerSequence, receiveErr
	}
	if client.drainStarted() || ctx.Err() != nil {
		return nextSend, receiveSequence, controllerSequence, nil
	}
	response, ok := helperPacket.responseValue()
	if !ok {
		return nextSend, receiveSequence, controllerSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	mapped, mapErr := mapHelperExecSuccessToV2(exec, helperPacket.headerValue(), response)
	if mapErr != nil {
		return nextSend, receiveSequence, controllerSequence, clientError(ClientContractCorrelation, ClientFieldBody)
	}
	if sendErr := client.sendControllerExecSuccess(ctx, controllerPacket, mapped); sendErr != nil {
		return nextSend, receiveSequence, controllerSequence, sendErr
	}
	return nextSend, receiveSequence + 1, controllerSequence, nil
}

func (client *Client) dispatchOneHelperExecPrivate(
	ctx context.Context,
	stream VerifiedHelperStream,
	exec v2control.CredentialExecRequest,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	privateLength uint32,
	privateDigest [32]byte,
	sendSequence, controllerSequence uint64,
) (nextSendSequence, nextControllerSequence uint64, returnErr error) {
	if !configuredDependency(stream) || privateLength == 0 || privateDigest == ([32]byte{}) {
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	receive, receiveErr := newControlReceiveRequest(controllerSequence, digest, true, session.MaxControlPlaintextBytes)
	if receiveErr != nil {
		return sendSequence, controllerSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	packet, dispatchErr, panicked := client.receiveControllerPacket(ctx, receive)
	if panicked {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, clientError(ClientContractPanic, ClientFieldPacketType)
	}
	if dispatchErr != nil {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		if client.drainStarted() || ctx.Err() != nil {
			return sendSequence, controllerSequence, nil
		}
		return sendSequence, controllerSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if packet.sequenceValue() != controllerSequence || packet.sessionIDValue() != identity.sessionIDValue() {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	controllerSequence++
	if _, isPrepare := packet.prepareValue(); isPrepare {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	if _, isStream := packet.streamValue(); isStream {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	private, ok := packet.privateValue()
	if !ok {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	body := packet.body
	packet.body = nil
	defer func() {
		if cleanupErr := destroyControllerBody(body); cleanupErr != nil {
			returnErr = clientError(ClientContractCleanup, ClientFieldBody)
		}
	}()
	if private.kind != credentialprotocol.PrivateRecordKindOpaqueExecBinding ||
		private.kind == credentialprotocol.PrivateRecordKindFileBytes ||
		private.requestID != exec.RequestID() ||
		private.identityDigest != digest ||
		private.bindingIndex != 0 ||
		private.chunkIndex != 0 ||
		private.chunkCount != 1 ||
		private.payloadLength != privateLength ||
		private.payloadSHA256 != privateDigest {
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	owner, copyErr := copyControllerExecPrivateOwner(ctx, body, exec.Revision(), privateDigest, privateLength)
	if copyErr != nil {
		wipeHelperExecPrivateOwner(owner)
		if client.drainStarted() || ctx.Err() != nil {
			return sendSequence, controllerSequence, nil
		}
		return sendSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	defer wipeHelperExecPrivateOwner(owner)
	if client.drainStarted() || ctx.Err() != nil {
		return sendSequence, controllerSequence, nil
	}
	if writeErr := client.writePinnedHelperExecPrivate(ctx, stream, sendSequence, identity, digest, exec.RequestID().Bytes(), owner); writeErr != nil {
		return sendSequence, controllerSequence, writeErr
	}
	return sendSequence + 1, controllerSequence, nil
}

func (client *Client) writePinnedHelperExecPrivate(
	ctx context.Context,
	stream VerifiedHelperStream,
	sequence uint64,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	requestID [16]byte,
	owner *helperExecPrivateOwner,
) error {
	if !configuredDependency(stream) || owner == nil || owner.body == nil {
		return helperPacketDependencyUnaccepted(digest)
	}
	if sequence == 0 || sequence > uint64(^uint32(0)) {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if !client.beginAdmittedOperation() {
		return nil
	}
	defer client.endAdmittedOperation()
	send, sendErr := newHelperExecPrivateSendPacket(injectedHelperSendHeader(sequence, requestID, digest, identity.sessionIdentity().GuestBootNonce), owner)
	if sendErr != nil {
		if errors.Is(sendErr, ErrClientControlDependencyUnaccepted) {
			return helperPacketDependencyUnaccepted(digest)
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if writeErr := writeHelperSendPacket(ctx, stream, send); writeErr != nil {
		if client.drainStarted() || ctx.Err() != nil {
			return nil
		}
		if errors.Is(writeErr, ErrClientControlDependencyUnaccepted) {
			return helperPacketDependencyUnaccepted(digest)
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return nil
}

func (client *Client) dispatchHelperExecStreams(
	ctx context.Context,
	stream VerifiedHelperStream,
	exec v2control.CredentialExecRequest,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	sendSequence, receiveSequence, controllerSequence uint64,
) (uint64, uint64, uint64, error) {
	if !configuredDependency(stream) {
		return sendSequence, receiveSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	stdinMax := uint64(exec.Plan().StdinMaxBytes())
	if stdinMax < 1 || stdinMax > credentialprotocol.MaxHelperExecStreamAggregateBytes {
		return sendSequence, receiveSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
	}
	var offset uint64
	var total uint64
	var records uint32
	for {
		if client.drainStarted() || ctx.Err() != nil {
			return sendSequence, receiveSequence, controllerSequence, nil
		}
		if records == ^uint32(0) {
			return sendSequence, receiveSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
		}
		remaining := stdinMax - total
		if total > credentialprotocol.MaxHelperExecStreamAggregateBytes {
			return sendSequence, receiveSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
		}
		if remaining > credentialprotocol.MaxHelperExecStreamAggregateBytes-total {
			remaining = credentialprotocol.MaxHelperExecStreamAggregateBytes - total
		}
		if creditErr := client.receiveHelperExecCredit(
			ctx, stream, receiveSequence, exec.RequestID().Bytes(), digest.Bytes(), exec.Revision(), offset,
		); creditErr != nil {
			return sendSequence, receiveSequence, controllerSequence, creditErr
		}
		receiveSequence++
		if client.drainStarted() || ctx.Err() != nil {
			return sendSequence, receiveSequence, controllerSequence, nil
		}
		nextSend, nextCtrl, flags, length, sendErr := client.dispatchOneHelperExecStream(
			ctx, stream, exec, identity, digest, offset, remaining, sendSequence, controllerSequence,
		)
		if sendErr != nil {
			return sendSequence, receiveSequence, controllerSequence, sendErr
		}
		sendSequence = nextSend
		controllerSequence = nextCtrl
		records++
		if flags == credentialprotocol.HelperExecStreamFlagEOF {
			return sendSequence, receiveSequence, controllerSequence, nil
		}
		if length == 0 || uint64(length) > remaining {
			return sendSequence, receiveSequence, controllerSequence, helperPacketDependencyUnaccepted(digest)
		}
		total += uint64(length)
		offset += uint64(length)
	}
}

func (client *Client) receiveHelperExecCredit(
	ctx context.Context,
	stream VerifiedHelperStream,
	sequence uint64,
	requestID [16]byte,
	identity [32]byte,
	revision, offset uint64,
) error {
	if !configuredDependency(stream) {
		return helperPacketDependencyUnaccepted(v2control.NewIdentityDigest(identity))
	}
	if client.drainStarted() || ctx.Err() != nil {
		return nil
	}
	request, err := newHelperControlReceiveRequest(
		sequence, credentialprotocol.HelperExecCreditBodyBytes, 0, requestID, true, identity,
	)
	if err != nil {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if !client.beginAdmittedOperation() {
		return nil
	}
	defer client.endAdmittedOperation()
	packet, receiveErr := readHelperExecCreditPacket(ctx, stream, request)
	if receiveErr != nil {
		if client.drainStarted() || ctx.Err() != nil {
			return nil
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	credit, ok := packet.execCreditValue()
	if !ok || credit.Revision != revision || credit.StreamKind != credentialprotocol.HelperExecStreamStdin || credit.NextOffset != offset {
		return clientError(ClientContractCorrelation, ClientFieldBody)
	}
	return nil
}

func (client *Client) dispatchOneHelperExecStream(
	ctx context.Context,
	stream VerifiedHelperStream,
	exec v2control.CredentialExecRequest,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	offset, remaining uint64,
	sendSequence, controllerSequence uint64,
) (nextSendSequence, nextControllerSequence uint64, flags credentialprotocol.HelperExecStreamFlags, payloadLength uint32, returnErr error) {
	if !configuredDependency(stream) {
		return sendSequence, controllerSequence, 0, 0, helperPacketDependencyUnaccepted(digest)
	}
	receive, receiveErr := newControlReceiveRequest(controllerSequence, digest, true, session.MaxControlPlaintextBytes)
	if receiveErr != nil {
		return sendSequence, controllerSequence, 0, 0, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	packet, dispatchErr, panicked := client.receiveControllerPacket(ctx, receive)
	if panicked {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, 0, 0, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, 0, 0, clientError(ClientContractPanic, ClientFieldPacketType)
	}
	if dispatchErr != nil {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, 0, 0, clientError(ClientContractCleanup, ClientFieldBody)
		}
		if client.drainStarted() || ctx.Err() != nil {
			return sendSequence, controllerSequence, 0, 0, nil
		}
		return sendSequence, controllerSequence, 0, 0, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if packet.sequenceValue() != controllerSequence || packet.sessionIDValue() != identity.sessionIDValue() {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, 0, 0, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, 0, 0, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	controllerSequence++
	if _, isPrepare := packet.prepareValue(); isPrepare {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, 0, 0, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, 0, 0, helperPacketDependencyUnaccepted(digest)
	}
	streamRecord, ok := packet.streamValue()
	if !ok {
		_, cleanupErr := rejectControllerPacketBody(&packet)
		if cleanupErr != nil {
			return sendSequence, controllerSequence, 0, 0, clientError(ClientContractCleanup, ClientFieldBody)
		}
		return sendSequence, controllerSequence, 0, 0, helperPacketDependencyUnaccepted(digest)
	}
	body := packet.body
	packet.body = nil
	defer func() {
		if cleanupErr := destroyControllerBody(body); cleanupErr != nil {
			returnErr = clientError(ClientContractCleanup, ClientFieldBody)
		}
	}()
	if streamRecord.kind != credentialprotocol.HelperExecStreamStdin ||
		streamRecord.kind == credentialprotocol.HelperExecStreamStdout ||
		streamRecord.kind == credentialprotocol.HelperExecStreamStderr ||
		!validControllerReceiveExecStream(streamRecord.kind, streamRecord.flags, streamRecord.payloadLength, streamRecord.payloadSHA256) ||
		streamRecord.requestID != exec.RequestID() ||
		streamRecord.identityDigest != digest ||
		streamRecord.offset != offset {
		return sendSequence, controllerSequence, 0, 0, helperPacketDependencyUnaccepted(digest)
	}
	if streamRecord.flags == credentialprotocol.HelperExecStreamFlagsNone {
		if streamRecord.payloadLength == 0 || uint64(streamRecord.payloadLength) > remaining {
			return sendSequence, controllerSequence, 0, 0, helperPacketDependencyUnaccepted(digest)
		}
	}
	owner, copyErr := copyControllerExecStreamOwner(
		ctx, body, exec.Revision(), streamRecord.kind, streamRecord.flags, streamRecord.offset,
		streamRecord.payloadSHA256, streamRecord.payloadLength,
	)
	if copyErr != nil {
		wipeHelperExecStreamOwner(owner)
		if client.drainStarted() || ctx.Err() != nil {
			return sendSequence, controllerSequence, 0, 0, nil
		}
		return sendSequence, controllerSequence, 0, 0, helperPacketDependencyUnaccepted(digest)
	}
	defer wipeHelperExecStreamOwner(owner)
	if client.drainStarted() || ctx.Err() != nil {
		return sendSequence, controllerSequence, 0, 0, nil
	}
	if writeErr := client.writePinnedHelperExecStream(ctx, stream, sendSequence, identity, digest, exec.RequestID().Bytes(), owner); writeErr != nil {
		return sendSequence, controllerSequence, 0, 0, writeErr
	}
	return sendSequence + 1, controllerSequence, streamRecord.flags, streamRecord.payloadLength, nil
}

func (client *Client) writePinnedHelperExecStream(
	ctx context.Context,
	stream VerifiedHelperStream,
	sequence uint64,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	requestID [16]byte,
	owner *helperExecStreamOwner,
) error {
	if !configuredDependency(stream) || owner == nil || owner.body == nil {
		return helperPacketDependencyUnaccepted(digest)
	}
	if sequence == 0 || sequence > uint64(^uint32(0)) {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if !client.beginAdmittedOperation() {
		return nil
	}
	defer client.endAdmittedOperation()
	send, sendErr := newHelperExecStreamSendPacket(injectedHelperSendHeader(sequence, requestID, digest, identity.sessionIdentity().GuestBootNonce), owner)
	if sendErr != nil {
		if errors.Is(sendErr, ErrClientControlDependencyUnaccepted) {
			return helperPacketDependencyUnaccepted(digest)
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if writeErr := writeHelperSendPacket(ctx, stream, send); writeErr != nil {
		if client.drainStarted() || ctx.Err() != nil {
			return nil
		}
		if errors.Is(writeErr, ErrClientControlDependencyUnaccepted) {
			return helperPacketDependencyUnaccepted(digest)
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return nil
}

func (client *Client) writePinnedHelperMetadata(
	ctx context.Context,
	stream VerifiedHelperStream,
	sequence uint64,
	identity transportIdentity,
	digest v2control.IdentityDigest,
	requestID [16]byte,
	build func(credentialprotocol.HelperPacketHeader) (HelperSendPacket, error),
) error {
	if !configuredDependency(stream) {
		return helperPacketDependencyUnaccepted(digest)
	}
	if sequence == 0 || sequence > uint64(^uint32(0)) {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if !client.beginAdmittedOperation() {
		return nil
	}
	defer client.endAdmittedOperation()
	send, sendErr := build(injectedHelperSendHeader(sequence, requestID, digest, identity.sessionIdentity().GuestBootNonce))
	if sendErr != nil {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if writeErr := writeHelperSendPacket(ctx, stream, send); writeErr != nil {
		if client.drainStarted() || ctx.Err() != nil {
			return nil
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return nil
}

func (client *Client) receiveHelperResponse(
	ctx context.Context,
	stream VerifiedHelperStream,
	sequence uint64,
	requestID [16]byte,
	identity [32]byte,
) (HelperPacket, error) {
	if !configuredDependency(stream) {
		return HelperPacket{}, helperPacketDependencyUnaccepted(v2control.NewIdentityDigest(identity))
	}
	if client.drainStarted() || ctx.Err() != nil {
		return HelperPacket{}, nil
	}
	request, err := newHelperControlReceiveRequest(sequence, credentialprotocol.MaxHelperPacketBodyBytes, 0, requestID, true, identity)
	if err != nil {
		return HelperPacket{}, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	if !client.beginAdmittedOperation() {
		return HelperPacket{}, nil
	}
	defer client.endAdmittedOperation()
	packet, receiveErr := readHelperResponsePacket(ctx, stream, request)
	if receiveErr != nil {
		if client.drainStarted() || ctx.Err() != nil {
			return HelperPacket{}, nil
		}
		return HelperPacket{}, clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return packet, nil
}

func (client *Client) sendControllerPrepareSuccess(ctx context.Context, packet ControllerPacket, response v2control.CredentialPrepareSuccessResponse) error {
	send, err := newControllerPrepareSendPacket(packet, response)
	if err != nil {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return client.sendControllerPacket(ctx, send)
}

func (client *Client) sendControllerRenewSuccess(ctx context.Context, packet ControllerPacket, response v2control.CredentialRenewSuccessResponse) error {
	send, err := newControllerRenewSendPacket(packet, response)
	if err != nil {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return client.sendControllerPacket(ctx, send)
}

func (client *Client) sendControllerRevokeSuccess(ctx context.Context, packet ControllerPacket, response v2control.CredentialRevokeSuccessResponse) error {
	send, err := newControllerRevokeSendPacket(packet, response)
	if err != nil {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return client.sendControllerPacket(ctx, send)
}

func (client *Client) sendControllerExecSuccess(ctx context.Context, packet ControllerPacket, response v2control.CredentialExecSuccessResponse) error {
	send, err := newControllerExecSendPacket(packet, response)
	if err != nil {
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return client.sendControllerPacket(ctx, send)
}

func (client *Client) sendControllerPacket(ctx context.Context, send ControllerSendPacket) error {
	if !client.beginAdmittedOperation() {
		return nil
	}
	defer client.endAdmittedOperation()
	if sendErr := client.transport.SendController(ctx, send); sendErr != nil {
		if client.drainStarted() || ctx.Err() != nil {
			return nil
		}
		return clientError(ClientContractPacket, ClientFieldPacketType)
	}
	return nil
}

func injectedHelperSendHeader(sequence uint64, requestID [16]byte, digest v2control.IdentityDigest, nonce [32]byte) credentialprotocol.HelperPacketHeader {
	return credentialprotocol.HelperPacketHeader{
		Sequence:                      sequence,
		RequestID:                     requestID,
		GuestCredentialIdentityDigest: digest.Bytes(),
		BootNonce:                     nonce,
	}
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
	return client.sendControllerPacket(ctx, send)
}

func (client *Client) receiveControllerPacket(ctx context.Context, request ControllerReceiveRequest) (packet ControllerPacket, err error, panicked bool) {
	if !client.beginAdmittedOperation() {
		return ControllerPacket{}, errInvalidControlReceiveRequest, false
	}
	defer client.endAdmittedOperation()
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

func (client *Client) beginAdmittedOperation() bool {
	state := client.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closeStarted {
		return false
	}
	state.admittedOperations.Add(1)
	return true
}

func (client *Client) endAdmittedOperation() {
	client.state.admittedOperations.Done()
}

func (client *Client) drainStarted() bool {
	client.state.mu.Lock()
	defer client.state.mu.Unlock()
	return client.state.closeStarted
}
