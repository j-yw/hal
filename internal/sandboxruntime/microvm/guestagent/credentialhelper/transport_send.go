package credentialhelper

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"sync"
	"sync/atomic"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type sendPacketArm interface {
	sendPacketArm()
	canonicalLength() (uint32, error)
	encodeCanonicalTo([]byte) error
}

type sealedSendPacketArm struct {
	arm        sendPacketArm
	bodyLength uint32
	bodySHA256 [32]byte
	written    atomic.Bool
}

type sendHelperReadyArm struct{}
type sendBootstrapAckArm struct{ bootstrapSHA256 [32]byte }
type sendAgentHelloAckArm struct{ bootstrapSHA256 [32]byte }
type sendSSHAcceptedArm struct {
	revision              uint64
	bindingIndex          uint16
	connectionOrdinal     uint8
	relayCapabilitySHA256 [32]byte
}
type sendExecCreditArm struct {
	body credentialprotocol.HelperExecCreditBody
}
type sendExecStreamArm struct {
	revision      uint64
	streamKind    credentialprotocol.HelperExecStreamKind
	flags         credentialprotocol.HelperExecStreamFlags
	offset        uint64
	payloadLength uint32
	payloadSHA256 [32]byte
	body          ReceivedBodyCapability
}
type sendResponseArm struct {
	body credentialprotocol.HelperResponseBody
}
type sendEventArm struct {
	body credentialprotocol.HelperEventBody
}
type sendCloseNotifyArm struct {
	body credentialprotocol.HelperCloseNotifyBody
}

func (sendHelperReadyArm) sendPacketArm()   {}
func (sendBootstrapAckArm) sendPacketArm()  {}
func (sendAgentHelloAckArm) sendPacketArm() {}
func (sendSSHAcceptedArm) sendPacketArm()   {}
func (sendExecCreditArm) sendPacketArm()    {}
func (sendExecStreamArm) sendPacketArm()    {}
func (sendResponseArm) sendPacketArm()      {}
func (sendEventArm) sendPacketArm()         {}
func (sendCloseNotifyArm) sendPacketArm()   {}
func (*sealedSendPacketArm) sendPacketArm() {}

func (*sealedSendPacketArm) canonicalLength() (uint32, error) { return 0, ErrContractCapability }
func (*sealedSendPacketArm) encodeCanonicalTo([]byte) error   { return ErrContractCapability }

func (sendHelperReadyArm) canonicalLength() (uint32, error) {
	return credentialprotocol.HelperReadyBodyEncodedLength(), nil
}
func (sendHelperReadyArm) encodeCanonicalTo(dst []byte) error {
	return credentialprotocol.EncodeHelperReadyBodyTo(dst)
}
func (sendBootstrapAckArm) canonicalLength() (uint32, error) {
	return credentialprotocol.HelperBootstrapAckBodyEncodedLength(), nil
}
func (arm sendBootstrapAckArm) encodeCanonicalTo(dst []byte) error {
	return credentialprotocol.EncodeHelperBootstrapAckBodyTo(dst, arm.bootstrapSHA256)
}
func (sendAgentHelloAckArm) canonicalLength() (uint32, error) {
	return credentialprotocol.HelperAgentHelloAckBodyEncodedLength(), nil
}
func (arm sendAgentHelloAckArm) encodeCanonicalTo(dst []byte) error {
	return credentialprotocol.EncodeHelperAgentHelloAckBodyTo(dst, arm.bootstrapSHA256)
}
func (sendSSHAcceptedArm) canonicalLength() (uint32, error) {
	return credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength(), nil
}
func (arm sendSSHAcceptedArm) encodeCanonicalTo(dst []byte) error {
	return credentialprotocol.EncodeHelperSSHAcceptedFDBodyTo(dst, arm.revision, arm.bindingIndex, arm.connectionOrdinal, arm.relayCapabilitySHA256)
}
func (arm sendExecCreditArm) canonicalLength() (uint32, error) {
	return credentialprotocol.HelperExecCreditBodyEncodedLength(arm.body)
}
func (arm sendExecCreditArm) encodeCanonicalTo(dst []byte) error {
	return credentialprotocol.EncodeHelperExecCreditBodyTo(dst, arm.body)
}
func (sendExecStreamArm) canonicalLength() (uint32, error) { return 0, ErrContractCapability }
func (sendExecStreamArm) encodeCanonicalTo([]byte) error   { return ErrContractCapability }
func (arm sendResponseArm) canonicalLength() (uint32, error) {
	return credentialprotocol.HelperResponseBodyEncodedLength(arm.body)
}
func (arm sendResponseArm) encodeCanonicalTo(dst []byte) error {
	return credentialprotocol.EncodeHelperResponseBodyTo(dst, arm.body)
}
func (arm sendEventArm) canonicalLength() (uint32, error) {
	return credentialprotocol.HelperEventBodyEncodedLength(arm.body)
}
func (arm sendEventArm) encodeCanonicalTo(dst []byte) error {
	return credentialprotocol.EncodeHelperEventBodyTo(dst, arm.body)
}
func (arm sendCloseNotifyArm) canonicalLength() (uint32, error) {
	return credentialprotocol.HelperCloseNotifyBodyEncodedLength(arm.body)
}
func (arm sendCloseNotifyArm) encodeCanonicalTo(dst []byte) error {
	return credentialprotocol.EncodeHelperCloseNotifyBodyTo(dst, arm.body)
}

// SendPacket is the service-built closed outbound union.
type SendPacket struct {
	liveValue
	header credentialprotocol.HelperPacketHeader
	arm    sendPacketArm
	right  ReceivedCapability
}

type exactForwardingSink struct {
	mu       sync.Mutex
	ctx      context.Context
	target   credentialmemory.CredentialSink
	expected int
	calls    int
	valid    bool
	err      error
}

func (sink *exactForwardingSink) MaxCredentialBytes() int { return sink.expected }
func (sink *exactForwardingSink) WriteCredential(value []byte) error {
	if sink.ctx.Err() != nil {
		return ErrContractOwnership
	}
	sink.mu.Lock()
	sink.calls++
	if sink.calls != 1 || len(value) != sink.expected {
		sink.valid = false
		sink.mu.Unlock()
		return ErrContractOwnership
	}
	sink.mu.Unlock()
	err := sink.target.WriteCredential(value)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if err != nil {
		sink.valid = false
		if sink.err == nil {
			sink.err = err
		}
	}
	if sink.ctx.Err() != nil {
		sink.valid = false
		if sink.err == nil {
			sink.err = ErrContractOwnership
		}
		return ErrContractOwnership
	}
	return err
}

func (sink *exactForwardingSink) snapshot() (int, bool, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.calls, sink.valid, sink.err
}

func newSendPacket(ctx context.Context, header credentialprotocol.HelperPacketHeader, arm sendPacketArm, right ReceivedCapability) (packet SendPacket, err error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return SendPacket{}, contextErr
	}
	success := false
	defer func() {
		if success {
			return
		}
		if stream, ok := arm.(sendExecStreamArm); ok && configuredDependency(stream.body) {
			if cleanupErr := destroyTransportBody(ctx, stream.body); cleanupErr != nil {
				err = ErrContractOwnership
			}
		}
		if configuredDependency(right) {
			if cleanupErr := closeTransportRight(ctx, right); cleanupErr != nil {
				err = ErrContractOwnership
			}
		}
	}()
	if ctx.Err() != nil {
		return SendPacket{}, ErrContractOwnership
	}
	if !configuredDependency(arm) || header.Sequence > uint64(^uint32(0)) || credentialprotocol.ValidateHelperPacketHeaderSemantics(header) != nil {
		return SendPacket{}, ErrContractInvalidArgument
	}
	arm = snapshotSendPacketArm(arm)
	wantsRight := header.Type == credentialprotocol.PacketTypeSSHAcceptedFD
	hasRight := configuredDependency(right)
	if wantsRight != hasRight {
		if right != nil && !hasRight {
			return SendPacket{}, ErrContractTypedNil
		}
		return SendPacket{}, ErrContractCapability
	}
	if hasRight {
		kind := right.Kind()
		if ctx.Err() != nil {
			return SendPacket{}, ErrContractOwnership
		}
		if kind != ReceivedCapabilitySSHConnection {
			return SendPacket{}, ErrContractCapability
		}
		sshAccepted, ok := arm.(sendSSHAcceptedArm)
		if ok && (sshAccepted.connectionOrdinal == 0 || sshAccepted.connectionOrdinal > credentialprotocol.SSHAgentRelayMaxLifetimeConnections) {
			return SendPacket{}, ErrContractInvalidArgument
		}
		rightDigest := right.SHA256()
		if ctx.Err() != nil {
			return SendPacket{}, ErrContractOwnership
		}
		if rightDigest == ([32]byte{}) {
			return SendPacket{}, ErrContractCapability
		}
		if !ok || subtle.ConstantTimeCompare(rightDigest[:], sshAccepted.relayCapabilitySHA256[:]) != 1 {
			return SendPacket{}, ErrContractCorrelation
		}
	}

	if stream, ok := arm.(sendExecStreamArm); ok {
		if header.Type != credentialprotocol.PacketTypeExecStream || !configuredDependency(stream.body) {
			if stream.body != nil && !configuredDependency(stream.body) {
				return SendPacket{}, ErrContractTypedNil
			}
			return SendPacket{}, ErrContractCorrelation
		}
		if !validSendExecStreamArm(ctx, stream, header.BodyLength) {
			if ctx.Err() != nil {
				return SendPacket{}, ErrContractOwnership
			}
			return SendPacket{}, ErrContractCorrelation
		}
		bodySHA256 := stream.body.SHA256()
		if ctx.Err() != nil {
			return SendPacket{}, ErrContractOwnership
		}
		if bodySHA256 == ([32]byte{}) {
			return SendPacket{}, ErrContractCorrelation
		}
		packet = SendPacket{header: header, arm: &sealedSendPacketArm{arm: stream, bodyLength: header.BodyLength, bodySHA256: bodySHA256}, right: right}
		success = true
		return packet, nil
	}
	length, err := arm.canonicalLength()
	if err != nil {
		return SendPacket{}, ErrContractInvalidArgument
	}
	if length != header.BodyLength || header.Type != sendArmPacketType(arm) {
		return SendPacket{}, ErrContractCorrelation
	}
	var bodySHA256 [32]byte
	if err := withCanonicalScratch(arm, length, func(encoded []byte) error {
		bodySHA256 = sha256.Sum256(encoded)
		return nil
	}); err != nil {
		return SendPacket{}, err
	}
	packet = SendPacket{header: header, arm: &sealedSendPacketArm{arm: arm, bodyLength: header.BodyLength, bodySHA256: bodySHA256}, right: right}
	success = true
	return packet, nil
}

func snapshotSendPacketArm(arm sendPacketArm) sendPacketArm {
	switch typed := arm.(type) {
	case sendHelperReadyArm:
		return typed
	case sendBootstrapAckArm:
		return typed
	case sendAgentHelloAckArm:
		return typed
	case sendSSHAcceptedArm:
		return typed
	case sendExecCreditArm:
		return typed
	case sendExecStreamArm:
		return typed
	case sendResponseArm:
		typed.body = cloneHelperResponseBody(typed.body)
		return typed
	case sendEventArm:
		return typed
	case sendCloseNotifyArm:
		return typed
	default:
		return arm
	}
}

func cloneHelperResponseBody(body credentialprotocol.HelperResponseBody) credentialprotocol.HelperResponseBody {
	clone := body
	if body.Prepare != nil {
		prepare := *body.Prepare
		prepare.BindingProofs = append([]credentialprotocol.HelperBindingProof(nil), body.Prepare.BindingProofs...)
		clone.Prepare = &prepare
	}
	if body.Renew != nil {
		renew := *body.Renew
		clone.Renew = &renew
	}
	if body.Revoke != nil {
		revoke := *body.Revoke
		clone.Revoke = &revoke
	}
	if body.Exec != nil {
		exec := *body.Exec
		clone.Exec = &exec
	}
	return clone
}

func sendArmPacketType(arm sendPacketArm) credentialprotocol.PacketType {
	switch arm.(type) {
	case sendHelperReadyArm:
		return credentialprotocol.PacketTypeHelperReady
	case sendBootstrapAckArm:
		return credentialprotocol.PacketTypeBootstrapAck
	case sendAgentHelloAckArm:
		return credentialprotocol.PacketTypeAgentHelloAck
	case sendSSHAcceptedArm:
		return credentialprotocol.PacketTypeSSHAcceptedFD
	case sendExecCreditArm:
		return credentialprotocol.PacketTypeExecCredit
	case sendExecStreamArm:
		return credentialprotocol.PacketTypeExecStream
	case sendResponseArm:
		return credentialprotocol.PacketTypeResponse
	case sendEventArm:
		return credentialprotocol.PacketTypeEvent
	case sendCloseNotifyArm:
		return credentialprotocol.PacketTypeCloseNotify
	default:
		return 0
	}
}

func newHelperReadyPacket(ctx context.Context, header credentialprotocol.HelperPacketHeader) (SendPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return SendPacket{}, contextErr
	}
	if ctx.Err() != nil {
		return SendPacket{}, ErrContractOwnership
	}
	if header.Sequence != 0 {
		return SendPacket{}, ErrContractCorrelation
	}
	return newSendPacket(ctx, header, sendHelperReadyArm{}, nil)
}
func newBootstrapAckPacket(ctx context.Context, header credentialprotocol.HelperPacketHeader, digest [32]byte) (SendPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return SendPacket{}, contextErr
	}
	if ctx.Err() != nil {
		return SendPacket{}, ErrContractOwnership
	}
	if header.Sequence != 1 {
		return SendPacket{}, ErrContractCorrelation
	}
	return newSendPacket(ctx, header, sendBootstrapAckArm{bootstrapSHA256: digest}, nil)
}
func newAgentHelloAckPacket(ctx context.Context, header credentialprotocol.HelperPacketHeader, digest [32]byte) (SendPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return SendPacket{}, contextErr
	}
	if ctx.Err() != nil {
		return SendPacket{}, ErrContractOwnership
	}
	if header.Sequence != 2 {
		return SendPacket{}, ErrContractCorrelation
	}
	return newSendPacket(ctx, header, sendAgentHelloAckArm{bootstrapSHA256: digest}, nil)
}
func newSSHAcceptedPacket(ctx context.Context, header credentialprotocol.HelperPacketHeader, revision uint64, bindingIndex uint16, ordinal uint8, digest [32]byte, right ReceivedCapability) (SendPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return SendPacket{}, contextErr
	}
	return newSendPacket(ctx, header, sendSSHAcceptedArm{revision: revision, bindingIndex: bindingIndex, connectionOrdinal: ordinal, relayCapabilitySHA256: digest}, right)
}
func newExecCreditPacket(ctx context.Context, header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperExecCreditBody) (SendPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return SendPacket{}, contextErr
	}
	if ctx.Err() != nil {
		return SendPacket{}, ErrContractOwnership
	}
	if body.StreamKind != credentialprotocol.HelperExecStreamStdin {
		return SendPacket{}, ErrContractInvalidArgument
	}
	return newSendPacket(ctx, header, sendExecCreditArm{body: body}, nil)
}
func newExecStreamPacket(ctx context.Context, header credentialprotocol.HelperPacketHeader, revision uint64, streamKind credentialprotocol.HelperExecStreamKind, flags credentialprotocol.HelperExecStreamFlags, offset uint64, payloadLength uint32, payloadSHA256 [32]byte, body ReceivedBodyCapability) (SendPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return SendPacket{}, contextErr
	}
	return newSendPacket(ctx, header, sendExecStreamArm{revision: revision, streamKind: streamKind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: payloadSHA256, body: body}, nil)
}
func newResponsePacket(ctx context.Context, header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperResponseBody) (SendPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return SendPacket{}, contextErr
	}
	return newSendPacket(ctx, header, sendResponseArm{body: body}, nil)
}

//nolint:unused // Frozen D4 Service seam; production use lands with the service state machine.
func newEventPacket(ctx context.Context, header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperEventBody) (SendPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return SendPacket{}, contextErr
	}
	return newSendPacket(ctx, header, sendEventArm{body: body}, nil)
}
func newCloseNotifyPacket(ctx context.Context, header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperCloseNotifyBody) (SendPacket, error) {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return SendPacket{}, contextErr
	}
	return newSendPacket(ctx, header, sendCloseNotifyArm{body: body}, nil)
}

func (packet SendPacket) Type() credentialprotocol.PacketType           { return packet.header.Type }
func (packet SendPacket) Header() credentialprotocol.HelperPacketHeader { return packet.header }
func (packet SendPacket) EncodedBodyLength() uint32                     { return packet.header.BodyLength }
func (packet SendPacket) BodySHA256() [32]byte {
	sealed := packet.sealedArm()
	if sealed == nil || sealed.bodyLength != packet.header.BodyLength {
		return [32]byte{}
	}
	return sealed.bodySHA256
}
func (packet SendPacket) WriteCanonicalBody(ctx context.Context, sink credentialmemory.CredentialSink) error {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return contextErr
	}
	sealed := packet.sealedArm()
	if sealed == nil || sealed.bodyLength != packet.header.BodyLength || !sealed.written.CompareAndSwap(false, true) {
		return ErrContractOwnership
	}
	if ctx.Err() != nil {
		return ErrContractOwnership
	}
	if !configuredDependency(sink) {
		return ErrContractTypedNil
	}
	if stream, ok := sealed.arm.(sendExecStreamArm); ok {
		if !configuredDependency(stream.body) {
			return ErrContractDestroyed
		}
		maximum := sink.MaxCredentialBytes()
		if ctx.Err() != nil {
			return ErrContractOwnership
		}
		if maximum < int(packet.header.BodyLength) {
			return ErrContractInvalidArgument
		}
		forward := &exactForwardingSink{ctx: ctx, target: sink, expected: int(packet.header.BodyLength), valid: true}
		callbacks := &callbackValidationState{valid: true}
		err := stream.body.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
			var callbackErr error
			if ctx.Err() != nil {
				callbackErr = ErrContractOwnership
			} else if !configuredDependency(view) {
				callbackErr = ErrContractOwnership
			} else {
				viewLength := view.Len()
				if ctx.Err() != nil || viewLength != int(packet.header.BodyLength) {
					callbackErr = ErrContractOwnership
				} else if err := view.WriteTo(ctx, forward); err != nil {
					callbackErr = ErrContractOwnership
				}
			}
			if ctx.Err() != nil {
				callbackErr = ErrContractOwnership
			}
			callbacks.record(callbackErr)
			return callbackErr
		})
		if ctx.Err() != nil {
			return ErrContractOwnership
		}
		calls, callbacksValid, callbackErr := callbacks.snapshot()
		writes, writeValid, writeErr := forward.snapshot()
		if err != nil || callbackErr != nil || calls != 1 || !callbacksValid || writeErr != nil || writes != 1 || !writeValid {
			return ErrContractOwnership
		}
		return nil
	}
	if !configuredDependency(sealed.arm) {
		return ErrContractInvalidArgument
	}
	length, err := sealed.arm.canonicalLength()
	if err != nil {
		return ErrContractInvalidArgument
	}
	if length != packet.header.BodyLength {
		return ErrContractInvalidArgument
	}
	return withCanonicalScratch(sealed.arm, length, func(encoded []byte) error {
		if ctx.Err() != nil {
			return ErrContractOwnership
		}
		if sha256.Sum256(encoded) != sealed.bodySHA256 {
			return ErrContractInvalidArgument
		}
		maximum := sink.MaxCredentialBytes()
		if ctx.Err() != nil {
			return ErrContractOwnership
		}
		if maximum < len(encoded) {
			return ErrContractInvalidArgument
		}
		if err := sink.WriteCredential(encoded); err != nil {
			return ErrContractOwnership
		}
		if ctx.Err() != nil {
			return ErrContractOwnership
		}
		return nil
	})
}
func (packet SendPacket) RightsCount() uint32 {
	if configuredDependency(packet.right) {
		return 1
	}
	return 0
}
func (packet SendPacket) Right() ReceivedCapability { return packet.right }

func (packet SendPacket) destroyBody(ctx context.Context) error {
	if contextErr := transportContextPrecondition(ctx); contextErr != nil {
		return contextErr
	}
	sealed := packet.sealedArm()
	if sealed == nil {
		return nil
	}
	stream, ok := sealed.arm.(sendExecStreamArm)
	if !ok || !configuredDependency(stream.body) {
		return nil
	}
	return destroyTransportBody(ctx, stream.body)
}

func (packet SendPacket) sealedArm() *sealedSendPacketArm {
	sealed, _ := packet.arm.(*sealedSendPacketArm)
	return sealed
}

func withCanonicalScratch(arm sendPacketArm, length uint32, consume func([]byte) error) error {
	if !configuredDependency(arm) || consume == nil {
		return ErrContractInvalidArgument
	}
	encoded := make([]byte, int(length))
	defer wipeBytes(encoded[:cap(encoded)])
	if err := arm.encodeCanonicalTo(encoded); err != nil {
		return ErrContractInvalidArgument
	}
	return consume(encoded)
}

func validSendExecStreamArm(ctx context.Context, arm sendExecStreamArm, bodyLength uint32) bool {
	if transportContextPrecondition(ctx) != nil || ctx.Err() != nil {
		return false
	}
	length := arm.body.Len()
	if ctx.Err() != nil {
		return false
	}
	if arm.revision == 0 || arm.streamKind != credentialprotocol.HelperExecStreamStdout && arm.streamKind != credentialprotocol.HelperExecStreamStderr ||
		(arm.flags != credentialprotocol.HelperExecStreamFlagsNone && arm.flags != credentialprotocol.HelperExecStreamFlagEOF) ||
		arm.payloadLength > credentialprotocol.MaxHelperExecStreamPayloadBytes ||
		(arm.flags == credentialprotocol.HelperExecStreamFlagsNone && arm.payloadLength == 0) ||
		(arm.flags == credentialprotocol.HelperExecStreamFlagEOF && arm.payloadLength != 0) ||
		(arm.payloadLength == 0 && arm.payloadSHA256 != sha256.Sum256(nil)) ||
		(arm.payloadLength > 0 && arm.payloadSHA256 == ([32]byte{})) ||
		length != bodyLength || bodyLength != 56+arm.payloadLength {
		return false
	}
	sink := &bodyValidationSink{maximum: int(length), validate: func(encoded []byte) bool {
		if len(encoded) != 56+int(arm.payloadLength) || binary.BigEndian.Uint64(encoded[:8]) != arm.revision || encoded[8] != byte(arm.streamKind) || encoded[9] != byte(arm.flags) || encoded[10] != 0 || encoded[11] != 0 || binary.BigEndian.Uint64(encoded[12:20]) != arm.offset || binary.BigEndian.Uint32(encoded[20:24]) != arm.payloadLength || !equalDigest(encoded[24:56], arm.payloadSHA256) {
			return false
		}
		return sha256.Sum256(encoded[56:]) == arm.payloadSHA256
	}}
	callbacks := &callbackValidationState{valid: true}
	borrowErr := arm.body.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		var callbackErr error
		if ctx.Err() != nil {
			callbackErr = ErrContractOwnership
		} else if !configuredDependency(view) {
			callbackErr = ErrContractOwnership
		} else {
			viewLength := view.Len()
			if ctx.Err() != nil || viewLength != int(length) {
				callbackErr = ErrContractOwnership
			} else if err := view.WriteTo(ctx, sink); err != nil {
				callbackErr = ErrContractOwnership
			}
		}
		if ctx.Err() != nil {
			callbackErr = ErrContractOwnership
		}
		callbacks.record(callbackErr)
		return callbackErr
	})
	if ctx.Err() != nil {
		return false
	}
	calls, callbacksValid, callbackErr := callbacks.snapshot()
	writes, bodyValid, validationDigest := sink.snapshot()
	bodyDigest := arm.body.SHA256()
	if ctx.Err() != nil {
		return false
	}
	return borrowErr == nil && callbackErr == nil && calls == 1 && callbacksValid && writes == 1 && bodyValid && bodyDigest != ([32]byte{}) && bodyDigest == validationDigest
}
