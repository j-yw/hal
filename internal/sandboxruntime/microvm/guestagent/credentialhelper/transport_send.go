package credentialhelper

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"sync/atomic"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type sendPacketArm interface {
	sendPacketArm()
	encodeCanonical() ([]byte, error)
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

func (*sealedSendPacketArm) encodeCanonical() ([]byte, error) {
	return nil, ErrContractCapability
}

func (sendHelperReadyArm) encodeCanonical() ([]byte, error) { return []byte{}, nil }
func (arm sendBootstrapAckArm) encodeCanonical() ([]byte, error) {
	if arm.bootstrapSHA256 == ([32]byte{}) {
		return nil, ErrContractInvalidArgument
	}
	encoded := make([]byte, 32)
	copy(encoded, arm.bootstrapSHA256[:])
	return encoded, nil
}
func (arm sendAgentHelloAckArm) encodeCanonical() ([]byte, error) {
	if arm.bootstrapSHA256 == ([32]byte{}) {
		return nil, ErrContractInvalidArgument
	}
	encoded := make([]byte, 32)
	copy(encoded, arm.bootstrapSHA256[:])
	return encoded, nil
}
func (arm sendSSHAcceptedArm) encodeCanonical() ([]byte, error) {
	if arm.revision == 0 || arm.bindingIndex >= credentialprotocol.MaxHelperBindings || arm.connectionOrdinal == 0 || arm.relayCapabilitySHA256 == ([32]byte{}) {
		return nil, ErrContractInvalidArgument
	}
	encoded := make([]byte, 43)
	binary.BigEndian.PutUint64(encoded[:8], arm.revision)
	binary.BigEndian.PutUint16(encoded[8:10], arm.bindingIndex)
	encoded[10] = arm.connectionOrdinal
	copy(encoded[11:], arm.relayCapabilitySHA256[:])
	return encoded, nil
}
func (arm sendExecCreditArm) encodeCanonical() ([]byte, error) {
	return credentialprotocol.EncodeHelperExecCreditBody(arm.body)
}
func (sendExecStreamArm) encodeCanonical() ([]byte, error) { return nil, ErrContractCapability }
func (arm sendResponseArm) encodeCanonical() ([]byte, error) {
	return credentialprotocol.EncodeHelperResponseBody(arm.body)
}
func (arm sendEventArm) encodeCanonical() ([]byte, error) {
	return credentialprotocol.EncodeHelperEventBody(arm.body)
}
func (arm sendCloseNotifyArm) encodeCanonical() ([]byte, error) {
	return credentialprotocol.EncodeHelperCloseNotifyBody(arm.body)
}

// SendPacket is the service-built closed outbound union.
type SendPacket struct {
	liveValue
	header credentialprotocol.HelperPacketHeader
	arm    sendPacketArm
	right  ReceivedCapability
}

func newSendPacket(header credentialprotocol.HelperPacketHeader, arm sendPacketArm, right ReceivedCapability) (packet SendPacket, err error) {
	success := false
	defer func() {
		if success {
			return
		}
		if stream, ok := arm.(sendExecStreamArm); ok && configuredDependency(stream.body) {
			if cleanupErr := stream.body.Destroy(context.Background()); cleanupErr != nil {
				err = ErrContractOwnership
			}
		}
		if configuredDependency(right) {
			if cleanupErr := right.Close(context.Background()); cleanupErr != nil {
				err = ErrContractOwnership
			}
		}
	}()
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
		if right.Kind() != ReceivedCapabilitySSHConnection {
			return SendPacket{}, ErrContractCapability
		}
		sshAccepted, ok := arm.(sendSSHAcceptedArm)
		rightDigest := right.SHA256()
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
		if !validSendExecStreamArm(stream, header.BodyLength) {
			return SendPacket{}, ErrContractCorrelation
		}
		bodySHA256 := stream.body.SHA256()
		if bodySHA256 == ([32]byte{}) {
			return SendPacket{}, ErrContractCorrelation
		}
		packet = SendPacket{header: header, arm: &sealedSendPacketArm{arm: stream, bodyLength: header.BodyLength, bodySHA256: bodySHA256}, right: right}
		success = true
		return packet, nil
	}
	encoded, err := arm.encodeCanonical()
	if err != nil {
		wipeBytes(encoded[:cap(encoded)])
		return SendPacket{}, ErrContractInvalidArgument
	}
	defer wipeBytes(encoded[:cap(encoded)])
	if uint32(len(encoded)) != header.BodyLength || header.Type != sendArmPacketType(arm) {
		return SendPacket{}, ErrContractCorrelation
	}
	packet = SendPacket{header: header, arm: &sealedSendPacketArm{arm: arm, bodyLength: header.BodyLength, bodySHA256: sha256.Sum256(encoded)}, right: right}
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

func newHelperReadyPacket(header credentialprotocol.HelperPacketHeader) (SendPacket, error) {
	return newSendPacket(header, sendHelperReadyArm{}, nil)
}
func newBootstrapAckPacket(header credentialprotocol.HelperPacketHeader, digest [32]byte) (SendPacket, error) {
	return newSendPacket(header, sendBootstrapAckArm{bootstrapSHA256: digest}, nil)
}
func newAgentHelloAckPacket(header credentialprotocol.HelperPacketHeader, digest [32]byte) (SendPacket, error) {
	return newSendPacket(header, sendAgentHelloAckArm{bootstrapSHA256: digest}, nil)
}
func newSSHAcceptedPacket(header credentialprotocol.HelperPacketHeader, revision uint64, bindingIndex uint16, ordinal uint8, digest [32]byte, right ReceivedCapability) (SendPacket, error) {
	return newSendPacket(header, sendSSHAcceptedArm{revision: revision, bindingIndex: bindingIndex, connectionOrdinal: ordinal, relayCapabilitySHA256: digest}, right)
}
func newExecCreditPacket(header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperExecCreditBody) (SendPacket, error) {
	return newSendPacket(header, sendExecCreditArm{body: body}, nil)
}
func newExecStreamPacket(header credentialprotocol.HelperPacketHeader, revision uint64, streamKind credentialprotocol.HelperExecStreamKind, flags credentialprotocol.HelperExecStreamFlags, offset uint64, payloadLength uint32, payloadSHA256 [32]byte, body ReceivedBodyCapability) (SendPacket, error) {
	return newSendPacket(header, sendExecStreamArm{revision: revision, streamKind: streamKind, flags: flags, offset: offset, payloadLength: payloadLength, payloadSHA256: payloadSHA256, body: body}, nil)
}
func newResponsePacket(header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperResponseBody) (SendPacket, error) {
	return newSendPacket(header, sendResponseArm{body: body}, nil)
}
func newEventPacket(header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperEventBody) (SendPacket, error) {
	return newSendPacket(header, sendEventArm{body: body}, nil)
}
func newCloseNotifyPacket(header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperCloseNotifyBody) (SendPacket, error) {
	return newSendPacket(header, sendCloseNotifyArm{body: body}, nil)
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
func (packet SendPacket) WriteCanonicalBody(sink credentialmemory.CredentialSink) error {
	sealed := packet.sealedArm()
	if sealed == nil || sealed.bodyLength != packet.header.BodyLength || !sealed.written.CompareAndSwap(false, true) {
		return ErrContractOwnership
	}
	if !configuredDependency(sink) {
		return ErrContractTypedNil
	}
	if stream, ok := sealed.arm.(sendExecStreamArm); ok {
		if !configuredDependency(stream.body) {
			return ErrContractDestroyed
		}
		if sink.MaxCredentialBytes() < int(packet.header.BodyLength) {
			return ErrContractInvalidArgument
		}
		calls := 0
		err := stream.body.Borrow(context.Background(), func(view credentialmemory.BorrowedView) error {
			calls++
			if calls != 1 || !configuredDependency(view) || view.Len() != int(packet.header.BodyLength) {
				return ErrContractOwnership
			}
			if err := view.WriteTo(context.Background(), sink); err != nil {
				return ErrContractOwnership
			}
			return nil
		})
		if err != nil || calls != 1 {
			return ErrContractOwnership
		}
		return nil
	}
	if !configuredDependency(sealed.arm) {
		return ErrContractInvalidArgument
	}
	encoded, err := sealed.arm.encodeCanonical()
	if err != nil {
		wipeBytes(encoded[:cap(encoded)])
		return ErrContractInvalidArgument
	}
	defer wipeBytes(encoded[:cap(encoded)])
	if len(encoded) != int(packet.header.BodyLength) || sha256.Sum256(encoded) != sealed.bodySHA256 || sink.MaxCredentialBytes() < len(encoded) {
		return ErrContractInvalidArgument
	}
	if err := sink.WriteCredential(encoded); err != nil {
		return ErrContractOwnership
	}
	return nil
}
func (packet SendPacket) RightsCount() uint32 {
	if configuredDependency(packet.right) {
		return 1
	}
	return 0
}
func (packet SendPacket) Right() ReceivedCapability { return packet.right }

func (packet SendPacket) destroyBody(ctx context.Context) error {
	sealed := packet.sealedArm()
	if sealed == nil {
		return nil
	}
	stream, ok := sealed.arm.(sendExecStreamArm)
	if !ok || !configuredDependency(stream.body) {
		return nil
	}
	return stream.body.Destroy(ctx)
}

func (packet SendPacket) sealedArm() *sealedSendPacketArm {
	sealed, _ := packet.arm.(*sealedSendPacketArm)
	return sealed
}

func validSendExecStreamArm(arm sendExecStreamArm, bodyLength uint32) bool {
	if arm.revision == 0 || arm.streamKind != credentialprotocol.HelperExecStreamStdout && arm.streamKind != credentialprotocol.HelperExecStreamStderr ||
		(arm.flags != credentialprotocol.HelperExecStreamFlagsNone && arm.flags != credentialprotocol.HelperExecStreamFlagEOF) ||
		arm.payloadLength > credentialprotocol.MaxHelperExecStreamPayloadBytes ||
		(arm.flags == credentialprotocol.HelperExecStreamFlagsNone && arm.payloadLength == 0) ||
		(arm.flags == credentialprotocol.HelperExecStreamFlagEOF && arm.payloadLength != 0) ||
		(arm.payloadLength == 0 && arm.payloadSHA256 != sha256.Sum256(nil)) ||
		(arm.payloadLength > 0 && arm.payloadSHA256 == ([32]byte{})) ||
		arm.body.Len() != bodyLength || bodyLength != 56+arm.payloadLength {
		return false
	}
	length := arm.body.Len()
	sink := &bodyValidationSink{maximum: int(length), validate: func(encoded []byte) bool {
		if len(encoded) != 56+int(arm.payloadLength) || binary.BigEndian.Uint64(encoded[:8]) != arm.revision || encoded[8] != byte(arm.streamKind) || encoded[9] != byte(arm.flags) || encoded[10] != 0 || encoded[11] != 0 || binary.BigEndian.Uint64(encoded[12:20]) != arm.offset || binary.BigEndian.Uint32(encoded[20:24]) != arm.payloadLength || !equalDigest(encoded[24:56], arm.payloadSHA256) {
			return false
		}
		return sha256.Sum256(encoded[56:]) == arm.payloadSHA256
	}}
	calls := 0
	borrowErr := arm.body.Borrow(context.Background(), func(view credentialmemory.BorrowedView) error {
		calls++
		if calls != 1 || !configuredDependency(view) || view.Len() != int(length) {
			return ErrContractOwnership
		}
		return view.WriteTo(context.Background(), sink)
	})
	bodyDigest := arm.body.SHA256()
	return borrowErr == nil && calls == 1 && sink.writes == 1 && sink.valid && bodyDigest != ([32]byte{}) && bodyDigest == sink.digest
}
