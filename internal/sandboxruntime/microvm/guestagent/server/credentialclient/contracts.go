package credentialclient

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

var ErrLiveValueSerialization = errors.New("credential client live value serialization is forbidden")

var ErrClientPolicyDecision = errors.New("credential client policy decision is invalid")

const clientPolicyID credentialprotocol.SafeID = "client-policy-v1"

// Transport is the exact unprivileged client's controller/helper boundary.
type Transport interface {
	ReceiveController(context.Context, ControllerReceiveRequest) (ControllerPacket, error)
	SendController(context.Context, ControllerSendPacket) error
	ReceiveHelper(context.Context, HelperReceiveRequest) (HelperPacket, error)
	SendHelper(context.Context, HelperSendPacket) error
	Close(context.Context) error
}

// Policy authorizes only safe decoded client metadata.
type Policy interface {
	Authorize(ClientPolicyRequest) (ClientPolicyDecision, error)
	Descriptor() PolicyDescriptor
}

type liveValue struct{}

func (liveValue) MarshalJSON() ([]byte, error) { return nil, ErrLiveValueSerialization }
func (liveValue) MarshalText() ([]byte, error) { return nil, ErrLiveValueSerialization }
func (liveValue) MarshalBinary() ([]byte, error) {
	return nil, ErrLiveValueSerialization
}
func (liveValue) UnmarshalJSON([]byte) error   { return ErrLiveValueSerialization }
func (liveValue) UnmarshalText([]byte) error   { return ErrLiveValueSerialization }
func (liveValue) UnmarshalBinary([]byte) error { return ErrLiveValueSerialization }
func (liveValue) String() string               { return "credentialclient.live[redacted]" }
func (liveValue) GoString() string             { return "credentialclient.live[redacted]" }
func (liveValue) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("credentialclient.live[redacted]"))
}

// ControllerReceiveRequest is a private-constructor, non-JSON receive union.
type ControllerReceiveRequest struct {
	liveValue
	nextSequence          uint64
	expectedIdentity      v2control.IdentityDigest
	expectedIdentitySet   bool
	maximumPlaintextBytes uint32
	state                 *controllerReceiveRequestState
}

// ControllerPacket is an authenticated closed controller union.
type ControllerPacket struct {
	liveValue
	sequence  uint64
	sessionID [32]byte
	arm       controllerPacketArm
	body      controllerBodyCapability
}

// ControllerSendPacket is a core-built closed controller union.
type ControllerSendPacket struct {
	liveValue
	sequence          uint64
	sessionID         [32]byte
	arm               controllerSendArmKind
	encodedBodyLength uint32
	bodySHA256        [32]byte
	state             *controllerSendPacketState
}

// HelperReceiveRequest is a private-constructor, non-JSON receive union.
type HelperReceiveRequest struct {
	liveValue
	nextSequence         uint64
	maximumBodyBytes     uint32
	maximumRights        uint32
	expectedRequestID    [16]byte
	expectedRequestIDSet bool
	expectedIdentity     [32]byte
	state                *helperReceiveRequestState
}

// HelperPacket is an authenticated closed helper union.
type HelperPacket struct {
	liveValue
	header credentialprotocol.HelperPacketHeader
	arm    helperPacketArm
	body   helperBodyCapability
	right  SSHConnectionCapability
}

// HelperSendPacket is a core-built closed helper union.
type HelperSendPacket struct {
	liveValue
	header            credentialprotocol.HelperPacketHeader
	arm               helperSendArmKind
	encodedBodyLength uint32
	bodySHA256        [32]byte
	state             *helperSendPacketState
}

type controllerReceiveRequestState struct {
	mu       sync.Mutex
	consumed bool
}

type helperReceiveRequestState struct {
	mu       sync.Mutex
	consumed bool
}

// ClientPolicyRequest contains only canonical safe policy inputs. The private
// slices are construction snapshots, never generic bodies.
type ClientPolicyRequest struct {
	liveValue
	operation       credentialprotocol.PacketType
	identityDigest  [32]byte
	revision        uint64
	bindingIDs      []credentialprotocol.SafeID
	bindingModes    []credentialprotocol.DeliveryMode
	descriptor      credentialprotocol.ExtensionDescriptor
	fixedLimitSetID credentialprotocol.SafeID
}

// ClientPolicyDecision is either an allow decision or a stable safe rejection.
type ClientPolicyDecision struct {
	liveValue
	allow         bool
	rejectionCode credentialprotocol.SafeID
}

// PolicyDescriptor is the non-JSON immutable client policy identity.
type PolicyDescriptor struct {
	liveValue
	id     credentialprotocol.SafeID
	digest [32]byte
}

// ID returns the descriptor's safe policy identifier.
func (descriptor PolicyDescriptor) ID() credentialprotocol.SafeID {
	return descriptor.id
}

// SHA256 returns the descriptor's fixed process-policy digest.
func (descriptor PolicyDescriptor) SHA256() [32]byte {
	return descriptor.digest
}

func newClientPolicyDescriptor() PolicyDescriptor {
	return newPolicyDescriptor(clientPolicyID)
}

func newPolicyDescriptor(id credentialprotocol.SafeID) PolicyDescriptor {
	encoded := append(encodeOpaque16("hal/l8/process-policy/v1"), encodeOpaque16(string(id))...)
	return PolicyDescriptor{id: id, digest: sha256.Sum256(encoded)}
}

func encodeOpaque16(value string) []byte {
	encoded := make([]byte, 2+len(value))
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(value)))
	copy(encoded[2:], value)
	return encoded
}

func newControllerReceiveRequest(sequence uint64, identityDigest [32]byte) ControllerReceiveRequest {
	return ControllerReceiveRequest{nextSequence: sequence, expectedIdentity: v2control.NewIdentityDigest(identityDigest), expectedIdentitySet: true, maximumPlaintextBytes: 1, state: &controllerReceiveRequestState{}}
}

func newControllerPacket(sequence uint64, identityDigest [32]byte) ControllerPacket {
	return ControllerPacket{sequence: sequence, sessionID: identityDigest}
}

func newControllerSendPacket(sequence uint64, identityDigest [32]byte) ControllerSendPacket {
	return ControllerSendPacket{sequence: sequence, sessionID: identityDigest}
}

func newHelperReceiveRequest(sequence uint64, identityDigest [32]byte) HelperReceiveRequest {
	return HelperReceiveRequest{nextSequence: sequence, expectedIdentity: identityDigest, state: &helperReceiveRequestState{}}
}

func newHelperPacket(packetType credentialprotocol.PacketType, sequence uint64, identityDigest [32]byte) HelperPacket {
	return HelperPacket{header: credentialprotocol.HelperPacketHeader{Type: packetType, Sequence: sequence, GuestCredentialIdentityDigest: identityDigest}}
}

func newHelperSendPacket(packetType credentialprotocol.PacketType, sequence uint64, identityDigest [32]byte) HelperSendPacket {
	return HelperSendPacket{header: credentialprotocol.HelperPacketHeader{Type: packetType, Sequence: sequence, GuestCredentialIdentityDigest: identityDigest}}
}

func newClientPolicyRequest(
	operation credentialprotocol.PacketType,
	identityDigest [32]byte,
	revision uint64,
	bindingIDs []credentialprotocol.SafeID,
	bindingModes []credentialprotocol.DeliveryMode,
	descriptor credentialprotocol.ExtensionDescriptor,
	fixedLimitSetID credentialprotocol.SafeID,
) ClientPolicyRequest {
	return ClientPolicyRequest{
		operation:       operation,
		identityDigest:  identityDigest,
		revision:        revision,
		bindingIDs:      cloneValues(bindingIDs),
		bindingModes:    cloneValues(bindingModes),
		descriptor:      credentialprotocol.CloneExtensionDescriptor(descriptor),
		fixedLimitSetID: fixedLimitSetID,
	}
}

func newClientPolicyAllowDecision() ClientPolicyDecision {
	return ClientPolicyDecision{allow: true}
}

func newClientPolicyRejectionDecision(rejectionCode credentialprotocol.SafeID) (ClientPolicyDecision, error) {
	if credentialprotocol.ValidateSafeID(rejectionCode) != nil {
		return ClientPolicyDecision{}, ErrClientPolicyDecision
	}
	return ClientPolicyDecision{rejectionCode: rejectionCode}, nil
}

func cloneValues[T any](values []T) []T {
	if values == nil {
		return nil
	}
	result := make([]T, len(values))
	copy(result, values)
	return result
}
