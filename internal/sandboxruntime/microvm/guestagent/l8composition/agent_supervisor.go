package l8composition

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	AgentSupervisorMagic   = "HL8A"
	AgentSupervisorVersion = 1
	AgentSupervisorFlags   = 0

	AgentSupervisorHeaderBytes      = 68
	MaxAgentSupervisorBodyBytes     = 8 * 1024
	MaxAgentSupervisorDatagramBytes = AgentSupervisorHeaderBytes + MaxAgentSupervisorBodyBytes

	AgentSupervisorServiceUID uint32 = 998
	AgentSupervisorServiceGID uint32 = 998

	agentSupervisorAgentConfigFixedBytes = 12 + 3*sha256.Size
	agentSupervisorDigestBodyBytes       = sha256.Size
	agentSupervisorCloseBodyBytes        = 1
)

var (
	ErrAgentSupervisorHeaderLength           = errors.New("L8 agent-supervisor header length is invalid")
	ErrAgentSupervisorMagic                  = errors.New("L8 agent-supervisor magic is invalid")
	ErrAgentSupervisorVersion                = errors.New("L8 agent-supervisor version is invalid")
	ErrAgentSupervisorFlags                  = errors.New("L8 agent-supervisor flags are invalid")
	ErrAgentSupervisorPacketType             = errors.New("L8 agent-supervisor packet type is invalid")
	ErrAgentSupervisorDirection              = errors.New("L8 agent-supervisor direction is invalid")
	ErrAgentSupervisorPacketDirection        = errors.New("L8 agent-supervisor packet direction is invalid")
	ErrAgentSupervisorRequestIdentity        = errors.New("L8 agent-supervisor request identity is nonzero")
	ErrAgentSupervisorJobIdentity            = errors.New("L8 agent-supervisor job identity is nonzero")
	ErrAgentSupervisorBodyLength             = errors.New("L8 agent-supervisor body length is invalid")
	ErrAgentSupervisorDatagramLength         = errors.New("L8 agent-supervisor datagram is truncated")
	ErrAgentSupervisorDatagramTrailingData   = errors.New("L8 agent-supervisor datagram has trailing data")
	ErrAgentSupervisorRights                 = errors.New("L8 agent-supervisor ancillary rights are invalid")
	ErrAgentSupervisorTruncated              = errors.New("L8 agent-supervisor receive metadata reports truncation")
	ErrAgentSupervisorCredentialCount        = errors.New("L8 agent-supervisor kernel credential count is invalid")
	ErrAgentSupervisorKernelCredential       = errors.New("L8 agent-supervisor kernel credential does not match")
	ErrAgentSupervisorControllerIdentity     = errors.New("L8 agent-supervisor controller identity is invalid")
	ErrAgentSupervisorPeerIdentity           = errors.New("L8 agent-supervisor peer identity is invalid")
	ErrAgentSupervisorDigestZero             = errors.New("L8 agent-supervisor digest is zero")
	ErrAgentSupervisorConfigLength           = errors.New("L8 agent-supervisor agent-config body is truncated")
	ErrAgentSupervisorConfigTrailingData     = errors.New("L8 agent-supervisor agent-config body has trailing data")
	ErrAgentSupervisorDescriptorLength       = errors.New("L8 agent-supervisor descriptor length is invalid")
	ErrAgentSupervisorDescriptorRole         = errors.New("L8 agent-supervisor descriptor role is invalid")
	ErrAgentSupervisorDescriptorTrailingData = errors.New("L8 agent-supervisor descriptor body has trailing data")
	ErrAgentSupervisorAcceptedLength         = errors.New("L8 agent-supervisor composition-accepted body is truncated")
	ErrAgentSupervisorAcceptedTrailingData   = errors.New("L8 agent-supervisor composition-accepted body has trailing data")
	ErrAgentSupervisorCloseLength            = errors.New("L8 agent-supervisor close-notify body is truncated")
	ErrAgentSupervisorCloseTrailingData      = errors.New("L8 agent-supervisor close-notify body has trailing data")
	ErrAgentSupervisorPacketBody             = errors.New("L8 agent-supervisor packet body does not match its type")
	ErrAgentSupervisorSequence               = errors.New("L8 agent-supervisor packet sequence is invalid")
	ErrAgentSupervisorSequenceWrap           = errors.New("L8 agent-supervisor packet sequence would wrap")
	ErrAgentSupervisorTransition             = errors.New("L8 agent-supervisor pre-admission transition is invalid")
	ErrAgentSupervisorConfigMismatch         = errors.New("L8 agent-supervisor agent config does not match")
	ErrAgentSupervisorDescriptorMismatch     = errors.New("L8 agent-supervisor client descriptor does not match")
	ErrAgentSupervisorCompositionMismatch    = errors.New("L8 agent-supervisor composition digest does not match")
	ErrAgentSupervisorClosed                 = errors.New("L8 agent-supervisor closed before admission")
	ErrAgentSupervisorPacketAfterAccepted    = errors.New("L8 agent-supervisor packet arrived after composition acceptance")
	ErrAgentSupervisorTerminal               = errors.New("L8 agent-supervisor pre-admission state is terminal")
	ErrAgentSupervisorSerialization          = errors.New("L8 agent-supervisor serialization is denied")
)

// AgentSupervisorPacketType is the closed HL8A packet catalog.
type AgentSupervisorPacketType uint8

const (
	AgentSupervisorPacketTypeAgentConfig         AgentSupervisorPacketType = 0x01
	AgentSupervisorPacketTypeClientAttestation   AgentSupervisorPacketType = 0x02
	AgentSupervisorPacketTypeCompositionAccepted AgentSupervisorPacketType = 0x03
	AgentSupervisorPacketTypeCloseNotify         AgentSupervisorPacketType = 0x7f
)

// AgentSupervisorDirection is authenticated sender-to-receiver metadata. It
// is deliberately absent from the wire and supplied by the endpoint owner.
type AgentSupervisorDirection uint8

const (
	AgentSupervisorDirectionPID1ToAgent AgentSupervisorDirection = 1
	AgentSupervisorDirectionAgentToPID1 AgentSupervisorDirection = 2
)

// AgentSupervisorDecision is the complete pure pre-admission disposition.
type AgentSupervisorDecision uint8

const (
	AgentSupervisorDecisionContinue AgentSupervisorDecision = 1
	AgentSupervisorDecisionCloseFD4 AgentSupervisorDecision = 2
	AgentSupervisorDecisionStopVM   AgentSupervisorDecision = 3
)

// AgentSupervisorHeader is the data-only projection of the exact 68-byte
// header. RequestID and JobIdentityDigest must always be zero for HL8A.
type AgentSupervisorHeader struct {
	Type              AgentSupervisorPacketType
	Sequence          uint64
	RequestID         [16]byte
	JobIdentityDigest [32]byte
	BodyLength        uint32
}

// AgentSupervisorAgentConfigBody is the exact safe boot tuple sent by PID1.
// Generation values use the existing canonical HL8P body-token encoding.
type AgentSupervisorAgentConfigBody struct {
	ControllerPID          uint32
	ControllerUID          uint32
	ControllerGID          uint32
	HelperGeneration       string
	BootGeneration         string
	BootNonce              [sha256.Size]byte
	BootstrapSHA256        [sha256.Size]byte
	ClientDescriptorSHA256 [sha256.Size]byte
	VSockGeneration        string
}

// AgentSupervisorClientAttestationBody owns a canonical client descriptor.
type AgentSupervisorClientAttestationBody struct {
	Descriptor ProcessDescriptor
}

// AgentSupervisorCompositionAcceptedBody carries the independently verified
// canonical composition digest.
type AgentSupervisorCompositionAcceptedBody struct {
	CompositionSHA256 [sha256.Size]byte
}

// AgentSupervisorCloseNotifyBody carries only the shared closed reason code.
type AgentSupervisorCloseNotifyBody struct {
	Reason credentialprotocol.CloseReason
}

// AgentSupervisorPacket is a closed decoded packet union. Its fields stay
// private so a caller cannot manufacture a mismatched type/body pair.
type AgentSupervisorPacket struct {
	header      AgentSupervisorHeader
	config      AgentSupervisorAgentConfigBody
	attestation AgentSupervisorClientAttestationBody
	accepted    AgentSupervisorCompositionAcceptedBody
	closeBody   AgentSupervisorCloseNotifyBody
}

// AgentSupervisorKernelCredential is inspected-kernel metadata supplied by a
// future live adapter; this package performs no credential or socket syscall.
type AgentSupervisorKernelCredential struct {
	PID uint32
	UID uint32
	GID uint32
}

// AgentSupervisorReceiveMetadata is the complete pure receive decision input.
// RightsCount is descriptor cardinality, never raw descriptor values.
type AgentSupervisorReceiveMetadata struct {
	Direction        AgentSupervisorDirection
	Credential       AgentSupervisorKernelCredential
	CredentialCount  uint32
	RightsCount      uint32
	MessageTruncated bool
	ControlTruncated bool
}

// AgentSupervisorPreAdmissionExpected is immutable caller-owned correlation.
type AgentSupervisorPreAdmissionExpected struct {
	PID1Credential    AgentSupervisorKernelCredential
	AgentCredential   AgentSupervisorKernelCredential
	AgentConfig       AgentSupervisorAgentConfigBody
	ClientDescriptor  ProcessDescriptor
	CompositionSHA256 [sha256.Size]byte
}

type agentSupervisorPhase uint8

const (
	agentSupervisorPhaseConfig agentSupervisorPhase = iota + 1
	agentSupervisorPhaseAttestation
	agentSupervisorPhaseComposition
	agentSupervisorPhaseAccepted
	agentSupervisorPhaseStopped
)

// AgentSupervisorPreAdmissionState is a deterministic, in-memory protocol
// verifier. It owns no live endpoint and all terminal decisions are permanent.
type AgentSupervisorPreAdmissionState struct {
	phase                agentSupervisorPhase
	pid1Credential       AgentSupervisorKernelCredential
	agentCredential      AgentSupervisorKernelCredential
	config               AgentSupervisorAgentConfigBody
	clientDescriptor     ProcessDescriptor
	clientDescriptorWire []byte
	compositionSHA256    [sha256.Size]byte
	nextPID1ToAgent      uint64
	nextAgentToPID1      uint64
}

func ValidateAgentSupervisorPacketType(value AgentSupervisorPacketType) error {
	switch value {
	case AgentSupervisorPacketTypeAgentConfig, AgentSupervisorPacketTypeClientAttestation,
		AgentSupervisorPacketTypeCompositionAccepted, AgentSupervisorPacketTypeCloseNotify:
		return nil
	default:
		return ErrAgentSupervisorPacketType
	}
}

func ValidateAgentSupervisorDirection(value AgentSupervisorDirection) error {
	if value != AgentSupervisorDirectionPID1ToAgent && value != AgentSupervisorDirectionAgentToPID1 {
		return ErrAgentSupervisorDirection
	}
	return nil
}

// ValidateAgentSupervisorPacketMetadata locks the direction and no-rights
// matrix independently of a state-machine phase.
func ValidateAgentSupervisorPacketMetadata(packetType AgentSupervisorPacketType, direction AgentSupervisorDirection, rightsCount uint32) error {
	if err := ValidateAgentSupervisorPacketType(packetType); err != nil {
		return err
	}
	if err := ValidateAgentSupervisorDirection(direction); err != nil {
		return err
	}
	if rightsCount != 0 {
		return ErrAgentSupervisorRights
	}
	switch packetType {
	case AgentSupervisorPacketTypeAgentConfig, AgentSupervisorPacketTypeCompositionAccepted:
		if direction != AgentSupervisorDirectionPID1ToAgent {
			return ErrAgentSupervisorPacketDirection
		}
	case AgentSupervisorPacketTypeClientAttestation:
		if direction != AgentSupervisorDirectionAgentToPID1 {
			return ErrAgentSupervisorPacketDirection
		}
	case AgentSupervisorPacketTypeCloseNotify:
		return nil
	}
	return nil
}

func EncodeAgentSupervisorHeader(header AgentSupervisorHeader) ([AgentSupervisorHeaderBytes]byte, error) {
	var encoded [AgentSupervisorHeaderBytes]byte
	if err := validateAgentSupervisorHeader(header); err != nil {
		return encoded, err
	}
	copy(encoded[:4], AgentSupervisorMagic)
	encoded[4] = AgentSupervisorVersion
	encoded[5] = byte(header.Type)
	binary.BigEndian.PutUint16(encoded[6:8], AgentSupervisorFlags)
	binary.BigEndian.PutUint64(encoded[8:16], header.Sequence)
	copy(encoded[16:32], header.RequestID[:])
	copy(encoded[32:64], header.JobIdentityDigest[:])
	binary.BigEndian.PutUint32(encoded[64:68], header.BodyLength)
	return encoded, nil
}

func DecodeAgentSupervisorHeader(encoded []byte) (AgentSupervisorHeader, error) {
	if len(encoded) != AgentSupervisorHeaderBytes {
		return AgentSupervisorHeader{}, ErrAgentSupervisorHeaderLength
	}
	if !bytes.Equal(encoded[:4], []byte(AgentSupervisorMagic)) {
		return AgentSupervisorHeader{}, ErrAgentSupervisorMagic
	}
	if encoded[4] != AgentSupervisorVersion {
		return AgentSupervisorHeader{}, ErrAgentSupervisorVersion
	}
	if binary.BigEndian.Uint16(encoded[6:8]) != AgentSupervisorFlags {
		return AgentSupervisorHeader{}, ErrAgentSupervisorFlags
	}
	header := AgentSupervisorHeader{
		Type:       AgentSupervisorPacketType(encoded[5]),
		Sequence:   binary.BigEndian.Uint64(encoded[8:16]),
		BodyLength: binary.BigEndian.Uint32(encoded[64:68]),
	}
	copy(header.RequestID[:], encoded[16:32])
	copy(header.JobIdentityDigest[:], encoded[32:64])
	if err := validateAgentSupervisorHeader(header); err != nil {
		return AgentSupervisorHeader{}, err
	}
	return header, nil
}

func validateAgentSupervisorHeader(header AgentSupervisorHeader) error {
	if err := ValidateAgentSupervisorPacketType(header.Type); err != nil {
		return err
	}
	if header.RequestID != [16]byte{} {
		return ErrAgentSupervisorRequestIdentity
	}
	if header.JobIdentityDigest != [32]byte{} {
		return ErrAgentSupervisorJobIdentity
	}
	if header.BodyLength > MaxAgentSupervisorBodyBytes {
		return ErrAgentSupervisorBodyLength
	}
	return nil
}

func EncodeAgentSupervisorAgentConfigBody(body AgentSupervisorAgentConfigBody) ([]byte, error) {
	if err := validateAgentSupervisorAgentConfig(body); err != nil {
		return nil, err
	}
	helper, _ := credentialprotocol.EncodeBodyToken(body.HelperGeneration)
	boot, _ := credentialprotocol.EncodeBodyToken(body.BootGeneration)
	vsock, _ := credentialprotocol.EncodeBodyToken(body.VSockGeneration)
	encoded := make([]byte, 12, agentSupervisorAgentConfigFixedBytes+len(helper)+len(boot)+len(vsock))
	binary.BigEndian.PutUint32(encoded[0:4], body.ControllerPID)
	binary.BigEndian.PutUint32(encoded[4:8], body.ControllerUID)
	binary.BigEndian.PutUint32(encoded[8:12], body.ControllerGID)
	encoded = append(encoded, helper...)
	encoded = append(encoded, boot...)
	encoded = append(encoded, body.BootNonce[:]...)
	encoded = append(encoded, body.BootstrapSHA256[:]...)
	encoded = append(encoded, body.ClientDescriptorSHA256[:]...)
	return append(encoded, vsock...), nil
}

func DecodeAgentSupervisorAgentConfigBody(encoded []byte) (AgentSupervisorAgentConfigBody, error) {
	if len(encoded) < 12 {
		return AgentSupervisorAgentConfigBody{}, ErrAgentSupervisorConfigLength
	}
	body := AgentSupervisorAgentConfigBody{
		ControllerPID: binary.BigEndian.Uint32(encoded[0:4]),
		ControllerUID: binary.BigEndian.Uint32(encoded[4:8]),
		ControllerGID: binary.BigEndian.Uint32(encoded[8:12]),
	}
	offset := 12
	var consumed int
	var err error
	body.HelperGeneration, consumed, err = credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
	if err != nil {
		return AgentSupervisorAgentConfigBody{}, err
	}
	offset += consumed
	body.BootGeneration, consumed, err = credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
	if err != nil {
		return AgentSupervisorAgentConfigBody{}, err
	}
	offset += consumed
	if len(encoded)-offset < 3*sha256.Size {
		return AgentSupervisorAgentConfigBody{}, ErrAgentSupervisorConfigLength
	}
	copy(body.BootNonce[:], encoded[offset:offset+sha256.Size])
	offset += sha256.Size
	copy(body.BootstrapSHA256[:], encoded[offset:offset+sha256.Size])
	offset += sha256.Size
	copy(body.ClientDescriptorSHA256[:], encoded[offset:offset+sha256.Size])
	offset += sha256.Size
	body.VSockGeneration, consumed, err = credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
	if err != nil {
		return AgentSupervisorAgentConfigBody{}, err
	}
	offset += consumed
	if offset != len(encoded) {
		return AgentSupervisorAgentConfigBody{}, ErrAgentSupervisorConfigTrailingData
	}
	if err := validateAgentSupervisorAgentConfig(body); err != nil {
		return AgentSupervisorAgentConfigBody{}, err
	}
	return body, nil
}

func validateAgentSupervisorAgentConfig(body AgentSupervisorAgentConfigBody) error {
	if !validAgentSupervisorPID(body.ControllerPID) || body.ControllerUID != 0 || body.ControllerGID != 0 {
		return ErrAgentSupervisorControllerIdentity
	}
	if err := credentialprotocol.ValidateBodyToken(body.HelperGeneration); err != nil {
		return err
	}
	if err := credentialprotocol.ValidateBodyToken(body.BootGeneration); err != nil {
		return err
	}
	if err := credentialprotocol.ValidateBodyToken(body.VSockGeneration); err != nil {
		return err
	}
	if body.BootNonce == [sha256.Size]byte{} || body.BootstrapSHA256 == [sha256.Size]byte{} || body.ClientDescriptorSHA256 == [sha256.Size]byte{} {
		return ErrAgentSupervisorDigestZero
	}
	return nil
}

func EncodeAgentSupervisorClientAttestationBody(body AgentSupervisorClientAttestationBody) ([]byte, error) {
	if body.Descriptor.Role != ProcessRoleClient {
		return nil, ErrAgentSupervisorDescriptorRole
	}
	descriptor, err := EncodeProcessDescriptor(body.Descriptor)
	if err != nil {
		return nil, err
	}
	if len(descriptor) == 0 || len(descriptor) > MaxProcessDescriptorBytes {
		return nil, ErrAgentSupervisorDescriptorLength
	}
	encoded := make([]byte, 2, 2+len(descriptor))
	binary.BigEndian.PutUint16(encoded, uint16(len(descriptor)))
	return append(encoded, descriptor...), nil
}

func DecodeAgentSupervisorClientAttestationBody(encoded []byte) (AgentSupervisorClientAttestationBody, error) {
	if len(encoded) < 2 {
		return AgentSupervisorClientAttestationBody{}, ErrAgentSupervisorDescriptorLength
	}
	length := int(binary.BigEndian.Uint16(encoded[:2]))
	if length == 0 || length > MaxProcessDescriptorBytes {
		return AgentSupervisorClientAttestationBody{}, ErrAgentSupervisorDescriptorLength
	}
	if len(encoded)-2 < length {
		return AgentSupervisorClientAttestationBody{}, ErrAgentSupervisorDescriptorLength
	}
	if len(encoded)-2 > length {
		return AgentSupervisorClientAttestationBody{}, ErrAgentSupervisorDescriptorTrailingData
	}
	descriptor, err := DecodeProcessDescriptor(encoded[2:])
	if err != nil {
		return AgentSupervisorClientAttestationBody{}, err
	}
	if descriptor.Role != ProcessRoleClient {
		return AgentSupervisorClientAttestationBody{}, ErrAgentSupervisorDescriptorRole
	}
	return AgentSupervisorClientAttestationBody{Descriptor: descriptor}, nil
}

func EncodeAgentSupervisorCompositionAcceptedBody(body AgentSupervisorCompositionAcceptedBody) ([]byte, error) {
	if body.CompositionSHA256 == [sha256.Size]byte{} {
		return nil, ErrAgentSupervisorDigestZero
	}
	return append([]byte(nil), body.CompositionSHA256[:]...), nil
}

func DecodeAgentSupervisorCompositionAcceptedBody(encoded []byte) (AgentSupervisorCompositionAcceptedBody, error) {
	if len(encoded) < agentSupervisorDigestBodyBytes {
		return AgentSupervisorCompositionAcceptedBody{}, ErrAgentSupervisorAcceptedLength
	}
	if len(encoded) > agentSupervisorDigestBodyBytes {
		return AgentSupervisorCompositionAcceptedBody{}, ErrAgentSupervisorAcceptedTrailingData
	}
	var body AgentSupervisorCompositionAcceptedBody
	copy(body.CompositionSHA256[:], encoded)
	if body.CompositionSHA256 == [sha256.Size]byte{} {
		return AgentSupervisorCompositionAcceptedBody{}, ErrAgentSupervisorDigestZero
	}
	return body, nil
}

func EncodeAgentSupervisorCloseNotifyBody(body AgentSupervisorCloseNotifyBody) ([]byte, error) {
	if err := credentialprotocol.ValidateCloseReason(body.Reason); err != nil {
		return nil, err
	}
	return []byte{byte(body.Reason)}, nil
}

func DecodeAgentSupervisorCloseNotifyBody(encoded []byte) (AgentSupervisorCloseNotifyBody, error) {
	if len(encoded) < agentSupervisorCloseBodyBytes {
		return AgentSupervisorCloseNotifyBody{}, ErrAgentSupervisorCloseLength
	}
	if len(encoded) > agentSupervisorCloseBodyBytes {
		return AgentSupervisorCloseNotifyBody{}, ErrAgentSupervisorCloseTrailingData
	}
	body := AgentSupervisorCloseNotifyBody{Reason: credentialprotocol.CloseReason(encoded[0])}
	if err := credentialprotocol.ValidateCloseReason(body.Reason); err != nil {
		return AgentSupervisorCloseNotifyBody{}, err
	}
	return body, nil
}

func EncodeAgentSupervisorAgentConfigPacket(sequence uint64, body AgentSupervisorAgentConfigBody) ([]byte, error) {
	encoded, err := EncodeAgentSupervisorAgentConfigBody(body)
	if err != nil {
		return nil, err
	}
	return encodeAgentSupervisorTypedPacket(AgentSupervisorPacketTypeAgentConfig, sequence, encoded)
}

func EncodeAgentSupervisorClientAttestationPacket(sequence uint64, body AgentSupervisorClientAttestationBody) ([]byte, error) {
	encoded, err := EncodeAgentSupervisorClientAttestationBody(body)
	if err != nil {
		return nil, err
	}
	return encodeAgentSupervisorTypedPacket(AgentSupervisorPacketTypeClientAttestation, sequence, encoded)
}

func EncodeAgentSupervisorCompositionAcceptedPacket(sequence uint64, body AgentSupervisorCompositionAcceptedBody) ([]byte, error) {
	encoded, err := EncodeAgentSupervisorCompositionAcceptedBody(body)
	if err != nil {
		return nil, err
	}
	return encodeAgentSupervisorTypedPacket(AgentSupervisorPacketTypeCompositionAccepted, sequence, encoded)
}

func EncodeAgentSupervisorCloseNotifyPacket(sequence uint64, body AgentSupervisorCloseNotifyBody) ([]byte, error) {
	encoded, err := EncodeAgentSupervisorCloseNotifyBody(body)
	if err != nil {
		return nil, err
	}
	return encodeAgentSupervisorTypedPacket(AgentSupervisorPacketTypeCloseNotify, sequence, encoded)
}

func encodeAgentSupervisorTypedPacket(packetType AgentSupervisorPacketType, sequence uint64, body []byte) ([]byte, error) {
	if len(body) > MaxAgentSupervisorBodyBytes {
		return nil, ErrAgentSupervisorBodyLength
	}
	header, err := EncodeAgentSupervisorHeader(AgentSupervisorHeader{Type: packetType, Sequence: sequence, BodyLength: uint32(len(body))})
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, len(header)+len(body))
	encoded = append(encoded, header[:]...)
	return append(encoded, body...), nil
}

func DecodeAgentSupervisorPacket(encoded []byte) (AgentSupervisorPacket, error) {
	if len(encoded) < AgentSupervisorHeaderBytes {
		return AgentSupervisorPacket{}, ErrAgentSupervisorHeaderLength
	}
	header, err := DecodeAgentSupervisorHeader(encoded[:AgentSupervisorHeaderBytes])
	if err != nil {
		return AgentSupervisorPacket{}, err
	}
	expectedLength := AgentSupervisorHeaderBytes + int(header.BodyLength)
	if len(encoded) < expectedLength {
		return AgentSupervisorPacket{}, ErrAgentSupervisorDatagramLength
	}
	if len(encoded) > expectedLength {
		return AgentSupervisorPacket{}, ErrAgentSupervisorDatagramTrailingData
	}
	packet := AgentSupervisorPacket{header: header}
	body := encoded[AgentSupervisorHeaderBytes:]
	switch header.Type {
	case AgentSupervisorPacketTypeAgentConfig:
		packet.config, err = DecodeAgentSupervisorAgentConfigBody(body)
	case AgentSupervisorPacketTypeClientAttestation:
		packet.attestation, err = DecodeAgentSupervisorClientAttestationBody(body)
	case AgentSupervisorPacketTypeCompositionAccepted:
		packet.accepted, err = DecodeAgentSupervisorCompositionAcceptedBody(body)
	case AgentSupervisorPacketTypeCloseNotify:
		packet.closeBody, err = DecodeAgentSupervisorCloseNotifyBody(body)
	default:
		err = ErrAgentSupervisorPacketType
	}
	if err != nil {
		return AgentSupervisorPacket{}, err
	}
	return packet, nil
}

func EncodeAgentSupervisorPacket(packet AgentSupervisorPacket) ([]byte, error) {
	if err := validateAgentSupervisorPacketUnion(packet); err != nil {
		return nil, err
	}
	var encoded []byte
	var err error
	switch packet.header.Type {
	case AgentSupervisorPacketTypeAgentConfig:
		encoded, err = EncodeAgentSupervisorAgentConfigPacket(packet.header.Sequence, packet.config)
	case AgentSupervisorPacketTypeClientAttestation:
		encoded, err = EncodeAgentSupervisorClientAttestationPacket(packet.header.Sequence, packet.attestation)
	case AgentSupervisorPacketTypeCompositionAccepted:
		encoded, err = EncodeAgentSupervisorCompositionAcceptedPacket(packet.header.Sequence, packet.accepted)
	case AgentSupervisorPacketTypeCloseNotify:
		encoded, err = EncodeAgentSupervisorCloseNotifyPacket(packet.header.Sequence, packet.closeBody)
	default:
		return nil, ErrAgentSupervisorPacketBody
	}
	if err != nil {
		return nil, err
	}
	rebuilt, err := DecodeAgentSupervisorHeader(encoded[:AgentSupervisorHeaderBytes])
	if err != nil || rebuilt != packet.header {
		return nil, ErrAgentSupervisorPacketBody
	}
	return encoded, nil
}

func validateAgentSupervisorPacketUnion(packet AgentSupervisorPacket) error {
	emptyDescriptor := func(value ProcessDescriptor) bool {
		return value.ContractVersion == "" && value.Role == 0 && len(value.Extensions) == 0 && value.PolicySHA256 == [sha256.Size]byte{}
	}
	emptyConfig := packet.config == (AgentSupervisorAgentConfigBody{})
	emptyAttestation := emptyDescriptor(packet.attestation.Descriptor)
	emptyAccepted := packet.accepted == (AgentSupervisorCompositionAcceptedBody{})
	emptyClose := packet.closeBody == (AgentSupervisorCloseNotifyBody{})
	switch packet.header.Type {
	case AgentSupervisorPacketTypeAgentConfig:
		if !emptyAttestation || !emptyAccepted || !emptyClose {
			return ErrAgentSupervisorPacketBody
		}
	case AgentSupervisorPacketTypeClientAttestation:
		if !emptyConfig || !emptyAccepted || !emptyClose {
			return ErrAgentSupervisorPacketBody
		}
	case AgentSupervisorPacketTypeCompositionAccepted:
		if !emptyConfig || !emptyAttestation || !emptyClose {
			return ErrAgentSupervisorPacketBody
		}
	case AgentSupervisorPacketTypeCloseNotify:
		if !emptyConfig || !emptyAttestation || !emptyAccepted {
			return ErrAgentSupervisorPacketBody
		}
	default:
		return ErrAgentSupervisorPacketBody
	}
	return nil
}

func (packet AgentSupervisorPacket) Header() AgentSupervisorHeader { return packet.header }

func (packet AgentSupervisorPacket) AgentConfig() (AgentSupervisorAgentConfigBody, bool) {
	return packet.config, packet.header.Type == AgentSupervisorPacketTypeAgentConfig
}

func (packet AgentSupervisorPacket) ClientAttestation() (AgentSupervisorClientAttestationBody, bool) {
	if packet.header.Type != AgentSupervisorPacketTypeClientAttestation {
		return AgentSupervisorClientAttestationBody{}, false
	}
	return AgentSupervisorClientAttestationBody{Descriptor: cloneAgentSupervisorDescriptor(packet.attestation.Descriptor)}, true
}

func (packet AgentSupervisorPacket) CompositionAccepted() (AgentSupervisorCompositionAcceptedBody, bool) {
	return packet.accepted, packet.header.Type == AgentSupervisorPacketTypeCompositionAccepted
}

func (packet AgentSupervisorPacket) CloseNotify() (AgentSupervisorCloseNotifyBody, bool) {
	return packet.closeBody, packet.header.Type == AgentSupervisorPacketTypeCloseNotify
}

// NewAgentSupervisorPreAdmissionState validates and snapshots all sealed
// expectations before accepting any packet.
func NewAgentSupervisorPreAdmissionState(expected AgentSupervisorPreAdmissionExpected) (*AgentSupervisorPreAdmissionState, error) {
	if !validAgentSupervisorPID1Credential(expected.PID1Credential) || !validAgentSupervisorAgentCredential(expected.AgentCredential) {
		return nil, ErrAgentSupervisorPeerIdentity
	}
	if err := validateAgentSupervisorAgentConfig(expected.AgentConfig); err != nil {
		return nil, err
	}
	clientWire, err := EncodeAgentSupervisorClientAttestationBody(AgentSupervisorClientAttestationBody{Descriptor: expected.ClientDescriptor})
	if err != nil {
		return nil, err
	}
	descriptorWire := clientWire[2:]
	if sha256.Sum256(descriptorWire) != expected.AgentConfig.ClientDescriptorSHA256 {
		return nil, ErrAgentSupervisorConfigMismatch
	}
	if expected.CompositionSHA256 == [sha256.Size]byte{} {
		return nil, ErrAgentSupervisorDigestZero
	}
	return &AgentSupervisorPreAdmissionState{
		phase:                agentSupervisorPhaseConfig,
		pid1Credential:       expected.PID1Credential,
		agentCredential:      expected.AgentCredential,
		config:               expected.AgentConfig,
		clientDescriptor:     cloneAgentSupervisorDescriptor(expected.ClientDescriptor),
		clientDescriptorWire: append([]byte(nil), descriptorWire...),
		compositionSHA256:    expected.CompositionSHA256,
	}, nil
}

// Accept authenticates metadata, decodes one complete packet, advances the
// exact finite pre-admission transition, and permanently fails closed.
func (state *AgentSupervisorPreAdmissionState) Accept(metadata AgentSupervisorReceiveMetadata, encoded []byte) (AgentSupervisorDecision, error) {
	if state == nil {
		return AgentSupervisorDecisionStopVM, ErrAgentSupervisorTerminal
	}
	if state.phase == agentSupervisorPhaseAccepted {
		state.phase = agentSupervisorPhaseStopped
		return AgentSupervisorDecisionStopVM, ErrAgentSupervisorPacketAfterAccepted
	}
	if state.phase == agentSupervisorPhaseStopped {
		return AgentSupervisorDecisionStopVM, ErrAgentSupervisorTerminal
	}
	if metadata.MessageTruncated || metadata.ControlTruncated {
		return state.stop(ErrAgentSupervisorTruncated)
	}
	if err := ValidateAgentSupervisorDirection(metadata.Direction); err != nil {
		return state.stop(err)
	}
	if metadata.RightsCount != 0 {
		return state.stop(ErrAgentSupervisorRights)
	}
	if metadata.CredentialCount != 1 {
		return state.stop(ErrAgentSupervisorCredentialCount)
	}
	if !state.credentialMatches(metadata.Direction, metadata.Credential) {
		return state.stop(ErrAgentSupervisorKernelCredential)
	}
	packet, err := DecodeAgentSupervisorPacket(encoded)
	if err != nil {
		return state.stop(err)
	}
	if err := ValidateAgentSupervisorPacketMetadata(packet.header.Type, metadata.Direction, metadata.RightsCount); err != nil {
		return state.stop(err)
	}
	expectedSequence := state.nextSequence(metadata.Direction)
	if packet.header.Sequence != expectedSequence {
		return state.stop(ErrAgentSupervisorSequence)
	}
	if packet.header.Sequence == ^uint64(0) {
		return state.stop(ErrAgentSupervisorSequenceWrap)
	}

	if packet.header.Type == AgentSupervisorPacketTypeCloseNotify {
		state.advance(metadata.Direction)
		return state.stop(ErrAgentSupervisorClosed)
	}

	switch state.phase {
	case agentSupervisorPhaseConfig:
		if packet.header.Type != AgentSupervisorPacketTypeAgentConfig {
			return state.stop(ErrAgentSupervisorTransition)
		}
		if packet.config != state.config {
			return state.stop(ErrAgentSupervisorConfigMismatch)
		}
		state.advance(metadata.Direction)
		state.phase = agentSupervisorPhaseAttestation
		return AgentSupervisorDecisionContinue, nil
	case agentSupervisorPhaseAttestation:
		if packet.header.Type != AgentSupervisorPacketTypeClientAttestation {
			return state.stop(ErrAgentSupervisorTransition)
		}
		actual, err := EncodeProcessDescriptor(packet.attestation.Descriptor)
		if err != nil || !bytes.Equal(actual, state.clientDescriptorWire) || sha256.Sum256(actual) != state.config.ClientDescriptorSHA256 {
			return state.stop(ErrAgentSupervisorDescriptorMismatch)
		}
		state.advance(metadata.Direction)
		state.phase = agentSupervisorPhaseComposition
		return AgentSupervisorDecisionContinue, nil
	case agentSupervisorPhaseComposition:
		if packet.header.Type != AgentSupervisorPacketTypeCompositionAccepted {
			return state.stop(ErrAgentSupervisorTransition)
		}
		if packet.accepted.CompositionSHA256 != state.compositionSHA256 {
			return state.stop(ErrAgentSupervisorCompositionMismatch)
		}
		state.advance(metadata.Direction)
		state.phase = agentSupervisorPhaseAccepted
		return AgentSupervisorDecisionCloseFD4, nil
	default:
		return state.stop(ErrAgentSupervisorTerminal)
	}
}

func (state *AgentSupervisorPreAdmissionState) credentialMatches(direction AgentSupervisorDirection, actual AgentSupervisorKernelCredential) bool {
	if direction == AgentSupervisorDirectionPID1ToAgent {
		return actual == state.pid1Credential
	}
	return actual == state.agentCredential
}

func (state *AgentSupervisorPreAdmissionState) nextSequence(direction AgentSupervisorDirection) uint64 {
	if direction == AgentSupervisorDirectionPID1ToAgent {
		return state.nextPID1ToAgent
	}
	return state.nextAgentToPID1
}

func (state *AgentSupervisorPreAdmissionState) advance(direction AgentSupervisorDirection) {
	if direction == AgentSupervisorDirectionPID1ToAgent {
		state.nextPID1ToAgent++
	} else {
		state.nextAgentToPID1++
	}
}

func (state *AgentSupervisorPreAdmissionState) stop(err error) (AgentSupervisorDecision, error) {
	state.phase = agentSupervisorPhaseStopped
	return AgentSupervisorDecisionStopVM, err
}

// Lost records endpoint/process loss before FD4 close as permanent VM stop.
func (state *AgentSupervisorPreAdmissionState) Lost() AgentSupervisorDecision {
	if state != nil {
		state.phase = agentSupervisorPhaseStopped
	}
	return AgentSupervisorDecisionStopVM
}

func (state *AgentSupervisorPreAdmissionState) Decision() AgentSupervisorDecision {
	if state == nil || state.phase == agentSupervisorPhaseStopped {
		return AgentSupervisorDecisionStopVM
	}
	if state.phase == agentSupervisorPhaseAccepted {
		return AgentSupervisorDecisionCloseFD4
	}
	return AgentSupervisorDecisionContinue
}

func validAgentSupervisorPID1Credential(value AgentSupervisorKernelCredential) bool {
	return value.PID == 1 && value.UID == 0 && value.GID == 0
}

func validAgentSupervisorAgentCredential(value AgentSupervisorKernelCredential) bool {
	return validAgentSupervisorPID(value.PID) && value.UID == AgentSupervisorServiceUID && value.GID == AgentSupervisorServiceGID
}

func validAgentSupervisorPID(value uint32) bool { return value > 0 && value <= 1<<31-1 }

func cloneAgentSupervisorDescriptor(value ProcessDescriptor) ProcessDescriptor {
	value.Extensions = credentialprotocol.CloneExtensionDescriptors(value.Extensions)
	return value
}

func agentSupervisorFormat(state fmt.State, name string) { _, _ = state.Write([]byte(name)) }

func (AgentSupervisorPacketType) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorPacketType")
}
func (AgentSupervisorDirection) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorDirection")
}
func (AgentSupervisorDecision) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorDecision")
}
func (AgentSupervisorHeader) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorHeader")
}
func (AgentSupervisorAgentConfigBody) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorAgentConfigBody")
}
func (AgentSupervisorClientAttestationBody) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorClientAttestationBody")
}
func (AgentSupervisorCompositionAcceptedBody) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorCompositionAcceptedBody")
}
func (AgentSupervisorCloseNotifyBody) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorCloseNotifyBody")
}
func (AgentSupervisorPacket) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorPacket")
}
func (AgentSupervisorKernelCredential) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorKernelCredential")
}
func (AgentSupervisorReceiveMetadata) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorReceiveMetadata")
}
func (AgentSupervisorPreAdmissionExpected) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorPreAdmissionExpected")
}
func (AgentSupervisorPreAdmissionState) Format(state fmt.State, _ rune) {
	agentSupervisorFormat(state, "AgentSupervisorPreAdmissionState")
}

func agentSupervisorMarshalDenied() ([]byte, error) { return nil, ErrAgentSupervisorSerialization }
func agentSupervisorUnmarshalDenied([]byte) error   { return ErrAgentSupervisorSerialization }

func (AgentSupervisorPacketType) MarshalJSON() ([]byte, error) { return agentSupervisorMarshalDenied() }
func (AgentSupervisorPacketType) MarshalText() ([]byte, error) { return agentSupervisorMarshalDenied() }
func (AgentSupervisorPacketType) MarshalBinary() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (*AgentSupervisorPacketType) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorPacketType) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorPacketType) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorDirection) MarshalJSON() ([]byte, error) { return agentSupervisorMarshalDenied() }
func (AgentSupervisorDirection) MarshalText() ([]byte, error) { return agentSupervisorMarshalDenied() }
func (AgentSupervisorDirection) MarshalBinary() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (*AgentSupervisorDirection) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorDirection) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorDirection) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorDecision) MarshalJSON() ([]byte, error)   { return agentSupervisorMarshalDenied() }
func (AgentSupervisorDecision) MarshalText() ([]byte, error)   { return agentSupervisorMarshalDenied() }
func (AgentSupervisorDecision) MarshalBinary() ([]byte, error) { return agentSupervisorMarshalDenied() }
func (*AgentSupervisorDecision) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorDecision) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorDecision) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorHeader) MarshalJSON() ([]byte, error)   { return agentSupervisorMarshalDenied() }
func (AgentSupervisorHeader) MarshalText() ([]byte, error)   { return agentSupervisorMarshalDenied() }
func (AgentSupervisorHeader) MarshalBinary() ([]byte, error) { return agentSupervisorMarshalDenied() }
func (*AgentSupervisorHeader) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorHeader) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorHeader) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorAgentConfigBody) MarshalJSON() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorAgentConfigBody) MarshalText() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorAgentConfigBody) MarshalBinary() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (*AgentSupervisorAgentConfigBody) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorAgentConfigBody) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorAgentConfigBody) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorClientAttestationBody) MarshalJSON() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorClientAttestationBody) MarshalText() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorClientAttestationBody) MarshalBinary() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (*AgentSupervisorClientAttestationBody) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorClientAttestationBody) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorClientAttestationBody) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorCompositionAcceptedBody) MarshalJSON() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorCompositionAcceptedBody) MarshalText() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorCompositionAcceptedBody) MarshalBinary() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (*AgentSupervisorCompositionAcceptedBody) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorCompositionAcceptedBody) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorCompositionAcceptedBody) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorCloseNotifyBody) MarshalJSON() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorCloseNotifyBody) MarshalText() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorCloseNotifyBody) MarshalBinary() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (*AgentSupervisorCloseNotifyBody) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorCloseNotifyBody) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorCloseNotifyBody) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorPacket) MarshalJSON() ([]byte, error)   { return agentSupervisorMarshalDenied() }
func (AgentSupervisorPacket) MarshalText() ([]byte, error)   { return agentSupervisorMarshalDenied() }
func (AgentSupervisorPacket) MarshalBinary() ([]byte, error) { return agentSupervisorMarshalDenied() }
func (*AgentSupervisorPacket) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorPacket) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorPacket) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorKernelCredential) MarshalJSON() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorKernelCredential) MarshalText() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorKernelCredential) MarshalBinary() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (*AgentSupervisorKernelCredential) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorKernelCredential) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorKernelCredential) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorReceiveMetadata) MarshalJSON() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorReceiveMetadata) MarshalText() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorReceiveMetadata) MarshalBinary() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (*AgentSupervisorReceiveMetadata) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorReceiveMetadata) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorReceiveMetadata) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorPreAdmissionExpected) MarshalJSON() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorPreAdmissionExpected) MarshalText() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorPreAdmissionExpected) MarshalBinary() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (*AgentSupervisorPreAdmissionExpected) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorPreAdmissionExpected) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorPreAdmissionExpected) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}

func (AgentSupervisorPreAdmissionState) MarshalJSON() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorPreAdmissionState) MarshalText() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (AgentSupervisorPreAdmissionState) MarshalBinary() ([]byte, error) {
	return agentSupervisorMarshalDenied()
}
func (*AgentSupervisorPreAdmissionState) UnmarshalJSON(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorPreAdmissionState) UnmarshalText(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
func (*AgentSupervisorPreAdmissionState) UnmarshalBinary(value []byte) error {
	return agentSupervisorUnmarshalDenied(value)
}
