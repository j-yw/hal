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
	// HelperAgentServiceUID is the exact unprivileged guest-agent UID.
	HelperAgentServiceUID uint32 = 998
	// HelperAgentServiceGID is the exact unprivileged guest-agent GID.
	HelperAgentServiceGID uint32 = 998

	helperBootstrapFixedBytes  = 12
	helperBootstrapDigestBytes = sha256.Size
	helperBootstrapDomain      = "hal/l8/guest-helper/bootstrap/v1"
)

var (
	ErrHelperBootstrapAgentIdentity         = errors.New("L8 helper bootstrap agent identity is invalid")
	ErrHelperBootstrapAgentIdentityMismatch = errors.New("L8 helper bootstrap agent identity does not match")
	ErrHelperBootstrapGenerationMismatch    = errors.New("L8 helper bootstrap generation does not match")
	ErrHelperBootstrapDigestZero            = errors.New("L8 helper bootstrap digest is zero")
	ErrHelperBootstrapDigestMismatch        = errors.New("L8 helper bootstrap digest does not match")
	ErrHelperBootstrapDescriptorLength      = errors.New("L8 helper bootstrap descriptor length is invalid")
	ErrHelperBootstrapDescriptorRole        = errors.New("L8 helper bootstrap descriptor role is invalid")
	ErrHelperBootstrapDescriptorMismatch    = errors.New("L8 helper bootstrap descriptor does not match")
	ErrHelperBootstrapBodyLength            = errors.New("L8 helper bootstrap body length is invalid")
	ErrHelperBootstrapBodyTrailingData      = errors.New("L8 helper bootstrap body has trailing data")
	ErrHelperBootstrapHeaderType            = errors.New("L8 helper bootstrap packet type is invalid")
	ErrHelperBootstrapHeaderSequence        = errors.New("L8 helper bootstrap packet sequence is invalid")
	ErrHelperBootstrapHeaderBodyLength      = errors.New("L8 helper bootstrap packet body length does not match")
	ErrHelperBootstrapNonceMismatch         = errors.New("L8 helper bootstrap nonce does not match")
	ErrHelperBootstrapSerialization         = errors.New("L8 helper bootstrap serialization is denied")
)

// HelperReadyBody is the exact empty PacketTypeHelperReady body.
type HelperReadyBody struct{}

// HelperBootstrapBody is the canonical safe PacketTypeBootstrap body.
type HelperBootstrapBody struct {
	AgentPID         uint32
	AgentUID         uint32
	AgentGID         uint32
	BootGeneration   string
	HelperGeneration string
}

// HelperBootstrapAckBody is the fixed-width PacketTypeBootstrapAck body.
type HelperBootstrapAckBody struct {
	BootstrapSHA256 [sha256.Size]byte
}

// HelperAgentHelloBody binds the authenticated agent to the bootstrap and its
// canonical client process descriptor.
type HelperAgentHelloBody struct {
	BootstrapSHA256  [sha256.Size]byte
	BootGeneration   string
	HelperGeneration string
	Descriptor       ProcessDescriptor
}

// HelperAgentHelloAckBody is the fixed-width PacketTypeAgentHelloAck body.
type HelperAgentHelloAckBody struct {
	BootstrapSHA256 [sha256.Size]byte
}

// HelperBootstrapExpected is caller-supplied correlation state. It contains
// no ambient process lookup, live handle, or clock-derived value.
type HelperBootstrapExpected struct {
	AgentPID         uint32
	AgentUID         uint32
	AgentGID         uint32
	BootGeneration   string
	HelperGeneration string
	BootNonce        [sha256.Size]byte
}

// EncodeHelperReadyBody returns the sole canonical empty ready body.
func EncodeHelperReadyBody(HelperReadyBody) ([]byte, error) { return []byte{}, nil }

// DecodeHelperReadyBody accepts exactly an empty body.
func DecodeHelperReadyBody(encoded []byte) (HelperReadyBody, error) {
	if len(encoded) != 0 {
		return HelperReadyBody{}, ErrHelperBootstrapBodyTrailingData
	}
	return HelperReadyBody{}, nil
}

// EncodeHelperBootstrapBody encodes exact big-endian identity fields followed
// by the two existing canonical HL8P body-token encodings.
func EncodeHelperBootstrapBody(body HelperBootstrapBody) ([]byte, error) {
	if err := validateHelperBootstrapBody(body); err != nil {
		return nil, err
	}
	boot, err := credentialprotocol.EncodeBodyToken(body.BootGeneration)
	if err != nil {
		return nil, err
	}
	helper, err := credentialprotocol.EncodeBodyToken(body.HelperGeneration)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, helperBootstrapFixedBytes, helperBootstrapFixedBytes+len(boot)+len(helper))
	binary.BigEndian.PutUint32(encoded[0:4], body.AgentPID)
	binary.BigEndian.PutUint32(encoded[4:8], body.AgentUID)
	binary.BigEndian.PutUint32(encoded[8:12], body.AgentGID)
	encoded = append(encoded, boot...)
	return append(encoded, helper...), nil
}

// DecodeHelperBootstrapBody strictly decodes one complete canonical body.
func DecodeHelperBootstrapBody(encoded []byte) (HelperBootstrapBody, error) {
	if len(encoded) < helperBootstrapFixedBytes {
		return HelperBootstrapBody{}, ErrHelperBootstrapBodyLength
	}
	body := HelperBootstrapBody{
		AgentPID: binary.BigEndian.Uint32(encoded[0:4]),
		AgentUID: binary.BigEndian.Uint32(encoded[4:8]),
		AgentGID: binary.BigEndian.Uint32(encoded[8:12]),
	}
	boot, consumed, err := credentialprotocol.DecodeBodyTokenPrefix(encoded[helperBootstrapFixedBytes:])
	if err != nil {
		return HelperBootstrapBody{}, err
	}
	offset := helperBootstrapFixedBytes + consumed
	helper, consumed, err := credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
	if err != nil {
		return HelperBootstrapBody{}, err
	}
	offset += consumed
	if offset != len(encoded) {
		return HelperBootstrapBody{}, ErrHelperBootstrapBodyTrailingData
	}
	body.BootGeneration = boot
	body.HelperGeneration = helper
	if err := validateHelperBootstrapBody(body); err != nil {
		return HelperBootstrapBody{}, err
	}
	return body, nil
}

// EncodeHelperBootstrapAckBody encodes one exact nonzero bootstrap digest.
func EncodeHelperBootstrapAckBody(body HelperBootstrapAckBody) ([]byte, error) {
	return encodeHelperBootstrapDigest(body.BootstrapSHA256)
}

// DecodeHelperBootstrapAckBody strictly decodes one exact nonzero digest.
func DecodeHelperBootstrapAckBody(encoded []byte) (HelperBootstrapAckBody, error) {
	digest, err := decodeHelperBootstrapDigest(encoded)
	if err != nil {
		return HelperBootstrapAckBody{}, err
	}
	return HelperBootstrapAckBody{BootstrapSHA256: digest}, nil
}

// EncodeHelperAgentHelloBody uses EncodeProcessDescriptor as the sole
// descriptor encoding authority and emits its exact declared uint16 length.
func EncodeHelperAgentHelloBody(body HelperAgentHelloBody) ([]byte, error) {
	if body.BootstrapSHA256 == [sha256.Size]byte{} {
		return nil, ErrHelperBootstrapDigestZero
	}
	boot, err := credentialprotocol.EncodeBodyToken(body.BootGeneration)
	if err != nil {
		return nil, err
	}
	helper, err := credentialprotocol.EncodeBodyToken(body.HelperGeneration)
	if err != nil {
		return nil, err
	}
	if body.Descriptor.Role != ProcessRoleClient {
		return nil, ErrHelperBootstrapDescriptorRole
	}
	descriptor, err := EncodeProcessDescriptor(body.Descriptor)
	if err != nil {
		return nil, err
	}
	if len(descriptor) == 0 || len(descriptor) > MaxProcessDescriptorBytes {
		return nil, ErrHelperBootstrapDescriptorLength
	}
	encoded := make([]byte, 0, sha256.Size+len(boot)+len(helper)+2+len(descriptor))
	encoded = append(encoded, body.BootstrapSHA256[:]...)
	encoded = append(encoded, boot...)
	encoded = append(encoded, helper...)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(descriptor)))
	return append(encoded, descriptor...), nil
}

// DecodeHelperAgentHelloBody rejects all noncanonical lengths and delegates
// descriptor syntax and catalog validation to DecodeProcessDescriptor.
func DecodeHelperAgentHelloBody(encoded []byte) (HelperAgentHelloBody, error) {
	if len(encoded) < sha256.Size {
		return HelperAgentHelloBody{}, ErrHelperBootstrapBodyLength
	}
	var body HelperAgentHelloBody
	copy(body.BootstrapSHA256[:], encoded[:sha256.Size])
	if body.BootstrapSHA256 == [sha256.Size]byte{} {
		return HelperAgentHelloBody{}, ErrHelperBootstrapDigestZero
	}
	offset := sha256.Size
	boot, consumed, err := credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
	if err != nil {
		return HelperAgentHelloBody{}, err
	}
	offset += consumed
	helper, consumed, err := credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
	if err != nil {
		return HelperAgentHelloBody{}, err
	}
	offset += consumed
	if len(encoded)-offset < 2 {
		return HelperAgentHelloBody{}, ErrHelperBootstrapBodyLength
	}
	descriptorLength := int(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	if descriptorLength == 0 || descriptorLength > MaxProcessDescriptorBytes {
		return HelperAgentHelloBody{}, ErrHelperBootstrapDescriptorLength
	}
	if len(encoded)-offset < descriptorLength {
		return HelperAgentHelloBody{}, ErrHelperBootstrapBodyLength
	}
	if len(encoded)-offset > descriptorLength {
		return HelperAgentHelloBody{}, ErrHelperBootstrapBodyTrailingData
	}
	descriptor, err := DecodeProcessDescriptor(encoded[offset : offset+descriptorLength])
	if err != nil {
		return HelperAgentHelloBody{}, err
	}
	if descriptor.Role != ProcessRoleClient {
		return HelperAgentHelloBody{}, ErrHelperBootstrapDescriptorRole
	}
	body.BootGeneration = boot
	body.HelperGeneration = helper
	body.Descriptor = descriptor
	return body, nil
}

// EncodeHelperAgentHelloAckBody encodes one exact nonzero bootstrap digest.
func EncodeHelperAgentHelloAckBody(body HelperAgentHelloAckBody) ([]byte, error) {
	return encodeHelperBootstrapDigest(body.BootstrapSHA256)
}

// DecodeHelperAgentHelloAckBody strictly decodes one exact nonzero digest.
func DecodeHelperAgentHelloAckBody(encoded []byte) (HelperAgentHelloAckBody, error) {
	digest, err := decodeHelperBootstrapDigest(encoded)
	if err != nil {
		return HelperAgentHelloAckBody{}, err
	}
	return HelperAgentHelloAckBody{BootstrapSHA256: digest}, nil
}

// ComputeHelperBootstrapSHA256 is the sole bootstrap digest authority. It
// validates exact bootstrap header/body/caller correlation before hashing.
func ComputeHelperBootstrapSHA256(header credentialprotocol.HelperPacketHeader, body HelperBootstrapBody, expected HelperBootstrapExpected) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	bodyEncoded, err := validateAndEncodeHelperBootstrap(header, body, expected)
	if err != nil {
		return digest, err
	}
	headerEncoded, err := credentialprotocol.EncodeHelperPacketHeader(header)
	if err != nil {
		return digest, err
	}
	hash := sha256.New()
	_, _ = hash.Write(helperOpaque16Bytes(helperBootstrapDomain))
	_, _ = hash.Write(headerEncoded[:])
	_, _ = hash.Write(bodyEncoded)
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

// ValidateHelperReadyCorrelation requires type 0x01, sequence zero, an exact
// empty body declaration, and the header's zero boot correlation semantics.
func ValidateHelperReadyCorrelation(header credentialprotocol.HelperPacketHeader) error {
	return validateHelperHandshakeHeader(header, credentialprotocol.PacketTypeHelperReady, 0, 0, [sha256.Size]byte{})
}

// ValidateHelperBootstrapCorrelation binds the complete bootstrap to explicit
// caller-supplied agent identity, generations, and boot nonce.
func ValidateHelperBootstrapCorrelation(header credentialprotocol.HelperPacketHeader, body HelperBootstrapBody, expected HelperBootstrapExpected) error {
	_, err := validateAndEncodeHelperBootstrap(header, body, expected)
	return err
}

// ValidateHelperBootstrapAckCorrelation binds the acknowledgement header and
// body to the caller's exact boot nonce and computed bootstrap digest.
func ValidateHelperBootstrapAckCorrelation(header credentialprotocol.HelperPacketHeader, body HelperBootstrapAckBody, expectedNonce [sha256.Size]byte, expectedDigest [sha256.Size]byte) error {
	encoded, err := EncodeHelperBootstrapAckBody(body)
	if err != nil {
		return err
	}
	if err := validateExpectedDigest(expectedDigest); err != nil {
		return err
	}
	if err := validateHelperHandshakeHeader(header, credentialprotocol.PacketTypeBootstrapAck, 1, uint32(len(encoded)), expectedNonce); err != nil {
		return err
	}
	if body.BootstrapSHA256 != expectedDigest {
		return ErrHelperBootstrapDigestMismatch
	}
	return nil
}

// ValidateHelperAgentHelloCorrelation binds hello to exact bootstrap,
// generation, nonce, and canonical expected client descriptor values.
func ValidateHelperAgentHelloCorrelation(header credentialprotocol.HelperPacketHeader, body HelperAgentHelloBody, expectedNonce [sha256.Size]byte, expectedDigest [sha256.Size]byte, expectedBootGeneration, expectedHelperGeneration string, expectedDescriptor ProcessDescriptor) error {
	if err := validateExpectedDigest(expectedDigest); err != nil {
		return err
	}
	if err := credentialprotocol.ValidateBodyToken(expectedBootGeneration); err != nil {
		return err
	}
	if err := credentialprotocol.ValidateBodyToken(expectedHelperGeneration); err != nil {
		return err
	}
	if body.BootstrapSHA256 != expectedDigest {
		return ErrHelperBootstrapDigestMismatch
	}
	if body.BootGeneration != expectedBootGeneration || body.HelperGeneration != expectedHelperGeneration {
		return ErrHelperBootstrapGenerationMismatch
	}
	actualDescriptor, err := canonicalClientDescriptor(body.Descriptor)
	if err != nil {
		return err
	}
	expectedDescriptorEncoding, err := canonicalClientDescriptor(expectedDescriptor)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualDescriptor, expectedDescriptorEncoding) {
		return ErrHelperBootstrapDescriptorMismatch
	}
	encoded, err := EncodeHelperAgentHelloBody(body)
	if err != nil {
		return err
	}
	return validateHelperHandshakeHeader(header, credentialprotocol.PacketTypeAgentHello, 1, uint32(len(encoded)), expectedNonce)
}

// ValidateHelperAgentHelloAckCorrelation binds the final handshake response to
// sequence two, the exact nonce, and the exact bootstrap digest.
func ValidateHelperAgentHelloAckCorrelation(header credentialprotocol.HelperPacketHeader, body HelperAgentHelloAckBody, expectedNonce [sha256.Size]byte, expectedDigest [sha256.Size]byte) error {
	encoded, err := EncodeHelperAgentHelloAckBody(body)
	if err != nil {
		return err
	}
	if err := validateExpectedDigest(expectedDigest); err != nil {
		return err
	}
	if err := validateHelperHandshakeHeader(header, credentialprotocol.PacketTypeAgentHelloAck, 2, uint32(len(encoded)), expectedNonce); err != nil {
		return err
	}
	if body.BootstrapSHA256 != expectedDigest {
		return ErrHelperBootstrapDigestMismatch
	}
	return nil
}

func validateAndEncodeHelperBootstrap(header credentialprotocol.HelperPacketHeader, body HelperBootstrapBody, expected HelperBootstrapExpected) ([]byte, error) {
	if err := validateHelperBootstrapExpected(expected); err != nil {
		return nil, err
	}
	if body.AgentPID != expected.AgentPID || body.AgentUID != expected.AgentUID || body.AgentGID != expected.AgentGID {
		return nil, ErrHelperBootstrapAgentIdentityMismatch
	}
	if body.BootGeneration != expected.BootGeneration || body.HelperGeneration != expected.HelperGeneration {
		return nil, ErrHelperBootstrapGenerationMismatch
	}
	encoded, err := EncodeHelperBootstrapBody(body)
	if err != nil {
		return nil, err
	}
	if err := validateHelperHandshakeHeader(header, credentialprotocol.PacketTypeBootstrap, 0, uint32(len(encoded)), expected.BootNonce); err != nil {
		return nil, err
	}
	return encoded, nil
}

func validateHelperBootstrapBody(body HelperBootstrapBody) error {
	if !validHelperBootstrapPID(body.AgentPID) || body.AgentUID != HelperAgentServiceUID || body.AgentGID != HelperAgentServiceGID {
		return ErrHelperBootstrapAgentIdentity
	}
	if err := credentialprotocol.ValidateBodyToken(body.BootGeneration); err != nil {
		return err
	}
	return credentialprotocol.ValidateBodyToken(body.HelperGeneration)
}

func validateHelperBootstrapExpected(expected HelperBootstrapExpected) error {
	if !validHelperBootstrapPID(expected.AgentPID) || expected.AgentUID != HelperAgentServiceUID || expected.AgentGID != HelperAgentServiceGID {
		return ErrHelperBootstrapAgentIdentity
	}
	if err := credentialprotocol.ValidateBodyToken(expected.BootGeneration); err != nil {
		return err
	}
	if err := credentialprotocol.ValidateBodyToken(expected.HelperGeneration); err != nil {
		return err
	}
	if expected.BootNonce == [sha256.Size]byte{} {
		return credentialprotocol.ErrHelperPacketNonceSemantics
	}
	return nil
}

func validHelperBootstrapPID(value uint32) bool { return value >= 2 && value <= 1<<31-1 }

func validateExpectedDigest(expected [sha256.Size]byte) error {
	if expected == [sha256.Size]byte{} {
		return ErrHelperBootstrapDigestZero
	}
	return nil
}

func validateHelperHandshakeHeader(header credentialprotocol.HelperPacketHeader, expectedType credentialprotocol.PacketType, expectedSequence uint64, expectedBodyLength uint32, expectedNonce [sha256.Size]byte) error {
	if err := credentialprotocol.ValidatePacketType(header.Type); err != nil {
		return err
	}
	if header.Type != expectedType {
		return ErrHelperBootstrapHeaderType
	}
	if err := credentialprotocol.ValidateHelperPacketHeaderSemantics(header); err != nil {
		return err
	}
	if header.Sequence != expectedSequence {
		return ErrHelperBootstrapHeaderSequence
	}
	if header.BodyLength != expectedBodyLength {
		return ErrHelperBootstrapHeaderBodyLength
	}
	if header.BootNonce != expectedNonce {
		return ErrHelperBootstrapNonceMismatch
	}
	return nil
}

func encodeHelperBootstrapDigest(digest [sha256.Size]byte) ([]byte, error) {
	if digest == [sha256.Size]byte{} {
		return nil, ErrHelperBootstrapDigestZero
	}
	return append([]byte(nil), digest[:]...), nil
}

func decodeHelperBootstrapDigest(encoded []byte) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if len(encoded) < helperBootstrapDigestBytes {
		return digest, ErrHelperBootstrapBodyLength
	}
	if len(encoded) > helperBootstrapDigestBytes {
		return digest, ErrHelperBootstrapBodyTrailingData
	}
	copy(digest[:], encoded)
	if digest == [sha256.Size]byte{} {
		return [sha256.Size]byte{}, ErrHelperBootstrapDigestZero
	}
	return digest, nil
}

func canonicalClientDescriptor(descriptor ProcessDescriptor) ([]byte, error) {
	if descriptor.Role != ProcessRoleClient {
		return nil, ErrHelperBootstrapDescriptorRole
	}
	return EncodeProcessDescriptor(descriptor)
}

func helperOpaque16Bytes(value string) []byte {
	encoded := make([]byte, 2, len(value)+2)
	binary.BigEndian.PutUint16(encoded, uint16(len(value)))
	return append(encoded, value...)
}

func helperBootstrapFormat(state fmt.State, name string) { _, _ = state.Write([]byte(name)) }

func (HelperReadyBody) Format(state fmt.State, _ rune) {
	helperBootstrapFormat(state, "HelperReadyBody")
}
func (HelperBootstrapBody) Format(state fmt.State, _ rune) {
	helperBootstrapFormat(state, "HelperBootstrapBody")
}
func (HelperBootstrapAckBody) Format(state fmt.State, _ rune) {
	helperBootstrapFormat(state, "HelperBootstrapAckBody")
}
func (HelperAgentHelloBody) Format(state fmt.State, _ rune) {
	helperBootstrapFormat(state, "HelperAgentHelloBody")
}
func (HelperAgentHelloAckBody) Format(state fmt.State, _ rune) {
	helperBootstrapFormat(state, "HelperAgentHelloAckBody")
}
func (HelperBootstrapExpected) Format(state fmt.State, _ rune) {
	helperBootstrapFormat(state, "HelperBootstrapExpected")
}

func (HelperReadyBody) MarshalJSON() ([]byte, error)     { return nil, ErrHelperBootstrapSerialization }
func (HelperReadyBody) MarshalText() ([]byte, error)     { return nil, ErrHelperBootstrapSerialization }
func (HelperReadyBody) MarshalBinary() ([]byte, error)   { return nil, ErrHelperBootstrapSerialization }
func (*HelperReadyBody) UnmarshalJSON([]byte) error      { return ErrHelperBootstrapSerialization }
func (*HelperReadyBody) UnmarshalText([]byte) error      { return ErrHelperBootstrapSerialization }
func (*HelperReadyBody) UnmarshalBinary([]byte) error    { return ErrHelperBootstrapSerialization }
func (HelperBootstrapBody) MarshalJSON() ([]byte, error) { return nil, ErrHelperBootstrapSerialization }
func (HelperBootstrapBody) MarshalText() ([]byte, error) { return nil, ErrHelperBootstrapSerialization }
func (HelperBootstrapBody) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (*HelperBootstrapBody) UnmarshalJSON([]byte) error   { return ErrHelperBootstrapSerialization }
func (*HelperBootstrapBody) UnmarshalText([]byte) error   { return ErrHelperBootstrapSerialization }
func (*HelperBootstrapBody) UnmarshalBinary([]byte) error { return ErrHelperBootstrapSerialization }
func (HelperBootstrapAckBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (HelperBootstrapAckBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (HelperBootstrapAckBody) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (*HelperBootstrapAckBody) UnmarshalJSON([]byte) error   { return ErrHelperBootstrapSerialization }
func (*HelperBootstrapAckBody) UnmarshalText([]byte) error   { return ErrHelperBootstrapSerialization }
func (*HelperBootstrapAckBody) UnmarshalBinary([]byte) error { return ErrHelperBootstrapSerialization }
func (HelperAgentHelloBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (HelperAgentHelloBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (HelperAgentHelloBody) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (*HelperAgentHelloBody) UnmarshalJSON([]byte) error   { return ErrHelperBootstrapSerialization }
func (*HelperAgentHelloBody) UnmarshalText([]byte) error   { return ErrHelperBootstrapSerialization }
func (*HelperAgentHelloBody) UnmarshalBinary([]byte) error { return ErrHelperBootstrapSerialization }
func (HelperAgentHelloAckBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (HelperAgentHelloAckBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (HelperAgentHelloAckBody) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (*HelperAgentHelloAckBody) UnmarshalJSON([]byte) error   { return ErrHelperBootstrapSerialization }
func (*HelperAgentHelloAckBody) UnmarshalText([]byte) error   { return ErrHelperBootstrapSerialization }
func (*HelperAgentHelloAckBody) UnmarshalBinary([]byte) error { return ErrHelperBootstrapSerialization }
func (HelperBootstrapExpected) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (HelperBootstrapExpected) MarshalText() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (HelperBootstrapExpected) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperBootstrapSerialization
}
func (*HelperBootstrapExpected) UnmarshalJSON([]byte) error   { return ErrHelperBootstrapSerialization }
func (*HelperBootstrapExpected) UnmarshalText([]byte) error   { return ErrHelperBootstrapSerialization }
func (*HelperBootstrapExpected) UnmarshalBinary([]byte) error { return ErrHelperBootstrapSerialization }
