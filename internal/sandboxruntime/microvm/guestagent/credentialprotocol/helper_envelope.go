package credentialprotocol

import (
	"encoding/binary"
	"errors"
)

const (
	// HelperPacketMagic is the fixed HL8P packet prefix.
	HelperPacketMagic = "HL8P"
	// HelperPacketVersion is the only supported HL8P wire version.
	HelperPacketVersion uint8 = 1
	// HelperPacketFlags is the sole canonical HL8P flags value.
	HelperPacketFlags uint16 = 0

	// HelperPacketHeaderSize is the exact fixed HL8P header size.
	HelperPacketHeaderSize = 100
	// MaxHelperPacketBodyBytes is the 72-KiB HL8P body ceiling.
	MaxHelperPacketBodyBytes = 72 * 1024
	// MaxHelperPacketDatagramBytes is the complete header-plus-body ceiling.
	MaxHelperPacketDatagramBytes = HelperPacketHeaderSize + MaxHelperPacketBodyBytes
)

var (
	ErrHelperPacketHeaderLength       = errors.New("credential protocol helper packet header length is invalid")
	ErrHelperPacketMagic              = errors.New("credential protocol helper packet magic is invalid")
	ErrHelperPacketVersion            = errors.New("credential protocol helper packet version is unsupported")
	ErrHelperPacketFlags              = errors.New("credential protocol helper packet flags are invalid")
	ErrHelperPacketBodyLength         = errors.New("credential protocol helper packet body length is invalid")
	ErrHelperPacketDatagramLength     = errors.New("credential protocol helper packet datagram length is invalid")
	ErrHelperPacketRequestIDSemantics = errors.New("credential protocol helper packet request ID semantics are invalid")
	ErrHelperPacketIdentitySemantics  = errors.New("credential protocol helper packet identity semantics are invalid")
	ErrHelperPacketNonceSemantics     = errors.New("credential protocol helper packet nonce semantics are invalid")
)

// HelperPacketHeader is the exact data-only HL8P fixed header. BodyLength is
// payload bytes only and never includes the fixed header.
type HelperPacketHeader struct {
	Type                          PacketType
	Sequence                      uint64
	RequestID                     [16]byte
	BodyLength                    uint32
	GuestCredentialIdentityDigest [32]byte
	BootNonce                     [32]byte
}

// EncodeHelperPacketHeader returns the canonical fixed-size header encoding.
// It validates catalog and structural fields but intentionally does not apply
// phase semantics or inspect a packet body.
func EncodeHelperPacketHeader(header HelperPacketHeader) ([HelperPacketHeaderSize]byte, error) {
	var encoded [HelperPacketHeaderSize]byte
	if err := validateHelperPacketHeaderStructure(header); err != nil {
		return encoded, err
	}
	copy(encoded[0:4], HelperPacketMagic)
	encoded[4] = HelperPacketVersion
	encoded[5] = byte(header.Type)
	binary.BigEndian.PutUint16(encoded[6:8], HelperPacketFlags)
	binary.BigEndian.PutUint64(encoded[8:16], header.Sequence)
	copy(encoded[16:32], header.RequestID[:])
	binary.BigEndian.PutUint32(encoded[32:36], header.BodyLength)
	copy(encoded[36:68], header.GuestCredentialIdentityDigest[:])
	copy(encoded[68:100], header.BootNonce[:])
	return encoded, nil
}

// DecodeHelperPacketHeader strictly decodes one exact 100-byte header. A
// caller validating a full datagram must use ValidateHelperPacketDatagram so
// the declared remaining length is also checked.
func DecodeHelperPacketHeader(encoded []byte) (HelperPacketHeader, error) {
	var header HelperPacketHeader
	if len(encoded) != HelperPacketHeaderSize {
		return header, ErrHelperPacketHeaderLength
	}
	if string(encoded[0:4]) != HelperPacketMagic {
		return header, ErrHelperPacketMagic
	}
	if encoded[4] != HelperPacketVersion {
		return header, ErrHelperPacketVersion
	}
	header.Type = PacketType(encoded[5])
	if err := ValidatePacketType(header.Type); err != nil {
		return HelperPacketHeader{}, err
	}
	if binary.BigEndian.Uint16(encoded[6:8]) != HelperPacketFlags {
		return HelperPacketHeader{}, ErrHelperPacketFlags
	}
	header.Sequence = binary.BigEndian.Uint64(encoded[8:16])
	copy(header.RequestID[:], encoded[16:32])
	header.BodyLength = binary.BigEndian.Uint32(encoded[32:36])
	copy(header.GuestCredentialIdentityDigest[:], encoded[36:68])
	copy(header.BootNonce[:], encoded[68:100])
	if err := validateHelperPacketHeaderStructure(header); err != nil {
		return HelperPacketHeader{}, err
	}
	return header, nil
}

// ValidateHelperPacketDatagram validates the fixed prefix and exact declared
// remaining length without allocating, copying, returning, or otherwise
// owning body bytes. Later typed body codecs must use their approved bounded
// value or credential-memory sink directly.
func ValidateHelperPacketDatagram(encoded []byte) (HelperPacketHeader, error) {
	if len(encoded) < HelperPacketHeaderSize {
		return HelperPacketHeader{}, ErrHelperPacketHeaderLength
	}
	header, err := DecodeHelperPacketHeader(encoded[:HelperPacketHeaderSize])
	if err != nil {
		return HelperPacketHeader{}, err
	}
	expectedLength := HelperPacketHeaderSize + int(header.BodyLength)
	if len(encoded) != expectedLength {
		return HelperPacketHeader{}, ErrHelperPacketDatagramLength
	}
	return header, nil
}

func validateHelperPacketHeaderStructure(header HelperPacketHeader) error {
	if err := ValidatePacketType(header.Type); err != nil {
		return err
	}
	if header.BodyLength > MaxHelperPacketBodyBytes {
		return ErrHelperPacketBodyLength
	}
	return nil
}

// ValidateHelperPacketHeaderSemantics validates only the header facts frozen
// independently of body codecs and state ownership. Positive revisions and
// exact correlation values belong to later body/state validation.
//
// Close request-ID and identity correlation is deliberately unconstrained at
// this common seam because the frozen architecture does not specify whether a
// close is boot- or job-correlated. The close body/state codec must resolve it;
// the common header still requires the echoed helper-local nonce.
func ValidateHelperPacketHeaderSemantics(header HelperPacketHeader) error {
	if err := validateHelperPacketHeaderStructure(header); err != nil {
		return err
	}
	switch header.Type {
	case PacketTypeHelperReady:
		if !isZero16(header.RequestID) {
			return ErrHelperPacketRequestIDSemantics
		}
		if !isZero32(header.GuestCredentialIdentityDigest) {
			return ErrHelperPacketIdentitySemantics
		}
		if !isZero32(header.BootNonce) {
			return ErrHelperPacketNonceSemantics
		}
		return nil
	case PacketTypeBootstrap, PacketTypeBootstrapAck, PacketTypeAgentHello, PacketTypeAgentHelloAck:
		if !isZero16(header.RequestID) {
			return ErrHelperPacketRequestIDSemantics
		}
		if !isZero32(header.GuestCredentialIdentityDigest) {
			return ErrHelperPacketIdentitySemantics
		}
		if isZero32(header.BootNonce) {
			return ErrHelperPacketNonceSemantics
		}
		return nil
	case PacketTypeCloseNotify:
		if isZero32(header.BootNonce) {
			return ErrHelperPacketNonceSemantics
		}
		return nil
	default:
		if isZero16(header.RequestID) {
			return ErrHelperPacketRequestIDSemantics
		}
		if isZero32(header.GuestCredentialIdentityDigest) {
			return ErrHelperPacketIdentitySemantics
		}
		if isZero32(header.BootNonce) {
			return ErrHelperPacketNonceSemantics
		}
		return nil
	}
}

func isZero16(value [16]byte) bool {
	return value == [16]byte{}
}

func isZero32(value [32]byte) bool {
	return value == [32]byte{}
}
