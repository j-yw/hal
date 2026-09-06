package credentialprotocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestHelperPacketEnvelopeExactVectorAndRoundTrip(t *testing.T) {
	t.Parallel()

	requestID := filled16(0x11)
	digest := filled32(0x22)
	nonce := filled32(0x33)
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	header := HelperPacketHeader{
		Type:                          PacketTypePrepareBegin,
		Sequence:                      0x0102030405060708,
		RequestID:                     requestID,
		BodyLength:                    uint32(len(body)),
		GuestCredentialIdentityDigest: digest,
		BootNonce:                     nonce,
	}

	prefix, err := EncodeHelperPacketHeader(header)
	if err != nil {
		t.Fatalf("EncodeHelperPacketHeader() error = %v", err)
	}
	wire := append(cloneBytes(prefix[:]), body...)
	if len(wire) != HelperPacketHeaderSize+len(body) {
		t.Fatalf("wire length = %d, want %d", len(wire), HelperPacketHeaderSize+len(body))
	}
	wantPrefix := make([]byte, HelperPacketHeaderSize)
	copy(wantPrefix[0:4], "HL8P")
	wantPrefix[4] = 1
	wantPrefix[5] = 0x10
	binary.BigEndian.PutUint64(wantPrefix[8:16], 0x0102030405060708)
	copy(wantPrefix[16:32], requestID[:])
	binary.BigEndian.PutUint32(wantPrefix[32:36], 4)
	copy(wantPrefix[36:68], digest[:])
	copy(wantPrefix[68:100], nonce[:])
	if !bytes.Equal(wire[:HelperPacketHeaderSize], wantPrefix) {
		t.Fatalf("encoded header = %x, want %x", wire[:HelperPacketHeaderSize], wantPrefix)
	}
	if !bytes.Equal(wire[HelperPacketHeaderSize:], body) {
		t.Fatalf("encoded body = %x, want %x", wire[HelperPacketHeaderSize:], body)
	}

	decodedHeader, err := DecodeHelperPacketHeader(wire[:HelperPacketHeaderSize])
	if err != nil {
		t.Fatalf("DecodeHelperPacketHeader() error = %v", err)
	}
	if decodedHeader != header {
		t.Fatalf("decoded header = %#v, want %#v", decodedHeader, header)
	}
	validatedHeader, err := ValidateHelperPacketDatagram(wire)
	if err != nil {
		t.Fatalf("ValidateHelperPacketDatagram() error = %v", err)
	}
	if validatedHeader != header {
		t.Fatalf("validated header = %#v, want %#v", validatedHeader, header)
	}

	wire[16] = 0
	if validatedHeader.RequestID != requestID {
		t.Fatal("validated header aliases input datagram")
	}
}

func TestHelperPacketEnvelopeConstantsAndBounds(t *testing.T) {
	t.Parallel()

	if HelperPacketMagic != "HL8P" || HelperPacketVersion != 1 || HelperPacketFlags != 0 {
		t.Fatalf("helper envelope constants = %q/%d/%d", HelperPacketMagic, HelperPacketVersion, HelperPacketFlags)
	}
	if HelperPacketHeaderSize != 100 || MaxHelperPacketBodyBytes != 72*1024 || MaxHelperPacketDatagramBytes != 73828 {
		t.Fatalf("helper bounds = header %d body %d datagram %d", HelperPacketHeaderSize, MaxHelperPacketBodyBytes, MaxHelperPacketDatagramBytes)
	}

	maxBody := make([]byte, MaxHelperPacketBodyBytes)
	header := semanticHeader(PacketTypePrepareFile)
	header.BodyLength = uint32(len(maxBody))
	prefix, err := EncodeHelperPacketHeader(header)
	if err != nil {
		t.Fatalf("EncodeHelperPacketHeader(max) error = %v", err)
	}
	wire := append(cloneBytes(prefix[:]), maxBody...)
	if len(wire) != MaxHelperPacketDatagramBytes {
		t.Fatalf("maximum datagram length = %d, want %d", len(wire), MaxHelperPacketDatagramBytes)
	}
	if _, err := ValidateHelperPacketDatagram(wire); err != nil {
		t.Fatalf("ValidateHelperPacketDatagram(max) error = %v", err)
	}

	header.BodyLength = MaxHelperPacketBodyBytes + 1
	if _, err := EncodeHelperPacketHeader(header); !errors.Is(err, ErrHelperPacketBodyLength) {
		t.Fatalf("EncodeHelperPacketHeader(plus one) error = %v, want ErrHelperPacketBodyLength", err)
	}
}

func TestHelperPacketStructuralDecodeRejectsEveryMalformedDimension(t *testing.T) {
	t.Parallel()

	header := semanticHeader(PacketTypeExec)
	header.BodyLength = 3
	valid := helperDatagramForTest(t, header, []byte{1, 2, 3})

	tests := []struct {
		name string
		wire []byte
		want error
	}{
		{name: "empty", wire: nil, want: ErrHelperPacketHeaderLength},
		{name: "truncated header", wire: cloneBytes(valid[:HelperPacketHeaderSize-1]), want: ErrHelperPacketHeaderLength},
		{name: "wrong magic", wire: mutateByte(valid, 0, 'X'), want: ErrHelperPacketMagic},
		{name: "wrong version", wire: mutateByte(valid, 4, 2), want: ErrHelperPacketVersion},
		{name: "unknown type zero", wire: mutateByte(valid, 5, 0), want: ErrUnknownPacketType},
		{name: "unknown type gap", wire: mutateByte(valid, 5, 0x06), want: ErrUnknownPacketType},
		{name: "flags high", wire: mutateByte(valid, 6, 1), want: ErrHelperPacketFlags},
		{name: "flags low", wire: mutateByte(valid, 7, 1), want: ErrHelperPacketFlags},
		{name: "declared too large", wire: mutateUint32(valid, 32, MaxHelperPacketBodyBytes+1), want: ErrHelperPacketBodyLength},
		{name: "body truncated", wire: cloneBytes(valid[:len(valid)-1]), want: ErrHelperPacketDatagramLength},
		{name: "body trailing", wire: append(cloneBytes(valid), 0), want: ErrHelperPacketDatagramLength},
		{name: "declared smaller", wire: mutateUint32(valid, 32, 2), want: ErrHelperPacketDatagramLength},
		{name: "declared larger", wire: mutateUint32(valid, 32, 4), want: ErrHelperPacketDatagramLength},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ValidateHelperPacketDatagram(test.wire); !errors.Is(err, test.want) {
				t.Fatalf("ValidateHelperPacketDatagram() error = %v, want %v", err, test.want)
			}
		})
	}

	for _, length := range []int{0, HelperPacketHeaderSize - 1, HelperPacketHeaderSize + 1} {
		if _, err := DecodeHelperPacketHeader(make([]byte, length)); !errors.Is(err, ErrHelperPacketHeaderLength) {
			t.Fatalf("DecodeHelperPacketHeader(length %d) error = %v, want ErrHelperPacketHeaderLength", length, err)
		}
	}
}

func TestHelperPacketHeaderEncodeRejectsUnknownOrOversizedHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header HelperPacketHeader
		want   error
	}{
		{name: "unknown type", header: HelperPacketHeader{Type: 0x06}, want: ErrUnknownPacketType},
		{name: "oversized body", header: HelperPacketHeader{Type: PacketTypeHelperReady, BodyLength: MaxHelperPacketBodyBytes + 1}, want: ErrHelperPacketBodyLength},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := EncodeHelperPacketHeader(test.header); !errors.Is(err, test.want) {
				t.Fatalf("EncodeHelperPacketHeader() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestValidateHelperPacketHeaderSemantics(t *testing.T) {
	t.Parallel()

	bootZeroNonce := HelperPacketHeader{Type: PacketTypeHelperReady}
	bootNonce := filled32(0x44)
	boot := []PacketType{PacketTypeBootstrap, PacketTypeBootstrapAck, PacketTypeAgentHello, PacketTypeAgentHelloAck}
	job := []PacketType{
		PacketTypePrepareBegin, PacketTypePrepareFile, PacketTypePrepareCommit,
		PacketTypeRenew, PacketTypeRevoke, PacketTypeExec, PacketTypeSSHAcceptedFD,
		PacketTypeExecPrivate, PacketTypeExecStream, PacketTypeExecCredit,
		PacketTypeResponse, PacketTypeEvent,
	}
	if err := ValidateHelperPacketHeaderSemantics(bootZeroNonce); err != nil {
		t.Fatalf("helper_ready semantics error = %v", err)
	}
	for _, packetType := range boot {
		header := HelperPacketHeader{Type: packetType, BootNonce: bootNonce}
		if err := ValidateHelperPacketHeaderSemantics(header); err != nil {
			t.Fatalf("%s semantics error = %v", packetType, err)
		}
	}
	for _, packetType := range job {
		header := semanticHeader(packetType)
		if err := ValidateHelperPacketHeaderSemantics(header); err != nil {
			t.Fatalf("%s semantics error = %v", packetType, err)
		}
	}

	closeHeader := HelperPacketHeader{Type: PacketTypeCloseNotify, BootNonce: bootNonce}
	if err := ValidateHelperPacketHeaderSemantics(closeHeader); err != nil {
		t.Fatalf("close with zero correlation semantics error = %v", err)
	}
	closeHeader.RequestID = filled16(0x55)
	closeHeader.GuestCredentialIdentityDigest = filled32(0x66)
	if err := ValidateHelperPacketHeaderSemantics(closeHeader); err != nil {
		t.Fatalf("close with nonzero correlation semantics error = %v", err)
	}

	tests := []struct {
		name   string
		header HelperPacketHeader
		want   error
	}{
		{name: "unknown type", header: HelperPacketHeader{Type: 0x06}, want: ErrUnknownPacketType},
		{name: "oversized body", header: HelperPacketHeader{Type: PacketTypeHelperReady, BodyLength: MaxHelperPacketBodyBytes + 1}, want: ErrHelperPacketBodyLength},
		{name: "ready request", header: withRequestID(bootZeroNonce), want: ErrHelperPacketRequestIDSemantics},
		{name: "ready digest", header: withDigest(bootZeroNonce), want: ErrHelperPacketIdentitySemantics},
		{name: "ready nonce", header: withNonce(bootZeroNonce), want: ErrHelperPacketNonceSemantics},
		{name: "bootstrap missing nonce", header: HelperPacketHeader{Type: PacketTypeBootstrap}, want: ErrHelperPacketNonceSemantics},
		{name: "bootstrap request", header: withRequestID(HelperPacketHeader{Type: PacketTypeBootstrap, BootNonce: bootNonce}), want: ErrHelperPacketRequestIDSemantics},
		{name: "bootstrap digest", header: withDigest(HelperPacketHeader{Type: PacketTypeBootstrap, BootNonce: bootNonce}), want: ErrHelperPacketIdentitySemantics},
		{name: "job missing request", header: HelperPacketHeader{Type: PacketTypeExec, GuestCredentialIdentityDigest: filled32(2), BootNonce: bootNonce}, want: ErrHelperPacketRequestIDSemantics},
		{name: "job missing digest", header: HelperPacketHeader{Type: PacketTypeExec, RequestID: filled16(1), BootNonce: bootNonce}, want: ErrHelperPacketIdentitySemantics},
		{name: "job missing nonce", header: HelperPacketHeader{Type: PacketTypeExec, RequestID: filled16(1), GuestCredentialIdentityDigest: filled32(2)}, want: ErrHelperPacketNonceSemantics},
		{name: "close missing nonce", header: HelperPacketHeader{Type: PacketTypeCloseNotify}, want: ErrHelperPacketNonceSemantics},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateHelperPacketHeaderSemantics(test.header); !errors.Is(err, test.want) {
				t.Fatalf("ValidateHelperPacketHeaderSemantics() error = %v, want %v", err, test.want)
			}
		})
	}
}

func semanticHeader(packetType PacketType) HelperPacketHeader {
	return HelperPacketHeader{
		Type:                          packetType,
		RequestID:                     filled16(1),
		GuestCredentialIdentityDigest: filled32(2),
		BootNonce:                     filled32(3),
	}
}

func filled16(value byte) [16]byte {
	var result [16]byte
	for index := range result {
		result[index] = value
	}
	return result
}

func filled32(value byte) [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = value
	}
	return result
}

func cloneBytes(value []byte) []byte {
	result := make([]byte, len(value))
	copy(result, value)
	return result
}

func mutateByte(value []byte, offset int, replacement byte) []byte {
	result := cloneBytes(value)
	result[offset] = replacement
	return result
}

func mutateUint32(value []byte, offset int, replacement int) []byte {
	result := cloneBytes(value)
	binary.BigEndian.PutUint32(result[offset:offset+4], uint32(replacement))
	return result
}

func withRequestID(header HelperPacketHeader) HelperPacketHeader {
	header.RequestID = filled16(1)
	return header
}

func withDigest(header HelperPacketHeader) HelperPacketHeader {
	header.GuestCredentialIdentityDigest = filled32(1)
	return header
}

func withNonce(header HelperPacketHeader) HelperPacketHeader {
	header.BootNonce = filled32(1)
	return header
}

func helperDatagramForTest(t *testing.T, header HelperPacketHeader, body []byte) []byte {
	t.Helper()
	if uint32(len(body)) != header.BodyLength {
		t.Fatalf("test body length = %d, header = %d", len(body), header.BodyLength)
	}
	prefix, err := EncodeHelperPacketHeader(header)
	if err != nil {
		t.Fatalf("EncodeHelperPacketHeader() error = %v", err)
	}
	return append(cloneBytes(prefix[:]), body...)
}
