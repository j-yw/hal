package session

import (
	"bytes"
	"encoding/binary"
)

var (
	handshakeMagic = [4]byte{'H', 'L', '8', 'H'}
	recordMagic    = [4]byte{'H', 'L', '8', 'F'}
)

const (
	handshakeTypeGuestHello     = byte(1)
	handshakeTypeControllerAuth = byte(2)
)

func MarshalGuestHello(hello GuestHello) ([]byte, error) {
	inner, err := marshalGuestHelloInner(hello)
	if err != nil {
		return nil, err
	}
	return marshalHandshakeOuter(inner)
}

func ParseGuestHello(wire []byte) (GuestHello, error) {
	inner, err := parseHandshakeOuter(wire, handshakeTypeGuestHello)
	if err != nil {
		return GuestHello{}, err
	}
	return parseGuestHelloInner(inner)
}

func MarshalControllerAuth(auth ControllerAuth) ([]byte, error) {
	unsigned, err := marshalControllerUnsignedInner(auth)
	if err != nil {
		return nil, err
	}
	inner := make([]byte, 0, len(unsigned)+len(auth.Signature))
	inner = append(inner, unsigned...)
	inner = append(inner, auth.Signature[:]...)
	return marshalHandshakeOuter(inner)
}

func ParseControllerAuth(wire []byte) (ControllerAuth, error) {
	inner, err := parseHandshakeOuter(wire, handshakeTypeControllerAuth)
	if err != nil {
		return ControllerAuth{}, err
	}
	const unsignedBytes = 8 + 2 + 1 + 1 + 32
	if len(inner) != unsignedBytes+64 {
		return ControllerAuth{}, ErrMalformedHandshake
	}
	auth, err := parseControllerUnsignedInner(inner[:unsignedBytes])
	if err != nil {
		return ControllerAuth{}, err
	}
	copy(auth.Signature[:], inner[unsignedBytes:])
	return auth, nil
}

func marshalGuestHelloInner(hello GuestHello) ([]byte, error) {
	if hello.Suite != HandshakeSuite1 || validateIdentity(hello.Identity) != nil {
		return nil, ErrMalformedHandshake
	}
	var inner bytes.Buffer
	inner.Grow(256)
	inner.Write(handshakeMagic[:])
	inner.WriteByte(WireVersion)
	inner.WriteByte(handshakeTypeGuestHello)
	inner.Write([]byte{0, 0})
	writeUint16(&inner, hello.Suite)
	inner.WriteByte(byte(hello.Identity.Channel))
	inner.WriteByte(0)
	inner.Write(hello.GuestX25519Public[:])
	inner.Write(hello.Identity.GuestBootNonce[:])
	writeUint32(&inner, hello.Identity.GuestCID)
	writeUint32(&inner, hello.Identity.GuestPort)
	for _, token := range identityBaseTokens(hello.Identity) {
		if err := writeToken(&inner, token); err != nil {
			return nil, err
		}
	}
	inner.Write(hello.Identity.ImageSHA256[:])
	if hello.Identity.Channel == ChannelSSHRelay {
		for _, token := range identityRelayTokens(hello.Identity) {
			if err := writeToken(&inner, token); err != nil {
				return nil, err
			}
		}
	}
	if inner.Len() > MaxHandshakeInnerBytes {
		return nil, ErrMalformedHandshake
	}
	return inner.Bytes(), nil
}

func parseGuestHelloInner(inner []byte) (GuestHello, error) {
	if err := validateHandshakeHeader(inner, handshakeTypeGuestHello); err != nil {
		return GuestHello{}, err
	}
	reader := boundedReader{data: inner[8:]}
	suite, ok := reader.uint16()
	if !ok || suite != HandshakeSuite1 {
		return GuestHello{}, ErrMalformedHandshake
	}
	channelByte, ok := reader.byte()
	if !ok {
		return GuestHello{}, ErrMalformedHandshake
	}
	reserved, ok := reader.byte()
	if !ok || reserved != 0 {
		return GuestHello{}, ErrMalformedHandshake
	}
	var hello GuestHello
	hello.Suite = suite
	hello.Identity.Channel = Channel(channelByte)
	if !reader.fixed(hello.GuestX25519Public[:]) || !reader.fixed(hello.Identity.GuestBootNonce[:]) {
		return GuestHello{}, ErrMalformedHandshake
	}
	var valid bool
	hello.Identity.GuestCID, valid = reader.uint32()
	if !valid {
		return GuestHello{}, ErrMalformedHandshake
	}
	hello.Identity.GuestPort, valid = reader.uint32()
	if !valid {
		return GuestHello{}, ErrMalformedHandshake
	}
	base := []*string{
		&hello.Identity.ControllerKeyGeneration,
		&hello.Identity.RuntimeID,
		&hello.Identity.RuntimeGeneration,
		&hello.Identity.FirecrackerProcessGeneration,
		&hello.Identity.VsockGeneration,
		&hello.Identity.BootGeneration,
		&hello.Identity.ImageGeneration,
	}
	for _, destination := range base {
		value, tokenOK := reader.token()
		if !tokenOK {
			return GuestHello{}, ErrMalformedHandshake
		}
		*destination = value
	}
	if !reader.fixed(hello.Identity.ImageSHA256[:]) {
		return GuestHello{}, ErrMalformedHandshake
	}
	if hello.Identity.Channel == ChannelSSHRelay {
		relay := []*string{
			&hello.Identity.JobGeneration,
			&hello.Identity.ActivationGeneration,
			&hello.Identity.RelayGeneration,
		}
		for _, destination := range relay {
			value, tokenOK := reader.token()
			if !tokenOK {
				return GuestHello{}, ErrMalformedHandshake
			}
			*destination = value
		}
	}
	if reader.remaining() != 0 || validateIdentity(hello.Identity) != nil {
		return GuestHello{}, ErrMalformedHandshake
	}
	return hello, nil
}

func marshalControllerUnsignedInner(auth ControllerAuth) ([]byte, error) {
	if auth.Suite != HandshakeSuite1 || auth.Channel.label() == "" {
		return nil, ErrMalformedHandshake
	}
	var inner bytes.Buffer
	inner.Grow(44)
	inner.Write(handshakeMagic[:])
	inner.WriteByte(WireVersion)
	inner.WriteByte(handshakeTypeControllerAuth)
	inner.Write([]byte{0, 0})
	writeUint16(&inner, auth.Suite)
	inner.WriteByte(byte(auth.Channel))
	inner.WriteByte(0)
	inner.Write(auth.ControllerX25519Public[:])
	return inner.Bytes(), nil
}

func parseControllerUnsignedInner(inner []byte) (ControllerAuth, error) {
	if len(inner) != 44 || validateHandshakeHeader(inner, handshakeTypeControllerAuth) != nil {
		return ControllerAuth{}, ErrMalformedHandshake
	}
	auth := ControllerAuth{
		Suite:   binary.BigEndian.Uint16(inner[8:10]),
		Channel: Channel(inner[10]),
	}
	if auth.Suite != HandshakeSuite1 || auth.Channel.label() == "" || inner[11] != 0 {
		return ControllerAuth{}, ErrMalformedHandshake
	}
	copy(auth.ControllerX25519Public[:], inner[12:44])
	return auth, nil
}

func marshalHandshakeOuter(inner []byte) ([]byte, error) {
	if len(inner) < 1 || len(inner) > MaxHandshakeInnerBytes {
		return nil, ErrMalformedHandshake
	}
	wire := make([]byte, 4+len(inner))
	binary.BigEndian.PutUint32(wire[:4], uint32(len(inner)))
	copy(wire[4:], inner)
	return wire, nil
}

func parseHandshakeOuter(wire []byte, expectedType byte) ([]byte, error) {
	length, err := ParseHandshakeLength(wire)
	if err != nil || uint64(length)+4 != uint64(len(wire)) {
		return nil, ErrMalformedHandshake
	}
	inner := wire[4:]
	if validateHandshakeHeader(inner, expectedType) != nil {
		return nil, ErrMalformedHandshake
	}
	return inner, nil
}

// ParseHandshakeLength validates the four-byte outer prefix before a caller
// allocates or reads the declared inner record.
func ParseHandshakeLength(prefix []byte) (uint32, error) {
	if len(prefix) < 4 {
		return 0, ErrMalformedHandshake
	}
	length := binary.BigEndian.Uint32(prefix[:4])
	if length < 1 || length > MaxHandshakeInnerBytes {
		return 0, ErrMalformedHandshake
	}
	return length, nil
}

func validateHandshakeHeader(inner []byte, expectedType byte) error {
	if len(inner) < 8 || !bytes.Equal(inner[:4], handshakeMagic[:]) || inner[4] != WireVersion || inner[5] != expectedType || inner[6] != 0 || inner[7] != 0 {
		return ErrMalformedHandshake
	}
	return nil
}

func validateIdentity(identity Identity) error {
	if identity.Channel.label() == "" || identity.GuestCID != GuestCID {
		return ErrMalformedHandshake
	}
	switch identity.Channel {
	case ChannelControl:
		if identity.GuestPort != ControlPort || identity.JobGeneration != "" || identity.ActivationGeneration != "" || identity.RelayGeneration != "" {
			return ErrMalformedHandshake
		}
	case ChannelSSHRelay:
		if identity.GuestPort != SSHRelayPort {
			return ErrMalformedHandshake
		}
	}
	for _, token := range identityBaseTokens(identity) {
		if !validToken(token) {
			return ErrMalformedHandshake
		}
	}
	if identity.Channel == ChannelSSHRelay {
		for _, token := range identityRelayTokens(identity) {
			if !validJobIdentityToken(token) {
				return ErrMalformedHandshake
			}
		}
	}
	return nil
}

func validJobIdentityToken(value string) bool {
	if !validToken(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] == ':' {
			return false
		}
	}
	return true
}

func identityBaseTokens(identity Identity) []string {
	return []string{
		identity.ControllerKeyGeneration,
		identity.RuntimeID,
		identity.RuntimeGeneration,
		identity.FirecrackerProcessGeneration,
		identity.VsockGeneration,
		identity.BootGeneration,
		identity.ImageGeneration,
	}
}

func identityRelayTokens(identity Identity) []string {
	return []string{identity.JobGeneration, identity.ActivationGeneration, identity.RelayGeneration}
}

func validToken(value string) bool {
	if len(value) < 1 || len(value) > 128 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for i := 1; i < len(value); i++ {
		if !asciiAlphaNumeric(value[i]) {
			switch value[i] {
			case '.', '_', ':', '-':
			default:
				return false
			}
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func writeToken(buffer *bytes.Buffer, value string) error {
	if !validToken(value) {
		return ErrMalformedHandshake
	}
	writeUint16(buffer, uint16(len(value)))
	buffer.WriteString(value)
	return nil
}

func writeUint16(buffer *bytes.Buffer, value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	buffer.Write(encoded[:])
}

func writeUint32(buffer *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	buffer.Write(encoded[:])
}

type boundedReader struct {
	data   []byte
	offset int
}

func (r *boundedReader) remaining() int {
	return len(r.data) - r.offset
}

func (r *boundedReader) byte() (byte, bool) {
	if r.remaining() < 1 {
		return 0, false
	}
	value := r.data[r.offset]
	r.offset++
	return value, true
}

func (r *boundedReader) uint16() (uint16, bool) {
	if r.remaining() < 2 {
		return 0, false
	}
	value := binary.BigEndian.Uint16(r.data[r.offset : r.offset+2])
	r.offset += 2
	return value, true
}

func (r *boundedReader) uint32() (uint32, bool) {
	if r.remaining() < 4 {
		return 0, false
	}
	value := binary.BigEndian.Uint32(r.data[r.offset : r.offset+4])
	r.offset += 4
	return value, true
}

func (r *boundedReader) fixed(destination []byte) bool {
	if r.remaining() < len(destination) {
		return false
	}
	copy(destination, r.data[r.offset:r.offset+len(destination)])
	r.offset += len(destination)
	return true
}

func (r *boundedReader) token() (string, bool) {
	length, ok := r.uint16()
	if !ok || length < 1 || length > 128 || r.remaining() < int(length) {
		return "", false
	}
	value := string(r.data[r.offset : r.offset+int(length)])
	r.offset += int(length)
	return value, validToken(value)
}
