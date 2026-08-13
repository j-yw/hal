package l8composition

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestHelperBootstrapBodyCanonicalVectors(t *testing.T) {
	t.Parallel()

	bootstrap := helperBootstrapFixture()
	wantBootstrap := make([]byte, 0, 64)
	wantBootstrap = binary.BigEndian.AppendUint32(wantBootstrap, 0x01020304)
	wantBootstrap = binary.BigEndian.AppendUint32(wantBootstrap, HelperAgentServiceUID)
	wantBootstrap = binary.BigEndian.AppendUint32(wantBootstrap, HelperAgentServiceGID)
	wantBootstrap = binary.BigEndian.AppendUint16(wantBootstrap, uint16(len("boot-generation-1")))
	wantBootstrap = append(wantBootstrap, "boot-generation-1"...)
	wantBootstrap = binary.BigEndian.AppendUint16(wantBootstrap, uint16(len("helper-generation-1")))
	wantBootstrap = append(wantBootstrap, "helper-generation-1"...)
	assertHelperBodyVector(t, bootstrap, wantBootstrap, EncodeHelperBootstrapBody, DecodeHelperBootstrapBody)

	if encoded, err := EncodeHelperReadyBody(HelperReadyBody{}); err != nil || len(encoded) != 0 {
		t.Fatalf("EncodeHelperReadyBody() = %x, %v, want empty", encoded, err)
	}
	if decoded, err := DecodeHelperReadyBody(nil); err != nil || decoded != (HelperReadyBody{}) {
		t.Fatalf("DecodeHelperReadyBody() = %v, %v", decoded, err)
	}

	digest := filledDigest(0x5a)
	ackVector := append([]byte(nil), digest[:]...)
	assertHelperBodyVector(t, HelperBootstrapAckBody{BootstrapSHA256: digest}, ackVector, EncodeHelperBootstrapAckBody, DecodeHelperBootstrapAckBody)
	assertHelperBodyVector(t, HelperAgentHelloAckBody{BootstrapSHA256: digest}, ackVector, EncodeHelperAgentHelloAckBody, DecodeHelperAgentHelloAckBody)

	descriptor := helperClientDescriptor()
	descriptorWire := independentClientDescriptorVector()
	wantHello := append([]byte(nil), digest[:]...)
	wantHello = binary.BigEndian.AppendUint16(wantHello, uint16(len("boot-generation-1")))
	wantHello = append(wantHello, "boot-generation-1"...)
	wantHello = binary.BigEndian.AppendUint16(wantHello, uint16(len("helper-generation-1")))
	wantHello = append(wantHello, "helper-generation-1"...)
	wantHello = binary.BigEndian.AppendUint16(wantHello, uint16(len(descriptorWire)))
	wantHello = append(wantHello, descriptorWire...)
	encodedHello, err := EncodeHelperAgentHelloBody(HelperAgentHelloBody{
		BootstrapSHA256:  digest,
		BootGeneration:   "boot-generation-1",
		HelperGeneration: "helper-generation-1",
		Descriptor:       descriptor,
	})
	if err != nil {
		t.Fatalf("EncodeHelperAgentHelloBody() error = %v", err)
	}
	if !bytes.Equal(encodedHello, wantHello) {
		t.Fatalf("agent hello = %x, want independently assembled %x", encodedHello, wantHello)
	}
	decodedHello, err := DecodeHelperAgentHelloBody(wantHello)
	if err != nil {
		t.Fatalf("DecodeHelperAgentHelloBody(vector) error = %v", err)
	}
	reencodedHello, err := EncodeHelperAgentHelloBody(decodedHello)
	if err != nil || !bytes.Equal(reencodedHello, wantHello) {
		t.Fatalf("agent hello reencode = %x, %v", reencodedHello, err)
	}
}

func TestComputeHelperBootstrapSHA256ExactVectorAndHeaderBinding(t *testing.T) {
	t.Parallel()

	body := helperBootstrapFixture()
	bodyWire := independentBootstrapVector()
	expected := helperBootstrapExpected()
	header := helperBootstrapHeader(uint32(len(bodyWire)))

	digest, err := ComputeHelperBootstrapSHA256(header, body, expected)
	if err != nil {
		t.Fatalf("ComputeHelperBootstrapSHA256() error = %v", err)
	}
	const wantHex = "8e3b5225e1c65dff41ce543c5cd69be9e981361819160dcfbd0447ce2166cba0"
	if got := hex.EncodeToString(digest[:]); got != wantHex {
		t.Fatalf("bootstrap digest = %s, want %s", got, wantHex)
	}
	independentHeader := make([]byte, credentialprotocol.HelperPacketHeaderSize)
	copy(independentHeader[0:4], "HL8P")
	independentHeader[4] = credentialprotocol.HelperPacketVersion
	independentHeader[5] = byte(credentialprotocol.PacketTypeBootstrap)
	binary.BigEndian.PutUint32(independentHeader[32:36], uint32(len(bodyWire)))
	copy(independentHeader[68:100], expected.BootNonce[:])
	independentInput := helperOpaque16("hal/l8/guest-helper/bootstrap/v1")
	independentInput = append(independentInput, independentHeader...)
	independentInput = append(independentInput, bodyWire...)
	if independentlyComputed := sha256.Sum256(independentInput); independentlyComputed != digest {
		t.Fatalf("bootstrap digest differs from independently assembled input: %x != %x", digest, independentlyComputed)
	}

	tests := []struct {
		name   string
		header credentialprotocol.HelperPacketHeader
		body   HelperBootstrapBody
		want   error
	}{
		{name: "unknown type", header: withHelperType(header, 0x06), body: body, want: credentialprotocol.ErrUnknownPacketType},
		{name: "wrong type", header: withHelperType(header, credentialprotocol.PacketTypeBootstrapAck), body: body, want: ErrHelperBootstrapHeaderType},
		{name: "wrong sequence", header: withHelperSequence(header, 1), body: body, want: ErrHelperBootstrapHeaderSequence},
		{name: "wrong body length", header: withHelperBodyLength(header, header.BodyLength+1), body: body, want: ErrHelperBootstrapHeaderBodyLength},
		{name: "request ID", header: withHelperRequestID(header), body: body, want: credentialprotocol.ErrHelperPacketRequestIDSemantics},
		{name: "identity digest", header: withHelperIdentity(header), body: body, want: credentialprotocol.ErrHelperPacketIdentitySemantics},
		{name: "missing nonce", header: withHelperNonce(header, [32]byte{}), body: body, want: credentialprotocol.ErrHelperPacketNonceSemantics},
		{name: "wrong nonce", header: withHelperNonce(header, filledDigest(0x99)), body: body, want: ErrHelperBootstrapNonceMismatch},
		{name: "PID drift", header: header, body: withBootstrapPID(body, body.AgentPID+1), want: ErrHelperBootstrapAgentIdentityMismatch},
		{name: "UID drift", header: header, body: withBootstrapUID(body, body.AgentUID+1), want: ErrHelperBootstrapAgentIdentityMismatch},
		{name: "GID drift", header: header, body: withBootstrapGID(body, body.AgentGID+1), want: ErrHelperBootstrapAgentIdentityMismatch},
		{name: "boot generation drift", header: header, body: withBootstrapBootGeneration(body, "boot-generation-2"), want: ErrHelperBootstrapGenerationMismatch},
		{name: "helper generation drift", header: header, body: withBootstrapHelperGeneration(body, "helper-generation-2"), want: ErrHelperBootstrapGenerationMismatch},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := ComputeHelperBootstrapSHA256(test.header, test.body, expected)
			if got != ([32]byte{}) || !errors.Is(err, test.want) {
				t.Fatalf("ComputeHelperBootstrapSHA256() = %x, %v, want zero and %v", got, err, test.want)
			}
		})
	}
}

func TestComputeHelperBootstrapSHA256DelegatesWithoutVectorDrift(t *testing.T) {
	t.Parallel()

	body := helperBootstrapFixture()
	bodyWire := independentBootstrapVector()
	header := helperBootstrapHeader(uint32(len(bodyWire)))
	got, err := ComputeHelperBootstrapSHA256(header, body, helperBootstrapExpected())
	if err != nil {
		t.Fatalf("ComputeHelperBootstrapSHA256() error = %v", err)
	}
	leaf, err := credentialprotocol.ComputeCanonicalHelperBootstrapSHA256(header, bodyWire)
	if err != nil {
		t.Fatalf("ComputeCanonicalHelperBootstrapSHA256() error = %v", err)
	}
	if got != leaf {
		t.Fatalf("compatibility digest = %x, shared leaf = %x", got, leaf)
	}
	const wantHex = "8e3b5225e1c65dff41ce543c5cd69be9e981361819160dcfbd0447ce2166cba0"
	if encoded := hex.EncodeToString(got[:]); encoded != wantHex {
		t.Fatalf("compatibility digest = %s, want %s", encoded, wantHex)
	}
}

func TestHelperBootstrapCorrelationValidators(t *testing.T) {
	t.Parallel()

	bootstrap := helperBootstrapFixture()
	expected := helperBootstrapExpected()
	bootstrapWire := independentBootstrapVector()
	bootstrapHeader := helperBootstrapHeader(uint32(len(bootstrapWire)))
	digest, err := ComputeHelperBootstrapSHA256(bootstrapHeader, bootstrap, expected)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := helperClientDescriptor()
	descriptorWire := independentClientDescriptorVector()

	if err := ValidateHelperReadyCorrelation(credentialprotocol.HelperPacketHeader{Type: credentialprotocol.PacketTypeHelperReady}); err != nil {
		t.Fatalf("ValidateHelperReadyCorrelation() error = %v", err)
	}
	if err := ValidateHelperBootstrapCorrelation(bootstrapHeader, bootstrap, expected); err != nil {
		t.Fatalf("ValidateHelperBootstrapCorrelation() error = %v", err)
	}
	ackHeader := helperHandshakeHeader(credentialprotocol.PacketTypeBootstrapAck, 1, 32)
	ack := HelperBootstrapAckBody{BootstrapSHA256: digest}
	if err := ValidateHelperBootstrapAckCorrelation(ackHeader, ack, expected.BootNonce, digest); err != nil {
		t.Fatalf("ValidateHelperBootstrapAckCorrelation() error = %v", err)
	}
	helloHeader := helperHandshakeHeader(credentialprotocol.PacketTypeAgentHello, 1, uint32(32+2+len(expected.BootGeneration)+2+len(expected.HelperGeneration)+2+len(descriptorWire)))
	hello := HelperAgentHelloBody{BootstrapSHA256: digest, BootGeneration: expected.BootGeneration, HelperGeneration: expected.HelperGeneration, Descriptor: descriptor}
	if err := ValidateHelperAgentHelloCorrelation(helloHeader, hello, expected.BootNonce, digest, expected.BootGeneration, expected.HelperGeneration, descriptor); err != nil {
		t.Fatalf("ValidateHelperAgentHelloCorrelation() error = %v", err)
	}
	helloAckHeader := helperHandshakeHeader(credentialprotocol.PacketTypeAgentHelloAck, 2, 32)
	helloAck := HelperAgentHelloAckBody{BootstrapSHA256: digest}
	if err := ValidateHelperAgentHelloAckCorrelation(helloAckHeader, helloAck, expected.BootNonce, digest); err != nil {
		t.Fatalf("ValidateHelperAgentHelloAckCorrelation() error = %v", err)
	}

	tests := []struct {
		name string
		run  func() error
		want error
	}{
		{name: "ready sequence", run: func() error {
			return ValidateHelperReadyCorrelation(withHelperSequence(credentialprotocol.HelperPacketHeader{Type: credentialprotocol.PacketTypeHelperReady}, 1))
		}, want: ErrHelperBootstrapHeaderSequence},
		{name: "ready body", run: func() error {
			return ValidateHelperReadyCorrelation(withHelperBodyLength(credentialprotocol.HelperPacketHeader{Type: credentialprotocol.PacketTypeHelperReady}, 1))
		}, want: ErrHelperBootstrapHeaderBodyLength},
		{name: "bootstrap PID", run: func() error {
			return ValidateHelperBootstrapCorrelation(bootstrapHeader, withBootstrapPID(bootstrap, bootstrap.AgentPID+1), expected)
		}, want: ErrHelperBootstrapAgentIdentityMismatch},
		{name: "ack sequence", run: func() error {
			return ValidateHelperBootstrapAckCorrelation(withHelperSequence(ackHeader, 2), ack, expected.BootNonce, digest)
		}, want: ErrHelperBootstrapHeaderSequence},
		{name: "ack request ID", run: func() error {
			return ValidateHelperBootstrapAckCorrelation(withHelperRequestID(ackHeader), ack, expected.BootNonce, digest)
		}, want: credentialprotocol.ErrHelperPacketRequestIDSemantics},
		{name: "ack nonce", run: func() error {
			return ValidateHelperBootstrapAckCorrelation(withHelperNonce(ackHeader, filledDigest(0x88)), ack, expected.BootNonce, digest)
		}, want: ErrHelperBootstrapNonceMismatch},
		{name: "ack digest", run: func() error {
			return ValidateHelperBootstrapAckCorrelation(ackHeader, HelperBootstrapAckBody{BootstrapSHA256: filledDigest(0x77)}, expected.BootNonce, digest)
		}, want: ErrHelperBootstrapDigestMismatch},
		{name: "hello type", run: func() error {
			return ValidateHelperAgentHelloCorrelation(withHelperType(helloHeader, credentialprotocol.PacketTypeAgentHelloAck), hello, expected.BootNonce, digest, expected.BootGeneration, expected.HelperGeneration, descriptor)
		}, want: ErrHelperBootstrapHeaderType},
		{name: "hello body length", run: func() error {
			return ValidateHelperAgentHelloCorrelation(withHelperBodyLength(helloHeader, helloHeader.BodyLength+1), hello, expected.BootNonce, digest, expected.BootGeneration, expected.HelperGeneration, descriptor)
		}, want: ErrHelperBootstrapHeaderBodyLength},
		{name: "hello identity", run: func() error {
			return ValidateHelperAgentHelloCorrelation(withHelperIdentity(helloHeader), hello, expected.BootNonce, digest, expected.BootGeneration, expected.HelperGeneration, descriptor)
		}, want: credentialprotocol.ErrHelperPacketIdentitySemantics},
		{name: "hello boot generation", run: func() error {
			return ValidateHelperAgentHelloCorrelation(helloHeader, withHelloBootGeneration(hello, "boot-generation-2"), expected.BootNonce, digest, expected.BootGeneration, expected.HelperGeneration, descriptor)
		}, want: ErrHelperBootstrapGenerationMismatch},
		{name: "hello helper generation", run: func() error {
			return ValidateHelperAgentHelloCorrelation(helloHeader, withHelloHelperGeneration(hello, "helper-generation-2"), expected.BootNonce, digest, expected.BootGeneration, expected.HelperGeneration, descriptor)
		}, want: ErrHelperBootstrapGenerationMismatch},
		{name: "hello descriptor", run: func() error {
			return ValidateHelperAgentHelloCorrelation(helloHeader, withHelloDescriptor(hello, descriptorWithPolicyByte(descriptor, 0)), expected.BootNonce, digest, expected.BootGeneration, expected.HelperGeneration, descriptor)
		}, want: ErrHelperBootstrapDescriptorMismatch},
		{name: "hello ack sequence", run: func() error {
			return ValidateHelperAgentHelloAckCorrelation(withHelperSequence(helloAckHeader, 1), helloAck, expected.BootNonce, digest)
		}, want: ErrHelperBootstrapHeaderSequence},
		{name: "hello ack missing nonce", run: func() error {
			return ValidateHelperAgentHelloAckCorrelation(withHelperNonce(helloAckHeader, [32]byte{}), helloAck, expected.BootNonce, digest)
		}, want: credentialprotocol.ErrHelperPacketNonceSemantics},
		{name: "hello ack digest", run: func() error {
			return ValidateHelperAgentHelloAckCorrelation(helloAckHeader, HelperAgentHelloAckBody{BootstrapSHA256: filledDigest(0x77)}, expected.BootNonce, digest)
		}, want: ErrHelperBootstrapDigestMismatch},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.run(); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestHelperBootstrapBodiesRejectBoundsTruncationTrailingAndNoncanonicalDescriptor(t *testing.T) {
	t.Parallel()

	maxToken := "a" + strings.Repeat("-", credentialprotocol.MaxBodyTokenBytes-1)
	maxBootstrap := HelperBootstrapBody{AgentPID: 2, AgentUID: HelperAgentServiceUID, AgentGID: HelperAgentServiceGID, BootGeneration: maxToken, HelperGeneration: maxToken}
	if _, err := EncodeHelperBootstrapBody(maxBootstrap); err != nil {
		t.Fatalf("maximum token error = %v", err)
	}
	if _, err := EncodeHelperAgentHelloBody(HelperAgentHelloBody{
		BootstrapSHA256: filledDigest(1), BootGeneration: maxToken,
		HelperGeneration: maxToken, Descriptor: helperClientDescriptor(),
	}); err != nil {
		t.Fatalf("maximum hello tokens error = %v", err)
	}
	for _, body := range []HelperBootstrapBody{
		withBootstrapBootGeneration(maxBootstrap, maxToken+"x"),
		withBootstrapHelperGeneration(maxBootstrap, maxToken+"x"),
	} {
		if _, err := EncodeHelperBootstrapBody(body); !errors.Is(err, credentialprotocol.ErrInvalidBodyToken) {
			t.Errorf("plus-one token error = %v", err)
		}
	}
	for _, body := range []HelperBootstrapBody{
		withBootstrapBootGeneration(maxBootstrap, " bad"),
		withBootstrapHelperGeneration(maxBootstrap, "bad/value"),
	} {
		if _, err := EncodeHelperBootstrapBody(body); !errors.Is(err, credentialprotocol.ErrInvalidBodyToken) {
			t.Errorf("noncanonical token error = %v", err)
		}
	}

	bootstrapWire := independentBootstrapVector()
	for cut := 0; cut < len(bootstrapWire); cut++ {
		if _, err := DecodeHelperBootstrapBody(bootstrapWire[:cut]); err == nil {
			t.Errorf("bootstrap truncation %d accepted", cut)
		}
	}
	if _, err := DecodeHelperBootstrapBody(append(append([]byte(nil), bootstrapWire...), 0)); !errors.Is(err, ErrHelperBootstrapBodyTrailingData) {
		t.Errorf("bootstrap trailing error = %v", err)
	}
	for _, offset := range []int{12, 12 + 2 + len("boot-generation-1")} {
		wire := append([]byte(nil), bootstrapWire...)
		binary.BigEndian.PutUint16(wire[offset:offset+2], credentialprotocol.MaxBodyTokenBytes+1)
		if _, err := DecodeHelperBootstrapBody(wire); !errors.Is(err, credentialprotocol.ErrInvalidBodyToken) {
			t.Errorf("token plus-one at %d error = %v", offset, err)
		}
	}
	for _, mutate := range []func([]byte){
		func(wire []byte) { binary.BigEndian.PutUint32(wire[0:4], 0) },
		func(wire []byte) { binary.BigEndian.PutUint32(wire[4:8], 999) },
		func(wire []byte) { binary.BigEndian.PutUint32(wire[8:12], 999) },
	} {
		wire := append([]byte(nil), bootstrapWire...)
		mutate(wire)
		if _, err := DecodeHelperBootstrapBody(wire); err == nil {
			t.Errorf("noncanonical bootstrap accepted: %x", wire[:12])
		}
	}

	for _, decode := range []func([]byte) error{
		func(wire []byte) error { _, err := DecodeHelperBootstrapAckBody(wire); return err },
		func(wire []byte) error { _, err := DecodeHelperAgentHelloAckBody(wire); return err },
	} {
		for length := 0; length < sha256.Size; length++ {
			if err := decode(make([]byte, length)); err == nil {
				t.Errorf("ack truncation %d accepted", length)
			}
		}
		if err := decode(make([]byte, sha256.Size)); !errors.Is(err, ErrHelperBootstrapDigestZero) {
			t.Errorf("zero ack error = %v", err)
		}
		if err := decode(make([]byte, sha256.Size+1)); !errors.Is(err, ErrHelperBootstrapBodyTrailingData) {
			t.Errorf("ack trailing error = %v", err)
		}
	}

	hello := helperHelloVector()
	for cut := 0; cut < len(hello); cut++ {
		if _, err := DecodeHelperAgentHelloBody(hello[:cut]); err == nil {
			t.Errorf("hello truncation %d accepted", cut)
		}
	}
	if _, err := DecodeHelperAgentHelloBody(append(append([]byte(nil), hello...), 0)); !errors.Is(err, ErrHelperBootstrapBodyTrailingData) {
		t.Errorf("hello trailing error = %v", err)
	}
	descriptorLengthOffset := 32 + 2 + len("boot-generation-1") + 2 + len("helper-generation-1")
	plusOneDescriptor := append([]byte(nil), hello...)
	binary.BigEndian.PutUint16(plusOneDescriptor[descriptorLengthOffset:descriptorLengthOffset+2], MaxProcessDescriptorBytes+1)
	if _, err := DecodeHelperAgentHelloBody(plusOneDescriptor); !errors.Is(err, ErrHelperBootstrapDescriptorLength) {
		t.Errorf("descriptor plus-one error = %v", err)
	}
	maximumDescriptor := append([]byte(nil), hello[:descriptorLengthOffset]...)
	maximumDescriptor = binary.BigEndian.AppendUint16(maximumDescriptor, MaxProcessDescriptorBytes)
	maximumDescriptor = append(maximumDescriptor, make([]byte, MaxProcessDescriptorBytes)...)
	if _, err := DecodeHelperAgentHelloBody(maximumDescriptor); errors.Is(err, ErrHelperBootstrapDescriptorLength) {
		t.Errorf("maximum descriptor rejected by hello length gate: %v", err)
	}

	for _, encode := range []func() error{
		func() error { _, err := EncodeHelperBootstrapAckBody(HelperBootstrapAckBody{}); return err },
		func() error { _, err := EncodeHelperAgentHelloAckBody(HelperAgentHelloAckBody{}); return err },
		func() error {
			_, err := EncodeHelperAgentHelloBody(HelperAgentHelloBody{BootGeneration: "boot-generation-1", HelperGeneration: "helper-generation-1", Descriptor: helperClientDescriptor()})
			return err
		},
	} {
		if err := encode(); !errors.Is(err, ErrHelperBootstrapDigestZero) {
			t.Errorf("zero digest encode error = %v", err)
		}
	}
	for _, mutation := range []struct {
		name   string
		offset int
		value  byte
		want   error
	}{
		{name: "unknown magic", offset: descriptorLengthOffset + 2, value: 'X', want: ErrProcessDescriptorMagic},
		{name: "unknown version", offset: descriptorLengthOffset + 6, value: 2, want: ErrProcessDescriptorWireVersion},
		{name: "wrong role", offset: descriptorLengthOffset + 7, value: byte(ProcessRoleHelper), want: ErrHelperBootstrapDescriptorRole},
		{name: "reserved high", offset: descriptorLengthOffset + 8, value: 1, want: ErrProcessDescriptorReserved},
		{name: "reserved low", offset: descriptorLengthOffset + 9, value: 1, want: ErrProcessDescriptorReserved},
	} {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			wire := append([]byte(nil), hello...)
			wire[mutation.offset] = mutation.value
			if _, err := DecodeHelperAgentHelloBody(wire); !errors.Is(err, mutation.want) {
				t.Fatalf("error = %v, want %v", err, mutation.want)
			}
		})
	}

	for _, malformed := range []struct {
		name       string
		descriptor []byte
		want       error
	}{
		{name: "descriptor trailing", descriptor: append(independentClientDescriptorVector(), 0), want: ErrProcessDescriptorTrailingData},
		{name: "unknown catalog", descriptor: rawClientDescriptorWithCatalog([]byte{0x06}), want: credentialprotocol.ErrUnknownPacketType},
		{name: "noncanonical catalog", descriptor: rawClientDescriptorWithCatalog([]byte{byte(credentialprotocol.PacketTypeSSHAcceptedFD), byte(credentialprotocol.PacketTypeSSHAcceptedFD)}), want: credentialprotocol.ErrExtensionCatalogDuplicate},
	} {
		malformed := malformed
		t.Run(malformed.name, func(t *testing.T) {
			if _, err := DecodeHelperAgentHelloBody(helloWithDescriptorWire(malformed.descriptor)); !errors.Is(err, malformed.want) {
				t.Fatalf("error = %v, want %v", err, malformed.want)
			}
		})
	}
}

func TestHelperBootstrapPublicValuesAreOpaqueAndSerializationDeniedWithoutMutation(t *testing.T) {
	t.Parallel()

	digest := filledDigest(0x5a)
	values := []interface{}{
		HelperReadyBody{},
		helperBootstrapFixture(),
		HelperBootstrapAckBody{BootstrapSHA256: digest},
		HelperAgentHelloBody{BootstrapSHA256: digest, BootGeneration: "boot-generation-1", HelperGeneration: "helper-generation-1", Descriptor: helperClientDescriptor()},
		HelperAgentHelloAckBody{BootstrapSHA256: digest},
		helperBootstrapExpected(),
	}
	for _, value := range values {
		value := value
		t.Run(reflect.TypeOf(value).Name(), func(t *testing.T) {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
				if rendered := fmt.Sprintf(verb, value); rendered != reflect.TypeOf(value).Name() {
					t.Errorf("fmt.Sprintf(%q, value) = %q", verb, rendered)
				}
				pointer := reflect.New(reflect.TypeOf(value))
				pointer.Elem().Set(reflect.ValueOf(value))
				if rendered := fmt.Sprintf(verb, pointer.Interface()); rendered != reflect.TypeOf(value).Name() {
					t.Errorf("fmt.Sprintf(%q, pointer) = %q", verb, rendered)
				}
			}
			if payload, err := value.(json.Marshaler).MarshalJSON(); payload != nil || !errors.Is(err, ErrHelperBootstrapSerialization) {
				t.Errorf("MarshalJSON() = %x, %v", payload, err)
			}
			if payload, err := value.(encoding.TextMarshaler).MarshalText(); payload != nil || !errors.Is(err, ErrHelperBootstrapSerialization) {
				t.Errorf("MarshalText() = %x, %v", payload, err)
			}
			if payload, err := value.(encoding.BinaryMarshaler).MarshalBinary(); payload != nil || !errors.Is(err, ErrHelperBootstrapSerialization) {
				t.Errorf("MarshalBinary() = %x, %v", payload, err)
			}
			pointer := reflect.New(reflect.TypeOf(value))
			pointer.Elem().Set(reflect.ValueOf(value))
			before := reflect.New(reflect.TypeOf(value))
			before.Elem().Set(pointer.Elem())
			for name, invoke := range map[string]func() error{
				"json": func() error { return pointer.Interface().(json.Unmarshaler).UnmarshalJSON([]byte("private-marker")) },
				"text": func() error {
					return pointer.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte("private-marker"))
				},
				"binary": func() error {
					return pointer.Interface().(encoding.BinaryUnmarshaler).UnmarshalBinary([]byte("private-marker"))
				},
			} {
				if err := invoke(); !errors.Is(err, ErrHelperBootstrapSerialization) {
					t.Errorf("Unmarshal%s() error = %v", name, err)
				}
				if !reflect.DeepEqual(pointer.Elem().Interface(), before.Elem().Interface()) {
					t.Fatalf("Unmarshal%s() mutated receiver", name)
				}
			}
		})
	}
}

func assertHelperBodyVector[T comparable](t *testing.T, body T, want []byte, encode func(T) ([]byte, error), decode func([]byte) (T, error)) {
	t.Helper()
	encoded, err := encode(body)
	if err != nil {
		t.Fatalf("encode error = %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded = %x, want %x", encoded, want)
	}
	decoded, err := decode(want)
	if err != nil {
		t.Fatalf("decode error = %v", err)
	}
	if decoded != body {
		t.Fatalf("decoded = %v, want %v", decoded, body)
	}
}

func helperBootstrapFixture() HelperBootstrapBody {
	return HelperBootstrapBody{AgentPID: 0x01020304, AgentUID: HelperAgentServiceUID, AgentGID: HelperAgentServiceGID, BootGeneration: "boot-generation-1", HelperGeneration: "helper-generation-1"}
}

func helperBootstrapExpected() HelperBootstrapExpected {
	return HelperBootstrapExpected{AgentPID: 0x01020304, AgentUID: HelperAgentServiceUID, AgentGID: HelperAgentServiceGID, BootGeneration: "boot-generation-1", HelperGeneration: "helper-generation-1", BootNonce: filledDigest(0x44)}
}

func helperBootstrapHeader(length uint32) credentialprotocol.HelperPacketHeader {
	return helperHandshakeHeader(credentialprotocol.PacketTypeBootstrap, 0, length)
}

func helperHandshakeHeader(packetType credentialprotocol.PacketType, sequence uint64, length uint32) credentialprotocol.HelperPacketHeader {
	return credentialprotocol.HelperPacketHeader{Type: packetType, Sequence: sequence, BodyLength: length, BootNonce: filledDigest(0x44)}
}

func independentBootstrapVector() []byte {
	body := helperBootstrapFixture()
	wire := make([]byte, 12)
	binary.BigEndian.PutUint32(wire[0:4], body.AgentPID)
	binary.BigEndian.PutUint32(wire[4:8], body.AgentUID)
	binary.BigEndian.PutUint32(wire[8:12], body.AgentGID)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(body.BootGeneration)))
	wire = append(wire, body.BootGeneration...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(body.HelperGeneration)))
	return append(wire, body.HelperGeneration...)
}

func helperClientDescriptor() ProcessDescriptor {
	return ProcessDescriptor{ContractVersion: ProcessDescriptorContractVersion, Role: ProcessRoleClient, PolicySHA256: helperClientPolicyDigest()}
}

func helperClientPolicyDigest() [32]byte {
	return sha256.Sum256(append(helperOpaque16("hal/l8/process-policy/v1"), helperOpaque16("client-policy-v1")...))
}

func independentClientDescriptorVector() []byte {
	wire := []byte{'H', 'L', '8', 'D', 1, byte(ProcessRoleClient), 0, 0, 0, 0}
	digest := helperClientPolicyDigest()
	return append(wire, digest[:]...)
}

func helperHelloVector() []byte {
	digest := filledDigest(0x5a)
	descriptor := independentClientDescriptorVector()
	wire := append([]byte(nil), digest[:]...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len("boot-generation-1")))
	wire = append(wire, "boot-generation-1"...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len("helper-generation-1")))
	wire = append(wire, "helper-generation-1"...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(descriptor)))
	return append(wire, descriptor...)
}

func helloWithDescriptorWire(descriptor []byte) []byte {
	digest := filledDigest(0x5a)
	wire := append([]byte(nil), digest[:]...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len("boot-generation-1")))
	wire = append(wire, "boot-generation-1"...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len("helper-generation-1")))
	wire = append(wire, "helper-generation-1"...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(descriptor)))
	return append(wire, descriptor...)
}

func rawClientDescriptorWithCatalog(helperPackets []byte) []byte {
	wire := []byte{'H', 'L', '8', 'D', 1, byte(ProcessRoleClient), 0, 0, 0, 1}
	digest := helperClientPolicyDigest()
	wire = append(wire, digest[:]...)
	wire = append(wire, byte(len("future-v1")))
	wire = append(wire, "future-v1"...)
	wire = append(wire, 0, 0, byte(len(helperPackets)))
	return append(wire, helperPackets...)
}

func helperOpaque16(value string) []byte {
	wire := make([]byte, 2)
	binary.BigEndian.PutUint16(wire, uint16(len(value)))
	return append(wire, value...)
}

func filledDigest(value byte) [32]byte {
	var digest [32]byte
	for index := range digest {
		digest[index] = value
	}
	return digest
}

func withHelperType(header credentialprotocol.HelperPacketHeader, packetType credentialprotocol.PacketType) credentialprotocol.HelperPacketHeader {
	header.Type = packetType
	return header
}
func withHelperSequence(header credentialprotocol.HelperPacketHeader, sequence uint64) credentialprotocol.HelperPacketHeader {
	header.Sequence = sequence
	return header
}
func withHelperBodyLength(header credentialprotocol.HelperPacketHeader, length uint32) credentialprotocol.HelperPacketHeader {
	header.BodyLength = length
	return header
}
func withHelperRequestID(header credentialprotocol.HelperPacketHeader) credentialprotocol.HelperPacketHeader {
	header.RequestID[0] = 1
	return header
}
func withHelperIdentity(header credentialprotocol.HelperPacketHeader) credentialprotocol.HelperPacketHeader {
	header.GuestCredentialIdentityDigest[0] = 1
	return header
}
func withHelperNonce(header credentialprotocol.HelperPacketHeader, nonce [32]byte) credentialprotocol.HelperPacketHeader {
	header.BootNonce = nonce
	return header
}
func withBootstrapPID(body HelperBootstrapBody, value uint32) HelperBootstrapBody {
	body.AgentPID = value
	return body
}
func withBootstrapUID(body HelperBootstrapBody, value uint32) HelperBootstrapBody {
	body.AgentUID = value
	return body
}
func withBootstrapGID(body HelperBootstrapBody, value uint32) HelperBootstrapBody {
	body.AgentGID = value
	return body
}
func withBootstrapBootGeneration(body HelperBootstrapBody, value string) HelperBootstrapBody {
	body.BootGeneration = value
	return body
}
func withBootstrapHelperGeneration(body HelperBootstrapBody, value string) HelperBootstrapBody {
	body.HelperGeneration = value
	return body
}
func withHelloBootGeneration(body HelperAgentHelloBody, value string) HelperAgentHelloBody {
	body.BootGeneration = value
	return body
}
func withHelloHelperGeneration(body HelperAgentHelloBody, value string) HelperAgentHelloBody {
	body.HelperGeneration = value
	return body
}
func withHelloDescriptor(body HelperAgentHelloBody, value ProcessDescriptor) HelperAgentHelloBody {
	body.Descriptor = value
	return body
}
func descriptorWithPolicyByte(descriptor ProcessDescriptor, index int) ProcessDescriptor {
	descriptor.PolicySHA256[index] ^= 0xff
	return descriptor
}
