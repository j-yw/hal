package l8composition

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestAgentSupervisorProtocolConstantsAndCatalog(t *testing.T) {
	t.Parallel()

	if AgentSupervisorHeaderBytes != 68 || MaxAgentSupervisorBodyBytes != 8*1024 || MaxAgentSupervisorDatagramBytes != 8260 {
		t.Fatalf("bounds = header %d body %d datagram %d", AgentSupervisorHeaderBytes, MaxAgentSupervisorBodyBytes, MaxAgentSupervisorDatagramBytes)
	}
	for value, want := range map[AgentSupervisorPacketType]byte{
		AgentSupervisorPacketTypeAgentConfig:         0x01,
		AgentSupervisorPacketTypeClientAttestation:   0x02,
		AgentSupervisorPacketTypeCompositionAccepted: 0x03,
		AgentSupervisorPacketTypeCloseNotify:         0x7f,
	} {
		if byte(value) != want {
			t.Errorf("packet type %d = %#x, want %#x", value, value, want)
		}
	}
	for value := 0; value <= math.MaxUint8; value++ {
		err := ValidateAgentSupervisorPacketType(AgentSupervisorPacketType(value))
		wantValid := value == 0x01 || value == 0x02 || value == 0x03 || value == 0x7f
		if (err == nil) != wantValid {
			t.Errorf("type %#x valid = %t, want %t", value, err == nil, wantValid)
		}
	}
	for value := 0; value <= math.MaxUint8; value++ {
		err := ValidateAgentSupervisorDirection(AgentSupervisorDirection(value))
		wantValid := value == 1 || value == 2
		if (err == nil) != wantValid {
			t.Errorf("direction %#x valid = %t, want %t", value, err == nil, wantValid)
		}
	}
}

func TestAgentSupervisorCanonicalPacketVectors(t *testing.T) {
	t.Parallel()

	fixture := agentSupervisorFixture(t)
	tests := []struct {
		name    string
		encode  func() ([]byte, error)
		wantHex string
	}{
		{
			name:   "agent config",
			encode: func() ([]byte, error) { return EncodeAgentSupervisorAgentConfigPacket(0, fixture.config) },
			wantHex: "484c384101010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000093" +
				"0000002a0000000000000000000c68656c7065722d67656e2d31000a626f6f742d67656e2d31" +
				"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
				"2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40" +
				"15cb8552a73246e3a0fd0b557a4140edab1da785165de9501c31fc6f16caa40a" +
				"000b76736f636b2d67656e2d31",
		},
		{
			name: "client attestation",
			encode: func() ([]byte, error) {
				return EncodeAgentSupervisorClientAttestationPacket(0, AgentSupervisorClientAttestationBody{Descriptor: fixture.client})
			},
			wantHex: "484c38410102000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003e" +
				"003c484c3844010200000001fc2b074212b3573e04be25d71be7dcdd49391a62cb898168bed5d305a68b35f30c7373682d72656c61792d76310103000116",
		},
		{
			name: "composition accepted",
			encode: func() ([]byte, error) {
				return EncodeAgentSupervisorCompositionAcceptedPacket(1, AgentSupervisorCompositionAcceptedBody{CompositionSHA256: fixture.composition})
			},
			wantHex: "484c384101030000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020" +
				"4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60",
		},
		{
			name: "close notify",
			encode: func() ([]byte, error) {
				return EncodeAgentSupervisorCloseNotifyPacket(1, AgentSupervisorCloseNotifyBody{Reason: credentialprotocol.CloseReasonProtocolError})
			},
			wantHex: "484c3841017f000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000102",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wire, err := test.encode()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if got := hex.EncodeToString(wire); got != test.wantHex {
				t.Fatalf("wire = %s\nwant = %s", got, test.wantHex)
			}
			packet, err := DecodeAgentSupervisorPacket(wire)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			reencoded, err := EncodeAgentSupervisorPacket(packet)
			if err != nil {
				t.Fatalf("reencode: %v", err)
			}
			if !bytes.Equal(reencoded, wire) {
				t.Fatalf("reencoded = %x, want %x", reencoded, wire)
			}
		})
	}
}

func TestAgentSupervisorHeaderRejectsMalformedWireAndNonzeroIdentity(t *testing.T) {
	t.Parallel()

	fixture := agentSupervisorFixture(t)
	if _, err := EncodeAgentSupervisorHeader(AgentSupervisorHeader{Type: AgentSupervisorPacketTypeAgentConfig, BodyLength: MaxAgentSupervisorBodyBytes}); err != nil {
		t.Fatalf("exact body limit rejected: %v", err)
	}
	if _, err := EncodeAgentSupervisorHeader(AgentSupervisorHeader{Type: AgentSupervisorPacketTypeAgentConfig, BodyLength: MaxAgentSupervisorBodyBytes + 1}); !errors.Is(err, ErrAgentSupervisorBodyLength) {
		t.Fatalf("body limit plus one error = %v", err)
	}
	base := mustEncodeAgentConfigPacket(t, fixture.config)
	tests := []struct {
		name string
		wire []byte
		want error
	}{
		{name: "nil", wire: nil, want: ErrAgentSupervisorHeaderLength},
		{name: "truncated header", wire: cloneAgentBytes(base[:AgentSupervisorHeaderBytes-1]), want: ErrAgentSupervisorHeaderLength},
		{name: "wrong magic", wire: agentWireByte(base, 0, 'X'), want: ErrAgentSupervisorMagic},
		{name: "wrong version", wire: agentWireByte(base, 4, 2), want: ErrAgentSupervisorVersion},
		{name: "unknown type", wire: agentWireByte(base, 5, 4), want: ErrAgentSupervisorPacketType},
		{name: "flags high", wire: agentWireByte(base, 6, 1), want: ErrAgentSupervisorFlags},
		{name: "flags low", wire: agentWireByte(base, 7, 1), want: ErrAgentSupervisorFlags},
		{name: "request identity", wire: agentWireByte(base, 16, 1), want: ErrAgentSupervisorRequestIdentity},
		{name: "job identity", wire: agentWireByte(base, 32, 1), want: ErrAgentSupervisorJobIdentity},
		{name: "declared plus one", wire: agentWireUint32(base, 64, uint32(len(base)-AgentSupervisorHeaderBytes+1)), want: ErrAgentSupervisorDatagramLength},
		{name: "declared minus one", wire: agentWireUint32(base, 64, uint32(len(base)-AgentSupervisorHeaderBytes-1)), want: ErrAgentSupervisorDatagramTrailingData},
		{name: "body plus one", wire: agentWireUint32(base, 64, MaxAgentSupervisorBodyBytes+1), want: ErrAgentSupervisorBodyLength},
		{name: "trailing byte", wire: append(cloneAgentBytes(base), 0), want: ErrAgentSupervisorDatagramTrailingData},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeAgentSupervisorPacket(test.wire); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAgentSupervisorBodiesRejectTruncationTrailingAndWrongDescriptor(t *testing.T) {
	t.Parallel()

	fixture := agentSupervisorFixture(t)
	config, err := EncodeAgentSupervisorAgentConfigBody(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := EncodeAgentSupervisorClientAttestationBody(AgentSupervisorClientAttestationBody{Descriptor: fixture.client})
	if err != nil {
		t.Fatal(err)
	}
	accepted := fixture.composition[:]
	closeBody := []byte{byte(credentialprotocol.CloseReasonNormal)}

	for name, test := range map[string]struct {
		wire   []byte
		decode func([]byte) error
	}{
		"config":      {config, func(wire []byte) error { _, err := DecodeAgentSupervisorAgentConfigBody(wire); return err }},
		"attestation": {attestation, func(wire []byte) error { _, err := DecodeAgentSupervisorClientAttestationBody(wire); return err }},
		"accepted":    {accepted, func(wire []byte) error { _, err := DecodeAgentSupervisorCompositionAcceptedBody(wire); return err }},
		"close":       {closeBody, func(wire []byte) error { _, err := DecodeAgentSupervisorCloseNotifyBody(wire); return err }},
	} {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := test.decode(test.wire[:len(test.wire)-1]); err == nil {
				t.Fatal("truncation accepted")
			}
			if err := test.decode(append(cloneAgentBytes(test.wire), 0)); err == nil {
				t.Fatal("trailing byte accepted")
			}
		})
	}

	helper := canonicalDescriptor(t, ProcessRoleHelper, fixture.client.Extensions)
	if _, err := EncodeAgentSupervisorClientAttestationBody(AgentSupervisorClientAttestationBody{Descriptor: helper}); !errors.Is(err, ErrAgentSupervisorDescriptorRole) {
		t.Fatalf("helper descriptor error = %v", err)
	}
	badDescriptor := cloneAgentBytes(attestation)
	badDescriptor[2] = 'X'
	if _, err := DecodeAgentSupervisorClientAttestationBody(badDescriptor); !errors.Is(err, ErrProcessDescriptorMagic) {
		t.Fatalf("malformed descriptor error = %v", err)
	}
}

func TestAgentSupervisorDirectionAndRightsMatrixIsClosed(t *testing.T) {
	t.Parallel()

	valid := []struct {
		typeValue AgentSupervisorPacketType
		direction AgentSupervisorDirection
	}{
		{AgentSupervisorPacketTypeAgentConfig, AgentSupervisorDirectionPID1ToAgent},
		{AgentSupervisorPacketTypeClientAttestation, AgentSupervisorDirectionAgentToPID1},
		{AgentSupervisorPacketTypeCompositionAccepted, AgentSupervisorDirectionPID1ToAgent},
		{AgentSupervisorPacketTypeCloseNotify, AgentSupervisorDirectionPID1ToAgent},
		{AgentSupervisorPacketTypeCloseNotify, AgentSupervisorDirectionAgentToPID1},
	}
	for _, test := range valid {
		if err := ValidateAgentSupervisorPacketMetadata(test.typeValue, test.direction, 0); err != nil {
			t.Errorf("valid %d/%d: %v", test.typeValue, test.direction, err)
		}
		if err := ValidateAgentSupervisorPacketMetadata(test.typeValue, test.direction, 1); !errors.Is(err, ErrAgentSupervisorRights) {
			t.Errorf("rights %d/%d: %v", test.typeValue, test.direction, err)
		}
	}
	if err := ValidateAgentSupervisorPacketMetadata(AgentSupervisorPacketTypeAgentConfig, AgentSupervisorDirectionPID1ToAgent, 256); !errors.Is(err, ErrAgentSupervisorRights) {
		t.Errorf("rights count 256 narrowed or accepted: %v", err)
	}
	for _, test := range []struct {
		typeValue AgentSupervisorPacketType
		direction AgentSupervisorDirection
	}{
		{AgentSupervisorPacketTypeAgentConfig, AgentSupervisorDirectionAgentToPID1},
		{AgentSupervisorPacketTypeClientAttestation, AgentSupervisorDirectionPID1ToAgent},
		{AgentSupervisorPacketTypeCompositionAccepted, AgentSupervisorDirectionAgentToPID1},
	} {
		if err := ValidateAgentSupervisorPacketMetadata(test.typeValue, test.direction, 0); !errors.Is(err, ErrAgentSupervisorPacketDirection) {
			t.Errorf("wrong direction %d/%d: %v", test.typeValue, test.direction, err)
		}
	}
}

func TestAgentSupervisorPreAdmissionHappyPathUsesIndependentSequencesAndClosesFD4(t *testing.T) {
	t.Parallel()

	fixture := agentSupervisorFixture(t)
	state := newAgentSupervisorState(t, fixture)
	steps := []struct {
		metadata AgentSupervisorReceiveMetadata
		wire     []byte
		want     AgentSupervisorDecision
	}{
		{fixture.pid1Metadata(), mustEncodeAgentConfigPacket(t, fixture.config), AgentSupervisorDecisionContinue},
		{fixture.agentMetadata(), mustEncodeClientAttestationPacket(t, fixture.client), AgentSupervisorDecisionContinue},
		{fixture.pid1Metadata(), mustEncodeCompositionPacket(t, 1, fixture.composition), AgentSupervisorDecisionCloseFD4},
	}
	for index, step := range steps {
		decision, err := state.Accept(step.metadata, step.wire)
		if err != nil {
			t.Fatalf("step %d: %v", index, err)
		}
		if decision != step.want {
			t.Fatalf("step %d decision = %d, want %d", index, decision, step.want)
		}
	}
	if state.Decision() != AgentSupervisorDecisionCloseFD4 {
		t.Fatalf("terminal decision = %d", state.Decision())
	}
	decision, err := state.Accept(fixture.agentMetadata(), mustEncodeClosePacket(t, 1))
	if decision != AgentSupervisorDecisionStopVM || !errors.Is(err, ErrAgentSupervisorPacketAfterAccepted) {
		t.Fatalf("packet after accepted = decision %d error %v", decision, err)
	}
}

func TestAgentSupervisorPreAdmissionFailsClosed(t *testing.T) {
	t.Parallel()

	fixture := agentSupervisorFixture(t)
	wrongClient := canonicalDescriptor(t, ProcessRoleClient, nil)
	wrongClientWire, err := EncodeProcessDescriptor(wrongClient)
	if err != nil {
		t.Fatal(err)
	}
	wrongDigest := sha256.Sum256(wrongClientWire)
	wrongConfig := fixture.config
	wrongConfig.ClientDescriptorSHA256 = wrongDigest
	wrongComposition := fixture.composition
	wrongComposition[0] ^= 0xff

	tests := []struct {
		name     string
		prepare  func(*AgentSupervisorPreAdmissionState)
		metadata AgentSupervisorReceiveMetadata
		wire     []byte
		want     error
	}{
		{name: "kernel pid", metadata: agentMetadataWithPID(fixture.pid1Metadata(), 2), wire: mustEncodeAgentConfigPacket(t, fixture.config), want: ErrAgentSupervisorKernelCredential},
		{name: "missing kernel credential", metadata: agentMetadataWithCredentialCount(fixture.pid1Metadata(), 0), wire: mustEncodeAgentConfigPacket(t, fixture.config), want: ErrAgentSupervisorCredentialCount},
		{name: "duplicate kernel credentials", metadata: agentMetadataWithCredentialCount(fixture.pid1Metadata(), 2), wire: mustEncodeAgentConfigPacket(t, fixture.config), want: ErrAgentSupervisorCredentialCount},
		{name: "rights", metadata: agentMetadataWithRights(fixture.pid1Metadata(), 1), wire: mustEncodeAgentConfigPacket(t, fixture.config), want: ErrAgentSupervisorRights},
		{name: "message truncation", metadata: agentMetadataTruncated(fixture.pid1Metadata(), true, false), wire: mustEncodeAgentConfigPacket(t, fixture.config), want: ErrAgentSupervisorTruncated},
		{name: "control truncation", metadata: agentMetadataTruncated(fixture.pid1Metadata(), false, true), wire: mustEncodeAgentConfigPacket(t, fixture.config), want: ErrAgentSupervisorTruncated},
		{name: "wrong direction", metadata: fixture.agentMetadata(), wire: mustEncodeAgentConfigPacket(t, fixture.config), want: ErrAgentSupervisorPacketDirection},
		{name: "gap", metadata: fixture.pid1Metadata(), wire: mustEncodeAgentConfigPacketAt(t, 1, fixture.config), want: ErrAgentSupervisorSequence},
		{name: "wrap", metadata: fixture.pid1Metadata(), wire: mustEncodeAgentConfigPacketAt(t, math.MaxUint64, fixture.config), want: ErrAgentSupervisorSequence},
		{name: "wrong config digest", metadata: fixture.pid1Metadata(), wire: mustEncodeAgentConfigPacket(t, wrongConfig), want: ErrAgentSupervisorConfigMismatch},
		{name: "attestation before config", metadata: fixture.agentMetadata(), wire: mustEncodeClientAttestationPacket(t, fixture.client), want: ErrAgentSupervisorTransition},
		{name: "close before accepted", metadata: fixture.pid1Metadata(), wire: mustEncodeClosePacket(t, 0), want: ErrAgentSupervisorClosed},
		{
			name: "replayed config",
			prepare: func(state *AgentSupervisorPreAdmissionState) {
				mustAcceptAgentPacket(t, state, fixture.pid1Metadata(), mustEncodeAgentConfigPacket(t, fixture.config))
			},
			metadata: fixture.pid1Metadata(), wire: mustEncodeAgentConfigPacket(t, fixture.config), want: ErrAgentSupervisorSequence,
		},
		{
			name: "wrong descriptor",
			prepare: func(state *AgentSupervisorPreAdmissionState) {
				mustAcceptAgentPacket(t, state, fixture.pid1Metadata(), mustEncodeAgentConfigPacket(t, fixture.config))
			},
			metadata: fixture.agentMetadata(), wire: mustEncodeClientAttestationPacket(t, wrongClient), want: ErrAgentSupervisorDescriptorMismatch,
		},
		{
			name: "wrong composition digest",
			prepare: func(state *AgentSupervisorPreAdmissionState) {
				mustAcceptAgentPacket(t, state, fixture.pid1Metadata(), mustEncodeAgentConfigPacket(t, fixture.config))
				mustAcceptAgentPacket(t, state, fixture.agentMetadata(), mustEncodeClientAttestationPacket(t, fixture.client))
			},
			metadata: fixture.pid1Metadata(), wire: mustEncodeCompositionPacket(t, 1, wrongComposition), want: ErrAgentSupervisorCompositionMismatch,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := newAgentSupervisorState(t, fixture)
			if test.prepare != nil {
				test.prepare(state)
			}
			decision, err := state.Accept(test.metadata, test.wire)
			if decision != AgentSupervisorDecisionStopVM || !errors.Is(err, test.want) {
				t.Fatalf("decision/error = %d/%v, want stop/%v", decision, err, test.want)
			}
			if state.Decision() != AgentSupervisorDecisionStopVM {
				t.Fatal("failure was not permanent")
			}
			decision, err = state.Accept(fixture.pid1Metadata(), mustEncodeAgentConfigPacket(t, fixture.config))
			if decision != AgentSupervisorDecisionStopVM || !errors.Is(err, ErrAgentSupervisorTerminal) {
				t.Fatalf("post-failure = %d/%v", decision, err)
			}
		})
	}
}

func TestAgentSupervisorLossAlwaysStopsVM(t *testing.T) {
	t.Parallel()
	fixture := agentSupervisorFixture(t)
	state := newAgentSupervisorState(t, fixture)
	if decision := state.Lost(); decision != AgentSupervisorDecisionStopVM {
		t.Fatalf("loss decision = %d", decision)
	}
	if state.Decision() != AgentSupervisorDecisionStopVM {
		t.Fatal("loss decision not permanent")
	}
}

func TestAgentSupervisorRejectsPIDOutsideLinuxSignedDomain(t *testing.T) {
	t.Parallel()

	fixture := agentSupervisorFixture(t)
	tooLarge := uint32(math.MaxInt32) + 1
	config := fixture.config
	config.ControllerPID = tooLarge
	if _, err := EncodeAgentSupervisorAgentConfigBody(config); !errors.Is(err, ErrAgentSupervisorControllerIdentity) {
		t.Fatalf("config encode error = %v", err)
	}
	config = fixture.config
	wire, err := EncodeAgentSupervisorAgentConfigBody(config)
	if err != nil {
		t.Fatal(err)
	}
	wire[0], wire[1], wire[2], wire[3] = 0x80, 0, 0, 0
	if _, err := DecodeAgentSupervisorAgentConfigBody(wire); !errors.Is(err, ErrAgentSupervisorControllerIdentity) {
		t.Fatalf("config decode error = %v", err)
	}

	expected := AgentSupervisorPreAdmissionExpected{
		PID1Credential:    fixture.pid1,
		AgentCredential:   fixture.agent,
		AgentConfig:       fixture.config,
		ClientDescriptor:  fixture.client,
		CompositionSHA256: fixture.composition,
	}
	expected.AgentCredential.PID = tooLarge
	if _, err := NewAgentSupervisorPreAdmissionState(expected); !errors.Is(err, ErrAgentSupervisorPeerIdentity) {
		t.Fatalf("expected agent PID error = %v", err)
	}
}

func TestAgentSupervisorDescriptorAndWireCopiesAreDefensive(t *testing.T) {
	t.Parallel()

	fixture := agentSupervisorFixture(t)
	body := AgentSupervisorClientAttestationBody{Descriptor: cloneAgentSupervisorDescriptor(fixture.client)}
	wire, err := EncodeAgentSupervisorClientAttestationBody(body)
	if err != nil {
		t.Fatal(err)
	}
	want := cloneAgentBytes(wire)
	body.Descriptor.Extensions[0].Modes[0] = credentialprotocol.DeliveryModeFileTmpfs
	if !bytes.Equal(wire, want) {
		t.Fatal("encoding aliases descriptor")
	}
	decoded, err := DecodeAgentSupervisorClientAttestationBody(want)
	if err != nil {
		t.Fatal(err)
	}
	wantDecoded, err := EncodeAgentSupervisorClientAttestationBody(decoded)
	if err != nil {
		t.Fatal(err)
	}
	want[2] ^= 0xff
	if !bytes.Equal(wantDecoded, mustEncodeClientAttestationBody(t, fixture.client)) {
		t.Fatal("decoded body aliases wire")
	}

	packetWire := mustEncodeClientAttestationPacket(t, fixture.client)
	packet, err := DecodeAgentSupervisorPacket(packetWire)
	if err != nil {
		t.Fatal(err)
	}
	first, ok := packet.ClientAttestation()
	if !ok {
		t.Fatal("missing attestation accessor")
	}
	first.Descriptor.Extensions[0].Modes[0] = credentialprotocol.DeliveryModeFileTmpfs
	second, ok := packet.ClientAttestation()
	if !ok || reflect.DeepEqual(first, second) {
		t.Fatal("packet descriptor accessor is not defensive")
	}
}

func TestEncodeAgentSupervisorPacketRejectsForgedPrivateUnion(t *testing.T) {
	t.Parallel()

	fixture := agentSupervisorFixture(t)
	wire := mustEncodeClientAttestationPacket(t, fixture.client)
	packet, err := DecodeAgentSupervisorPacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	packet.header.BodyLength++
	if _, err := EncodeAgentSupervisorPacket(packet); !errors.Is(err, ErrAgentSupervisorPacketBody) {
		t.Fatalf("forged length error = %v", err)
	}

	packet, err = DecodeAgentSupervisorPacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	packet.header.Type = AgentSupervisorPacketTypeAgentConfig
	if _, err := EncodeAgentSupervisorPacket(packet); !errors.Is(err, ErrAgentSupervisorPacketBody) {
		t.Fatalf("forged type error = %v", err)
	}
}

type agentSupervisorTestFixture struct {
	config      AgentSupervisorAgentConfigBody
	client      ProcessDescriptor
	composition [32]byte
	pid1        AgentSupervisorKernelCredential
	agent       AgentSupervisorKernelCredential
}

func agentSupervisorFixture(t *testing.T) agentSupervisorTestFixture {
	t.Helper()
	client := canonicalDescriptor(t, ProcessRoleClient, []credentialprotocol.ExtensionDescriptor{credentialprotocol.SSHRelayV1ExtensionDescriptor()})
	clientWire, err := EncodeProcessDescriptor(client)
	if err != nil {
		t.Fatal(err)
	}
	var nonce, bootstrap, composition [32]byte
	for index := range nonce {
		nonce[index] = byte(index + 1)
		bootstrap[index] = byte(index + 33)
		composition[index] = byte(index + 65)
	}
	return agentSupervisorTestFixture{
		config: AgentSupervisorAgentConfigBody{
			ControllerPID:          42,
			ControllerUID:          0,
			ControllerGID:          0,
			HelperGeneration:       "helper-gen-1",
			BootGeneration:         "boot-gen-1",
			BootNonce:              nonce,
			BootstrapSHA256:        bootstrap,
			ClientDescriptorSHA256: sha256.Sum256(clientWire),
			VSockGeneration:        "vsock-gen-1",
		},
		client:      client,
		composition: composition,
		pid1:        AgentSupervisorKernelCredential{PID: 1, UID: 0, GID: 0},
		agent:       AgentSupervisorKernelCredential{PID: 84, UID: AgentSupervisorServiceUID, GID: AgentSupervisorServiceGID},
	}
}

func (fixture agentSupervisorTestFixture) pid1Metadata() AgentSupervisorReceiveMetadata {
	return AgentSupervisorReceiveMetadata{Direction: AgentSupervisorDirectionPID1ToAgent, Credential: fixture.pid1, CredentialCount: 1}
}

func (fixture agentSupervisorTestFixture) agentMetadata() AgentSupervisorReceiveMetadata {
	return AgentSupervisorReceiveMetadata{Direction: AgentSupervisorDirectionAgentToPID1, Credential: fixture.agent, CredentialCount: 1}
}

func newAgentSupervisorState(t *testing.T, fixture agentSupervisorTestFixture) *AgentSupervisorPreAdmissionState {
	t.Helper()
	state, err := NewAgentSupervisorPreAdmissionState(AgentSupervisorPreAdmissionExpected{
		PID1Credential:    fixture.pid1,
		AgentCredential:   fixture.agent,
		AgentConfig:       fixture.config,
		ClientDescriptor:  fixture.client,
		CompositionSHA256: fixture.composition,
	})
	if err != nil {
		t.Fatalf("NewAgentSupervisorPreAdmissionState: %v", err)
	}
	return state
}

func mustEncodeAgentConfigPacket(t *testing.T, body AgentSupervisorAgentConfigBody) []byte {
	t.Helper()
	return mustEncodeAgentConfigPacketAt(t, 0, body)
}

func mustEncodeAgentConfigPacketAt(t *testing.T, sequence uint64, body AgentSupervisorAgentConfigBody) []byte {
	t.Helper()
	wire, err := EncodeAgentSupervisorAgentConfigPacket(sequence, body)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func mustEncodeClientAttestationPacket(t *testing.T, descriptor ProcessDescriptor) []byte {
	t.Helper()
	wire, err := EncodeAgentSupervisorClientAttestationPacket(0, AgentSupervisorClientAttestationBody{Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func mustEncodeClientAttestationBody(t *testing.T, descriptor ProcessDescriptor) []byte {
	t.Helper()
	wire, err := EncodeAgentSupervisorClientAttestationBody(AgentSupervisorClientAttestationBody{Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func mustEncodeCompositionPacket(t *testing.T, sequence uint64, digest [32]byte) []byte {
	t.Helper()
	wire, err := EncodeAgentSupervisorCompositionAcceptedPacket(sequence, AgentSupervisorCompositionAcceptedBody{CompositionSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func mustEncodeClosePacket(t *testing.T, sequence uint64) []byte {
	t.Helper()
	wire, err := EncodeAgentSupervisorCloseNotifyPacket(sequence, AgentSupervisorCloseNotifyBody{Reason: credentialprotocol.CloseReasonProtocolError})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func mustAcceptAgentPacket(t *testing.T, state *AgentSupervisorPreAdmissionState, metadata AgentSupervisorReceiveMetadata, wire []byte) {
	t.Helper()
	if decision, err := state.Accept(metadata, wire); err != nil || decision != AgentSupervisorDecisionContinue {
		t.Fatalf("Accept = %d/%v", decision, err)
	}
}

func cloneAgentBytes(value []byte) []byte { return append([]byte(nil), value...) }

func agentWireByte(wire []byte, offset int, value byte) []byte {
	result := cloneAgentBytes(wire)
	result[offset] = value
	return result
}

func agentWireUint32(wire []byte, offset int, value uint32) []byte {
	result := cloneAgentBytes(wire)
	result[offset] = byte(value >> 24)
	result[offset+1] = byte(value >> 16)
	result[offset+2] = byte(value >> 8)
	result[offset+3] = byte(value)
	return result
}

func agentMetadataWithPID(value AgentSupervisorReceiveMetadata, pid uint32) AgentSupervisorReceiveMetadata {
	value.Credential.PID = pid
	return value
}

func agentMetadataWithRights(value AgentSupervisorReceiveMetadata, count uint32) AgentSupervisorReceiveMetadata {
	value.RightsCount = count
	return value
}

func agentMetadataWithCredentialCount(value AgentSupervisorReceiveMetadata, count uint32) AgentSupervisorReceiveMetadata {
	value.CredentialCount = count
	return value
}

func agentMetadataTruncated(value AgentSupervisorReceiveMetadata, message, control bool) AgentSupervisorReceiveMetadata {
	value.MessageTruncated = message
	value.ControlTruncated = control
	return value
}
