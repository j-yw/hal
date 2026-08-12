package l8composition

import (
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestHelperBootstrapPreAdmissionHappyPathSharesDirectionSequences(t *testing.T) {
	t.Parallel()

	fixture := helperBootstrapStateFixture(t)
	state := newHelperBootstrapState(t, fixture)
	steps := []struct {
		metadata HelperBootstrapReceiveMetadata
		wire     []byte
		want     HelperBootstrapDecision
	}{
		{fixture.helperToPID1(), helperReadyDatagram(t), HelperBootstrapDecisionContinue},
		{fixture.pid1Bootstrap(), helperBootstrapDatagram(t, fixture.bootstrap, fixture.expected.Bootstrap), HelperBootstrapDecisionContinue},
		{fixture.helperToPID1(), helperBootstrapAckDatagram(t, 1, fixture.digest), HelperBootstrapDecisionContinue},
		{fixture.agentToHelper(), helperAgentHelloDatagram(t, 1, fixture, fixture.client), HelperBootstrapDecisionContinue},
		{fixture.helperToAgent(), helperAgentHelloAckDatagram(t, 2, fixture.digest), HelperBootstrapDecisionComplete},
	}
	for index, step := range steps {
		decision, err := state.Accept(step.metadata, step.wire)
		if err != nil || decision != step.want {
			t.Fatalf("step %d = %v, %v, want %v", index, decision, err, step.want)
		}
	}
	if state.Decision() != HelperBootstrapDecisionComplete {
		t.Fatalf("decision = %v", state.Decision())
	}
	state.state.mu.Lock()
	nextReceive, nextSend := state.state.nextReceive, state.state.nextSend
	state.state.mu.Unlock()
	if nextReceive != 2 || nextSend != 3 {
		t.Fatalf("handoff sequences = receive %d send %d, want 2/3", nextReceive, nextSend)
	}
	decision, err := state.Accept(fixture.agentToHelper(), helperAgentHelloDatagram(t, 2, fixture, fixture.client))
	if decision != HelperBootstrapDecisionStopVM || !errors.Is(err, ErrHelperBootstrapPacketAfterCompletion) {
		t.Fatalf("packet after completion = %v, %v", decision, err)
	}
}

func TestHelperBootstrapStateClosedMetadataCatalogs(t *testing.T) {
	t.Parallel()

	for value := 0; value <= math.MaxUint8; value++ {
		directionErr := ValidateHelperBootstrapDirection(HelperBootstrapDirection(value))
		validDirection := value >= 1 && value <= 4
		if (directionErr == nil) != validDirection {
			t.Errorf("direction %d valid = %t, want %t", value, directionErr == nil, validDirection)
		}
		rightErr := ValidateHelperBootstrapRightKind(HelperBootstrapRightKind(value))
		if (rightErr == nil) != (value == 1) {
			t.Errorf("right kind %d valid = %t, want %t", value, rightErr == nil, value == 1)
		}
	}
	if HelperBootstrapDecisionContinue != 1 || HelperBootstrapDecisionComplete != 2 || HelperBootstrapDecisionStopVM != 3 {
		t.Fatal("helper bootstrap decision catalog changed")
	}
}

func TestHelperBootstrapPreAdmissionFailsClosedWithoutMutationRecovery(t *testing.T) {
	t.Parallel()

	fixture := helperBootstrapStateFixture(t)
	wrongDescriptor := descriptorWithPolicyByte(fixture.client, int(fixture.client.PolicySHA256[0]^0xff))
	wrongDigest := fixture.digest
	wrongDigest[0] ^= 0xff
	tests := []struct {
		name     string
		prepare  func(*HelperBootstrapPreAdmissionState)
		metadata HelperBootstrapReceiveMetadata
		wire     []byte
		want     error
	}{
		{name: "message truncation", metadata: withHelperBootstrapTruncation(fixture.helperToPID1(), true, false), wire: helperReadyDatagram(t), want: ErrHelperBootstrapReceiveTruncated},
		{name: "control truncation", metadata: withHelperBootstrapTruncation(fixture.helperToPID1(), false, true), wire: helperReadyDatagram(t), want: ErrHelperBootstrapReceiveTruncated},
		{name: "missing credentials", metadata: withHelperBootstrapCredentialCount(fixture.helperToPID1(), 0), wire: helperReadyDatagram(t), want: ErrHelperBootstrapCredentialCount},
		{name: "duplicate credentials", metadata: withHelperBootstrapCredentialCount(fixture.helperToPID1(), 2), wire: helperReadyDatagram(t), want: ErrHelperBootstrapCredentialCount},
		{name: "large credentials count", metadata: withHelperBootstrapCredentialCount(fixture.helperToPID1(), math.MaxUint32), wire: helperReadyDatagram(t), want: ErrHelperBootstrapCredentialCount},
		{name: "wrong helper credential", metadata: withHelperBootstrapCredential(fixture.helperToPID1(), fixture.agent), wire: helperReadyDatagram(t), want: ErrHelperBootstrapKernelCredential},
		{name: "ready right", metadata: withHelperBootstrapRight(fixture.helperToPID1(), 1, HelperBootstrapRight{Kind: HelperBootstrapRightAgentPIDFD, AgentPID: fixture.agent.PID}), wire: helperReadyDatagram(t), want: ErrHelperBootstrapRights},
		{name: "ready opaque right despite zero count", metadata: withHelperBootstrapRight(fixture.helperToPID1(), 0, HelperBootstrapRight{Kind: HelperBootstrapRightAgentPIDFD, AgentPID: fixture.agent.PID}), wire: helperReadyDatagram(t), want: ErrHelperBootstrapRights},
		{name: "wrong direction", metadata: fixture.pid1Bootstrap(), wire: helperReadyDatagram(t), want: ErrHelperBootstrapPacketDirection},
		{name: "ready gap", metadata: fixture.helperToPID1(), wire: helperReadyDatagramAt(t, 1), want: ErrHelperBootstrapStateSequence},
		{name: "ready wrap", metadata: fixture.helperToPID1(), wire: helperReadyDatagramAt(t, math.MaxUint64), want: ErrHelperBootstrapStateSequence},
		{name: "bootstrap before ready", metadata: fixture.pid1Bootstrap(), wire: helperBootstrapDatagram(t, fixture.bootstrap, fixture.expected.Bootstrap), want: ErrHelperBootstrapTransition},
		{
			name: "bootstrap missing pidfd",
			prepare: func(state *HelperBootstrapPreAdmissionState) {
				mustAcceptHelperBootstrap(t, state, fixture.helperToPID1(), helperReadyDatagram(t))
			},
			metadata: withHelperBootstrapRight(fixture.pid1Bootstrap(), 0, HelperBootstrapRight{}),
			wire:     helperBootstrapDatagram(t, fixture.bootstrap, fixture.expected.Bootstrap), want: ErrHelperBootstrapRights,
		},
		{
			name: "bootstrap extra pidfds",
			prepare: func(state *HelperBootstrapPreAdmissionState) {
				mustAcceptHelperBootstrap(t, state, fixture.helperToPID1(), helperReadyDatagram(t))
			},
			metadata: withHelperBootstrapRight(fixture.pid1Bootstrap(), math.MaxUint32, HelperBootstrapRight{Kind: HelperBootstrapRightAgentPIDFD, AgentPID: fixture.agent.PID}),
			wire:     helperBootstrapDatagram(t, fixture.bootstrap, fixture.expected.Bootstrap), want: ErrHelperBootstrapRights,
		},
		{
			name: "bootstrap wrong right kind",
			prepare: func(state *HelperBootstrapPreAdmissionState) {
				mustAcceptHelperBootstrap(t, state, fixture.helperToPID1(), helperReadyDatagram(t))
			},
			metadata: withHelperBootstrapRight(fixture.pid1Bootstrap(), 1, HelperBootstrapRight{Kind: 2, AgentPID: fixture.agent.PID}),
			wire:     helperBootstrapDatagram(t, fixture.bootstrap, fixture.expected.Bootstrap), want: ErrHelperBootstrapRightKind,
		},
		{
			name: "bootstrap wrong pidfd target",
			prepare: func(state *HelperBootstrapPreAdmissionState) {
				mustAcceptHelperBootstrap(t, state, fixture.helperToPID1(), helperReadyDatagram(t))
			},
			metadata: withHelperBootstrapRight(fixture.pid1Bootstrap(), 1, HelperBootstrapRight{Kind: HelperBootstrapRightAgentPIDFD, AgentPID: fixture.agent.PID + 1}),
			wire:     helperBootstrapDatagram(t, fixture.bootstrap, fixture.expected.Bootstrap), want: ErrHelperBootstrapRightIdentity,
		},
		{
			name:     "ack wrong digest",
			prepare:  func(state *HelperBootstrapPreAdmissionState) { helperBootstrapThroughBootstrap(t, state, fixture) },
			metadata: fixture.helperToPID1(), wire: helperBootstrapAckDatagram(t, 1, wrongDigest), want: ErrHelperBootstrapDigestMismatch,
		},
		{
			name:     "hello before ack",
			prepare:  func(state *HelperBootstrapPreAdmissionState) { helperBootstrapThroughBootstrap(t, state, fixture) },
			metadata: fixture.agentToHelper(), wire: helperAgentHelloDatagram(t, 1, fixture, fixture.client), want: ErrHelperBootstrapTransition,
		},
		{
			name:     "hello wrong descriptor",
			prepare:  func(state *HelperBootstrapPreAdmissionState) { helperBootstrapThroughAck(t, state, fixture) },
			metadata: fixture.agentToHelper(), wire: helperAgentHelloDatagram(t, 1, fixture, wrongDescriptor), want: ErrHelperBootstrapDescriptorMismatch,
		},
		{
			name:     "hello ack wrong sender",
			prepare:  func(state *HelperBootstrapPreAdmissionState) { helperBootstrapThroughHello(t, state, fixture) },
			metadata: fixture.helperToPID1(), wire: helperAgentHelloAckDatagram(t, 2, fixture.digest), want: ErrHelperBootstrapPacketDirection,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := newHelperBootstrapState(t, fixture)
			if test.prepare != nil {
				test.prepare(state)
			}
			decision, err := state.Accept(test.metadata, test.wire)
			if decision != HelperBootstrapDecisionStopVM || !errors.Is(err, test.want) {
				t.Fatalf("decision/error = %v/%v, want stop/%v", decision, err, test.want)
			}
			if state.Decision() != HelperBootstrapDecisionStopVM {
				t.Fatal("failure was not terminal")
			}
			decision, err = state.Accept(fixture.helperToPID1(), helperReadyDatagram(t))
			if decision != HelperBootstrapDecisionStopVM || !errors.Is(err, ErrHelperBootstrapStateTerminal) {
				t.Fatalf("post failure = %v/%v", decision, err)
			}
		})
	}
}

func TestHelperBootstrapPreAdmissionLossAndValueCopiesShareTerminalState(t *testing.T) {
	t.Parallel()
	fixture := helperBootstrapStateFixture(t)
	state := newHelperBootstrapState(t, fixture)
	copyValue := *state
	if copyValue.Lost() != HelperBootstrapDecisionStopVM || state.Decision() != HelperBootstrapDecisionStopVM {
		t.Fatal("copied value did not share terminal ownership")
	}

	wrapping := newHelperBootstrapState(t, fixture)
	wrapping.state.nextSend = math.MaxUint64
	decision, err := wrapping.Accept(fixture.helperToPID1(), helperReadyDatagramAt(t, math.MaxUint64))
	if decision != HelperBootstrapDecisionStopVM || !errors.Is(err, ErrHelperBootstrapStateSequenceWrap) {
		t.Fatalf("sequence wrap = %v/%v", decision, err)
	}
}

func TestHelperBootstrapStateSnapshotsClientDescriptor(t *testing.T) {
	t.Parallel()

	fixture := helperBootstrapStateFixture(t)
	fixture.client = canonicalDescriptor(t, ProcessRoleClient, []credentialprotocol.ExtensionDescriptor{credentialprotocol.SSHRelayV1ExtensionDescriptor()})
	fixture.expected.ClientDescriptor = cloneAgentSupervisorDescriptor(fixture.client)
	state := newHelperBootstrapState(t, fixture)
	fixture.expected.ClientDescriptor.Extensions[0].Modes[0] = credentialprotocol.DeliveryModeFileTmpfs
	helperBootstrapThroughHello(t, state, fixture)
	decision, err := state.Accept(fixture.helperToAgent(), helperAgentHelloAckDatagram(t, 2, fixture.digest))
	if err != nil || decision != HelperBootstrapDecisionComplete {
		t.Fatalf("completion after caller mutation = %v/%v", decision, err)
	}
}

func TestHelperBootstrapRejectsPIDOutsideLinuxSignedDomain(t *testing.T) {
	t.Parallel()
	tooLarge := uint32(math.MaxInt32) + 1
	body := helperBootstrapFixture()
	body.AgentPID = tooLarge
	if _, err := EncodeHelperBootstrapBody(body); !errors.Is(err, ErrHelperBootstrapAgentIdentity) {
		t.Fatalf("encode = %v", err)
	}
	wire := independentBootstrapVector()
	wire[0], wire[1], wire[2], wire[3] = 0x80, 0, 0, 0
	if _, err := DecodeHelperBootstrapBody(wire); !errors.Is(err, ErrHelperBootstrapAgentIdentity) {
		t.Fatalf("decode = %v", err)
	}
	expected := helperBootstrapExpected()
	expected.AgentPID = tooLarge
	if err := ValidateHelperBootstrapCorrelation(helperBootstrapHeader(uint32(len(independentBootstrapVector()))), helperBootstrapFixture(), expected); !errors.Is(err, ErrHelperBootstrapAgentIdentity) {
		t.Fatalf("expected = %v", err)
	}
}

func TestHelperBootstrapRejectsPID1AndCrossRoleAliases(t *testing.T) {
	t.Parallel()

	body := helperBootstrapFixture()
	body.AgentPID = 1
	if _, err := EncodeHelperBootstrapBody(body); !errors.Is(err, ErrHelperBootstrapAgentIdentity) {
		t.Fatalf("PID1 agent body error = %v", err)
	}
	wire := independentBootstrapVector()
	wire[0], wire[1], wire[2], wire[3] = 0, 0, 0, 1
	if _, err := DecodeHelperBootstrapBody(wire); !errors.Is(err, ErrHelperBootstrapAgentIdentity) {
		t.Fatalf("PID1 decoded agent body error = %v", err)
	}

	fixture := helperBootstrapStateFixture(t)
	tests := []struct {
		name   string
		mutate func(*HelperBootstrapPreAdmissionExpected)
		want   error
	}{
		{name: "helper is PID1", mutate: func(expected *HelperBootstrapPreAdmissionExpected) { expected.HelperCredential.PID = 1 }, want: ErrHelperBootstrapPeerIdentity},
		{name: "agent is PID1", mutate: func(expected *HelperBootstrapPreAdmissionExpected) {
			expected.AgentCredential.PID = 1
			expected.Bootstrap.AgentPID = 1
		}, want: ErrHelperBootstrapPeerIdentity},
		{name: "helper aliases agent", mutate: func(expected *HelperBootstrapPreAdmissionExpected) {
			expected.HelperCredential.PID = expected.AgentCredential.PID
		}, want: ErrHelperBootstrapRoleIdentityAlias},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			expected := fixture.expected
			test.mutate(&expected)
			if _, err := NewHelperBootstrapPreAdmissionState(expected); !errors.Is(err, test.want) {
				t.Fatalf("constructor error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestHelperBootstrapStateFormattingSerializationAndSeededUnmarshalAreOpaque(t *testing.T) {
	t.Parallel()
	fixture := helperBootstrapStateFixture(t)
	state := newHelperBootstrapState(t, fixture)
	values := []any{
		HelperBootstrapDirectionPID1ToHelper, HelperBootstrapDecisionContinue, HelperBootstrapRightAgentPIDFD,
		fixture.pid1, fixture.pid1Bootstrap(), fixture.expected, HelperBootstrapRight{Kind: HelperBootstrapRightAgentPIDFD, AgentPID: fixture.agent.PID}, state,
	}
	for _, value := range values {
		formatted := fmt.Sprintf("%v %#v %+v %s", value, value, value, value)
		for _, secret := range []string{fixture.expected.Bootstrap.BootGeneration, fixture.expected.Bootstrap.HelperGeneration} {
			if strings.Contains(formatted, secret) {
				t.Fatalf("%T formatting leaked seed", value)
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrHelperBootstrapStateSerialization) {
			t.Fatalf("%T JSON = %v", value, err)
		}
		if marshaler, ok := value.(encoding.TextMarshaler); ok {
			if _, err := marshaler.MarshalText(); !errors.Is(err, ErrHelperBootstrapStateSerialization) {
				t.Fatalf("%T text = %v", value, err)
			}
		}
		if marshaler, ok := value.(encoding.BinaryMarshaler); ok {
			if _, err := marshaler.MarshalBinary(); !errors.Is(err, ErrHelperBootstrapStateSerialization) {
				t.Fatalf("%T binary = %v", value, err)
			}
		}
	}

	seeded := fixture.expected
	want := seeded
	for _, unmarshal := range []func() error{
		func() error { return json.Unmarshal([]byte(`{"AgentPID":1}`), &seeded) },
		func() error { return seeded.UnmarshalText([]byte("seed")) },
		func() error { return seeded.UnmarshalBinary([]byte("seed")) },
	} {
		if err := unmarshal(); !errors.Is(err, ErrHelperBootstrapStateSerialization) {
			t.Fatalf("unmarshal = %v", err)
		}
		if !reflect.DeepEqual(seeded, want) {
			t.Fatal("denied unmarshal mutated receiver")
		}
	}

	direction := HelperBootstrapDirectionPID1ToHelper
	decision := HelperBootstrapDecisionComplete
	rightKind := HelperBootstrapRightAgentPIDFD
	credential := fixture.agent
	right := HelperBootstrapRight{Kind: rightKind, AgentPID: fixture.agent.PID}
	metadata := fixture.pid1Bootstrap()
	for name, test := range map[string]struct {
		pointer any
		before  any
	}{
		"direction":  {&direction, direction},
		"decision":   {&decision, decision},
		"right kind": {&rightKind, rightKind},
		"credential": {&credential, credential},
		"right":      {&right, right},
		"metadata":   {&metadata, metadata},
	} {
		if err := json.Unmarshal([]byte(`{"PID":1}`), test.pointer); !errors.Is(err, ErrHelperBootstrapStateSerialization) {
			t.Errorf("%s JSON unmarshal = %v", name, err)
		}
		if unmarshaler, ok := test.pointer.(encoding.TextUnmarshaler); !ok {
			t.Errorf("%s lacks text unmarshaler", name)
		} else if err := unmarshaler.UnmarshalText([]byte("seed")); !errors.Is(err, ErrHelperBootstrapStateSerialization) {
			t.Errorf("%s text unmarshal = %v", name, err)
		}
		if unmarshaler, ok := test.pointer.(encoding.BinaryUnmarshaler); !ok {
			t.Errorf("%s lacks binary unmarshaler", name)
		} else if err := unmarshaler.UnmarshalBinary([]byte("seed")); !errors.Is(err, ErrHelperBootstrapStateSerialization) {
			t.Errorf("%s binary unmarshal = %v", name, err)
		}
		if after := reflect.ValueOf(test.pointer).Elem().Interface(); !reflect.DeepEqual(after, test.before) {
			t.Errorf("%s denied unmarshal mutated receiver", name)
		}
	}
	beforeDecision := state.Decision()
	if err := json.Unmarshal([]byte(`{"state":null}`), state); !errors.Is(err, ErrHelperBootstrapStateSerialization) {
		t.Fatalf("state JSON unmarshal = %v", err)
	}
	if err := state.UnmarshalText([]byte("seed")); !errors.Is(err, ErrHelperBootstrapStateSerialization) {
		t.Fatalf("state text unmarshal = %v", err)
	}
	if err := state.UnmarshalBinary([]byte("seed")); !errors.Is(err, ErrHelperBootstrapStateSerialization) {
		t.Fatalf("state binary unmarshal = %v", err)
	}
	if state.Decision() != beforeDecision {
		t.Fatal("denied state unmarshal mutated receiver")
	}
}

type helperBootstrapStateTestFixture struct {
	pid1, helper, agent HelperBootstrapKernelCredential
	expected            HelperBootstrapPreAdmissionExpected
	bootstrap           HelperBootstrapBody
	client              ProcessDescriptor
	digest              [sha256.Size]byte
}

func helperBootstrapStateFixture(t *testing.T) helperBootstrapStateTestFixture {
	t.Helper()
	bootstrapExpected := helperBootstrapExpected()
	bootstrap := helperBootstrapFixture()
	client := helperClientDescriptor()
	digest, err := ComputeHelperBootstrapSHA256(helperBootstrapHeader(uint32(len(independentBootstrapVector()))), bootstrap, bootstrapExpected)
	if err != nil {
		t.Fatal(err)
	}
	pid1 := HelperBootstrapKernelCredential{PID: 1, UID: 0, GID: 0}
	helper := HelperBootstrapKernelCredential{PID: 41, UID: 0, GID: 0}
	agent := HelperBootstrapKernelCredential{PID: bootstrap.AgentPID, UID: HelperAgentServiceUID, GID: HelperAgentServiceGID}
	return helperBootstrapStateTestFixture{pid1: pid1, helper: helper, agent: agent, bootstrap: bootstrap, client: client, digest: digest,
		expected: HelperBootstrapPreAdmissionExpected{PID1Credential: pid1, HelperCredential: helper, AgentCredential: agent, Bootstrap: bootstrapExpected, ClientDescriptor: client}}
}

func newHelperBootstrapState(t *testing.T, fixture helperBootstrapStateTestFixture) *HelperBootstrapPreAdmissionState {
	t.Helper()
	state, err := NewHelperBootstrapPreAdmissionState(fixture.expected)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func (f helperBootstrapStateTestFixture) helperToPID1() HelperBootstrapReceiveMetadata {
	return helperBootstrapMetadata(HelperBootstrapDirectionHelperToPID1, f.helper)
}
func (f helperBootstrapStateTestFixture) pid1Bootstrap() HelperBootstrapReceiveMetadata {
	m := helperBootstrapMetadata(HelperBootstrapDirectionPID1ToHelper, f.pid1)
	m.RightsCount = 1
	m.Right = HelperBootstrapRight{Kind: HelperBootstrapRightAgentPIDFD, AgentPID: f.agent.PID}
	return m
}
func (f helperBootstrapStateTestFixture) agentToHelper() HelperBootstrapReceiveMetadata {
	return helperBootstrapMetadata(HelperBootstrapDirectionAgentToHelper, f.agent)
}
func (f helperBootstrapStateTestFixture) helperToAgent() HelperBootstrapReceiveMetadata {
	return helperBootstrapMetadata(HelperBootstrapDirectionHelperToAgent, f.helper)
}
func helperBootstrapMetadata(direction HelperBootstrapDirection, credential HelperBootstrapKernelCredential) HelperBootstrapReceiveMetadata {
	return HelperBootstrapReceiveMetadata{Direction: direction, Credential: credential, CredentialCount: 1}
}
func withHelperBootstrapCredentialCount(m HelperBootstrapReceiveMetadata, count uint32) HelperBootstrapReceiveMetadata {
	m.CredentialCount = count
	return m
}
func withHelperBootstrapCredential(m HelperBootstrapReceiveMetadata, c HelperBootstrapKernelCredential) HelperBootstrapReceiveMetadata {
	m.Credential = c
	return m
}
func withHelperBootstrapRight(m HelperBootstrapReceiveMetadata, count uint32, right HelperBootstrapRight) HelperBootstrapReceiveMetadata {
	m.RightsCount, m.Right = count, right
	return m
}
func withHelperBootstrapTruncation(m HelperBootstrapReceiveMetadata, message, control bool) HelperBootstrapReceiveMetadata {
	m.MessageTruncated, m.ControlTruncated = message, control
	return m
}

func helperBootstrapDatagramFrom(t *testing.T, header credentialprotocol.HelperPacketHeader, body []byte) []byte {
	t.Helper()
	prefix, err := credentialprotocol.EncodeHelperPacketHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	return append(prefix[:], body...)
}
func helperReadyDatagram(t *testing.T) []byte { return helperReadyDatagramAt(t, 0) }
func helperReadyDatagramAt(t *testing.T, sequence uint64) []byte {
	return helperBootstrapDatagramFrom(t, credentialprotocol.HelperPacketHeader{Type: credentialprotocol.PacketTypeHelperReady, Sequence: sequence}, nil)
}
func helperBootstrapDatagram(t *testing.T, body HelperBootstrapBody, expected HelperBootstrapExpected) []byte {
	encoded, err := EncodeHelperBootstrapBody(body)
	if err != nil {
		t.Fatal(err)
	}
	return helperBootstrapDatagramFrom(t, credentialprotocol.HelperPacketHeader{Type: credentialprotocol.PacketTypeBootstrap, BodyLength: uint32(len(encoded)), BootNonce: expected.BootNonce}, encoded)
}
func helperBootstrapAckDatagram(t *testing.T, sequence uint64, digest [32]byte) []byte {
	body, err := EncodeHelperBootstrapAckBody(HelperBootstrapAckBody{BootstrapSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	return helperBootstrapDatagramFrom(t, credentialprotocol.HelperPacketHeader{Type: credentialprotocol.PacketTypeBootstrapAck, Sequence: sequence, BodyLength: uint32(len(body)), BootNonce: filledDigest(0x44)}, body)
}
func helperAgentHelloDatagram(t *testing.T, sequence uint64, f helperBootstrapStateTestFixture, descriptor ProcessDescriptor) []byte {
	body, err := EncodeHelperAgentHelloBody(HelperAgentHelloBody{BootstrapSHA256: f.digest, BootGeneration: f.bootstrap.BootGeneration, HelperGeneration: f.bootstrap.HelperGeneration, Descriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	return helperBootstrapDatagramFrom(t, credentialprotocol.HelperPacketHeader{Type: credentialprotocol.PacketTypeAgentHello, Sequence: sequence, BodyLength: uint32(len(body)), BootNonce: f.expected.Bootstrap.BootNonce}, body)
}
func helperAgentHelloAckDatagram(t *testing.T, sequence uint64, digest [32]byte) []byte {
	body, err := EncodeHelperAgentHelloAckBody(HelperAgentHelloAckBody{BootstrapSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	return helperBootstrapDatagramFrom(t, credentialprotocol.HelperPacketHeader{Type: credentialprotocol.PacketTypeAgentHelloAck, Sequence: sequence, BodyLength: uint32(len(body)), BootNonce: filledDigest(0x44)}, body)
}
func mustAcceptHelperBootstrap(t *testing.T, state *HelperBootstrapPreAdmissionState, metadata HelperBootstrapReceiveMetadata, wire []byte) {
	t.Helper()
	if decision, err := state.Accept(metadata, wire); err != nil || decision == HelperBootstrapDecisionStopVM {
		t.Fatalf("accept = %v/%v", decision, err)
	}
}
func helperBootstrapThroughBootstrap(t *testing.T, state *HelperBootstrapPreAdmissionState, f helperBootstrapStateTestFixture) {
	mustAcceptHelperBootstrap(t, state, f.helperToPID1(), helperReadyDatagram(t))
	mustAcceptHelperBootstrap(t, state, f.pid1Bootstrap(), helperBootstrapDatagram(t, f.bootstrap, f.expected.Bootstrap))
}
func helperBootstrapThroughAck(t *testing.T, state *HelperBootstrapPreAdmissionState, f helperBootstrapStateTestFixture) {
	helperBootstrapThroughBootstrap(t, state, f)
	mustAcceptHelperBootstrap(t, state, f.helperToPID1(), helperBootstrapAckDatagram(t, 1, f.digest))
}
func helperBootstrapThroughHello(t *testing.T, state *HelperBootstrapPreAdmissionState, f helperBootstrapStateTestFixture) {
	helperBootstrapThroughAck(t, state, f)
	mustAcceptHelperBootstrap(t, state, f.agentToHelper(), helperAgentHelloDatagram(t, 1, f, f.client))
}
