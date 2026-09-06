package l8composition

import (
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestPID1StartGateReleasesOnlyAfterCanonicalHelperThenClientValidation(t *testing.T) {
	t.Parallel()

	fixture := pid1StartGateFixture(t)
	state := newPID1StartGateState(t, fixture.expected)
	if composition, ok := state.Composition(); ok || composition != (CompositionDescriptor{}) || state.Decision() != PID1StartGateDecisionContinue {
		t.Fatalf("new start gate composition = (%#v, %t) decision = %v", composition, ok, state.Decision())
	}

	helper := cloneProcessDescriptor(fixture.helper)
	decision, err := state.AcceptHelperDescriptor(helper)
	if err != nil || decision != PID1StartGateDecisionContinue || state.Decision() != PID1StartGateDecisionContinue {
		t.Fatalf("AcceptHelperDescriptor() = %v, %v", decision, err)
	}
	helper.Extensions[0].Modes[0] = credentialprotocol.DeliveryModeHTTPProxy
	if composition, ok := state.Composition(); ok || composition != (CompositionDescriptor{}) {
		t.Fatal("helper-only start gate released composition")
	}

	client := cloneProcessDescriptor(fixture.client)
	decision, err = state.AcceptClientDescriptor(client)
	if err != nil || decision != PID1StartGateDecisionRelease || state.Decision() != PID1StartGateDecisionRelease {
		t.Fatalf("AcceptClientDescriptor() = %v, %v", decision, err)
	}
	client.Extensions[0].Modes[0] = credentialprotocol.DeliveryModeFileTmpfs

	composition, ok := state.Composition()
	if !ok || composition != fixture.composition {
		t.Fatalf("Composition() = %#v, %t, want exact canonical composition", composition, ok)
	}
	state.owner.mu.Lock()
	helperBody := state.owner.helper
	helperWire := append([]byte(nil), state.owner.helperWire...)
	clientBody := state.owner.client
	clientWire := append([]byte(nil), state.owner.clientWire...)
	state.owner.mu.Unlock()
	if helperBody.ContractVersion != "" || helperBody.Role != 0 || len(helperBody.Extensions) != 0 ||
		clientBody.ContractVersion != "" || clientBody.Role != 0 || len(clientBody.Extensions) != 0 ||
		len(helperWire) != 0 || len(clientWire) != 0 {
		t.Fatal("PID1 start gate retained descriptor bodies after release")
	}

	copyValue := *state
	decision, err = copyValue.AcceptHelperDescriptor(fixture.helper)
	if decision != PID1StartGateDecisionStopVM || !errors.Is(err, ErrPID1StartGateReleased) || state.Decision() != PID1StartGateDecisionStopVM {
		t.Fatalf("packet after release = %v, %v", decision, err)
	}
}

func TestPID1StartGateConstructorRejectsZeroAndAliasedSealedDigests(t *testing.T) {
	t.Parallel()

	fixture := pid1StartGateFixture(t)
	tests := []struct {
		name   string
		mutate func(*PID1StartGateExpected)
		want   error
	}{
		{name: "zero helper", mutate: func(expected *PID1StartGateExpected) { expected.HelperDescriptorSHA256 = [32]byte{} }, want: ErrPID1StartGateDigestZero},
		{name: "zero client", mutate: func(expected *PID1StartGateExpected) { expected.ClientDescriptorSHA256 = [32]byte{} }, want: ErrPID1StartGateDigestZero},
		{name: "zero composition", mutate: func(expected *PID1StartGateExpected) { expected.CompositionSHA256 = [32]byte{} }, want: ErrPID1StartGateDigestZero},
		{name: "helper aliases client", mutate: func(expected *PID1StartGateExpected) {
			expected.HelperDescriptorSHA256 = expected.ClientDescriptorSHA256
		}, want: ErrPID1StartGateDigestAlias},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			expected := fixture.expected
			test.mutate(&expected)
			state, err := NewPID1StartGateState(expected)
			if state != nil || !errors.Is(err, test.want) {
				t.Fatalf("NewPID1StartGateState() = (%v, %v), want nil/%v", state, err, test.want)
			}
		})
	}
}

func TestPID1StartGateFailsClosedOnRoleOrderDuplicatesAndMismatches(t *testing.T) {
	t.Parallel()

	fixture := pid1StartGateFixture(t)
	emptyHelper := canonicalDescriptor(t, ProcessRoleHelper, nil)
	emptyClient := canonicalDescriptor(t, ProcessRoleClient, nil)
	emptyComposition, err := ValidateProcessDescriptors(emptyHelper, emptyClient)
	if err != nil {
		t.Fatal(err)
	}
	wrongPolicy := replacePolicy(fixture.helper, xorDigest(fixture.helper.PolicySHA256))
	mismatchedClient := canonicalDescriptor(t, ProcessRoleClient, nil)
	tests := []struct {
		name    string
		prepare func(*PID1StartGateState)
		accept  func(*PID1StartGateState) (PID1StartGateDecision, error)
		want    error
	}{
		{
			name: "client before helper",
			accept: func(state *PID1StartGateState) (PID1StartGateDecision, error) {
				return state.AcceptClientDescriptor(fixture.client)
			},
			want: ErrPID1StartGateRoleOrder,
		},
		{
			name: "helper role is client",
			accept: func(state *PID1StartGateState) (PID1StartGateDecision, error) {
				return state.AcceptHelperDescriptor(fixture.client)
			},
			want: ErrPID1StartGateRole,
		},
		{
			name: "duplicate helper",
			prepare: func(state *PID1StartGateState) {
				mustAcceptPID1Helper(t, state, fixture.helper)
			},
			accept: func(state *PID1StartGateState) (PID1StartGateDecision, error) {
				return state.AcceptHelperDescriptor(fixture.helper)
			},
			want: ErrPID1StartGateTransition,
		},
		{
			name: "helper digest mismatch",
			accept: func(state *PID1StartGateState) (PID1StartGateDecision, error) {
				return state.AcceptHelperDescriptor(wrongPolicy)
			},
			want: ErrPID1StartGateDigestMismatch,
		},
		{
			name: "client role is helper",
			prepare: func(state *PID1StartGateState) {
				mustAcceptPID1Helper(t, state, fixture.helper)
			},
			accept: func(state *PID1StartGateState) (PID1StartGateDecision, error) {
				return state.AcceptClientDescriptor(fixture.helper)
			},
			want: ErrPID1StartGateRole,
		},
		{
			name: "client digest mismatch",
			prepare: func(state *PID1StartGateState) {
				mustAcceptPID1Helper(t, state, fixture.helper)
			},
			accept: func(state *PID1StartGateState) (PID1StartGateDecision, error) {
				return state.AcceptClientDescriptor(mismatchedClient)
			},
			want: ErrPID1StartGateDigestMismatch,
		},
		{
			name: "extension set mismatch after sealed digests",
			prepare: func(state *PID1StartGateState) {
				replaced := newPID1StartGateState(t, PID1StartGateExpected{
					HelperDescriptorSHA256: digestProcessDescriptor(t, fixture.helper),
					ClientDescriptorSHA256: digestProcessDescriptor(t, mismatchedClient),
					CompositionSHA256:      fixture.composition.CompositionSHA256,
				})
				*state = *replaced
				mustAcceptPID1Helper(t, state, fixture.helper)
			},
			accept: func(state *PID1StartGateState) (PID1StartGateDecision, error) {
				return state.AcceptClientDescriptor(mismatchedClient)
			},
			want: credentialprotocol.ErrExtensionSetMismatch,
		},
		{
			name: "policy mismatch after sealed digests",
			prepare: func(state *PID1StartGateState) {
				replaced := newPID1StartGateState(t, PID1StartGateExpected{
					HelperDescriptorSHA256: digestProcessDescriptor(t, wrongPolicy),
					ClientDescriptorSHA256: fixture.expected.ClientDescriptorSHA256,
					CompositionSHA256:      fixture.composition.CompositionSHA256,
				})
				*state = *replaced
				mustAcceptPID1Helper(t, state, wrongPolicy)
			},
			accept: func(state *PID1StartGateState) (PID1StartGateDecision, error) {
				return state.AcceptClientDescriptor(fixture.client)
			},
			want: ErrProcessDescriptorPolicy,
		},
		{
			name: "empty matching extensions are not production SSH",
			prepare: func(state *PID1StartGateState) {
				replaced := newPID1StartGateState(t, PID1StartGateExpected{
					HelperDescriptorSHA256: emptyComposition.HelperSHA256,
					ClientDescriptorSHA256: emptyComposition.ClientSHA256,
					CompositionSHA256:      emptyComposition.CompositionSHA256,
				})
				*state = *replaced
				mustAcceptPID1Helper(t, state, emptyHelper)
			},
			accept: func(state *PID1StartGateState) (PID1StartGateDecision, error) {
				return state.AcceptClientDescriptor(emptyClient)
			},
			want: ErrPID1StartGateRegistration,
		},
		{
			name: "sealed composition mismatch",
			prepare: func(state *PID1StartGateState) {
				expected := fixture.expected
				expected.CompositionSHA256 = xorDigest(expected.CompositionSHA256)
				replaced := newPID1StartGateState(t, expected)
				*state = *replaced
				mustAcceptPID1Helper(t, state, fixture.helper)
			},
			accept: func(state *PID1StartGateState) (PID1StartGateDecision, error) {
				return state.AcceptClientDescriptor(fixture.client)
			},
			want: ErrPID1StartGateCompositionMismatch,
		},
		{
			name: "noncanonical helper contract",
			accept: func(state *PID1StartGateState) (PID1StartGateDecision, error) {
				return state.AcceptHelperDescriptor(replaceContract(fixture.helper, "secret-canary /tmp/private.sock"))
			},
			want: ErrProcessDescriptorContract,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := newPID1StartGateState(t, fixture.expected)
			if test.prepare != nil {
				test.prepare(state)
			}
			decision, err := test.accept(state)
			if decision != PID1StartGateDecisionStopVM || !errors.Is(err, test.want) {
				t.Fatalf("decision/error = %v, %v, want StopVM/%v", decision, err, test.want)
			}
			if state.Decision() != PID1StartGateDecisionStopVM {
				t.Fatal("failed start gate did not latch stop-VM")
			}
			if composition, ok := state.Composition(); ok || composition != (CompositionDescriptor{}) {
				t.Fatal("failed start gate published composition")
			}
			if strings.Contains(fmt.Sprint(err), "secret-canary") || strings.Contains(fmt.Sprint(err), "/tmp/private.sock") {
				t.Fatalf("start-gate error leaked seeded material: %v", err)
			}
			decision, err = state.AcceptClientDescriptor(fixture.client)
			if decision != PID1StartGateDecisionStopVM || !errors.Is(err, ErrPID1StartGateTerminal) {
				t.Fatalf("retry after failure = %v, %v", decision, err)
			}
		})
	}
}

func TestPID1StartGateNilLostAndDeniedSerializationStayFailClosed(t *testing.T) {
	t.Parallel()

	var state *PID1StartGateState
	if decision, err := state.AcceptHelperDescriptor(ProcessDescriptor{}); decision != PID1StartGateDecisionStopVM || !errors.Is(err, ErrPID1StartGateTerminal) {
		t.Fatalf("nil helper accept = %v, %v", decision, err)
	}
	if decision, err := state.AcceptClientDescriptor(ProcessDescriptor{}); decision != PID1StartGateDecisionStopVM || !errors.Is(err, ErrPID1StartGateTerminal) {
		t.Fatalf("nil client accept = %v, %v", decision, err)
	}
	if state.Lost() != PID1StartGateDecisionStopVM || state.Decision() != PID1StartGateDecisionStopVM {
		t.Fatal("nil Lost/Decision did not require stop-VM")
	}

	fixture := pid1StartGateFixture(t)
	live := newPID1StartGateState(t, fixture.expected)
	mustAcceptPID1Helper(t, live, fixture.helper)
	if live.Lost() != PID1StartGateDecisionStopVM || live.Decision() != PID1StartGateDecisionStopVM {
		t.Fatal("Lost did not permanently stop the start gate")
	}
	if composition, ok := live.Composition(); ok || composition != (CompositionDescriptor{}) {
		t.Fatal("Lost published composition")
	}

	expected := fixture.expected
	expected.HelperDescriptorSHA256[0] = 0x42
	values := []any{
		PID1StartGateDecisionContinue,
		expected,
		live,
	}
	for _, value := range values {
		formatted := fmt.Sprintf("%v %#v %+v %s", value, value, value, value)
		if strings.Contains(formatted, "secret-canary") || !strings.Contains(formatted, "PID1StartGate") {
			t.Fatalf("%T formatting = %q, want opaque type name", value, formatted)
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrPID1StartGateSerialization) {
			t.Fatalf("%T JSON = %v", value, err)
		}
		if marshaler, ok := value.(encoding.TextMarshaler); ok {
			if _, err := marshaler.MarshalText(); !errors.Is(err, ErrPID1StartGateSerialization) {
				t.Fatalf("%T text = %v", value, err)
			}
		}
		if marshaler, ok := value.(encoding.BinaryMarshaler); ok {
			if _, err := marshaler.MarshalBinary(); !errors.Is(err, ErrPID1StartGateSerialization) {
				t.Fatalf("%T binary = %v", value, err)
			}
		}
	}

	before := live.Decision()
	if err := json.Unmarshal([]byte(`{"CompositionSHA256":"seed"}`), live); !errors.Is(err, ErrPID1StartGateSerialization) {
		t.Fatalf("state JSON unmarshal = %v", err)
	}
	if err := live.UnmarshalText([]byte("seed")); !errors.Is(err, ErrPID1StartGateSerialization) {
		t.Fatalf("state text unmarshal = %v", err)
	}
	if err := live.UnmarshalBinary([]byte("seed")); !errors.Is(err, ErrPID1StartGateSerialization) {
		t.Fatalf("state binary unmarshal = %v", err)
	}
	if live.Decision() != before {
		t.Fatal("denied unmarshal mutated start-gate state")
	}
	if err := json.Unmarshal([]byte(`{"HelperDescriptorSHA256":"seed"}`), &expected); !errors.Is(err, ErrPID1StartGateSerialization) {
		t.Fatalf("expected JSON unmarshal = %v", err)
	}
}

func TestPID1StartGateCatalogAndClosedDecisionValuesAreExact(t *testing.T) {
	t.Parallel()

	if PID1StartGateDecisionContinue != 1 || PID1StartGateDecisionRelease != 2 || PID1StartGateDecisionStopVM != 3 {
		t.Fatal("PID1 start-gate decision catalog changed")
	}
	expectedType := reflect.TypeOf(PID1StartGateExpected{})
	if expectedType.NumField() != 3 {
		t.Fatalf("PID1StartGateExpected fields = %d, want 3 sealed digests", expectedType.NumField())
	}
	want := []string{"HelperDescriptorSHA256", "ClientDescriptorSHA256", "CompositionSHA256"}
	for index, name := range want {
		field := expectedType.Field(index)
		if field.Name != name || field.Type.String() != "[32]uint8" || field.Tag != "" {
			t.Fatalf("field %d = %s %s %q", index, field.Name, field.Type, field.Tag)
		}
	}
}

type pid1StartGateTestFixture struct {
	helper      ProcessDescriptor
	client      ProcessDescriptor
	composition CompositionDescriptor
	expected    PID1StartGateExpected
}

func pid1StartGateFixture(t *testing.T) pid1StartGateTestFixture {
	t.Helper()
	ssh := []credentialprotocol.ExtensionDescriptor{credentialprotocol.SSHRelayV1ExtensionDescriptor()}
	helper := canonicalDescriptor(t, ProcessRoleHelper, ssh)
	client := canonicalDescriptor(t, ProcessRoleClient, ssh)
	composition, err := ValidateProcessDescriptors(helper, client)
	if err != nil {
		t.Fatalf("ValidateProcessDescriptors() error = %v", err)
	}
	return pid1StartGateTestFixture{
		helper:      helper,
		client:      client,
		composition: composition,
		expected: PID1StartGateExpected{
			HelperDescriptorSHA256: composition.HelperSHA256,
			ClientDescriptorSHA256: composition.ClientSHA256,
			CompositionSHA256:      composition.CompositionSHA256,
		},
	}
}

func newPID1StartGateState(t *testing.T, expected PID1StartGateExpected) *PID1StartGateState {
	t.Helper()
	state, err := NewPID1StartGateState(expected)
	if err != nil {
		t.Fatalf("NewPID1StartGateState() error = %v", err)
	}
	if state == nil {
		t.Fatal("NewPID1StartGateState() returned nil state")
	}
	return state
}

func mustAcceptPID1Helper(t *testing.T, state *PID1StartGateState, descriptor ProcessDescriptor) {
	t.Helper()
	decision, err := state.AcceptHelperDescriptor(descriptor)
	if err != nil || decision != PID1StartGateDecisionContinue {
		t.Fatalf("AcceptHelperDescriptor() = %v, %v", decision, err)
	}
}

func digestProcessDescriptor(t *testing.T, descriptor ProcessDescriptor) [32]byte {
	t.Helper()
	encoded, err := EncodeProcessDescriptor(descriptor)
	if err != nil {
		t.Fatalf("EncodeProcessDescriptor() error = %v", err)
	}
	return sha256.Sum256(encoded)
}

func xorDigest(value [32]byte) [32]byte {
	value[0] ^= 0xff
	return value
}
