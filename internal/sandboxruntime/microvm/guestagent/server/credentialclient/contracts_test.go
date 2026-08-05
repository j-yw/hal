package credentialclient

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

func TestClientTransportAndPolicyMethodSetsAreExact(t *testing.T) {
	t.Parallel()

	assertInterfaceMethods(t, reflect.TypeOf((*Transport)(nil)).Elem(), map[string]string{
		"Close":             "func(context.Context) error",
		"ReceiveController": "func(context.Context, credentialclient.ControllerReceiveRequest) (credentialclient.ControllerPacket, error)",
		"ReceiveHelper":     "func(context.Context, credentialclient.HelperReceiveRequest) (credentialclient.HelperPacket, error)",
		"SendController":    "func(context.Context, credentialclient.ControllerSendPacket) error",
		"SendHelper":        "func(context.Context, credentialclient.HelperSendPacket) error",
	})
	assertInterfaceMethods(t, reflect.TypeOf((*Policy)(nil)).Elem(), map[string]string{
		"Authorize":  "func(credentialclient.ClientPolicyRequest) (credentialclient.ClientPolicyDecision, error)",
		"Descriptor": "func() credentialclient.PolicyDescriptor",
	})
}

func TestClosedClientValuesExposeNoPublicFieldsOrDurableTags(t *testing.T) {
	t.Parallel()

	values := []any{
		ControllerReceiveRequest{}, ControllerPacket{}, ControllerSendPacket{},
		HelperReceiveRequest{}, HelperPacket{}, HelperSendPacket{},
		ClientPolicyRequest{}, ClientPolicyDecision{}, PolicyDescriptor{}, ExtensionPacket{},
	}
	for _, value := range values {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			if field.IsExported() {
				t.Errorf("%s exposes field %s", typeOf, field.Name)
			}
			if field.Tag != "" {
				t.Errorf("%s.%s tag = %q, want none", typeOf, field.Name, field.Tag)
			}
			if field.Type.Kind() == reflect.Int || field.Type.Kind() == reflect.Uintptr || field.Type.Kind() == reflect.UnsafePointer {
				t.Errorf("%s.%s exposes raw descriptor-capable type %s", typeOf, field.Name, field.Type)
			}
			if field.Type == reflect.TypeOf([]byte(nil)) {
				t.Errorf("%s.%s owns a raw byte slice", typeOf, field.Name)
			}
		}
	}
}

func TestPolicyDescriptorUsesExactClientPolicyDigestAndFailsClosed(t *testing.T) {
	t.Parallel()

	descriptor := newClientPolicyDescriptor()
	if got := descriptor.ID(); got != credentialprotocol.SafeID("client-policy-v1") {
		t.Fatalf("ID() = %q, want client-policy-v1", got)
	}
	want := sha256.Sum256(append(opaque16ForTest("hal/l8/process-policy/v1"), opaque16ForTest("client-policy-v1")...))
	if got := descriptor.SHA256(); got != want {
		t.Fatalf("SHA256() = %x, want %x", got, want)
	}
	assertFailsClosed(t, descriptor)

	zero := PolicyDescriptor{}
	if zero.ID() != "" || zero.SHA256() != ([32]byte{}) {
		t.Fatalf("zero descriptor accessors = %q/%x", zero.ID(), zero.SHA256())
	}
	assertFailsClosed(t, zero)
}

func TestClientPolicyDecisionConstructorsAreClosed(t *testing.T) {
	t.Parallel()

	allowed := newClientPolicyAllowDecision()
	if !allowed.allow || allowed.rejectionCode != "" {
		t.Fatalf("allow decision = allow %t rejection %q", allowed.allow, allowed.rejectionCode)
	}
	rejected, err := newClientPolicyRejectionDecision("helper_unavailable")
	if err != nil || rejected.allow || rejected.rejectionCode != "helper_unavailable" {
		t.Fatalf("rejection decision = (%v, %v)", rejected, err)
	}
	for _, invalid := range []credentialprotocol.SafeID{"", "not safe"} {
		decision, err := newClientPolicyRejectionDecision(invalid)
		if !errors.Is(err, ErrClientPolicyDecision) || decision != (ClientPolicyDecision{}) {
			t.Errorf("newClientPolicyRejectionDecision(%q) = (%v, %v), want zero/error", invalid, decision, err)
		}
	}
}

func TestExtensionPacketIsExactSSHAcceptedCapabilityAndOwnershipIsExplicit(t *testing.T) {
	t.Parallel()

	right := &countingRight{}
	metadata := extensionPacketMetadata{
		identityDigest:   [32]byte{1},
		revision:         7,
		bindingIndex:     2,
		ordinal:          3,
		capabilitySHA256: [32]byte{4},
	}
	packet, err := newExtensionPacket(credentialprotocol.PacketTypeSSHAcceptedFD, metadata, right)
	if err != nil {
		t.Fatalf("newExtensionPacket() error = %v", err)
	}
	if packet.packetType != credentialprotocol.PacketTypeSSHAcceptedFD || packet.metadata != metadata {
		t.Fatal("newExtensionPacket() did not preserve authenticated safe metadata")
	}
	if packet.ownership == nil || packet.ownership.capability != right {
		t.Fatal("newExtensionPacket() did not retain the opaque right capability")
	}
	assertFailsClosed(t, packet)

	if err := closeOwnedExtensionPacket(context.Background(), packet); err != nil {
		t.Fatalf("closeOwnedExtensionPacket() error = %v", err)
	}
	if err := closeOwnedExtensionPacket(context.Background(), packet); err != nil {
		t.Fatalf("second closeOwnedExtensionPacket() error = %v", err)
	}
	if got := right.closes.Load(); got != 1 {
		t.Fatalf("right Close calls = %d, want 1", got)
	}

	transferredRight := &countingRight{}
	transferred, err := newExtensionPacket(credentialprotocol.PacketTypeSSHAcceptedFD, metadata, transferredRight)
	if err != nil {
		t.Fatalf("newExtensionPacket(transfer) error = %v", err)
	}
	if err := commitExtensionPacketOwnership(transferred); err != nil {
		t.Fatalf("commitExtensionPacketOwnership() error = %v", err)
	}
	if err := closeOwnedExtensionPacket(context.Background(), transferred); !errors.Is(err, ErrExtensionPacketOwnership) {
		t.Fatalf("close after transfer error = %v, want ErrExtensionPacketOwnership", err)
	}
	if got := transferredRight.closes.Load(); got != 0 {
		t.Fatalf("transferred right Close calls = %d, want 0", got)
	}
}

func TestExtensionPacketFormattingNeverTraversesRightCapability(t *testing.T) {
	t.Parallel()

	const secret = "raw-right-secret-canary"
	packet, err := newExtensionPacket(
		credentialprotocol.PacketTypeSSHAcceptedFD,
		extensionPacketMetadata{identityDigest: [32]byte{1}, revision: 1, ordinal: 1, capabilitySHA256: [32]byte{2}},
		&leakingRight{secret: secret},
	)
	if err != nil {
		t.Fatalf("newExtensionPacket() error = %v", err)
	}
	formats := []string{"%v", "%#v", "%s"}
	for _, format := range formats {
		formatted := fmt.Sprintf(format, packet)
		if strings.Contains(formatted, secret) || !strings.Contains(formatted, "redacted") {
			t.Errorf("ExtensionPacket formatting = %q, want redacted without canary", formatted)
		}
	}
	if encoded, err := json.Marshal(packet); !errors.Is(err, ErrLiveValueSerialization) || strings.Contains(string(encoded), secret) {
		t.Errorf("json.Marshal(ExtensionPacket) = (%q, %v), want fail-closed without canary", encoded, err)
	}
}

func TestExtensionPacketRejectsUnknownCoreAndTypedNilRights(t *testing.T) {
	t.Parallel()

	metadata := extensionPacketMetadata{identityDigest: [32]byte{1}, revision: 1, ordinal: 1, capabilitySHA256: [32]byte{2}}
	var typedNil *countingRight
	tests := []struct {
		name       string
		packetType credentialprotocol.PacketType
		right      extensionRightCapability
		want       error
	}{
		{name: "zero packet", packetType: 0, right: &countingRight{}, want: credentialprotocol.ErrUnknownPacketType},
		{name: "core packet", packetType: credentialprotocol.PacketTypeResponse, right: &countingRight{}, want: ErrExtensionPacketType},
		{name: "nil right", packetType: credentialprotocol.PacketTypeSSHAcceptedFD, right: nil, want: ErrExtensionRightRequired},
		{name: "typed nil right", packetType: credentialprotocol.PacketTypeSSHAcceptedFD, right: typedNil, want: ErrExtensionRightRequired},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			packet, err := newExtensionPacket(test.packetType, metadata, test.right)
			if !errors.Is(err, test.want) || packet.ownership != nil {
				t.Fatalf("newExtensionPacket() = (%v, %v), want zero packet and %v", packet, err, test.want)
			}
		})
	}
}

func TestExtensionPacketSSHBindingAndOrdinalBounds(t *testing.T) {
	t.Parallel()

	base := extensionPacketMetadata{identityDigest: [32]byte{1}, revision: 1, capabilitySHA256: [32]byte{2}}
	for _, test := range []struct {
		name         string
		bindingIndex uint16
		ordinal      uint8
		wantErr      bool
	}{
		{name: "first binding and connection", bindingIndex: 0, ordinal: 1},
		{name: "last binding", bindingIndex: 15, ordinal: 1},
		{name: "last connection", bindingIndex: 0, ordinal: 64},
		{name: "binding plus one", bindingIndex: 16, ordinal: 1, wantErr: true},
		{name: "zero ordinal", bindingIndex: 0, ordinal: 0, wantErr: true},
		{name: "ordinal plus one", bindingIndex: 0, ordinal: 65, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := base
			metadata.bindingIndex = test.bindingIndex
			metadata.ordinal = test.ordinal
			packet, err := newExtensionPacket(credentialprotocol.PacketTypeSSHAcceptedFD, metadata, &countingRight{})
			if test.wantErr {
				if !errors.Is(err, ErrExtensionPacketMetadata) || packet.ownership != nil {
					t.Fatalf("newExtensionPacket() = (%v, %v), want metadata rejection", packet, err)
				}
				return
			}
			if err != nil || packet.metadata != metadata {
				t.Fatalf("newExtensionPacket() = (%v, %v), want success", packet, err)
			}
		})
	}
}

func TestAllClosedTransportAndPolicyValuesFailClosedSerializationAndFormatting(t *testing.T) {
	t.Parallel()

	registry, err := NewExtensionRegistry(ExtensionRegistration{
		Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(),
		Factory:    leakingFactory{secret: "factory-secret-canary"},
	})
	if err != nil {
		t.Fatalf("NewExtensionRegistry() error = %v", err)
	}
	values := []any{
		ExtensionRegistration{Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor(), Factory: leakingFactory{secret: "factory-secret-canary"}},
		ExtensionOpenRequest{Descriptor: credentialprotocol.SSHRelayV1ExtensionDescriptor()},
		registry,
		newControllerReceiveRequest(9, [32]byte{1}),
		newControllerPacket(9, [32]byte{2}),
		newControllerSendPacket(10, [32]byte{3}),
		newHelperReceiveRequest(11, [32]byte{4}),
		newHelperPacket(credentialprotocol.PacketTypeResponse, 11, [32]byte{5}),
		newHelperSendPacket(credentialprotocol.PacketTypeExec, 12, [32]byte{6}),
		newClientPolicyRequest(credentialprotocol.PacketTypeExec, [32]byte{7}, 1, []credentialprotocol.SafeID{"binding-1"}, []credentialprotocol.DeliveryMode{credentialprotocol.DeliveryModeSSHAgent}, credentialprotocol.SSHRelayV1ExtensionDescriptor(), "limits-v1"),
		newClientPolicyAllowDecision(),
	}
	for _, value := range values {
		assertFailsClosed(t, value)
	}
}

func assertFailsClosed(t *testing.T, value any) {
	t.Helper()
	seeded := fmt.Sprintf("top-secret-%T", value)
	jsonBytes, jsonErr := json.Marshal(value)
	if !errors.Is(jsonErr, ErrLiveValueSerialization) {
		t.Errorf("json.Marshal(%T) error = %v, want ErrLiveValueSerialization", value, jsonErr)
	}
	if strings.Contains(string(jsonBytes), seeded) {
		t.Errorf("json.Marshal(%T) exposed seeded data", value)
	}
	textMarshaler, ok := value.(interface{ MarshalText() ([]byte, error) })
	if !ok {
		t.Errorf("%T does not implement fail-closed MarshalText", value)
	} else if text, err := textMarshaler.MarshalText(); !errors.Is(err, ErrLiveValueSerialization) || strings.Contains(string(text), seeded) {
		t.Errorf("MarshalText(%T) = (%q, %v), want empty denial", value, text, err)
	}
	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%O", "%b", "%U"}
	for _, format := range formats {
		formatted := fmt.Sprintf(format, value)
		if strings.Contains(formatted, seeded) || strings.Contains(formatted, "binding-1") || strings.Contains(formatted, "limits-v1") {
			t.Errorf("formatting %T exposed live content: %q", value, formatted)
		}
		if strings.Contains(formatted, "factory-secret-canary") || strings.Contains(formatted, "ssh-relay-v1") {
			t.Errorf("formatting %T traversed registration content: %q", value, formatted)
		}
		if !strings.Contains(formatted, "redacted") {
			t.Errorf("formatting %T = %q, want redacted marker", value, formatted)
		}
	}
}

func opaque16ForTest(value string) []byte {
	result := make([]byte, 2+len(value))
	binary.BigEndian.PutUint16(result[:2], uint16(len(value)))
	copy(result[2:], value)
	return result
}

type countingRight struct {
	closes atomic.Uint32
}

type leakingRight struct {
	secret string
}

func (right *leakingRight) Close(context.Context) error  { return nil }
func (right *leakingRight) String() string               { return right.secret }
func (right *leakingRight) GoString() string             { return right.secret }
func (right *leakingRight) MarshalJSON() ([]byte, error) { return []byte(right.secret), nil }

type leakingFactory struct {
	secret string
}

func (factory leakingFactory) Open(context.Context, ExtensionOpenRequest) (ExtensionSession, error) {
	return staticSession{}, nil
}

func (factory leakingFactory) String() string   { return factory.secret }
func (factory leakingFactory) GoString() string { return factory.secret }

func (right *countingRight) Close(context.Context) error {
	right.closes.Add(1)
	return nil
}
