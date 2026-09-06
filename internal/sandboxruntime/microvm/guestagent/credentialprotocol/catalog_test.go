package credentialprotocol

import (
	"errors"
	"strings"
	"testing"
)

func TestDeliveryModeCatalogIsClosedAndCanonical(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode DeliveryMode
		wire uint8
		name string
	}{
		{mode: DeliveryModeHTTPProxy, wire: 1, name: "http_proxy"},
		{mode: DeliveryModeFileTmpfs, wire: 2, name: "file_tmpfs"},
		{mode: DeliveryModeSSHAgent, wire: 3, name: "ssh_agent"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := uint8(test.mode); got != test.wire {
				t.Fatalf("wire value = %d, want %d", got, test.wire)
			}
			if got := test.mode.String(); got != test.name {
				t.Fatalf("String() = %q, want %q", got, test.name)
			}
			if err := ValidateDeliveryMode(test.mode); err != nil {
				t.Fatalf("ValidateDeliveryMode() error = %v", err)
			}
		})
	}

	for _, mode := range []DeliveryMode{0, 4, 0xff} {
		if err := ValidateDeliveryMode(mode); !errors.Is(err, ErrUnknownDeliveryMode) {
			t.Fatalf("ValidateDeliveryMode(%d) error = %v, want ErrUnknownDeliveryMode", mode, err)
		}
		if got := mode.String(); got != "unknown" {
			t.Fatalf("DeliveryMode(%d).String() = %q, want unknown", mode, got)
		}
	}
}

func TestPacketTypeCatalogIsClosedAndClassified(t *testing.T) {
	t.Parallel()

	tests := []struct {
		packet    PacketType
		wire      uint8
		name      string
		extension bool
	}{
		{PacketTypeHelperReady, 0x01, "helper_ready", false},
		{PacketTypeBootstrap, 0x02, "bootstrap", false},
		{PacketTypeBootstrapAck, 0x03, "bootstrap_ack", false},
		{PacketTypeAgentHello, 0x04, "agent_hello", false},
		{PacketTypeAgentHelloAck, 0x05, "agent_hello_ack", false},
		{PacketTypePrepareBegin, 0x10, "prepare_begin", false},
		{PacketTypePrepareFile, 0x11, "prepare_file", false},
		{PacketTypePrepareCommit, 0x12, "prepare_commit", false},
		{PacketTypeRenew, 0x13, "renew", false},
		{PacketTypeRevoke, 0x14, "revoke", false},
		{PacketTypeExec, 0x15, "exec", false},
		{PacketTypeSSHAcceptedFD, 0x16, "ssh_accepted_fd", true},
		{PacketTypeExecPrivate, 0x17, "exec_private", false},
		{PacketTypeExecStream, 0x18, "exec_stream", false},
		{PacketTypeExecCredit, 0x19, "exec_credit", false},
		{PacketTypeResponse, 0x20, "response", false},
		{PacketTypeEvent, 0x21, "event", false},
		{PacketTypeCloseNotify, 0x7f, "close_notify", false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := uint8(test.packet); got != test.wire {
				t.Fatalf("wire value = 0x%02x, want 0x%02x", got, test.wire)
			}
			if got := test.packet.String(); got != test.name {
				t.Fatalf("String() = %q, want %q", got, test.name)
			}
			if err := ValidatePacketType(test.packet); err != nil {
				t.Fatalf("ValidatePacketType() error = %v", err)
			}
			if got := test.packet.IsExtension(); got != test.extension {
				t.Fatalf("IsExtension() = %t, want %t", got, test.extension)
			}
			if got := test.packet.IsCore(); got != !test.extension {
				t.Fatalf("IsCore() = %t, want %t", got, !test.extension)
			}
		})
	}

	known := make(map[PacketType]bool, len(tests))
	for _, test := range tests {
		known[test.packet] = true
	}
	for value := 0; value <= 0xff; value++ {
		packet := PacketType(value)
		if known[packet] {
			continue
		}
		if err := ValidatePacketType(packet); !errors.Is(err, ErrUnknownPacketType) {
			t.Fatalf("ValidatePacketType(0x%02x) error = %v, want ErrUnknownPacketType", value, err)
		}
		if packet.IsCore() || packet.IsExtension() {
			t.Fatalf("unknown PacketType(0x%02x) has a catalog classification", value)
		}
	}
}

func TestSafeIDUsesExactCrossPhaseVocabulary(t *testing.T) {
	t.Parallel()

	allowed := []SafeID{
		"a",
		"-",
		"_",
		".",
		"._-Upper9",
		SafeID(strings.Repeat("-._Aa0", 21) + "-."),
	}
	for _, id := range allowed {
		if err := ValidateSafeID(id); err != nil {
			t.Fatalf("ValidateSafeID(%q) error = %v", id, err)
		}
	}

	invalid := []SafeID{"", SafeID(strings.Repeat("a", MaxSafeIDBytes+1)), "credential-邻居"}
	for value := 0; value < 128; value++ {
		if isSafeIDByte(byte(value)) {
			continue
		}
		invalid = append(invalid, SafeID("credential"+string(rune(value))+"neighbor"))
	}
	for _, id := range invalid {
		if err := ValidateSafeID(id); !errors.Is(err, ErrInvalidSafeID) {
			t.Fatalf("ValidateSafeID(%q) error = %v, want ErrInvalidSafeID", id, err)
		}
	}
}

func TestExtensionIDIsSafeAndBounded(t *testing.T) {
	t.Parallel()

	if ExtensionIDSSHRelayV1 != "ssh-relay-v1" {
		t.Fatalf("ExtensionIDSSHRelayV1 = %q", ExtensionIDSSHRelayV1)
	}
	if err := ValidateExtensionID(ExtensionIDSSHRelayV1); err != nil {
		t.Fatalf("ValidateExtensionID() error = %v", err)
	}
	if err := ValidateExtensionID("future-static-v2"); err != nil {
		t.Fatalf("ValidateExtensionID(future static ID) error = %v", err)
	}

	for _, id := range []ExtensionID{
		"",
		"ssh-relay-v1 ",
		ExtensionID(strings.Repeat("a", MaxExtensionIDBytes+1)),
	} {
		if err := ValidateExtensionID(id); !errors.Is(err, ErrInvalidExtensionID) {
			t.Fatalf("ValidateExtensionID(%q) error = %v, want ErrInvalidExtensionID", id, err)
		}
	}
}
