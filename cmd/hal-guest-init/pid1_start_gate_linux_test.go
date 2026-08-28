//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"
)

func TestL8PID1StartGateAdmitsHelperThenClientBeforeRelease(t *testing.T) {
	fixture := newPID1GuestInitStartGateFixture(t)
	if code := admitPID1StartGate(fixture.expected, fixture.helper, fixture.client); code != 0 {
		t.Fatalf("admitPID1StartGate() = %d, want 0", code)
	}
}

func TestL8PID1StartGateFailsClosedOnZeroAliasMismatchAndOrder(t *testing.T) {
	fixture := newPID1GuestInitStartGateFixture(t)
	tests := []struct {
		name     string
		expected l8composition.PID1StartGateExpected
		helper   l8composition.ProcessDescriptor
		client   l8composition.ProcessDescriptor
	}{
		{
			name: "zero helper digest",
			expected: l8composition.PID1StartGateExpected{
				ClientDescriptorSHA256: fixture.expected.ClientDescriptorSHA256,
				CompositionSHA256:      fixture.expected.CompositionSHA256,
			},
			helper: fixture.helper,
			client: fixture.client,
		},
		{
			name: "zero client digest",
			expected: l8composition.PID1StartGateExpected{
				HelperDescriptorSHA256: fixture.expected.HelperDescriptorSHA256,
				CompositionSHA256:      fixture.expected.CompositionSHA256,
			},
			helper: fixture.helper,
			client: fixture.client,
		},
		{
			name: "zero composition digest",
			expected: l8composition.PID1StartGateExpected{
				HelperDescriptorSHA256: fixture.expected.HelperDescriptorSHA256,
				ClientDescriptorSHA256: fixture.expected.ClientDescriptorSHA256,
			},
			helper: fixture.helper,
			client: fixture.client,
		},
		{
			name: "aliased helper and client digests",
			expected: l8composition.PID1StartGateExpected{
				HelperDescriptorSHA256: fixture.expected.ClientDescriptorSHA256,
				ClientDescriptorSHA256: fixture.expected.ClientDescriptorSHA256,
				CompositionSHA256:      fixture.expected.CompositionSHA256,
			},
			helper: fixture.helper,
			client: fixture.client,
		},
		{
			name:     "client descriptor supplied as helper",
			expected: fixture.expected,
			helper:   fixture.client,
			client:   fixture.helper,
		},
		{
			name:     "helper digest mismatch",
			expected: fixture.expected,
			helper:   xorPID1DescriptorPolicy(fixture.helper),
			client:   fixture.client,
		},
		{
			name:     "client digest mismatch",
			expected: fixture.expected,
			helper:   fixture.helper,
			client:   xorPID1DescriptorPolicy(fixture.client),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if code := admitPID1StartGate(test.expected, test.helper, test.client); code != 127 {
				t.Fatalf("admitPID1StartGate() = %d, want 127", code)
			}
		})
	}
}

func TestL8PID1StartGateSealedExpectedChannelIsMissing(t *testing.T) {
	expected, present, err := loadPID1StartGateExpected()
	if err != nil || present || expected != (l8composition.PID1StartGateExpected{}) {
		t.Fatalf("loadPID1StartGateExpected() = %#v, %t, %v, want absent sealed expected", expected, present, err)
	}
	if code := releasePID1AgentStartGate(); code != 0 {
		t.Fatalf("releasePID1AgentStartGate() = %d, want L7 supervisor continue", code)
	}

	source, err := os.ReadFile("pid1_start_gate_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"go:embed",
		"os.Getenv",
		"os.ReadFile",
		"os.Open",
		"/proc/cmdline",
		"hal_l8_",
		"json.Unmarshal",
		"l8composition.NewHelper",
		"l8composition.NewClient",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("PID1 start-gate loader contains unsigned or live marker %q", forbidden)
		}
	}
	for _, required := range []string{
		"l8composition.NewPID1StartGateState",
		"AcceptHelperDescriptor",
		"AcceptClientDescriptor",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("PID1 start-gate omits %q", required)
		}
	}
}

func TestL8PID1GuestInitReleasesStartGateBeforeChildStart(t *testing.T) {
	source, err := os.ReadFile("main_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	gate := strings.Index(text, "releasePID1AgentStartGate()")
	child := strings.Index(text, "os.StartProcess(")
	if gate < 0 || child < 0 || gate > child {
		t.Fatal("PID1 must consult the start-gate before os.StartProcess")
	}
	if !strings.Contains(text, requireL7NetworkArgument) {
		t.Fatal("L7 --require-l7-network argument was removed")
	}
}

type pid1GuestInitStartGateFixture struct {
	helper   l8composition.ProcessDescriptor
	client   l8composition.ProcessDescriptor
	expected l8composition.PID1StartGateExpected
}

func newPID1GuestInitStartGateFixture(t *testing.T) pid1GuestInitStartGateFixture {
	t.Helper()
	ssh := []credentialprotocol.ExtensionDescriptor{credentialprotocol.SSHRelayV1ExtensionDescriptor()}
	helper := pid1CanonicalDescriptor(t, l8composition.ProcessRoleHelper, ssh)
	client := pid1CanonicalDescriptor(t, l8composition.ProcessRoleClient, ssh)
	composition, err := l8composition.ValidateProcessDescriptors(helper, client)
	if err != nil {
		t.Fatalf("ValidateProcessDescriptors() error = %v", err)
	}
	return pid1GuestInitStartGateFixture{
		helper: helper,
		client: client,
		expected: l8composition.PID1StartGateExpected{
			HelperDescriptorSHA256: composition.HelperSHA256,
			ClientDescriptorSHA256: composition.ClientSHA256,
			CompositionSHA256:      composition.CompositionSHA256,
		},
	}
}

func pid1CanonicalDescriptor(t *testing.T, role l8composition.ProcessRole, extensions []credentialprotocol.ExtensionDescriptor) l8composition.ProcessDescriptor {
	t.Helper()
	policyID := "helper-policy-v1"
	if role == l8composition.ProcessRoleClient {
		policyID = "client-policy-v1"
	}
	return l8composition.ProcessDescriptor{
		ContractVersion: l8composition.ProcessDescriptorContractVersion,
		Role:            role,
		Extensions:      credentialprotocol.CloneExtensionDescriptors(extensions),
		PolicySHA256:    pid1PolicyDigest(policyID),
	}
}

func pid1PolicyDigest(policyID string) [32]byte {
	return sha256.Sum256(append(pid1Opaque16("hal/l8/process-policy/v1"), pid1Opaque16(policyID)...))
}

func pid1Opaque16(value string) []byte {
	encoded := make([]byte, 2, len(value)+2)
	binary.BigEndian.PutUint16(encoded, uint16(len(value)))
	return append(encoded, value...)
}

func xorPID1DescriptorPolicy(descriptor l8composition.ProcessDescriptor) l8composition.ProcessDescriptor {
	descriptor.PolicySHA256[0] ^= 0xff
	return descriptor
}
