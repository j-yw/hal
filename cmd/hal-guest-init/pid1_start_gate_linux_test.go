//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"
	"golang.org/x/sys/unix"
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
	admitted, code := pid1StartGateRelease()
	if admitted || code != 0 {
		t.Fatalf("pid1StartGateRelease() = %t, %d, want missing FD 15 L7 continue", admitted, code)
	}

	source, err := os.ReadFile("pid1_start_gate_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"go:embed",
		"os.Getenv",
		"os.LookupEnv",
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
		"return l8composition.PID1StartGateExpected{}, false, nil",
		"pid1StartGateHelperFDNumber",
		"pid1StartGateClientFDNumber",
		"DecodeProcessDescriptor",
		"admitPID1StartGate(expected, helper, client)",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("PID1 start-gate omits %q", required)
		}
	}
}

func TestL8PID1StartGateSealedMemfdLoadsExpectedAndAdmits(t *testing.T) {
	fixture := newPID1GuestInitStartGateFixture(t)
	fd := newPID1StartGateTestSealedFD(t, pid1StartGateExpectedJSON(t, fixture.expected))
	withPID1StartGateExpectedFD(t, fd)

	expected, present, err := loadPID1StartGateExpected()
	if err != nil || !present {
		t.Fatalf("loadPID1StartGateExpected() = %#v, %t, %v, want present sealed expected", expected, present, err)
	}
	if expected != fixture.expected {
		t.Fatalf("loaded expected mismatch")
	}
	assertPID1StartGateSourceFDConsumed(t, fd)
	if code := admitPID1StartGate(expected, fixture.helper, fixture.client); code != 0 {
		t.Fatalf("admitPID1StartGate() = %d, want 0", code)
	}
	withPID1StartGateExpectedFD(t, newPID1StartGateTestSealedFD(t, pid1StartGateExpectedJSON(t, fixture.expected)))
	if code := releasePID1AgentStartGate(); code != 127 {
		t.Fatalf("releasePID1AgentStartGate() = %d, want 127 without authenticated descriptors", code)
	}
}

func TestL8PID1StartGateReleaseAdmitsInheritedHelperThenClientDescriptors(t *testing.T) {
	fixture := newPID1GuestInitStartGateFixture(t)
	expectedFD := newPID1StartGateTestSealedFD(t, pid1StartGateExpectedJSON(t, fixture.expected))
	helperFD := newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.helper))
	clientFD := newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.client))
	withPID1StartGateExpectedFD(t, expectedFD)
	withPID1StartGateHelperFD(t, helperFD)
	withPID1StartGateClientFD(t, clientFD)

	admitted, code := pid1StartGateRelease()
	if !admitted || code != 0 {
		t.Fatalf("pid1StartGateRelease() = %t, %d, want admitted helper-then-client", admitted, code)
	}
	assertPID1StartGateSourceFDConsumed(t, expectedFD)
	assertPID1StartGateSourceFDConsumed(t, helperFD)
	assertPID1StartGateSourceFDConsumed(t, clientFD)
}

func TestL8PID1StartGateReleaseFailsClosedWithoutInheritedHelperOrClient(t *testing.T) {
	fixture := newPID1GuestInitStartGateFixture(t)
	tests := []struct {
		name   string
		helper func(*testing.T) int
		client func(*testing.T) int
	}{
		{
			name:   "missing helper",
			helper: newPID1StartGateClosedFD,
			client: func(t *testing.T) int {
				return newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.client))
			},
		},
		{
			name: "missing client",
			helper: func(t *testing.T) int {
				return newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.helper))
			},
			client: newPID1StartGateClosedFD,
		},
		{
			name: "swapped helper and client slots",
			helper: func(t *testing.T) int {
				return newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.client))
			},
			client: func(t *testing.T) int {
				return newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.helper))
			},
		},
		{
			name: "helper digest mismatch",
			helper: func(t *testing.T) int {
				return newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, xorPID1DescriptorPolicy(fixture.helper)))
			},
			client: func(t *testing.T) int {
				return newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.client))
			},
		},
		{
			name: "client digest mismatch",
			helper: func(t *testing.T) int {
				return newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.helper))
			},
			client: func(t *testing.T) int {
				return newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, xorPID1DescriptorPolicy(fixture.client)))
			},
		},
		{
			name: "invalid helper payload",
			helper: func(t *testing.T) int {
				return newPID1StartGateTestSealedFD(t, []byte("not-an-hl8d-descriptor"))
			},
			client: func(t *testing.T) int {
				return newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.client))
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			withPID1StartGateExpectedFD(t, newPID1StartGateTestSealedFD(t, pid1StartGateExpectedJSON(t, fixture.expected)))
			withPID1StartGateHelperFD(t, test.helper(t))
			withPID1StartGateClientFD(t, test.client(t))
			if code := releasePID1AgentStartGate(); code != 127 {
				t.Fatalf("releasePID1AgentStartGate() = %d, want 127", code)
			}
		})
	}
}

func TestL8PID1StartGateClaimedExpectedDuplicationFailureFailsClosed(t *testing.T) {
	fixture := newPID1GuestInitStartGateFixture(t)
	withPID1StartGateExpectedFD(t, newPID1StartGateTestSealedFD(t, pid1StartGateExpectedJSON(t, fixture.expected)))
	withPID1StartGateHelperFD(t, newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.helper)))
	withPID1StartGateClientFD(t, newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.client)))

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	if original.Cur <= pid1StartGateClientFDNumber+1 {
		t.Skip("RLIMIT_NOFILE is already too small for the deterministic duplicate-failure probe")
	}
	limited := original
	limited.Cur = pid1StartGateClientFDNumber + 1
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limited); err != nil {
		t.Fatal(err)
	}
	code := releasePID1AgentStartGate()
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatalf("restore RLIMIT_NOFILE: %v", err)
	}
	if code != 127 {
		t.Fatalf("releasePID1AgentStartGate() = %d, want 127 when a claimed sealed channel cannot be snapshotted", code)
	}
}

func TestL8PID1StartGateMissingExpectedIgnoresInheritedDescriptors(t *testing.T) {
	fixture := newPID1GuestInitStartGateFixture(t)
	expectedFD := newPID1StartGateClosedFD(t)
	helperFD := newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.helper))
	clientFD := newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.client))
	withPID1StartGateExpectedFD(t, expectedFD)
	withPID1StartGateHelperFD(t, helperFD)
	withPID1StartGateClientFD(t, clientFD)

	if code := releasePID1AgentStartGate(); code != 0 {
		t.Fatalf("releasePID1AgentStartGate() = %d, want L7 supervisor continue", code)
	}
	assertPID1StartGateSourceFDConsumed(t, helperFD)
	assertPID1StartGateSourceFDConsumed(t, clientFD)
}

func TestL8PID1StartGateUnsignedHelperDescriptorFailsClosedWhenExpectedPresent(t *testing.T) {
	fixture := newPID1GuestInitStartGateFixture(t)
	payload := pid1StartGateDescriptorBytes(t, fixture.helper)
	path := t.TempDir() + "/pid1-helper.hl8d"
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	helperFD, err := unix.Open(path, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	withPID1StartGateExpectedFD(t, newPID1StartGateTestSealedFD(t, pid1StartGateExpectedJSON(t, fixture.expected)))
	withPID1StartGateHelperFD(t, helperFD)
	withPID1StartGateClientFD(t, newPID1StartGateTestSealedFD(t, pid1StartGateDescriptorBytes(t, fixture.client)))
	if code := releasePID1AgentStartGate(); code != 127 {
		t.Fatalf("releasePID1AgentStartGate() = %d, want 127", code)
	}
	assertPID1StartGateSourceFDProtected(t, helperFD)
}

func TestL8PID1StartGateSealedMemfdAcceptsProcessCompositionFactsJSON(t *testing.T) {
	fixture := newPID1GuestInitStartGateFixture(t)
	fd := newPID1StartGateTestSealedFD(t, pid1StartGateCompositionFactsJSON(t, fixture.expected))
	withPID1StartGateExpectedFD(t, fd)

	expected, present, err := loadPID1StartGateExpected()
	if err != nil || !present || expected != fixture.expected {
		t.Fatalf("loadPID1StartGateExpected() = %#v, %t, %v, want subset copy from L8ProcessCompositionFacts", expected, present, err)
	}
	if code := admitPID1StartGate(expected, fixture.helper, fixture.client); code != 0 {
		t.Fatalf("admitPID1StartGate() = %d, want 0", code)
	}
}

func TestL8PID1StartGateMissingFDRemainsAbsent(t *testing.T) {
	fd, err := unix.MemfdCreate("hal-pid1-start-gate-missing", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	withPID1StartGateExpectedFD(t, fd)

	expected, present, err := loadPID1StartGateExpected()
	if err != nil || present || expected != (l8composition.PID1StartGateExpected{}) {
		t.Fatalf("loadPID1StartGateExpected() = %#v, %t, %v, want absent", expected, present, err)
	}
	if code := releasePID1AgentStartGate(); code != 0 {
		t.Fatalf("releasePID1AgentStartGate() = %d, want L7 supervisor continue", code)
	}
}

func TestL8PID1StartGateUnsignedOrEmptyDescriptorsRemainAbsent(t *testing.T) {
	fixture := newPID1GuestInitStartGateFixture(t)
	payload := pid1StartGateExpectedJSON(t, fixture.expected)

	t.Run("path backed file", func(t *testing.T) {
		path := t.TempDir() + "/pid1-start-gate.json"
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(path, unix.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		withPID1StartGateExpectedFD(t, fd)
		assertPID1StartGateExpectedAbsentAndProtected(t, fd)
	})
	t.Run("empty sealed memfd", func(t *testing.T) {
		fd := newPID1StartGateTestSealedFD(t, nil)
		withPID1StartGateExpectedFD(t, fd)
		assertPID1StartGateExpectedAbsentAndProtected(t, fd)
	})
	t.Run("unsealed memfd", func(t *testing.T) {
		fd, err := unix.MemfdCreate("hal-pid1-start-gate-unsealed", unix.MFD_ALLOW_SEALING)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Write(fd, payload); err != nil {
			t.Fatal(err)
		}
		withPID1StartGateExpectedFD(t, fd)
		assertPID1StartGateExpectedAbsentAndProtected(t, fd)
	})
	t.Run("socket", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fds[1]) })
		withPID1StartGateExpectedFD(t, fds[0])
		assertPID1StartGateExpectedAbsentAndProtected(t, fds[0])
	})
}

func TestL8PID1StartGateMutatedAndZeroDigestsFailClosed(t *testing.T) {
	fixture := newPID1GuestInitStartGateFixture(t)
	helper := hex.EncodeToString(fixture.expected.HelperDescriptorSHA256[:])
	client := hex.EncodeToString(fixture.expected.ClientDescriptorSHA256[:])
	composition := hex.EncodeToString(fixture.expected.CompositionSHA256[:])
	zero := strings.Repeat("0", 64)
	tests := []struct {
		name  string
		facts pid1StartGateSealedFacts
	}{
		{
			name: "zero helper",
			facts: pid1StartGateSealedFacts{
				HelperDescriptorSHA256: zero,
				ClientDescriptorSHA256: client,
				CompositionSHA256:      composition,
			},
		},
		{
			name: "zero client",
			facts: pid1StartGateSealedFacts{
				HelperDescriptorSHA256: helper,
				ClientDescriptorSHA256: zero,
				CompositionSHA256:      composition,
			},
		},
		{
			name: "zero composition",
			facts: pid1StartGateSealedFacts{
				HelperDescriptorSHA256: helper,
				ClientDescriptorSHA256: client,
				CompositionSHA256:      zero,
			},
		},
		{
			name: "aliased helper and client",
			facts: pid1StartGateSealedFacts{
				HelperDescriptorSHA256: client,
				ClientDescriptorSHA256: client,
				CompositionSHA256:      composition,
			},
		},
		{
			name: "uppercase helper",
			facts: pid1StartGateSealedFacts{
				HelperDescriptorSHA256: strings.ToUpper(helper),
				ClientDescriptorSHA256: client,
				CompositionSHA256:      composition,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(test.facts)
			if err != nil {
				t.Fatal(err)
			}
			fd := newPID1StartGateTestSealedFD(t, payload)
			withPID1StartGateExpectedFD(t, fd)
			expected, present, err := loadPID1StartGateExpected()
			if !errors.Is(err, errPID1StartGateExpectedInvalid) || present || expected != (l8composition.PID1StartGateExpected{}) {
				t.Fatalf("loadPID1StartGateExpected() = %#v, %t, %v, want invalid", expected, present, err)
			}
			assertPID1StartGateSourceFDConsumed(t, fd)
			withPID1StartGateExpectedFD(t, newPID1StartGateTestSealedFD(t, payload))
			if code := releasePID1AgentStartGate(); code != 127 {
				t.Fatalf("releasePID1AgentStartGate() = %d, want 127", code)
			}
		})
	}

	mutated := fixture.expected
	mutated.HelperDescriptorSHA256[0] ^= 0xff
	mutatedPayload := pid1StartGateExpectedJSON(t, mutated)
	fd := newPID1StartGateTestSealedFD(t, mutatedPayload)
	withPID1StartGateExpectedFD(t, fd)
	expected, present, err := loadPID1StartGateExpected()
	if err != nil || !present || expected != mutated {
		t.Fatalf("mutated canonical expected load = %#v, %t, %v", expected, present, err)
	}
	if code := admitPID1StartGate(expected, fixture.helper, fixture.client); code != 127 {
		t.Fatalf("admitPID1StartGate() = %d, want 127 on mutated helper digest", code)
	}
	assertPID1StartGateSourceFDConsumed(t, fd)
	withPID1StartGateExpectedFD(t, newPID1StartGateTestSealedFD(t, mutatedPayload))
	if code := releasePID1AgentStartGate(); code != 127 {
		t.Fatalf("releasePID1AgentStartGate() = %d, want 127", code)
	}
}

func TestL8PID1GuestInitReleasesStartGateBeforeChildStart(t *testing.T) {
	source, err := os.ReadFile("main_linux_l7.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	gate := strings.Index(text, "releasePID1AgentStartGate()")
	child := strings.Index(text, "os.StartProcess(")
	if gate < 0 || child < 0 || gate > child {
		t.Fatal("untagged L7 PID1 must consult the start-gate before os.StartProcess")
	}
	shared, err := os.ReadFile("main_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(shared), requireL7NetworkArgument) || !strings.Contains(text, "requireL7NetworkArgument") {
		t.Fatal("L7 --require-l7-network argument was removed")
	}
}

func TestL8ProductionPID1OmitsForkExecAfterAdmit(t *testing.T) {
	source, err := os.ReadFile("main_linux_l8.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "//go:build linux && l8_production_pid1") {
		t.Fatal("L8 production PID1 is missing the ForkExec-omitting build tag")
	}
	if !strings.Contains(text, "pid1StartGateRelease()") {
		t.Fatal("L8 production PID1 must consult the start-gate before supervising")
	}
	if !strings.Contains(text, "superviseAdmittedPID1()") {
		t.Fatal("L8 production PID1 must supervise admitted children without ForkExec")
	}
	for _, forbidden := range []string{
		"os/exec",
		"os.StartProcess",
		"exec.Command",
		"exec.CommandContext",
		"syscall.ForkExec",
		"syscall.StartProcess",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("L8 production PID1 contains ForkExec marker %q", forbidden)
		}
	}
	shared, err := os.ReadFile("main_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	sharedText := string(shared)
	for _, forbidden := range []string{"os/exec", "os.StartProcess", "exec.CommandContext"} {
		if strings.Contains(sharedText, forbidden) {
			t.Fatalf("shared PID1 linux source contains ForkExec marker %q", forbidden)
		}
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

func withPID1StartGateExpectedFD(t *testing.T, fd int) {
	t.Helper()
	previous := pid1StartGateExpectedFD
	pid1StartGateExpectedFD = fd
	t.Cleanup(func() { pid1StartGateExpectedFD = previous })
}

func withPID1StartGateHelperFD(t *testing.T, fd int) {
	t.Helper()
	previous := pid1StartGateHelperFD
	pid1StartGateHelperFD = fd
	t.Cleanup(func() { pid1StartGateHelperFD = previous })
}

func withPID1StartGateClientFD(t *testing.T, fd int) {
	t.Helper()
	previous := pid1StartGateClientFD
	pid1StartGateClientFD = fd
	t.Cleanup(func() { pid1StartGateClientFD = previous })
}

func newPID1StartGateClosedFD(t *testing.T) int {
	t.Helper()
	fd, err := unix.MemfdCreate("hal-pid1-start-gate-closed", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	return fd
}

func pid1StartGateDescriptorBytes(t *testing.T, descriptor l8composition.ProcessDescriptor) []byte {
	t.Helper()
	encoded, err := l8composition.EncodeProcessDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertPID1StartGateExpectedAbsentAndProtected(t *testing.T, fd int) {
	t.Helper()
	expected, present, err := loadPID1StartGateExpected()
	if err != nil || present || expected != (l8composition.PID1StartGateExpected{}) {
		t.Fatalf("loadPID1StartGateExpected() = %#v, %t, %v, want absent", expected, present, err)
	}
	assertPID1StartGateSourceFDProtected(t, fd)
	if code := releasePID1AgentStartGate(); code != 0 {
		t.Fatalf("releasePID1AgentStartGate() = %d, want L7 supervisor continue", code)
	}
}

func assertPID1StartGateSourceFDProtected(t *testing.T, fd int) {
	t.Helper()
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if errors.Is(err, unix.EBADF) {
		return
	}
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("inherited PID1 start-gate fd %d can cross child exec: flags=%d err=%v", fd, flags, err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatalf("close protected PID1 start-gate fd %d: %v", fd, err)
	}
}

func assertPID1StartGateSourceFDConsumed(t *testing.T, fd int) {
	t.Helper()
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("inherited PID1 start-gate fd %d remains open: %v", fd, err)
	}
}

func pid1StartGateExpectedJSON(t *testing.T, expected l8composition.PID1StartGateExpected) []byte {
	t.Helper()
	payload, err := json.Marshal(pid1StartGateSealedFacts{
		HelperDescriptorSHA256: hex.EncodeToString(expected.HelperDescriptorSHA256[:]),
		ClientDescriptorSHA256: hex.EncodeToString(expected.ClientDescriptorSHA256[:]),
		CompositionSHA256:      hex.EncodeToString(expected.CompositionSHA256[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func pid1StartGateCompositionFactsJSON(t *testing.T, expected l8composition.PID1StartGateExpected) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"catalogVersion":         "l8-process-composition-catalog-v1",
		"guestAgentSha256":       strings.Repeat("11", 32),
		"helperDescriptorSha256": hex.EncodeToString(expected.HelperDescriptorSHA256[:]),
		"clientDescriptorSha256": hex.EncodeToString(expected.ClientDescriptorSHA256[:]),
		"compositionSha256":      hex.EncodeToString(expected.CompositionSHA256[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func newPID1StartGateTestSealedFD(t *testing.T, payload []byte) int {
	t.Helper()
	fd, err := unix.MemfdCreate("hal-pid1-start-gate", unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > 0 {
		if _, err := unix.Write(fd, payload); err != nil {
			_ = unix.Close(fd)
			t.Fatal(err)
		}
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, pid1StartGateRequiredSeals); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	readOnly, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), unix.O_RDONLY, 0)
	_ = unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	return readOnly
}
