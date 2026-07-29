package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL5ArchitectureContainsMandatoryPhaseSections(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l5-firecracker-vsock-architecture.md"))
	if err != nil {
		t.Fatalf("read L5 architecture: %v", err)
	}
	text := string(data)
	for _, required := range []string{
		"## 1. Inputs, outputs, states, and failure codes",
		"## 2. Package ownership and import boundaries",
		"## 3. Durable and machine-contract schema changes",
		"## 4. Redaction and containment rules",
		"## 5. Crash, retry, cancellation, and cleanup semantics",
		"## 6. Red-first fake and live acceptance tests",
		"## 7. Non-goals and L6 handoff",
		"API-socket availability and UDS existence",
		"OK <assignedHostPort>",
		"`VMADDR_PORT_ANY` (`4294967295`)",
		"`1..4294967294`",
		"`SO_PEERCRED`",
		"private in-memory live-session registry",
		"not caller-carried",
		"daemon-wide and lifecycle-only",
		"synthetic",
		"TERM with a bounded grace deadline",
		"KILL",
		"wait/reap",
		`"boot_args": "console=ttyS0 reboot=k panic=1 pci=off nomodule ro root=/dev/vda rootfstype=ext4 rootwait init=/sbin/init"`,
		`"is_read_only": true`,
		`"guest_cid": 3`,
		"`BR2_DOWNLOAD_FORCE_CHECK_HASHES=y`",
		"`CONFIG_HYPERVISOR_GUEST=y`",
		"`CONFIG_PARAVIRT=y`",
		"`CONFIG_KVM_GUEST=y`",
		"`CONFIG_DEVTMPFS_MOUNT` disabled",
		"BusyBox `1.38.0`",
		"util-linux `setpriv`",
		"`BR2_PACKAGE_UTIL_LINUX_SETPRIV=y`",
		"`--reuid`",
		"`--regid`",
		"`--clear-groups`",
		"`--no-new-privs`",
		"e2fsprogs `1.47.4`",
		"Go `1.25.7`",
		"registry.gitlab.com/buildroot.org/buildroot/base@sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6",
		"fixed ext4 UUID",
		"`-trimpath`, `-buildvcs=false`, an empty Go build ID",
		"wrong-process, wrong-state, wrong-inode",
		"post-cleanup reconnect rejection",
		"non-Linux build-tagged stub",
		"Once selected it never skips",
		"L5 does not implement policy proxying",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("L5 architecture missing %q", required)
		}
	}
}

func TestL5VerificationLocksLiveSelectorAndBroadGates(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l5-firecracker-vsock-verification.md"))
	if err != nil {
		t.Fatalf("read L5 verification: %v", err)
	}
	text := string(data)
	for _, required := range []string{
		"TestL5PreparedLinuxFirecrackerVsockE2E",
		"TestL5PreparedLinuxImagePrerequisites",
		"l5_firecracker_vsock_integration",
		"HAL_L5_DISTRIBUTION_DIR",
		"7e8b57e88c459396d4680d83dcdd8c7f72305447cb55b11f4ac98ad70a3f7825",
		"bounded workspace tmpfs",
		"process-group cleanup before teardown",
		"independently probed guest-agent failure",
		"POLLRDHUP",
		"POLLHUP",
		"must not skip",
		"regular util-linux binary",
		"non-executing inspection",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"GOOS=darwin GOARCH=amd64",
		"GOOS=windows GOARCH=amd64",
		"golangci-lint run --new-from-rev 762ee1a61d2efc5bb9241a6e87409ca20d68f976 ./...",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("L5 verification missing %q", required)
		}
	}
}

func TestL5PreparedLinuxAcceptanceLocksIndependentProofAndCleanup(t *testing.T) {
	path := filepath.Join(
		"..",
		"internal",
		"sandboxruntime",
		"microvm",
		"firecrackerhost",
		"l5_prepared_linux_e2e_test.go",
	)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read L5 prepared-Linux acceptance: %v", err)
	}
	source := string(data)
	for _, required := range []string{
		"l5FirecrackerBinarySHA256",
		"scratchFirecracker",
		"scratchKernel",
		"l5MountSizeAtMost",
		"l5GuestReadinessGate",
		"assertL5PreparedProcessGroupGone",
		"newFirecrackerVsockTransport",
		"killAndWaitAll",
		`os.MkdirTemp("", "hal-l5-vsock-e2e-")`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("L5 prepared-Linux acceptance missing %q", required)
		}
	}
	for _, forbidden := range []string{"t.Skip(", "t.Skipf(", "testing.Short()"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("L5 prepared-Linux acceptance contains forbidden skip marker %q", forbidden)
		}
	}
}

func TestL5GuestTransportLocksFullPeerCloseCancellation(t *testing.T) {
	paths := []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "vsock", "transport.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "vsock", "listener_linux.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "vsock", "listener_linux_test.go"),
	}
	var source strings.Builder
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read L5 guest transport peer-close source: %v", err)
		}
		source.Write(data)
	}
	for _, required := range []string{
		"WaitPeerClosed",
		"cancelHandler",
		"unix.POLLHUP",
		"TestL5LinuxConnectionDistinguishesPeerHalfCloseFromFullClose",
	} {
		if !strings.Contains(source.String(), required) {
			t.Fatalf("L5 guest transport peer-close cancellation missing %q", required)
		}
	}
}
