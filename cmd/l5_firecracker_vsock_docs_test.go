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
		"l5_firecracker_vsock_integration",
		"must not skip",
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
