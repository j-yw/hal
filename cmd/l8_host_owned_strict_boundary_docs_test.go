package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const l8HostOwnedStrictBoundaryDoc = "sandbox-runtime-v2-host-owned-strict-boundary.md"

func TestL8HostOwnedStrictBoundaryDocumentation(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "docs", "design", l8HostOwnedStrictBoundaryDoc))
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Join(strings.Fields(string(payload)), " ")

	for _, required := range []string{
		"3713cddaf7f4d0cb1591093f795fc6e551969cb6",
		"5068151561",
		"5068157402",
		"5068162708",
		"The implementation and prepared-Linux acceptance are not complete",
		"including its kernel, init, helper processes, coding agent, tools, and workspace contents, is untrusted",
		"Firecracker Jailer is mandatory for every strict launch",
		"The Firecracker Jailer closes inherited descriptors before exec",
		"Replacing only the executable would be broken",
		"Firecracker alone is not strict proof, and the Jailer alone is not strict proof",
		"MaxConcurrentSandboxes=1",
		"Each run receives one fresh Firecracker microVM",
		"Rootless Podman remains available for local development and advisory work",
		"direct non-Jailer Firecracker launch may remain only as an explicitly non-strict compatibility or test path",
		"HL8E must remain unissued",
		"No committed slice needs to be reverted before implementation",
		"Remove HL8E from this selection dependency; do not manufacture an HL8E success",
		"Red-first implementation plan",
		"Lock the host launch contract",
		"Implement the smallest Jailer-owned launch seam",
		"immediately before the existing process lifecycle manager",
		"chroot resource staging, live launch, and strict authority remain blocked",
		"Move the strict claim to host evidence",
		"Accept on prepared Linux, then enable selection",
		"go test -count=1 ./cmd -run '^TestL8HostOwnedStrictBoundary'",
		"go test -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^Test(PlanStrictJailerLaunch|StrictJailerLaunch)'",
		"command -v golangci-lint",
		"the honest result is `blocked`",
		"whole-Go syscall verifier",
		"gVisor, Kata Containers",
		"distributed scheduler, worker mTLS, or hardware attestation",
		"multi-tenant UID/cgroup allocator",
		"transparency log, signature framework, or new artifact publisher",
		"Hetzner, Lightsail",
	} {
		if !strings.Contains(doc, required) {
			t.Errorf("host-owned strict-boundary document omits %q", required)
		}
	}
}

func TestL8HostOwnedStrictBoundaryForbidsPrematureClaims(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "docs", "design", l8HostOwnedStrictBoundaryDoc))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(payload)

	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"HL8E is issued",
		"Rootless Podman is strict",
		"direct Firecracker is strict",
		"Jailer is sufficient strict proof",
		"prepared-Linux acceptance passed",
	} {
		if strings.Contains(doc, forbidden) {
			t.Errorf("host-owned strict-boundary document contains premature claim %q", forbidden)
		}
	}
}
