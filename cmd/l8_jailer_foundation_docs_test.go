package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	l8JailerFoundationVerificationDoc = "sandbox-runtime-v2-l8-jailer-foundation-verification.md"
	l8JailerFoundationImplementation  = "64391caec0e9e9503f820cefb00eb3665801a4e5"
)

func TestL8JailerFoundationVerificationDocumentation(t *testing.T) {
	doc := readL8JailerFoundationFile(t, filepath.Join("..", "docs", "design", l8JailerFoundationVerificationDoc))
	normalized := strings.Join(strings.Fields(doc), " ")

	for _, required := range []string{
		l8JailerFoundationImplementation,
		"implementation head before this verification-only commit",
		"read-only host inspector",
		"retained-dirfd stager",
		"network-only direct `setns` runner",
		"private strict Jailer lifecycle",
		"private strict Jailer coordinator",
		"one active or cleanup-pending generation",
		"prepared initial-user-namespace-root live host",
		"dedicated UID/GID authority",
		"measured executable handoff",
		"post-credential-drop crash containment",
		"expected-runtime-UID vsock readiness",
		"bounded Jailer resource and cgroup controls",
		"prepared-Linux acceptance has not run",
		"strict runtime selection remains unchanged and default-off",
		"No L8, HL8E, L10, or L11 claim is made",
		"direct Firecracker compatibility behavior is unchanged",
	} {
		if !strings.Contains(normalized, required) {
			t.Errorf("Jailer foundation verification document omits %q", required)
		}
	}
}

func TestL8JailerFoundationImplementationMarkers(t *testing.T) {
	coordinator := readL8JailerFoundationFile(t, filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "jailer_coordinator.go"))
	coordinator = strings.Join(strings.Fields(coordinator), " ")
	for _, required := range []string{
		"type strictJailerCoordinator struct",
		"func newStrictJailerCoordinator(",
		"strictJailerCoordinatorStartCleanupPending",
		"strictJailerCoordinatorStopCleanupPending",
		"strictJailerCoordinatorRootCleanupPending",
	} {
		if !strings.Contains(coordinator, required) {
			t.Errorf("private Jailer coordinator omits %q", required)
		}
	}

	runner := readL8JailerFoundationFile(t, filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "jailer_namespace_runner.go"))
	runner = strings.Join(strings.Fields(runner), " ")
	linuxRunner := readL8JailerFoundationFile(t, filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "jailer_namespace_runner_linux.go"))
	for _, required := range []string{
		"DuplicateNetworkNamespaceForStrictJailer",
		"networkNamespace *os.File",
		"InheritedFiles: []*os.File{}",
	} {
		if !strings.Contains(runner, required) {
			t.Errorf("private Jailer namespace runner omits %q", required)
		}
	}
	if strings.Contains(runner, "DuplicateUserNamespace") {
		t.Error("private Jailer namespace runner accepts a user namespace descriptor")
	}
	for _, required := range []string{"unix.Setns", "unix.CLONE_NEWNET", "runtime.LockOSThread"} {
		if !strings.Contains(linuxRunner, required) {
			t.Errorf("Linux Jailer namespace runner omits %q", required)
		}
	}
}

func TestL8JailerFoundationDefaultCommandsStayFakeOnly(t *testing.T) {
	doc := readL8JailerFoundationFile(t, filepath.Join("..", "docs", "design", l8JailerFoundationVerificationDoc))
	section := l8JailerFoundationSection(t, doc, "## Default fake-safe verification", "## Optional future prepared-Linux acceptance")
	for _, required := range []string{
		"go test -count=1 ./cmd -run '^TestL8JailerFoundation'",
		"go test -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^Test(InspectStrictJailerHost|OSStrictJailerHostInspection|PlanStrictJailerLaunch|StrictJailerLaunch|StrictJailerLifecycle|StrictJailerNamespaceRunner|StrictJailerOSExecLaunch|StageStrictJailerResources|JailerStaging|LinuxJailerStager|StrictJailerCoordinator)'",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"command -v golangci-lint",
	} {
		if !strings.Contains(section, required) {
			t.Errorf("default fake-safe verification omits %q", required)
		}
	}
	for _, forbidden := range []string{" -tags", "HAL_", "/dev/kvm", "sudo ", "prepared-Linux acceptance passed"} {
		if strings.Contains(section, forbidden) {
			t.Errorf("default fake-safe verification contains live prerequisite %q", forbidden)
		}
	}
}

func TestL8JailerFoundationOptionalAcceptanceRemainsUnaccepted(t *testing.T) {
	doc := readL8JailerFoundationFile(t, filepath.Join("..", "docs", "design", l8JailerFoundationVerificationDoc))
	section := l8JailerFoundationSection(t, doc, "## Optional future prepared-Linux acceptance", "## Non-claims")
	section = strings.Join(strings.Fields(section), " ")
	for _, required := range []string{
		"internal/sandboxruntime/microvm/firecrackerhost/jailer_live_acceptance_test.go",
		"linux && firecracker_live && l8_jailer_live",
		"TestL8JailerPreparedLinuxAcceptance",
		"not present at the implementation head",
		"does not introduce a runnable live command",
		"A skip would not be acceptance evidence",
	} {
		if !strings.Contains(section, required) {
			t.Errorf("optional prepared-Linux section omits %q", required)
		}
	}
}

func TestL8JailerFoundationForbidsPrematureClaims(t *testing.T) {
	doc := readL8JailerFoundationFile(t, filepath.Join("..", "docs", "design", l8JailerFoundationVerificationDoc))
	for _, forbidden := range []string{
		"prepared-Linux acceptance passed",
		"strict Jailer is selected by default",
		"L8 is complete",
		"HL8E is issued",
		"L10 is complete",
		"L11 is complete",
	} {
		if strings.Contains(doc, forbidden) {
			t.Errorf("Jailer foundation verification document contains premature claim %q", forbidden)
		}
	}
}

func l8JailerFoundationSection(t *testing.T, doc, start, end string) string {
	t.Helper()
	startIndex := strings.Index(doc, start)
	if startIndex < 0 {
		t.Fatalf("Jailer foundation verification document omits section %q", start)
	}
	endIndex := strings.Index(doc[startIndex+len(start):], end)
	if endIndex < 0 {
		t.Fatalf("Jailer foundation verification document omits section %q after %q", end, start)
	}
	return doc[startIndex : startIndex+len(start)+endIndex]
}

func readL8JailerFoundationFile(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
