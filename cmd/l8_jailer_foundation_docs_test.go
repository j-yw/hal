package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	l8JailerFoundationVerificationDoc = "sandbox-runtime-v2-l8-jailer-foundation-verification.md"
	l8JailerFoundationImplementation  = "c7d471d60a9e960306cce262cda8475569e4fef8"
)

func TestL8JailerFoundationVerificationDocumentation(t *testing.T) {
	doc := readL8JailerFoundationFile(t, filepath.Join("..", "docs", "design", l8JailerFoundationVerificationDoc))
	normalized := strings.Join(strings.Fields(doc), " ")

	for _, required := range []string{
		l8JailerFoundationImplementation,
		"implementation head before the verification-only commits",
		"read-only host inspector",
		"retained-dirfd stager",
		"network-only direct `setns` runner",
		"private strict Jailer lifecycle",
		"private strict Jailer coordinator",
		"one active or cleanup-pending generation",
		"one GiB per staged resource and four GiB in aggregate",
		"only correlated log, metrics, and optional initrd files",
		"rejects network-interface and non-empty entropy configuration",
		"retains exact root authority when staging and initial cleanup both fail",
		"returns a non-nil retry lease only when that rollback is incomplete",
		"Creation-time quarantine removes only exact verified empty directories",
		"Before finalization, cleanup removes only identity-recorded staged entries and quarantines unexpected/unrecorded descendants",
		"recursive deletion of unrecorded Jailer output is reserved for a fully finalized generation",
		"opened directory exact identity/type is verified before any metadata mutation",
		"every recorded intermediate parent and retained file/link authority is revalidated immediately before nested/file mutation",
		"same-UID check-use race remains an explicit dedicated/quiescent UID prerequisite",
		"does not provide durable recovery or live proof",
		"terminal cleanup recursively removes correlated staged content and Jailer-created runtime output without following symlinks",
		"unresolved identity blocks reuse rather than guessing by path",
		"private and in-memory only and does not provide durable crash recovery",
		"retires the exact terminal process record only after terminal root release",
		"closed process completion as terminal proof regardless of exit status",
		"close-on-exec namespace descriptor",
		"canonical JSON field casing",
		"rejects whitespace-bearing or endpoint-overlapping jail paths",
		"prepared initial-user-namespace-root live host",
		"dedicated UID/GID authority",
		"measured executable handoff",
		"post-credential-drop crash containment",
		"expected-runtime-UID vsock readiness",
		"runtime and cgroup resource controls",
		"typed network topology handoff",
		"durable crash reconciliation",
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
	for _, required := range []string{"unix.Setns", "unix.CLONE_NEWNET", "runtime.LockOSThread", "unix.FD_CLOEXEC"} {
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
		"go test -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^Test(InspectStrictJailerHost|OSStrictJailerHostInspection|PlanStrictJailerLaunch|StrictJailer|StageStrictJailerResources|ValidateJailerStagingResources|JailerStaging|LinuxJailer)'",
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

func TestL8JailerFoundationFocusedSelectorIncludesCriticalRegressions(t *testing.T) {
	doc := readL8JailerFoundationFile(t, filepath.Join("..", "docs", "design", l8JailerFoundationVerificationDoc))
	section := l8JailerFoundationSection(t, doc, "## Default fake-safe verification", "## Optional future prepared-Linux acceptance")
	selector := l8JailerFoundationPackageSelector(t, section)
	compiled, err := regexp.Compile(selector)
	if err != nil {
		t.Fatalf("documented Jailer package selector is invalid: %v", err)
	}

	testFiles, err := filepath.Glob(filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "*_test.go"))
	if err != nil || len(testFiles) == 0 {
		t.Fatalf("locate Jailer package tests: files=%d error=%v", len(testFiles), err)
	}
	var source strings.Builder
	for _, testFile := range testFiles {
		source.WriteString(readL8JailerFoundationFile(t, testFile))
	}
	for _, testName := range []string{
		"TestLinuxJailerCreateDirectoryDoesNotMutateUncorrelatedOpenedDirectory",
		"TestLinuxJailerStagingLeaseDetectsReplacementAndFailsCleanupClosed",
		"TestLinuxJailerStagerRejectsReplacedNestedMutationParent",
		"TestLinuxJailerStagerRejectsAliasedFileBeforeMutation",
		"TestLinuxJailerStagerRejectsRenamedFileBeforeMutation",
		"TestLinuxJailerStagerPreFinalizationCleanupPreservesUnrecordedEntries",
		"TestLinuxJailerStagerQuarantinesRuntimeWhenPostMkdirStatCannotBePinned",
		"TestStrictJailerCleanupAuthorityAllowsOnlyRootOrExpectedRuntimeUID",
		"TestStrictJailerHostInspectionErrorsAreSanitized",
		"TestStrictJailerHostInspectionHasNoDurableJSONShape",
		"TestStrictJailerNetworkNamespaceProviderCannotExpressDuplicateDescriptors",
	} {
		if !strings.Contains(source.String(), "func "+testName+"(") {
			t.Fatalf("critical Jailer regression %s no longer exists", testName)
		}
		if !compiled.MatchString(testName) {
			t.Errorf("documented Jailer package selector skips %s", testName)
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
		"retains exact or quarantined directory authority after post-creation checks fail",
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

func l8JailerFoundationPackageSelector(t *testing.T, section string) string {
	t.Helper()
	prefix := "go test -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '"
	start := strings.Index(section, prefix)
	if start < 0 {
		t.Fatalf("Jailer verification section omits focused package command")
	}
	remainder := section[start+len(prefix):]
	end := strings.Index(remainder, "'")
	if end < 0 {
		t.Fatalf("Jailer focused package command omits closing selector quote")
	}
	return remainder[:end]
}

func readL8JailerFoundationFile(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
