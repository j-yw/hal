package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D6FirecrackerFocusedSelectorListsCausalCoverage(t *testing.T) {
	selector := `^(TestL8.*|TestBackendConfigJSONNeverProjectsL8Authority)$`
	command := exec.Command("go", "test", "-list", selector, "./internal/sandboxruntime/microvm/firecracker")
	command.Dir = ".."
	payload, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go test -list %q failed: %v\n%s", selector, err, payload)
	}
	listed := string(payload)
	for _, required := range []string{
		"TestL8DuplicateStartDoesNotCleanupHealthyActiveRuntime",
		"TestL8ConcurrentDuplicateStartCannotEnterUncertainCleanupRoute",
		"TestL8StartValueAndErrorCleansLiveHandleBeforeLease",
		"TestL8ExternalBoundaryPanicsAreContainedAndCleaned",
		"TestL8RetainedCleanupIsReachableFromOriginalTarget",
		"TestL8ConcurrentRetainedCleanupRetryIsSerializedAndIdempotent",
		"TestBackendConfigJSONNeverProjectsL8Authority",
	} {
		if !strings.Contains(listed, required) {
			t.Fatalf("focused selector omits %q:\n%s", required, listed)
		}
	}
	if strings.Contains(listed, "TestL7") {
		t.Fatalf("focused selector unexpectedly lists L7 tests:\n%s", listed)
	}
}

func TestL8D6FirecrackerOverlayFoundationDocumentsTruthfulBoundary(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-d6-firecracker-overlay-foundation-verification.md"))
	for _, required := range []string{
		"Planning-only/default construction remains inert.",
		"L8 authority is omitted from",
		"JSON and runtime target metadata;",
		"positive accepted-profile start path is deliberately unaccepted",
		"Provisional, active, and",
		"cleanup-uncertain ownership are distinct registry states",
		"duplicate Start on a",
		"healthy active runtime is a stable nonmutating rejection",
		"EmbeddedExpectedPinnedCallsiteEvidence",
		"l8_d6_live_firecracker_overlay",
		"dependency_unaccepted",
		"does not add a production fake issuer, synthetic production proof, active L8",
		"they cannot be configured through `BackendOptions` or command wiring.",
		"go test -count=20 ./internal/sandboxruntime/microvm/firecracker",
		"go test -race -count=5 ./internal/sandboxruntime/microvm/firecracker",
		"go test -count=20 ./internal/sandboxruntime/microvm/firecracker -run '^(TestL8.*|TestBackendConfigJSONNeverProjectsL8Authority)$'",
		"go test -race -count=5 ./internal/sandboxruntime/microvm/firecracker -run '^(TestL8.*|TestBackendConfigJSONNeverProjectsL8Authority)$'",
		"GOOS=darwin GOARCH=arm64",
		"GOOS=windows GOARCH=amd64",
		"make build",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 D6 Firecracker overlay verification omits %q", required)
		}
	}
}

func TestL8D6FirecrackerOverlayFoundationStaysOffCommandPaths(t *testing.T) {
	for _, path := range phase34DefaultFirecrackerProductionFiles(t) {
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"L8LiveConfigProvider", "VerifiedL8Profile", "VerifiedL8AssetLease"} {
			if strings.Contains(string(payload), forbidden) {
				t.Fatalf("default production path %s contains L8 authority marker %q", filepath.ToSlash(path), forbidden)
			}
		}
	}
}

func TestL8D6FirecrackerOverlayDependencyGateRemainsExplicitlyRed(t *testing.T) {
	payload := readL8CredentialDeliveryFile(t, filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "l8_accepted_profile_dependency_test.go"))
	for _, required := range []string{
		"//go:build l8_d6_live_firecracker_overlay",
		"TestL8LiveBootConfigAcceptedAuthorityDependencyGate",
		"dependency_unaccepted: truthful D7 HL8E",
		"VerifiedL8Profile/VerifiedL8AssetLease fixture are required",
	} {
		if !strings.Contains(payload, required) {
			t.Fatalf("L8 D6 accepted-profile dependency gate omits %q", required)
		}
	}
}
