package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phase46FinalFakeOnlyDocPath = "sandbox-runtime-v2-phase46-final-fake-only-verification.md"

func TestPhase46FinalFakeOnlyVerificationDocumentation(t *testing.T) {
	doc := readPhase46FinalFakeOnlyDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 46 final verification barrier is fake-only and default-safe.",
		"credential delivery activation contracts",
		"fake activation adapters",
		"fail-closed downgrade rules",
		"sanitized command/factory projection",
		"runtime and worker metadata redaction guards",
		"import-boundary guards",
		"optional live-harness gate",
		"Phase 46 records the default-safe credential delivery matrix without making secure credential delivery generally available.",
		"Secure default selection/gating is Phase 48 and is not part of Phase 46.",
		"Template acquisition is Phase 47 and is not implemented by Phase 46.",
		"No story implementation or documentation requires running `hal run`.",
		"Passing this matrix satisfies the Phase 46 fake-only checks and typecheck gate.",
		"Phase 47 owns template acquisition.",
		"Phase 48 owns secure default selection/gating.",
		"`credential_delivery_live`",
		"`HAL_CREDENTIAL_DELIVERY_LIVE`",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 46 final fake-only verification documentation missing %q", want)
		}
	}

	phase46FinalAssertDocumentedCommands(t, doc)
	phase46FinalAssertNoHalRunCommand(t, doc)
}

func TestPhase46FinalDefaultSafeCredentialDeliveryMatrix(t *testing.T) {
	doc := readPhase46FinalFakeOnlyDoc(t)
	requiredRows := []string{
		"| `http_proxy` | Fake activation can report active only when sanitized credential proxy, secret broker, network proxy, and Phase 45 network-enforcement proof metadata correlate through an injected adapter. | No default active delivery; missing proof, missing adapter, or uncorrelated metadata is skipped or plan-only. | No live proxy credential injection, live upstream proxying, secure default selection, or default gating. |",
		"| `file_tmpfs` | Fake activation can report sanitized active metadata for explicit test fixtures. | No default active delivery; without an injected fake adapter it is skipped or plan-only. | No tmpfs mount, file write, guest file injection, secure default selection, or default gating. |",
		"| `ssh_agent` | Fake activation can report sanitized active metadata for explicit test fixtures. | No default active delivery; without an injected fake adapter it is skipped or plan-only. | No SSH-agent forwarding, `SSH_AUTH_SOCK` dependency, secure default selection, or default gating. |",
		"| `env` | Fake activation can report sanitized active metadata for explicit test fixtures. | No default active delivery; without an injected fake adapter it is skipped or plan-only. | No environment mutation, environment secret injection, secure default selection, or default gating. |",
		"| `legacy_auth_sync` | Compatibility metadata remains requested/skipped metadata with a compatibility warning. | Never projected as an active secure credential delivery mode. | No secure delivery proof, no default active delivery, no secure default selection, or default gating. |",
	}
	for _, row := range requiredRows {
		if !strings.Contains(doc, row) {
			t.Fatalf("phase 46 final default-safe matrix missing row %q", row)
		}
	}
}

func TestPhase46FinalFakeOnlyVerificationCommandsStayDefaultSafe(t *testing.T) {
	doc := readPhase46FinalFakeOnlyDoc(t)
	commands := phase46FinalDefaultGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 46 final verification documentation must list default go test commands")
	}

	for _, command := range commands {
		for _, forbidden := range append(phase34ForbiddenDefaultFocusedCommandRequirements(), phase46FinalForbiddenDefaultMarkers()...) {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 46 final default command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase46FinalAssertFocusedVerificationCoversRequiredSelectors(t, doc)
}

func readPhase46FinalFakeOnlyDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", phase46FinalFakeOnlyDocPath))
	if err != nil {
		t.Fatalf("ReadFile(phase 46 final fake-only verification doc) error = %v", err)
	}
	return string(data)
}

func phase46FinalAssertDocumentedCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 ./internal/credentialdelivery",
		"go test -count=1 ./internal/sandbox",
		"go test -count=1 ./internal/factory",
		"go test -count=1 ./internal/sandboxruntime",
		"go test -count=1 ./internal/sandboxworker",
		"go test -count=1 ./cmd -run 'TestCredentialDelivery|TestCredentialProxy|TestPhase46'",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 46 final verification documentation missing command line %q", want)
		}
	}
}

func phase46FinalAssertNoHalRunCommand(t *testing.T, doc string) {
	t.Helper()
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "hal run") {
			t.Fatalf("phase 46 final verification documentation must not require running hal run, got command line %q", line)
		}
	}
}

func phase46FinalDefaultGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		commands = append(commands, command)
	}
	return commands
}

func phase46FinalAssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase46FinalDefaultGoTestCommands(doc)
	for _, req := range phase46FinalRequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 46 final verification documentation missing focused command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 46 final verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase46FinalRequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		phase46FinalFocusedTest("./internal/credentialdelivery", "internal/credentialdelivery/projection_test.go", "TestStatusMetadataFromActivationProjectsActiveModesOnlyForActiveResult"),
		phase46FinalFocusedTest("./internal/credentialdelivery", "internal/credentialdelivery/import_boundary_test.go", "TestCredentialDeliveryActivationImportBoundariesCoverCoreAndDefaultFakePaths"),
		phase46FinalFocusedTest("./internal/sandbox", "internal/sandbox/credential_delivery_test.go", "TestProjectSandboxCredentialDeliveryStatusMetadataIsPlanOnly"),
		phase46FinalFocusedTest("./internal/sandbox", "internal/sandbox/credential_proxy_validation_test.go", "TestCredentialProxyValidationDoesNotInferNetworkEnforcement"),
		phase46FinalFocusedTest("./internal/factory", "internal/factory/phase46_redaction_guard_test.go", "TestPhase46FactoryPersistedOutputRedactionGuards"),
		phase46FinalFocusedTest("./internal/factory", "internal/factory/secret_broker_credential_proxy_test.go", "TestFactoryCredentialProxyMetadataCanSatisfyHTTPProxyActivationProof"),
		phase46FinalFocusedTest("./internal/sandboxruntime", "internal/sandboxruntime/phase46_redaction_guard_test.go", "TestPhase46RuntimeMetadataRedactionGuards"),
		phase46FinalFocusedTest("./internal/sandboxruntime", "internal/sandboxruntime/import_boundary_test.go", "TestSandboxruntimeCredentialDeliveryActivationImportsStayMetadataOnly"),
		phase46FinalFocusedTest("./internal/sandboxworker", "internal/sandboxworker/phase46_redaction_guard_test.go", "TestPhase46WorkerMetadataRedactionGuards"),
		phase46FinalFocusedTest("./internal/sandboxworker", "internal/sandboxworker/import_boundary_test.go", "TestSandboxworkerCredentialDeliveryDefaultMetadataImportsStayFakeOnly"),
		{pkg: "./cmd", file: "credential_delivery_projection_test.go", testName: "TestCredentialDeliveryProjectionAcrossRunAutoAndFactoryIsPlanOnly"},
		{pkg: "./cmd", file: "credential_delivery_projection_test.go", testName: "TestCredentialDeliveryHTTPProxyProjectionRequiresProvenActivationResult"},
		{pkg: "./cmd", file: "credential_delivery_projection_test.go", testName: "TestCredentialProxyIntentKeepsLegacyAuthSyncRequestedOnly"},
		{pkg: "./cmd", file: "phase46_redaction_guard_test.go", testName: "TestPhase46SandboxExecutionManifestRedactionGuards"},
		{pkg: "./cmd", file: "phase46_runtime_worker_docs_test.go", testName: "TestPhase46RuntimeWorkerVerificationDocs"},
		{pkg: "./cmd", file: "phase46_final_fake_only_verification_test.go", testName: "TestPhase46FinalFakeOnlyVerificationDocumentation"},
	}
}

func phase46FinalFocusedTest(pkg, relPath, testName string) phase34FocusedTest {
	return phase34FocusedTest{
		pkg:      pkg,
		file:     filepath.Join("..", filepath.FromSlash(relPath)),
		testName: testName,
	}
}

func phase46FinalForbiddenDefaultMarkers() []string {
	return []string{
		"-tags=network_enforcement_live",
		"-tags=credential_delivery_live",
		"network_enforcement_live",
		"credential_delivery_live",
		"HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_CREDENTIAL_DELIVERY_LIVE",
		"SSH_AUTH_SOCK",
		"OPENAI_API_KEY=",
		"Authorization:",
		"Bearer ",
		"token=",
		"secret=",
		"hal run",
	}
}

func TestPhase46FinalFakeOnlyVerificationDocPathStable(t *testing.T) {
	if got, want := phase46FinalFakeOnlyDocPath, "sandbox-runtime-v2-phase46-final-fake-only-verification.md"; got != want {
		t.Fatalf("phase46 final doc path = %q, want %q", got, want)
	}
}
