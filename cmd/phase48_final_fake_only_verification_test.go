package cmd

import (
	"go/parser"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phase48FinalFakeOnlyDocPath = "sandbox-runtime-v2-phase48-final-fake-only-verification.md"

func TestPhase48FinalFakeOnlyVerificationDocumentation(t *testing.T) {
	doc := readPhase48FinalFakeOnlyDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 48 final verification barrier is fake-only.",
		"secure-default readiness",
		"proof projection",
		"target selection",
		"command propagation",
		"runtime status",
		"contracts",
		"docs",
		"import boundaries",
		"Focused Checks",
		"Broad Checks",
		"`go test -count=1 -run '^$' ./...` is the typecheck-only pass.",
		"`make docs-check` is the generated CLI documentation drift check.",
		"No intentional Phase 48 contract drift is expected",
		"Verification remains fake-only.",
		"does not require KVM, Firecracker live boot, real firewall, real proxy, real secret broker, Docker/Podman, cloud, network, or live E2E setup",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 48 final fake-only verification documentation missing %q", want)
		}
	}

	phase48FinalAssertDocumentedCommands(t, doc)
}

func TestPhase48FinalFocusedCommandsCoverAllSecureDefaultLanes(t *testing.T) {
	doc := readPhase48FinalFakeOnlyDoc(t)
	commands := phase48FinalDefaultGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 48 final verification documentation must list default go test commands")
	}

	for _, req := range phase48FinalRequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 48 final verification documentation missing focused command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 48 final verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func TestPhase48FinalVerificationStaysFakeOnlyByDefault(t *testing.T) {
	doc := readPhase48FinalFakeOnlyDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	for _, want := range []string{
		"Verification remains fake-only.",
		"does not require KVM, Firecracker live boot, real firewall, real proxy, real secret broker, Docker/Podman, cloud, network, or live E2E setup",
		"Do not add live Firecracker boot checks, KVM prerequisites, firewall or proxy mutation, credential broker sessions, credential injection, template pulls, Docker or Podman workflows, cloud API calls, external network calls, `hal sandboxd` daemon requirements, live worker daemon requirements, or optional live build tags to the default Phase 48 barrier.",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 48 final fake-only documentation missing %q", want)
		}
	}

	for _, command := range phase48FinalDefaultGoTestCommands(doc) {
		for _, forbidden := range append(phase34ForbiddenDefaultFocusedCommandRequirements(), phase48FinalForbiddenDefaultMarkers()...) {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 48 final default command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	for _, path := range phase48FinalFakeOnlyGuardedTestFiles() {
		phase48FinalAssertNoLiveIntegrationBuildTag(t, path)
		phase34AssertDefaultTestFileAvoidsLiveImports(t, path)
	}
}

func TestPhase48FinalImportBoundaryDocumentsPureReadinessIsolation(t *testing.T) {
	doc := readPhase48FinalFakeOnlyDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Pure secure-default readiness decisions stay in `internal/sandbox` metadata logic.",
		"do not import concrete microVM or Firecracker packages",
		"live network/proxy/firewall implementation packages",
		"credential activation implementation packages",
		"template acquisition implementation packages",
		"Docker or Podman clients",
		"cloud SDKs",
		"network packages",
		"`os/exec`",
		"provider packages",
		"proxy startup",
		"firewall mutation",
		"credential activation or injection",
		"template acquisition",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 48 final import-boundary documentation missing %q", want)
		}
	}
}

func TestPhase48FinalFakeOnlyVerificationDocPathStable(t *testing.T) {
	if got, want := phase48FinalFakeOnlyDocPath, "sandbox-runtime-v2-phase48-final-fake-only-verification.md"; got != want {
		t.Fatalf("phase48 final doc path = %q, want %q", got, want)
	}
}

func readPhase48FinalFakeOnlyDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", phase48FinalFakeOnlyDocPath))
	if err != nil {
		t.Fatalf("ReadFile(phase 48 final fake-only verification doc) error = %v", err)
	}
	return string(data)
}

func phase48FinalAssertDocumentedCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 ./internal/sandbox -run 'Test(SecureDefaultReadiness|ProjectSecureDefaultReadinessInput|SecurityCapability.*(Import|Source))'",
		"go test -count=1 ./internal/sandboxtarget -run 'Test(SelectStrictSecureDefault|SelectCompatibilitySecureDefault|Sandboxtarget.*Import|SchedulerImportBoundary)'",
		"go test -count=1 ./cmd -run 'TestUS007'",
		"go test -count=1 ./cmd -run 'Test(US009SandboxRuntime|US009RuntimeDocs|Phase48Final)'",
		"go test ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 48 final verification documentation missing command line %q", want)
		}
	}
}

func phase48FinalDefaultGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		commands = append(commands, command)
	}
	return commands
}

func phase48FinalRequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		phase48FinalFocusedTest("./internal/sandbox", "internal/sandbox/security_capability_secure_default_test.go", "TestSecureDefaultReadinessStrictBlocksMissingAndIncompleteProofs"),
		phase48FinalFocusedTest("./internal/sandbox", "internal/sandbox/security_capability_secure_default_test.go", "TestSecureDefaultReadinessProofCompleteAllowedIncludesReasonCodeCounts"),
		phase48FinalFocusedTest("./internal/sandbox", "internal/sandbox/security_capability_secure_default_test.go", "TestSecureDefaultReadinessDiagnosticsAndDecisionsAreRedactionSafe"),
		phase48FinalFocusedTest("./internal/sandbox", "internal/sandbox/security_capability_secure_default_projection_test.go", "TestProjectSecureDefaultReadinessInputAcceptsActiveSuccessProxyFirewallNetworkProof"),
		phase48FinalFocusedTest("./internal/sandbox", "internal/sandbox/security_capability_secure_default_projection_test.go", "TestProjectSecureDefaultReadinessInputRequiresActiveCredentialActivationProof"),
		phase48FinalFocusedTest("./internal/sandbox", "internal/sandbox/security_capability_secure_default_projection_test.go", "TestProjectSecureDefaultReadinessInputRequiresLockedTemplateDigestProof"),
		phase48FinalFocusedTest("./internal/sandbox", "internal/sandbox/security_capability_import_boundary_test.go", "TestSecurityCapabilityImportBoundaries"),
		phase48FinalFocusedTest("./internal/sandbox", "internal/sandbox/security_capability_import_boundary_test.go", "TestSecurityCapabilityForbiddenImportListCoversRequiredBoundaries"),
		phase48FinalFocusedTest("./internal/sandbox", "internal/sandbox/security_capability_import_boundary_test.go", "TestSecurityCapabilitySourceGuardCoversRequiredLiveBehaviorMarkers"),
		phase48FinalFocusedTest("./internal/sandboxtarget", "internal/sandboxtarget/secure_default_selection_red_test.go", "TestSelectStrictSecureDefaultRejectsMicroVMTargetWithoutCachedReadiness"),
		phase48FinalFocusedTest("./internal/sandboxtarget", "internal/sandboxtarget/secure_default_selection_red_test.go", "TestSelectStrictSecureDefaultRejectsCompatibilityTargetsInsteadOfSelectingThem"),
		phase48FinalFocusedTest("./internal/sandboxtarget", "internal/sandboxtarget/secure_default_selection_red_test.go", "TestSelectStrictSecureDefaultDoesNotPlanCompatibilityProvisioningForMissingMicroVMTarget"),
		phase48FinalFocusedTest("./internal/sandboxtarget", "internal/sandboxtarget/secure_default_selection_red_test.go", "TestSelectCompatibilitySecureDefaultReadinessRemainsAdvisoryAndTruthful"),
		phase48FinalFocusedTest("./internal/sandboxtarget", "internal/sandboxtarget/import_boundary_test.go", "TestSandboxtargetImportsStayCommandAgnostic"),
		phase48FinalFocusedTest("./internal/sandboxtarget", "internal/sandboxtarget/import_boundary_test.go", "TestSandboxtargetForbiddenImportListCoversCommandCouplingSurfaces"),
		phase48FinalFocusedTest("./internal/sandboxtarget", "internal/sandboxtarget/scheduler_import_boundary_test.go", "TestSchedulerImportBoundaryRejectsWorkerProviderAndNetworkCoupling"),
		{pkg: "./cmd", file: "secure_default_propagation_red_test.go", testName: "TestUS007FactoryStrictSecureDefaultBlockedGatePropagatesDecisionToRunRecord"},
		{pkg: "./cmd", file: "secure_default_propagation_red_test.go", testName: "TestUS007FactoryStrictSecureDefaultProofCompletePropagatesAllowedDecision"},
		{pkg: "./cmd", file: "secure_default_propagation_red_test.go", testName: "TestUS007RunAndAutoDefaultSecureDefaultReadinessPersistsAdvisoryDecision"},
		{pkg: "./cmd", file: "secure_default_propagation_red_test.go", testName: "TestUS007RunAndAutoStrictSecureDefaultSelectionBlocksAndPersistsDecision"},
		{pkg: "./cmd", file: "sandbox_runtime_secure_default_red_test.go", testName: "TestUS009SandboxRuntimeListJSONSurfacesStrictAndCompatibilitySecureDefaultDecisions"},
		{pkg: "./cmd", file: "sandbox_runtime_secure_default_red_test.go", testName: "TestUS009SandboxRuntimeStatusJSONSurfacesProofCompleteAllowedSecureDefaultDecision"},
		{pkg: "./cmd", file: "sandbox_runtime_secure_default_red_test.go", testName: "TestUS009SandboxRuntimeHumanOutputExplainsStrictVersusAdvisorySecureDefaultBehavior"},
		{pkg: "./cmd", file: "sandbox_runtime_secure_default_red_test.go", testName: "TestUS009SandboxRuntimeSecureDefaultOutputRedactsUnsafeFragments"},
		{pkg: "./cmd", file: "secure_default_runtime_docs_red_test.go", testName: "TestUS009RuntimeDocsCLIExamplesExplainStrictVersusCompatibilitySecureDefaultBehavior"},
		{pkg: "./cmd", file: "secure_default_runtime_docs_red_test.go", testName: "TestUS009RuntimeDocsVerificationCommandsAreFakeOnly"},
		{pkg: "./cmd", file: "phase48_final_fake_only_verification_test.go", testName: "TestPhase48FinalFakeOnlyVerificationDocumentation"},
	}
}

func phase48FinalFocusedTest(pkg, relPath, testName string) phase34FocusedTest {
	return phase34FocusedTest{
		pkg:      pkg,
		file:     filepath.Join("..", filepath.FromSlash(relPath)),
		testName: testName,
	}
}

func phase48FinalForbiddenDefaultMarkers() []string {
	return []string{
		"-tags=network_enforcement_live",
		"-tags=credential_delivery_live",
		"-tags=firecracker_live",
		"network_enforcement_live",
		"credential_delivery_live",
		"firecracker_live",
		"HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_CREDENTIAL_DELIVERY_LIVE",
		"HAL_FIRECRACKER_LIVE",
		"HAL_PODMAN_" + "TEST_IMAGE",
		"SSH_AUTH_SOCK",
		"OPENAI_API_KEY=",
		"Authorization:",
		"Bearer ",
		"token=",
		"secret=",
		"hal run",
		"hal auto",
		"hal sandboxd",
	}
}

func phase48FinalFakeOnlyGuardedTestFiles() []string {
	seen := map[string]bool{}
	var files []string
	for _, req := range phase48FinalRequiredFocusedTests() {
		if seen[req.file] {
			continue
		}
		seen[req.file] = true
		files = append(files, req.file)
	}
	return files
}

func phase48FinalAssertNoLiveIntegrationBuildTag(t *testing.T, path string) {
	t.Helper()
	file := phase34ParseGoFile(t, path, parser.ParseComments)
	for _, group := range file.Comments {
		if group.End() > file.Package {
			continue
		}
		for _, comment := range group.List {
			text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
			text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
			text = strings.TrimSpace(strings.TrimSuffix(text, "*/"))
			for _, tag := range []string{
				"integration",
				"worker_integration",
				"podman_integration",
				"microvm_integration",
				"kvm_integration",
				"firecracker_live",
				"network_enforcement_live",
				"credential_delivery_live",
			} {
				if strings.HasPrefix(text, "go:build") && strings.Contains(text, tag) {
					t.Fatalf("%s uses integration build tag %q; Phase 48 focused tests must stay fake-only by default", phase34FirecrackerDisplayPath(t, path), tag)
				}
			}
		}
	}
}
