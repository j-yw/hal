package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phase49FinalCodeVerificationDocPath = "sandbox-runtime-v2-phase49-final-code-verification.md"

func TestPhase49FinalCodeVerificationDocumentation(t *testing.T) {
	doc := readPhase49FinalCodeVerificationDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 49 final code verification barrier checks implemented code, tests, and runtime behavior only.",
		"fake-only default matrix",
		"secure-default diagnostics",
		"runtime status",
		"workflow status",
		"run/auto/factory propagation",
		"redaction evidence",
		"live-provider gate guards",
		"touched package suites",
		"repository-wide tests",
		"typecheck",
		"vet",
		"conditional lint",
		"does not require validating, auditing, regenerating, or reconverting the PRD after implementation",
		"does not change canonical Hal PRD or progress state",
		"Focused Checks",
		"Touched Package Suites",
		"Repository Checks",
		"`go test -count=1 -run '^$' ./...`",
		"`golangci-lint run ./...`",
		"If `golangci-lint` is unavailable, report `golangci-lint unavailable` in the verification evidence instead of claiming lint success.",
		"does not run PRD validation, PRD audit, PRD conversion, PRD regeneration, report ingestion, or Hal workflow commands",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 49 final code verification documentation missing %q", want)
		}
	}

	phase49FinalAssertDocumentedCommands(t, doc)
}

func TestPhase49FinalFocusedCommandsCoverAllPhase49Stories(t *testing.T) {
	doc := readPhase49FinalCodeVerificationDoc(t)
	commands := phase49FinalDefaultGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 49 final code verification documentation must list go test commands")
	}

	for _, req := range phase49FinalRequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 49 final code verification documentation missing focused command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 49 verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func TestPhase49FinalVerificationCommandsStayCodeOnly(t *testing.T) {
	doc := readPhase49FinalCodeVerificationDoc(t)
	commands := phase49FinalDocumentedCommandLines(doc)
	if len(commands) == 0 {
		t.Fatal("phase 49 final code verification documentation must list command lines")
	}

	for _, command := range commands {
		for _, forbidden := range phase49FinalForbiddenCommandMarkers() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 49 final command %q contains forbidden non-code or live marker %q", command, forbidden)
			}
		}
	}
}

func TestPhase49FinalVerificationExcludesPRDWorkflowCommands(t *testing.T) {
	doc := readPhase49FinalCodeVerificationDoc(t)
	for _, forbidden := range []string{
		"```bash\nhal validate",
		"```bash\nhal convert",
		"```bash\nhal plan",
		"```bash\nhal auto",
		"```bash\nhal run",
		"```bash\nhal report",
		"```sh\nhal validate",
		"```sh\nhal convert",
		"```sh\nhal plan",
		"```sh\nhal auto",
		"```sh\nhal run",
		"```sh\nhal report",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("phase 49 final code verification documentation must not require PRD or workflow command %q", forbidden)
		}
	}

	for _, want := range []string{
		"`hal validate`",
		"`hal convert`",
		"`hal plan`",
		"`hal auto`",
		"`hal run`",
		"`hal report`",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("phase 49 final non-goals must explicitly exclude %s", want)
		}
	}
}

func TestPhase49FinalDefaultGuardFileStaysInDefaultSuite(t *testing.T) {
	source := phase49FinalReadFile(t, "phase49_final_code_verification_test.go")
	header := phase19SourceHeader(source)
	for _, tag := range []string{
		"integration",
		"worker_integration",
		"podman_integration",
		"firecracker_live",
		"network_enforcement_live",
		"credential_delivery_live",
	} {
		if strings.Contains(header, tag) {
			t.Fatalf("phase49_final_code_verification_test.go uses build tag %q; final code verification must run under go test ./cmd", tag)
		}
	}
}

func TestPhase49FinalCodeVerificationDocPathStable(t *testing.T) {
	if got, want := phase49FinalCodeVerificationDocPath, "sandbox-runtime-v2-phase49-final-code-verification.md"; got != want {
		t.Fatalf("phase49 final code verification doc path = %q, want %q", got, want)
	}
}

func readPhase49FinalCodeVerificationDoc(t *testing.T) string {
	t.Helper()
	return phase49FinalReadFile(t, filepath.Join("..", "docs", "design", phase49FinalCodeVerificationDocPath))
}

func phase49FinalReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}

func phase49FinalAssertDocumentedCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 ./internal/sandbox -run 'TestUS001SecureDefaultDiagnosticSummariesExposeSafeReadinessDecisions'",
		"go test -count=1 ./cmd -run 'Test(US00[2-9]|RunStatusFn_(JSONDecodesWorkflowStates|DoesNotExposeSandboxSecretsOrProviderConfig)|Phase49)'",
		"go test -count=1 ./cmd ./internal/compound ./internal/factory ./internal/sandbox ./internal/status",
		"go test ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 49 final code verification documentation missing command line %q", want)
		}
	}
	if !strings.Contains(doc, "golangci-lint run ./...") {
		t.Fatal("phase 49 final code verification documentation missing conditional golangci-lint command")
	}
}

func phase49FinalDefaultGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		commands = append(commands, command)
	}
	return commands
}

func phase49FinalDocumentedCommandLines(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "go test "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "go vet "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "golangci-lint "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "hal "):
			commands = append(commands, line)
		}
	}
	return commands
}

func phase49FinalRequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		phase49FinalFocusedTest("./internal/sandbox", "internal/sandbox/security_capability_secure_default_test.go", "TestUS001SecureDefaultDiagnosticSummariesExposeSafeReadinessDecisions"),
		{pkg: "./cmd", file: "sandbox_runtime_us002_test.go", testName: "TestUS002SandboxRuntimeListJSONDecodesCachedUnsupportedLiveAndSecureDefaultState"},
		{pkg: "./cmd", file: "sandbox_runtime_us002_test.go", testName: "TestUS002SandboxRuntimeStatusJSONDecodesSuccessMissingRuntimeAndSecureDefaultState"},
		{pkg: "./cmd", file: "sandbox_runtime_us002_test.go", testName: "TestUS002SandboxRuntimeHumanOutputReportsModesReadinessAndSafeRemediation"},
		{pkg: "./cmd", file: "status_test.go", testName: "TestRunStatusFn_JSONDecodesWorkflowStates"},
		{pkg: "./cmd", file: "status_test.go", testName: "TestRunStatusFn_DoesNotExposeSandboxSecretsOrProviderConfig"},
		{pkg: "./cmd", file: "secure_default_propagation_red_test.go", testName: "TestUS004RunAndAutoConfiguredStrictSecureDefaultBlocksBeforeLiveWork"},
		{pkg: "./cmd", file: "factory_sandbox_readiness_test.go", testName: "TestUS005FactoryStrictDefaultSecureDefaultBlocksBeforeSecretsAndSandboxSetup"},
		{pkg: "./cmd", file: "factory_sandbox_readiness_test.go", testName: "TestUS005FactoryPolicySecurityReadinessModesPropagateToSandboxExecutor"},
		{pkg: "./cmd", file: "default_fake_only_e2e_test.go", testName: "TestUS006DefaultFakeOnlyE2ERunAutoAndFactoryPaths"},
		{pkg: "./cmd", file: "sandbox_default_fake_only_guard_test.go", testName: "TestUS006DefaultFakeOnlyE2ETestStaysInDefaultSuite"},
		{pkg: "./cmd", file: "secure_default_propagation_red_test.go", testName: "TestUS007FactoryStrictSecureDefaultBlockedGatePropagatesDecisionToRunRecord"},
		{pkg: "./cmd", file: "secure_default_propagation_red_test.go", testName: "TestUS007FactoryStrictSecureDefaultProofCompletePropagatesAllowedDecision"},
		{pkg: "./cmd", file: "secure_default_propagation_red_test.go", testName: "TestUS007RunAndAutoDefaultSecureDefaultReadinessPersistsAdvisoryDecision"},
		{pkg: "./cmd", file: "secure_default_propagation_red_test.go", testName: "TestUS007RunAndAutoStrictSecureDefaultSelectionBlocksAndPersistsDecision"},
		{pkg: "./cmd", file: "status_progress_redaction_us007_test.go", testName: "TestUS007SandboxRuntimeListStatusRedactSeededHostStatusMetadata"},
		{pkg: "./cmd", file: "status_test.go", testName: "TestUS007RunStatusRedactsWorkflowAndProgressInputs"},
		{pkg: "./cmd", file: "run_test.go", testName: "TestUS007RunProgressOutputRedactsStoryAndErrorInputs"},
		{pkg: "./cmd", file: "redaction_e2e_us008_test.go", testName: "TestUS008RunAutoAndFactoryFakeBackedE2ERedactionSurfaces"},
		{pkg: "./cmd", file: "redaction_e2e_us008_test.go", testName: "TestUS008PersistedCommandSummaryRedactsTokenLikeValues"},
		{pkg: "./cmd", file: "sandbox_runtime_secure_default_red_test.go", testName: "TestUS009SandboxRuntimeListJSONSurfacesStrictAndCompatibilitySecureDefaultDecisions"},
		{pkg: "./cmd", file: "sandbox_runtime_secure_default_red_test.go", testName: "TestUS009SandboxRuntimeStatusJSONSurfacesProofCompleteAllowedSecureDefaultDecision"},
		{pkg: "./cmd", file: "sandbox_runtime_secure_default_red_test.go", testName: "TestUS009SandboxRuntimeHumanOutputExplainsStrictVersusAdvisorySecureDefaultBehavior"},
		{pkg: "./cmd", file: "sandbox_runtime_secure_default_red_test.go", testName: "TestUS009SandboxRuntimeSecureDefaultOutputRedactsUnsafeFragments"},
		{pkg: "./cmd", file: "secure_default_runtime_docs_red_test.go", testName: "TestUS009RuntimeDocsCLIExamplesExplainStrictVersusCompatibilitySecureDefaultBehavior"},
		{pkg: "./cmd", file: "secure_default_runtime_docs_red_test.go", testName: "TestUS009RuntimeDocsExamplesDoNotOverclaimRequestedMetadataAsLiveProof"},
		{pkg: "./cmd", file: "secure_default_runtime_docs_red_test.go", testName: "TestUS009RuntimeDocsVerificationCommandsAreFakeOnly"},
		{pkg: "./cmd", file: "phase49_live_provider_gates_test.go", testName: "TestPhase49LiveProviderGateDocumentation"},
		{pkg: "./cmd", file: "phase49_live_provider_gates_test.go", testName: "TestPhase49DefaultVerificationCommandsStayFakeOnly"},
		{pkg: "./cmd", file: "phase49_final_code_verification_test.go", testName: "TestPhase49FinalCodeVerificationDocumentation"},
	}
}

func phase49FinalFocusedTest(pkg, relPath, testName string) phase34FocusedTest {
	return phase34FocusedTest{
		pkg:      pkg,
		file:     filepath.Join("..", filepath.FromSlash(relPath)),
		testName: testName,
	}
}

func phase49FinalForbiddenCommandMarkers() []string {
	return []string{
		"hal validate",
		"hal convert",
		"hal plan",
		"hal auto",
		"hal run",
		"hal report",
		"-tags=integration",
		"-tags=worker_integration",
		"-tags=podman_integration",
		"-tags=firecracker_live",
		"-tags=network_enforcement_live",
		"-tags=credential_delivery_live",
		"worker_integration",
		"podman_integration",
		"firecracker_live",
		"network_enforcement_live",
		"credential_delivery_live",
		"HAL_FIRECRACKER_LIVE",
		"HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_CREDENTIAL_DELIVERY_LIVE",
		"HAL_WORKER_INTEGRATION_",
		"HAL_PODMAN_" + "TEST_IMAGE",
		"DOCKER_HOST",
		"SSH_AUTH_SOCK",
		"OPENAI_API_KEY=",
		"Authorization:",
		"Bearer ",
		"token=",
		"secret=",
		"docker ",
		"podman ",
		"firecracker ",
		"/dev/kvm",
		"curl ",
		"hal sandboxd",
		"--live",
	}
}
