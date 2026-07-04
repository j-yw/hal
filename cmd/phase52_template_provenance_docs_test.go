package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phase52TemplateProvenancePolicyDocPath = "sandbox-runtime-v2-phase52-template-provenance-policy-verification.md"

func TestPhase52TemplateProvenancePolicyVerificationDocumentation(t *testing.T) {
	doc := readPhase52TemplateProvenancePolicyDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 52 documents template provenance and trust policy contracts for production template acquisition.",
		"production template acquisition requires locked, digest-pinned references unless explicit advisory mode is selected",
		"`internal/sandboxtemplate/acquisition` owns data-only trust policy contracts, strict and advisory evaluation, lock/provenance consistency checks, sanitized provenance projection, and runtime template-lock trust metadata projection.",
		"`TrustPolicyRequest`",
		"`TrustPolicyResult`",
		"`TrustPolicyError`",
		"`TrustPolicyWarning`",
		"`TrustPolicyModeStrict`",
		"`TrustPolicyModeAdvisory`",
		"`metadata.reference`",
		"`runtime.image`",
		"`runtime.launch.descriptorRef`",
		"`workspace.ref`",
		"`network.policySnapshotReference`",
		"`mutable_reference`",
		"`missing_digest_pin`",
		"`unresolved_lock_entry`",
		"`lock_provenance_mismatch`",
		"`unsupported_source`",
		"`resolver_unavailable`",
		"Default Phase 52 verification is fake/local only.",
		"default tests use local files, in-memory OCI fixtures, and fake resolvers only",
		"live OCI/registry behavior, hosted registries, signature services, transparency logs, key management, and broad runtime rewrites are future or opt-in integration work",
		"Focused Fake/Local Commands",
		"Full Quality Commands",
		"`golangci-lint run ./...` only when `golangci-lint` is installed.",
		"If it is unavailable, report lint unavailable instead of reporting lint as passed.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 52 template provenance policy verification documentation missing %q", want)
		}
	}

	phase52AssertDocumentedCommands(t, doc)
}

func TestPhase52TemplateProvenancePolicyFocusedCommandsCoverRequiredSelectors(t *testing.T) {
	doc := readPhase52TemplateProvenancePolicyDoc(t)
	commands := phase52DefaultGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 52 template provenance policy verification documentation must list go test commands")
	}

	for _, req := range phase52RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 52 template provenance policy documentation missing focused command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 52 verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func TestPhase52TemplateProvenancePolicyVerificationCommandsStayFakeLocal(t *testing.T) {
	doc := readPhase52TemplateProvenancePolicyDoc(t)
	commands := phase52DocumentedCommandLines(doc)
	if len(commands) == 0 {
		t.Fatal("phase 52 template provenance policy verification documentation must list command lines")
	}

	for _, command := range commands {
		for _, forbidden := range phase52ForbiddenDefaultCommandMarkers() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 52 default verification command %q contains forbidden live/integration marker %q", command, forbidden)
			}
		}
	}

	for _, path := range phase52GuardedDefaultTestFiles() {
		phase52AssertNoLiveIntegrationBuildTag(t, path)
		phase34AssertDefaultTestFileAvoidsLiveImports(t, path)
	}
}

func TestPhase52TemplateProvenancePolicyDocPathStable(t *testing.T) {
	if got, want := phase52TemplateProvenancePolicyDocPath, "sandbox-runtime-v2-phase52-template-provenance-policy-verification.md"; got != want {
		t.Fatalf("phase 52 template provenance policy doc path = %q, want %q", got, want)
	}
}

func readPhase52TemplateProvenancePolicyDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", phase52TemplateProvenancePolicyDocPath))
	if err != nil {
		t.Fatalf("ReadFile(phase 52 template provenance policy verification doc) error: %v", err)
	}
	return string(data)
}

func phase52AssertDocumentedCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 -timeout=180s ./internal/sandboxtemplate/acquisition -run 'Test(TrustPolicy|EvaluateTrustPolicy|ProjectTemplateProvenance|ProjectRuntimeTemplateLockMetadata|SandboxTemplateAcquisitionImportBoundaryAllowsTrustPolicyRuntimeMetadataProjection)'",
		"go test -count=1 -timeout=180s ./cmd -run 'TestPhase52Template'",
		"go test -count=1 -timeout=180s ./internal/sandboxtemplate/acquisition ./cmd",
		"go test -count=1 -timeout=420s ./...",
		"make test",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 52 template provenance policy documentation missing command line %q", want)
		}
	}
	if !strings.Contains(doc, "golangci-lint run ./...") {
		t.Fatal("phase 52 template provenance policy documentation missing conditional golangci-lint command")
	}
}

func phase52DefaultGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "-tags=template_oci_integration") {
			continue
		}
		commands = append(commands, command)
	}
	return commands
}

func phase52DocumentedCommandLines(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "go test "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "go vet "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "make "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "git diff "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "golangci-lint "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "hal "):
			commands = append(commands, line)
		}
	}
	return commands
}

func phase52RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_contract_test.go", "TestTrustPolicyContractConstantsAreStable"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_contract_test.go", "TestTrustPolicyContractFieldsAndJSONTags"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_contract_test.go", "TestTrustPolicyJSONShapeIncludesOnlySafePolicyMetadata"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_contract_test.go", "TestTrustPolicyJSONOmitsOptionalMetadata"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_contract_test.go", "TestTrustPolicyContractsAvoidUnsafeRawMetadataSurface"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_import_boundary_test.go", "TestTrustPolicyProductionImportsStayDataOnly"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_import_boundary_test.go", "TestTrustPolicyImportBoundaryCoversOnlyPolicyProductionFiles"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_import_boundary_test.go", "TestTrustPolicyForbiddenImportListCoversArchitectureBoundaries"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_evaluator_test.go", "TestEvaluateTrustPolicyStrictRejectsUnresolvedRequiredReferences"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_evaluator_test.go", "TestEvaluateTrustPolicyStrictRejectsMissingDigestPinWithoutLockOrProvenance"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_evaluator_test.go", "TestEvaluateTrustPolicyDefaultModeIsStrictProductionRejection"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_evaluator_test.go", "TestEvaluateTrustPolicyStrictRejectsMissingTemplateDocumentIdentity"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_evaluator_test.go", "TestEvaluateTrustPolicyStrictTrustsMatchingLockAndProvenanceEvidence"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_evaluator_test.go", "TestEvaluateTrustPolicyStrictRejectsMissingRequiredLockEntryEvenWithProvenance"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_evaluator_test.go", "TestEvaluateTrustPolicyStrictRejectsProvenanceDigestMismatch"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_evaluator_test.go", "TestEvaluateTrustPolicyAdvisoryReportsWarningsWithoutRejecting"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_evaluator_test.go", "TestEvaluateTrustPolicyAdvisoryReportsMutableAndUnresolvedWarningCodes"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/provenance_projection_test.go", "TestProjectTemplateProvenanceProjectsLocalLockJSONFields"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/provenance_projection_test.go", "TestProjectTemplateProvenanceProjectsOCIResolverLocksWithoutUnsafeRefs"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/provenance_projection_test.go", "TestProjectTemplateProvenanceOmitsUnsafeValuesAndBoundsWarnings"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_runtime_projection_test.go", "TestProjectRuntimeTemplateLockMetadataSurfacesSanitizedTrustPolicyOutcome"),
		phase52FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/import_boundary_test.go", "TestSandboxTemplateAcquisitionImportBoundaryAllowsTrustPolicyRuntimeMetadataProjection"),
		{pkg: "./cmd", file: "template_lock_metadata_test.go", testName: "TestPhase52TemplateLockTrustPolicyMetadataPersistsSafely"},
		{pkg: "./cmd", file: "phase52_template_provenance_docs_test.go", testName: "TestPhase52TemplateProvenancePolicyVerificationDocumentation"},
		{pkg: "./cmd", file: "phase52_template_provenance_docs_test.go", testName: "TestPhase52TemplateProvenancePolicyVerificationCommandsStayFakeLocal"},
	}
}

func phase52FocusedTest(pkg, relPath, testName string) phase34FocusedTest {
	return phase34FocusedTest{
		pkg:      pkg,
		file:     filepath.Join("..", filepath.FromSlash(relPath)),
		testName: testName,
	}
}

func phase52ForbiddenDefaultCommandMarkers() []string {
	return []string{
		"-tags=integration",
		"-tags=worker_integration",
		"-tags=podman_integration",
		"-tags=firecracker_live",
		"-tags=network_enforcement_live",
		"-tags=credential_delivery_live",
		"-tags=template_oci_integration",
		"worker_integration",
		"podman_integration",
		"firecracker_live",
		"network_enforcement_live",
		"credential_delivery_live",
		"template_oci_integration",
		"HAL_TEMPLATE_OCI_",
		"DOCKER_HOST",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"docker ",
		"podman ",
		"oras ",
		"crane ",
		"skopeo ",
		"cosign ",
		"rekor ",
		"hal run",
		"hal sandboxd",
		"--live",
	}
}

func phase52GuardedDefaultTestFiles() []string {
	seen := map[string]bool{}
	var files []string
	for _, req := range phase52RequiredFocusedTests() {
		if seen[req.file] {
			continue
		}
		seen[req.file] = true
		files = append(files, req.file)
	}
	return files
}

func phase52AssertNoLiveIntegrationBuildTag(t *testing.T, path string) {
	t.Helper()
	source := phase49FinalReadFile(t, path)
	header := phase19SourceHeader(source)
	for _, tag := range []string{
		"integration",
		"worker_integration",
		"podman_integration",
		"firecracker_live",
		"network_enforcement_live",
		"credential_delivery_live",
		"template_oci_integration",
	} {
		if strings.Contains(header, tag) {
			t.Fatalf("%s uses build tag %q; Phase 52 default verification must stay fake/local", phase34FirecrackerDisplayPath(t, path), tag)
		}
	}
}
