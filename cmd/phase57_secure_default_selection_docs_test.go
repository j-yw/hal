package cmd

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	phase57VerificationDocPath = "sandbox-runtime-v2-phase57-secure-runtime-readiness-default-selection-verification.md"

	phase57PolicyFocusedCommand     = "go test -count=1 -timeout=180s ./internal/sandbox -run 'Test(US001SecureDefault|SecureDefaultReadiness|US002ProjectSecureDefault|ProjectSecureDefaultReadinessInput|US004SelectedTemplate|US006SelectedTemplate|SecurityCapabilityReadinessGate)'"
	phase57ProofSourcesCommand      = "go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement ./internal/sandboxruntime ./internal/sandboxworker -run 'Test(LiveEnforcementAggregationRequiresBothActiveSides|RuntimeNetworkEnforcementProxyOnlyProofCannotClaimProxyFirewall|ServiceStatusProjectsStrictNetworkSecurityOnlyFromActiveDualProof|RuntimeCredentialDeliveryProjectsActiveSecureProofSummaries|WorkerSecurityProjectsRuntimeCredentialDeliveryProofSummaries)'"
	phase57CredentialFocusedCommand = "go test -count=1 -timeout=180s ./internal/credentialdelivery ./internal/factory/credentialactivation -run 'Test(US003|CredentialActivation|CredentialDelivery|ActivateDelivery|HTTPProxyHandoffActivation|SSHAgentHandoffActivation|FileTmpfsSimulation)'"
	phase57TemplateFocusedCommand   = "go test -count=1 -timeout=180s ./internal/sandboxtemplate ./internal/sandboxtemplate/acquisition -run 'Test(US004TemplateReferenceClassificationSeparatesDigestLockedAndMutableInput|EvaluateTrustPolicyStrictRejectsEveryRolloutPolicyCode|ProjectRuntimeTemplateLockMetadataSurfacesSanitizedTrustPolicyOutcome|SandboxTemplateProductionImportsStayPure|SandboxTemplateAcquisitionProductionImportsStayFakeSafe|TrustPolicyProductionImportsStayDataOnly)'"
	phase57SelectionFocusedCommand  = "go test -count=1 -timeout=180s ./internal/sandboxtarget -run 'Test(SelectStrictSecureDefault|SelectCompatibilitySecureDefault|SandboxtargetImportsStayCommandAgnostic|SandboxtargetForbiddenImportListCoversCommandCouplingSurfaces)'"
	phase57CommandSurfaceCommand    = "go test -count=1 -timeout=180s ./cmd -run 'Test(US005(CommandNetworkSecurityDowngradesProxyFirewallWithoutRuntimeProof|SandboxRuntimeStatusJSONRequiresActiveDualNetworkProof|FactoryStrictReadinessBlocksDowngradedProxyFirewallMetadata|CommandStatusReadinessFilesAvoidLiveEnforcementImplementation)|US006(RunSandboxStrictSelectionJSONRendersAndPersistsDecision|AutoSandboxStrictSelectionJSONRendersAndPersistsDecision|RunSandboxJSONAugmentsAllowedAndCompatibilityGateDecisions|RunSandboxStrictHumanErrorIncludesGateCountsAndReasons)|US007(FactoryRunResultSurfacesSecurityReadinessGateOutcomes|FactoryStatusSurfacesSecurityReadinessGateSummary)|Phase57)'"
)

func TestPhase57SecureDefaultSelectionVerificationDocumentation(t *testing.T) {
	doc := readPhase57VerificationDoc(t)
	for _, want := range []string{
		"Phase 57 final docs/guard barrier for secure runtime readiness and default selection.",
		"secure-default selection invariant: strict default selection is allowed only when every configured sanitized proof source is ready, warning-free, and proof-backed.",
		"strict mode blocks selection when any required proof is missing, unsupported, failed, metadata-only, advisory-only, compatibility-only, partial, or warning-bearing.",
		"compatibility and advisory modes render diagnostics only and must not claim strict secure-default readiness.",
		"Phase 56 provides active MicroVM isolation and active `proxy_firewall` network proof.",
		"Phase 58 provides active brokered credential delivery proof.",
		"Phase 59 provides selected-template trust and digest-lock proof.",
		"`internal/sandbox` owns the secure-default readiness policy and reason-code projection.",
		"`internal/sandboxtarget` owns fail-closed secure-default/default-selection behavior.",
		"`cmd` and `internal/factory` remain render-only consumers of sanitized decisions.",
		"stable reason-code expectations include `readiness_missing`, `readiness_ready`, `microvm_readiness_missing`, `network_enforcement_partial`, `network_enforcement_confirmed`, `credential_activation_missing`, `credential_activation_confirmed`, `template_lock_digest_missing`, `selected_template_trust_confirmed`, and `warning_bearing`.",
		"Phase 60 live E2E remains outside Phase 57 default verification.",
		"US-008 is the single final docs/guard barrier story for Phase 57.",
	} {
		if !phase57DocContains(doc, want) {
			t.Fatalf("%s missing required Phase 57 text %q", phase50SafeDisplayPath(phase57VerificationDocFile()), want)
		}
	}
	phase57AssertDocumentedCommands(t, doc)
}

func TestPhase57DefaultCommandsStayFakeOnly(t *testing.T) {
	doc := readPhase57VerificationDoc(t)
	defaultCommands := phase54DefaultDocumentedCommands(doc)
	if len(defaultCommands) == 0 {
		t.Fatalf("%s must list default fake-only command lines", phase50SafeDisplayPath(phase57VerificationDocFile()))
	}
	for _, command := range defaultCommands {
		if marker := phase57ForbiddenDefaultCommandMarker(command); marker != "" {
			t.Fatalf("%s default command %q contains forbidden live/default dependency marker %q", phase50SafeDisplayPath(phase57VerificationDocFile()), command, marker)
		}
	}
}

func TestPhase57DocumentedFocusedSelectorsMatchTestsAndPackages(t *testing.T) {
	doc := readPhase57VerificationDoc(t)
	commands := phase57DefaultGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatalf("%s must list focused go test commands", phase50SafeDisplayPath(phase57VerificationDocFile()))
	}
	for _, command := range commands {
		runSelector, ok := phase54CommandRunSelector(command)
		if !ok || runSelector == "^$" {
			continue
		}
		packages := phase54CommandPackageSelectors(command)
		if len(packages) == 0 {
			t.Fatalf("%s focused go test command %q has no package selector", phase50SafeDisplayPath(phase57VerificationDocFile()), command)
		}
		for _, packageSelector := range packages {
			phase54AssertPackageSelectorExists(t, packageSelector, command)
			phase54AssertRunSelectorMatchesPackageTests(t, runSelector, packageSelector, command)
		}
	}
	for _, req := range phase57RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("Phase 57 documentation missing focused command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 57 focused test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func TestPhase57ImportBoundaryCoverageDocumentsRequiredOwners(t *testing.T) {
	doc := readPhase57VerificationDoc(t)
	for _, want := range []string{
		"`internal/sandbox` import boundary",
		"`internal/sandboxtarget` import boundary",
		"Phase 56 proof-source boundary",
		"Phase 58 proof-source boundary",
		"Phase 59 proof-source boundary",
		"`cmd` and `internal/factory` render-only boundary",
	} {
		if !phase57DocContains(doc, want) {
			t.Fatalf("%s missing import-boundary coverage text %q", phase50SafeDisplayPath(phase57VerificationDocFile()), want)
		}
	}
}

func TestPhase57CommandFactoryStatusSurfacesRemainRenderOnlyConsumers(t *testing.T) {
	for _, path := range phase57CommandFactoryStatusProductionFiles(t) {
		source := phase50ReadFile(t, path)
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", phase50SafeDisplayPath(path), err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, phase50SafeDisplayPath(path), err)
			}
			if message := phase57RenderOnlyImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
		if message := phase57RenderOnlySourceBoundaryMessage(path, source); message != "" {
			t.Fatal(message)
		}
	}
}

func TestPhase57RenderOnlyBoundaryRejectsUnsafeFixtures(t *testing.T) {
	for _, tt := range []struct {
		name       string
		source     string
		importPath string
		want       string
	}{
		{
			name:   "secure default policy evaluator",
			source: `package cmd; func run() { _ = sandbox.EvaluateSandboxSecureDefaultReadiness }`,
			want:   "EvaluateSandboxSecureDefaultReadiness",
		},
		{
			name:   "secure default diagnostic projection",
			source: `package cmd; func run() { _ = sandbox.ProjectSandboxSecureDefaultReadinessDiagnostics }`,
			want:   "ProjectSandboxSecureDefaultReadinessDiagnostics",
		},
		{
			name:   "target proof construction",
			source: `package cmd; func run() { _ = targetSelectionRequestedSecureDefaultReadinessInput }`,
			want:   "targetSelectionRequestedSecureDefaultReadinessInput",
		},
		{
			name:       "network proof implementation import",
			importPath: "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement",
			want:       "network enforcement implementation",
		},
		{
			name:       "template acquisition implementation import",
			importPath: "github.com/jywlabs/hal/internal/sandboxtemplate/acquisition",
			want:       "template acquisition implementation",
		},
		{
			name:       "credential activation implementation import",
			importPath: "github.com/jywlabs/hal/internal/factory/credentialactivation",
			want:       "credential activation implementation",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.importPath != "" {
				message := phase57RenderOnlyImportBoundaryMessage("fixture.go", tt.importPath)
				if !strings.Contains(message, tt.want) {
					t.Fatalf("import boundary message = %q, want %q", message, tt.want)
				}
				return
			}
			message := phase57RenderOnlySourceBoundaryMessage("fixture.go", tt.source)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("source boundary message = %q, want %q", message, tt.want)
			}
		})
	}
}

func TestPhase57SingleFinalBarrierStory(t *testing.T) {
	doc := readPhase57VerificationDoc(t)
	for _, want := range []string{
		"| US-008 | US-001, US-002, US-003, US-004, US-005, US-006, US-007 | docs/design; docs/cli; docs/contracts; cmd; docs/guards | false | true |",
		"US-008 is the single final docs/guard barrier story for Phase 57.",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("%s missing barrier story text %q", phase50SafeDisplayPath(phase57VerificationDocFile()), want)
		}
	}

	var barrierDocs []string
	for _, path := range phase57DesignDocFiles(t) {
		source := phase50ReadFile(t, path)
		if strings.Contains(source, "single final docs/guard barrier story for Phase 57") {
			barrierDocs = append(barrierDocs, phase50SafeDisplayPath(path))
		}
	}
	if len(barrierDocs) != 1 || barrierDocs[0] != phase50SafeDisplayPath(phase57VerificationDocFile()) {
		t.Fatalf("Phase 57 final barrier docs = %#v, want only %s", barrierDocs, phase50SafeDisplayPath(phase57VerificationDocFile()))
	}
}

func TestPhase57VerificationDocPathStable(t *testing.T) {
	if got, want := phase57VerificationDocPath, "sandbox-runtime-v2-phase57-secure-runtime-readiness-default-selection-verification.md"; got != want {
		t.Fatalf("phase57 verification doc path = %q, want %q", got, want)
	}
}

func readPhase57VerificationDoc(t *testing.T) string {
	t.Helper()
	return phase50ReadFile(t, phase57VerificationDocFile())
}

func phase57DocContains(doc, want string) bool {
	normalized := strings.Join(strings.Fields(doc), " ")
	if strings.Contains(doc, want) || strings.Contains(normalized, want) {
		return true
	}
	lowerWant := strings.ToLower(want)
	return strings.Contains(strings.ToLower(doc), lowerWant) ||
		strings.Contains(strings.ToLower(normalized), lowerWant)
}

func phase57VerificationDocFile() string {
	return filepath.Join("..", "docs", "design", phase57VerificationDocPath)
}

func phase57AssertDocumentedCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	for _, want := range []string{
		phase57PolicyFocusedCommand,
		phase57ProofSourcesCommand,
		phase57CredentialFocusedCommand,
		phase57TemplateFocusedCommand,
		phase57SelectionFocusedCommand,
		phase57CommandSurfaceCommand,
		"go test ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	} {
		if !commands[want] {
			t.Fatalf("%s missing command line %q", phase50SafeDisplayPath(phase57VerificationDocFile()), want)
		}
	}
}

func phase57DefaultGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase54DefaultDocumentedCommands(doc) {
		if strings.HasPrefix(command, "go test ") {
			commands = append(commands, command)
		}
	}
	return commands
}

func phase57RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		phase57FocusedTest("./internal/sandbox", "internal/sandbox/security_capability_secure_default_policy_test.go", "TestUS001SecureDefaultReadinessPolicyClassifiesIncompleteEvidence"),
		phase57FocusedTest("./internal/sandbox", "internal/sandbox/security_capability_secure_default_projection_test.go", "TestUS002ProjectSecureDefaultReadinessRequiresActiveMicroVMIsolationProof"),
		phase57FocusedTest("./internal/sandbox", "internal/sandbox/security_capability_secure_default_projection_test.go", "TestProjectSecureDefaultReadinessInputRequiresActiveCredentialActivationProof"),
		phase57FocusedTest("./internal/sandbox", "internal/sandbox/security_capability_template_trust_readiness_test.go", "TestUS004SelectedTemplateStrictReadinessRequiresDigestLockedTrustedEvidence"),
		phase57FocusedTest("./internal/sandbox", "internal/sandbox/security_capability_secure_default_test.go", "TestSecureDefaultReadinessDiagnosticsAndDecisionsAreRedactionSafe"),
		phase57FocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/aggregation_test.go", "TestLiveEnforcementAggregationRequiresBothActiveSides"),
		phase57FocusedTest("./internal/sandboxruntime", "internal/sandboxruntime/types_test.go", "TestRuntimeNetworkEnforcementProxyOnlyProofCannotClaimProxyFirewall"),
		phase57FocusedTest("./internal/sandboxruntime", "internal/sandboxruntime/credential_delivery_projection_test.go", "TestRuntimeCredentialDeliveryProjectsActiveSecureProofSummaries"),
		phase57FocusedTest("./internal/sandboxworker", "internal/sandboxworker/service_test.go", "TestServiceStatusProjectsStrictNetworkSecurityOnlyFromActiveDualProof"),
		phase57FocusedTest("./internal/sandboxworker", "internal/sandboxworker/credential_delivery_projection_test.go", "TestWorkerSecurityProjectsRuntimeCredentialDeliveryProofSummaries"),
		phase57FocusedTest("./internal/credentialdelivery", "internal/credentialdelivery/projection_test.go", "TestUS003StatusMetadataFromActivationRequiresBrokeredProofSummaries"),
		phase57FocusedTest("./internal/factory/credentialactivation", "internal/factory/credentialactivation/broker_activation_proof_test.go", "TestUS003BrokerActivationStatusProjectsStrictProofSummaries"),
		phase57FocusedTest("./internal/sandboxtemplate", "internal/sandboxtemplate/reference_intake_test.go", "TestUS004TemplateReferenceClassificationSeparatesDigestLockedAndMutableInput"),
		phase57FocusedTest("./internal/sandboxtemplate/acquisition", "internal/sandboxtemplate/acquisition/trust_policy_evaluator_test.go", "TestEvaluateTrustPolicyStrictRejectsEveryRolloutPolicyCode"),
		phase57FocusedTest("./internal/sandboxtarget", "internal/sandboxtarget/secure_default_selection_red_test.go", "TestSelectStrictSecureDefaultRejectsMicroVMTargetWithoutCachedReadiness"),
		phase57FocusedTest("./internal/sandboxtarget", "internal/sandboxtarget/import_boundary_test.go", "TestSandboxtargetImportsStayCommandAgnostic"),
		{pkg: "./cmd", file: "us005_command_status_readiness_test.go", testName: "TestUS005CommandStatusReadinessFilesAvoidLiveEnforcementImplementation"},
		{pkg: "./cmd", file: "us006_secure_default_run_surfaces_test.go", testName: "TestUS006RunSandboxStrictSelectionJSONRendersAndPersistsDecision"},
		{pkg: "./cmd", file: "us007_factory_readiness_surfaces_test.go", testName: "TestUS007FactoryStatusSurfacesSecurityReadinessGateSummary"},
		{pkg: "./cmd", file: "phase57_secure_default_selection_docs_test.go", testName: "TestPhase57CommandFactoryStatusSurfacesRemainRenderOnlyConsumers"},
	}
}

func phase57FocusedTest(pkg, relPath, testName string) phase34FocusedTest {
	return phase34FocusedTest{
		pkg:      pkg,
		file:     filepath.Join("..", filepath.FromSlash(relPath)),
		testName: testName,
	}
}

func phase57ForbiddenDefaultCommandMarker(command string) string {
	lower := strings.ToLower(command)
	for _, marker := range []string{
		"-tags=",
		"network_" + "enforcement_live",
		"credential_" + "delivery_live",
		"template_" + "acquisition_live",
		"microvm_" + "e2e_live",
		"firecracker_" + "live",
		"worker_" + "integration",
		"podman_" + "integration",
		"hal_" + "network_" + "enforcement_live",
		"hal_" + "credential_" + "delivery_live",
		"hal_" + "firecracker_" + "live",
		"hal_" + "worker_" + "integration_",
		"hal_" + "podman_",
		"root ",
		"/dev/" + "kvm",
		"k" + "vm",
		"pf" + "ctl",
		"ip" + "tables",
		"nf" + "tables",
		"docker" + " ",
		"podman" + " ",
		"docker" + ".sock",
		"/var/run/" + "docker.sock",
		"cloud credentials",
		"provider credentials",
		"real credentials",
		"real network",
		"live network",
		"live worker",
		"live registr",
		"hcloud_token",
		"digitalocean_access_token",
		"aws_access_key_id",
		"google_application_credentials",
		"hal " + "sandboxd",
		"hal " + "run",
		"curl" + " ",
		"wget" + " ",
		"oras" + " ",
		"crane" + " ",
		"skopeo" + " ",
	} {
		if strings.Contains(lower, marker) {
			return marker
		}
	}
	return ""
}

func phase57CommandFactoryStatusProductionFiles(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, root := range []string{".", filepath.Join("..", "internal", "factory")} {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("ReadDir(%s) error: %v", phase50SafeDisplayPath(root), err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			paths = append(paths, filepath.Join(root, name))
		}
	}
	if len(paths) == 0 {
		t.Fatal("Phase 57 render-only boundary matched no command/factory production files")
	}
	sort.Strings(paths)
	return paths
}

func phase57RenderOnlyImportBoundaryMessage(fileName, importPath string) string {
	switch {
	case importPath == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/"):
		return phase50SafeDisplayPath(fileName) + " imports forbidden Phase 56 network enforcement implementation package " + importPath
	case importPath == "github.com/jywlabs/hal/internal/sandboxtemplate/acquisition" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/"):
		return phase50SafeDisplayPath(fileName) + " imports forbidden Phase 59 template acquisition implementation package " + importPath
	case importPath == "github.com/jywlabs/hal/internal/factory/credentialactivation" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/factory/credentialactivation/"):
		return phase50SafeDisplayPath(fileName) + " imports forbidden Phase 58 credential activation implementation package " + importPath
	}
	return ""
}

func phase57RenderOnlySourceBoundaryMessage(fileName, source string) string {
	for _, forbidden := range []struct {
		token  string
		reason string
	}{
		{token: "EvaluateSandboxSecureDefaultReadiness", reason: "secure-default policy evaluation"},
		{token: "ProjectSandboxSecureDefaultReadinessDiagnostics", reason: "secure-default diagnostic projection"},
		{token: "targetSelectionRequestedSecureDefaultReadinessInput", reason: "target-selection proof construction"},
		{token: "LiveEnforcementRunner", reason: "Phase 56 live network enforcement orchestration"},
		{token: "RunRuleProofStep", reason: "Phase 56 firewall/runtime rule proof execution"},
		{token: "EvaluateTrustPolicy", reason: "Phase 59 template trust policy evaluation"},
		{token: "ResolveOCIArtifact", reason: "Phase 59 template acquisition"},
		{token: "ActivateCredentialDelivery(", reason: "Phase 58 credential activation implementation"},
	} {
		if strings.Contains(source, forbidden.token) {
			return phase50SafeDisplayPath(fileName) + " contains forbidden " + forbidden.reason + " marker " + forbidden.token
		}
	}
	return ""
}

func phase57DesignDocFiles(t *testing.T) []string {
	t.Helper()
	var paths []string
	root := filepath.Join("..", "docs", "design")
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		if strings.Contains(strings.ToLower(filepath.Base(path)), "phase57") {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkDir(%s) error: %v", phase50SafeDisplayPath(root), err)
	}
	return paths
}
