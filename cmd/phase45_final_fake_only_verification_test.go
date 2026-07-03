package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phase45FinalFakeOnlyDocPath = "sandbox-runtime-v2-phase45-final-fake-only-verification.md"

func TestPhase45FinalFakeOnlyVerificationDocumentation(t *testing.T) {
	doc := readPhase45FinalFakeOnlyDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 45 final verification barrier is fake-only.",
		"network enforcement contracts",
		"listener lifecycle",
		"firewall/runtime rule lifecycle",
		"aggregation",
		"runtime projection",
		"microVM metadata",
		"command and sandboxd security metadata",
		"worker descriptors",
		"optional live-test and documentation guards",
		"Default Phase 45 verification is fake-only and does not require network egress, listener binding, root privileges, firewall mutation, KVM, Docker, Podman, Firecracker, hypervisor runtime dependencies, live environment variables, `hal sandboxd`, or optional live build tags.",
		"Optional live coverage remains documented but excluded from the default matrix.",
		"`HAL_NETWORK_ENFORCEMENT_LIVE=1`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=1`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=1`",
		"`hal convert <generated-prd-md> --validate --json`",
		"plain convert command, not the granular convert mode",
		"dependsOn",
		"conflictDomains",
		"parallelSafe",
		"barrier",
		"US-010 is the only barrier story.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 45 final fake-only verification documentation missing %q", want)
		}
	}
	if strings.Contains(doc, "hal convert --granular") || strings.Contains(normalizedDoc, "hal convert --granular") {
		t.Fatal("phase 45 final verification must name the plain conversion command and must not recommend granular conversion")
	}

	phase45FinalAssertDocumentedCommands(t, doc)
	phase45AssertOptionalLiveCommand(t, doc)
	phase45AssertDefaultCommandsAvoidLiveOptIn(t, doc)
}

func TestPhase45FinalFakeOnlyVerificationCommandsCoverRequiredSelectors(t *testing.T) {
	doc := readPhase45FinalFakeOnlyDoc(t)
	commands := phase45FinalDefaultGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 45 final verification documentation must list default go test commands")
	}

	for _, req := range phase45FinalRequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 45 final verification documentation missing focused command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 45 final verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func TestPhase45FinalFakeOnlyVerificationStaysFakeOnlyByDefault(t *testing.T) {
	doc := readPhase45FinalFakeOnlyDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	for _, want := range []string{
		"Default Phase 45 verification is fake-only",
		"does not require network egress, listener binding, root privileges, firewall mutation, KVM, Docker, Podman, Firecracker, hypervisor runtime dependencies, live environment variables, `hal sandboxd`, or optional live build tags.",
	} {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 45 final fake-only documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"default verification requires network egress",
		"default verification requires listener binding",
		"default verification requires root privileges",
		"default verification requires firewall mutation",
		"default verification requires KVM",
		"default verification requires Docker",
		"default verification requires Podman",
		"default verification requires Firecracker",
		"default verification requires hypervisor runtime dependencies",
		"default verification requires live environment variables",
		"default verification runs network_enforcement_live",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 45 final fake-only documentation makes unsupported default requirement claim %q", claim)
		}
	}

	for _, command := range phase45FinalDefaultGoTestCommands(doc) {
		for _, forbidden := range append(phase34ForbiddenDefaultFocusedCommandRequirements(), phase45FinalForbiddenDefaultMarkers()...) {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 45 final default command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	for _, path := range phase45FinalFakeOnlyGuardedTestFiles() {
		phase34AssertNoLiveIntegrationBuildTag(t, path)
		phase34AssertDefaultTestFileAvoidsLiveImports(t, path)
	}
}

func TestPhase45FinalFakeOnlyVerificationDocumentsPRDScheduleMetadata(t *testing.T) {
	doc := readPhase45FinalFakeOnlyDoc(t)
	requiredRows := []string{
		"| US-001 | [] | sandboxruntime/networkenforcement/contracts | false | false |",
		"| US-002 | US-001 | sandboxruntime/networkenforcement/lifecycle | false | false |",
		"| US-003 | US-001 | sandboxruntime/networkenforcement/lifecycle | false | false |",
		"| US-004 | US-002, US-003 | sandboxruntime/networkenforcement/lifecycle | false | false |",
		"| US-005 | US-004 | sandboxruntime/network-metadata | false | false |",
		"| US-006 | US-005 | sandboxruntime/microvm/network-metadata | false | false |",
		"| US-007 | US-005, US-006 | cmd/sandboxd-security-metadata | false | false |",
		"| US-008 | US-005 | sandboxworker/security-descriptor | false | false |",
		"| US-009 | US-001, US-004 | docs/network-enforcement | true | false |",
		"| US-010 | US-001, US-002, US-003, US-004, US-005, US-006, US-007, US-008, US-009 | sandboxruntime/networkenforcement/contracts; sandboxruntime/networkenforcement/lifecycle; sandboxruntime/network-metadata; sandboxruntime/microvm/network-metadata; cmd/sandboxd-security-metadata; sandboxworker/security-descriptor; docs/network-enforcement | false | true |",
	}
	for _, row := range requiredRows {
		if !strings.Contains(doc, row) {
			t.Fatalf("phase 45 final PRD scheduling documentation missing row %q", row)
		}
	}
}

func readPhase45FinalFakeOnlyDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", phase45FinalFakeOnlyDocPath))
	if err != nil {
		t.Fatalf("ReadFile(phase 45 final fake-only verification doc) error: %v", err)
	}
	return string(data)
}

func phase45FinalAssertDocumentedCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement -run 'Test(LiveLifecycleJSONRepresentsProxyAndRuleState|NetworkEnforcementProductionImportsStayDataOnly|NetworkEnforcementImportBoundaryCoversPlanningAndAdapterFiles|NetworkEnforcementForbiddenImportListCoversLiveSurfaces|NetworkEnforcementImportBoundaryAllowsMetadataHelpersOnly|ProxyListenerLifecycleRunner|RuleLifecycleRunner|LiveEnforcement(Aggregation|Runner))'",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime -run 'Test(SandboxruntimeNetworkEnforcement|RuntimeNetworkEnforcement)'",
		"go test -count=1 -timeout=180s -run 'Test(Driver.*NetworkEnforcement|MicroVMNetworkEnforcement|BackendNetworkEnforcement|NewLiveDriverPassesExplicitNetworkEnforcementPlanningToMicroVMDriver)' ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecrackerhost ./internal/sandboxruntime/microvm/firecracker",
		"go test -count=1 -timeout=180s ./cmd -run 'Test(CommandAndSandboxdProductionSecurityPathsAvoidLiveMutationDependencies|Sandboxd.*Network|SandboxHostFromWorkerMetadataMapsExplicitNetworkEnforcementCapability|Phase45(NetworkEnforcement|FinalFakeOnly))'",
		"go test -count=1 -timeout=180s ./internal/sandboxworker -run 'Test(ServiceMicroVMCapabilityOutputDoesNotClaimDefaultNetworkEnforcement|ServiceRuntimeDriverDescriptorProjectsNetworkSecurityFromActiveMetadataOnly|ServiceCapabilitiesCanIncludeExplicitNetworkEnforcementCapability|WorkerSecurityPolicy(DistinguishesRequestedFromEnforcedControls|RejectsOverstatedCapabilityClaims|AllowsExplicitNetworkEnforcementCapability))'",
		"go test -count=1 -timeout=300s ./internal/sandboxruntime/networkenforcement ./internal/sandboxruntime ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecrackerhost ./cmd ./internal/sandboxworker ./internal/sandboxruntime/microvm/firecracker",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 45 final verification documentation missing command line %q", want)
		}
	}
	if !strings.Contains(doc, "hal convert <generated-prd-md> --validate --json") {
		t.Fatal("phase 45 final verification documentation missing plain hal convert command")
	}
}

func phase45FinalDefaultGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "network_enforcement_live") {
			continue
		}
		commands = append(commands, command)
	}
	return commands
}

func phase45FinalRequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/live_contracts_test.go", "TestLiveLifecycleJSONRepresentsProxyAndRuleState"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/import_boundary_test.go", "TestNetworkEnforcementProductionImportsStayDataOnly"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/import_boundary_test.go", "TestNetworkEnforcementImportBoundaryCoversPlanningAndAdapterFiles"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/listener_lifecycle_test.go", "TestProxyListenerLifecycleRunnerStartAndStopSequence"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/listener_lifecycle_test.go", "TestProxyListenerLifecycleRunnerFailureStopsPartialListener"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/listener_lifecycle_test.go", "TestProxyListenerLifecycleRunnerReportsCleanupFailureAsSanitizedWarning"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/rule_lifecycle_test.go", "TestRuleLifecycleRunnerApplyAndCleanupSequence"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/rule_lifecycle_test.go", "TestRuleLifecycleRunnerApplyFailureRollsBackPartialRules"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/rule_lifecycle_test.go", "TestRuleLifecycleRunnerActiveCheckFailureRollsBackAppliedRules"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/rule_lifecycle_test.go", "TestRuleLifecycleRunnerUsesFakeAdapterOnly"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/aggregation_test.go", "TestLiveEnforcementAggregationRequiresBothActiveSides"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/aggregation_test.go", "TestLiveEnforcementAggregationDowngradesPartialAndMetadataOnlyResults"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/aggregation_test.go", "TestLiveEnforcementRunnerOrchestratesBothSidesBeforeClaimingStrongMode"),
		phase45FinalFocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/aggregation_test.go", "TestLiveEnforcementRunnerFailsClosedForNilAndPartialAdapters"),
		phase45FinalFocusedTest("./internal/sandboxruntime", "internal/sandboxruntime/import_boundary_test.go", "TestSandboxruntimeNetworkEnforcementProjectionImportsStayMetadataOnly"),
		phase45FinalFocusedTest("./internal/sandboxruntime", "internal/sandboxruntime/types_test.go", "TestRuntimeNetworkEnforcementFailureClearsCapabilityUpgrade"),
		phase45FinalFocusedTest("./internal/sandboxruntime", "internal/sandboxruntime/types_test.go", "TestRuntimeNetworkEnforcementProjectionDowngradesNonEnforcingResults"),
		phase45FinalFocusedTest("./internal/sandboxruntime/microvm", "internal/sandboxruntime/microvm/driver_test.go", "TestDriverNetworkEnforcementPlanningUsesInjectedBoundaryOnlyWhenConfigured"),
		phase45FinalFocusedTest("./internal/sandboxruntime/microvm", "internal/sandboxruntime/microvm/driver_test.go", "TestDriverNetworkEnforcementMetadataOptionsAreClonedSanitizedAdditiveAndInert"),
		phase45FinalFocusedTest("./internal/sandboxruntime/microvm", "internal/sandboxruntime/microvm/import_boundary_test.go", "TestMicroVMNetworkEnforcementPlanningImportsStayBoundaryOnly"),
		phase45FinalFocusedTest("./internal/sandboxruntime/microvm/firecracker", "internal/sandboxruntime/microvm/firecracker/backend_test.go", "TestBackendNetworkEnforcementMetadataIsClonedSanitizedAndPlanningOnly"),
		phase45FinalFocusedTest("./internal/sandboxruntime/microvm/firecracker", "internal/sandboxruntime/microvm/firecracker/backend_test.go", "TestBackendNetworkEnforcementMetadataDoesNotBreakMicroVMPlanningConstruction"),
		phase45FinalFocusedTest("./internal/sandboxruntime/microvm/firecrackerhost", "internal/sandboxruntime/microvm/firecrackerhost/live_driver_test.go", "TestNewLiveDriverPassesExplicitNetworkEnforcementPlanningToMicroVMDriver"),
		{pkg: "./cmd", file: "sandboxd_safety_test.go", testName: "TestCommandAndSandboxdProductionSecurityPathsAvoidLiveMutationDependencies"},
		{pkg: "./cmd", file: "sandboxd_safety_test.go", testName: "TestSandboxdProductionCodeDoesNotOwnNetworkEnforcementPlanningOrSetup"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdMicroVMDescriptorDoesNotClaimNetworkEnforcementFromPlanOnlyMetadata"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdMicroVMDescriptorRequiresActiveNetworkRuntimeMetadataBeforeEnforcedPolicy"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdRuntimeRegistrationRequestsNetworkPlanOnlyForExplicitMicroVMPath"},
		{pkg: "./cmd", file: "sandbox_host_mapping_test.go", testName: "TestSandboxHostFromWorkerMetadataMapsExplicitNetworkEnforcementCapability"},
		{pkg: "./cmd", file: "phase45_network_enforcement_live_guard_test.go", testName: "TestPhase45NetworkEnforcementLiveGuardDocumentation"},
		{pkg: "./cmd", file: "phase45_network_enforcement_live_guard_test.go", testName: "TestPhase45NetworkEnforcementLiveTestsRequireExplicitOptIn"},
		{pkg: "./cmd", file: "phase45_network_enforcement_live_guard_test.go", testName: "TestPhase45NetworkEnforcementDocsAvoidDefaultLiveClaims"},
		{pkg: "./cmd", file: "phase45_final_fake_only_verification_test.go", testName: "TestPhase45FinalFakeOnlyVerificationDocumentation"},
		phase45FinalFocusedTest("./internal/sandboxworker", "internal/sandboxworker/service_test.go", "TestServiceMicroVMCapabilityOutputDoesNotClaimDefaultNetworkEnforcement"),
		phase45FinalFocusedTest("./internal/sandboxworker", "internal/sandboxworker/service_test.go", "TestServiceRuntimeDriverDescriptorProjectsNetworkSecurityFromActiveMetadataOnly"),
		phase45FinalFocusedTest("./internal/sandboxworker", "internal/sandboxworker/service_test.go", "TestServiceCapabilitiesCanIncludeExplicitNetworkEnforcementCapability"),
		phase45FinalFocusedTest("./internal/sandboxworker", "internal/sandboxworker/types_test.go", "TestWorkerSecurityPolicyDistinguishesRequestedFromEnforcedControls"),
		phase45FinalFocusedTest("./internal/sandboxworker", "internal/sandboxworker/types_test.go", "TestWorkerSecurityPolicyRejectsOverstatedCapabilityClaims"),
		phase45FinalFocusedTest("./internal/sandboxworker", "internal/sandboxworker/types_test.go", "TestWorkerSecurityPolicyAllowsExplicitNetworkEnforcementCapability"),
	}
}

func phase45FinalFocusedTest(pkg, relPath, testName string) phase34FocusedTest {
	return phase34FocusedTest{
		pkg:      pkg,
		file:     filepath.Join("..", filepath.FromSlash(relPath)),
		testName: testName,
	}
}

func phase45FinalForbiddenDefaultMarkers() []string {
	return []string{
		"-tags=network_enforcement_live",
		"network_enforcement_live",
		"HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_NETWORK_ENFORCEMENT_LIVE_PROXY",
		"HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL",
	}
}

func phase45FinalFakeOnlyGuardedTestFiles() []string {
	seen := map[string]bool{}
	var files []string
	for _, req := range phase45FinalRequiredFocusedTests() {
		if seen[req.file] {
			continue
		}
		seen[req.file] = true
		files = append(files, req.file)
	}
	for _, file := range []string{
		"phase45_final_fake_only_verification_test.go",
		"phase45_network_enforcement_live_guard_test.go",
	} {
		if !seen[file] {
			seen[file] = true
			files = append(files, file)
		}
	}
	return files
}

func TestPhase45FinalFakeOnlyVerificationDocPathStable(t *testing.T) {
	if got, want := phase45FinalFakeOnlyDocPath, "sandbox-runtime-v2-phase45-final-fake-only-verification.md"; got != want {
		t.Fatalf("phase45 final doc path = %q, want %q", got, want)
	}
}
