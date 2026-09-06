package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPhase42NetworkProxyEnforcementVerificationDocs(t *testing.T) {
	doc := readPhase42NetworkProxyEnforcementDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 42 adds a fake-safe network proxy enforcement planning layer for sandbox runtime metadata, worker capability projection, sandboxd microVM registration, and microVM runtime metadata.",
		"`internal/sandboxruntime/networkenforcement` owns the runtime-owned network enforcement plan, planner, adapter, result, fake adapter test harness, and import-boundary guards.",
		"`internal/sandbox` keeps requested-versus-enforced security honest.",
		"`internal/sandboxruntime` projects optional network enforcement plan and result metadata through `RuntimeMetadata.networkEnforcement`.",
		"`internal/sandboxworker` can include explicit sanitized network enforcement capability in worker and runtime-driver capability output.",
		"`internal/sandboxruntime/microvm` accepts explicit `NetworkEnforcementPlanning` options.",
		"`internal/sandboxruntime/microvm/firecrackerhost` passes explicit network enforcement planning to the microVM driver through the existing live-driver option boundary.",
		"`cmd/sandboxd.go` does not own network policy parsing, proxy setup, firewall setup, or live listener logic.",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement",
		"go test -count=1 -timeout=180s ./internal/sandbox ./internal/sandboxruntime",
		"go test -count=1 -timeout=180s ./internal/sandboxworker",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase4[2].*Network|NetworkEnforcement|Sandboxd.*Network|SandboxHost.*Network'",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`golangci-lint run ./...` only when `golangci-lint` is installed.",
		"If it is unavailable, report lint unavailable instead of reporting lint as passed.",
		"Passing this matrix satisfies the Phase 42 tests and typecheck gates.",
		"Phase 42 does not implement real proxy listeners, listener socket lifecycle, HTTP proxy routing, reverse proxy setup, firewall mutation, iptables/nftables or pf rule application, credential injection, credential proxy delivery, tmpfs secret delivery, SSH-agent forwarding, production microVM egress, guest network device configuration, Firecracker SDK network configuration, cloud networking, provider/runtime live integration, or live E2E network-policy enforcement.",
		"Future phases are responsible for real proxy listener lifecycle, concrete firewall application, credential injection or broker delivery, production microVM egress controls, Firecracker guest network configuration, host privilege handling, operator documentation, and live E2E network-policy verification.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 42 network proxy enforcement verification documentation missing %q", want)
		}
	}

	phase42AssertVerificationCommands(t, doc)
	phase42AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase42AssertDocumentedFocusedCommandsExecutable(t, doc)

	unsupportedClaims := []string{
		"real proxy listeners are implemented",
		"listener socket lifecycle is implemented",
		"HTTP proxy routing is implemented",
		"reverse proxy setup is implemented",
		"firewall mutation is implemented",
		"iptables rules are applied",
		"nftables rules are applied",
		"pf rules are applied",
		"credential injection is implemented",
		"credential proxy delivery is implemented",
		"production microVM egress is implemented",
		"Firecracker SDK network configuration is implemented",
		"live E2E network-policy enforcement is implemented",
		"metadata-only network proxy sessions prove enforcement",
		"requested deny-by-default policy proves enforcement",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 42 network proxy enforcement documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase42NetworkProxyEnforcementFakeOnlyVerification(t *testing.T) {
	doc := readPhase42NetworkProxyEnforcementDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 42 verification is fake-only.",
		"Phase 42 verification is fake-only. It does not require real network access, live proxy listeners, bound sockets, firewall mutation, credential delivery, credential injection, tmpfs secret writes, SSH-agent forwarding, Docker, Podman, KVM, a Firecracker binary, root privileges, cloud credentials, worker daemons, provider/runtime integration, a live guest, a guest agent, vsock, or a running `hal sandboxd`.",
		"Default Phase 42 tests use pure DTOs, deterministic planner inputs, sanitized public JSON assertions, fake adapter implementations, injected planner and adapter boundaries, fake command dependencies, parsed imports, source guards, temporary state directories, and explicit metadata only.",
		"Default Phase 42 verification must not use integration build tags, the `firecracker_live` build tag, require live environment variables, start a real proxy, bind listener sockets, mutate firewall rules, inject credentials, start a real Firecracker process, access KVM, require root, start worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs, invoke Firecracker SDKs, or depend on live providers or runtime adapters.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 42 network proxy enforcement fake-only documentation missing %q", want)
		}
	}

	commands := phase42DefaultFocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 42 network proxy enforcement verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase34ForbiddenDefaultFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 42 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase42AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase42AssertFocusedTestFilesAvoidLiveDependencies(t)
}

func readPhase42NetworkProxyEnforcementDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase42-network-proxy-enforcement-verification.md"))
	if err != nil {
		t.Fatalf("ReadFile(phase 42 network proxy enforcement verification doc) error: %v", err)
	}
	return string(data)
}

func phase42DefaultFocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "./...") {
			continue
		}
		commands = append(commands, command)
	}
	return commands
}

func phase42AssertVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement",
		"go test -count=1 -timeout=180s ./internal/sandbox ./internal/sandboxruntime",
		"go test -count=1 -timeout=180s ./internal/sandboxworker",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase4[2].*Network|NetworkEnforcement|Sandboxd.*Network|SandboxHost.*Network'",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 42 network proxy enforcement verification documentation missing command line %q", want)
		}
	}
}

func phase42AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase42DefaultFocusedGoTestCommands(doc)
	for _, req := range phase42RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 42 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 42 verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase42RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_evaluator_test.go"), testName: "TestEvaluateSecurityCapabilityReadinessMarksRequestedStrictNetworkEnforcementUnsupportedWithoutSupport"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_evaluator_test.go"), testName: "TestEvaluateSecurityCapabilityReadinessMarksExplicitReadyNetworkEnforcement"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_evaluator_test.go"), testName: "TestEvaluateSecurityCapabilityReadinessDoesNotInferReadyFromLegacyCompatibilityMetadata"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_evaluator_test.go"), testName: "TestEvaluateSecurityCapabilityReadinessTreatsWorkerPostureCapabilitiesAsMetadataOnly"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_test.go"), testName: "TestEffectiveNetworkPolicyCompatibility"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "plan_test.go"), testName: "TestPlanJSONRepresentsRequiredNetworkPosture"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "plan_test.go"), testName: "TestPlanJSONRedactsUnsafeDynamicValues"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "plan_test.go"), testName: "TestPlanJSONDropsUnsafePolicySnapshotAndProxySessionIdentifiers"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "planner_test.go"), testName: "TestBuildPlanConstructsDefaultDenyPrivateAndMetadataPosture"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "planner_test.go"), testName: "TestNormalizeAllowlistRulesSupportsSafeRuleCategories"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "planner_test.go"), testName: "TestBuildPlanNormalizesAllowlistRulesWithoutExposingRawValues"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "planner_test.go"), testName: "TestNormalizeAllowlistRulesRejectsUnsafeValuesWithSanitizedErrors"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "adapter_test.go"), testName: "TestRunAdapterPassesSanitizedPlanAndReturnsSanitizedResult"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "adapter_test.go"), testName: "TestRunAdapterNilAdapterReportsUnsupported"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "fake_adapter_test.go"), testName: "TestFakeEnforcementAdapterSuccessCanClaimStrongerCapability"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "fake_adapter_test.go"), testName: "TestFakeEnforcementAdapterFailureFailsClosed"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "fake_adapter_test.go"), testName: "TestFakeEnforcementAdapterErrorSurfacesAreRedacted"},
		{pkg: "./internal/sandboxruntime/networkenforcement", file: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "import_boundary_test.go"), testName: "TestNetworkEnforcementProductionImportsStayDataOnly"},
		{pkg: "./internal/sandboxruntime", file: filepath.Join("..", "internal", "sandboxruntime", "types_test.go"), testName: "TestRuntimeMetadataIncludesOptionalNetworkEnforcementMetadata"},
		{pkg: "./internal/sandboxruntime", file: filepath.Join("..", "internal", "sandboxruntime", "types_test.go"), testName: "TestRuntimeNetworkEnforcementMetadataSanitizesUnsafeValues"},
		{pkg: "./internal/sandboxruntime", file: filepath.Join("..", "internal", "sandboxruntime", "types_test.go"), testName: "TestRuntimeNetworkEnforcementFailureClearsCapabilityUpgrade"},
		{pkg: "./internal/sandboxruntime", file: filepath.Join("..", "internal", "sandboxruntime", "import_boundary_test.go"), testName: "TestSandboxruntimeNetworkEnforcementProjectionImportsStayMetadataOnly"},
		{pkg: "./internal/sandboxworker", file: filepath.Join("..", "internal", "sandboxworker", "types_test.go"), testName: "TestWorkerSecurityPolicyAllowsExplicitNetworkEnforcementCapability"},
		{pkg: "./internal/sandboxworker", file: filepath.Join("..", "internal", "sandboxworker", "service_test.go"), testName: "TestServiceMicroVMCapabilityOutputDoesNotClaimDefaultNetworkEnforcement"},
		{pkg: "./internal/sandboxworker", file: filepath.Join("..", "internal", "sandboxworker", "service_test.go"), testName: "TestServiceCapabilitiesCanIncludeExplicitNetworkEnforcementCapability"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestDriverMetadataProjectsExplicitNetworkEnforcementAdapterSuccessAndFailure"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestDriverNetworkEnforcementPlanningUsesInjectedBoundaryOnlyWhenConfigured"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestDriverNetworkEnforcementPlanningWithoutAdapterFailsClosed"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMNetworkEnforcementPlanningImportsStayBoundaryOnly"},
		{pkg: "./internal/sandboxruntime/microvm/firecrackerhost", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "live_driver_test.go"), testName: "TestNewLiveDriverPassesExplicitNetworkEnforcementPlanningToMicroVMDriver"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdDefaultCapabilitiesDoNotClaimNetworkPolicyEnforcement"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdMicroVMDescriptorCanAdvertiseExplicitNetworkEnforcementCapability"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdRuntimeRegistrationRequestsNetworkPlanOnlyForExplicitMicroVMPath"},
		{pkg: "./cmd", file: "sandboxd_safety_test.go", testName: "TestSandboxdProductionCodeDoesNotOwnNetworkEnforcementPlanningOrSetup"},
		{pkg: "./cmd", file: "sandbox_host_mapping_test.go", testName: "TestSandboxHostFromWorkerMetadataMapsExplicitNetworkEnforcementCapability"},
		{pkg: "./cmd", file: "phase42_network_proxy_enforcement_docs_test.go", testName: "TestPhase42NetworkProxyEnforcementVerificationDocs"},
		{pkg: "./cmd", file: "phase42_network_proxy_enforcement_docs_test.go", testName: "TestPhase42NetworkProxyEnforcementFakeOnlyVerification"},
	}
}

func phase42AssertDocumentedFocusedCommandsExecutable(t *testing.T, doc string) {
	t.Helper()
	for _, command := range phase42DefaultFocusedGoTestCommands(doc) {
		fields := strings.Fields(command)
		if len(fields) < 3 || fields[0] != "go" || fields[1] != "test" {
			t.Fatalf("phase 42 focused verification command %q is not a go test command", command)
		}
		if selector, ok := phase34FocusedCommandRunSelector(t, command); ok {
			if _, err := regexp.Compile(selector); err != nil {
				t.Fatalf("phase 42 focused verification command %q has invalid -run selector %q: %v", command, selector, err)
			}
		}
		hasPackage := false
		for _, field := range fields[2:] {
			pkg := strings.Trim(field, "'\"")
			if !strings.HasPrefix(pkg, "./") || strings.Contains(pkg, "...") {
				continue
			}
			hasPackage = true
			dir := strings.TrimPrefix(pkg, "./")
			if _, err := os.Stat(filepath.Join("..", dir)); err != nil {
				t.Fatalf("phase 42 focused verification command %q references missing package %s: %v", command, pkg, err)
			}
		}
		if !hasPackage {
			t.Fatalf("phase 42 focused verification command %q does not reference an executable package", command)
		}
	}
}

func phase42AssertFocusedTestFilesAvoidLiveDependencies(t *testing.T) {
	t.Helper()
	seen := map[string]bool{}
	for _, req := range phase42RequiredFocusedTests() {
		if seen[req.file] {
			continue
		}
		seen[req.file] = true
		phase34AssertNoLiveIntegrationBuildTag(t, req.file)
		phase34AssertDefaultTestFileAvoidsLiveImports(t, req.file)
	}
}
