package cmd

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	phase56LiveGateDocPath = "sandbox-runtime-v2-phase56-live-gate-default-fake-only-verification.md"
	phase56GuardFile       = "cmd/phase56_live_gate_docs_test.go"

	phase56NetworkEnforcementFocusedCommand = "go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement -run 'Test(LiveEnforcementAggregationRequires(DefaultDenyRuleCapabilityProof|BothActiveSides)|LiveEnforcementAggregationDowngradesPartialAndMetadataOnlyResults|LiveEnforcementRunner(FailsClosedForNilAndPartialAdapters|OrchestratesBothSidesBeforeClaimingStrongMode)|RuleProofAdapters(RepresentFirewallAndRuntimeLifecycle|NilDisabledDefaultBuildAndBestEffortNeverStrictReady)|RuleProofLiveGateSeamsRequireBuildTagAndEnvironmentMarkers|NetworkEnforcementProductionImportsStayDataOnly|NetworkEnforcementForbiddenImportListCoversLiveSurfaces|Phase56NetworkEnforcementImportBoundaryRejectsCommandFactoryAndCobra)'"
	phase56RuntimeWorkerFocusedCommand      = "go test -count=1 -timeout=180s ./internal/sandboxruntime ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecrackerhost ./internal/sandboxworker -run 'Test(RuntimeNetworkEnforcement(ProxyOnlyProofCannotClaimProxyFirewall|FailureClearsCapabilityUpgrade)|GatedNetworkEnforcementPlanning(RoutesThroughRuntimeContracts|MissingGateDoesNotInvokeLiveAdapters|DisabledRuleAdapterDoesNotSatisfyStrictReadiness)|LiveNetworkEnforcementPlanningDefaultBuildIgnoresEnvGatesAndDoesNotInvokeAdapters|NewLiveDriver(CanUseMicroVMGatedNetworkEnforcementWiring|NetworkEnforcement(MissingGateDoesNotStartProxyOrRules|LiveOptionUsesBuildTagGate))|ServiceStatusProjects(ProxyActiveNetworkEnforcementProof|StrictNetworkSecurityOnlyFromActiveDualProof)|ServiceStatusDoesNotUpgradeNetworkEnforcementWithoutActiveSuccessfulProxyProof)'"
	phase56CommandFocusedCommand            = "go test -count=1 -timeout=180s ./cmd -run 'Test(Phase50DefaultGoTestSuiteDoesNotRequireLivePrerequisites|US005(CommandNetworkSecurityDowngradesProxyFirewallWithoutRuntimeProof|SandboxRuntimeStatusJSONRequiresActiveDualNetworkProof|FactoryStrictReadinessBlocksDowngradedProxyFirewallMetadata|CommandStatusReadinessFilesAvoidLiveEnforcementImplementation)|Phase55CommandProductionCodeDoesNotOwnPolicyProxyImplementation|Phase56(LiveGateDocumentation|DefaultCommandsStayFakeOnly|DocumentedFocusedSelectorsMatchTestsAndPackages|CommandProductionCodeDoesNotOwnFirewallProxyOrRuntimeImplementation|SingleFinalDocsGuardStory))'"
	phase56OptionalNetworkLiveCommand       = "env HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> HAL_NETWORK_ENFORCEMENT_LIVE_RUNTIME=<set> go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'"
)

func TestPhase56LiveGateDocumentation(t *testing.T) {
	doc := readPhase56LiveGateDoc(t)
	normalized := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 56 final live-gate documentation and default fake-only guard is the only explicit final docs/guard barrier story for Phase 56.",
		"secure-default invariant: `proxy_firewall` with `deny_by_default` is reported only after sanitized active proxy proof and active firewall or runtime rule proof.",
		"Default Phase 56 verification is fake-only.",
		"must not require root, KVM, pfctl, iptables, nftables, Docker, Podman, cloud credentials, real network egress, or live worker daemons.",
		"Optional live checks are outside the default matrix.",
		"`network_enforcement_live`",
		"`microvm_e2e_live`",
		"`firecracker_live`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_PROXY`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL`",
		"`HAL_NETWORK_ENFORCEMENT_LIVE_RUNTIME`",
		"`proxy` means active proxy proof without active firewall or runtime rule proof.",
		"`proxy_firewall` means active proxy proof plus active firewall or runtime rule proof.",
		"`best_effort` means partial, advisory, unsupported, warning-bearing, or compatibility enforcement that must not satisfy strict readiness.",
		"`deny_by_default` means the requested/effective default-deny network posture, not proof by itself.",
		"US-006 is the only explicit final docs/guard barrier story for Phase 56.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("%s missing required Phase 56 text %q", phase50SafeDisplayPath(phase56LiveGateDocFile()), want)
		}
	}

	phase56AssertDocumentedCommands(t, doc)
}

func TestPhase56DefaultCommandsStayFakeOnly(t *testing.T) {
	doc := readPhase56LiveGateDoc(t)
	defaultCommands := phase54DefaultDocumentedCommands(doc)
	if len(defaultCommands) == 0 {
		t.Fatal("Phase 56 documentation must list default fake-only command lines")
	}
	for _, command := range defaultCommands {
		for _, forbidden := range phase56ForbiddenDefaultCommandMarkers() {
			if strings.Contains(strings.ToLower(command), strings.ToLower(forbidden)) {
				t.Fatalf("Phase 56 default command %q contains forbidden live/default dependency marker %q", command, forbidden)
			}
		}
	}

	optionalCommands := phase54OptionalLiveDocumentedCommands(doc)
	if len(optionalCommands) == 0 {
		t.Fatal("Phase 56 documentation must keep optional live commands in an optional live verification section")
	}
	for command := range optionalCommands {
		if !strings.HasPrefix(command, "env ") || !strings.Contains(command, " go test ") || !strings.Contains(command, "-tags=") {
			t.Fatalf("Phase 56 optional live command %q must stay env-gated, tagged, and outside the default matrix", command)
		}
	}
}

func TestPhase56DocumentedFocusedSelectorsMatchTestsAndPackages(t *testing.T) {
	doc := readPhase56LiveGateDoc(t)
	for _, command := range phase56DocumentedGoTestCommands(doc) {
		runSelector, ok := phase54CommandRunSelector(command)
		if !ok || runSelector == "^$" {
			continue
		}
		packages := phase54CommandPackageSelectors(command)
		if len(packages) == 0 {
			t.Fatalf("%s focused go test command %q has no package selector", phase50SafeDisplayPath(phase56LiveGateDocFile()), command)
		}
		for _, packageSelector := range packages {
			phase54AssertPackageSelectorExists(t, packageSelector, command)
			phase54AssertRunSelectorMatchesPackageTests(t, runSelector, packageSelector, command)
		}
	}

	commands := phase56DocumentedGoTestCommands(doc)
	for _, req := range phase56RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("Phase 56 documentation missing focused command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 56 focused test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func TestPhase56CommandProductionCodeDoesNotOwnFirewallProxyOrRuntimeImplementation(t *testing.T) {
	for _, path := range phase55CommandProductionFiles(t) {
		source := phase55ReadCommandProductionFile(t, path)
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := phase56CommandImplementationImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
		if message := phase56CommandImplementationSourceBoundaryMessage(path, string(source)); message != "" {
			t.Fatal(message)
		}
	}
}

func TestPhase56CommandImplementationBoundaryRejectsFixtures(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "network enforcement import",
			source: `package cmd; import "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"; func run() {}`,
			want:   "network enforcement implementation package",
		},
		{
			name:   "proxy lifecycle service",
			source: `package cmd; func run() { _ = PolicyProxyLifecycleService{} }`,
			want:   "PolicyProxyLifecycleService",
		},
		{
			name:   "firewall rule proof adapter",
			source: `package cmd; func run() { _ = NewLiveFirewallRuleProofAdapter }`,
			want:   "NewLiveFirewallRuleProofAdapter",
		},
		{
			name:   "runtime rule proof runner",
			source: `package cmd; func run() { _ = RunRuleProofStep }`,
			want:   "RunRuleProofStep",
		},
		{
			name:   "live aggregation",
			source: `package cmd; func run() { _ = AggregateLiveEnforcementResult }`,
			want:   "AggregateLiveEnforcementResult",
		},
		{
			name:   "firewall command",
			source: `package cmd; func run() { _ = "pfctl -f <redacted>" }`,
			want:   "pfctl",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", []byte(tt.source), parser.ImportsOnly)
			if err != nil {
				t.Fatalf("ParseFile(%s) error: %v", tt.name, err)
			}
			for _, spec := range file.Imports {
				importPath, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatalf("unquote import %s: %v", spec.Path.Value, err)
				}
				if message := phase56CommandImplementationImportBoundaryMessage(tt.name+".go", importPath); message != "" {
					if !strings.Contains(message, tt.want) {
						t.Fatalf("boundary message = %q, want marker %q", message, tt.want)
					}
					return
				}
			}
			message := phase56CommandImplementationSourceBoundaryMessage(tt.name+".go", tt.source)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want marker %q", message, tt.want)
			}
		})
	}
}

func TestPhase56SingleFinalDocsGuardStory(t *testing.T) {
	doc := readPhase56LiveGateDoc(t)
	for _, want := range []string{
		"| US-006 | US-002, US-003, US-004, US-005 | docs/guards; cmd; internal/sandboxruntime/networkenforcement; internal/sandboxruntime/microvm; internal/sandboxworker | false | true |",
		"US-006 is the only explicit final docs/guard barrier story for Phase 56.",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("Phase 56 barrier documentation missing %q", want)
		}
	}

	var barrierDocs []string
	for _, path := range phase56DesignDocFiles(t) {
		source := phase50ReadFile(t, path)
		if strings.Contains(source, "explicit final docs/guard barrier story for Phase 56") {
			barrierDocs = append(barrierDocs, phase50SafeDisplayPath(path))
		}
	}
	if len(barrierDocs) != 1 || barrierDocs[0] != phase50SafeDisplayPath(phase56LiveGateDocFile()) {
		t.Fatalf("Phase 56 final docs/guard barrier docs = %#v, want only %s", barrierDocs, phase50SafeDisplayPath(phase56LiveGateDocFile()))
	}
}

func TestPhase56GuardFileStaysInLiveMarkerAllowlists(t *testing.T) {
	if !phase50ApprovedLiveMarkerFiles()[phase56GuardFile] {
		t.Fatalf("%s must stay in the Phase 50 live marker allowlist because it documents optional live marker names", phase56GuardFile)
	}
	if !us010ApprovedLiveE2EGuardFiles()[phase56GuardFile] {
		t.Fatalf("%s must stay in the Phase 53 live E2E marker allowlist because it documents optional live marker names", phase56GuardFile)
	}
}

func TestPhase56LiveGateDocPathStable(t *testing.T) {
	if got, want := phase56LiveGateDocPath, "sandbox-runtime-v2-phase56-live-gate-default-fake-only-verification.md"; got != want {
		t.Fatalf("phase56 doc path = %q, want %q", got, want)
	}
}

func readPhase56LiveGateDoc(t *testing.T) string {
	t.Helper()
	return phase50ReadFile(t, phase56LiveGateDocFile())
}

func phase56LiveGateDocFile() string {
	return filepath.Join("..", "docs", "design", phase56LiveGateDocPath)
}

func phase56AssertDocumentedCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	for _, want := range []string{
		phase56NetworkEnforcementFocusedCommand,
		phase56RuntimeWorkerFocusedCommand,
		phase56CommandFocusedCommand,
		"go test ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	} {
		if !commands[want] {
			t.Fatalf("Phase 56 documentation missing command line %q", want)
		}
	}
	if !phase54OptionalLiveDocumentedCommands(doc)[phase56OptionalNetworkLiveCommand] {
		t.Fatalf("Phase 56 documentation missing optional live command line %q", phase56OptionalNetworkLiveCommand)
	}
}

func phase56DocumentedGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		commands = append(commands, command)
	}
	for command := range phase54OptionalLiveDocumentedCommands(doc) {
		if strings.Contains(command, " go test ") {
			commands = append(commands, command[strings.Index(command, "go test "):])
		}
	}
	return commands
}

func phase56RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		phase56FocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/aggregation_test.go", "TestLiveEnforcementAggregationRequiresDefaultDenyRuleCapabilityProof"),
		phase56FocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/aggregation_test.go", "TestLiveEnforcementAggregationDowngradesPartialAndMetadataOnlyResults"),
		phase56FocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/aggregation_test.go", "TestLiveEnforcementRunnerFailsClosedForNilAndPartialAdapters"),
		phase56FocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/rule_proof_adapter_test.go", "TestRuleProofLiveGateSeamsRequireBuildTagAndEnvironmentMarkers"),
		phase56FocusedTest("./internal/sandboxruntime/networkenforcement", "internal/sandboxruntime/networkenforcement/import_boundary_test.go", "TestPhase56NetworkEnforcementImportBoundaryRejectsCommandFactoryAndCobra"),
		phase56FocusedTest("./internal/sandboxruntime", "internal/sandboxruntime/types_test.go", "TestRuntimeNetworkEnforcementProxyOnlyProofCannotClaimProxyFirewall"),
		phase56FocusedTest("./internal/sandboxruntime/microvm", "internal/sandboxruntime/microvm/network_enforcement_wiring_test.go", "TestGatedNetworkEnforcementPlanningMissingGateDoesNotInvokeLiveAdapters"),
		phase56FocusedTest("./internal/sandboxruntime/microvm", "internal/sandboxruntime/microvm/network_enforcement_live_wiring_tag_off_test.go", "TestLiveNetworkEnforcementPlanningDefaultBuildIgnoresEnvGatesAndDoesNotInvokeAdapters"),
		phase56FocusedTest("./internal/sandboxruntime/microvm/firecrackerhost", "internal/sandboxruntime/microvm/firecrackerhost/network_enforcement_live_wiring_test.go", "TestNewLiveDriverNetworkEnforcementMissingGateDoesNotStartProxyOrRules"),
		phase56FocusedTest("./internal/sandboxworker", "internal/sandboxworker/service_test.go", "TestServiceStatusProjectsStrictNetworkSecurityOnlyFromActiveDualProof"),
		{pkg: "./cmd", file: "phase50_default_live_gate_guard_test.go", testName: "TestPhase50DefaultGoTestSuiteDoesNotRequireLivePrerequisites"},
		{pkg: "./cmd", file: "us005_command_status_readiness_test.go", testName: "TestUS005SandboxRuntimeStatusJSONRequiresActiveDualNetworkProof"},
		{pkg: "./cmd", file: "phase55_import_boundary_test.go", testName: "TestPhase55CommandProductionCodeDoesNotOwnPolicyProxyImplementation"},
		{pkg: "./cmd", file: "phase56_live_gate_docs_test.go", testName: "TestPhase56CommandProductionCodeDoesNotOwnFirewallProxyOrRuntimeImplementation"},
	}
}

func phase56FocusedTest(pkg, relPath, testName string) phase34FocusedTest {
	return phase34FocusedTest{
		pkg:      pkg,
		file:     filepath.Join("..", filepath.FromSlash(relPath)),
		testName: testName,
	}
}

func phase56ForbiddenDefaultCommandMarkers() []string {
	return []string{
		"-tags=",
		"network_enforcement_live",
		"microvm_e2e_live",
		"firecracker_live",
		"credential_delivery_live",
		"worker_integration",
		"podman_integration",
		"HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_FIRECRACKER_LIVE",
		"HAL_CREDENTIAL_DELIVERY_LIVE",
		"HAL_WORKER_INTEGRATION_",
		"HAL_PODMAN_",
		"root ",
		"/dev/kvm",
		"kvm",
		"pfctl",
		"iptables",
		"nftables",
		"docker ",
		"podman ",
		"cloud credentials",
		"real network",
		"live worker",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"hal sandboxd",
		"curl ",
	}
}

func phase56CommandImplementationImportBoundaryMessage(fileName, importPath string) string {
	if strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement") {
		return "cmd file " + fileName + " imports forbidden network enforcement implementation package " + importPath
	}
	lower := strings.ToLower(importPath)
	for _, marker := range []string{"iptables", "nftables", "pfctl", "firewallctl"} {
		if strings.Contains(lower, marker) {
			return "cmd file " + fileName + " imports forbidden firewall implementation package " + importPath
		}
	}
	return ""
}

func phase56CommandImplementationSourceBoundaryMessage(fileName, source string) string {
	for _, forbidden := range []struct {
		token  string
		reason string
	}{
		{token: "EvaluatePolicyProxyDecision", reason: "policy proxy decision evaluation"},
		{token: "PolicyProxyLifecycleService", reason: "policy proxy lifecycle service"},
		{token: "NewPolicyProxyEnforcementAdapter", reason: "policy proxy adapter construction"},
		{token: "StartPolicyProxy", reason: "policy proxy start lifecycle"},
		{token: "ActivePolicyProxy", reason: "policy proxy active lifecycle"},
		{token: "StopPolicyProxy", reason: "policy proxy stop lifecycle"},
		{token: "NewFirewallRuleProofAdapter", reason: "firewall rule proof adapter construction"},
		{token: "NewRuntimeRuleProofAdapter", reason: "runtime rule proof adapter construction"},
		{token: "NewGatedFirewallRuleProofAdapter", reason: "firewall rule proof live gate construction"},
		{token: "NewGatedRuntimeRuleProofAdapter", reason: "runtime rule proof live gate construction"},
		{token: "NewLiveFirewallRuleProofAdapter", reason: "live firewall rule proof construction"},
		{token: "NewLiveRuntimeRuleProofAdapter", reason: "live runtime rule proof construction"},
		{token: "RuleProofStepRunner", reason: "rule proof runner implementation"},
		{token: "RunRuleProofStep", reason: "rule proof runner execution"},
		{token: "LiveEnforcementRunner", reason: "live enforcement orchestration"},
		{token: "AggregateLiveEnforcementResult", reason: "live enforcement aggregation"},
		{token: "NewLiveNetworkEnforcementPlanning", reason: "live network enforcement planning"},
		{token: "NewGatedNetworkEnforcementPlanning", reason: "gated network enforcement planning"},
		{token: "iptables", reason: "firewall command"},
		{token: "nftables", reason: "firewall command"},
		{token: "pfctl", reason: "firewall command"},
		{token: "firewall.Apply", reason: "firewall mutation"},
		{token: "EnforceFirewall", reason: "firewall mutation"},
	} {
		if strings.Contains(source, forbidden.token) {
			return "cmd file " + fileName + " contains forbidden " + forbidden.reason + " marker " + forbidden.token
		}
	}
	return ""
}

func phase56DesignDocFiles(t *testing.T) []string {
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
		if strings.Contains(strings.ToLower(filepath.Base(path)), "phase56") {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkDir(%s) error: %v", phase50SafeDisplayPath(root), err)
	}
	return paths
}
