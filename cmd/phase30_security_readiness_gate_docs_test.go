package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestPhase30SecurityReadinessGateVerificationDocs(t *testing.T) {
	doc := readPhase30SecurityReadinessGateDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase30-security-readiness-gate-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 30 adds a strict security readiness gate contract and evaluator",
		"`internal/sandbox/security_capability_gate.go`",
		"`SandboxSecurityCapabilityReadinessGateDecision`",
		"The supported policy modes are `off`, `advisory`, and `strict`.",
		"`hal run --sandbox` and `hal auto --sandbox` remain advisory-only for readiness diagnostics in Phase 30.",
		"No run/auto config hook currently represents `off`, `advisory`, and `strict` readiness-gate policy modes before workspace planning, auth sync, or remote execution.",
		"`factory.policy.securityReadinessGatePolicyMode` is the accepted explicit policy surface",
		"Factory sandbox execution evaluates the gate after sanitized factory sandbox security metadata and readiness diagnostics have been attached to the run record, and before remote bootstrap, runtime driver resolution, or remote execution.",
		"Run and auto sandbox execution keep using advisory readiness diagnostics only.",
		"go test -timeout=120s ./internal/sandbox -run 'TestSecurityCapabilityReadinessGate'",
		"go test -timeout=120s ./internal/factory -run 'Test(FactoryPolicy.*SecurityReadinessGate|LoadPolicyConfig.*SecurityReadinessGate|PolicyDecisionMetadataSecurityReadinessGate)'",
		"go test -timeout=120s ./cmd -run 'TestRunFactorySandboxExecutor(StrictReadinessGateBlocksBeforeRemoteExecution|AdvisoryReadinessGateRecordsWithoutBlocking)'",
		"go test -timeout=120s ./cmd -run 'Test(Run|Auto)SandboxLocalReadinessGateConfigRemainsAdvisoryOnly|TestRunAutoReadinessGateNonWiringDocumented'",
		"go test -timeout=120s ./cmd -run 'Test(Run|Auto)SandboxDefaultReadinessGateDoesNotTriggerSchedulerLeaseOrLiveRefresh'",
		"go test -timeout=120s ./internal/sandboxtarget -run 'Test(ScheduleIgnoresStrictBlockingSecurityReadinessForFilteringAndLease|ScheduleCapacityRejectionIgnoresStrictBlockingSecurityReadiness|SelectExplicitSandboxDoesNotRejectStrictBlockingSecurityReadiness)'",
		"go test -timeout=120s ./internal/sandboxexec -run 'TestRunDoesNotRejectWorkerTargetWithStrictBlockingSecurityReadiness'",
		"go test -timeout=120s ./internal/sandboxworker -run 'TestWorkerProtocolOmitsSecurityReadinessGateDecisionFields'",
		"go test -timeout=120s ./cmd -run 'TestPhase30SecurityReadinessGate'",
		"pure evaluator, policy config parsing, factory strict/advisory behavior, default non-blocking run/auto behavior, scheduler and target-selection non-wiring, sandboxexec non-rejection, worker protocol non-expansion, and documentation guard coverage",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`make lint` is optional for Phase 30",
		"Phase 30 verification is metadata-only and fake-only.",
		"Phase 30 test commands must not use integration build tags, require live environment variables, contact remote services, start providers, start runtimes, start worker daemons, run `hal sandboxd`, bind live worker sockets, start network proxies, mutate firewall state, deliver credentials, or perform live scheduler/lease/provider/runtime enforcement.",
		"No scheduler filtering is included in Phase 30.",
		"No target rejection based on readiness diagnostics is included in Phase 30.",
		"No lease rejection based on readiness diagnostics is included in Phase 30.",
		"No live enforcement is included in Phase 30.",
		"No worker protocol changes are included in Phase 30.",
		"No run/auto strict readiness-gate mode is wired in Phase 30.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 30 security readiness gate verification documentation missing %q", want)
		}
	}

	phase30AssertBroadVerificationCommands(t, doc)
	phase30AssertFocusedVerificationCoversRequiredSelectors(t, doc)

	unsupportedClaims := []string{
		"scheduler filtering is implemented",
		"target rejection based on readiness diagnostics is implemented",
		"lease rejection based on readiness diagnostics is implemented",
		"live enforcement is implemented",
		"live network proxy enforcement is implemented",
		"firewall integration is implemented",
		"credential broker behavior is implemented",
		"worker protocol changes are implemented",
		"worker daemon behavior is implemented",
		"runtime/provider integrations are implemented",
		"Run/auto strict readiness-gate mode is wired in Phase 30",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 30 security readiness gate documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase30SecurityReadinessGateFakeOnlyVerification(t *testing.T) {
	doc := readPhase30SecurityReadinessGateDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase30-security-readiness-gate-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 30 verification is metadata-only and fake-only.",
		"Tests should use pure data contracts, JSON marshaling, reflection over struct tags, temporary stores, fake command dependencies, fake clocks, fake runtime drivers, cached target metadata, factory stores, production source scans, and seeded unsafe strings.",
		"Phase 30 test commands must not use integration build tags, require live environment variables, contact remote services, start providers, start runtimes, start worker daemons, run `hal sandboxd`, bind live worker sockets, start network proxies, mutate firewall state, deliver credentials, or perform live scheduler/lease/provider/runtime enforcement.",
		"No scheduler filtering is included in Phase 30.",
		"No target rejection based on readiness diagnostics is included in Phase 30.",
		"No lease rejection based on readiness diagnostics is included in Phase 30.",
		"No live enforcement is included in Phase 30.",
		"No live network proxy enforcement is included in Phase 30.",
		"No firewall integration or firewall mutation is included in Phase 30.",
		"No credential broker behavior or credential delivery is included in Phase 30.",
		"No worker protocol changes are included in Phase 30.",
		"No worker daemon behavior is included in Phase 30.",
		"No runtime/provider integrations are included in Phase 30.",
		"No Docker, Podman, KVM, or microVM runtime requirement is included in Phase 30.",
		"No run/auto strict readiness-gate mode is wired in Phase 30.",
		"go test -timeout=120s ./cmd -run 'TestPhase30SecurityReadinessGate'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 30 security readiness gate fake-only documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"requires integration build tags",
		"requires live environment variables",
		"requires live cloud",
		"requires cloud credentials",
		"requires remote services",
		"requires live providers",
		"requires live runtimes",
		"requires worker daemons",
		"requires live worker sockets",
		"requires network proxies",
		"requires firewall",
		"requires credential delivery",
		"requires Docker",
		"requires Podman",
		"requires KVM",
		"requires microVM",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 30 security readiness gate fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase30FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 30 security readiness gate verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase30ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 30 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase30AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase30AssertFocusedTestFilesAvoidLiveDependencies(t)
}

func readPhase30SecurityReadinessGateDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}

func phase30FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase30AssertBroadVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase30DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 30 verification documentation missing broad verification command line %q", want)
		}
	}
}

func phase30DocumentedShellCommands(doc string) map[string]bool {
	commands := make(map[string]bool)
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "go test "):
			commands[line] = true
		case strings.HasPrefix(line, "go vet "):
			commands[line] = true
		case strings.HasPrefix(line, "make "):
			commands[line] = true
		case strings.HasPrefix(line, "git diff "):
			commands[line] = true
		}
	}
	return commands
}

func phase30ForbiddenFocusedCommandRequirements() []string {
	return []string{
		"-tags=integration",
		"-tags=worker_integration",
		"-tags=podman_integration",
		"worker_integration",
		"podman_integration",
		"HAL_WORKER_INTEGRATION_",
		"HAL_PODMAN_" + "TEST_IMAGE",
		"DOCKER_HOST",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"docker ",
		"podman ",
		"curl ",
		"hal sandboxd",
		"--live",
	}
}

func phase30AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase30FocusedGoTestCommands(doc)
	required := phase30RequiredFocusedTests()
	for _, req := range required {
		command := phase30FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 30 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase30TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 30 verification test %s", phase30SecurityReadinessGateDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase30RequiredFocusedTests() []phase30FocusedTest {
	return []phase30FocusedTest{
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_gate_test.go"), testName: "TestSecurityCapabilityReadinessGateContractConstants"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_gate_test.go"), testName: "TestSecurityCapabilityReadinessGate"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_gate_test.go"), testName: "TestSecurityCapabilityReadinessGateDeterministic"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_gate_test.go"), testName: "TestSecurityCapabilityReadinessGateDoesNotCopyRawDiagnosticValues"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_gate_test.go"), testName: "TestSecurityCapabilityReadinessGateDecisionJSONSchema"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_gate_test.go"), testName: "TestSecurityCapabilityReadinessGateDefaultOmitsOptionalJSONFields"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_gate_test.go"), testName: "TestSecurityCapabilityReadinessGateJSONTagsAreStable"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_gate_test.go"), testName: "TestSecurityCapabilityReadinessGateContractsExposeNoRawValueFields"},
		{pkg: "./internal/sandbox", file: filepath.Join("..", "internal", "sandbox", "security_capability_gate_test.go"), testName: "TestSecurityCapabilityReadinessGateSerializedDecisionContainsOnlySafeMetadataFields"},
		{pkg: "./internal/factory", file: filepath.Join("..", "internal", "factory", "policy_test.go"), testName: "TestFactoryPolicySecurityReadinessGateModeJSONIsAdditive"},
		{pkg: "./internal/factory", file: filepath.Join("..", "internal", "factory", "policy_test.go"), testName: "TestLoadPolicyConfigNormalizesSecurityReadinessGatePolicyMode"},
		{pkg: "./internal/factory", file: filepath.Join("..", "internal", "factory", "types_test.go"), testName: "TestPolicyDecisionMetadataSecurityReadinessGateOptionalFields"},
		{pkg: "./cmd", file: "factory_sandbox_readiness_test.go", testName: "TestRunFactorySandboxExecutorStrictReadinessGateBlocksBeforeRemoteExecution"},
		{pkg: "./cmd", file: "factory_sandbox_readiness_test.go", testName: "TestRunFactorySandboxExecutorAdvisoryReadinessGateRecordsWithoutBlocking"},
		{pkg: "./cmd", file: "sandbox_readiness_gate_non_wiring_test.go", testName: "TestRunSandboxLocalReadinessGateConfigRemainsAdvisoryOnly"},
		{pkg: "./cmd", file: "sandbox_readiness_gate_non_wiring_test.go", testName: "TestAutoSandboxLocalReadinessGateConfigRemainsAdvisoryOnly"},
		{pkg: "./cmd", file: "sandbox_readiness_gate_non_wiring_test.go", testName: "TestRunAutoReadinessGateNonWiringDocumented"},
		{pkg: "./cmd", file: "run_sandbox_capability_readiness_test.go", testName: "TestRunSandboxDefaultReadinessGateDoesNotTriggerSchedulerLeaseOrLiveRefresh"},
		{pkg: "./cmd", file: "auto_sandbox_readiness_test.go", testName: "TestAutoSandboxDefaultReadinessGateDoesNotTriggerSchedulerLeaseOrLiveRefresh"},
		{pkg: "./cmd", file: "phase30_security_readiness_gate_docs_test.go", testName: "TestPhase30SecurityReadinessGateVerificationDocs"},
		{pkg: "./cmd", file: "phase30_security_readiness_gate_docs_test.go", testName: "TestPhase30SecurityReadinessGateFakeOnlyVerification"},
		{pkg: "./internal/sandboxtarget", file: filepath.Join("..", "internal", "sandboxtarget", "readiness_gate_regression_test.go"), testName: "TestScheduleIgnoresStrictBlockingSecurityReadinessForFilteringAndLease"},
		{pkg: "./internal/sandboxtarget", file: filepath.Join("..", "internal", "sandboxtarget", "readiness_gate_regression_test.go"), testName: "TestScheduleCapacityRejectionIgnoresStrictBlockingSecurityReadiness"},
		{pkg: "./internal/sandboxtarget", file: filepath.Join("..", "internal", "sandboxtarget", "readiness_gate_regression_test.go"), testName: "TestSelectExplicitSandboxDoesNotRejectStrictBlockingSecurityReadiness"},
		{pkg: "./internal/sandboxexec", file: filepath.Join("..", "internal", "sandboxexec", "readiness_gate_regression_test.go"), testName: "TestRunDoesNotRejectWorkerTargetWithStrictBlockingSecurityReadiness"},
		{pkg: "./internal/sandboxworker", file: filepath.Join("..", "internal", "sandboxworker", "types_test.go"), testName: "TestWorkerProtocolOmitsSecurityReadinessGateDecisionFields"},
	}
}

type phase30FocusedTest struct {
	pkg      string
	file     string
	testName string
}

func phase30FocusedCommandCoveringTest(t *testing.T, commands []string, pkg, testName string) string {
	t.Helper()
	for _, command := range commands {
		if !phase30FocusedCommandTargetsPackage(command, pkg) {
			continue
		}
		selector := phase30FocusedCommandRunSelector(t, command)
		compiled, err := regexp.Compile(selector)
		if err != nil {
			t.Fatalf("phase 30 focused command %q has invalid -run selector %q: %v", command, selector, err)
		}
		if compiled.MatchString(testName) {
			return command
		}
	}
	return ""
}

func phase30FocusedCommandTargetsPackage(command, pkg string) bool {
	for _, field := range strings.Fields(command) {
		if strings.Trim(field, "'\"") == pkg {
			return true
		}
	}
	return false
}

func phase30FocusedCommandRunSelector(t *testing.T, command string) string {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == "-run" {
			if i+1 >= len(fields) {
				t.Fatalf("phase 30 focused command %q has -run without selector", command)
			}
			return strings.Trim(fields[i+1], "'\"")
		}
		if selector, ok := strings.CutPrefix(field, "-run="); ok {
			return strings.Trim(selector, "'\"")
		}
	}
	t.Fatalf("phase 30 focused command %q missing -run selector", command)
	return ""
}

func phase30TestFileDefinesFunction(t *testing.T, path, testName string) bool {
	t.Helper()
	file := phase30ParseGoFile(t, path, parser.ParseComments)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == testName {
			return true
		}
	}
	return false
}

func phase30AssertFocusedTestFilesAvoidLiveDependencies(t *testing.T) {
	t.Helper()
	seen := make(map[string]bool)
	for _, req := range phase30RequiredFocusedTests() {
		if seen[req.file] {
			continue
		}
		seen[req.file] = true
		phase30AssertNoIntegrationBuildTag(t, req.file)
		phase30AssertDefaultTestFileAvoidsLiveImports(t, req.file)
	}
}

func phase30AssertNoIntegrationBuildTag(t *testing.T, path string) {
	t.Helper()
	file := phase30ParseGoFile(t, path, parser.ParseComments)
	for _, group := range file.Comments {
		if group.End() > file.Package {
			continue
		}
		for _, comment := range group.List {
			text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
			text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
			text = strings.TrimSpace(strings.TrimSuffix(text, "*/"))
			if strings.HasPrefix(text, "go:build") {
				for _, tag := range []string{"integration", "worker_integration", "podman_integration"} {
					if strings.Contains(text, tag) {
						t.Fatalf("%s uses integration build tag %q; Phase 30 focused tests must stay fake-only", phase30SecurityReadinessGateDisplayPath(t, path), tag)
					}
				}
			}
		}
	}
}

func phase30AssertDefaultTestFileAvoidsLiveImports(t *testing.T, path string) {
	t.Helper()
	file := phase30ParseGoFile(t, path, parser.ImportsOnly)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
		}
		if forbidden := phase30ForbiddenDefaultTestImport(importPath); forbidden != "" {
			t.Fatalf("%s imports %q; Phase 30 focused tests must stay fake-only and avoid %s", phase30SecurityReadinessGateDisplayPath(t, path), importPath, forbidden)
		}
	}
}

func phase30ParseGoFile(t *testing.T, path string, mode parser.Mode) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, mode)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	return file
}

func phase30ForbiddenDefaultTestImport(importPath string) string {
	switch importPath {
	case "net", "net/http", "net/http/httputil", "net/rpc", "net/smtp":
		return "network clients or live proxy servers"
	case "os/exec":
		return "process execution"
	}
	for _, forbidden := range []struct {
		prefix string
		label  string
	}{
		{prefix: "github.com/docker/docker", label: "Docker clients"},
		{prefix: "github.com/containers/podman", label: "Podman clients"},
		{prefix: "github.com/digitalocean/godo", label: "cloud SDKs"},
		{prefix: "github.com/aws/aws-sdk-go", label: "cloud SDKs"},
		{prefix: "github.com/aws/aws-sdk-go-v2", label: "cloud SDKs"},
		{prefix: "github.com/Azure/azure-sdk-for-go", label: "cloud SDKs"},
		{prefix: "github.com/hetznercloud/hcloud-go", label: "cloud SDKs"},
		{prefix: "cloud.google.com/go", label: "cloud SDKs"},
		{prefix: "google.golang.org/api", label: "cloud SDKs"},
		{prefix: "google.golang.org/grpc", label: "network clients"},
		{prefix: "golang.org/x/net/proxy", label: "HTTP proxy implementations"},
		{prefix: "golang.org/x/crypto/ssh", label: "SSH or SSH-agent implementations"},
		{prefix: "github.com/firecracker-microvm", label: "microVM integrations"},
		{prefix: "libvirt.org/go/libvirt", label: "KVM or microVM integrations"},
	} {
		if strings.HasPrefix(importPath, forbidden.prefix) {
			return forbidden.label
		}
	}
	return ""
}

func phase30SecurityReadinessGateDisplayPath(t *testing.T, path string) string {
	t.Helper()
	if !strings.HasPrefix(filepath.ToSlash(path), "../") {
		return filepath.ToSlash(filepath.Join("cmd", path))
	}
	rel, err := filepath.Rel(filepath.Join(".."), path)
	if err != nil {
		t.Fatalf("Rel(%s, %s) error: %v", filepath.Join(".."), path, err)
	}
	return filepath.ToSlash(rel)
}
