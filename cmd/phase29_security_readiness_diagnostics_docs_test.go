package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPhase29SecurityReadinessDiagnosticsVerificationDocs(t *testing.T) {
	doc := readPhase29SecurityReadinessDiagnosticsDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase29-security-readiness-diagnostics-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 29 derives additive, redaction-safe security readiness diagnostics",
		"`capabilityReadinessDiagnostics`",
		"Diagnostics are advisory only and must not block execution or target selection.",
		"`wouldBlockStrictGate` fields describe what a future explicit strict gate would do",
		"`internal/sandbox/security_capability_diagnostics.go`",
		"`sandbox.SandboxSecurity`",
		"`factory.SandboxSecurityMetadata`",
		"`SandboxRuntimeSecuritySummary`",
		"`hal run --sandbox` sandbox execution manifests",
		"`hal auto --sandbox` sandbox execution manifests",
		"factory sandbox metadata and factory timeline security metadata",
		"When readiness output is absent, default run, auto, runtime-summary, factory metadata, and factory timeline JSON continue to omit `capabilityReadinessDiagnostics`.",
		"go test -timeout=120s ./internal/sandbox -run 'TestSecurityCapability(ReadinessDiagnostics|SerializedReadinessDiagnostics)'",
		"go test -timeout=120s ./cmd -run 'Test(SandboxRuntimeStatusJSONSecurityReadinessDiagnostics|SandboxRuntimeSecurityReadinessDiagnostics|SandboxRuntimeSecurityReadinessDiagnosticsJSONFieldApprovedStruct)'",
		"go test -timeout=120s ./cmd -run 'Test(RunSandboxManifest(OmitsReadinessDiagnosticsWhenUnavailable|AttachesSanitizedReadinessDiagnostics)|RunSandboxReadinessDiagnosticsDoNotBlockOrAlterExecution|AutoSandboxManifest(OmitsReadinessDiagnosticsWhenUnavailable|AttachesReadinessDiagnosticsFromSanitizedReadiness)|AutoSandboxReadinessDiagnosticsDoNotBlockOrAlterExecution|FactorySandbox(MetadataAttachesSanitizedReadinessDiagnostics|TimelineAttachesSanitizedReadinessDiagnostics)|RunFactorySandboxExecutorCapabilityReadinessDoesNotChangeExecution)'",
		"go test -timeout=120s ./cmd -run 'TestPhase29SecurityReadinessDiagnostics(VerificationDocs|FakeOnlyVerification)'",
		"internal/sandbox diagnostics, runtime summaries, run/auto/factory surfacing, advisory-only behavior, and documentation guard coverage",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`make lint` is optional for Phase 29.",
		"Record `make lint` as unavailable if `golangci-lint` is missing",
		"Phase 29 verification is metadata-only and fake-only.",
		"Phase 29 verification explicitly excludes live cloud, Docker, Podman, KVM, microVM, network proxy, firewall, credential broker, runtime/provider, and worker daemon requirements.",
		"Default Phase 29 test commands must not use integration build tags or require live environment variables.",
		"No readiness gate is included in Phase 29.",
		"No scheduler readiness filtering is included in Phase 29.",
		"No target-selection rejection based on diagnostics is included in Phase 29.",
		"No execution blocking based on diagnostics is included in Phase 29.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 29 security readiness diagnostics verification documentation missing %q", want)
		}
	}

	phase29AssertBroadVerificationCommands(t, doc)

	unsupportedClaims := []string{
		"diagnostics block execution",
		"diagnostics block target selection",
		"readiness gate is implemented",
		"scheduler readiness filtering is implemented",
		"target-selection rejection based on diagnostics is implemented",
		"execution blocking based on diagnostics is implemented",
		"worker daemon behavior is implemented",
		"concrete runtime/provider integration is implemented",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 29 security readiness diagnostics documentation makes unsupported implementation claim %q", claim)
		}
	}

	phase29AssertFocusedVerificationCoversRequiredSelectors(t, doc)
}

func TestPhase29SecurityReadinessDiagnosticsFakeOnlyVerification(t *testing.T) {
	doc := readPhase29SecurityReadinessDiagnosticsDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase29-security-readiness-diagnostics-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 29 verification is metadata-only and fake-only.",
		"Phase 29 verification explicitly excludes live cloud, Docker, Podman, KVM, microVM, network proxy, firewall, credential broker, runtime/provider, and worker daemon requirements.",
		"Default Phase 29 test commands must not use integration build tags or require live environment variables.",
		"Do not start a live network proxy, bind listener sockets, mutate firewall rules, deliver credentials, inject credentials, start a credential broker, start a worker daemon, run `hal sandboxd`, bind real worker sockets, contact remote worker hosts, run Podman or Docker workflows, access KVM devices, access cloud APIs, open network connections, invoke concrete providers or runtimes, add readiness gates, block sandbox execution on diagnostics, or reject scheduler or target-selection candidates from diagnostics as part of Phase 29 verification.",
		"go test -timeout=120s ./cmd -run 'TestPhase29SecurityReadinessDiagnostics(VerificationDocs|FakeOnlyVerification)'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 29 security readiness diagnostics fake-only documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"requires live cloud",
		"requires cloud credentials",
		"requires Docker",
		"requires Podman",
		"requires KVM",
		"requires microVM",
		"requires network proxy",
		"requires firewall",
		"requires credential broker",
		"requires runtime/provider",
		"requires worker daemon",
		"requires integration build tags",
		"requires live environment variables",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 29 security readiness diagnostics fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase29FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 29 security readiness diagnostics verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase29ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 29 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase29AssertFocusedVerificationCoversRequiredSelectors(t, doc)
}

func readPhase29SecurityReadinessDiagnosticsDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}

func phase29FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase29AssertBroadVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase29DocumentedShellCommands(doc)
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
			t.Fatalf("phase 29 verification documentation missing broad verification command line %q", want)
		}
	}
}

func phase29DocumentedShellCommands(doc string) map[string]bool {
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

func phase29ForbiddenFocusedCommandRequirements() []string {
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

func phase29AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase29FocusedGoTestCommands(doc)
	required := []struct {
		pkg      string
		file     string
		testName string
	}{
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_diagnostics_test.go"),
			testName: "TestSecurityCapabilityReadinessDiagnosticsContractConstants",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_diagnostics_test.go"),
			testName: "TestSecurityCapabilityReadinessDiagnosticsDeriveStateMatrix",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_diagnostics_test.go"),
			testName: "TestSecurityCapabilityReadinessDiagnosticsSanitizeUnsafeReadinessOutput",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_diagnostics_test.go"),
			testName: "TestSecurityCapabilitySerializedReadinessDiagnosticsContainNoUnsafeRawFieldNames",
		},
		{
			pkg:      "./cmd",
			file:     "sandbox_security_metadata_test.go",
			testName: "TestSandboxRuntimeSecurityReadinessDiagnosticsJSONFieldApprovedStruct",
		},
		{
			pkg:      "./cmd",
			file:     "sandbox_runtime_test.go",
			testName: "TestSandboxRuntimeStatusJSONSecurityReadinessDiagnosticsFromCachedMetadata",
		},
		{
			pkg:      "./cmd",
			file:     "sandbox_runtime_test.go",
			testName: "TestSandboxRuntimeStatusJSONSecurityReadinessDiagnosticsOmittedWhenSecurityAbsent",
		},
		{
			pkg:      "./cmd",
			file:     "sandbox_runtime_test.go",
			testName: "TestSandboxRuntimeSecurityReadinessDiagnosticsSanitizeBeforeJSON",
		},
		{
			pkg:      "./cmd",
			file:     "run_sandbox_capability_readiness_test.go",
			testName: "TestRunSandboxManifestOmitsReadinessDiagnosticsWhenUnavailable",
		},
		{
			pkg:      "./cmd",
			file:     "run_sandbox_capability_readiness_test.go",
			testName: "TestRunSandboxManifestAttachesSanitizedReadinessDiagnostics",
		},
		{
			pkg:      "./cmd",
			file:     "run_sandbox_capability_readiness_test.go",
			testName: "TestRunSandboxReadinessDiagnosticsDoNotBlockOrAlterExecution",
		},
		{
			pkg:      "./cmd",
			file:     "auto_sandbox_readiness_test.go",
			testName: "TestAutoSandboxManifestOmitsReadinessDiagnosticsWhenUnavailable",
		},
		{
			pkg:      "./cmd",
			file:     "auto_sandbox_readiness_test.go",
			testName: "TestAutoSandboxManifestAttachesReadinessDiagnosticsFromSanitizedReadiness",
		},
		{
			pkg:      "./cmd",
			file:     "auto_sandbox_readiness_test.go",
			testName: "TestAutoSandboxReadinessDiagnosticsDoNotBlockOrAlterExecution",
		},
		{
			pkg:      "./cmd",
			file:     "factory_sandbox_readiness_test.go",
			testName: "TestFactorySandboxMetadataAttachesSanitizedReadinessDiagnostics",
		},
		{
			pkg:      "./cmd",
			file:     "factory_sandbox_readiness_test.go",
			testName: "TestFactorySandboxTimelineAttachesSanitizedReadinessDiagnostics",
		},
		{
			pkg:      "./cmd",
			file:     "factory_sandbox_readiness_test.go",
			testName: "TestRunFactorySandboxExecutorCapabilityReadinessDoesNotChangeExecution",
		},
		{
			pkg:      "./cmd",
			file:     "phase29_security_readiness_diagnostics_docs_test.go",
			testName: "TestPhase29SecurityReadinessDiagnosticsVerificationDocs",
		},
		{
			pkg:      "./cmd",
			file:     "phase29_security_readiness_diagnostics_docs_test.go",
			testName: "TestPhase29SecurityReadinessDiagnosticsFakeOnlyVerification",
		},
	}
	for _, req := range required {
		command := phase29FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 29 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		source := readPhase29SecurityReadinessDiagnosticsDoc(t, req.file)
		if !strings.Contains(source, "func "+req.testName+"(") {
			t.Fatalf("%s does not define required Phase 29 verification test %s", phase29SecurityReadinessDiagnosticsDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase29FocusedCommandCoveringTest(t *testing.T, commands []string, pkg, testName string) string {
	t.Helper()
	for _, command := range commands {
		if !phase29FocusedCommandTargetsPackage(command, pkg) {
			continue
		}
		selector := phase29FocusedCommandRunSelector(t, command)
		compiled, err := regexp.Compile(selector)
		if err != nil {
			t.Fatalf("phase 29 focused command %q has invalid -run selector %q: %v", command, selector, err)
		}
		if compiled.MatchString(testName) {
			return command
		}
	}
	return ""
}

func phase29FocusedCommandTargetsPackage(command, pkg string) bool {
	for _, field := range strings.Fields(command) {
		if strings.Trim(field, "'\"") == pkg {
			return true
		}
	}
	return false
}

func phase29FocusedCommandRunSelector(t *testing.T, command string) string {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == "-run" {
			if i+1 >= len(fields) {
				t.Fatalf("phase 29 focused command %q has -run without selector", command)
			}
			return strings.Trim(fields[i+1], "'\"")
		}
		if selector, ok := strings.CutPrefix(field, "-run="); ok {
			return strings.Trim(selector, "'\"")
		}
	}
	t.Fatalf("phase 29 focused command %q missing -run selector", command)
	return ""
}

func phase29SecurityReadinessDiagnosticsDisplayPath(t *testing.T, path string) string {
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
