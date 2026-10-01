package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPhase28SecurityCapabilityReadinessProjectionVerificationDocs(t *testing.T) {
	doc := readPhase28SecurityCapabilityReadinessProjectionDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase28-security-capability-readiness-projection-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 28 projects Phase 27 security capability readiness metadata",
		"`internal/sandbox/security_capability_projection.go`",
		"Projected Phase 24 network proxy metadata and Phase 25/26 credential proxy metadata remain `metadata_only`",
		"`EvaluateProjectedSandboxSecurityCapabilityReadiness` delegates to the Phase 27 evaluator and sanitizes output before any command or factory surface attaches it.",
		"Readiness projection does not add CLI flags, remote command arguments, target resolution changes, lease behavior changes, sync-out changes, loop behavior changes, execution result handling changes, or execution blocking.",
		"Cached runtime status paths stay fake-only and must not contact worker daemons to compute readiness.",
		"Factory run records and timeline events omit readiness by default.",
		"Readiness output does not affect factory target selection, scheduler filtering, lease acquisition, execution, status transitions, failure classification, or cleanup behavior.",
		"go test -timeout=120s ./internal/sandbox -run 'Test(SandboxSecurityCapabilityReadinessJSONField|ProjectSandboxSecurityCapabilityReadinessInput|ProjectSandboxWorkerRuntimeCapabilityReadinessInput|ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput|EvaluateProjectedSandboxSecurityCapabilityReadiness)'",
		"go test -timeout=120s ./cmd -run 'TestSandboxSecurityCapabilityReadiness(JSONFieldApprovedStructs|MetadataPreservedWhenAttached)'",
		"go test -timeout=120s ./cmd -run 'Test(RunSandboxCapabilityReadiness|RunSandboxManifestAttachesSanitizedProjectedCapabilityReadiness|AutoSandboxManifestOmitsCapabilityReadinessWhenUnavailable|RunAutoSandboxWithWriterAttachesCapabilityReadinessWithoutChangingExecution)'",
		"go test -timeout=120s ./cmd -run 'Test(SandboxRuntimeStatusJSON(CachedWorkerRuntimeContractStableAndSafe|OmitsCapabilityReadinessWhenSecurityAbsent)|SandboxRuntimeSecuritySummarySanitizesCapabilityReadinessBeforeJSON|FactorySandbox(CapabilityReadinessOmittedByDefault|MetadataAttachesSanitizedProjectedCapabilityReadiness)|RunFactorySandboxExecutorCapabilityReadinessDoesNotChangeExecution)'",
		"go test -timeout=120s ./cmd -run 'TestPhase28SecurityCapabilityReadinessProjection(VerificationDocs|FakeOnlyVerification)'",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`make lint` is optional for Phase 28.",
		"Phase 28 verification is metadata-only and fake-only.",
		"No worker protocol changes are included in Phase 28.",
		"No readiness gates are included in Phase 28.",
		"No scheduler readiness filtering is included in Phase 28.",
		"No target-selection rejection based on readiness is included in Phase 28.",
		"No execution blocking based on readiness is included in Phase 28.",
		"No new CLI flags are included in Phase 28.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 28 security capability readiness projection verification documentation missing %q", want)
		}
	}

	unsupportedClaims := []string{
		"live sockets are required",
		"network access is required",
		"Docker is required",
		"Podman is required",
		"KVM is required",
		"cloud credentials are required",
		"worker daemon is required",
		"worker daemons are required",
		"readiness gates are implemented",
		"scheduler filtering is implemented",
		"scheduler readiness filtering is implemented",
		"target-selection rejection is implemented",
		"target-selection rejection based on readiness is implemented",
		"execution blocking is implemented",
		"execution blocking based on readiness is implemented",
		"worker protocol changes are implemented",
		"new CLI flags are implemented",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 28 security capability readiness projection documentation makes unsupported implementation claim %q", claim)
		}
	}

	phase28AssertFocusedVerificationCoversRequiredSelectors(t, doc)
}

func TestPhase28SecurityCapabilityReadinessProjectionFakeOnlyVerification(t *testing.T) {
	doc := readPhase28SecurityCapabilityReadinessProjectionDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase28-security-capability-readiness-projection-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 28 verification is metadata-only and fake-only.",
		"Phase 28 fake-only verification has no live services, live sockets, live proxying, live firewall configuration, firewall mutation, credential delivery, credential injection, tmpfs writes, SSH-agent forwarding, worker daemon, worker protocol negotiation, provider startup, runtime startup, Docker, Podman, KVM, microVM, cloud credentials, provider credentials, external network access, scheduler readiness gates, target-selection rejection, new command flags, or execution blocking.",
		"Default Phase 28 test commands must not use integration build tags or require live environment variables.",
		"Do not start a live proxy, bind listener sockets, mutate firewall rules, deliver credentials, inject credentials, write tmpfs secret payloads, forward SSH agents, start a worker daemon, run `hal sandboxd`, bind real worker sockets, contact remote worker hosts, change worker protocol contracts, run Podman or Docker workflows, access KVM devices, access cloud APIs, open network connections, invoke concrete providers or runtimes, add new CLI flags, block sandbox execution on readiness output, or reject scheduler or target selection candidates from readiness output as part of Phase 28 verification.",
		"go test -timeout=120s ./cmd -run 'TestPhase28SecurityCapabilityReadinessProjection(VerificationDocs|FakeOnlyVerification)'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 28 security capability readiness projection fake-only documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"requires live services",
		"requires live sockets",
		"requires real network access",
		"requires external network access",
		"requires network access",
		"requires networking",
		"requires Docker",
		"requires Podman",
		"requires KVM",
		"requires cloud credentials",
		"requires worker daemon",
		"requires worker daemons",
		"requires integration build tags",
		"requires live environment variables",
		"requires readiness gates",
		"requires scheduler filtering",
		"requires target-selection rejection",
		"requires execution blocking",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 28 security capability readiness projection fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase28FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 28 security capability readiness projection verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase28ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 28 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase28AssertFocusedVerificationCoversRequiredSelectors(t, doc)
}

func readPhase28SecurityCapabilityReadinessProjectionDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}

func phase28FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase28ForbiddenFocusedCommandRequirements() []string {
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

func phase28AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase28FocusedGoTestCommands(doc)
	required := []struct {
		pkg      string
		file     string
		testName string
	}{
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "types_test.go"),
			testName: "TestSandboxSecurityCapabilityReadinessJSONField",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_projection_test.go"),
			testName: "TestProjectSandboxSecurityCapabilityReadinessInputExplicitSafeMetadata",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_projection_test.go"),
			testName: "TestProjectSandboxWorkerRuntimeCapabilityReadinessInputExplicitReadyMetadata",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_projection_test.go"),
			testName: "TestProjectSandboxPolicyProxyCredentialCapabilityReadinessInputMetadataOnlyNotReady",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_projection_test.go"),
			testName: "TestEvaluateProjectedSandboxSecurityCapabilityReadinessMergesProjectedInputAndEvaluates",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_projection_test.go"),
			testName: "TestEvaluateProjectedSandboxSecurityCapabilityReadinessSanitizesOutputForAttachment",
		},
		{
			pkg:      "./cmd",
			file:     "sandbox_security_metadata_test.go",
			testName: "TestSandboxSecurityCapabilityReadinessJSONFieldApprovedStructs",
		},
		{
			pkg:      "./cmd",
			file:     "sandbox_security_metadata_test.go",
			testName: "TestSandboxSecurityCapabilityReadinessMetadataPreservedWhenAttached",
		},
		{
			pkg:      "./cmd",
			file:     "run_sandbox_capability_readiness_test.go",
			testName: "TestRunSandboxCapabilityReadinessOmittedWhenUnavailable",
		},
		{
			pkg:      "./cmd",
			file:     "run_sandbox_capability_readiness_test.go",
			testName: "TestRunSandboxManifestAttachesSanitizedProjectedCapabilityReadiness",
		},
		{
			pkg:      "./cmd",
			file:     "run_sandbox_capability_readiness_test.go",
			testName: "TestRunSandboxCapabilityReadinessDoesNotBlockOrAlterExecution",
		},
		{
			pkg:      "./cmd",
			file:     "auto_sandbox_readiness_test.go",
			testName: "TestAutoSandboxManifestOmitsCapabilityReadinessWhenUnavailable",
		},
		{
			pkg:      "./cmd",
			file:     "auto_sandbox_readiness_test.go",
			testName: "TestRunAutoSandboxWithWriterAttachesCapabilityReadinessWithoutChangingExecution",
		},
		{
			pkg:      "./cmd",
			file:     "sandbox_runtime_test.go",
			testName: "TestSandboxRuntimeStatusJSONCachedWorkerRuntimeContractStableAndSafe",
		},
		{
			pkg:      "./cmd",
			file:     "sandbox_runtime_test.go",
			testName: "TestSandboxRuntimeStatusJSONOmitsCapabilityReadinessWhenSecurityAbsent",
		},
		{
			pkg:      "./cmd",
			file:     "sandbox_runtime_test.go",
			testName: "TestSandboxRuntimeSecuritySummarySanitizesCapabilityReadinessBeforeJSON",
		},
		{
			pkg:      "./cmd",
			file:     "factory_sandbox_readiness_test.go",
			testName: "TestFactorySandboxCapabilityReadinessOmittedByDefault",
		},
		{
			pkg:      "./cmd",
			file:     "factory_sandbox_readiness_test.go",
			testName: "TestFactorySandboxMetadataAttachesSanitizedProjectedCapabilityReadiness",
		},
		{
			pkg:      "./cmd",
			file:     "factory_sandbox_readiness_test.go",
			testName: "TestRunFactorySandboxExecutorCapabilityReadinessDoesNotChangeExecution",
		},
		{
			pkg:      "./cmd",
			file:     "phase28_security_capability_docs_test.go",
			testName: "TestPhase28SecurityCapabilityReadinessProjectionVerificationDocs",
		},
		{
			pkg:      "./cmd",
			file:     "phase28_security_capability_docs_test.go",
			testName: "TestPhase28SecurityCapabilityReadinessProjectionFakeOnlyVerification",
		},
	}
	for _, req := range required {
		command := phase28FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 28 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		source := readPhase28SecurityCapabilityReadinessProjectionDoc(t, req.file)
		if !strings.Contains(source, "func "+req.testName+"(") {
			t.Fatalf("%s does not define required Phase 28 verification test %s", phase28SecurityCapabilityReadinessProjectionDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase28FocusedCommandCoveringTest(t *testing.T, commands []string, pkg, testName string) string {
	t.Helper()
	for _, command := range commands {
		if !phase28FocusedCommandTargetsPackage(command, pkg) {
			continue
		}
		selector := phase28FocusedCommandRunSelector(t, command)
		compiled, err := regexp.Compile(selector)
		if err != nil {
			t.Fatalf("phase 28 focused command %q has invalid -run selector %q: %v", command, selector, err)
		}
		if compiled.MatchString(testName) {
			return command
		}
	}
	return ""
}

func phase28FocusedCommandTargetsPackage(command, pkg string) bool {
	for _, field := range strings.Fields(command) {
		if strings.Trim(field, "'\"") == pkg {
			return true
		}
	}
	return false
}

func phase28FocusedCommandRunSelector(t *testing.T, command string) string {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == "-run" {
			if i+1 >= len(fields) {
				t.Fatalf("phase 28 focused command %q has -run without selector", command)
			}
			return strings.Trim(fields[i+1], "'\"")
		}
		if selector, ok := strings.CutPrefix(field, "-run="); ok {
			return strings.Trim(selector, "'\"")
		}
	}
	t.Fatalf("phase 28 focused command %q missing -run selector", command)
	return ""
}

func phase28SecurityCapabilityReadinessProjectionDisplayPath(t *testing.T, path string) string {
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
