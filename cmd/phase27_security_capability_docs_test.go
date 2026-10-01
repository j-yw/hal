package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPhase27SecurityCapabilityReadinessVerificationDocs(t *testing.T) {
	doc := readPhase27SecurityCapabilityDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase27-security-capability-readiness-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 27 adds data-only, redaction-safe security capability readiness contracts",
		"`internal/sandbox/security_capability.go`",
		"`internal/sandbox/security_capability_sanitize.go`",
		"`internal/sandbox/security_capability_evaluator.go`",
		"Phase 27 treats Phase 24 network proxy session and policy decision-log metadata as `metadata_only`",
		"Phase 25 and Phase 26 credential proxy plan, session, and binding metadata as `metadata_only`",
		"Requested capabilities without matching explicit support are `unsupported`, and explicit safe blocker metadata can classify a capability as `blocked`.",
		"go test -timeout=120s ./internal/sandbox -run 'TestSecurityCapability(Readiness|MetadataStatusReasonWarning|SerializedReadiness)'",
		"go test -timeout=120s ./internal/sandbox -run 'TestEvaluateSecurityCapabilityReadiness|TestValidateSecurityCapabilityReadinessInputErrorsAreSanitized'",
		"go test -timeout=120s ./internal/sandbox -run 'TestSecurityCapability(ImportBoundar|Source)'",
		"go test -timeout=120s ./cmd -run 'TestPhase27SecurityCapability(ReadinessVerificationDocs|FakeOnlyVerification)'",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`make lint` is optional for Phase 27.",
		"No live proxy implementation",
		"No firewall implementation or firewall rule mutation",
		"No credential delivery",
		"No credential injection",
		"No tmpfs credential delivery",
		"No SSH-agent forwarding",
		"No worker protocol changes",
		"No worker daemon changes",
		"No worker daemon behavior",
		"No provider integration",
		"No runtime integration",
		"No new CLI flags",
		"No new command persistence behavior",
		"No new factory persistence behavior",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 27 security capability readiness verification documentation missing %q", want)
		}
	}

	unsupportedClaims := []string{
		"live proxy is implemented",
		"firewall implementation is implemented",
		"firewall rule mutation is implemented",
		"credential delivery is implemented",
		"credential injection is implemented",
		"tmpfs credential delivery is implemented",
		"SSH-agent forwarding is implemented",
		"worker protocol changes are implemented",
		"worker daemon changes are implemented",
		"worker daemon behavior is implemented",
		"provider integration is implemented",
		"runtime integration is implemented",
		"new CLI flags are implemented",
		"new command persistence behavior is implemented",
		"new factory persistence behavior is implemented",
		"security capability readiness gate enforcement is implemented",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 27 security capability documentation makes unsupported implementation claim %q", claim)
		}
	}

	phase27AssertFocusedVerificationCoversRequiredAreas(t, doc)
}

func TestPhase27SecurityCapabilityFakeOnlyVerification(t *testing.T) {
	doc := readPhase27SecurityCapabilityDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase27-security-capability-readiness-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 27 verification is metadata-only and fake-only.",
		"Phase 27 fake-only verification has no live services, live proxy server, live firewall configuration, credential delivery, credential injection, tmpfs writes, SSH-agent forwarding, worker daemon changes, worker daemon, worker protocol negotiation, provider startup, runtime startup, Docker, Podman, KVM, microVM, cloud credentials, provider credentials, external network access, new command flags, or durable persistence behavior.",
		"Default Phase 27 test commands must not use integration build tags or require live environment variables.",
		"go test -timeout=120s ./cmd -run 'TestPhase27SecurityCapability(ReadinessVerificationDocs|FakeOnlyVerification)'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 27 security capability fake-only verification documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"requires live services",
		"requires real network access",
		"requires external network access",
		"requires network access",
		"requires provider credentials",
		"requires live proxy",
		"requires live firewall",
		"requires credential delivery",
		"requires credential injection",
		"requires tmpfs",
		"requires SSH-agent",
		"requires worker daemon changes",
		"requires worker daemon",
		"requires Docker",
		"requires Podman",
		"requires KVM",
		"requires microVM",
		"requires integration build tags",
		"requires live environment variables",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 27 security capability fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase27FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 27 security capability verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase27ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 27 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase27AssertFocusedVerificationCoversRequiredAreas(t, doc)
}

func readPhase27SecurityCapabilityDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}

func phase27FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase27ForbiddenFocusedCommandRequirements() []string {
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

func phase27AssertFocusedVerificationCoversRequiredAreas(t *testing.T, doc string) {
	t.Helper()
	commands := phase27FocusedGoTestCommands(doc)
	required := []struct {
		pkg      string
		file     string
		testName string
	}{
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_test.go"),
			testName: "TestSecurityCapabilityReadinessContractConstants",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_test.go"),
			testName: "TestSecurityCapabilityReadinessDefaultMetadataOmitsOptionalJSONFields",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_test.go"),
			testName: "TestSecurityCapabilitySerializedReadinessContainsNoUnsafeRawFieldNames",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_evaluator_test.go"),
			testName: "TestEvaluateSecurityCapabilityReadinessTreatsNetworkProxyMetadataAsMetadataOnly",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_evaluator_test.go"),
			testName: "TestEvaluateSecurityCapabilityReadinessTreatsCredentialProxyMetadataAsMetadataOnly",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_evaluator_test.go"),
			testName: "TestEvaluateSecurityCapabilityReadinessMarksRequestedStrictNetworkEnforcementUnsupportedWithoutSupport",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_evaluator_test.go"),
			testName: "TestEvaluateSecurityCapabilityReadinessMarksExplicitReadyNetworkEnforcement",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_evaluator_test.go"),
			testName: "TestEvaluateSecurityCapabilityReadinessMarksExplicitBlockedCapability",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_evaluator_test.go"),
			testName: "TestEvaluateSecurityCapabilityReadinessSanitizesUnsafeInputValues",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_evaluator_test.go"),
			testName: "TestValidateSecurityCapabilityReadinessInputErrorsAreSanitized",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_import_boundary_test.go"),
			testName: "TestSecurityCapabilityImportBoundaries",
		},
		{
			pkg:      "./internal/sandbox",
			file:     filepath.Join("..", "internal", "sandbox", "security_capability_import_boundary_test.go"),
			testName: "TestSecurityCapabilitySourceOmitsLiveBehaviorMarkers",
		},
		{
			pkg:      "./cmd",
			file:     "phase27_security_capability_docs_test.go",
			testName: "TestPhase27SecurityCapabilityReadinessVerificationDocs",
		},
		{
			pkg:      "./cmd",
			file:     "phase27_security_capability_docs_test.go",
			testName: "TestPhase27SecurityCapabilityFakeOnlyVerification",
		},
	}
	for _, req := range required {
		command := phase27FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 27 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		source := readPhase27SecurityCapabilityDoc(t, req.file)
		if !strings.Contains(source, "func "+req.testName+"(") {
			t.Fatalf("%s does not define required Phase 27 verification test %s", phase27SecurityCapabilityDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase27FocusedCommandCoveringTest(t *testing.T, commands []string, pkg, testName string) string {
	t.Helper()
	for _, command := range commands {
		if !phase27FocusedCommandTargetsPackage(command, pkg) {
			continue
		}
		selector := phase27FocusedCommandRunSelector(t, command)
		compiled, err := regexp.Compile(selector)
		if err != nil {
			t.Fatalf("phase 27 focused command %q has invalid -run selector %q: %v", command, selector, err)
		}
		if compiled.MatchString(testName) {
			return command
		}
	}
	return ""
}

func phase27FocusedCommandTargetsPackage(command, pkg string) bool {
	for _, field := range strings.Fields(command) {
		if strings.Trim(field, "'\"") == pkg {
			return true
		}
	}
	return false
}

func phase27FocusedCommandRunSelector(t *testing.T, command string) string {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == "-run" {
			if i+1 >= len(fields) {
				t.Fatalf("phase 27 focused command %q has -run without selector", command)
			}
			return strings.Trim(fields[i+1], "'\"")
		}
		if selector, ok := strings.CutPrefix(field, "-run="); ok {
			return strings.Trim(selector, "'\"")
		}
	}
	t.Fatalf("phase 27 focused command %q missing -run selector", command)
	return ""
}

func phase27SecurityCapabilityDisplayPath(t *testing.T, path string) string {
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
