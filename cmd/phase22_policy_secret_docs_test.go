package cmd

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestPhase22PolicySecretDocs(t *testing.T) {
	doc := readPhase22PolicySecretDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase22-policy-secret-broker-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 22 establishes the fake-only network policy and secret broker foundation",
		"Network policy model",
		"typed policy presets",
		"requested policy intent",
		"enforcement capability",
		"effective policy result",
		"Effective policy evaluation",
		"derives effective intent and enforcement mode only from capability metadata",
		"downgrades unsupported strict policy to `legacy_default` with `none` enforcement",
		"Secret broker metadata",
		"raw `ResolvedRunSecret.Value` data stays in unexported in-memory session maps",
		"`SecretBrokerSessionMetadata` and `SecretBrokerSecretMetadata` are durable JSON-safe metadata only",
		"Redaction guarantees",
		"`RunSecretRedactor`",
		"`Store.SaveRunWithRedactor`",
		"`Store.AppendEventWithRedactor`",
		"`Store.AppendLogChunkWithRedactor`",
		"Fake-only scope",
		"go test -timeout=120s ./internal/sandbox -run 'TestNetworkPolicy|TestEffectiveNetworkPolicy|TestSandboxSecurityCompatibility'",
		"go test -timeout=120s ./internal/factory -run 'TestSecretBroker|TestSecretBrokerRedaction|TestSecretBrokerMarshalSafety'",
		"go test -timeout=120s ./internal/compound -run 'TestSandboxPolicyConfig|TestSandboxConfig'",
		"go test -timeout=120s ./cmd -run 'TestSandboxSecurityMetadata|TestFactorySandboxSecurityPolicyEvent|TestPhase22PolicySecretDocs'",
		"go test -timeout=300s ./...",
		"go vet ./...",
		"git diff --check",
		"docs/contracts examples are updated only when command JSON or durable record contracts change.",
		"No proxy or firewall enforcement",
		"No credential proxying",
		"No tmpfs secret files",
		"No SSH agent forwarding",
		"No default behavior changes",
		"No microVM or container runtime work",
		"No factory rewrite",
		"No raw secret persistence",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 22 policy/secret documentation missing %q", want)
		}
	}

	unsupportedClaims := []string{
		"requires proxy enforcement",
		"requires firewall enforcement",
		"requires credential proxying",
		"requires tmpfs secret files",
		"requires SSH agent forwarding",
		"requires default behavior changes",
		"requires microVM",
		"requires container runtime",
		"requires factory rewrite",
		"persists raw secrets",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 22 policy/secret documentation makes unsupported claim %q", claim)
		}
	}
}

func TestPhase22PolicySecretFakeOnlyVerification(t *testing.T) {
	doc := readPhase22PolicySecretDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase22-policy-secret-broker-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 22 fake-only verification has no real network calls, Docker, Podman, cloud credentials, worker daemon, microVM, live proxy/firewall, or provider credential requirement.",
		"Default Phase 22 test commands must not use integration build tags or require live environment variables.",
		"go test -timeout=120s ./cmd -run 'TestPhase22PolicySecret(Docs|FakeOnlyVerification)'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 22 fake-only verification documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"requires real network calls",
		"requires network calls",
		"requires Docker",
		"requires Podman",
		"requires cloud credentials",
		"requires worker daemon",
		"requires a worker daemon",
		"requires microVM",
		"requires live proxy",
		"requires live firewall",
		"requires provider credentials",
		"requires integration build tags",
		"requires live environment variables",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 22 fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase22FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 22 verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase22ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 22 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	for _, path := range phase22PolicySecretDefaultTestFiles(t) {
		source := readPhase22PolicySecretDoc(t, path)
		rel := phase22PolicySecretDisplayPath(t, path)
		header := phase22PolicySecretSourceHeader(source)
		for _, tag := range []string{"integration", "worker_integration", "podman_integration"} {
			if strings.Contains(header, tag) {
				t.Fatalf("%s uses integration build tag %q; Phase 22 default tests must stay fake-only", rel, tag)
			}
		}
		if phase22PolicySecretRequiresLiveEnv(source) {
			t.Fatalf("%s requires live integration environment variables; Phase 22 default tests must stay fake-only", rel)
		}
	}
}

func readPhase22PolicySecretDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}

func phase22FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase22ForbiddenFocusedCommandRequirements() []string {
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

func phase22PolicySecretDefaultTestFiles(t *testing.T) []string {
	t.Helper()
	patterns := []string{
		"phase22_policy_secret_docs_test.go",
		"sandbox_security_metadata_test.go",
		filepath.Join("..", "internal", "sandbox", "network_policy*_test.go"),
		filepath.Join("..", "internal", "sandbox", "security_test.go"),
		filepath.Join("..", "internal", "factory", "secret*_test.go"),
		filepath.Join("..", "internal", "compound", "config_test.go"),
	}
	var files []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("Glob(%s) error: %v", pattern, err)
		}
		if len(matches) == 0 {
			t.Fatalf("phase 22 fake-only guard pattern %s matched no files", pattern)
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	return files
}

func phase22PolicySecretDisplayPath(t *testing.T, path string) string {
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

func phase22PolicySecretSourceHeader(source string) string {
	lines := strings.Split(source, "\n")
	var header []string
	for _, line := range lines {
		if strings.HasPrefix(line, "package ") {
			break
		}
		header = append(header, line)
	}
	return strings.Join(header, "\n")
}

func phase22PolicySecretRequiresLiveEnv(source string) bool {
	getenvCall := "os." + "Getenv"
	lookupEnvCall := "os." + "LookupEnv"
	if !strings.Contains(source, getenvCall) && !strings.Contains(source, lookupEnvCall) {
		return false
	}
	for _, marker := range phase22LiveEnvironmentMarkers() {
		if strings.Contains(source, marker) {
			return true
		}
	}
	return false
}

func phase22LiveEnvironmentMarkers() []string {
	return []string{
		"HAL_WORKER_INTEGRATION_",
		"HAL_PODMAN_" + "TEST_IMAGE",
		"DOCKER_HOST",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"CLOUDSDK_",
		"OPENAI_API_KEY",
		"ANTHROPIC_API_KEY",
	}
}
