package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase25CredentialProxyVerificationDocs(t *testing.T) {
	doc := readPhase25CredentialProxyDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase25-credential-proxy-plan-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 25 establishes the metadata-only and fake-only credential proxy plan foundation",
		"`internal/sandbox/credential_proxy.go`",
		"`internal/sandbox/credential_proxy_test.go`",
		"`internal/sandbox/credential_proxy_validation.go`",
		"`internal/sandbox/credential_proxy_normalization.go`",
		"`internal/sandbox/credential_proxy_sanitize.go`",
		"`internal/factory/secret_broker_credential_proxy.go`",
		"`internal/sandbox/credential_proxy_network_proxy.go`",
		"`internal/sandbox/credential_proxy_import_boundary_test.go`",
		"Credential proxy contracts",
		"Safe References",
		"Guard Coverage",
		"Unchanged JSON Surfaces",
		"Command JSON, run/auto manifest JSON, factory run record JSON, and factory timeline event JSON surfaces remain unchanged in Phase 25.",
		"No command, manifest, factory record, or timeline JSON surface gains credential proxy fields in Phase 25.",
		"`credentialProxy`, `credentialProxyPlan`, `credentialProxySession`, and `credentialProxyBindings`",
		"Phase 25 verification is fake-only.",
		"Phase 25 fake-only verification has no real network access, live proxy server, credential injection, tmpfs mount, SSH-agent forwarding, firewall mutation, Docker, Podman, KVM, cloud credentials, worker daemon, microVM, runtime/provider integration, or provider credential requirement.",
		"Default Phase 25 test commands must not use integration build tags or require live environment variables.",
		"No live proxying",
		"No credential injection",
		"No tmpfs delivery",
		"No SSH-agent forwarding",
		"No firewall enforcement",
		"No worker daemon changes",
		"No runtime/provider integration",
		"No command JSON surface changes",
		"No manifest JSON surface changes",
		"No factory record JSON surface changes",
		"No timeline JSON surface changes",
		"Future phases are responsible for live credential proxy delivery, credential injection, tmpfs delivery integration, SSH-agent forwarding integration, firewall enforcement integration, worker daemon support, concrete runtime/provider integration, and durable command/factory plumbing.",
		"go test -timeout=120s ./internal/sandbox -run 'TestCredentialProxy'",
		"go test -timeout=120s ./internal/factory -run 'TestCredentialProxyReferencesSecretBrokerMetadataBySafeIDs|TestCredentialProxySecretBrokerHelperDropsUnsafeSecretReferences'",
		"go test -timeout=120s ./cmd -run 'Test(RunAndAutoSandboxManifestsOmitCredentialProxyMetadataInPhase25|Phase25NonFactoryManifestSourcesDoNotPersistCredentialProxyMetadata|FactoryPersistenceOmitsCredentialProxyMetadataInPhase25|Phase25FactorySourcesDoNotPersistCredentialProxyMetadata|Phase25CredentialProxy(VerificationDocs|FakeOnlyVerification))'",
		"go test -timeout=300s ./...",
		"go vet ./...",
		"git diff --check",
		"make build",
		"make lint",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 25 credential proxy verification documentation missing %q", want)
		}
	}

	unsupportedClaims := []string{
		"live proxying is implemented",
		"live credential proxy delivery is implemented",
		"credential injection is implemented",
		"tmpfs delivery is implemented",
		"SSH-agent forwarding is implemented",
		"firewall enforcement is implemented",
		"worker daemon support is implemented",
		"runtime/provider integration is implemented",
		"command JSON surface changes are implemented",
		"manifest JSON surface changes are implemented",
		"factory record JSON surface changes are implemented",
		"timeline JSON surface changes are implemented",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 25 credential proxy documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase25CredentialProxyFakeOnlyVerification(t *testing.T) {
	doc := readPhase25CredentialProxyDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase25-credential-proxy-plan-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 25 verification is fake-only.",
		"Phase 25 fake-only verification has no real network access, live proxy server, credential injection, tmpfs mount, SSH-agent forwarding, firewall mutation, Docker, Podman, KVM, cloud credentials, worker daemon, microVM, runtime/provider integration, or provider credential requirement.",
		"Default Phase 25 test commands must not use integration build tags or require live environment variables.",
		"go test -timeout=120s ./cmd -run 'Test(RunAndAutoSandboxManifestsOmitCredentialProxyMetadataInPhase25|Phase25NonFactoryManifestSourcesDoNotPersistCredentialProxyMetadata|FactoryPersistenceOmitsCredentialProxyMetadataInPhase25|Phase25FactorySourcesDoNotPersistCredentialProxyMetadata|Phase25CredentialProxy(VerificationDocs|FakeOnlyVerification))'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 25 credential proxy fake-only verification documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"requires real network access",
		"requires network access",
		"requires live proxy",
		"requires credential injection",
		"requires tmpfs",
		"requires SSH-agent",
		"requires firewall",
		"requires Docker",
		"requires Podman",
		"requires KVM",
		"requires cloud credentials",
		"requires worker daemon",
		"requires microVM",
		"requires runtime/provider integration",
		"requires provider credentials",
		"requires integration build tags",
		"requires live environment variables",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 25 credential proxy fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase25FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 25 credential proxy verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase25ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 25 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}
}

func readPhase25CredentialProxyDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}

func phase25FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase25ForbiddenFocusedCommandRequirements() []string {
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
