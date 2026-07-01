package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase24NetworkProxyVerificationDocs(t *testing.T) {
	doc := readPhase24NetworkProxyDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase24-network-proxy-policy-log-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 24 adds data-only, redaction-safe network proxy session and network policy decision-log contracts",
		"Proxy and decision-log contracts",
		"`internal/sandbox/network_proxy.go`",
		"`internal/sandbox/network_proxy_validation.go`",
		"`internal/sandbox/network_proxy_import_boundary_test.go`",
		"schema coverage",
		"validation and normalization coverage",
		"import-boundary coverage",
		"redaction coverage",
		"JSON marshal coverage",
		"compatibility-runtime coverage",
		"metadata plumbing coverage",
		"`sandboxexecution.Manifest`",
		"`factory.SandboxMetadata`",
		"`factory.EventRecord`",
		"compatibility enforcement semantics",
		"`audit_only`, `none`, `best_effort`, and `legacy_default`",
		"Phase 24 verification is fake-only.",
		"Phase 24 does not implement a live HTTP proxy, firewall rules, credential proxying, tmpfs secret delivery, SSH-agent delivery, Podman/Docker/KVM/cloud integration, or microVM runtime implementation.",
		"Future phases are responsible for live proxy enforcement, firewall integration, credential proxy delivery, secret delivery integrations, concrete runtime/provider integration, and end-to-end network-policy enforcement.",
		"go test -timeout=120s ./internal/sandbox -run 'TestNetworkProxyDecisionContractConstants|TestNetworkProxySessionMetadataJSONSchema|TestNetworkPolicyDecisionLogRecordJSONSchema|TestNetworkProxyContractsExposeNoRawRequestFields'",
		"go test -timeout=120s ./internal/sandbox -run 'TestNetworkProxyImportBoundaries|TestNetworkProxyImportBoundaryCoversProductionContractFiles|TestNetworkProxyForbiddenImportListCoversRequiredBoundaries|TestNetworkProxyImportBoundaryAllowsStandardLibraryMetadataHelpersOnly|TestNetworkProxyContractsDoNotExposeLiveRuntimeHelpers|TestNetworkProxyContractSourceOmitsLiveRuntimeOperationMarkers'",
		"go test -timeout=120s ./internal/sandbox -run 'TestNetworkProxySessionValidation|TestNetworkPolicyDecisionLogValidation|TestNetworkProxySessionMetadataSanitization|TestNetworkPolicyDecisionLogSanitization'",
		"go test -timeout=120s ./internal/sandboxexecution -run 'TestManifestJSONFieldsAndSandboxMetadataTypes|TestManifestUnmarshalWithoutArtifactMetadata'",
		"go test -timeout=120s ./internal/factory -run 'TestSandboxMetadata(NetworkProxySessionJSONShape|NetworkProxySessionJSONRedactionSafety)|TestEventRecord(NetworkPolicyDecisionLogsJSONFields|OptionalFieldsOmitted)'",
		"go test -timeout=120s ./cmd -run 'TestRunAndAutoSandboxManifests|TestFactory(SandboxMetadata|SandboxPersistentMetadata|Timeline|Status).*Network|TestFactorySandboxSecurityPolicyEventAttachesSanitizedDecisionLogs|TestFactorySandboxNetworkProxyMetadataPlumbingAvoidsLiveAdapterImports'",
		"go test -timeout=120s ./cmd -run 'TestPhase24NetworkProxy(VerificationDocs|FakeOnlyVerification)'",
		"go test -timeout=300s ./...",
		"go vet ./...",
		"git diff --check",
		"make build",
		"make lint",
		"No live HTTP proxy",
		"No firewall rules",
		"No credential proxying",
		"No tmpfs secret delivery",
		"No SSH-agent delivery",
		"No Podman, Docker, KVM, or cloud integration",
		"No microVM runtime implementation",
		"No default behavior changes",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 24 network proxy verification documentation missing %q", want)
		}
	}

	unsupportedClaims := []string{
		"live HTTP proxy is implemented",
		"firewall rules are implemented",
		"credential proxying is implemented",
		"tmpfs secret delivery is implemented",
		"SSH-agent delivery is implemented",
		"Podman integration is implemented",
		"Docker integration is implemented",
		"KVM integration is implemented",
		"cloud integration is implemented",
		"microVM runtime implementation is complete",
		"microVM enforcement is implemented",
		"live proxy enforcement is implemented",
		"firewall enforcement is implemented",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 24 network proxy documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase24NetworkProxyFakeOnlyVerification(t *testing.T) {
	doc := readPhase24NetworkProxyDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase24-network-proxy-policy-log-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 24 fake-only verification has no real network calls, live HTTP proxy, firewall mutation, Docker, Podman, KVM, cloud credentials, worker daemon, microVM, credential proxy, tmpfs secret delivery, SSH-agent delivery, or provider credential requirement.",
		"Default Phase 24 test commands must not use integration build tags or require live environment variables.",
		"go test -timeout=120s ./cmd -run 'TestPhase24NetworkProxy(VerificationDocs|FakeOnlyVerification)'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 24 fake-only verification documentation missing %q", want)
		}
	}

	commands := phase24FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 24 verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase24ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 24 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}
}

func readPhase24NetworkProxyDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}

func phase24FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase24ForbiddenFocusedCommandRequirements() []string {
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
