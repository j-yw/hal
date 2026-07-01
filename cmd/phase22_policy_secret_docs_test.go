package cmd

import (
	"os"
	"path/filepath"
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

func readPhase22PolicySecretDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}
