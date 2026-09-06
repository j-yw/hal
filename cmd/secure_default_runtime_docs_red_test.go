package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const us009Phase48RuntimeStatusDoc = "sandbox-runtime-v2-phase48-secure-default-runtime-status-verification.md"

func TestUS009RuntimeDocsCLIExamplesExplainStrictVersusCompatibilitySecureDefaultBehavior(t *testing.T) {
	docs := us009ReadRuntimeStatusDocs(t,
		filepath.Join("..", "docs", "cli", "hal_sandbox_runtime.md"),
		filepath.Join("..", "docs", "cli", "hal_sandbox_runtime_list.md"),
		filepath.Join("..", "docs", "cli", "hal_sandbox_runtime_status.md"),
		filepath.Join("..", "docs", "contracts", "sandbox-runtime-list-v1.md"),
		filepath.Join("..", "docs", "contracts", "sandbox-runtime-status-v1.md"),
	)
	normalized := strings.Join(strings.Fields(docs), " ")

	required := []string{
		"strict secure-default readiness",
		"compatibility advisory",
		"`securityReadinessGate`",
		"strict mode reports blocked decisions when required proof is missing",
		"compatibility mode reports advisory diagnostics without claiming live protection",
		"proof-complete allowed",
		"reason-code counts",
	}
	for _, want := range required {
		if !strings.Contains(docs, want) && !strings.Contains(normalized, want) {
			t.Fatalf("runtime CLI/contract docs missing secure-default explanation %q", want)
		}
	}
}

func TestUS009RuntimeDocsExamplesDoNotOverclaimRequestedMetadataAsLiveProof(t *testing.T) {
	docs := us009ReadRuntimeStatusDocs(t,
		filepath.Join("..", "docs", "cli", "hal_sandbox_runtime_list.md"),
		filepath.Join("..", "docs", "cli", "hal_sandbox_runtime_status.md"),
		filepath.Join("..", "docs", "contracts", "sandbox-runtime-list-v1.md"),
		filepath.Join("..", "docs", "contracts", "sandbox-runtime-status-v1.md"),
	)
	normalized := strings.Join(strings.Fields(docs), " ")

	requiredDisclaimers := []string{
		"Requested deny-by-default metadata alone does not prove live deny-by-default enforcement.",
		"Requested credential modes alone do not prove active credential delivery.",
		"Template references without locked digest metadata do not prove digest-locked templates.",
		"Requested VM isolation alone does not prove VM isolation.",
	}
	for _, want := range requiredDisclaimers {
		if !strings.Contains(docs, want) && !strings.Contains(normalized, want) {
			t.Fatalf("runtime docs missing overclaim guardrail %q", want)
		}
	}

	for _, forbidden := range []string{
		"requested deny_by_default proves live deny-by-default",
		"requested network policy proves live protection",
		"requested credential modes are active credentials",
		"requested credentials are active secure delivery",
		"template reference proves digest-locked template",
		"requested vm isolation proves vm isolation",
		"requested microvm runtime proves vm isolation",
	} {
		if strings.Contains(strings.ToLower(docs), forbidden) {
			t.Fatalf("runtime docs overclaim requested metadata as live proof with %q", forbidden)
		}
	}
}

func TestUS009RuntimeDocsVerificationCommandsAreFakeOnly(t *testing.T) {
	doc := us009ReadRuntimeStatusDoc(t, filepath.Join("..", "docs", "design", us009Phase48RuntimeStatusDoc))
	normalized := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Default Phase 48 runtime status/docs verification is fake-only.",
		"Live E2E validation is future Phase 49 scope.",
		"go test -count=1 ./cmd -run 'TestUS009SandboxRuntime'",
		"go test -count=1 ./cmd -run 'TestUS009RuntimeDocs'",
		"go test -count=1 -run '^$' ./...",
		"make docs-check",
		"git diff --check",
		"does not require KVM, Firecracker live boot, real firewall/proxy, real secret broker, Docker/Podman, cloud, or network execution",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("phase 48 runtime status/docs verification documentation missing %q", want)
		}
	}

	commands := us009DocumentedShellCommands(doc)
	for _, command := range commands {
		for _, forbidden := range []string{
			"-tags=integration",
			"-tags=worker_integration",
			"-tags=podman_integration",
			"-tags=firecracker_live",
			"-tags=network_enforcement_live",
			"-tags=credential_delivery_live",
			"HAL_FIRECRACKER_LIVE",
			"HAL_NETWORK_ENFORCEMENT_LIVE",
			"HAL_CREDENTIAL_DELIVERY_LIVE",
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
		} {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 48 runtime docs verification command %q contains forbidden live dependency marker %q", command, forbidden)
			}
		}
	}
}

func us009ReadRuntimeStatusDocs(t *testing.T, paths ...string) string {
	t.Helper()
	var combined strings.Builder
	for _, path := range paths {
		combined.WriteString(us009ReadRuntimeStatusDoc(t, path))
		combined.WriteByte('\n')
	}
	return combined.String()
}

func us009ReadRuntimeStatusDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}

func us009DocumentedShellCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "go test "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "go vet "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "make "):
			commands = append(commands, line)
		case strings.HasPrefix(line, "git diff "):
			commands = append(commands, line)
		}
	}
	return commands
}
