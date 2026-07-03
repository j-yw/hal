package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase44SandboxTemplatesVerificationDocs(t *testing.T) {
	doc := readPhase44Doc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase44-sandbox-templates-kits-verification.md"))
	normalized := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 44 adds a pure, fake-safe sandbox runtime template contract in `internal/sandboxtemplate`.",
		"The package is distinct from `internal/template`",
		"structured YAML/JSON decoding",
		"redaction-safe validation",
		"durable sanitization",
		"digest-pinned reference preservation",
		"data-only projection into existing sandbox/runtime DTOs",
		"Phase 44 does not implement image builds, OCI pulls, Git fetches, runtime execution, workspace mutation, network enforcement, credential delivery, Docker AI Sandboxes, Docker Hub requirements, hosted services, or live provider integration.",
		"go test -count=1 -timeout=180s ./internal/sandboxtemplate",
		"go test -count=1 -timeout=180s ./internal/sandbox ./internal/sandboxruntime/microvm",
		"go test -count=1 ./cmd -run 'TestPhase44SandboxTemplates'",
		"go test -count=1 -timeout=420s ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"Phase 44 verification is fake-only.",
		"does not require network access, Docker, Podman, OCI registries, Git remotes, KVM, Firecracker, root privileges, cloud credentials, provider credentials, worker daemons, live sandboxd, live proxy servers, firewall mutation, credential broker delivery, tmpfs mounts, SSH-agent forwarding, or environment secret injection.",
		"TestSandboxTemplateContractFieldsAndJSONTags",
		"TestDecodeBytesYAML",
		"TestNormalizeTemplateTrimsSafeFieldsAndNormalizesEnums",
		"TestValidateTemplateRejectsUnsafeURLsPathsSecretsAndCommands",
		"TestSanitizeTemplateRemovesUnsafeOptionalMetadata",
		"TestProjectRuntimeStatePreservesBaseAndLaunchDigests",
		"TestProjectNetworkPolicyDoesNotClaimEnforcement",
		"TestSandboxTemplateProductionImportsStayPure",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("phase 44 sandbox templates verification docs missing %q", want)
		}
	}

	unsupported := []string{
		"image builds are implemented",
		"OCI pulls are implemented",
		"Git fetches are implemented",
		"runtime execution is implemented",
		"workspace mutation is implemented",
		"network enforcement is implemented",
		"credential delivery is implemented",
		"Docker AI Sandboxes are required",
		"Docker Hub is required",
	}
	for _, claim := range unsupported {
		if strings.Contains(doc, claim) || strings.Contains(normalized, claim) {
			t.Fatalf("phase 44 verification docs make unsupported claim %q", claim)
		}
	}
}

func TestPhase44SandboxTemplatesUserDocs(t *testing.T) {
	doc := readPhase44Doc(t, filepath.Join("..", "docs", "sandboxtemplate", "README.md"))
	normalized := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Sandbox runtime templates describe sandbox requirements.",
		"separate from Hal project templates",
		"Phase 44 templates are contracts only.",
		"Hal does not build images, pull artifacts, fetch Git repositories, execute runtimes, enforce network policy, or deliver credentials from these files.",
		"apiVersion: sandbox-template.hal.dev/v1",
		"kind: SandboxTemplate",
		"kind: oci_artifact",
		"kind: oci_image",
		"`clone` and `copy` are not unsafe by default.",
		"`direct` means the sandbox may operate against a directly shared workspace and must be treated as trusted-only or unsafe.",
		"A reference with valid digest metadata is digest-pinned.",
		"A reference without digest metadata is unresolved mutable metadata.",
		"Network requirements are requested policy metadata.",
		"Credential requirements are requested delivery metadata.",
		"Setup commands are descriptors only.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("phase 44 sandbox template user docs missing %q", want)
		}
	}
}

func readPhase44Doc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}
