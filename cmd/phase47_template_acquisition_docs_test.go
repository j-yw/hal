package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase47SandboxTemplateAcquisitionUserDocs(t *testing.T) {
	doc := readPhase47TemplateAcquisitionDoc(t, filepath.Join("..", "docs", "sandboxtemplate", "README.md"))
	normalized := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Local YAML/JSON acquisition",
		"`local_file`",
		"codex-go.yaml",
		"codex-go.json",
		"`document_digest`",
		"deterministic SHA-256 document digest",
		"Fake OCI acquisition",
		"`oci_artifact`",
		"injected resolver",
		"does not require a live registry",
		"`templateArtifactDigest`",
		"`immutable_digest`",
		"digest-locked references",
		"unresolved mutable references",
		"`metadata.reference`",
		"`runtime.image`",
		"`workspace.ref`",
		"`mutable_reference`",
		"`internal/sandbox.SandboxRuntimeState.TemplateLock`",
		"`internal/sandboxexecution.Manifest.TemplateLock`",
		"`internal/factory.SandboxMetadata.TemplateLock`",
		"`internal/sandboxruntime.RuntimeMetadata.TemplateLock`",
		"`templateLock`",
		"`document`",
		"`templateReference`",
		"`runtimeImage`",
		"`sourceArtifact`",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("phase 47 sandbox template acquisition user docs missing %q", want)
		}
	}
}

func TestPhase47SandboxTemplateAcquisitionVerificationDocs(t *testing.T) {
	doc := readPhase47TemplateAcquisitionDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase47-template-acquisition-verification.md"))
	normalized := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 47 adds local YAML/JSON and fake OCI-like sandbox template acquisition for sandbox runtime templates.",
		"`internal/sandboxtemplate/acquisition` owns resolver request/result contracts, local file acquisition, fake OCI artifact acquisition, deterministic digest locking, sanitized errors, and import-boundary guards.",
		"Local acquisition records a locked template document digest while preserving digest-pinned template references and marking mutable runtime image or workspace references unresolved.",
		"Fake OCI acquisition uses injected resolver fixtures and must not contact a live registry by default.",
		"`internal/sandbox.SandboxRuntimeState.TemplateLock`",
		"`internal/sandboxexecution.Manifest.TemplateLock`",
		"`internal/factory.SandboxMetadata.TemplateLock`",
		"`internal/sandboxruntime.RuntimeMetadata.TemplateLock`",
		"`templateLock`",
		"`document`, `templateReference`, `runtimeImage`, and `sourceArtifact`",
		"For this PRD conversion workflow, use `hal convert` without `--granular`.",
		"Do not run `hal run` as part of the planning phase.",
		"Default Phase 47 verification is fake-only.",
		"Default Phase 47 verification is fake-only and does not require Docker Hub, Docker AI Sandboxes, OCI registries, live network access, Docker, Podman, KVM, Firecracker, cloud credentials, or provider credentials.",
		"Default Phase 47 test commands must not use integration build tags or require live environment variables.",
		"Default `go test ./...` does not run optional live integration tests.",
		"go test -count=1 -timeout=180s ./internal/sandboxtemplate/acquisition",
		"go test -count=1 -timeout=180s ./internal/sandboxtemplate",
		"go test -count=1 ./cmd -run 'TestPhase47SandboxTemplateAcquisition'",
		"go test -count=1 ./cmd -run 'TestPhase47TemplateLock'",
		"go test -count=1 -timeout=420s ./...",
		"make test",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`golangci-lint run ./...` only when `golangci-lint` is installed.",
		"If it is unavailable, report lint unavailable instead of reporting lint as passed.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("phase 47 template acquisition verification docs missing %q", want)
		}
	}
}

func TestPhase47SandboxTemplateAcquisitionOptionalOCIIntegrationDocumentation(t *testing.T) {
	doc := readPhase47TemplateAcquisitionDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase47-template-acquisition-verification.md"))
	normalized := strings.Join(strings.Fields(doc), " ")

	if !phase47MentionsOptionalOCIIntegration(doc, normalized) {
		return
	}

	required := []string{
		"`template_oci_integration`",
		"skip unless required environment variables are set",
		"Default `go test ./...` does not run optional live integration tests.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalized, want) {
			t.Fatalf("phase 47 optional OCI/live integration documentation missing %q", want)
		}
	}
}

func TestPhase47SandboxTemplateAcquisitionVerificationCommandsStayFakeOnly(t *testing.T) {
	doc := readPhase47TemplateAcquisitionDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase47-template-acquisition-verification.md"))
	for _, command := range phase47TemplateAcquisitionGoTestCommands(doc) {
		if strings.Contains(command, "-tags=template_oci_integration") {
			continue
		}
		for _, forbidden := range []string{
			"-tags=integration",
			"-tags=worker_integration",
			"-tags=podman_integration",
			"-tags=firecracker_live",
			"-tags=template_oci_integration",
			"HAL_TEMPLATE_OCI_",
			"DOCKER_HOST",
			"docker ",
			"podman ",
			"hal run",
		} {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 47 default verification command %q uses forbidden live/planning marker %q", command, forbidden)
			}
		}
	}
}

func readPhase47TemplateAcquisitionDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}

func phase47MentionsOptionalOCIIntegration(doc string, normalized string) bool {
	markers := []string{
		"optional OCI",
		"optional live",
		"OCI/live integration",
		"live OCI integration",
		"live integration tests",
		"template_oci_integration",
	}
	for _, marker := range markers {
		if strings.Contains(doc, marker) || strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func phase47TemplateAcquisitionGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}
