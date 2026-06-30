package sandboxworker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase14WorkerIOVerificationChecklistDocumentsFocusedScope(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "design", "sandbox-runtime-v2-phase14-worker-io-verification.md")
	content, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", docPath, err)
	}
	text := string(content)
	required := []string{
		"go test -timeout=180s ./internal/sandboxworker",
		"go test -timeout=180s ./internal/sandboxworker/...",
		"go test -timeout=180s ./cmd -run 'TestExistingSandboxExecutionDefaultResolversStayWorkerOptIn|TestClientDriverSelectedOnlyWhenExplicitlyConstructed|TestRunSandboxDefaultRuntimeDriverResolver|TestAutoSandboxDefaultRuntimeDriverResolver|TestFactorySandboxDefaultRuntimeDriverResolver'",
		"make build",
		"make vet",
		"The full-suite `go test ./...` command is intentionally skipped",
		"Phase 14 is restricted to focused worker I/O tests",
		"must not exercise unrelated runtime providers or command workflows",
		"must not run `hal run`, `hal auto`, factory execution, real runtime adapters, Podman, Docker, KVM, cloud resources, network proxy, credential proxy, templates, or kits",
	}
	for _, want := range required {
		if !strings.Contains(text, want) {
			t.Fatalf("verification checklist missing %q", want)
		}
	}
}
