package sandboxworkspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase10VerificationChecklistDocumentsRequiredCommands(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "design", "sandbox-runtime-v2-phase10-verification.md")
	content, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", docPath, err)
	}
	text := string(content)
	required := []string{
		"go test -timeout=180s ./internal/sandboxworkspace ./internal/sandboxexec ./cmd ./internal/sandboxexecution ./internal/sandbox ./internal/factory",
		"git diff --check",
		"go test -timeout=300s ./...",
		"without running `hal run`",
	}
	for _, command := range required {
		if !strings.Contains(text, command) {
			t.Fatalf("verification checklist missing %q", command)
		}
	}
}
