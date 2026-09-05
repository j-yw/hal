package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL10StrictCompositionDocumentationIsNormative(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l10-strict-composition.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(payload)
	for _, required := range []string{
		"5068151561", "5068157402", "5068162708",
		"c3922c2dc0b11d2e731d451e669d8c3c1ba1444b",
		"L10 remains unaccepted and default-off",
		"Strict success is a conjunction", "Rootless Podman remains advisory",
		"internal/strictcomposition", "opaque, short-lived active attestation",
		"ValidateJobCredentialActiveProof", "ValidateJobCredentialCleanupProof", "selection.Bind",
		"same sandbox, execution, worker, Firecracker generation, network plan",
		"clone` or `copy`, never `direct", "active credential proof",
		"cannot recreate selection authority", "Fake or simulated sources never establish live authority",
		"go test -count=1 ./internal/strictcomposition ./internal/sandbox ./internal/sandboxtarget ./internal/factory ./cmd -run '^TestL10'",
		"go test -count=1 ./cmd -run '^TestL11FinalClosure'",
		"No selected L10 live lane exists", "no cloud or billed provider call",
	} {
		if !strings.Contains(doc, required) {
			t.Errorf("L10 strict-composition documentation omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"rootless can satisfy strict", "cached readiness is sufficient", "skip when prerequisites are absent",
		"fallback can remain strict", "warning-bearing strict success",
		"357090101f8479ed11a6a84976787a9c09a1f4ff", "-tags=l10_strict_composition_integration",
		"TestL10PreparedLinuxStrictCompositionE2E",
	} {
		if strings.Contains(strings.ToLower(doc), strings.ToLower(forbidden)) {
			t.Errorf("L10 strict-composition documentation contains forbidden claim %q", forbidden)
		}
	}
}
