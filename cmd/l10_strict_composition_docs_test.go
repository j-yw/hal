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
		"Strict success is a conjunction", "Rootless Podman remains advisory",
		"internal/strictcomposition", "opaque, short-lived active attestation",
		"ValidateJobCredentialActiveProof", "ValidateJobCredentialCleanupProof", "selection.Bind",
		"same sandbox, execution, worker, Firecracker generation, network plan",
		"clone` or `copy`, never `direct", "active credential proof to have been discarded",
		"cannot recreate selection authority", "Fake or simulated sources can never satisfy that live lane",
		"go test -count=1 ./internal/strictcomposition ./internal/sandbox ./internal/sandboxtarget ./internal/factory ./cmd -run '^TestL10'",
		"go test -count=1 -tags=l10_strict_composition_integration ./internal/strictcomposition -run '^TestL10PreparedLinuxStrictCompositionE2E$'",
		"must fail, rather than skip", "no cloud or billed provider call",
	} {
		if !strings.Contains(doc, required) {
			t.Errorf("L10 strict-composition documentation omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"rootless can satisfy strict", "cached readiness is sufficient", "skip when prerequisites are absent",
		"fallback can remain strict", "warning-bearing strict success",
	} {
		if strings.Contains(strings.ToLower(doc), strings.ToLower(forbidden)) {
			t.Errorf("L10 strict-composition documentation contains forbidden claim %q", forbidden)
		}
	}
}
