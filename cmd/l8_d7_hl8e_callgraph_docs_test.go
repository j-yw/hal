package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7HL8ECallgraphDoc = "sandbox-runtime-v2-l8-d7-hl8e-callgraph.md"

func TestL8D7HL8ECallgraphVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7HL8ECallgraphDoc))), " ")
	for _, required := range []string{
		"HL8E is issued",
		"unique/reachable D4/D6 callsite graph",
		"D7 live remains disabled",
		"errEvidenceInputsUnavailable",
		"internal/runtime/syscall.Syscall6",
		"offset 12",
		"source-derived instruction template",
		"Go 1.25.7",
		"asm_linux_amd64.s",
		"non-authority / not the pinned-direct path",
		"unique/reachable D4/D6 call graph is unavailable",
		"verified-pinned-callsites.hl8e",
		"pinned_callsite_evidence_expected_d7_gen.go",
		"l8_verified_pinned_callsite_evidence",
		"ImportPinnedCallsiteEvidence",
		"EmbeddedVerifiedPolicyArtifact",
		"launch-base plus pinned Go runtime",
		"does not claim D7 live",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"does not change live D7 stub fatals",
		"pinned_evidence_default.go",
		"does not treat L5 images as L8",
		"go test ./tools/microvm/l8/policy/generate -count=1",
		"go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1",
		"go test -tags=l8_verified_policy_artifact,l8_verified_pinned_callsite_evidence ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1",
		"go test ./cmd -run '^TestL8D7HL8ECallgraph' -count=1",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"generate `verified-pinned-callsites.hl8e` from a fixture",
		"treat L5 images as L8 proof",
		"boot Firecracker or require KVM",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("HL8E callgraph verification document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"D7 prepared-Linux acceptance is accepted",
		"D7 live is accepted",
		"HL8E remains unissued",
		"HL8E issuance is still disabled",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("HL8E callgraph verification document contains forbidden claim %q", forbidden)
		}
	}
}
