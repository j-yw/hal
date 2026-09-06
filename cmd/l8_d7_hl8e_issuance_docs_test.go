package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7HL8EIssuanceDoc = "sandbox-runtime-v2-l8-d7-hl8e-issuance.md"

func TestL8D7HL8EIssuanceVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7HL8EIssuanceDoc))), " ")
	for _, required := range []string{
		"HL8E remains unissued",
		"final-binary inspector",
		"-evidence-binaries-dir",
		"-evidence-binary",
		"errEvidenceInputsUnavailable",
		"internal/runtime/syscall.Syscall6",
		"offset 12",
		"source-derived `0f05`",
		"Go 1.25.7",
		"asm_linux_amd64.s",
		"hal-init",
		"hal-guest-agent",
		"hal-guest-credential-helper",
		"hal-guest-mount-monitor",
		"hal-guest-workload-shim",
		"hal-guest-role-bootstrap",
		"cmd/hal-guest-init",
		"missing-role",
		"unique/reachable D4/D6 call graph is unavailable",
		"never writes `verified-pinned-callsites.hl8e`",
		"pinned_evidence_default.go",
		"does not claim D7 live",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"does not change live D7 stub fatals",
		"go test ./tools/microvm/l8/policy/generate -count=1",
		"go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1",
		"go test ./cmd -run '^TestL8D7HL8EIssuance' -count=1",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"issue HL8E or enable `generateEvidence` success",
		"generate `verified-pinned-callsites.hl8e` from a fixture",
		"treat L5 images as L8 proof",
		"boot Firecracker or require KVM",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("HL8E issuance verification document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"D7 prepared-Linux acceptance is accepted",
		"HL8E is issued",
		"HL8E issuance is accepted",
		"D7 live is accepted",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("HL8E issuance verification document contains forbidden claim %q", forbidden)
		}
	}
}
