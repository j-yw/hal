package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7GoCallRegFuncvalTrampolineDoc = "sandbox-runtime-v2-l8-d7-go-call-reg-funcval-trampoline.md"

func TestL8D7GoCallRegFuncvalTrampolineVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7GoCallRegFuncvalTrampolineDoc))), " ")
	for _, required := range []string{
		"HL8E remains unissued",
		"errEvidenceInputsUnavailable",
		"Prefix membership",
		"`runtime.*`",
		"`syscall.*`",
		"`unix.*`",
		"`internal/runtime/syscall.*`",
		"`MOV r, (AX); CALL r`",
		"`LEA AX, [RSP+disp]`",
		"listed function **start**",
		"only for that trampoline callee",
		"without a proven funcval",
		"traversed subset",
		"complete points-to proof",
		"`requireCompleteHonestIssuanceInputs`",
		"unique/reachable D4/D6",
		"never writes `verified-pinned-callsites.hl8e`",
		"pinned_evidence_default.go",
		"`ImportPinnedCallsiteEvidence`",
		"does not claim D7 live",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"does not change live D7 stub fatals",
		"go test ./tools/microvm/l8/policy/generate -count=1",
		"go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1",
		"go test ./cmd -run '^TestL8D7GoCallRegFuncvalTrampoline|^TestL8D7GoCallRegVEXItab|^TestL8D7HL8E' -count=1",
		"tools/microvm/l8/policy/verify-artifact.sh",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"issue HL8E or enable `generateEvidence` success",
		"generate `verified-pinned-callsites.hl8e` from a fixture",
		"treat a global pointer-taken or LEA inventory as a complete CALL-reg proof",
		"treat L5 images as L8 proof",
		"boot Firecracker or require KVM",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("Go CALL-reg funcval trampoline verification document omits %q", required)
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
			t.Fatalf("Go CALL-reg funcval trampoline verification document contains forbidden claim %q", forbidden)
		}
	}
}
