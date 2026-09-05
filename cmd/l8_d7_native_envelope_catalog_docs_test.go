package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7NativeEnvelopeCatalogDoc = "sandbox-runtime-v2-l8-d7-native-envelope-catalog.md"

func TestL8D7NativeEnvelopeCatalogVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7NativeEnvelopeCatalogDoc))), " ")
	for _, required := range []string{
		"HL8E remains unissued",
		"explicit D7 catalog authority",
		"errEvidenceInputsUnavailable",
		"Prefix membership",
		"`runtime.*`",
		"`syscall.*`",
		"`unix.*`",
		"`internal/runtime/syscall.*`",
		"`runtime.reviewerAuthority`",
		"`runtimeEnvelope`",
		"`exactRuntimeEnvelope()`",
		"`getppid`",
		"`main.main`",
		"`clone` and `clone3` are not added",
		"process-creation/shim authority",
		"`nativeEnvelope`",
		"`exactNativeEnvelope()`",
		"used only for the native bootstrap binary",
		"launch-bootstrap origin-1",
		"identity preflight plus the PID1 listen-table subset",
		"`getuid`",
		"`geteuid`",
		"`getgid`",
		"`getegid`",
		"`capget`",
		"`prlimit64`",
		"`socket`",
		"`bind`",
		"`listen`",
		"`dup3`",
		"`close`",
		"`prctl`",
		"`seccomp`",
		"`exit_group`",
		"`clone3` and `execve` are not added",
		"still exit 127 after listen",
		"`internal/runtime/syscall.Syscall6`",
		"`0f05` at offset 12",
		"Unknown-number sites",
		"Remaining extras after this slice are `clone` and `clone3`",
		"not HL8E pinned-direct evidence",
		"singular `-evidence-binary`",
		"pinned_evidence_default.go",
		"never writes `verified-pinned-callsites.hl8e` from a fixture",
		"`requireCompleteHonestIssuanceInputs`",
		"unique/reachable D4/D6",
		"does not claim D7 live",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"does not change live D7 stub fatals",
		"go test ./tools/microvm/l8/policy/generate -count=1",
		"go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1",
		"go test ./cmd -run '^TestL8D7NativeEnvelope|^TestL8D7RuntimeEnvelope|^TestL8D7HL8E' -count=1",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"issue HL8E or enable `generateEvidence` success",
		"generate `verified-pinned-callsites.hl8e` from a fixture",
		"add `clone` or `clone3` to the Go runtime envelope",
		"add `clone3` or `execve` to the native envelope",
		"treat L5 images as L8 proof",
		"boot Firecracker or require KVM",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("native-envelope catalog verification document omits %q", required)
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
			t.Fatalf("native-envelope catalog verification document contains forbidden claim %q", forbidden)
		}
	}
}
