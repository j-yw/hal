package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7NativePID1SeccompDoc = "sandbox-runtime-v2-l8-d7-native-pid1-seccomp.md"

func TestL8D7NativePID1SeccompVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7NativePID1SeccompDoc))), " ")
	for _, required := range []string{
		"HL8E remains unissued",
		"errEvidenceInputsUnavailable",
		"Prefix membership",
		"`runtime.*`",
		"`syscall.*`",
		"`unix.*`",
		"`internal/runtime/syscall.*`",
		"RoleLaunchBase",
		"prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)",
		"syscall 157",
		"seccomp(SECCOMP_SET_MODE_FILTER)",
		"syscall 317",
		"CompileFilterProfile",
		"FilterProfile(RoleLaunchBase)",
		"AUDIT_ARCH_X86_64",
		"ActionKillProcess",
		"FilterProfile.Decide",
		"sock_fprog",
		"exit_group 127",
		"Filters are inherited and cannot be relaxed",
		"unimplemented `execve`",
		"`clone3`",
		"SCM_RIGHTS",
		"`exactNativeEnvelope()`",
		"`runtimeEnvelope`",
		"pinned_evidence_default.go",
		"never writes `verified-pinned-callsites.hl8e` from a fixture",
		"`requireCompleteHonestIssuanceInputs`",
		"unique/reachable D4/D6",
		"`ImportPinnedCallsiteEvidence`",
		"does not claim D7 live",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"does not change live D7 stub fatals",
		"go test ./tools/microvm/l8/role-bootstrap/generate -count=1",
		"go test ./tools/microvm/l8/policy/generate -count=1",
		"go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1",
		"go test -tags=l8_verified_native_artifact ./internal/sandboxruntime/microvm/guestagent/rolebootstrap -count=1",
		"go test ./cmd -run '^TestL8D7NativePID1Seccomp|^TestL8D7NativeEnvelope|^TestL8D7NativeRoleBootstrap|^TestL8D7HL8E' -count=1",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"issue HL8E or enable `generateEvidence` success",
		"generate `verified-pinned-callsites.hl8e` from a fixture",
		"implement clone3, execve, or SCM_RIGHTS",
		"add `clone` or `clone3` to the Go runtime envelope",
		"add `clone3` or `execve` to the native envelope",
		"treat L5 images as L8 proof",
		"boot Firecracker or require KVM",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("native PID1 seccomp verification document omits %q", required)
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
			t.Fatalf("native PID1 seccomp verification document contains forbidden claim %q", forbidden)
		}
	}
}
