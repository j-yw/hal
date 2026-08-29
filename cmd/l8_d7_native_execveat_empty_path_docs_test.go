package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7NativeExecveatEmptyPathDoc = "sandbox-runtime-v2-l8-d7-native-execveat-empty-path.md"

func TestL8D7NativeExecveatEmptyPathVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7NativeExecveatEmptyPathDoc))), " ")
	for _, required := range []string{
		"HL8E remains unissued",
		"errEvidenceInputsUnavailable",
		"Prefix membership",
		"`runtime.*`",
		"`syscall.*`",
		"`unix.*`",
		"`internal/runtime/syscall.*`",
		"template-bound not catalog-name-bound",
		"execveat",
		"AT_EMPTY_PATH",
		"FD 5",
		"FD 6",
		"envp NULL",
		"exit_group 127",
		"does not exit 0",
		"FAIL CLOSED",
		"does not allow unrestricted `execve`/`execveat`",
		"Controller and agent have no PID1-held sealed executable FD",
		"live `open()` of `/usr/bin/hal-guest-*`",
		"FD-admission gap",
		"Pathname `execve` (59) is no longer a native `_start` site",
		"Native PID1 is the image-init supervisor",
		"Go PID1 remains ForkExec-free",
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
		"go test ./cmd -run '^TestL8D7NativeExecveatEmptyPath|^TestL8D7NativePID1SCMRights|^TestL8D7NativePID1Clone3Execve|^TestL8D7NativePID1Seccomp|^TestL8D7NativeEnvelope|^TestL8D7NativeRoleBootstrap|^TestL8D7HL8E' -count=1",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"issue HL8E or enable `generateEvidence` success",
		"generate `verified-pinned-callsites.hl8e` from a fixture",
		"allow unrestricted execve or execveat",
		"add `execve` or `execveat` to the Go runtime envelope",
		"treat L5 images as L8 proof",
		"boot Firecracker or require KVM",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("native execveat AT_EMPTY_PATH verification document omits %q", required)
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
			t.Fatalf("native execveat AT_EMPTY_PATH verification document contains forbidden claim %q", forbidden)
		}
	}
}
