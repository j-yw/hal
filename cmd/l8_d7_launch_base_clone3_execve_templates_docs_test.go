package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7LaunchBaseClone3ExecveTemplatesDoc = "sandbox-runtime-v2-l8-d7-launch-base-clone3-execve-templates.md"

func TestL8D7LaunchBaseClone3ExecveTemplatesVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7LaunchBaseClone3ExecveTemplatesDoc))), " ")
	for _, required := range []string{
		"HL8E remains unissued",
		"errEvidenceInputsUnavailable",
		"Prefix membership",
		"`runtime.*`",
		"`syscall.*`",
		"`unix.*`",
		"`internal/runtime/syscall.*`",
		"template-bound not catalog-name-bound",
		"clone3",
		"CLONE_VFORK|CLONE_VM|CLONE_PIDFD",
		"CLONE_NEWNS",
		"CLONE_INTO_CGROUP",
		"exit_signal=SIGCHLD",
		"cgroup=9",
		"Go 1.25.7",
		"size 88",
		"/usr/bin/hal-guest-credential-helper",
		"/usr/bin/hal-guest-agent",
		"/usr/bin/hal-guest-mount-monitor",
		"/usr/bin/hal-guest-workload-shim",
		"envp NULL",
		"FAIL CLOSED",
		"does not allow all execve",
		"SCM_RIGHTS",
		"`sendmsg`",
		"`recvmsg`",
		"`runtimeEnvelope`",
		"does not claim D7 live",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"does not change live D7 stub fatals",
		"go test ./tools/microvm/l8/policy/generate -count=1",
		"go test ./tools/microvm/l8/role-bootstrap/generate -count=1",
		"go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1",
		"go test -tags=l8_verified_native_artifact ./internal/sandboxruntime/microvm/guestagent/rolebootstrap -count=1",
		"go test ./cmd -run '^TestL8D7LaunchBaseClone3ExecveTemplates|^TestL8D7NativePID1Clone3Execve|^TestL8D7NativePID1Seccomp|^TestL8D7HL8E' -count=1",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"issue HL8E or enable `generateEvidence` success",
		"allow unrestricted clone3 or execve",
		"implement SCM_RIGHTS, sendmsg, or recvmsg",
		"add `clone` or `clone3` to the Go runtime envelope",
		"treat L5 images as L8 proof",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("launch-base clone3/execve templates verification document omits %q", required)
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
			t.Fatalf("launch-base clone3/execve templates verification document contains forbidden claim %q", forbidden)
		}
	}
}
