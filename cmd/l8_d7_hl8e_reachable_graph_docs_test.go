package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7HL8EReachableGraphDoc = "sandbox-runtime-v2-l8-d7-hl8e-reachable-graph.md"

func TestL8D7HL8EReachableGraphVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7HL8EReachableGraphDoc))), " ")
	for _, required := range []string{
		"HL8E remains unissued",
		"entry-point plus call-edge reachable graph",
		"errEvidenceInputsUnavailable",
		"Prefix membership",
		"`runtime.*`",
		"`syscall.*`",
		"`unix.*`",
		"`internal/runtime/syscall.*`",
		"`runtime.reviewerAuthority`",
		"`syscall` / `sysenter` / `int $0x80`",
		"`main.main`",
		"`_start`",
		"pclntab spans as authoritative",
		"every out-of-function relative branch",
		"conditional and loop branches",
		"Ambiguous entry symbols and ELF spans fail closed",
		"truncated transfers",
		"`internal/runtime/syscall.Syscall6`",
		"source-derived `0f05` at offset 12",
		"cmd/hal-guest-init",
		"clock_gettime",
		"exit_group",
		"futex",
		"mmap",
		"rawVforkSyscall",
		"getuid",
		"capget",
		"prlimit64",
		"fail-closed live behavior",
		"not HL8E pinned-direct evidence",
		"pinned_evidence_default.go",
		"never writes `verified-pinned-callsites.hl8e` from a fixture",
		"does not claim D7 live",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"does not change live D7 stub fatals",
		"go test ./tools/microvm/l8/policy/generate -count=1",
		"go test ./internal/sandboxruntime/microvm/guestagent/syscallpolicy -count=1",
		"go test ./cmd -run '^TestL8D7HL8EReachableGraph' -count=1",
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
			t.Fatalf("HL8E reachable-graph verification document omits %q", required)
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
			t.Fatalf("HL8E reachable-graph verification document contains forbidden claim %q", forbidden)
		}
	}
}
