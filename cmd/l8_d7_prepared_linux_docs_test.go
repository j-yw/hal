package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7PreparedLinuxAcceptanceDoc = "sandbox-runtime-v2-l8-d7-prepared-linux-acceptance.md"

func TestL8D7PreparedLinuxAcceptanceDocument(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7PreparedLinuxAcceptanceDoc))
	for _, required := range []string{
		"D7 prepared-Linux acceptance remains unaccepted",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"fixture-as-strict",
		"never treat a fixture as a passing live proof",
		"sealed PID1 expected digests",
		"live helper transport",
		"durable handle store",
		"production L7 session factory",
		"loadPID1StartGateExpected",
		"L8ProcessCompositionFacts",
		"dependency_unaccepted",
		"TestL8PreparedLinuxCredentialDeliveryPrerequisites",
		"TestL8PreparedLinuxCredentialDeliveryE2E",
		"http_only",
		"file_tmpfs_only",
		"ssh_agent_only",
		"all_modes",
		"failure_recovery_matrix",
		"tools/microvm/l8/verify-selected-live.sh prerequisites",
		"tools/microvm/l8/verify-selected-live.sh e2e",
		"never t.Skip after the selected live test is discovered",
		"default go test ./... does not run D7 live tests",
		"`golangci-lint` reported only when `command -v golangci-lint` succeeds",
		"go test ./cmd -run '^TestL8D7PreparedLinux' -count=1",
		"go test ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestL8D7PreparedLinux' -count=1",
		"go vet ./cmd ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
		"environment delivery as strict proof",
		"t.Fatal",
		"VerifiedL8Profile",
		"verified-syscall-policy.hl8q",
		"verified-pinned-callsites.hl8e",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("D7 prepared-Linux acceptance document omits %q", required)
		}
	}
}

func TestL8D7PreparedLinuxAcceptanceDocumentForbidsCompleteClaims(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7PreparedLinuxAcceptanceDoc))
	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"D7 prepared-Linux acceptance is accepted",
		"D7 prepared-Linux acceptance is complete",
		"treat a fixture as a passing live proof",
	} {
		if forbidden == "treat a fixture as a passing live proof" {
			if strings.Contains(doc, "never treat a fixture as a passing live proof") {
				continue
			}
		}
		if strings.Contains(doc, forbidden) {
			t.Fatalf("D7 prepared-Linux acceptance document contains forbidden claim %q", forbidden)
		}
	}
	if !strings.Contains(doc, "fixture-as-strict") || !strings.Contains(doc, "forbidden practice") {
		t.Fatal("D7 prepared-Linux acceptance document does not forbid fixture-as-strict")
	}
}
