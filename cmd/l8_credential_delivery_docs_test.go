package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	l8CredentialArchitectureDoc = "sandbox-runtime-v2-l8-production-credential-delivery-architecture.md"
	l8CredentialVerificationDoc = "sandbox-runtime-v2-l8-production-credential-delivery-verification.md"
)

func TestL8CredentialDeliveryArchitecture(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	for _, required := range []string{
		"5068151561",
		"5068157402",
		"5068162708",
		"sandbox-runtime-v2-l8-helper-syscall-policy.md",
		"sandbox-runtime-v2-l8-guest-extension-seams.md",
		"guest-agent-v2",
		"sandboxjob-v2",
		"sandboxworker-v1",
		"job_start_v2",
		"LiveSecretSource",
		"keyctl_read",
		"AuthenticatedWorkerPrincipal",
		"CredentialAdmissionAuthorizer",
		"CredentialAdmissionGrant",
		"credential_admission_denied",
		"Source reference IDs are identity, never authorization",
		"same-UID process that can open that socket",
		"VMADDR_CID_HOST",
		"signed ephemeral X25519 handshake",
		"applicationroute.Handler",
		"azure-openai-responses-v1",
		"--no-prompt-templates",
		"--no-themes",
		"intentionally does not set `--no-context-files` or",
		"exclusively leased to one",
		"deployments/<sealed-deployment>/responses?api-version=<sealed-version>",
		"43 unpadded base64url characters",
		"hard lifetime is 35 minutes",
		"dedicated UID/GID 998",
		"musl target `nodejs` 22.22.0",
		"@earendil-works/pi-coding-agent` 0.82.1",
		"/usr/bin/pi --version",
		"Seccomp is not claimed to inspect pathname strings",
		"hal-guest-credential-helper",
		"CAP_SYS_ADMIN",
		"cgroup.kill",
		"JobCredentialActiveProof",
		"JobCredentialCleanupProof",
		"CredentialCleanup *FinalizationCheckpoint",
		"credential_cleanup_incomplete",
		"CredentialCleanup",
		"no arbitrary-public-host fallback",
		"Lazy unmount is not successful cleanup proof",
		"L8 guest asset profile",
		"L6 CONNECT remains an opaque byte tunnel",
		"Rootless Podman remains advisory",
		"Physical zeroization cannot be promised",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 credential-delivery architecture omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"InsecureSkipVerify: true",
		"environment delivery can satisfy",
		"network proof is credential delivery proof",
		"An optional sealed public-key fingerprint set",
		"process-group termination alone is sufficient",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 credential-delivery architecture contains forbidden claim %q", forbidden)
		}
	}
}

func TestL8CredentialDeliveryVerification(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialVerificationDoc))
	liveTag := "l8_production_" + "credential_" + "delivery_live"
	for _, required := range []string{
		"TestL8(CredentialDelivery(Architecture|Verification|DefaultGuards|SourceGuards.*)|D2(GuestHelper|CredentialClient).*)",
		"sandbox-runtime-v2-l8-helper-syscall-policy.md",
		"sandbox-runtime-v2-l8-guest-extension-seams.md",
		"tools/microvm/l8/verify-reproducible.sh",
		"tools/microvm/l8/verify-focused.sh",
		"tools/microvm/l8/verify-selected-live.sh",
		"TestL8PreparedLinuxCredentialDeliveryPrerequisites",
		"TestL8PreparedLinuxCredentialDeliveryE2E",
		liveTag,
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"A selected live test that skips is a failure",
		"rejects every skip event",
		"no internet route",
		"strict `sandboxjob-v2`",
		"initial Pi Azure Responses clean-environment",
		"direct syscall read into locked",
		"distinct `job_*_v2` operations",
		"nested root `sandboxruntime` DTO",
		"unauthorized-host negatives",
		"post-admission in-memory binding without RPC/job",
		"`cgroup.kill`/zero-population proof",
		"mandatory key and algorithm/flag allowlists",
		"server-derived authenticated",
		"trusted same-UID host control-plane boundary",
		"every file that declares either selected prepared-Linux test",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 credential-delivery verification omits %q", required)
		}
	}
}

func TestL8CredentialDeliveryDefaultGuards(t *testing.T) {
	targets := []string{
		filepath.Join("run_sandbox.go"),
		filepath.Join("auto_sandbox.go"),
		filepath.Join("factory_sandbox_executor.go"),
		filepath.Join("..", "internal", "sandboxworker", "job_manager.go"),
		filepath.Join("..", "internal", "sandboxworker", "server.go"),
		filepath.Join("..", "internal", "factory", "secret_broker.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "l7_live_composition.go"),
	}
	sandboxdFiles, err := filepath.Glob("sandboxd*.go")
	if err != nil {
		t.Fatalf("glob sandboxd production composition: %v", err)
	}
	for _, path := range sandboxdFiles {
		if !strings.HasSuffix(path, "_test.go") {
			targets = append(targets, path)
		}
	}
	for _, path := range targets {
		source := readL8CredentialDeliveryFile(t, path)
		for _, forbidden := range []string{
			"guest-agent-v2",
			"JobCredentialRuntime",
			"internal/credentialmemory",
			"internal/credentialproxy",
			"credential_" + "delivery_live",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("default pre-L8 production path %s contains premature live marker %q", filepath.ToSlash(path), forbidden)
			}
		}
	}
}

func readL8CredentialDeliveryFile(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
