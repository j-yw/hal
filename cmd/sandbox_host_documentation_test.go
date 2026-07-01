package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxHostContractDocsDocumentAutomationSafety(t *testing.T) {
	listDoc := readSandboxHostDoc(t, filepath.Join("..", "docs", "contracts", "sandbox-host-list-v1.md"))
	for _, want := range []string{
		SandboxHostListContractVersion,
		"`contractVersion`",
		"`hosts`",
		"`totals`",
		"sorted by host `name`, then `id`",
		"Raw Unix socket paths, URL hosts, credentials, and query strings are omitted.",
		"Example: Multiple Hosts",
		"Example: Empty Registry",
		"does not contact worker daemons or runtime providers",
	} {
		if !strings.Contains(listDoc, want) {
			t.Fatalf("sandbox-host-list-v1.md missing %q", want)
		}
	}

	statusDoc := readSandboxHostDoc(t, filepath.Join("..", "docs", "contracts", "sandbox-host-status-v1.md"))
	for _, want := range []string{
		SandboxHostStatusContractVersion,
		"`contractVersion`",
		"`source`",
		"`refresh`",
		"`host`",
		SandboxHostStatusSourceCached,
		SandboxHostStatusSourceLiveRefreshed,
		"cached durable registry",
		"live worker refresh",
		"Raw Unix socket paths, URL hosts, credentials, and query strings are omitted.",
		"Example: Cached Status",
		"Example: Live-Refreshed Status",
	} {
		if !strings.Contains(statusDoc, want) {
			t.Fatalf("sandbox-host-status-v1.md missing %q", want)
		}
	}
}

func TestPhase15WorkerHostDocumentationCoversContractsVerificationAndScope(t *testing.T) {
	doc := readSandboxHostDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase15-worker-hosts-verification.md"))
	required := []string{
		"hal sandbox host register worker <id> --socket <path>",
		"hal sandbox host register worker <id> --socket <path> --live",
		"hal sandbox host list --json",
		"hal sandbox host status <id> --json",
		"hal sandbox host status <id> --live --json",
		"hal sandbox host delete <id>",
		SandboxHostListContractVersion,
		SandboxHostStatusContractVersion,
		"`contractVersion`, `hosts`, and `totals`",
		"`contractVersion`, `source`, `refresh`, and `host`",
		"sorted by host name, then id",
		"Raw socket paths, hostnames, credentials, and URL query strings are intentionally omitted.",
		"`cached`",
		"`live-refreshed`",
		"go test -timeout=120s ./cmd -run 'TestSandboxHostCommandScaffoldRegistered|TestSandboxHostHelpListsScaffoldSubcommands'",
		"go test -timeout=120s ./cmd -run 'TestSandboxHostRegisterWorker'",
		"go test -timeout=120s ./cmd -run 'TestSandboxHostList'",
		"go test -timeout=120s ./cmd -run 'TestSandboxHostStatus'",
		"go test -timeout=120s ./cmd -run 'TestSandboxHostDelete'",
		"go test -timeout=120s ./cmd -run 'TestContractDocsIncludeSandboxHostListFields|TestContractDocsIncludeSandboxHostStatusFields|TestSandboxHostContractDocsDocumentAutomationSafety|TestPhase15WorkerHostDocumentationCoversContractsVerificationAndScope'",
		"go test -timeout=180s ./cmd -run 'TestExistingSandboxExecutionDefaultResolversStayWorkerOptIn|TestClientDriverSelectedOnlyWhenExplicitlyConstructed|TestRunSandboxDefaultRuntimeDriverResolver|TestAutoSandboxDefaultRuntimeDriverResolver|TestFactorySandboxDefaultRuntimeDriverResolver'",
		"make docs-check",
		"make build",
		"make vet",
		"go test -timeout=300s ./...",
		"Phase 15 does not implement scheduling, remote worker networking, Podman host management, microVM support, credential proxying, network proxying, or automatic runtime selection.",
		"requested security controls",
		"actually enforced worker controls",
		"must not claim deny-by-default network enforcement",
		"credential proxy support",
		"network proxy support",
		"microVM isolation",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) {
			t.Fatalf("phase 15 worker host documentation missing %q", want)
		}
	}
}

func readSandboxHostDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}
