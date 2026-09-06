package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase16RuntimeInspectionDocumentationCoversVerificationAndScope(t *testing.T) {
	doc := readSandboxRuntimeDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase16-runtime-inspection-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"hal sandbox runtime list <host-id>",
		"hal sandbox runtime list <host-id> --json",
		"hal sandbox runtime list <host-id> --live",
		"hal sandbox runtime list <host-id> --live --json",
		"hal sandbox runtime status <host-id> <runtime-id>",
		"hal sandbox runtime status <host-id> <runtime-id> --json",
		"hal sandbox runtime status <host-id> <runtime-id> --live",
		"hal sandbox runtime status <host-id> <runtime-id> --live --json",
		SandboxRuntimeListContractVersion,
		SandboxRuntimeStatusContractVersion,
		"`contractType`, `contractVersion`, `host`, `source`, `runtimes`,",
		"`contractType`, `contractVersion`, `host`, `runtime`,",
		SandboxRuntimeSourceCached,
		SandboxRuntimeSourceLiveRefreshed,
		SandboxRuntimeSourceUnsupportedLive,
		SandboxRuntimeReadinessReady,
		SandboxRuntimeReadinessUnavailable,
		SandboxRuntimeReadinessUnknown,
		SandboxRuntimeStatusErrorRuntimeNotFound,
		"Cached output reads durable host records only and does not construct worker",
		"Phase 16 does not persist refreshed runtime data",
		"Runtime entries are sorted by runtime id",
		"Raw socket paths, hostnames, credentials, URL query strings, temp paths, and sensitive endpoint details are intentionally omitted.",
		"go test -timeout=120s ./cmd -run 'TestSandboxRuntime(Command|Help|Generated)'",
		"go test -timeout=120s ./cmd -run 'TestContractDocsIncludeSandboxRuntime(List|Status)Fields|TestSandboxRuntime(List|Status)ContractExamplesMatchSchema|TestPhase16RuntimeInspectionDocumentationCoversVerificationAndScope'",
		"go test -timeout=120s ./cmd -run 'TestSandboxRuntimeList'",
		"go test -timeout=120s ./cmd -run 'TestSandboxRuntimeStatus'",
		"go test -timeout=120s ./cmd -run 'TestSandboxRuntimeInspectionDoesNotBleedIntoExecutionCommands|TestSandboxHost(Command|Help|RegisterWorker|List|Status|Delete)'",
		"go test -timeout=120s ./cmd -run 'TestExistingSandboxExecutionDefaultResolversStayWorkerOptIn|TestClientDriverSelectedOnlyWhenExplicitlyConstructed|TestSandboxRuntimeCompat'",
		"make docs-check",
		"git diff --check",
		"go test -timeout=300s ./...",
		"go vet ./...",
		"make build",
		"make lint",
		"Run `make docs-cli` before `make docs-check` when command metadata or examples change.",
		"Phase 16 verification explicitly excludes real worker socket integration tests, Podman workflows, network tests, and sandbox execution behavior changes.",
		"Do not run real worker daemons, bind real worker sockets, contact remote worker hosts, run Podman or Docker workflows, pull images, access cloud resources, open network connections",
		"execute `hal run`, `hal auto`, `hal factory run`, or `hal sandboxd`",
		"Runtime inspection is read-only.",
		"must not write refreshed capability data back to durable host records or alter sandbox runtime selection",
		"Security metadata separates requested controls from enforced controls.",
		"must not claim deny-by-default network enforcement",
		"credential proxy support",
		"network proxy support",
		"microVM isolation",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 16 runtime inspection documentation missing %q", want)
		}
	}
}

func readSandboxRuntimeDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}
