package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL2DurableWorkerJobContractAndVerificationDocs(t *testing.T) {
	contract := readL2WorkerJobDoc(t, filepath.Join("..", "docs", "contracts", "sandboxjob-v1.md"))
	normalizedContract := strings.Join(strings.Fields(contract), " ")
	for _, required := range []string{
		"Sandbox Job Contract v1",
		"`sandboxjob-v1`",
		"caller-stable submission identifier",
		"runtime driver and runtime ID",
		"complete accepted execution request",
		"`submission_conflict`",
		"bounded",
		"redacted",
		"cursor",
		"`unknown`",
		"must not rerun",
		"external runtime observation",
		"durable write succeeds",
		"Complete safe lines are durable and readable while execution is still running",
		"recycled process-group ID",
		"does not expose command arguments, environment values, stdin, process IDs, filesystem paths, endpoints, or credentials",
	} {
		if !strings.Contains(contract, required) && !strings.Contains(normalizedContract, required) {
			t.Fatalf("sandboxjob-v1 contract documentation missing %q", required)
		}
	}

	verification := readL2WorkerJobDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l2-durable-worker-jobs-verification.md"))
	normalizedVerification := strings.Join(strings.Fields(verification), " ")
	for _, required := range []string{
		"L2 Durable Worker Jobs Verification",
		"client disconnect",
		"daemon crash and restart",
		"never silently rerun",
		"rootless Podman",
		"process-group cancellation proof",
		"same-UID workload replacing the control FIFO cannot manufacture proof",
		"private digest binds the complete accepted execution request",
		"PID reuse cannot target another group",
		"go test ./internal/sandboxworker ./internal/sandboxexecution ./cmd",
		"go test -race ./internal/sandboxworker ./internal/sandboxruntime/rootlesspodman",
		"go test -tags='podman_integration' ./internal/sandboxworker ./internal/sandboxruntime/rootlesspodman",
		"go test ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"Retention pruning is deferred.",
		"L3",
	} {
		if !strings.Contains(verification, required) && !strings.Contains(normalizedVerification, required) {
			t.Fatalf("L2 verification documentation missing %q", required)
		}
	}
}

func readL2WorkerJobDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
