package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase20LeaseAwareSchedulerDocumentationCoversVerificationAndScope(t *testing.T) {
	doc := readSandboxSchedulerPhase20Doc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase20-lease-aware-scheduler-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 20 covers the lease-aware scheduler",
		"`hal run --sandbox`, `hal auto --sandbox`, and `hal factory run --sandbox`",
		"preserves the legacy default sandbox resolver when no `--sandbox-host` or `--sandbox-runtime` flag is provided",
		"The scheduler is a cached metadata decision layer.",
		"filters by explicit host, cached health, runtime, isolation, and lease-aware capacity",
		"ranks candidates deterministically",
		"Command code owns lease acquisition, release, and persistence.",
		"Persisted metadata must include only safe `SandboxLeaseRef` or factory `SandboxLeaseMetadata` fields",
		"must omit lease holders, endpoints, hostnames, filesystem paths, repository URLs, worker socket paths, bundle paths, credential values, and raw provider details",
		"Phase 20 verification is fake-only.",
		"fake cached hosts",
		"fake leases",
		"fake clocks",
		"fake runtime drivers",
		"temporary `HAL_CONFIG_HOME`",
		"no live worker or sandbox daemon",
		"go test -timeout=120s ./internal/sandboxtarget -run 'TestScheduler|TestSandboxtarget|TestSchedulerProductionImportsStayCommandAgnosticAndOffline|TestSchedulerImportBoundaryRejectsWorkerProviderAndNetworkCoupling'",
		"go test -timeout=120s ./cmd -run 'Test(Run|Auto|Factory)SandboxLegacyDefaultResolutionDoesNotUseSchedulerOrLeaseMetadata|Test(Run|Auto|Factory)SandboxDefaultTargetResolutionStaysCachedAndFakeOnly'",
		"go test -timeout=120s ./cmd -run 'Test(Run|Auto|Factory)SandboxExplicitSchedulerAcquiresLeaseAndPersists|Test(Run|Auto|Factory)SandboxSchedulerFailure|TestFactorySandboxSchedulerFailureRecordsFailureBeforeRuntimeConstruction'",
		"go test -timeout=120s ./cmd -run 'TestScheduledSandboxCommandsReleaseAcquiredLeaseExactlyOnce|TestScheduledSandboxCommandCancellationReleasesLease|TestSandboxCommandDefaultLeaseListerExpiresStaleLeases|TestSandboxScheduler'",
		"go test -timeout=120s ./cmd -run 'TestPhase20LeaseAwareSchedulerDocumentationCoversVerificationAndScope'",
		"make docs-check",
		"git diff --check",
		"go test -timeout=300s ./...",
		"go vet ./...",
		"make build",
		"make lint",
		"Run `make docs-cli` before `make docs-check` when command metadata, examples, or generated CLI surfaces change.",
		"Phase 20 verification explicitly excludes scheduler daemon behavior, live refresh, Podman or Docker workflows, cloud provider dependencies, microVM execution, network proxy enforcement, firewall enforcement, and secret broker support.",
		"Do not start a scheduler daemon, run `hal sandboxd`, refresh live worker capabilities, bind real worker sockets, contact remote worker hosts, run Podman or Docker workflows",
		"No scheduler daemon, no live refresh, no Podman/Docker/cloud dependency, no microVM, no network proxy, and no secret broker are required for this phase.",
		"`internal/sandboxtarget` must remain command-agnostic.",
		"Scheduler production code must not import Cobra, `cmd`, factory, engine, loop, PRD, compound, concrete runtime adapters, worker clients, provider packages, or network-only dependencies.",
		"Default `hal run --sandbox`, `hal auto --sandbox`, and `hal factory run --sandbox` without explicit host/runtime flags must remain on the legacy resolver path.",
		"Explicit scheduler rejections happen before provider construction, worker client construction, runtime driver construction, target ready hooks, or persisted target metadata.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 20 lease-aware scheduler documentation missing %q", want)
		}
	}
}

func readSandboxSchedulerPhase20Doc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}
