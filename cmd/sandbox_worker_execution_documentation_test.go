package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase18WorkerBackedExecutionDocumentationCoversVerificationAndScope(t *testing.T) {
	doc := readSandboxWorkerExecutionDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase18-worker-backed-execution-routing-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 18 covers explicit worker-backed sandbox execution routing",
		"`hal run --sandbox --sandbox-host <worker-id> --sandbox-runtime rootless_podman`",
		"`hal auto --sandbox --sandbox-host <worker-id> --sandbox-runtime rootless_podman`",
		"`hal factory run --sandbox --sandbox-host <worker-id> --sandbox-runtime rootless_podman`",
		"cmd/sandbox_worker_runtime.go",
		"sandboxWorkerRuntimeDriverFromTarget",
		"Unconstrained `hal run --sandbox`, `hal auto --sandbox`, and `hal factory run --sandbox` must preserve legacy SSH-machine-compatible resolution",
		"internal/sandbox.WorkerRoutingMetadata",
		"sandboxexecution.Manifest",
		"factory.SandboxMetadata",
		"Raw Unix socket paths, endpoint URLs, hostnames, credentials, URL query strings, host temp paths, remote temp paths, and local bundle paths must not be persisted",
		"go test -timeout=120s ./cmd -run 'TestSandboxWorkerRuntimeResolver|TestWorkerRootless(Run|Auto|Factory)Sandbox(DefaultResolverBuildsClientDriver|UsesSharedWorkerRuntimeResolver)|TestWorkerExecutionRuntimeConstructionStaysCentralized'",
		"go test -timeout=120s ./cmd -run 'TestExistingSandboxExecutionDefaultResolversStayWorkerOptIn|Test(Run|Auto|Factory)SandboxDefaultTargetResolutionStaysCachedAndFakeOnly|TestSandboxRuntimeCompat'",
		"go test -timeout=120s ./cmd -run 'TestWorkerMicroVM|TestWorkerRootless.*Endpoint|TestWorkerClient.*Sanitized|TestSandboxWorkerRuntimeResolver.*(Rejects|Wraps|Sanitizes)'",
		"go test -timeout=120s ./cmd -run 'TestWorkerRootless(Run|Auto)SandboxStreamsOutputAndSummariesExcludePreparation|TestWorkerRootlessFactorySandboxStreamsOutputInOrder|TestWorkerRootless(Run|Auto)SandboxUsesRuntimeCopyForWorkspaceAndArtifacts|TestWorkerRootless(Run|Auto)Sandbox.*Recovery'",
		"go test -timeout=120s ./cmd ./internal/sandboxexec -run 'TestWorkerRootless(Run|Auto|Factory)SandboxUsesSharedWorkerRuntimeResolver|TestRunAttachesCompatibilitySecurityMetadataBeforeTargetReady|TestRunPreservesExistingSecurityMetadataWithoutEvaluationRequest'",
		"go test -timeout=120s ./internal/sandbox ./internal/sandboxexecution ./internal/factory ./cmd -run 'TestWorkerRoutingMetadataJSONTags|TestManifestJSONFieldsAndSandboxMetadataTypes|TestSandboxMetadata(LoadsLegacyJSON|OptionalMetadataOmittedWhenNil|RuntimeV2SummaryJSONShape)|TestFactoryStatusDocsIncludeSandboxMetadataJSONFields|TestRunSandboxListJSONPreservesV1ContractForRootlessPodmanRuntime'",
		"go test -timeout=120s ./internal/sandboxworker ./internal/sandboxruntime ./internal/sandboxexecution ./internal/sandboxexec ./internal/sandboxtarget -run 'Test.*Import|TestPackageImportBoundaries|TestSandboxexecDoesNotImportCommandOrProviderLayers|TestSandboxexecForbiddenImportListCoversRequiredBoundaries'",
		"go test -timeout=120s ./cmd -run 'TestPhase18WorkerBackedExecutionDocumentationCoversVerificationAndScope'",
		"git diff --check",
		"go test -timeout=300s ./...",
		"go vet ./...",
		"make build",
		"make lint",
		"fake selected targets",
		"fake worker clients",
		"fake runtime drivers",
		"git-bundle workspace materialization",
		"temporary `HAL_CONFIG_HOME`",
		"go test -timeout=120s -tags=worker_integration ./cmd -run TestWorkerIntegrationRootlessPodmanExecutionThroughSharedResolver -count=1 -v",
		"HAL_WORKER_INTEGRATION_ENDPOINT",
		"HAL_WORKER_INTEGRATION_HOST_NAME",
		"HAL_WORKER_INTEGRATION_RUNTIME_DRIVER=rootless_podman",
		"HAL_WORKER_INTEGRATION_IMAGE",
		"Phase 18 verification explicitly excludes real network execution, untagged Podman tests, microVM execution support, changes to default SSH-machine behavior",
		"Do not run real worker daemons, bind real worker sockets, contact remote worker hosts, run Podman or Docker workflows without the `worker_integration` tag",
		"Unsupported selected worker runtimes such as `microvm` must fail with a `runtime_unsupported` classification before provisioning, worker-client construction, or SSH-machine fallback.",
		"Preparation output belongs on setup writers; persisted stdout/stderr summaries should contain only remote command output from the existing `sandboxexec.EventCommandOutput` path.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 18 worker-backed execution documentation missing %q", want)
		}
	}
}

func readSandboxWorkerExecutionDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}
