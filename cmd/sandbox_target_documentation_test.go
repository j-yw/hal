package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase17TargetSelectionDocumentationCoversVerificationAndScope(t *testing.T) {
	doc := readSandboxTargetDoc(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase17-target-selection-verification.md"))
	normalizedDoc := strings.Join(strings.Fields(doc), " ")
	required := []string{
		"Phase 17 covers cached target-selection and scheduling foundations",
		"`hal run --sandbox`, `hal auto --sandbox`, and `hal factory run --sandbox`",
		"cached metadata decision layer",
		"validates explicit sandbox, host, runtime, and isolation intent",
		"Phase 17 verification is fake-only.",
		"fake cached state",
		"fake default target resolvers",
		"fake runtime drivers",
		"temporary `HAL_CONFIG_HOME`",
		"deterministic clocks",
		"go test -timeout=120s ./internal/sandboxtarget",
		"go test -timeout=120s ./cmd -run 'TestSandboxTargetSelectionFlagHelpStaysConservative|TestSandboxRuntimeInspectionDoesNotBleedIntoExecutionCommands'",
		"go test -timeout=120s ./cmd -run 'TestRunSandboxDefaultTargetResolutionStaysCachedAndFakeOnly|TestAutoSandboxDefaultTargetResolutionStaysCachedAndFakeOnly|TestFactorySandboxDefaultTargetResolutionStaysCachedAndFakeOnly'",
		"go test -timeout=120s ./cmd -run 'TestRunWithWriterRejectsSandboxTargetFlagsWithoutSandbox|TestRunSandboxResolveTargetRejectsExplicitRuntimeBeforeDefaultFallback|TestRunSandboxResolveTargetUsesSelectedRuntimeMetadata|TestRunAutoWithDirRejectsSandboxTargetFlagsWithoutSandbox|TestAutoSandboxResolveTargetRejectsExplicitRuntimeBeforeDefaultFallback|TestFactoryRunRequestFromCommandRejectsTargetSelectionFlagsWithoutSandbox|TestResolveFactorySandboxTargetRejectsExplicitRuntimeBeforeDefaultFallback'",
		"go test -timeout=120s ./cmd -run 'TestSandboxRuntimeCompatRejectsUnsupportedSelectedRuntimeDrivers|TestSandboxRuntimeCompatDefaultsToSSHMachineUnlessRootlessExplicit|TestSandboxRuntimeCompatWorkerHostMetadataDoesNotSelectRuntime'",
		"go test -timeout=120s ./cmd -run 'TestPhase17TargetSelectionDocumentationCoversVerificationAndScope'",
		"make docs-check",
		"git diff --check",
		"go test -timeout=300s ./...",
		"go vet ./...",
		"make build",
		"make lint",
		"Run `make docs-cli` before `make docs-check` when command metadata, examples, or generated CLI surfaces change.",
		"Phase 17 verification explicitly excludes Docker, Podman, KVM, cloud resources, worker-backed execution, microVM execution, real network tests, and live runtime refresh.",
		"Do not run real worker daemons, bind real worker sockets, contact remote worker hosts, run Podman or Docker workflows, pull images, access KVM or other virtualization devices, access cloud APIs, open network connections",
		"execute worker-backed runtime drivers",
		"execute microVM runtimes",
		"Live runtime refresh is out of scope for Phase 17.",
		"durable cached metadata supplied through fakeable selector and command-layer dependencies",
		"not from worker clients, runtime drivers, cloud providers, Docker, Podman, KVM, or network APIs",
		"target flags being rejected outside sandbox mode",
		"constrained target resolution not falling back to default SSH-machine execution",
		"Unsupported explicit runtime drivers such as `microvm` or worker-only driver strings",
		"reject them at runtime driver resolution instead of silently downgrading to SSH-machine execution",
		"Missing runtime metadata remains the legacy SSH-machine compatibility path.",
		"Target-selection flags are sandbox-only intent.",
		"`hal run`, `hal auto`, and `hal factory run` must reject `--sandbox-host` and `--sandbox-runtime` unless `--sandbox` is also set",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 17 target-selection documentation missing %q", want)
		}
	}
}

func readSandboxTargetDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}
