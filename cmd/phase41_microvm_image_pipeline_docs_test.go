package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPhase41MicroVMImagePipelineVerificationDocs(t *testing.T) {
	doc := readPhase41MicroVMImagePipelineDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 41 establishes backend-neutral, deterministic Firecracker microVM launch asset contracts and local digest-lock resolution while preserving explicit sandboxd Firecracker compatibility.",
		"`internal/sandboxruntime/microvm/assets` owns the immutable launch descriptor contracts.",
		"`internal/sandboxruntime/microvm/assets/localresolver` owns explicit local file verification and SHA-256 digest locking.",
		"`internal/sandboxruntime/microvm.Config` can carry an optional `launchDescriptor` while preserving legacy path-only fields.",
		"`internal/sandboxruntime/microvm/firecracker` consumes descriptor kernel, rootfs, and optional initrd paths during rendering when a descriptor is present.",
		"`hal sandboxd --driver microvm` keeps the existing `--firecracker-executable`, `--firecracker-kernel`, `--firecracker-rootfs`, `--firecracker-initrd`, `--firecracker-jailer`, and `--firecracker-state-dir` flags.",
		"The command layer collects structured values only; the local resolver owns path validation, read-only file inspection, digesting, and descriptor construction before live driver construction.",
		"Default command, factory, scheduler, worker, and rootless Podman paths do not resolve launch assets, construct Firecracker launch descriptors, or start Firecracker implicitly.",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/assets ./internal/sandboxruntime/microvm/assets/localresolver",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase4[1].*MicroVM|Phase4[1].*Firecracker|Sandboxd.*MicroVM|MicroVM'",
		"go test -count=1 -timeout=420s ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`golangci-lint run ./...` only when `golangci-lint` is installed.",
		"If it is unavailable, report lint unavailable instead of reporting lint as passed.",
		"Phase 41 does not implement sandbox templates or kits, image building, kernel/rootfs provisioning, network proxy enforcement, credential proxy delivery, default Firecracker runtime selection, worker protocol changes, factory record persistence, Firecracker SDK integration, or a production live image pipeline.",
		"Future phases are responsible for templates and kits, image packaging, network proxy integration, credential proxy delivery, worker and scheduler registration policy, production image lifecycle management, and live E2E coverage.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 41 microVM image pipeline verification documentation missing %q", want)
		}
	}

	phase41AssertVerificationCommands(t, doc)
	phase41AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase41AssertDocumentedFocusedCommandsExecutable(t, doc)

	unsupportedClaims := []string{
		"sandbox templates are implemented",
		"sandbox kits are implemented",
		"image building is implemented",
		"kernel provisioning is implemented",
		"rootfs provisioning is implemented",
		"network proxy enforcement is implemented",
		"credential proxy delivery is implemented",
		"default Firecracker runtime selection is implemented",
		"worker protocol changes are implemented",
		"factory record persistence is implemented",
		"Firecracker SDK integration is implemented",
		"production live image pipeline is implemented",
		"default commands start Firecracker",
		"default sandboxd starts Firecracker",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 41 microVM image pipeline documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase41MicroVMImagePipelineFakeSafeVerification(t *testing.T) {
	doc := readPhase41MicroVMImagePipelineDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Default Phase 41 verification is fake-safe and does not require KVM, a Firecracker binary, root privileges, live network sockets, Firecracker SDKs, cloud credentials, Docker, Podman, worker daemons, provider/runtime integration, host-specific kernel or rootfs images beyond temporary test files, a live guest, a guest agent, vsock, SSH, or a running `hal sandboxd`.",
		"Default Phase 41 tests use pure descriptor DTOs, temporary local files, deterministic SHA-256 digest assertions, injected fake command dependencies, parsed imports, AST source guards, JSON redaction assertions, and temporary state directories only.",
		"Default Phase 41 verification must not use integration build tags, the `firecracker_live` build tag, require live environment variables, start a real Firecracker process, access KVM, require root, bind network sockets, start worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs, invoke Firecracker SDKs, or depend on live providers or runtime adapters.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 41 microVM image pipeline fake-safe documentation missing %q", want)
		}
	}

	commands := phase41DefaultFocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 41 verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase36ForbiddenDefaultFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 41 default focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase41AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase41AssertFocusedTestFilesAvoidLiveDependencies(t)
}

func TestPhase41MicroVMImagePipelineOptionalLivePostureDocs(t *testing.T) {
	doc := readPhase41MicroVMImagePipelineDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 41 does not add a required live-test gate.",
		"Optional live Firecracker checks remain behind existing live-specific test posture such as the `firecracker_live` build tag and operator-provided Firecracker prerequisites.",
		"Optional live checks may verify that the descriptor-rendered kernel, rootfs, and initrd paths still reach the explicit Firecracker live driver, but they are not part of default Phase 41 verification.",
		"Live checks must not weaken the default fake-safe gate or make KVM, root, a Firecracker binary, or host images required for normal CI.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 41 optional live-test posture documentation missing %q", want)
		}
	}

	for _, command := range phase41DefaultFocusedGoTestCommands(doc) {
		if strings.Contains(command, "firecracker_live") {
			t.Fatalf("phase 41 default focused command %q must not use optional firecracker_live coverage", command)
		}
	}
}

func readPhase41MicroVMImagePipelineDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase41-microvm-image-pipeline-verification.md"))
	if err != nil {
		t.Fatalf("ReadFile(phase 41 microVM image pipeline verification doc) error: %v", err)
	}
	return string(data)
}

func phase41DefaultFocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		if strings.Contains(command, "firecracker_live") {
			continue
		}
		if strings.Contains(command, "./...") {
			continue
		}
		commands = append(commands, command)
	}
	return commands
}

func phase41AssertVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/assets ./internal/sandboxruntime/microvm/assets/localresolver",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=180s ./cmd -run 'Phase4[1].*MicroVM|Phase4[1].*Firecracker|Sandboxd.*MicroVM|MicroVM'",
		"go test -count=1 -timeout=420s ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 41 microVM image pipeline verification documentation missing command line %q", want)
		}
	}
}

func phase41AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase41DefaultFocusedGoTestCommands(doc)
	for _, req := range phase41RequiredFocusedTests() {
		command := phase34FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 41 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase34TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 41 verification test %s", phase34FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase41RequiredFocusedTests() []phase34FocusedTest {
	return []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm/assets", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "contracts_test.go"), testName: "TestLaunchAssetContractFieldsAndJSONNames"},
		{pkg: "./internal/sandboxruntime/microvm/assets", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "contracts_test.go"), testName: "TestLaunchDescriptorJSONShapeIncludesSafeMetadata"},
		{pkg: "./internal/sandboxruntime/microvm/assets", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "validation_test.go"), testName: "TestValidateLaunchDescriptorRejectsUnsafeIDsAndLabels"},
		{pkg: "./internal/sandboxruntime/microvm/assets", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "validation_test.go"), testName: "TestValidateLaunchDescriptorRejectsMalformedDigestLocks"},
		{pkg: "./internal/sandboxruntime/microvm/assets", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "import_boundary_test.go"), testName: "TestLaunchAssetProductionImportsStayDataOnly"},
		{pkg: "./internal/sandboxruntime/microvm/assets", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "import_boundary_test.go"), testName: "TestLaunchAssetProductionSourceOmitsRuntimeSideEffects"},
		{pkg: "./internal/sandboxruntime/microvm/assets/localresolver", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver", "resolver_test.go"), testName: "TestResolveLocalAssetsComputesStableSHA256DigestLocks"},
		{pkg: "./internal/sandboxruntime/microvm/assets/localresolver", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver", "resolver_test.go"), testName: "TestResolveLocalAssetsPublicErrorsDoNotLeakRejectedInput"},
		{pkg: "./internal/sandboxruntime/microvm/assets/localresolver", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver", "import_boundary_test.go"), testName: "TestLocalResolverProductionImportsStayInResolverBoundary"},
		{pkg: "./internal/sandboxruntime/microvm/assets/localresolver", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver", "import_boundary_test.go"), testName: "TestLocalResolverProductionSourceOmitsRuntimeSideEffects"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "contracts_test.go"), testName: "TestConfigContractFieldsAndJSONNames"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "config_validation_test.go"), testName: "TestValidateConfigAcceptsLaunchDescriptorWithoutLegacyImagePaths"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "config_validation_test.go"), testName: "TestValidateConfigLaunchDescriptorErrorsAreSanitized"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "launch_descriptor_rendering_test.go"), testName: "TestBackendConfigFromMicroVMConfigUsesLaunchDescriptorAssetPaths"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "launch_descriptor_rendering_test.go"), testName: "TestDescriptorBackedOperationMetadataExposesOnlySafeAssetMetadata"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "launch_descriptor_rendering_test.go"), testName: "TestDescriptorValidationErrorsAreSanitizedBeforeLiveBootRender"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdCommandResolvesExplicitFirecrackerLaunchAssetsBeforeDriverConstruction"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdCommandRejectsUnavailableLaunchAssetBeforeMicroVMDriverConstruction"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdMicroVMValidationDoesNotRunForRootlessPodmanOnly"},
		{pkg: "./cmd", file: "phase41_microvm_image_pipeline_guard_test.go", testName: "TestPhase41MicroVMAssetContractsAndResolverStayIsolatedFromRuntimeBoundaries"},
		{pkg: "./cmd", file: "phase41_microvm_image_pipeline_guard_test.go", testName: "TestPhase41DefaultHalPathsDoNotResolveAssetsOrLaunchFirecrackerImplicitly"},
		{pkg: "./cmd", file: "phase41_microvm_image_pipeline_guard_test.go", testName: "TestPhase41SandboxdFirecrackerAssetResolverStaysExplicitAndPreDriver"},
		{pkg: "./cmd", file: "phase41_microvm_image_pipeline_guard_test.go", testName: "TestPhase41MicroVMImagePipelinePublicErrorsStayRedactionSafe"},
		{pkg: "./cmd", file: "phase41_microvm_image_pipeline_docs_test.go", testName: "TestPhase41MicroVMImagePipelineVerificationDocs"},
		{pkg: "./cmd", file: "phase41_microvm_image_pipeline_docs_test.go", testName: "TestPhase41MicroVMImagePipelineFakeSafeVerification"},
		{pkg: "./cmd", file: "phase41_microvm_image_pipeline_docs_test.go", testName: "TestPhase41MicroVMImagePipelineOptionalLivePostureDocs"},
	}
}

func phase41AssertDocumentedFocusedCommandsExecutable(t *testing.T, doc string) {
	t.Helper()
	for _, command := range phase41DefaultFocusedGoTestCommands(doc) {
		fields := strings.Fields(command)
		if len(fields) < 3 || fields[0] != "go" || fields[1] != "test" {
			t.Fatalf("phase 41 focused verification command %q is not a go test command", command)
		}
		if selector, ok := phase34FocusedCommandRunSelector(t, command); ok {
			if _, err := regexp.Compile(selector); err != nil {
				t.Fatalf("phase 41 focused verification command %q has invalid -run selector %q: %v", command, selector, err)
			}
		}
		hasPackage := false
		for _, field := range fields[2:] {
			pkg := strings.Trim(field, "'\"")
			if !strings.HasPrefix(pkg, "./") || strings.Contains(pkg, "...") {
				continue
			}
			hasPackage = true
			dir := strings.TrimPrefix(pkg, "./")
			if _, err := os.Stat(filepath.Join("..", dir)); err != nil {
				t.Fatalf("phase 41 focused verification command %q references missing package %s: %v", command, pkg, err)
			}
		}
		if !hasPackage {
			t.Fatalf("phase 41 focused verification command %q does not reference an executable package", command)
		}
	}
}

func phase41AssertFocusedTestFilesAvoidLiveDependencies(t *testing.T) {
	t.Helper()
	seen := map[string]bool{}
	for _, req := range phase41RequiredFocusedTests() {
		if seen[req.file] {
			continue
		}
		seen[req.file] = true
		phase34AssertNoLiveIntegrationBuildTag(t, req.file)
		phase34AssertDefaultTestFileAvoidsLiveImports(t, req.file)
	}
}
