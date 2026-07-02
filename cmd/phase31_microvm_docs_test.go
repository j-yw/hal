package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestPhase31MicroVMRuntimeFoundationVerificationDocs(t *testing.T) {
	doc := readPhase31MicroVMDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 31 adds a concrete fakeable microVM sandbox runtime foundation.",
		"`internal/sandboxruntime/microvm`",
		"`Config` and `Options` describe kernel image, rootfs, optional initrd",
		"The default network mode is `no_live_networking`.",
		"Stable operation error codes cover unavailable capability, invalid config, backend not configured, target required, and target name required.",
		"`HostCapabilityDetector` is injectable and fakeable.",
		"macOS and other non-Linux hosts report unavailable without live KVM access.",
		"`microvm.Driver` satisfies `sandboxruntime.Driver`",
		"Lifecycle, exec, copy-in, and copy-out operations delegate through injected backend/controller boundaries.",
		"Explicit microVM runtime metadata resolves to the microVM driver and does not fall back to SSH-machine or rootless Podman behavior.",
		"Worker microVM metadata remains metadata-driven.",
		"Without an explicit injected worker runtime hook, worker-backed microVM selection reports an unsupported runtime classification instead of constructing a live worker client, starting a microVM, or falling back to a local driver.",
		"`hal sandboxd` rejects the microVM driver unless a microVM driver factory is injected.",
		"go test -timeout=120s ./internal/sandboxruntime/microvm",
		"go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*DefaultRuntimeDriverResolver|Test.*RuntimeResolver'",
		"go test -timeout=120s ./cmd -run 'TestSandboxRuntimeCompatDefaultsToSSHMachineUnlessExplicitRuntimeSelected'",
		"go test -timeout=120s ./internal/sandboxruntime ./internal/sandboxworker",
		"go test -timeout=120s ./internal/sandboxtarget -run 'TestSelectRequestedMicroVMRuntimeDoesNotUseWeakerRuntimeFallback'",
		"go test -timeout=120s ./cmd -run 'TestPhase31MicroVMRuntimeFoundation(VerificationDocs|FakeOnlyVerification)'",
		"microVM contracts, capability detection, validation, driver metadata, lifecycle delegation, resolver integration, worker metadata preservation, sandboxd registration boundaries, target-selection no-fallback behavior, import-boundary guards, default-test fake-only guards, and documentation guard coverage",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`make lint` is optional for Phase 31",
		"Default verification is fake-only and does not require KVM, Firecracker, Cloud Hypervisor, Docker, Podman, network sockets, root privileges, or cloud credentials.",
		"Default Phase 31 verification must not use integration build tags, require live environment variables, contact cloud APIs, start providers, start Docker or Podman workflows, start Firecracker or Cloud Hypervisor, access live KVM, bind network sockets, start worker daemons, run `hal sandboxd`, require root, or create live microVM backends.",
		"No live Firecracker backend is included in Phase 31.",
		"No live Cloud Hypervisor backend is included in Phase 31.",
		"No KVM-backed microVM launch is included in Phase 31.",
		"No root-privileged runtime behavior is included in Phase 31.",
		"No live network sockets are included in Phase 31 default verification.",
		"No Docker or Podman dependency is introduced for the microVM foundation.",
		"No cloud provider SDK or cloud credential behavior is introduced.",
		"No worker protocol expansion is included for microVM execution.",
		"No default sandboxd live microVM registration is included.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 31 microVM verification documentation missing %q", want)
		}
	}

	phase31AssertBroadVerificationCommands(t, doc)
	phase31AssertFocusedVerificationCoversRequiredSelectors(t, doc)

	unsupportedClaims := []string{
		"live Firecracker backend is implemented",
		"live Cloud Hypervisor backend is implemented",
		"KVM-backed microVM launch is implemented",
		"root-privileged runtime behavior is implemented",
		"live network sockets are required",
		"Docker or Podman dependency is required",
		"cloud provider SDK behavior is implemented",
		"cloud credential behavior is implemented",
		"worker protocol expansion is implemented",
		"default sandboxd live microVM registration is implemented",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 31 microVM verification documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase31MicroVMRuntimeFoundationFakeOnlyVerification(t *testing.T) {
	doc := readPhase31MicroVMDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Default verification is fake-only and does not require KVM, Firecracker, Cloud Hypervisor, Docker, Podman, network sockets, root privileges, or cloud credentials.",
		"Phase 31 tests should use data contracts, JSON marshaling, reflection over struct tags, fake capability probes, fake backend/controller implementations, fake command dependencies, temporary stores, parsed imports, AST checks, explicit build-tag checks, and seeded unsafe strings.",
		"Default Phase 31 verification must not use integration build tags, require live environment variables, contact cloud APIs, start providers, start Docker or Podman workflows, start Firecracker or Cloud Hypervisor, access live KVM, bind network sockets, start worker daemons, run `hal sandboxd`, require root, or create live microVM backends.",
		"go test -timeout=120s ./cmd -run 'TestPhase31MicroVMRuntimeFoundation(VerificationDocs|FakeOnlyVerification)'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 31 microVM fake-only documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"requires KVM",
		"requires Firecracker",
		"requires Cloud Hypervisor",
		"requires Docker",
		"requires Podman",
		"requires network sockets",
		"requires root privileges",
		"requires cloud credentials",
		"requires integration build tags",
		"requires live environment variables",
		"KVM is required",
		"Firecracker is required",
		"Cloud Hypervisor is required",
		"Docker is required",
		"Podman is required",
		"network sockets are required",
		"root privileges are required",
		"cloud credentials are required",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 31 microVM fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase31FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 31 microVM verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase31ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 31 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase31AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase31AssertFocusedTestFilesAvoidLiveDependencies(t)
}

func readPhase31MicroVMDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase31-microvm-runtime-foundation-verification.md"))
	if err != nil {
		t.Fatalf("ReadFile(phase 31 microVM verification doc) error: %v", err)
	}
	return string(data)
}

func phase31FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase31AssertBroadVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase31DocumentedShellCommands(doc)
	required := []string{
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !commands[want] {
			t.Fatalf("phase 31 microVM verification documentation missing broad verification command line %q", want)
		}
	}
}

func phase31DocumentedShellCommands(doc string) map[string]bool {
	commands := make(map[string]bool)
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "go test "):
			commands[line] = true
		case strings.HasPrefix(line, "go vet "):
			commands[line] = true
		case strings.HasPrefix(line, "make "):
			commands[line] = true
		case strings.HasPrefix(line, "git diff "):
			commands[line] = true
		}
	}
	return commands
}

func phase31ForbiddenFocusedCommandRequirements() []string {
	return []string{
		"-tags=integration",
		"-tags=worker_integration",
		"-tags=podman_integration",
		"worker_integration",
		"podman_integration",
		"HAL_WORKER_INTEGRATION_",
		"HAL_PODMAN_" + "TEST_IMAGE",
		"DOCKER_HOST",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"docker ",
		"podman ",
		"firecracker ",
		"cloud-hypervisor ",
		"curl ",
		"hal sandboxd",
		"--live",
	}
}

func phase31AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase31FocusedGoTestCommands(doc)
	for _, req := range phase31RequiredFocusedTests() {
		command := phase31FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 31 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase31TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 31 verification test %s", phase31MicroVMDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase31RequiredFocusedTests() []phase31FocusedTest {
	return []phase31FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "contracts_test.go"), testName: "TestConfigContractFieldsAndJSONNames"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "contracts_test.go"), testName: "TestConfigJSONIncludesMicroVMRuntimeInputs"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "contracts_test.go"), testName: "TestDefaultConfigUsesNoLiveNetworking"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "contracts_test.go"), testName: "TestOperationErrorCodesAreStable"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "contracts_test.go"), testName: "TestOperationErrorStringAndJSONAreSanitized"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "capability_test.go"), testName: "TestDetectCapabilityReportsNonLinuxUnavailableWithoutKVMProbe"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "capability_test.go"), testName: "TestDetectCapabilityAllowsFakeKVMAvailableWithoutHostKVM"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "capability_test.go"), testName: "TestDetectCapabilityReportsMissingConfiguredHypervisorExecutableUnavailable"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "capability_test.go"), testName: "TestCapabilityErrorStringsAreSanitized"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "config_validation_test.go"), testName: "TestValidateConfigAcceptsMinimalNoLiveNetworking"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "config_validation_test.go"), testName: "TestValidateConfigDoesNotRequireLiveBackendState"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "config_validation_test.go"), testName: "TestValidateConfigRejectsMissingKernelAndRootfs"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "config_validation_test.go"), testName: "TestValidateConfigErrorStringsAreSanitized"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestDriverSatisfiesSandboxruntimeDriver"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestDriverMetadataIdentifiesMicroVMRuntimeBoundary"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestDefaultDriverConstructionIsUnavailableWithoutBackendPrerequisites"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestDriverLifecycleDelegatesThroughBackendControllerBoundary"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestDriverExecDelegatesThroughControllerAndStreamsOutput"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestDriverCopyDelegatesThroughControllerWithSanitizedPaths"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"), testName: "TestDriverRejectsUnavailableOperationsBeforeBackendCalls"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMProductionImportBoundaries"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMDefaultTestsStayFakeOnlyAndOffline"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMIntegrationTestPlaceholdersRequireExplicitBuildTags"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMUnavailableBehaviorIsAssertedWithFakeMacOSProbe"},
		{pkg: "./internal/sandboxruntime", file: filepath.Join("..", "internal", "sandboxruntime", "types_test.go"), testName: "TestRuntimeDriverIDConstants"},
		{pkg: "./internal/sandboxworker", file: filepath.Join("..", "internal", "sandboxworker", "types_test.go"), testName: "TestWorkerRuntimeDriverRejectsMicroVMIsolationClaim"},
		{pkg: "./internal/sandboxtarget", file: filepath.Join("..", "internal", "sandboxtarget", "select_test.go"), testName: "TestSelectRequestedMicroVMRuntimeDoesNotUseWeakerRuntimeFallback"},
		{pkg: "./cmd", file: "sandbox_runtime_compat_test.go", testName: "TestSandboxRuntimeCompatSelectsMicroVMAndDefersUnavailableToDriver"},
		{pkg: "./cmd", file: "sandbox_runtime_compat_test.go", testName: "TestSandboxRuntimeCompatDefaultsToSSHMachineUnlessExplicitRuntimeSelected"},
		{pkg: "./cmd", file: "sandbox_worker_runtime_test.go", testName: "TestSandboxWorkerRuntimeResolverUsesInjectedMicroVMWorkerFactory"},
		{pkg: "./cmd", file: "sandbox_worker_runtime_test.go", testName: "TestSandboxWorkerRuntimeResolverKeepsMicroVMMetadataUnsupportedWithoutHook"},
		{pkg: "./cmd", file: "sandbox_worker_routing_regression_test.go", testName: "TestWorkerMicroVMFactorySandboxDefaultResolverDoesNotFallbackToLocalDriver"},
		{pkg: "./cmd", file: "sandbox_worker_routing_regression_test.go", testName: "TestWorkerMicroVMFactorySandboxResolverUsesInjectedWorkerHook"},
		{pkg: "./cmd", file: "sandbox_command_target_regression_test.go", testName: "TestWorkerMicroVMRunSandboxJSONFailsWithRuntimeUnsupportedClassification"},
		{pkg: "./cmd", file: "sandbox_command_target_regression_test.go", testName: "TestWorkerMicroVMAutoSandboxJSONFailsWithRuntimeUnsupportedClassification"},
		{pkg: "./cmd", file: "sandbox_command_target_regression_test.go", testName: "TestWorkerMicroVMFactorySandboxJSONFailsWithRuntimeUnsupportedClassification"},
		{pkg: "./cmd", file: "sandbox_command_target_regression_test.go", testName: "TestWorkerMicroVMRuntimeResolverSelectsMicroVMAndDoesNotFallback"},
		{pkg: "./cmd", file: "sandbox_host_mapping_test.go", testName: "TestSandboxHostFromWorkerMetadataPreservesMicroVMRuntimeDriverID"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdCommandRejectsMicroVMDriverWithoutConfiguredFactory"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdCommandRegistersMicroVMOnlyWithInjectedFactory"},
		{pkg: "./cmd", file: "run_sandbox_test.go", testName: "TestRunSandboxDefaultRuntimeDriverResolverSelectsRootlessPodmanFromTargetMetadata"},
		{pkg: "./cmd", file: "auto_sandbox_test.go", testName: "TestAutoSandboxDefaultRuntimeDriverResolverSelectsRootlessPodmanFromTargetMetadata"},
		{pkg: "./cmd", file: "factory_sandbox_executor_test.go", testName: "TestFactorySandboxDefaultRuntimeDriverResolverSelectsRootlessPodmanFromTargetMetadata"},
		{pkg: "./cmd", file: "phase31_microvm_docs_test.go", testName: "TestPhase31MicroVMRuntimeFoundationVerificationDocs"},
		{pkg: "./cmd", file: "phase31_microvm_docs_test.go", testName: "TestPhase31MicroVMRuntimeFoundationFakeOnlyVerification"},
	}
}

type phase31FocusedTest struct {
	pkg      string
	file     string
	testName string
}

func phase31FocusedCommandCoveringTest(t *testing.T, commands []string, pkg, testName string) string {
	t.Helper()
	for _, command := range commands {
		if !phase31FocusedCommandTargetsPackage(command, pkg) {
			continue
		}
		selector, ok := phase31FocusedCommandRunSelector(t, command)
		if !ok {
			return command
		}
		compiled, err := regexp.Compile(selector)
		if err != nil {
			t.Fatalf("phase 31 focused command %q has invalid -run selector %q: %v", command, selector, err)
		}
		if compiled.MatchString(testName) {
			return command
		}
	}
	return ""
}

func phase31FocusedCommandTargetsPackage(command, pkg string) bool {
	for _, field := range strings.Fields(command) {
		if strings.Trim(field, "'\"") == pkg {
			return true
		}
	}
	return false
}

func phase31FocusedCommandRunSelector(t *testing.T, command string) (string, bool) {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == "-run" {
			if i+1 >= len(fields) {
				t.Fatalf("phase 31 focused command %q has -run without selector", command)
			}
			return strings.Trim(fields[i+1], "'\""), true
		}
		if selector, ok := strings.CutPrefix(field, "-run="); ok {
			return strings.Trim(selector, "'\""), true
		}
	}
	return "", false
}

func phase31TestFileDefinesFunction(t *testing.T, path, testName string) bool {
	t.Helper()
	file := phase31ParseGoFile(t, path, parser.ParseComments)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == testName {
			return true
		}
	}
	return false
}

func phase31AssertFocusedTestFilesAvoidLiveDependencies(t *testing.T) {
	t.Helper()
	for _, file := range phase31FakeOnlyGuardedTestFiles() {
		phase31AssertNoLiveIntegrationBuildTag(t, file)
		phase31AssertDefaultTestFileAvoidsLiveImports(t, file)
	}
}

func phase31FakeOnlyGuardedTestFiles() []string {
	return []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "contracts_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "capability_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "config_validation_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "driver_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "types_test.go"),
		filepath.Join("..", "internal", "sandboxworker", "types_test.go"),
		"phase31_microvm_docs_test.go",
	}
}

func phase31AssertNoLiveIntegrationBuildTag(t *testing.T, path string) {
	t.Helper()
	file := phase31ParseGoFile(t, path, parser.ParseComments)
	for _, group := range file.Comments {
		if group.End() > file.Package {
			continue
		}
		for _, comment := range group.List {
			text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
			text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
			text = strings.TrimSpace(strings.TrimSuffix(text, "*/"))
			if strings.HasPrefix(text, "go:build") {
				for _, tag := range []string{"integration", "worker_integration", "podman_integration", "microvm_integration", "kvm_integration"} {
					if strings.Contains(text, tag) {
						t.Fatalf("%s uses integration build tag %q; Phase 31 focused tests must stay fake-only by default", phase31MicroVMDisplayPath(t, path), tag)
					}
				}
			}
		}
	}
}

func phase31AssertDefaultTestFileAvoidsLiveImports(t *testing.T, path string) {
	t.Helper()
	file := phase31ParseGoFile(t, path, parser.ImportsOnly)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
		}
		if forbidden := phase31ForbiddenDefaultTestImport(importPath); forbidden != "" {
			t.Fatalf("%s imports %q; Phase 31 fake-only guard avoids %s", phase31MicroVMDisplayPath(t, path), importPath, forbidden)
		}
	}
}

func phase31ParseGoFile(t *testing.T, path string, mode parser.Mode) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, mode)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	return file
}

func phase31ForbiddenDefaultTestImport(importPath string) string {
	switch importPath {
	case "net", "net/http", "net/http/httputil", "net/rpc", "net/smtp":
		return "network sockets or live proxy servers"
	}
	for _, forbidden := range []struct {
		prefix string
		label  string
	}{
		{prefix: "github.com/docker/docker", label: "Docker clients"},
		{prefix: "github.com/containers/podman", label: "Podman clients"},
		{prefix: "github.com/containers/image", label: "container image clients"},
		{prefix: "github.com/containers/storage", label: "container storage clients"},
		{prefix: "github.com/firecracker-microvm", label: "Firecracker SDKs"},
		{prefix: "github.com/example/cloud-hypervisor", label: "Cloud Hypervisor SDKs"},
		{prefix: "libvirt.org/go/libvirt", label: "KVM or microVM integrations"},
		{prefix: "github.com/digitalocean/godo", label: "cloud SDKs"},
		{prefix: "github.com/aws/aws-sdk-go", label: "cloud SDKs"},
		{prefix: "github.com/aws/aws-sdk-go-v2", label: "cloud SDKs"},
		{prefix: "github.com/Azure/azure-sdk-for-go", label: "cloud SDKs"},
		{prefix: "github.com/hetznercloud/hcloud-go", label: "cloud SDKs"},
		{prefix: "cloud.google.com/go", label: "cloud SDKs"},
		{prefix: "google.golang.org/api", label: "cloud SDKs"},
		{prefix: "google.golang.org/grpc", label: "network clients"},
	} {
		if strings.HasPrefix(importPath, forbidden.prefix) {
			return forbidden.label
		}
	}
	return ""
}

func phase31MicroVMDisplayPath(t *testing.T, path string) string {
	t.Helper()
	if !strings.HasPrefix(filepath.ToSlash(path), "../") {
		return filepath.ToSlash(filepath.Join("cmd", path))
	}
	rel, err := filepath.Rel(filepath.Join(".."), path)
	if err != nil {
		t.Fatalf("Rel(%s, %s) error: %v", filepath.Join(".."), path, err)
	}
	return filepath.ToSlash(rel)
}
