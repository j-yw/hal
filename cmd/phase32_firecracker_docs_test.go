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

func TestPhase32FirecrackerBackendFoundationVerificationDocs(t *testing.T) {
	doc := readPhase32FirecrackerDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 32 adds a fake-only Firecracker backend foundation for the existing microVM runtime.",
		"`internal/sandboxruntime/microvm/firecracker`",
		"The Firecracker package maps `microvm.Config` into backend-specific config, plans deterministic target paths, renders Firecracker machine, boot source, and root drive payloads, and builds sanitized start, stop, inspect, and delete operation plans.",
		"The process adapter boundary prepares descriptors through injected fakes by default; default verification does not start a Firecracker process.",
		"`microvm.Driver` can use an injected Firecracker backend, but default production microVM construction remains backend-neutral and unavailable until an explicit backend factory is supplied.",
		"Command defaults remain explicit-only: run, auto, factory, scheduler, and sandboxd defaults do not import, construct, register, or launch Firecracker.",
		"go test -timeout=120s ./internal/sandboxruntime/microvm",
		"go test -timeout=120s ./internal/sandboxruntime/microvm/firecracker",
		"go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase32'",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`make lint` should run only when `golangci-lint` is installed.",
		"Default Phase 32 verification is fake-only and does not require KVM, a Firecracker binary, root privileges, live network sockets, Firecracker SDKs, cloud credentials, Docker, Podman, worker daemons, or provider/runtime integration.",
		"Default Phase 32 tests must use pure contracts, deterministic path and payload rendering, injected fake process adapters, fake command dependencies, parsed imports, AST source guards, JSON redaction assertions, and temporary stores only.",
		"No live Firecracker VM launch is included in Phase 32.",
		"No Firecracker SDK integration is included in Phase 32.",
		"No KVM access, root requirement, jailer execution, or privileged host setup is included in Phase 32.",
		"No live API socket listener, guest networking, vsock transport, guest agent, exec transport, copy transport, or SSH access is included in Phase 32.",
		"No default command, scheduler, factory, or sandboxd path imports, constructs, registers, or launches Firecracker.",
		"No Docker, Podman, cloud provider, worker daemon, or provider/runtime integration dependency is introduced by Phase 32 verification.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 32 Firecracker verification documentation missing %q", want)
		}
	}

	phase32AssertBroadVerificationCommands(t, doc)
	phase32AssertFocusedVerificationCoversRequiredSelectors(t, doc)

	unsupportedClaims := []string{
		"live Firecracker VM launch is implemented",
		"Firecracker SDK integration is implemented",
		"KVM access is implemented",
		"root requirement is implemented",
		"jailer execution is implemented",
		"live API socket listener is implemented",
		"guest networking is implemented",
		"vsock transport is implemented",
		"guest agent is implemented",
		"exec transport is implemented",
		"copy transport is implemented",
		"default commands construct Firecracker",
		"default sandboxd registers Firecracker",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 32 Firecracker verification documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase32FirecrackerBackendFoundationFakeOnlyVerification(t *testing.T) {
	doc := readPhase32FirecrackerDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Default Phase 32 verification is fake-only and does not require KVM, a Firecracker binary, root privileges, live network sockets, Firecracker SDKs, cloud credentials, Docker, Podman, worker daemons, or provider/runtime integration.",
		"Default Phase 32 tests must use pure contracts, deterministic path and payload rendering, injected fake process adapters, fake command dependencies, parsed imports, AST source guards, JSON redaction assertions, and temporary stores only.",
		"Default Phase 32 verification must not use integration build tags, require live environment variables, start Firecracker, access KVM, require root, bind network sockets, start worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs, invoke Firecracker SDKs, or depend on live providers or runtime adapters.",
		"go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase32'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 32 Firecracker fake-only documentation missing %q", want)
		}
	}

	forbiddenClaims := []string{
		"requires KVM",
		"requires a Firecracker binary",
		"requires root privileges",
		"requires live network sockets",
		"requires Firecracker SDKs",
		"requires cloud credentials",
		"requires Docker",
		"requires Podman",
		"requires worker daemons",
		"requires provider/runtime integration",
		"KVM is required",
		"Firecracker binary is required",
		"root privileges are required",
		"live network sockets are required",
		"Firecracker SDKs are required",
		"cloud credentials are required",
		"Docker is required",
		"Podman is required",
	}
	for _, claim := range forbiddenClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 32 Firecracker fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase32FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 32 Firecracker verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase32ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 32 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase32AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase32AssertFocusedTestFilesAvoidLiveDependencies(t)
}

func readPhase32FirecrackerDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase32-firecracker-backend-foundation-verification.md"))
	if err != nil {
		t.Fatalf("ReadFile(phase 32 Firecracker verification doc) error: %v", err)
	}
	return string(data)
}

func phase32FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase32AssertBroadVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase32DocumentedShellCommands(doc)
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
			t.Fatalf("phase 32 Firecracker verification documentation missing broad verification command line %q", want)
		}
	}
}

func phase32DocumentedShellCommands(doc string) map[string]bool {
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

func phase32ForbiddenFocusedCommandRequirements() []string {
	return []string{
		"-tags=integration",
		"-tags=worker_integration",
		"-tags=podman_integration",
		"-tags=microvm_integration",
		"-tags=kvm_integration",
		"worker_integration",
		"podman_integration",
		"microvm_integration",
		"kvm_integration",
		"HAL_FIRECRACKER",
		"HAL_PODMAN_" + "TEST_IMAGE",
		"HAL_WORKER_INTEGRATION_",
		"DOCKER_HOST",
		"HCLOUD_TOKEN",
		"DIGITALOCEAN_ACCESS_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"docker ",
		"podman ",
		"firecracker ",
		"cloud-hypervisor ",
		"/dev/kvm",
		"curl ",
		"hal sandboxd",
		"--live",
	}
}

func phase32AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase32FocusedGoTestCommands(doc)
	for _, req := range phase32RequiredFocusedTests() {
		command := phase32FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 32 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase32TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 32 verification test %s", phase32FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase32RequiredFocusedTests() []phase32FocusedTest {
	return []phase32FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMProductionImportBoundaries"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMForbiddenImportListCoversRequiredBoundaries"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMProductionSourceOmitsLiveBackendOperations"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"), testName: "TestFirecrackerPackageDeclaresExpectedFoundationExports"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"), testName: "TestFirecrackerProductionImportBoundaries"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"), testName: "TestFirecrackerProductionSourceOmitsLiveBackendOperations"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"), testName: "TestFirecrackerDefaultTestsUseFakeProcessBoundaryOnly"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "config_test.go"), testName: "TestBackendConfigFromMicroVMConfigMapsRequiredFields"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "paths_test.go"), testName: "TestPlanPathsReturnsDeterministicTargetPaths"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "payloads_test.go"), testName: "TestRenderMachineConfigPayloadReturnsExactJSON"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "plans_test.go"), testName: "TestRenderStartOperationPlanConstructsDeterministicProcessDescriptor"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "process_test.go"), testName: "TestPrepareStartCommandUsesInjectedProcessAdapterOnly"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"), testName: "TestBackendCreateReturnsDeterministicTargetMetadata"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"), testName: "TestBackendStartReturnsSanitizedOperationPlanWithoutStartingProcess"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"), testName: "TestBackendStopInspectDeleteBuildSanitizedLifecyclePlans"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"), testName: "TestBackendUnsupportedExecAndCopyOperationsReturnSanitizedErrors"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"), testName: "TestMicroVMDriverCreateCanUseInjectedFirecrackerBackend"},
		{pkg: "./cmd", file: "sandbox_runtime_compat_test.go", testName: "TestProductionRuntimeResolverMicroVMFactoryDoesNotConfigureFirecrackerBackend"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdDefaultsDoNotRegisterMicroVMFactory"},
		{pkg: "./cmd", file: "phase32_default_regression_test.go", testName: "TestPhase32DefaultRuntimeResolversDoNotConstructMicroVMWithoutExplicitRuntime"},
		{pkg: "./cmd", file: "phase32_default_regression_test.go", testName: "TestPhase32CommandDefaultsDoNotImportOrConstructFirecracker"},
		{pkg: "./cmd", file: "phase32_default_regression_test.go", testName: "TestPhase32DefaultTargetResolutionIgnoresMicroVMCapableCachedHosts"},
		{pkg: "./cmd", file: "phase32_default_regression_test.go", testName: "TestPhase32CommandDefaultRegressionTestsStayFakeOnly"},
		{pkg: "./cmd", file: "phase32_firecracker_docs_test.go", testName: "TestPhase32FirecrackerBackendFoundationVerificationDocs"},
		{pkg: "./cmd", file: "phase32_firecracker_docs_test.go", testName: "TestPhase32FirecrackerBackendFoundationFakeOnlyVerification"},
	}
}

type phase32FocusedTest struct {
	pkg      string
	file     string
	testName string
}

func phase32FocusedCommandCoveringTest(t *testing.T, commands []string, pkg, testName string) string {
	t.Helper()
	for _, command := range commands {
		if !phase32FocusedCommandTargetsPackage(command, pkg) {
			continue
		}
		selector, ok := phase32FocusedCommandRunSelector(t, command)
		if !ok {
			return command
		}
		compiled, err := regexp.Compile(selector)
		if err != nil {
			t.Fatalf("phase 32 focused command %q has invalid -run selector %q: %v", command, selector, err)
		}
		if compiled.MatchString(testName) {
			return command
		}
	}
	return ""
}

func phase32FocusedCommandTargetsPackage(command, pkg string) bool {
	for _, field := range strings.Fields(command) {
		if strings.Trim(field, "'\"") == pkg {
			return true
		}
	}
	return false
}

func phase32FocusedCommandRunSelector(t *testing.T, command string) (string, bool) {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == "-run" {
			if i+1 >= len(fields) {
				t.Fatalf("phase 32 focused command %q has -run without selector", command)
			}
			return strings.Trim(fields[i+1], "'\""), true
		}
		if selector, ok := strings.CutPrefix(field, "-run="); ok {
			return strings.Trim(selector, "'\""), true
		}
	}
	return "", false
}

func phase32TestFileDefinesFunction(t *testing.T, path, testName string) bool {
	t.Helper()
	file := phase32ParseGoFile(t, path, parser.ParseComments)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == testName {
			return true
		}
	}
	return false
}

func phase32AssertFocusedTestFilesAvoidLiveDependencies(t *testing.T) {
	t.Helper()
	for _, file := range phase32FakeOnlyGuardedTestFiles() {
		phase32AssertNoLiveIntegrationBuildTag(t, file)
		phase32AssertDefaultTestFileAvoidsLiveImports(t, file)
	}
}

func phase32FakeOnlyGuardedTestFiles() []string {
	return []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "config_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "paths_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "payloads_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "plans_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "process_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"),
		"phase32_default_regression_test.go",
		"phase32_firecracker_docs_test.go",
		"sandbox_runtime_compat_test.go",
		"sandboxd_test.go",
	}
}

func phase32AssertNoLiveIntegrationBuildTag(t *testing.T, path string) {
	t.Helper()
	file := phase32ParseGoFile(t, path, parser.ParseComments)
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
						t.Fatalf("%s uses integration build tag %q; Phase 32 focused tests must stay fake-only by default", phase32FirecrackerDisplayPath(t, path), tag)
					}
				}
			}
		}
	}
}

func phase32AssertDefaultTestFileAvoidsLiveImports(t *testing.T, path string) {
	t.Helper()
	file := phase32ParseGoFile(t, path, parser.ImportsOnly)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
		}
		if forbidden := phase32ForbiddenDefaultTestImport(importPath); forbidden != "" {
			t.Fatalf("%s imports %q; Phase 32 fake-only guard avoids %s", phase32FirecrackerDisplayPath(t, path), importPath, forbidden)
		}
	}
}

func phase32ParseGoFile(t *testing.T, path string, mode parser.Mode) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, mode)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	return file
}

func phase32ForbiddenDefaultTestImport(importPath string) string {
	switch importPath {
	case "net", "net/http", "net/http/httputil", "net/rpc", "net/smtp":
		return "network sockets or live proxy servers"
	case "os/exec":
		return "process launch"
	case "syscall":
		return "host privilege or KVM access"
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
		{prefix: "libvirt.org/go/libvirt", label: "KVM or microVM integrations"},
		{prefix: "golang.org/x/sys", label: "host privilege or KVM access"},
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

func phase32FirecrackerDisplayPath(t *testing.T, path string) string {
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
