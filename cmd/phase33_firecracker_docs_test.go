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

func TestPhase33FirecrackerProcessLaunchAdapterVerificationDocs(t *testing.T) {
	doc := readPhase33FirecrackerDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 33 implements an explicit opt-in Firecracker process launch adapter for the existing fake-only Firecracker backend foundation.",
		"`internal/sandboxruntime/microvm/firecracker`",
		"The adapter converts rendered start-operation descriptors into injected process-runner requests, passes cancellation through the provided context, omits host environment delivery, and stores only sanitized process handle metadata.",
		"The default Firecracker backend remains planning-only unless `BackendOptions.LiveStart` is set with an injected `ProcessAdapter` or `ProcessLaunchAdapter`.",
		"No default command, scheduler, factory, or sandboxd path launches Firecracker.",
		"go test -timeout=120s ./internal/sandboxruntime/microvm",
		"go test -timeout=120s ./internal/sandboxruntime/microvm/firecracker",
		"go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase33'",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -timeout=300s -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
		"`make lint` should run only when `golangci-lint` is installed.",
		"If `golangci-lint` is unavailable, report lint unavailable instead of reporting lint as passed.",
		"Phase 33 does not implement Firecracker SDK integration, API socket machine configuration calls, boot readiness checks, guest networking, guest agent or vsock transport, exec/copy support, Docker/Podman inside the guest, credential delivery, network proxy/firewall enforcement, jailer/root setup, cgroups, default registration, or default live E2E tests.",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 33 Firecracker verification documentation missing %q", want)
		}
	}

	phase33AssertBroadVerificationCommands(t, doc)
	phase33AssertFocusedVerificationCoversRequiredSelectors(t, doc)

	unsupportedClaims := []string{
		"Firecracker SDK integration is implemented",
		"API socket machine configuration calls are implemented",
		"boot readiness checks are implemented",
		"guest networking is implemented",
		"guest agent transport is implemented",
		"vsock transport is implemented",
		"exec/copy support is implemented",
		"Docker/Podman inside the guest is implemented",
		"credential delivery is implemented",
		"network proxy/firewall enforcement is implemented",
		"jailer/root setup is implemented",
		"cgroups are implemented",
		"default registration is implemented",
		"default live E2E tests are implemented",
		"default commands launch Firecracker",
		"default sandboxd launches Firecracker",
	}
	for _, claim := range unsupportedClaims {
		if strings.Contains(doc, claim) || strings.Contains(normalizedDoc, claim) {
			t.Fatalf("phase 33 Firecracker verification documentation makes unsupported implementation claim %q", claim)
		}
	}
}

func TestPhase33FirecrackerProcessLaunchAdapterFakeOnlyVerification(t *testing.T) {
	doc := readPhase33FirecrackerDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Default Phase 33 verification is fake-only and does not require KVM, a Firecracker binary, root privileges, live network sockets, Firecracker SDKs, cloud credentials, Docker, Podman, worker daemons, provider/runtime integration, or a live guest.",
		"Default Phase 33 tests must use pure contracts, deterministic plans, injected fake process adapters and starters, fake command dependencies, parsed imports, AST source guards, JSON redaction assertions, and temporary stores only.",
		"Default Phase 33 verification must not use integration build tags, require live environment variables, start Firecracker by default, access KVM, require root, bind network sockets, start worker daemons, run `hal sandboxd`, call Docker or Podman, contact cloud APIs, invoke Firecracker SDKs, or depend on live providers or runtime adapters.",
		"go test -timeout=120s ./cmd -run 'Test.*MicroVM|Test.*Firecracker|TestPhase33'",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 33 Firecracker fake-only documentation missing %q", want)
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
		"requires a live guest",
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
			t.Fatalf("phase 33 Firecracker fake-only documentation makes unsupported requirement claim %q", claim)
		}
	}

	commands := phase33FocusedGoTestCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 33 Firecracker verification documentation must list focused go test commands")
	}
	for _, command := range commands {
		for _, forbidden := range phase33ForbiddenFocusedCommandRequirements() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 33 focused verification command %q requires forbidden live dependency marker %q", command, forbidden)
			}
		}
	}

	phase33AssertFocusedVerificationCoversRequiredSelectors(t, doc)
	phase33AssertFocusedTestFilesAvoidLiveDependencies(t)
}

func readPhase33FirecrackerDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "design", "sandbox-runtime-v2-phase33-firecracker-process-launch-adapter-verification.md"))
	if err != nil {
		t.Fatalf("ReadFile(phase 33 Firecracker verification doc) error: %v", err)
	}
	return string(data)
}

func phase33FocusedGoTestCommands(doc string) []string {
	var commands []string
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "go test ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func phase33AssertBroadVerificationCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase33DocumentedShellCommands(doc)
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
			t.Fatalf("phase 33 Firecracker verification documentation missing broad verification command line %q", want)
		}
	}
}

func phase33DocumentedShellCommands(doc string) map[string]bool {
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

func phase33ForbiddenFocusedCommandRequirements() []string {
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

func phase33AssertFocusedVerificationCoversRequiredSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase33FocusedGoTestCommands(doc)
	for _, req := range phase33RequiredFocusedTests() {
		command := phase33FocusedCommandCoveringTest(t, commands, req.pkg, req.testName)
		if command == "" {
			t.Fatalf("phase 33 verification documentation missing focused go test command covering %s in %s", req.testName, req.pkg)
		}
		if !phase33TestFileDefinesFunction(t, req.file, req.testName) {
			t.Fatalf("%s does not define required Phase 33 verification test %s", phase33FirecrackerDisplayPath(t, req.file), req.testName)
		}
	}
}

func phase33RequiredFocusedTests() []phase33FocusedTest {
	return []phase33FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMProductionImportBoundaries"},
		{pkg: "./internal/sandboxruntime/microvm", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"), testName: "TestMicroVMProductionSourceOmitsLiveBackendOperations"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "metadata_test.go"), testName: "TestProcessLaunchMetadataDoesNotClaimGuestReadinessOrUnsupportedCapabilities"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "process_test.go"), testName: "TestStartProcessCallsOnlyInjectedProcessAdapter"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "process_adapter_test.go"), testName: "TestProcessLaunchAdapterStartProcessBuildsRunnerRequestAndUsesContext"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "process_adapter_test.go"), testName: "TestProcessLaunchAdapterStartProcessRejectsDescriptorEnvironmentBeforeStarter"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "process_adapter_test.go"), testName: "TestProcessLaunchAdapterStartProcessHonorsCanceledContextBeforeStarter"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "process_adapter_test.go"), testName: "TestProcessLaunchAdapterStartProcessSanitizesStarterHandleMetadata"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"), testName: "TestBackendInjectedAdapterWithoutLiveStartRemainsPlanningOnly"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"), testName: "TestBackendLiveStartOptionCallsInjectedAdapterAfterPlanRendered"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"), testName: "TestBackendLiveStartReturnsSanitizedRunnerFailure"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"), testName: "TestPhase33FirecrackerLiveProcessCodeStaysInExplicitAdapterBoundary"},
		{pkg: "./internal/sandboxruntime/microvm/firecracker", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"), testName: "TestPhase33ExplicitLiveAdapterTestsUseInjectedFakesByDefault"},
		{pkg: "./cmd", file: "phase33_firecracker_default_guard_test.go", testName: "TestPhase33DefaultHalPathsDoNotImportFirecrackerLiveAdapter"},
		{pkg: "./cmd", file: "phase33_firecracker_default_guard_test.go", testName: "TestPhase33DefaultHalPathsDoNotConstructOrLaunchFirecracker"},
		{pkg: "./cmd", file: "phase33_firecracker_default_guard_test.go", testName: "TestPhase33DefaultFirecrackerGuardCoversRequiredPaths"},
		{pkg: "./cmd", file: "phase33_firecracker_docs_test.go", testName: "TestPhase33FirecrackerProcessLaunchAdapterVerificationDocs"},
		{pkg: "./cmd", file: "phase33_firecracker_docs_test.go", testName: "TestPhase33FirecrackerProcessLaunchAdapterFakeOnlyVerification"},
	}
}

type phase33FocusedTest struct {
	pkg      string
	file     string
	testName string
}

func phase33FocusedCommandCoveringTest(t *testing.T, commands []string, pkg, testName string) string {
	t.Helper()
	for _, command := range commands {
		if !phase33FocusedCommandTargetsPackage(command, pkg) {
			continue
		}
		selector, ok := phase33FocusedCommandRunSelector(t, command)
		if !ok {
			return command
		}
		compiled, err := regexp.Compile(selector)
		if err != nil {
			t.Fatalf("phase 33 focused command %q has invalid -run selector %q: %v", command, selector, err)
		}
		if compiled.MatchString(testName) {
			return command
		}
	}
	return ""
}

func phase33FocusedCommandTargetsPackage(command, pkg string) bool {
	for _, field := range strings.Fields(command) {
		if strings.Trim(field, "'\"") == pkg {
			return true
		}
	}
	return false
}

func phase33FocusedCommandRunSelector(t *testing.T, command string) (string, bool) {
	t.Helper()
	fields := strings.Fields(command)
	for i, field := range fields {
		if field == "-run" {
			if i+1 >= len(fields) {
				t.Fatalf("phase 33 focused command %q has -run without selector", command)
			}
			return strings.Trim(fields[i+1], "'\""), true
		}
		if selector, ok := strings.CutPrefix(field, "-run="); ok {
			return strings.Trim(selector, "'\""), true
		}
	}
	return "", false
}

func phase33TestFileDefinesFunction(t *testing.T, path, testName string) bool {
	t.Helper()
	file := phase33ParseGoFile(t, path, parser.ParseComments)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == testName {
			return true
		}
	}
	return false
}

func phase33AssertFocusedTestFilesAvoidLiveDependencies(t *testing.T) {
	t.Helper()
	for _, file := range phase33FakeOnlyGuardedTestFiles() {
		phase33AssertNoLiveIntegrationBuildTag(t, file)
		phase33AssertDefaultTestFileAvoidsLiveImports(t, file)
	}
}

func phase33FakeOnlyGuardedTestFiles() []string {
	return []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "import_boundary_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "metadata_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "process_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "process_adapter_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "backend_test.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "import_boundary_test.go"),
		"phase33_firecracker_default_guard_test.go",
		"phase33_firecracker_docs_test.go",
		"sandbox_runtime_compat_test.go",
		"sandboxd_test.go",
	}
}

func phase33AssertNoLiveIntegrationBuildTag(t *testing.T, path string) {
	t.Helper()
	file := phase33ParseGoFile(t, path, parser.ParseComments)
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
						t.Fatalf("%s uses integration build tag %q; Phase 33 focused tests must stay fake-only by default", phase33FirecrackerDisplayPath(t, path), tag)
					}
				}
			}
		}
	}
}

func phase33AssertDefaultTestFileAvoidsLiveImports(t *testing.T, path string) {
	t.Helper()
	file := phase33ParseGoFile(t, path, parser.ImportsOnly)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
		}
		if forbidden := phase33ForbiddenDefaultTestImport(importPath); forbidden != "" {
			t.Fatalf("%s imports %q; Phase 33 fake-only guard avoids %s", phase33FirecrackerDisplayPath(t, path), importPath, forbidden)
		}
	}
}

func phase33ParseGoFile(t *testing.T, path string, mode parser.Mode) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, mode)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	return file
}

func phase33ForbiddenDefaultTestImport(importPath string) string {
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

func phase33FirecrackerDisplayPath(t *testing.T, path string) string {
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
