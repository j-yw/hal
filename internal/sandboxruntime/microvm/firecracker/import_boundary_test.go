package firecracker

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const firecrackerPackagePath = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"

var forbiddenFirecrackerProductionImports = []firecrackerForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: firecrackerModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory record package", match: firecrackerModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "PRD package", match: firecrackerModuleImportMatcher("github.com/jywlabs/hal/internal/prd")},
	{name: "command-specific compound package", match: firecrackerModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "command-specific loop package", match: firecrackerModuleImportMatcher("github.com/jywlabs/hal/internal/loop")},
	{
		name: "Docker or Podman package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/docker/docker") ||
				strings.HasPrefix(importPath, "github.com/containers/podman") ||
				strings.HasPrefix(importPath, "github.com/containers/image") ||
				strings.HasPrefix(importPath, "github.com/containers/storage") ||
				strings.HasPrefix(importPath, "github.com/containers/buildah")
		},
	},
	{
		name: "cloud SDK package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/digitalocean/godo") ||
				strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go") ||
				strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go-v2") ||
				strings.HasPrefix(importPath, "github.com/Azure/azure-sdk-for-go") ||
				strings.HasPrefix(importPath, "github.com/hetznercloud/hcloud-go") ||
				strings.HasPrefix(importPath, "github.com/linode/linodego") ||
				strings.HasPrefix(importPath, "github.com/vultr/govultr") ||
				strings.HasPrefix(importPath, "cloud.google.com/go") ||
				strings.HasPrefix(importPath, "google.golang.org/api")
		},
	},
	{
		name: "Firecracker SDK package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/firecracker-microvm")
		},
	},
	{
		name: "KVM access package",
		match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return importPath == "syscall" ||
				strings.HasPrefix(importPath, "golang.org/x/sys") ||
				strings.Contains(lower, "/kvm") ||
				strings.Contains(lower, "kvm")
		},
	},
	{
		name: "network listener package",
		match: func(importPath string) bool {
			switch importPath {
			case "net", "net/http", "net/http/httputil", "net/rpc":
				return true
			default:
				return strings.HasPrefix(importPath, "net/http/") ||
					strings.HasPrefix(importPath, "google.golang.org/grpc")
			}
		},
	},
	{
		name: "process-starting package",
		match: func(importPath string) bool {
			return importPath == "os/exec" ||
				strings.HasPrefix(importPath, "github.com/creack/pty")
		},
	},
}

func TestFirecrackerPackageDeclaresExpectedFoundationExports(t *testing.T) {
	paths := firecrackerProductionBoundaryFiles(t)
	allowedExportedNames := map[string]bool{
		"Backend":                               true,
		"BackendConfig":                         true,
		"BackendConfigFromMicroVMConfig":        true,
		"BackendID":                             true,
		"BackendOptions":                        true,
		"BootAcceptanceRequest":                 true,
		"BootAcceptanceResult":                  true,
		"BootAcceptanceWaiter":                  true,
		"BootSourcePayload":                     true,
		"DefaultConfigPath":                     true,
		"ConfigOperation":                       true,
		"DeleteOperationPlan":                   true,
		"DefaultAPISocketPath":                  true,
		"DefaultLogPath":                        true,
		"DefaultMetricsPath":                    true,
		"DefaultRuntimeID":                      true,
		"DefaultStateDir":                       true,
		"GuestWorkDirMetadata":                  true,
		"InspectOperationPlan":                  true,
		"LiveProcessManager":                    true,
		"LiveProcessRequest":                    true,
		"MachineConfigPayload":                  true,
		"NewBackend":                            true,
		"OperationAction":                       true,
		"OperationActionDelete":                 true,
		"OperationActionInspect":                true,
		"OperationActionStart":                  true,
		"OperationActionStop":                   true,
		"OperationArgumentSummary":              true,
		"OperationEnvironmentMetadata":          true,
		"OperationPathReference":                true,
		"OperationPathRole":                     true,
		"OperationPathRoleAPISocket":            true,
		"OperationPathRoleConfig":               true,
		"OperationPathRoleExecutable":           true,
		"OperationPathRoleLog":                  true,
		"OperationPathRoleMetrics":              true,
		"OperationPathRoleStateDir":             true,
		"OperationPayloadReference":             true,
		"OperationPayloadRole":                  true,
		"OperationPayloadRoleBootSource":        true,
		"OperationPayloadRoleMachineConfig":     true,
		"OperationPayloadRoleRootDrive":         true,
		"OperationPlanSummary":                  true,
		"OperationPlanningOperation":            true,
		"PathPlan":                              true,
		"PathPlanRequest":                       true,
		"PathPlanningOperation":                 true,
		"PayloadRenderingOperation":             true,
		"PlanPaths":                             true,
		"PrepareStartCommand":                   true,
		"ProcessAdapter":                        true,
		"ProcessBoundaryOperation":              true,
		"ProcessCommandDescriptor":              true,
		"ProcessCommandDescriptorFromStartPlan": true,
		"ProcessHandleMetadata":                 true,
		"ProcessLaunchAdapter":                  true,
		"ProcessLaunchMetadata":                 true,
		"ProcessLaunchState":                    true,
		"ProcessLaunchStateAccepted":            true,
		"ProcessLaunchStateAttempted":           true,
		"ProcessLaunchStateBoundaryAvailable":   true,
		"ProcessRunnerStartRequest":             true,
		"ProcessStartCommandRequest":            true,
		"ProcessStartRequest":                   true,
		"ProcessStarter":                        true,
		"RenderBootSourcePayload":               true,
		"RenderDeleteOperationPlan":             true,
		"RenderInspectOperationPlan":            true,
		"RenderMachineConfigPayload":            true,
		"RenderRootDrivePayload":                true,
		"RenderStartOperationPlan":              true,
		"RenderStopOperationPlan":               true,
		"RootDrivePayload":                      true,
		"SanitizeProcessLaunchMetadata":         true,
		"StartProcess":                          true,
		"StartOperationPlan":                    true,
		"StopOperationPlan":                     true,
		"NewProcessLaunchMetadata":              true,
	}
	seenExportedNames := map[string]bool{}

	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if file.Name.Name != "firecracker" {
			t.Fatalf("%s package name = %q, want firecracker", path, file.Name.Name)
		}
		for _, decl := range file.Decls {
			switch typed := decl.(type) {
			case *ast.FuncDecl:
				if typed.Recv == nil && ast.IsExported(typed.Name.Name) {
					seenExportedNames[typed.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if ast.IsExported(spec.Name.Name) {
							seenExportedNames[spec.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if ast.IsExported(name.Name) {
								seenExportedNames[name.Name] = true
							}
						}
					}
				}
			}
		}
	}

	for name := range seenExportedNames {
		if !allowedExportedNames[name] {
			t.Fatalf("unexpected exported Firecracker namespace %q; Firecracker package exports must stay limited to foundation contracts and Phase 33 launch metadata labels", name)
		}
	}
	for name := range allowedExportedNames {
		if !seenExportedNames[name] {
			t.Fatalf("missing exported Firecracker namespace %q", name)
		}
	}
}

func TestFirecrackerPackageCommentDocumentsFutureBoundary(t *testing.T) {
	paths := firecrackerProductionBoundaryFiles(t)
	fset := token.NewFileSet()
	var docs []string
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if file.Doc != nil {
			docs = append(docs, file.Doc.Text())
		}
	}
	text := strings.Join(docs, "\n")
	for _, want := range []string{
		"Package firecracker",
		"config mapping",
		"payload rendering",
		"command planning",
		"backend behavior",
		"backend-neutral microvm code",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Firecracker package comments missing %q in %q", want, text)
		}
	}
}

func TestFirecrackerProductionImportBoundaries(t *testing.T) {
	paths := firecrackerProductionBoundaryFiles(t)
	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := firecrackerProductionImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestFirecrackerForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra", want: "Cobra package"},
		{name: "cmd package", importPath: "github.com/jywlabs/hal/cmd", want: "cmd package"},
		{name: "factory records", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory record package"},
		{name: "PRD logic", importPath: "github.com/jywlabs/hal/internal/prd", want: "PRD package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "Docker or Podman package"},
		{name: "Podman", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman package"},
		{name: "AWS SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "cloud SDK package"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "Firecracker SDK package"},
		{name: "KVM access", importPath: "golang.org/x/sys/unix", want: "KVM access package"},
		{name: "network listener", importPath: "net", want: "network listener package"},
		{name: "HTTP listener", importPath: "net/http", want: "network listener package"},
		{name: "process starting", importPath: "os/exec", want: "process-starting package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := firecrackerProductionImportBoundaryMessage("doc.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func TestFirecrackerProductionSourceOmitsLiveBackendOperations(t *testing.T) {
	paths := firecrackerProductionBoundaryFiles(t)
	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if message := firecrackerProductionCallBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		if strings.Contains(string(source), "/dev/kvm") {
			t.Fatalf("%s references /dev/kvm; KVM access belongs behind a later explicit Firecracker adapter boundary", path)
		}
	}
}

func TestPhase34FirecrackerProductionLiveBootDoesNotCallOSExecDirectly(t *testing.T) {
	paths := firecrackerProductionBoundaryFiles(t)
	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s imports) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if importPath == "os/exec" {
				t.Fatalf("%s imports os/exec; live Firecracker boot must cross the injected ProcessRunnerStartRequest boundary", path)
			}
		}

		file, err = parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if message := firecrackerFirstForbiddenCall(file, func(selector string) string {
			switch selector {
			case "exec.Command", "exec.CommandContext":
				return "direct os/exec process launch"
			default:
				return ""
			}
		}, func(selector, reason string) string {
			return fmt.Sprintf("%s calls %s (%s); live Firecracker boot must use an injected ProcessStarter or ProcessAdapter", path, selector, reason)
		}); message != "" {
			t.Fatal(message)
		}
	}
}

func TestFirecrackerProductionSourceDoesNotIntroduceDockerOrPodmanGuestEngine(t *testing.T) {
	for _, path := range firecrackerProductionBoundaryFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		lower := strings.ToLower(string(source))
		for _, marker := range []string{
			"docker",
			"podman",
			"buildah",
			"containers/",
			"container image",
			"oci image",
			"dockerfile",
			"docker.sock",
			"host docker socket",
		} {
			if strings.Contains(lower, marker) {
				t.Fatalf("%s contains %q; Phase 32 Firecracker backend foundation must not introduce a Docker or Podman guest engine", path, marker)
			}
		}
	}
}

func TestFirecrackerDefaultTestsUseFakeProcessBoundaryOnly(t *testing.T) {
	paths := firecrackerDefaultTestBoundaryFiles(t)
	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := firecrackerDefaultTestImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestFirecrackerDefaultTestSourceOmitsLiveProcessAndKVMAccess(t *testing.T) {
	paths := firecrackerDefaultTestBoundaryFiles(t)
	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if message := firecrackerDefaultTestCallBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
	}
}

func TestFirecrackerDefaultTestBoundaryGuardsCoverLiveOperations(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "process start",
			source: `package firecracker; import "os/exec"; func TestLive(t *testing.T) { _ = exec.Command("firecracker") }`,
			want:   "process launch",
		},
		{
			name:   "API socket listener",
			source: `package firecracker; import "net"; func TestLive(t *testing.T) { _, _ = net.Listen("tcp", "127.0.0.1:0") }`,
			want:   "network socket",
		},
		{
			name:   "KVM open",
			source: `package firecracker; import "os"; func TestLive(t *testing.T) { _, _ = os.Open("/dev/kvm") }`,
			want:   "live KVM or root-only path",
		},
		{
			name:   "root path stat",
			source: `package firecracker; import "os"; func TestLive(t *testing.T) { _, _ = os.Stat("/root/private") }`,
			want:   "live KVM or root-only path",
		},
		{
			name:   "root requirement",
			source: `package firecracker; import "os"; func TestLive(t *testing.T) { _ = os.Geteuid() }`,
			want:   "root privilege check",
		},
		{
			name:   "Firecracker SDK",
			source: `package firecracker; func TestLive(t *testing.T) { _, _ = firecracker.NewMachine(ctx, cfg) }`,
			want:   "Firecracker SDK",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", tt.source, 0)
			if err != nil {
				t.Fatalf("ParseFile fixture error: %v", err)
			}
			message := firecrackerDefaultTestCallBoundaryMessage(tt.name+".go", file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want %q", message, tt.want)
			}
		})
	}

	for _, tt := range []struct {
		importPath string
		want       string
	}{
		{importPath: "os/exec", want: "process-starting package"},
		{importPath: "net", want: "network listener package"},
		{importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "Firecracker SDK package"},
		{importPath: "golang.org/x/sys/unix", want: "KVM access package"},
	} {
		message := firecrackerDefaultTestImportBoundaryMessage("fixture_test.go", tt.importPath)
		if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
			t.Fatalf("default test import boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
		}
	}
}

func TestFirecrackerDefaultTestBoundaryExcludesOptInLiveTests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "firecracker_live_integration_test.go")
	if err := os.WriteFile(path, []byte("//go:build firecracker_live\n\npackage firecracker\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error: %v", path, err)
	}
	if firecrackerDefaultTestFile(t, path) {
		t.Fatalf("%s matched default Firecracker test boundaries; firecracker_live tests must stay opt-in", path)
	}
}

func TestPhase33FirecrackerLiveProcessCodeStaysInExplicitAdapterBoundary(t *testing.T) {
	allowedFiles := map[string]bool{
		"backend.go":         true,
		"process.go":         true,
		"process_adapter.go": true,
	}
	for _, path := range firecrackerProductionBoundaryFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		if allowedFiles[path] {
			continue
		}
		for _, marker := range []string{
			"ProcessLaunchAdapter",
			"ProcessStarter",
			"ProcessRunnerStartRequest",
			"ProcessStartRequest",
			"StartProcess(",
			"LiveStart",
		} {
			if strings.Contains(string(source), marker) {
				t.Fatalf("%s contains %q; Phase 33 live-start process code must stay in the explicit Firecracker process adapter/backend boundary", path, marker)
			}
		}
	}
}

func TestPhase33ExplicitLiveAdapterTestsUseInjectedFakesByDefault(t *testing.T) {
	for _, tt := range []struct {
		fileName   string
		testName   string
		fakeMarker string
	}{
		{
			fileName:   "backend_test.go",
			testName:   "TestBackendLiveStartOptionCallsInjectedAdapterAfterPlanRendered",
			fakeMarker: "fakeProcessAdapter",
		},
		{
			fileName:   "backend_test.go",
			testName:   "TestBackendLiveStartReturnsSanitizedRunnerFailure",
			fakeMarker: "fakeProcessStarter",
		},
		{
			fileName:   "process_adapter_test.go",
			testName:   "TestProcessLaunchAdapterStartProcessBuildsRunnerRequestAndUsesContext",
			fakeMarker: "fakeProcessStarter",
		},
		{
			fileName:   "process_test.go",
			testName:   "TestStartProcessCallsOnlyInjectedProcessAdapter",
			fakeMarker: "fakeProcessAdapter",
		},
	} {
		t.Run(tt.testName, func(t *testing.T) {
			body := firecrackerTestFunctionSource(t, tt.fileName, tt.testName)
			if !strings.Contains(body, tt.fakeMarker) {
				t.Fatalf("%s in %s does not use injected fake marker %q", tt.testName, tt.fileName, tt.fakeMarker)
			}
		})
	}

	for _, path := range []string{
		"backend_test.go",
		"process_adapter_test.go",
		"process_test.go",
	} {
		file := firecrackerParseTestFile(t, path, parser.ImportsOnly)
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := firecrackerDefaultTestImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}

		file = firecrackerParseTestFile(t, path, 0)
		if message := firecrackerDefaultTestCallBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
	}
}

func firecrackerProductionBoundaryFiles(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob(*.go) error: %v", err)
	}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		out = append(out, path)
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("no Firecracker production files matched import-boundary guard")
	}
	return out
}

func firecrackerDefaultTestBoundaryFiles(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("Glob(*_test.go) error: %v", err)
	}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if !firecrackerDefaultTestFile(t, path) {
			continue
		}
		out = append(out, path)
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("no Firecracker default test files matched process-boundary guard")
	}
	return out
}

func firecrackerDefaultTestFile(t *testing.T, path string) bool {
	t.Helper()

	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	for _, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "//go:build") || strings.HasPrefix(trimmed, "// +build") {
			if strings.Contains(trimmed, "integration") || strings.Contains(trimmed, "firecracker_live") {
				return false
			}
			continue
		}
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		break
	}
	return true
}

func firecrackerProductionImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := firecrackerForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", firecrackerPackagePath, fileName, forbidden.name, importPath)
	}
	if firecrackerAllowedProductionImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unapproved dependency %q; Firecracker backend code may only depend on standard library and approved microVM contracts until an explicit adapter boundary is added", firecrackerPackagePath, fileName, importPath)
}

func firecrackerDefaultTestImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := firecrackerForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s default test file %s imports forbidden %s %q; default Firecracker tests must use fake process adapters only", firecrackerPackagePath, fileName, forbidden.name, importPath)
	}
	return ""
}

func firecrackerForbiddenImportFor(importPath string) *firecrackerForbiddenImport {
	for i := range forbiddenFirecrackerProductionImports {
		if forbiddenFirecrackerProductionImports[i].match(importPath) {
			return &forbiddenFirecrackerProductionImports[i]
		}
	}
	return nil
}

func firecrackerAllowedProductionImport(importPath string) bool {
	return firecrackerIsStandardLibraryImport(importPath) ||
		importPath == "github.com/jywlabs/hal/internal/sandbox" ||
		importPath == "github.com/jywlabs/hal/internal/sandboxruntime" ||
		importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm"
}

func firecrackerIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func firecrackerModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

func firecrackerProductionCallBoundaryMessage(fileName string, file *ast.File) string {
	return firecrackerFirstForbiddenCall(file, func(selector string) string {
		switch selector {
		case "exec.Command", "exec.CommandContext":
			return "process launch"
		case "net.Listen", "net.ListenPacket", "net.Dial", "net.DialTimeout":
			return "network socket"
		case "http.Get", "http.Head", "http.Post", "http.PostForm", "http.ListenAndServe", "http.ListenAndServeTLS":
			return "HTTP client or server"
		case "grpc.Dial", "grpc.DialContext", "grpc.NewClient":
			return "gRPC client"
		case "firecracker.NewMachine":
			return "Firecracker SDK"
		default:
			return ""
		}
	}, func(selector, reason string) string {
		return fmt.Sprintf("%s calls %s (%s); live Firecracker behavior belongs behind a later explicit adapter boundary", fileName, selector, reason)
	})
}

func firecrackerDefaultTestCallBoundaryMessage(fileName string, file *ast.File) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if reason := firecrackerDefaultTestForbiddenCallReason(call); reason != "" {
			selector := firecrackerCallSelectorName(call.Fun)
			message = fmt.Sprintf("%s calls %s (%s); default Firecracker tests must stay fake-only", fileName, selector, reason)
			return false
		}
		return true
	})
	return message
}

func firecrackerDefaultTestForbiddenCallReason(call *ast.CallExpr) string {
	switch firecrackerCallSelectorName(call.Fun) {
	case "exec.Command", "exec.CommandContext":
		return "process launch"
	case "net.Listen", "net.ListenPacket", "net.Dial", "net.DialTimeout":
		return "network socket"
	case "http.Get", "http.Head", "http.Post", "http.PostForm", "http.ListenAndServe", "http.ListenAndServeTLS":
		return "HTTP client or server"
	case "grpc.Dial", "grpc.DialContext", "grpc.NewClient":
		return "gRPC client"
	case "firecracker.NewMachine":
		return "Firecracker SDK"
	case "os.Geteuid":
		return "root privilege check"
	case "os.Open", "os.OpenFile", "os.Stat":
		if firecrackerCallHasRootOnlyPathArg(call) {
			return "live KVM or root-only path"
		}
	}
	return ""
}

func firecrackerTestFunctionSource(t *testing.T, path, testName string) string {
	t.Helper()

	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, 0)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != testName {
			continue
		}
		start := fset.Position(fn.Pos()).Offset
		end := fset.Position(fn.End()).Offset
		if start < 0 || end > len(source) || start >= end {
			t.Fatalf("invalid source span for %s in %s: start=%d end=%d len=%d", testName, path, start, end, len(source))
		}
		return string(source[start:end])
	}
	t.Fatalf("%s does not define required Phase 33 live adapter test %s", path, testName)
	return ""
}

func firecrackerParseTestFile(t *testing.T, path string, mode parser.Mode) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, mode)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	return file
}

func firecrackerCallHasRootOnlyPathArg(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			continue
		}
		if firecrackerRootOnlyPathLiteral(value) {
			return true
		}
	}
	return false
}

func firecrackerRootOnlyPathLiteral(value string) bool {
	return value == "/dev/kvm" ||
		strings.HasPrefix(value, "/dev/kvm/") ||
		value == "/root" ||
		strings.HasPrefix(value, "/root/")
}

func firecrackerFirstForbiddenCall(file *ast.File, classify func(string) string, format func(string, string) string) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := firecrackerCallSelectorName(call.Fun)
		if selector == "" {
			return true
		}
		if reason := classify(selector); reason != "" {
			message = format(selector, reason)
			return false
		}
		return true
	})
	return message
}

func firecrackerCallSelectorName(expr ast.Expr) string {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	receiver := firecrackerExprName(selector.X)
	if receiver == "" {
		return selector.Sel.Name
	}
	return receiver + "." + selector.Sel.Name
}

func firecrackerExprName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		parent := firecrackerExprName(typed.X)
		if parent == "" {
			return typed.Sel.Name
		}
		return parent + "." + typed.Sel.Name
	default:
		return ""
	}
}

type firecrackerForbiddenImport struct {
	name  string
	match func(string) bool
}
