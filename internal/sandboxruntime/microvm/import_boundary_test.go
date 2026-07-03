package microvm

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

const microVMPackagePath = "github.com/jywlabs/hal/internal/sandboxruntime/microvm"
const microVMFirecrackerHostPackagePath = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"

var forbiddenMicroVMProductionImports = []microVMForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: microVMModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory orchestration package", match: microVMModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "worker server package", match: microVMModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "sandbox execution package", match: microVMModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "sandbox execution record package", match: microVMModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "sandbox target package", match: microVMModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxtarget")},
	{name: "sandbox workspace package", match: microVMModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworkspace")},
	{name: "concrete provider adapter package", match: microVMModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
	{name: "Firecracker host adapter package", match: microVMModuleImportMatcher(microVMFirecrackerHostPackagePath)},
	{
		name: "concrete sibling runtime adapter package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/") &&
				importPath != microVMPackagePath
		},
	},
	{
		name: "network socket or RPC package",
		match: func(importPath string) bool {
			switch importPath {
			case "net", "net/http", "net/http/httputil", "net/rpc", "net/smtp":
				return true
			default:
				return strings.HasPrefix(importPath, "net/http/") ||
					strings.HasPrefix(importPath, "google.golang.org/grpc")
			}
		},
	},
	{
		name: "host privilege package",
		match: func(importPath string) bool {
			return importPath == "os/user" ||
				importPath == "syscall" ||
				strings.HasPrefix(importPath, "golang.org/x/sys")
		},
	},
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
		name: "microVM backend SDK package",
		match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return strings.Contains(lower, "firecracker") ||
				strings.Contains(lower, "cloud-hypervisor") ||
				strings.Contains(lower, "cloudhypervisor") ||
				strings.Contains(lower, "libvirt") ||
				strings.Contains(lower, "qemu") ||
				strings.Contains(lower, "kvm")
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
}

func TestMicroVMProductionImportBoundaries(t *testing.T) {
	paths := microVMProductionBoundaryFiles(t)

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
			if message := microVMProductionImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestMicroVMImportBoundaryCoversProductionFiles(t *testing.T) {
	paths := microVMProductionBoundaryFiles(t)
	found := make(map[string]bool, len(paths))
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("import-boundary guard should scan production files only, got %s", path)
		}
		found[path] = true
	}
	for _, path := range []string{
		"backend.go",
		"capability.go",
		"config_validation.go",
		"contracts.go",
		"driver.go",
	} {
		if !found[path] {
			t.Fatalf("import-boundary guard files = %#v, want %s covered", paths, path)
		}
	}
}

func TestMicroVMForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra", want: "Cobra package"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd", want: "cmd package"},
		{name: "factory packages", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory orchestration package"},
		{name: "worker server packages", importPath: "github.com/jywlabs/hal/internal/sandboxworker", want: "worker server package"},
		{name: "worker server subpackages", importPath: "github.com/jywlabs/hal/internal/sandboxworker/server", want: "worker server package"},
		{name: "sandbox execution packages", importPath: "github.com/jywlabs/hal/internal/sandboxexec", want: "sandbox execution package"},
		{name: "sandbox execution record packages", importPath: "github.com/jywlabs/hal/internal/sandboxexecution", want: "sandbox execution record package"},
		{name: "sandbox target packages", importPath: "github.com/jywlabs/hal/internal/sandboxtarget", want: "sandbox target package"},
		{name: "sandbox workspace packages", importPath: "github.com/jywlabs/hal/internal/sandboxworkspace", want: "sandbox workspace package"},
		{name: "concrete provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/daytona", want: "concrete provider adapter package"},
		{name: "rootless Podman runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", want: "concrete sibling runtime adapter package"},
		{name: "SSH-machine runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine", want: "concrete sibling runtime adapter package"},
		{name: "Firecracker backend subpackage", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker", want: "concrete sibling runtime adapter package"},
		{name: "Firecracker host adapter package", importPath: microVMFirecrackerHostPackagePath, want: "Firecracker host adapter package"},
		{name: "standard network package", importPath: "net", want: "network socket or RPC package"},
		{name: "standard HTTP package", importPath: "net/http", want: "network socket or RPC package"},
		{name: "gRPC package", importPath: "google.golang.org/grpc", want: "network socket or RPC package"},
		{name: "host user package", importPath: "os/user", want: "host privilege package"},
		{name: "syscall package", importPath: "syscall", want: "host privilege package"},
		{name: "Docker client", importPath: "github.com/docker/docker/client", want: "Docker or Podman package"},
		{name: "Podman bindings", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman package"},
		{name: "containers image package", importPath: "github.com/containers/image/v5/copy", want: "Docker or Podman package"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "microVM backend SDK package"},
		{name: "Cloud Hypervisor SDK", importPath: "github.com/example/cloud-hypervisor/client", want: "microVM backend SDK package"},
		{name: "libvirt binding", importPath: "libvirt.org/go/libvirt", want: "microVM backend SDK package"},
		{name: "QEMU helper", importPath: "github.com/example/qemu-driver", want: "microVM backend SDK package"},
		{name: "KVM helper", importPath: "github.com/example/kvm-driver", want: "microVM backend SDK package"},
		{name: "DigitalOcean SDK", importPath: "github.com/digitalocean/godo", want: "cloud SDK package"},
		{name: "AWS SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "cloud SDK package"},
		{name: "Azure SDK", importPath: "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute", want: "cloud SDK package"},
		{name: "Google Cloud SDK", importPath: "cloud.google.com/go/compute/apiv1", want: "cloud SDK package"},
		{name: "Hetzner SDK", importPath: "github.com/hetznercloud/hcloud-go/hcloud", want: "cloud SDK package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := microVMProductionImportBoundaryMessage("driver.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func TestMicroVMImportBoundaryAllowsOnlyCurrentContracts(t *testing.T) {
	for _, importPath := range []string{
		"context",
		"errors",
		"fmt",
		"io",
		"io/fs",
		"os",
		"os/exec",
		"runtime",
		"strings",
		"github.com/jywlabs/hal/internal/sandbox",
		"github.com/jywlabs/hal/internal/sandboxruntime",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := microVMProductionImportBoundaryMessage("capability.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"github.com/jywlabs/hal/internal/template",
		"github.com/jywlabs/hal/internal/compound",
		"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := microVMProductionImportBoundaryMessage("driver.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func TestMicroVMImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := microVMProductionImportBoundaryMessage("driver.go", importPath)
	if !strings.Contains(message, microVMPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, microVMPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func TestMicroVMHostInspectionImportsStayBehindCapabilityProbe(t *testing.T) {
	paths := microVMProductionBoundaryFiles(t)
	fset := token.NewFileSet()
	hostInspectionImports := map[string]bool{
		"io/fs":   true,
		"os":      true,
		"os/exec": true,
		"runtime": true,
	}

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
			if hostInspectionImports[importPath] && path != "capability.go" {
				t.Fatalf("%s imports host-inspection dependency %q; direct host checks must stay behind CapabilityProbe in capability.go", path, importPath)
			}
		}
	}
}

func TestMicroVMProductionSourceOmitsLiveBackendOperations(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range microVMProductionBoundaryFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if message := microVMProductionCallBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
	}
}

func TestMicroVMProductionSourceDoesNotSelectFirecrackerHostByDefault(t *testing.T) {
	for _, path := range microVMProductionBoundaryFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		if message := microVMFirecrackerHostSourceBoundaryMessage(path, string(source)); message != "" {
			t.Fatal(message)
		}
	}
}

func TestMicroVMFirecrackerHostDefaultGuardRejectsSelectionFixtures(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{name: "package selection literal", source: `package microvm; const defaultBackend = "firecrackerhost"`, want: "Firecracker host adapter selection"},
		{name: "dash selection literal", source: `package microvm; const defaultBackend = "firecracker-host"`, want: "Firecracker host adapter selection"},
		{name: "underscore selection literal", source: `package microvm; const defaultBackend = "firecracker_host"`, want: "Firecracker host adapter selection"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := microVMFirecrackerHostSourceBoundaryMessage(tt.name+".go", tt.source)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want %q", message, tt.want)
			}
		})
	}
}

func TestMicroVMDefaultTestsStayFakeOnlyAndOffline(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range microVMTestFiles(t) {
		if microVMFileHasBuildTag(t, path) {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := microVMDefaultTestImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
		if message := microVMDefaultTestCallBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
	}
}

func TestMicroVMIntegrationTestPlaceholdersRequireExplicitBuildTags(t *testing.T) {
	for _, path := range microVMTestFiles(t) {
		name := strings.ToLower(filepath.Base(path))
		if !strings.Contains(name, "integration") &&
			!strings.Contains(name, "e2e") &&
			!strings.Contains(name, "live") {
			continue
		}
		if !microVMFileHasBuildTag(t, path) {
			t.Fatalf("%s looks like an optional live/integration test but has no explicit build tag", path)
		}
	}
}

func TestMicroVMUnavailableBehaviorIsAssertedWithFakeMacOSProbe(t *testing.T) {
	probe := &microVMBoundaryCapabilityProbe{goos: "darwin", goarch: "arm64"}
	report := HostCapabilityDetector{Probe: probe}.DetectMicroVMCapability(CapabilityDetectionRequest{})

	if report.Availability != CapabilityAvailabilityUnavailable {
		t.Fatalf("Availability = %q, want %q", report.Availability, CapabilityAvailabilityUnavailable)
	}
	if report.ReasonCode != CapabilityReasonUnsupportedOS {
		t.Fatalf("ReasonCode = %q, want %q", report.ReasonCode, CapabilityReasonUnsupportedOS)
	}
	if len(probe.statPaths) != 0 || len(probe.openPaths) != 0 || len(probe.lookPathNames) != 0 {
		t.Fatalf("fake macOS unavailable path touched live probes: stat=%v open=%v lookPath=%v", probe.statPaths, probe.openPaths, probe.lookPathNames)
	}
}

func microVMProductionBoundaryFiles(t *testing.T) []string {
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
		t.Fatal("no microVM production files matched import-boundary guard")
	}
	return out
}

func microVMTestFiles(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatalf("Glob(*_test.go) error: %v", err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("no microVM test files matched fake-only guard")
	}
	return paths
}

func microVMProductionImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := microVMForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", microVMPackagePath, fileName, forbidden.name, importPath)
	}
	if microVMAllowedProductionImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unapproved dependency %q; microVM foundation code may only depend on standard library plus root sandbox contracts", microVMPackagePath, fileName, importPath)
}

func microVMDefaultTestImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := microVMForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s default test file %s imports forbidden live dependency %s %q", microVMPackagePath, fileName, forbidden.name, importPath)
	}
	if microVMAllowedTestImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s default test file %s imports unapproved dependency %q; default microVM tests must stay fake-only and offline", microVMPackagePath, fileName, importPath)
}

func microVMForbiddenImportFor(importPath string) *microVMForbiddenImport {
	for i := range forbiddenMicroVMProductionImports {
		if forbiddenMicroVMProductionImports[i].match(importPath) {
			return &forbiddenMicroVMProductionImports[i]
		}
	}
	return nil
}

func microVMAllowedProductionImport(importPath string) bool {
	return microVMIsStandardLibraryImport(importPath) ||
		importPath == "github.com/jywlabs/hal/internal/sandbox" ||
		importPath == "github.com/jywlabs/hal/internal/sandboxruntime"
}

func microVMAllowedTestImport(importPath string) bool {
	return microVMAllowedProductionImport(importPath)
}

func microVMIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func microVMModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

func microVMProductionCallBoundaryMessage(fileName string, file *ast.File) string {
	return microVMFirstForbiddenCall(file, func(selector string) string {
		switch selector {
		case "exec.Command", "exec.CommandContext":
			return "process launch"
		case "net.Listen", "net.ListenPacket", "net.Dial", "net.DialTimeout":
			return "network socket"
		case "http.Get", "http.Head", "http.Post", "http.PostForm", "http.ListenAndServe", "http.ListenAndServeTLS":
			return "HTTP client or server"
		case "httptest.NewServer", "httptest.NewTLSServer":
			return "live test HTTP server"
		case "grpc.Dial", "grpc.DialContext", "grpc.NewClient":
			return "gRPC client"
		case "os.Geteuid", "os.Getuid", "user.Current":
			return "host privilege probe"
		default:
			return ""
		}
	}, func(selector, reason string) string {
		return fmt.Sprintf("%s calls %s (%s); live backend operations must stay behind future explicit integration boundaries", fileName, selector, reason)
	})
}

func microVMFirecrackerHostSourceBoundaryMessage(fileName, source string) string {
	lowerSource := strings.ToLower(source)
	for _, marker := range []string{"firecrackerhost", "firecracker-host", "firecracker_host"} {
		if strings.Contains(lowerSource, marker) {
			return fmt.Sprintf("%s contains Firecracker host adapter selection marker %q; default microVM construction must not select firecrackerhost without explicit live prerequisites", fileName, marker)
		}
	}
	return ""
}

func microVMDefaultTestCallBoundaryMessage(fileName string, file *ast.File) string {
	return microVMFirstForbiddenCall(file, func(selector string) string {
		switch selector {
		case "exec.Command", "exec.CommandContext", "exec.LookPath":
			return "process or executable dependency"
		case "net.Listen", "net.ListenPacket", "net.Dial", "net.DialTimeout":
			return "network socket"
		case "http.Get", "http.Head", "http.Post", "http.PostForm", "http.ListenAndServe", "http.ListenAndServeTLS":
			return "HTTP client or server"
		case "httptest.NewServer", "httptest.NewTLSServer":
			return "live test HTTP server"
		case "grpc.Dial", "grpc.DialContext", "grpc.NewClient":
			return "gRPC client"
		case "os.Getenv", "os.LookupEnv", "os.Environ", "os.Setenv", "os.Unsetenv":
			return "environment or credential dependency"
		case "os.Geteuid", "os.Getuid", "user.Current":
			return "root/user privilege dependency"
		case "os.Open", "os.OpenFile", "os.Stat", "os.Lstat", "os.Readlink":
			return "live host filesystem probe"
		default:
			if strings.HasPrefix(selector, "t.Skip") {
				return "skip-based host dependency"
			}
			return ""
		}
	}, func(selector, reason string) string {
		return fmt.Sprintf("%s calls %s (%s); default microVM tests must use fake probes and assert unavailable behavior without skips or live host requirements", fileName, selector, reason)
	})
}

func microVMFirstForbiddenCall(file *ast.File, classify func(string) string, format func(string, string) string) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := microVMCallSelectorName(call.Fun)
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

func microVMCallSelectorName(expr ast.Expr) string {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	receiver := microVMExprName(selector.X)
	if receiver == "" {
		return selector.Sel.Name
	}
	return receiver + "." + selector.Sel.Name
}

func microVMExprName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		parent := microVMExprName(typed.X)
		if parent == "" {
			return typed.Sel.Name
		}
		return parent + "." + typed.Sel.Name
	default:
		return ""
	}
}

func microVMFileHasBuildTag(t *testing.T, path string) bool {
	t.Helper()

	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	for _, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") {
			return false
		}
		if strings.HasPrefix(trimmed, "//go:build ") || strings.HasPrefix(trimmed, "// +build ") {
			return true
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		return false
	}
	return false
}

type microVMForbiddenImport struct {
	name  string
	match func(string) bool
}

type microVMBoundaryCapabilityProbe struct {
	goos   string
	goarch string

	statPaths     []string
	openPaths     []string
	lookPathNames []string
}

func (probe *microVMBoundaryCapabilityProbe) RuntimeOS() string {
	return probe.goos
}

func (probe *microVMBoundaryCapabilityProbe) RuntimeArch() string {
	return probe.goarch
}

func (probe *microVMBoundaryCapabilityProbe) Stat(path string) error {
	probe.statPaths = append(probe.statPaths, path)
	return nil
}

func (probe *microVMBoundaryCapabilityProbe) OpenReadOnly(path string) error {
	probe.openPaths = append(probe.openPaths, path)
	return nil
}

func (probe *microVMBoundaryCapabilityProbe) LookPath(file string) (string, error) {
	probe.lookPathNames = append(probe.lookPathNames, file)
	return "/fake/bin/" + file, nil
}
