package livegate

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

const liveGatePackagePath = "github.com/jywlabs/hal/internal/livegate"

var forbiddenLiveGateImports = []liveGateForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "command test helper package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/cmdtest")},
	{name: "factory orchestration package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "compound package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "worker client package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "sandbox execution package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "sandbox execution record package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "sandbox target package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxtarget")},
	{name: "sandbox workspace package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworkspace")},
	{name: "credential delivery implementation package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/credentialdelivery")},
	{name: "concrete provider adapter package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
	{name: "live network enforcement implementation package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement")},
	{name: "concrete microVM runtime package", match: liveGateModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm")},
	{
		name: "concrete runtime adapter package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/")
		},
	},
	{
		name: "network client package",
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
		name: "process execution package",
		match: func(importPath string) bool {
			return importPath == "os/exec"
		},
	},
	{
		name: "filesystem execution helper package",
		match: func(importPath string) bool {
			switch importPath {
			case "io/fs", "os", "path/filepath":
				return true
			default:
				return strings.HasPrefix(importPath, "github.com/spf13/afero")
			}
		},
	},
	{
		name: "Docker or Podman client package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/docker/docker") ||
				strings.HasPrefix(importPath, "github.com/containers/podman")
		},
	},
	{
		name: "Firecracker SDK or KVM-specific package",
		match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return strings.Contains(lower, "firecracker") ||
				strings.Contains(lower, "libvirt") ||
				strings.Contains(lower, "kvm") ||
				strings.Contains(lower, "qemu")
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
				strings.HasPrefix(importPath, "cloud.google.com/go") ||
				strings.HasPrefix(importPath, "google.golang.org/api")
		},
	},
}

func TestLiveGateImportBoundaries(t *testing.T) {
	paths := liveGateBoundaryFiles(t)

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
			if message := liveGateImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestLiveGateImportBoundaryCoversProductionContractFiles(t *testing.T) {
	paths := liveGateBoundaryFiles(t)
	foundContract := false
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("import-boundary guard should scan production files only, got %s", path)
		}
		if path == "contracts.go" {
			foundContract = true
		}
	}
	if !foundContract {
		t.Fatalf("import-boundary guard files = %#v, want contracts.go covered", paths)
	}
}

func TestLiveGateForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "command test helper packages", importPath: "github.com/jywlabs/hal/internal/cmdtest"},
		{name: "factory orchestration packages", importPath: "github.com/jywlabs/hal/internal/factory"},
		{name: "compound packages", importPath: "github.com/jywlabs/hal/internal/compound"},
		{name: "worker client packages", importPath: "github.com/jywlabs/hal/internal/sandboxworker"},
		{name: "sandbox execution packages", importPath: "github.com/jywlabs/hal/internal/sandboxexec"},
		{name: "sandbox execution record packages", importPath: "github.com/jywlabs/hal/internal/sandboxexecution"},
		{name: "sandbox target packages", importPath: "github.com/jywlabs/hal/internal/sandboxtarget"},
		{name: "sandbox workspace packages", importPath: "github.com/jywlabs/hal/internal/sandboxworkspace"},
		{name: "credential delivery implementation", importPath: "github.com/jywlabs/hal/internal/credentialdelivery"},
		{name: "concrete provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/hetzner"},
		{name: "live network enforcement implementation", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"},
		{name: "concrete Firecracker runtime implementation", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"},
		{name: "concrete rootless Podman runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"},
		{name: "standard network package", importPath: "net"},
		{name: "standard HTTP package", importPath: "net/http"},
		{name: "external network client", importPath: "google.golang.org/grpc"},
		{name: "process execution", importPath: "os/exec"},
		{name: "filesystem package", importPath: "os"},
		{name: "filesystem path package", importPath: "path/filepath"},
		{name: "filesystem abstraction", importPath: "github.com/spf13/afero"},
		{name: "Docker client", importPath: "github.com/docker/docker/client"},
		{name: "Podman bindings", importPath: "github.com/containers/podman/v5/pkg/bindings"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk"},
		{name: "libvirt binding", importPath: "libvirt.org/go/libvirt"},
		{name: "KVM helper", importPath: "github.com/example/kvm-driver"},
		{name: "QEMU helper", importPath: "github.com/example/qemu-driver"},
		{name: "DigitalOcean SDK", importPath: "github.com/digitalocean/godo"},
		{name: "AWS SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2"},
		{name: "Google Cloud SDK", importPath: "cloud.google.com/go/compute/apiv1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := liveGateForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestLiveGateImportBoundaryAllowsStandardLibraryMetadataHelpersOnly(t *testing.T) {
	for _, importPath := range []string{
		"encoding/json",
		"strings",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := liveGateImportBoundaryMessage("contracts.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"net",
		"net/http",
		"os",
		"os/exec",
		"path/filepath",
		"github.com/jywlabs/hal/internal/sandboxruntime",
		"github.com/jywlabs/hal/internal/template",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := liveGateImportBoundaryMessage("contracts.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func TestLiveGateImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := liveGateImportBoundaryMessage("contracts.go", importPath)
	if !strings.Contains(message, liveGatePackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, liveGatePackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func TestLiveGateContractSourceOmitsLiveBehaviorMarkers(t *testing.T) {
	for _, path := range liveGateBoundaryFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		if message := liveGateSourceBoundaryMessage(path, string(source)); message != "" {
			t.Fatal(message)
		}
	}
}

func TestLiveGateSourceGuardCoversRequiredLiveBehaviorMarkers(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{name: "listener", source: `net.Listen("tcp", ":8080")`, want: "net.Listen"},
		{name: "HTTP server", source: `server.ListenAndServe()`, want: "ListenAndServe"},
		{name: "process execution", source: `exec.Command("sh", "-c", script)`, want: "exec.Command"},
		{name: "Docker client", source: `docker.NewClientWithOpts()`, want: "docker.NewClient"},
		{name: "Podman bindings", source: `bindings.NewConnection(ctx, uri)`, want: "bindings.NewConnection"},
		{name: "Firecracker SDK", source: `firecracker.NewMachine(ctx, cfg)`, want: "firecracker"},
		{name: "KVM helper", source: `kvm.NewDriver()`, want: "kvm."},
		{name: "filesystem write", source: `os.WriteFile(path, data, 0600)`, want: "os.WriteFile"},
		{name: "worker client", source: `sandboxworker.NewClientDriver(opts)`, want: "sandboxworker."},
		{name: "provider constructor", source: `NewProvider(config)`, want: "NewProvider"},
		{name: "credential injection", source: `DeliverCredential(binding)`, want: "DeliverCredential"},
		{name: "network proxy start", source: `StartNetworkProxy(plan)`, want: "StartNetworkProxy"},
		{name: "firewall apply", source: `ApplyFirewallRules(plan)`, want: "ApplyFirewallRules"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := liveGateSourceBoundaryMessage("contracts.go", liveGateFunctionSource(tt.source))
			if !strings.Contains(message, tt.want) {
				t.Fatalf("source boundary message = %q, want marker %q", message, tt.want)
			}
		})
	}
}

func TestLiveGateSourceGuardAllowsEnumValuesAndComments(t *testing.T) {
	source := `package livegate

// Live gates may document Firecracker, KVM, Docker, Podman, proxy, firewall,
// worker integration, env vars, build tags, and command labels without
// importing or executing those implementations.
const (
	firecrackerGate = GateCategoryFirecracker
	networkGate = GateCategoryNetworkEnforcement
	credentialGate = GateCategoryCredentialDelivery
	workerGate = GateCategoryWorkerIntegration
	podmanGate = GateCategoryPodmanIntegration
	firecrackerBuildTag = BuildTagFirecrackerLive
	workerCapability = CapabilityWorkerIntegration
)
`
	if message := liveGateSourceBoundaryMessage("contracts.go", source); message != "" {
		t.Fatalf("safe enum values and documentation comments unexpectedly failed source guard: %s", message)
	}
}

func liveGateBoundaryFiles(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("Glob(*.go) error: %v", err)
	}
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("no live gate production files matched import-boundary guard")
	}
	return out
}

func liveGateSourceBoundaryMessage(fileName, source string) string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fileName, source, 0)
	if err != nil {
		return fmt.Sprintf("package %s file %s could not be parsed for source guard: %v", liveGatePackagePath, fileName, err)
	}

	var marker string
	ast.Inspect(file, func(node ast.Node) bool {
		if marker != "" {
			return false
		}
		switch n := node.(type) {
		case *ast.FuncDecl:
			marker = liveGateForbiddenIdentifierMarker(n.Name.Name)
		case *ast.CallExpr:
			switch fn := n.Fun.(type) {
			case *ast.Ident:
				marker = liveGateForbiddenIdentifierMarker(fn.Name)
			case *ast.SelectorExpr:
				marker = liveGateForbiddenSelectorMarker(fn)
			}
		case *ast.SelectorExpr:
			marker = liveGateForbiddenSelectorMarker(n)
		}
		return marker == ""
	})
	if marker != "" {
		return fmt.Sprintf("package %s file %s contains forbidden live gate behavior marker %q", liveGatePackagePath, fileName, marker)
	}
	return ""
}

func liveGateForbiddenSelectorMarker(selector *ast.SelectorExpr) string {
	qualifier, _ := selector.X.(*ast.Ident)
	if qualifier == nil {
		if selector.Sel.Name == "ListenAndServe" {
			return selector.Sel.Name
		}
		return liveGateForbiddenIdentifierMarker(selector.Sel.Name)
	}

	switch qualifier.Name {
	case "net":
		if selector.Sel.Name == "Listen" || strings.HasPrefix(selector.Sel.Name, "Dial") {
			return "net." + selector.Sel.Name
		}
	case "http":
		if strings.HasPrefix(selector.Sel.Name, "Proxy") || selector.Sel.Name == "ListenAndServe" {
			return "http." + selector.Sel.Name
		}
	case "exec":
		if selector.Sel.Name == "Command" || selector.Sel.Name == "CommandContext" {
			return "exec." + selector.Sel.Name
		}
	case "os":
		if selector.Sel.Name == "WriteFile" || selector.Sel.Name == "Create" || selector.Sel.Name == "Mkdir" || selector.Sel.Name == "MkdirAll" {
			return "os." + selector.Sel.Name
		}
	case "docker":
		if strings.HasPrefix(selector.Sel.Name, "NewClient") {
			return "docker.NewClient"
		}
		return "docker."
	case "bindings":
		if selector.Sel.Name == "NewConnection" {
			return "bindings.NewConnection"
		}
		return "bindings."
	case "podman", "kvm", "qemu", "tmpfs", "sandboxworker":
		return qualifier.Name + "."
	case "firecracker", "libvirt":
		return qualifier.Name
	}
	if selector.Sel.Name == "ListenAndServe" {
		return selector.Sel.Name
	}
	return liveGateForbiddenIdentifierMarker(selector.Sel.Name)
}

func liveGateForbiddenIdentifierMarker(name string) string {
	switch name {
	case "ListenAndServe",
		"NewClientDriver",
		"NewProvider",
		"NewRuntimeDriver",
		"NewWorkerClient",
		"StartNetworkProxy",
		"RunNetworkProxy",
		"StartFirewall",
		"ApplyFirewall",
		"ApplyFirewallRules",
		"DeliverCredential",
		"DeliverCredentials",
		"InjectCredential",
		"InjectCredentials",
		"BootFirecracker",
		"StartWorker",
		"RunPodman",
		"PullImage":
		return name
	default:
		return ""
	}
}

func liveGateFunctionSource(statement string) string {
	return "package livegate\nfunc forbiddenLiveGateSourceMarker() {\n" + statement + "\n}\n"
}

func liveGateImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := liveGateForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", liveGatePackagePath, fileName, forbidden.name, importPath)
	}
	if liveGateAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unapproved dependency %q; live gate contracts must remain pure metadata logic and fake-only", liveGatePackagePath, fileName, importPath)
}

func liveGateForbiddenImportFor(importPath string) *liveGateForbiddenImport {
	for i := range forbiddenLiveGateImports {
		if forbiddenLiveGateImports[i].match(importPath) {
			return &forbiddenLiveGateImports[i]
		}
	}
	return nil
}

func liveGateAllowedImport(importPath string) bool {
	switch importPath {
	case "encoding/json",
		"strings":
		return true
	default:
		return false
	}
}

func liveGateModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type liveGateForbiddenImport struct {
	name  string
	match func(string) bool
}
