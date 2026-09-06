package sandbox

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

const sandboxNetworkProxyPackagePath = "github.com/jywlabs/hal/internal/sandbox"

var forbiddenSandboxNetworkProxyImports = []sandboxNetworkProxyForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: sandboxNetworkProxyModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory orchestration package", match: sandboxNetworkProxyModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "compound package", match: sandboxNetworkProxyModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "worker client package", match: sandboxNetworkProxyModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "concrete provider adapter package", match: sandboxNetworkProxyModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
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
		name: "Docker or Podman client package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/docker/docker") ||
				strings.HasPrefix(importPath, "github.com/containers/podman")
		},
	},
	{
		name: "KVM or microVM package",
		match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return strings.Contains(lower, "libvirt") ||
				strings.Contains(lower, "firecracker") ||
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

func TestNetworkProxyImportBoundaries(t *testing.T) {
	paths := sandboxNetworkProxyBoundaryFiles(t)

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
			if message := sandboxNetworkProxyImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestNetworkProxyImportBoundaryCoversProductionContractFiles(t *testing.T) {
	paths := sandboxNetworkProxyBoundaryFiles(t)
	foundContract := false
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("import-boundary guard should scan production files only, got %s", path)
		}
		if path == "network_proxy.go" {
			foundContract = true
		}
	}
	if !foundContract {
		t.Fatalf("import-boundary guard files = %#v, want network_proxy.go covered", paths)
	}
}

func TestNetworkProxyForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "factory orchestration packages", importPath: "github.com/jywlabs/hal/internal/factory"},
		{name: "compound packages", importPath: "github.com/jywlabs/hal/internal/compound"},
		{name: "worker client packages", importPath: "github.com/jywlabs/hal/internal/sandboxworker"},
		{name: "concrete provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/hetzner"},
		{name: "concrete SSH-machine runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"},
		{name: "concrete rootless Podman runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"},
		{name: "standard net package", importPath: "net"},
		{name: "standard HTTP package", importPath: "net/http"},
		{name: "standard HTTP utility package", importPath: "net/http/httputil"},
		{name: "external network client", importPath: "google.golang.org/grpc"},
		{name: "process execution", importPath: "os/exec"},
		{name: "Docker client", importPath: "github.com/docker/docker/client"},
		{name: "Podman bindings", importPath: "github.com/containers/podman/v5/pkg/bindings"},
		{name: "libvirt binding", importPath: "libvirt.org/go/libvirt"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk"},
		{name: "KVM helper", importPath: "github.com/example/kvm-driver"},
		{name: "DigitalOcean SDK", importPath: "github.com/digitalocean/godo"},
		{name: "AWS SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2"},
		{name: "Google Cloud SDK", importPath: "cloud.google.com/go/compute/apiv1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := sandboxNetworkProxyForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestNetworkProxyImportBoundaryAllowsStandardLibraryMetadataHelpersOnly(t *testing.T) {
	for _, importPath := range []string{
		"encoding/json",
		"fmt",
		"reflect",
		"sort",
		"strconv",
		"strings",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxNetworkProxyImportBoundaryMessage("network_proxy.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"net",
		"net/http",
		"os/exec",
		"github.com/jywlabs/hal/internal/sandboxruntime",
		"github.com/jywlabs/hal/internal/template",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := sandboxNetworkProxyImportBoundaryMessage("network_proxy.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func TestNetworkProxyImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := sandboxNetworkProxyImportBoundaryMessage("network_proxy.go", importPath)
	if !strings.Contains(message, sandboxNetworkProxyPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, sandboxNetworkProxyPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func TestNetworkProxyContractsDoNotExposeLiveRuntimeHelpers(t *testing.T) {
	paths := sandboxNetworkProxyBoundaryFiles(t)
	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if sandboxNetworkProxyLiveRuntimeHelperName(fn.Name.Name) {
				t.Fatalf("%s declares %s; proxy/log contracts must not expose live listener, shell, host inspection, provider, or mutation helpers", path, fn.Name.Name)
			}
		}
	}
}

func TestNetworkProxyContractSourceOmitsLiveRuntimeOperationMarkers(t *testing.T) {
	for _, path := range sandboxNetworkProxyBoundaryFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		for _, marker := range []string{
			"net.Listen",
			"ListenAndServe",
			"exec.Command",
			"CommandContext",
			"NewClientDriver",
			"NewProvider",
			"docker.NewClient",
			"podman",
		} {
			if strings.Contains(string(source), marker) {
				t.Fatalf("%s contains live runtime operation marker %q", path, marker)
			}
		}
	}
}

func sandboxNetworkProxyBoundaryFiles(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob("network_proxy*.go")
	if err != nil {
		t.Fatalf("Glob(network_proxy*.go) error: %v", err)
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
		t.Fatal("no network proxy contract files matched import-boundary guard")
	}
	return out
}

func sandboxNetworkProxyImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxNetworkProxyForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxNetworkProxyPackagePath, fileName, forbidden.name, importPath)
	}
	if sandboxNetworkProxyAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports non-standard-library dependency %q; proxy and policy-log contracts must remain data-only metadata", sandboxNetworkProxyPackagePath, fileName, importPath)
}

func sandboxNetworkProxyForbiddenImportFor(importPath string) *sandboxNetworkProxyForbiddenImport {
	for i := range forbiddenSandboxNetworkProxyImports {
		if forbiddenSandboxNetworkProxyImports[i].match(importPath) {
			return &forbiddenSandboxNetworkProxyImports[i]
		}
	}
	return nil
}

func sandboxNetworkProxyAllowedImport(importPath string) bool {
	return sandboxNetworkProxyIsStandardLibraryImport(importPath)
}

func sandboxNetworkProxyIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func sandboxNetworkProxyModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

func sandboxNetworkProxyLiveRuntimeHelperName(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{
		"start",
		"listen",
		"serve",
		"dial",
		"shell",
		"exec",
		"inspect",
		"provider",
		"provision",
		"mutate",
		"apply",
	} {
		if strings.HasPrefix(lower, marker) {
			return true
		}
	}
	return false
}

type sandboxNetworkProxyForbiddenImport struct {
	name  string
	match func(string) bool
}
