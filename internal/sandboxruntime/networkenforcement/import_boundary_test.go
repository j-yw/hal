package networkenforcement

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const networkEnforcementPackagePath = "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"

var forbiddenNetworkEnforcementImports = []networkEnforcementForbiddenImport{
	{name: "cmd package", match: networkEnforcementModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory package", match: networkEnforcementModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "worker package", match: networkEnforcementModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "execution package", match: networkEnforcementModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "execution record package", match: networkEnforcementModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "target package", match: networkEnforcementModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxtarget")},
	{name: "workspace package", match: networkEnforcementModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworkspace")},
	{name: "sandbox policy package", match: networkEnforcementModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox")},
	{name: "concrete runtime package", match: networkEnforcementConcreteRuntimeImport},
	{
		name: "network package",
		match: func(importPath string) bool {
			return importPath == "net" ||
				importPath == "net/http" ||
				strings.HasPrefix(importPath, "net/http/") ||
				strings.HasPrefix(importPath, "google.golang.org/grpc")
		},
	},
	{
		name: "process or privilege package",
		match: func(importPath string) bool {
			return importPath == "os/exec" ||
				importPath == "os/user" ||
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
				strings.HasPrefix(importPath, "cloud.google.com/go") ||
				strings.HasPrefix(importPath, "google.golang.org/api")
		},
	},
}

func TestNetworkEnforcementProductionImportsStayDataOnly(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", networkEnforcementPackagePath, err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := networkEnforcementImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestNetworkEnforcementForbiddenImportListCoversLiveSurfaces(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd", want: "cmd package"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory package"},
		{name: "sandbox", importPath: "github.com/jywlabs/hal/internal/sandbox", want: "sandbox policy package"},
		{name: "worker", importPath: "github.com/jywlabs/hal/internal/sandboxworker", want: "worker package"},
		{name: "rootless Podman runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", want: "concrete runtime package"},
		{name: "microVM runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm", want: "concrete runtime package"},
		{name: "network", importPath: "net", want: "network package"},
		{name: "HTTP", importPath: "net/http", want: "network package"},
		{name: "process", importPath: "os/exec", want: "process or privilege package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "Docker or Podman package"},
		{name: "Firecracker", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "microVM backend SDK package"},
		{name: "cloud SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "cloud SDK package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := networkEnforcementImportBoundaryMessage("plan.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func networkEnforcementImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := networkEnforcementForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", networkEnforcementPackagePath, fileName, forbidden.name, importPath)
	}
	if !networkEnforcementStandardLibraryImport(importPath) {
		return fmt.Sprintf("package %s file %s imports non-standard-library dependency %q; keep enforcement plan contracts standard-library only", networkEnforcementPackagePath, fileName, importPath)
	}
	return ""
}

func networkEnforcementForbiddenImportFor(importPath string) *networkEnforcementForbiddenImport {
	for i := range forbiddenNetworkEnforcementImports {
		if forbiddenNetworkEnforcementImports[i].match(importPath) {
			return &forbiddenNetworkEnforcementImports[i]
		}
	}
	return nil
}

func networkEnforcementModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

func networkEnforcementConcreteRuntimeImport(importPath string) bool {
	prefix := "github.com/jywlabs/hal/internal/sandboxruntime/"
	return strings.HasPrefix(importPath, prefix) && importPath != networkEnforcementPackagePath
}

func networkEnforcementStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

type networkEnforcementForbiddenImport struct {
	name  string
	match func(string) bool
}
