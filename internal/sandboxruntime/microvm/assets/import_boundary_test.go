package assets

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

const launchAssetsPackagePath = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"

var forbiddenLaunchAssetProductionImports = []launchAssetForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: launchAssetModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory package", match: launchAssetModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "worker protocol package", match: launchAssetModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "sandbox execution package", match: launchAssetModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "sandbox execution record package", match: launchAssetModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "sandbox provider package", match: launchAssetModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
	{name: "Firecracker execution package", match: launchAssetModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker")},
	{name: "Firecracker host package", match: launchAssetModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost")},
	{name: "rootless Podman runtime package", match: launchAssetModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman")},
	{name: "SSH-machine runtime package", match: launchAssetModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/sshmachine")},
	{
		name: "filesystem execution package",
		match: func(importPath string) bool {
			return importPath == "os" ||
				importPath == "io/fs" ||
				importPath == "path/filepath" ||
				importPath == "syscall" ||
				strings.HasPrefix(importPath, "golang.org/x/sys")
		},
	},
	{
		name: "process launch package",
		match: func(importPath string) bool {
			return importPath == "os/exec"
		},
	},
	{
		name: "network client or server package",
		match: func(importPath string) bool {
			switch importPath {
			case "net", "net/http", "net/http/httptest", "net/http/httputil", "net/rpc":
				return true
			default:
				return strings.HasPrefix(importPath, "net/http/") ||
					strings.HasPrefix(importPath, "google.golang.org/grpc")
			}
		},
	},
	{
		name: "Docker or Podman API package",
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

func TestLaunchAssetProductionImportsStayDataOnly(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range launchAssetProductionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := launchAssetProductionImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestLaunchAssetProductionSourceOmitsRuntimeSideEffects(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range launchAssetProductionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if message := launchAssetForbiddenCallBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
	}
}

func TestLaunchAssetImportBoundaryCoversProductionFiles(t *testing.T) {
	paths := launchAssetProductionFiles(t)
	found := map[string]bool{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("import-boundary guard should scan production files only, got %s", path)
		}
		found[path] = true
	}
	for _, path := range []string{"contracts.go", "validation.go"} {
		if !found[path] {
			t.Fatalf("import-boundary guard files = %#v, want %s covered", paths, path)
		}
	}
}

func TestLaunchAssetForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra", want: "Cobra package"},
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd", want: "cmd package"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory package"},
		{name: "worker", importPath: "github.com/jywlabs/hal/internal/sandboxworker/protocol", want: "worker protocol package"},
		{name: "provider", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/hetzner", want: "sandbox provider package"},
		{name: "Firecracker", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker", want: "Firecracker execution package"},
		{name: "Firecracker host", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost", want: "Firecracker host package"},
		{name: "rootless Podman", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", want: "rootless Podman runtime package"},
		{name: "SSH machine", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine", want: "SSH-machine runtime package"},
		{name: "os", importPath: "os", want: "filesystem execution package"},
		{name: "filepath", importPath: "path/filepath", want: "filesystem execution package"},
		{name: "exec", importPath: "os/exec", want: "process launch package"},
		{name: "net", importPath: "net", want: "network client or server package"},
		{name: "http", importPath: "net/http", want: "network client or server package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "Docker or Podman API package"},
		{name: "Podman", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman API package"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "microVM backend SDK package"},
		{name: "AWS", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "cloud SDK package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := launchAssetProductionImportBoundaryMessage("contracts.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func launchAssetProductionFiles(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.) error: %v", err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		paths = append(paths, filepath.Join(".", name))
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("no launch asset production files matched import-boundary guard")
	}
	return paths
}

func launchAssetProductionImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := launchAssetForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", launchAssetsPackagePath, fileName, forbidden.name, importPath)
	}
	if launchAssetIsStandardLibraryImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unapproved dependency %q; launch asset contracts must stay data-only", launchAssetsPackagePath, fileName, importPath)
}

func launchAssetForbiddenImportFor(importPath string) *launchAssetForbiddenImport {
	for i := range forbiddenLaunchAssetProductionImports {
		if forbiddenLaunchAssetProductionImports[i].match(importPath) {
			return &forbiddenLaunchAssetProductionImports[i]
		}
	}
	return nil
}

func launchAssetForbiddenCallBoundaryMessage(fileName string, file *ast.File) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := launchAssetCallSelector(call)
		reason := ""
		switch selector {
		case "os.Open", "os.OpenFile", "os.Stat", "os.Lstat", "os.ReadFile", "os.WriteFile", "os.Create", "os.CreateTemp", "os.Mkdir", "os.MkdirAll", "os.Remove", "os.RemoveAll", "os.Rename":
			reason = "filesystem access"
		case "exec.Command", "exec.CommandContext":
			reason = "process launch"
		case "net.Listen", "net.ListenPacket", "net.Dial", "net.DialTimeout":
			reason = "network listener or dialer"
		case "http.Get", "http.Post", "http.ListenAndServe", "http.ListenAndServeTLS":
			reason = "HTTP client or server"
		case "grpc.Dial", "grpc.DialContext", "grpc.NewClient":
			reason = "gRPC client"
		}
		if reason != "" {
			message = fmt.Sprintf("%s calls %s (%s); launch asset package must remain data-only", fileName, selector, reason)
			return false
		}
		return true
	})
	return message
}

func launchAssetCallSelector(call *ast.CallExpr) string {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	ident, ok := selector.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name + "." + selector.Sel.Name
}

func launchAssetIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func launchAssetModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type launchAssetForbiddenImport struct {
	name  string
	match func(string) bool
}
