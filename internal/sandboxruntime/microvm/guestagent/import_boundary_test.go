package guestagent

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

const guestAgentPackagePath = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"

var forbiddenGuestAgentProductionImports = []guestAgentForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: guestAgentModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory package", match: guestAgentModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "worker package", match: guestAgentModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "sandbox execution package", match: guestAgentModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "sandbox execution record package", match: guestAgentModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "Firecracker launch package", match: guestAgentModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker")},
	{name: "Firecracker host package", match: guestAgentModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost")},
	{name: "rootless Podman runtime package", match: guestAgentModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman")},
	{
		name: "filesystem mutation package",
		match: func(importPath string) bool {
			switch importPath {
			case "os", "io/fs", "path/filepath", "syscall":
				return true
			default:
				return strings.HasPrefix(importPath, "golang.org/x/sys")
			}
		},
	},
	{
		name: "process launch package",
		match: func(importPath string) bool {
			return importPath == "os/exec"
		},
	},
	{
		name: "network listener or RPC package",
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

func TestGuestAgentProtocolProductionImportsStayDataOnly(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range guestAgentProductionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := guestAgentProductionImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestGuestAgentProtocolProductionSourceOmitsRuntimeSideEffects(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range guestAgentProductionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if message := guestAgentForbiddenCallBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
	}
}

func TestGuestAgentImportBoundaryCoversProductionFiles(t *testing.T) {
	paths := guestAgentProductionFiles(t)
	found := map[string]bool{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("import-boundary guard should scan production files only, got %s", path)
		}
		found[path] = true
	}
	for _, path := range []string{"contracts.go", "errors.go", "validation.go"} {
		if !found[path] {
			t.Fatalf("import-boundary guard files = %#v, want %s covered", paths, path)
		}
	}
}

func TestGuestAgentForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra", want: "Cobra package"},
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd", want: "cmd package"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory package"},
		{name: "worker", importPath: "github.com/jywlabs/hal/internal/sandboxworker", want: "worker package"},
		{name: "Firecracker", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker", want: "Firecracker launch package"},
		{name: "Firecracker host", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost", want: "Firecracker host package"},
		{name: "os", importPath: "os", want: "filesystem mutation package"},
		{name: "exec", importPath: "os/exec", want: "process launch package"},
		{name: "net", importPath: "net", want: "network listener or RPC package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "Docker or Podman API package"},
		{name: "Podman", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman API package"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "microVM backend SDK package"},
		{name: "AWS", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "cloud SDK package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := guestAgentProductionImportBoundaryMessage("contracts.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func guestAgentProductionFiles(t *testing.T) []string {
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
		t.Fatal("no guest-agent production files matched import-boundary guard")
	}
	return paths
}

func guestAgentProductionImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := guestAgentForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", guestAgentPackagePath, fileName, forbidden.name, importPath)
	}
	if guestAgentIsStandardLibraryImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unapproved dependency %q; guest-agent protocol contracts must stay data-only", guestAgentPackagePath, fileName, importPath)
}

func guestAgentForbiddenImportFor(importPath string) *guestAgentForbiddenImport {
	for i := range forbiddenGuestAgentProductionImports {
		if forbiddenGuestAgentProductionImports[i].match(importPath) {
			return &forbiddenGuestAgentProductionImports[i]
		}
	}
	return nil
}

func guestAgentForbiddenCallBoundaryMessage(fileName string, file *ast.File) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := guestAgentCallSelector(call)
		reason := ""
		switch selector {
		case "os.WriteFile", "os.Create", "os.CreateTemp", "os.Mkdir", "os.MkdirAll", "os.Remove", "os.RemoveAll", "os.Rename":
			reason = "filesystem mutation"
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
			message = fmt.Sprintf("%s calls %s (%s); guest-agent protocol package must remain data-only", fileName, selector, reason)
			return false
		}
		return true
	})
	return message
}

func guestAgentCallSelector(call *ast.CallExpr) string {
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

func guestAgentModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

func guestAgentIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

type guestAgentForbiddenImport struct {
	name  string
	match func(string) bool
}
