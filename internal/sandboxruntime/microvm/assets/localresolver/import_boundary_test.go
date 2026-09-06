package localresolver

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

const localResolverPackagePath = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"

var forbiddenLocalResolverProductionImports = []localResolverForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: localResolverModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory package", match: localResolverModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "worker protocol package", match: localResolverModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "sandbox execution package", match: localResolverModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "sandbox execution record package", match: localResolverModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "Firecracker execution package", match: localResolverModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker")},
	{name: "Firecracker host package", match: localResolverModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost")},
	{name: "rootless Podman runtime package", match: localResolverModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman")},
	{name: "SSH-machine runtime package", match: localResolverModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/sshmachine")},
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

func TestLocalResolverProductionImportsStayInResolverBoundary(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range localResolverProductionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := localResolverProductionImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestLocalResolverProductionSourceOmitsRuntimeSideEffects(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range localResolverProductionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		if message := localResolverForbiddenCallBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
	}
}

func TestLocalResolverImportBoundaryCoversProductionFiles(t *testing.T) {
	paths := localResolverProductionFiles(t)
	found := map[string]bool{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("import-boundary guard should scan production files only, got %s", path)
		}
		found[path] = true
	}
	if !found["resolver.go"] {
		t.Fatalf("import-boundary guard files = %#v, want resolver.go covered", paths)
	}
}

func TestLocalResolverForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra", want: "Cobra package"},
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd", want: "cmd package"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory package"},
		{name: "worker", importPath: "github.com/jywlabs/hal/internal/sandboxworker/protocol", want: "worker protocol package"},
		{name: "sandboxexec", importPath: "github.com/jywlabs/hal/internal/sandboxexec", want: "sandbox execution package"},
		{name: "Firecracker", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker", want: "Firecracker execution package"},
		{name: "Firecracker host", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost", want: "Firecracker host package"},
		{name: "rootless Podman", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", want: "rootless Podman runtime package"},
		{name: "SSH machine", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine", want: "SSH-machine runtime package"},
		{name: "exec", importPath: "os/exec", want: "process launch package"},
		{name: "net", importPath: "net", want: "network client or server package"},
		{name: "http", importPath: "net/http", want: "network client or server package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "Docker or Podman API package"},
		{name: "Podman", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman API package"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "microVM backend SDK package"},
		{name: "AWS", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "cloud SDK package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := localResolverProductionImportBoundaryMessage("resolver.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func TestLocalResolverAllowsReadOnlyFilesystemAndHashingImports(t *testing.T) {
	for _, importPath := range []string{
		"crypto/sha256",
		"encoding/hex",
		"encoding/json",
		"errors",
		"fmt",
		"io",
		"os",
		"path/filepath",
		"strings",
		"unicode",
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := localResolverProductionImportBoundaryMessage("resolver.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}
}

func TestLocalResolverConfinesL8PolicyAuthorityImport(t *testing.T) {
	const policyPath = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
	for _, fileName := range []string{"l8_distribution_verifier.go", "l8_policy_composition_correlation.go"} {
		if message := localResolverProductionImportBoundaryMessage(fileName, policyPath); message != "" {
			t.Fatalf("exact L8 authority file %q rejected: %s", fileName, message)
		}
	}
	if message := localResolverProductionImportBoundaryMessage("resolver.go", policyPath); !strings.Contains(message, "unapproved L8 policy authority dependency") {
		t.Fatalf("ordinary resolver policy import = %q, want exact-file rejection", message)
	}
}

func localResolverProductionFiles(t *testing.T) []string {
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
		t.Fatal("no local resolver production files matched import-boundary guard")
	}
	return paths
}

func localResolverProductionImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := localResolverForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", localResolverPackagePath, fileName, forbidden.name, importPath)
	}
	if localResolverIsStandardLibraryImport(importPath) {
		return ""
	}
	if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets" {
		return ""
	}
	if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build" {
		return ""
	}
	if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy" {
		switch filepath.Base(fileName) {
		case "l8_distribution_verifier.go", "l8_policy_composition_correlation.go":
			return ""
		default:
			return fmt.Sprintf("package %s file %s imports unapproved L8 policy authority dependency %q", localResolverPackagePath, fileName, importPath)
		}
	}
	if importPath == "golang.org/x/sys/unix" {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unapproved dependency %q; local asset resolver must stay isolated from command, runtime, network, and factory behavior", localResolverPackagePath, fileName, importPath)
}

func localResolverForbiddenImportFor(importPath string) *localResolverForbiddenImport {
	for i := range forbiddenLocalResolverProductionImports {
		if forbiddenLocalResolverProductionImports[i].match(importPath) {
			return &forbiddenLocalResolverProductionImports[i]
		}
	}
	return nil
}

func localResolverForbiddenCallBoundaryMessage(fileName string, file *ast.File) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := localResolverCallSelector(call)
		reason := ""
		switch selector {
		case "os.WriteFile", "os.Create", "os.CreateTemp", "os.Mkdir", "os.MkdirAll", "os.Remove", "os.RemoveAll", "os.Rename", "os.Chmod", "os.Chown", "os.Symlink", "os.Link":
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
			message = fmt.Sprintf("%s calls %s (%s); local asset resolver must remain read-only and runtime-free", fileName, selector, reason)
			return false
		}
		return true
	})
	return message
}

func localResolverCallSelector(call *ast.CallExpr) string {
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

func localResolverIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func localResolverModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type localResolverForbiddenImport struct {
	name  string
	match func(string) bool
}
