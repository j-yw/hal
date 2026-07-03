package sandboxtemplate

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSandboxTemplateProductionImportsStayPure(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range sandboxTemplateProductionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := sandboxTemplateForbiddenImportMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSandboxTemplateProductionSourceOmitsLiveBehaviorMarkers(t *testing.T) {
	for _, path := range sandboxTemplateProductionFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		if message := sandboxTemplateForbiddenSourceMessage(path, string(source)); message != "" {
			t.Fatal(message)
		}
	}
}

func TestSandboxTemplateImportBoundaryCoversProductionFiles(t *testing.T) {
	paths := sandboxTemplateProductionFiles(t)
	if len(paths) == 0 {
		t.Fatal("sandbox template import-boundary guard found no production files")
	}
	found := map[string]bool{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("sandbox template import-boundary guard should scan production files only, got %s", path)
		}
		found[filepath.Base(path)] = true
	}
	for _, want := range []string{"contracts.go", "decode.go", "normalize.go", "validation.go", "sanitize.go", "projection.go"} {
		if !found[want] {
			t.Fatalf("sandbox template import-boundary guard files = %#v, want %s covered", paths, want)
		}
	}
}

func TestSandboxTemplateForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd", want: "command package"},
		{name: "project template", importPath: "github.com/jywlabs/hal/internal/template", want: "Hal project template package"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory orchestration package"},
		{name: "provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/daytona", want: "concrete provider package"},
		{name: "rootless Podman runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", want: "concrete runtime package"},
		{name: "SSH-machine runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine", want: "concrete runtime package"},
		{name: "Firecracker runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker", want: "concrete runtime package"},
		{name: "Firecracker host", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost", want: "concrete runtime package"},
		{name: "exec", importPath: "os/exec", want: "process execution package"},
		{name: "syscall", importPath: "syscall", want: "process execution package"},
		{name: "x/sys", importPath: "golang.org/x/sys/unix", want: "process execution package"},
		{name: "net", importPath: "net", want: "network client or server package"},
		{name: "http", importPath: "net/http", want: "network client or server package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "Docker or Podman package"},
		{name: "Podman", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman package"},
		{name: "OCI client", importPath: "github.com/google/go-containerregistry/pkg/v1/remote", want: "OCI client package"},
		{name: "Git client", importPath: "github.com/go-git/go-git/v5", want: "Git client package"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "live microVM SDK package"},
		{name: "KVM helper", importPath: "github.com/example/kvm-driver", want: "live microVM SDK package"},
		{name: "cloud SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "cloud SDK package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := sandboxTemplateForbiddenImportMessage("contracts.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func TestSandboxTemplateAllowedImportListCoversCurrentPureDependencies(t *testing.T) {
	for _, tt := range []struct {
		file       string
		importPath string
	}{
		{file: "contracts.go", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"},
		{file: "projection.go", importPath: "github.com/jywlabs/hal/internal/sandbox"},
		{file: "projection.go", importPath: "github.com/jywlabs/hal/internal/sandboxruntime"},
		{file: "projection.go", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"},
		{file: "decode.go", importPath: "encoding/json"},
		{file: "decode.go", importPath: "gopkg.in/yaml.v3"},
		{file: "validation.go", importPath: "strings"},
	} {
		t.Run(tt.file+"/"+tt.importPath, func(t *testing.T) {
			if message := sandboxTemplateForbiddenImportMessage(tt.file, tt.importPath); message != "" {
				t.Fatalf("allowed import rejected: %s", message)
			}
		})
	}
}

func sandboxTemplateProductionFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.) error = %v", err)
	}
	var paths []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		paths = append(paths, name)
	}
	return paths
}

func sandboxTemplateForbiddenImportMessage(fileName, importPath string) string {
	if sandboxTemplateAllowedImport(fileName, importPath) {
		return ""
	}
	for _, forbidden := range sandboxTemplateForbiddenImports() {
		if forbidden.match(importPath) {
			return fileName + " imports forbidden " + forbidden.name + " " + importPath
		}
	}
	if strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/") {
		return fileName + " imports unapproved internal package " + importPath
	}
	return ""
}

func sandboxTemplateAllowedImport(fileName, importPath string) bool {
	switch importPath {
	case "encoding/json", "fmt", "sort", "strings":
		return true
	case "gopkg.in/yaml.v3":
		return fileName == "decode.go"
	case "github.com/jywlabs/hal/internal/sandbox":
		return fileName == "projection.go"
	case "github.com/jywlabs/hal/internal/sandboxruntime":
		return fileName == "projection.go"
	case "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets":
		return fileName == "contracts.go" || fileName == "normalize.go" || fileName == "projection.go"
	default:
		return false
	}
}

type sandboxTemplateForbiddenImport struct {
	name  string
	match func(string) bool
}

func sandboxTemplateForbiddenImports() []sandboxTemplateForbiddenImport {
	return []sandboxTemplateForbiddenImport{
		{name: "command package", match: moduleImport("github.com/jywlabs/hal/cmd")},
		{name: "Hal project template package", match: moduleImport("github.com/jywlabs/hal/internal/template")},
		{name: "factory orchestration package", match: moduleImport("github.com/jywlabs/hal/internal/factory")},
		{name: "concrete provider package", match: moduleImport("github.com/jywlabs/hal/internal/sandbox/provider")},
		{name: "concrete runtime package", match: func(path string) bool {
			return moduleImport("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman")(path) ||
				moduleImport("github.com/jywlabs/hal/internal/sandboxruntime/sshmachine")(path) ||
				moduleImport("github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker")(path) ||
				moduleImport("github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost")(path)
		}},
		{name: "process execution package", match: func(path string) bool {
			return path == "os/exec" || path == "syscall" || strings.HasPrefix(path, "golang.org/x/sys")
		}},
		{name: "network client or server package", match: func(path string) bool {
			return path == "net" || path == "net/http" || strings.HasPrefix(path, "net/http/") || strings.HasPrefix(path, "google.golang.org/grpc")
		}},
		{name: "Docker or Podman package", match: func(path string) bool {
			return strings.HasPrefix(path, "github.com/docker/docker") ||
				strings.HasPrefix(path, "github.com/containers/podman") ||
				strings.HasPrefix(path, "github.com/containers/image") ||
				strings.HasPrefix(path, "github.com/containers/storage") ||
				strings.HasPrefix(path, "github.com/containers/buildah")
		}},
		{name: "OCI client package", match: func(path string) bool {
			return strings.HasPrefix(path, "github.com/google/go-containerregistry") ||
				strings.HasPrefix(path, "oras.land/") ||
				strings.Contains(path, "/remote/") && strings.Contains(path, "container")
		}},
		{name: "Git client package", match: func(path string) bool {
			return strings.HasPrefix(path, "github.com/go-git/") ||
				strings.HasPrefix(path, "github.com/libgit2/") ||
				strings.HasPrefix(path, "gopkg.in/src-d/go-git")
		}},
		{name: "live microVM SDK package", match: func(path string) bool {
			lower := strings.ToLower(path)
			return strings.Contains(lower, "firecracker") ||
				strings.Contains(lower, "cloud-hypervisor") ||
				strings.Contains(lower, "cloudhypervisor") ||
				strings.Contains(lower, "libvirt") ||
				strings.Contains(lower, "qemu") ||
				strings.Contains(lower, "kvm")
		}},
		{name: "cloud SDK package", match: func(path string) bool {
			return strings.HasPrefix(path, "github.com/aws/aws-sdk-go") ||
				strings.HasPrefix(path, "github.com/aws/aws-sdk-go-v2") ||
				strings.HasPrefix(path, "github.com/Azure/azure-sdk-for-go") ||
				strings.HasPrefix(path, "github.com/digitalocean/godo") ||
				strings.HasPrefix(path, "github.com/hetznercloud/hcloud-go") ||
				strings.HasPrefix(path, "cloud.google.com/go") ||
				strings.HasPrefix(path, "google.golang.org/api")
		}},
	}
}

func sandboxTemplateForbiddenSourceMessage(fileName, source string) string {
	for _, marker := range sandboxTemplateForbiddenSourceMarkers() {
		if strings.Contains(source, marker) {
			return fileName + " contains forbidden live behavior marker " + marker
		}
	}
	return ""
}

func sandboxTemplateForbiddenSourceMarkers() []string {
	return []string{
		"exec.Command",
		"http.Get",
		"http.Post",
		"net.Dial",
		"git clone",
		"git fetch",
		"docker ",
		"podman ",
		"firecracker-go-sdk",
		"/dev/kvm",
		"KVM_CREATE_VM",
		"syscall.Exec",
		"StartVM",
		"CreateMachine",
		"DeliverCredentials",
		"secretsmanager.NewFromConfig",
		"godo.New",
		"hcloud.New",
		"compute.New",
	}
}

func moduleImport(prefix string) func(string) bool {
	return func(path string) bool {
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
}
