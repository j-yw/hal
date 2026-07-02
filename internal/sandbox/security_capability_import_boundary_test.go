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

const sandboxSecurityCapabilityPackagePath = "github.com/jywlabs/hal/internal/sandbox"

var forbiddenSandboxSecurityCapabilityImports = []sandboxSecurityCapabilityForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory orchestration package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "compound package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "engine package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/internal/engine")},
	{name: "loop package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/internal/loop")},
	{name: "PRD package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/internal/prd")},
	{name: "worker client package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "sandbox execution package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "sandbox execution record package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "sandbox target package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxtarget")},
	{name: "sandbox workspace package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworkspace")},
	{name: "concrete provider adapter package", match: sandboxSecurityCapabilityModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
	{
		name: "concrete runtime adapter package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/")
		},
	},
	{
		name: "network client or HTTP package",
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
		name: "HTTP proxy implementation package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "golang.org/x/net/proxy") ||
				strings.HasPrefix(importPath, "github.com/elazarl/goproxy") ||
				strings.HasPrefix(importPath, "github.com/armon/go-socks5")
		},
	},
	{
		name: "SSH agent implementation package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "golang.org/x/crypto/ssh") ||
				strings.HasPrefix(importPath, "github.com/gliderlabs/ssh")
		},
	},
	{
		name: "tmpfs or filesystem mutation package",
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

func TestSecurityCapabilityImportBoundaries(t *testing.T) {
	paths := sandboxSecurityCapabilityBoundaryFiles(t)

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
			if message := sandboxSecurityCapabilityImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSecurityCapabilityImportBoundaryCoversProductionEvaluatorFiles(t *testing.T) {
	paths := sandboxSecurityCapabilityBoundaryFiles(t)
	found := make(map[string]bool, len(paths))
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("import-boundary guard should scan production files only, got %s", path)
		}
		found[path] = true
	}
	for _, path := range []string{
		"security_capability.go",
		"security_capability_evaluator.go",
		"security_capability_sanitize.go",
	} {
		if !found[path] {
			t.Fatalf("import-boundary guard files = %#v, want %s covered", paths, path)
		}
	}
}

func TestSecurityCapabilityForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "factory orchestration packages", importPath: "github.com/jywlabs/hal/internal/factory"},
		{name: "compound packages", importPath: "github.com/jywlabs/hal/internal/compound"},
		{name: "engine packages", importPath: "github.com/jywlabs/hal/internal/engine"},
		{name: "loop packages", importPath: "github.com/jywlabs/hal/internal/loop"},
		{name: "PRD packages", importPath: "github.com/jywlabs/hal/internal/prd"},
		{name: "worker client packages", importPath: "github.com/jywlabs/hal/internal/sandboxworker"},
		{name: "sandbox execution packages", importPath: "github.com/jywlabs/hal/internal/sandboxexec"},
		{name: "sandbox execution record packages", importPath: "github.com/jywlabs/hal/internal/sandboxexecution"},
		{name: "sandbox target packages", importPath: "github.com/jywlabs/hal/internal/sandboxtarget"},
		{name: "sandbox workspace packages", importPath: "github.com/jywlabs/hal/internal/sandboxworkspace"},
		{name: "concrete provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/daytona"},
		{name: "concrete SSH-machine runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"},
		{name: "concrete rootless Podman runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"},
		{name: "standard network package", importPath: "net"},
		{name: "standard HTTP package", importPath: "net/http"},
		{name: "standard HTTP proxy utility package", importPath: "net/http/httputil"},
		{name: "external network client", importPath: "google.golang.org/grpc"},
		{name: "process execution", importPath: "os/exec"},
		{name: "HTTP proxy implementation", importPath: "golang.org/x/net/proxy"},
		{name: "third-party HTTP proxy implementation", importPath: "github.com/elazarl/goproxy"},
		{name: "SSH agent implementation", importPath: "golang.org/x/crypto/ssh/agent"},
		{name: "SSH implementation", importPath: "golang.org/x/crypto/ssh"},
		{name: "tmpfs writer", importPath: "os"},
		{name: "filesystem path package", importPath: "path/filepath"},
		{name: "filesystem abstraction", importPath: "github.com/spf13/afero"},
		{name: "Docker client", importPath: "github.com/docker/docker/client"},
		{name: "Podman bindings", importPath: "github.com/containers/podman/v5/pkg/bindings"},
		{name: "libvirt binding", importPath: "libvirt.org/go/libvirt"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk"},
		{name: "KVM helper", importPath: "github.com/example/kvm-driver"},
		{name: "QEMU helper", importPath: "github.com/example/qemu-driver"},
		{name: "DigitalOcean SDK", importPath: "github.com/digitalocean/godo"},
		{name: "AWS SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2"},
		{name: "Google Cloud SDK", importPath: "cloud.google.com/go/compute/apiv1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := sandboxSecurityCapabilityForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestSecurityCapabilityImportBoundaryAllowsStandardLibraryMetadataHelpersOnly(t *testing.T) {
	for _, importPath := range []string{
		"encoding/json",
		"fmt",
		"reflect",
		"sort",
		"strconv",
		"strings",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxSecurityCapabilityImportBoundaryMessage("security_capability_sanitize.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"net",
		"net/http",
		"os",
		"os/exec",
		"plugin",
		"syscall",
		"github.com/jywlabs/hal/internal/factory",
		"github.com/jywlabs/hal/internal/sandboxruntime",
		"github.com/jywlabs/hal/internal/template",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := sandboxSecurityCapabilityImportBoundaryMessage("security_capability.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func TestSecurityCapabilityImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := sandboxSecurityCapabilityImportBoundaryMessage("security_capability.go", importPath)
	if !strings.Contains(message, sandboxSecurityCapabilityPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, sandboxSecurityCapabilityPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func TestSecurityCapabilitySourceOmitsLiveBehaviorMarkers(t *testing.T) {
	for _, path := range sandboxSecurityCapabilityBoundaryFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		if message := sandboxSecurityCapabilitySourceBoundaryMessage(path, string(source)); message != "" {
			t.Fatal(message)
		}
	}
}

func TestSecurityCapabilitySourceGuardCoversRequiredLiveBehaviorMarkers(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{name: "listener", source: `net.Listen("tcp", ":8080")`, want: "net.Listen"},
		{name: "HTTP server", source: `server.ListenAndServe()`, want: "ListenAndServe"},
		{name: "HTTP proxy", source: `http.ProxyURL(target)`, want: "http.Proxy"},
		{name: "HTTP proxy utility", source: `httputil.NewSingleHostReverseProxy(target)`, want: "httputil"},
		{name: "process execution", source: `exec.Command("sh", "-c", script)`, want: "exec.Command"},
		{name: "process execution with context", source: `exec.CommandContext(ctx, "sh", "-c", script)`, want: "exec.CommandContext"},
		{name: "Docker client", source: `docker.NewClientWithOpts()`, want: "docker.NewClient"},
		{name: "Podman bindings", source: `bindings.NewConnection(ctx, uri)`, want: "bindings.NewConnection"},
		{name: "KVM helper", source: `kvm.NewDriver()`, want: "kvm."},
		{name: "microVM helper", source: `firecracker.NewMachine(ctx, cfg)`, want: "firecracker"},
		{name: "SSH agent helper", source: `agent.NewClient(conn)`, want: "agent.NewClient"},
		{name: "tmpfs writer", source: `os.WriteFile(tmpfsPath, secret, 0600)`, want: "os.WriteFile"},
		{name: "worker client", source: `sandboxworker.NewClientDriver(opts)`, want: "sandboxworker."},
		{name: "provider constructor", source: `NewProvider(config)`, want: "NewProvider"},
		{name: "credential injection", source: `injectCredential(target, value)`, want: "injectCredential"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := sandboxSecurityCapabilitySourceBoundaryMessage("security_capability.go", sandboxSecurityCapabilityFunctionSource(tt.source))
			if !strings.Contains(message, tt.want) {
				t.Fatalf("source boundary message = %q, want marker %q", message, tt.want)
			}
		})
	}
}

func TestSecurityCapabilitySourceGuardAllowsEnumValuesAndDocumentationComments(t *testing.T) {
	source := `package sandbox

// Readiness can mention net.Listen, exec.Command, worker daemon startup,
// file_tmpfs, ssh_agent, http_proxy, and microvm as documentation without
// making the evaluator responsible for live runtime behavior.
const (
	allowedSecretFileTmpfs = SandboxSecretModeFileTmpfs
	allowedSecretSSHAgent = SandboxSecretModeSSHAgent
	allowedSecretHTTPProxy = SandboxSecretModeHTTPProxy
	allowedRuntimeMicroVM = SandboxRuntimeDriverMicroVM
	allowedIsolationMicroVM = SandboxSecurityCapabilityIsolationMicroVM
	allowedFileTmpfsLabel = "file_tmpfs"
	allowedSSHAgentLabel = "ssh_agent"
	allowedHTTPProxyLabel = "http_proxy"
	allowedMicroVMLabel = "microvm"
)
`
	if message := sandboxSecurityCapabilitySourceBoundaryMessage("security_capability.go", source); message != "" {
		t.Fatalf("safe enum values and documentation comments unexpectedly failed source guard: %s", message)
	}
}

func sandboxSecurityCapabilityBoundaryFiles(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob("security_capability*.go")
	if err != nil {
		t.Fatalf("Glob(security_capability*.go) error: %v", err)
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
		t.Fatal("no security capability files matched import-boundary guard")
	}
	return out
}

func sandboxSecurityCapabilitySourceBoundaryMessage(fileName, source string) string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fileName, source, 0)
	if err != nil {
		return fmt.Sprintf("package %s file %s could not be parsed for source guard: %v", sandboxSecurityCapabilityPackagePath, fileName, err)
	}

	var marker string
	ast.Inspect(file, func(node ast.Node) bool {
		if marker != "" {
			return false
		}
		switch n := node.(type) {
		case *ast.FuncDecl:
			marker = sandboxSecurityCapabilityForbiddenIdentifierMarker(n.Name.Name)
		case *ast.CallExpr:
			switch fn := n.Fun.(type) {
			case *ast.Ident:
				marker = sandboxSecurityCapabilityForbiddenIdentifierMarker(fn.Name)
			case *ast.SelectorExpr:
				marker = sandboxSecurityCapabilityForbiddenSelectorMarker(fn)
			}
		case *ast.SelectorExpr:
			marker = sandboxSecurityCapabilityForbiddenSelectorMarker(n)
		}
		return marker == ""
	})
	if marker != "" {
		return fmt.Sprintf("package %s file %s contains forbidden live security capability behavior marker %q", sandboxSecurityCapabilityPackagePath, fileName, marker)
	}
	return ""
}

func sandboxSecurityCapabilityForbiddenSelectorMarker(selector *ast.SelectorExpr) string {
	qualifier, _ := selector.X.(*ast.Ident)
	if qualifier == nil {
		if selector.Sel.Name == "ListenAndServe" {
			return selector.Sel.Name
		}
		return sandboxSecurityCapabilityForbiddenIdentifierMarker(selector.Sel.Name)
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
	case "httputil":
		return "httputil"
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
	case "podman", "kvm", "microvm", "qemu", "tmpfs", "sshagent", "sandboxworker":
		return qualifier.Name + "."
	case "firecracker", "libvirt":
		return qualifier.Name
	case "agent":
		if selector.Sel.Name == "NewClient" || selector.Sel.Name == "NewKeyring" {
			return "agent." + selector.Sel.Name
		}
	}
	if selector.Sel.Name == "ListenAndServe" {
		return selector.Sel.Name
	}
	return sandboxSecurityCapabilityForbiddenIdentifierMarker(selector.Sel.Name)
}

func sandboxSecurityCapabilityForbiddenIdentifierMarker(name string) string {
	switch name {
	case "ListenAndServe",
		"NewClientDriver",
		"NewProvider",
		"NewRuntimeDriver",
		"NewWorkerClient",
		"StartProxy",
		"RunProxy",
		"StartFirewall",
		"ApplyFirewall",
		"MountTmpfs",
		"WriteTmpfs",
		"DeliverCredential",
		"DeliverCredentials",
		"InjectCredential",
		"InjectCredentials",
		"injectCredential",
		"injectCredentials":
		return name
	default:
		return ""
	}
}

func sandboxSecurityCapabilityFunctionSource(statement string) string {
	return "package sandbox\nfunc forbiddenSecurityCapabilitySourceMarker() {\n" + statement + "\n}\n"
}

func sandboxSecurityCapabilityImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxSecurityCapabilityForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxSecurityCapabilityPackagePath, fileName, forbidden.name, importPath)
	}
	if sandboxSecurityCapabilityAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unapproved dependency %q; security capability readiness must remain pure metadata logic and fake-only", sandboxSecurityCapabilityPackagePath, fileName, importPath)
}

func sandboxSecurityCapabilityForbiddenImportFor(importPath string) *sandboxSecurityCapabilityForbiddenImport {
	for i := range forbiddenSandboxSecurityCapabilityImports {
		if forbiddenSandboxSecurityCapabilityImports[i].match(importPath) {
			return &forbiddenSandboxSecurityCapabilityImports[i]
		}
	}
	return nil
}

func sandboxSecurityCapabilityAllowedImport(importPath string) bool {
	switch importPath {
	case "encoding/json",
		"fmt",
		"reflect",
		"sort",
		"strconv",
		"strings":
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type sandboxSecurityCapabilityForbiddenImport struct {
	name  string
	match func(string) bool
}
