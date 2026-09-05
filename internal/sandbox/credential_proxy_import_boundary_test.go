package sandbox

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const sandboxCredentialProxyPackagePath = "github.com/jywlabs/hal/internal/sandbox"

var forbiddenSandboxCredentialProxyImports = []sandboxCredentialProxyForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: sandboxCredentialProxyModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory orchestration package", match: sandboxCredentialProxyModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "compound package", match: sandboxCredentialProxyModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "worker client or daemon package", match: sandboxCredentialProxyModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "sandbox execution package", match: sandboxCredentialProxyModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "sandbox execution record package", match: sandboxCredentialProxyModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "sandbox target package", match: sandboxCredentialProxyModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxtarget")},
	{name: "sandbox workspace package", match: sandboxCredentialProxyModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworkspace")},
	{name: "concrete provider adapter package", match: sandboxCredentialProxyModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
	{
		name: "concrete runtime adapter package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/")
		},
	},
	{
		name: "network client or HTTP server package",
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
		name: "tmpfs or filesystem writer package",
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

func TestCredentialProxyImportBoundaries(t *testing.T) {
	paths := sandboxCredentialProxyBoundaryFiles(t)

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
			if message := sandboxCredentialProxyImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestCredentialProxyImportBoundaryCoversProductionContractFiles(t *testing.T) {
	paths := sandboxCredentialProxyBoundaryFiles(t)
	found := make(map[string]bool, len(paths))
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("import-boundary guard should scan production files only, got %s", path)
		}
		found[path] = true
	}
	for _, path := range []string{
		"credential_proxy.go",
		"credential_proxy_network_proxy.go",
		"credential_proxy_normalization.go",
		"credential_proxy_sanitize.go",
		"credential_proxy_validation.go",
	} {
		if !found[path] {
			t.Fatalf("import-boundary guard files = %#v, want %s covered", paths, path)
		}
	}
}

func TestCredentialProxyForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "factory orchestration packages", importPath: "github.com/jywlabs/hal/internal/factory"},
		{name: "compound packages", importPath: "github.com/jywlabs/hal/internal/compound"},
		{name: "worker client packages", importPath: "github.com/jywlabs/hal/internal/sandboxworker"},
		{name: "sandbox execution packages", importPath: "github.com/jywlabs/hal/internal/sandboxexec"},
		{name: "sandbox execution record packages", importPath: "github.com/jywlabs/hal/internal/sandboxexecution"},
		{name: "sandbox target packages", importPath: "github.com/jywlabs/hal/internal/sandboxtarget"},
		{name: "sandbox workspace packages", importPath: "github.com/jywlabs/hal/internal/sandboxworkspace"},
		{name: "concrete provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/hetzner"},
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
			if forbidden := sandboxCredentialProxyForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestCredentialProxyImportBoundaryAllowsStandardLibraryMetadataHelpersOnly(t *testing.T) {
	for _, importPath := range []string{
		"encoding/json",
		"fmt",
		"reflect",
		"sort",
		"strconv",
		"strings",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxCredentialProxyImportBoundaryMessage("credential_proxy_validation.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"net",
		"net/http",
		"os",
		"os/exec",
		"github.com/jywlabs/hal/internal/factory",
		"github.com/jywlabs/hal/internal/sandboxruntime",
		"github.com/jywlabs/hal/internal/template",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := sandboxCredentialProxyImportBoundaryMessage("credential_proxy.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func TestCredentialProxyImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := sandboxCredentialProxyImportBoundaryMessage("credential_proxy.go", importPath)
	if !strings.Contains(message, sandboxCredentialProxyPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, sandboxCredentialProxyPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func TestCredentialProxyContractSourceOmitsLiveProxyBehaviorMarkers(t *testing.T) {
	for _, path := range sandboxCredentialProxyBoundaryFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		if message := sandboxCredentialProxySourceBoundaryMessage(path, string(source)); message != "" {
			t.Fatal(message)
		}
	}
}

func TestCredentialProxySourceGuardCoversRequiredLiveBehaviorMarkers(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{name: "listener", source: `net.Listen("tcp", ":8080")`, want: "net.Listen"},
		{name: "HTTP server", source: `server.ListenAndServe()`, want: "ListenAndServe"},
		{name: "HTTP proxy", source: `handler := http.ProxyURL(target)`, want: "http.Proxy"},
		{name: "HTTP proxy utility", source: `proxy := httputil.NewSingleHostReverseProxy(target)`, want: "httputil"},
		{name: "process execution", source: `cmd := exec.Command("sh", "-c", script)`, want: "exec.Command"},
		{name: "process execution with context", source: `cmd := exec.CommandContext(ctx, "sh", "-c", script)`, want: "exec.CommandContext"},
		{name: "Docker client", source: `client, _ := docker.NewClientWithOpts()`, want: "docker.NewClient"},
		{name: "Podman bindings", source: `conn, _ := bindings.NewConnection(ctx, uri)`, want: "bindings.NewConnection"},
		{name: "KVM package", source: `driver := kvm.NewDriver()`, want: "kvm."},
		{name: "microVM package", source: `vm := firecracker.NewMachine(ctx, cfg)`, want: "firecracker"},
		{name: "SSH agent helper", source: `agent.NewClient(conn)`, want: "agent.NewClient"},
		{name: "tmpfs writer", source: `os.WriteFile(tmpfsPath, secret, 0600)`, want: "os.WriteFile"},
		{name: "worker client", source: `driver := sandboxworker.NewClientDriver(opts)`, want: "sandboxworker."},
		{name: "worker daemon", source: `worker daemon socket ready`, want: "worker daemon"},
		{name: "credential injection", source: `injectCredential(target, value)`, want: "injectCredential"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := sandboxCredentialProxySourceBoundaryMessage("credential_proxy.go", tt.source)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("source boundary message = %q, want marker %q", message, tt.want)
			}
		})
	}
}

func TestCredentialProxySourceGuardScopeAllowsTestFixtures(t *testing.T) {
	const fixtureWithForbiddenMarkers = `net.Listen("tcp", ":8080"); exec.Command("sh"); injectCredential(target, value)`
	if message := sandboxCredentialProxySourceBoundaryMessage("credential_proxy_source_fixture_test.go", fixtureWithForbiddenMarkers); message == "" {
		t.Fatal("source boundary fixture should prove the forbidden markers are active")
	}
	for _, path := range sandboxCredentialProxyBoundaryFiles(t) {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("source guard should scan production files only, got %s", path)
		}
	}
}

func sandboxCredentialProxyBoundaryFiles(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob("credential_proxy*.go")
	if err != nil {
		t.Fatalf("Glob(credential_proxy*.go) error: %v", err)
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
		t.Fatal("no credential proxy files matched import-boundary guard")
	}
	return out
}

func sandboxCredentialProxySourceBoundaryMessage(fileName, source string) string {
	for _, marker := range sandboxCredentialProxyForbiddenSourceMarkers() {
		if strings.Contains(source, marker) {
			return fmt.Sprintf("package %s file %s contains forbidden live credential proxy behavior marker %q", sandboxCredentialProxyPackagePath, fileName, marker)
		}
	}
	return ""
}

func sandboxCredentialProxyForbiddenSourceMarkers() []string {
	return []string{
		"net.Listen",
		"ListenAndServe",
		"http.Proxy",
		"httputil",
		"exec.CommandContext",
		"exec.Command",
		"docker.NewClient",
		"NewClientWithOpts",
		"bindings.NewConnection",
		"podman.New",
		"kvm.",
		"KVM",
		"libvirt",
		"firecracker",
		"microvm.",
		"microVM.",
		"qemu.",
		"agent.NewClient",
		"agent.NewKeyring",
		"sshagent.",
		"SSH_AUTH_SOCK",
		"os.WriteFile",
		"tmpfs.Write",
		"TmpfsWriter",
		"WriteTmpfs",
		"sandboxworker.",
		"NewClientDriver",
		"worker client",
		"worker daemon",
		"credential injection",
		"CredentialInjector",
		"InjectCredential",
		"InjectCredentials",
		"injectCredential",
		"injectCredentials",
	}
}

func sandboxCredentialProxyImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxCredentialProxyForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxCredentialProxyPackagePath, fileName, forbidden.name, importPath)
	}
	if sandboxCredentialProxyAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unapproved dependency %q; credential proxy contracts must remain metadata-only and fake-only", sandboxCredentialProxyPackagePath, fileName, importPath)
}

func sandboxCredentialProxyForbiddenImportFor(importPath string) *sandboxCredentialProxyForbiddenImport {
	for i := range forbiddenSandboxCredentialProxyImports {
		if forbiddenSandboxCredentialProxyImports[i].match(importPath) {
			return &forbiddenSandboxCredentialProxyImports[i]
		}
	}
	return nil
}

func sandboxCredentialProxyAllowedImport(importPath string) bool {
	return sandboxCredentialProxyIsStandardLibraryImport(importPath)
}

func sandboxCredentialProxyIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func sandboxCredentialProxyModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type sandboxCredentialProxyForbiddenImport struct {
	name  string
	match func(string) bool
}
