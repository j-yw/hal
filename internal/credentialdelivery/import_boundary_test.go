package credentialdelivery

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

const credentialDeliveryPackagePath = "github.com/jywlabs/hal/internal/credentialdelivery"

var forbiddenCredentialDeliveryImports = []credentialDeliveryForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory orchestration package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "compound package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "engine package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/engine")},
	{name: "loop package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/loop")},
	{name: "PRD package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/prd")},
	{name: "template package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/template")},
	{name: "worker client package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "sandbox execution package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "sandbox execution record package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "sandbox target package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxtarget")},
	{name: "sandbox workspace package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworkspace")},
	{name: "concrete provider adapter package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
	{name: "runtime provider or concrete runtime package", match: credentialDeliveryModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime")},
	{
		name: "network client or HTTP server package",
		match: func(importPath string) bool {
			switch importPath {
			case "net", "net/http", "net/http/httputil", "net/rpc", "net/smtp":
				return true
			default:
				return strings.HasPrefix(importPath, "net/http/") ||
					strings.HasPrefix(importPath, "google.golang.org/grpc") ||
					strings.HasPrefix(importPath, "github.com/gorilla/websocket")
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
		name: "tmpfs, mount, or filesystem mutation package",
		match: func(importPath string) bool {
			switch importPath {
			case "io/fs", "os", "path/filepath", "plugin", "syscall":
				return true
			default:
				return strings.HasPrefix(importPath, "github.com/spf13/afero") ||
					strings.HasPrefix(importPath, "golang.org/x/sys/unix") ||
					strings.HasPrefix(importPath, "bazil.org/fuse") ||
					strings.HasPrefix(importPath, "github.com/hanwen/go-fuse")
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
		name: "Firecracker, KVM, or microVM package",
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

func TestCredentialDeliveryImportBoundaries(t *testing.T) {
	paths := credentialDeliveryBoundaryFiles(t)

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
			if message := credentialDeliveryImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestCredentialDeliveryImportBoundaryCoversProductionFiles(t *testing.T) {
	paths := credentialDeliveryBoundaryFiles(t)
	found := make(map[string]bool, len(paths))
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("import-boundary guard should scan production files only, got %s", path)
		}
		found[path] = true
	}
	for _, path := range []string{
		"activation.go",
		"activation_fake.go",
		"binding_validation.go",
		"contracts.go",
		"diagnostics.go",
		"normalization.go",
		"planning.go",
		"projection.go",
		"request_validation.go",
		"sanitize.go",
		"secret_resolution.go",
	} {
		if !found[path] {
			t.Fatalf("import-boundary guard files = %#v, want %s covered", paths, path)
		}
	}
}

func TestCredentialDeliveryActivationImportBoundariesCoverCoreAndDefaultFakePaths(t *testing.T) {
	paths := credentialDeliveryActivationBoundaryFiles(t)

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
			if message := credentialDeliveryImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestCredentialDeliveryDefaultFakeActivationPathsRejectLiveDependencies(t *testing.T) {
	for _, importPath := range []string{
		"github.com/jywlabs/hal/cmd",
		"github.com/jywlabs/hal/internal/factory",
		"github.com/jywlabs/hal/internal/sandbox/provider/hetzner",
		"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman",
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker",
		"github.com/jywlabs/hal/internal/sandboxworker",
		"net",
		"net/http",
		"net/http/httputil",
		"os",
		"os/exec",
		"path/filepath",
		"syscall",
		"golang.org/x/sys/unix",
		"golang.org/x/net/proxy",
		"golang.org/x/crypto/ssh/agent",
		"github.com/spf13/afero",
		"github.com/docker/docker/client",
		"github.com/containers/podman/v5/pkg/bindings",
		"github.com/firecracker-microvm/firecracker-go-sdk",
		"github.com/aws/aws-sdk-go-v2/service/secretsmanager",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := credentialDeliveryImportBoundaryMessage("activation_fake.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected default fake activation import %q", message, importPath)
			}
		})
	}
}

func TestCredentialDeliveryActivationImportBoundaryAllowsMetadataHelpersOnly(t *testing.T) {
	for _, importPath := range []string{
		"encoding/json",
		"strings",
		"github.com/jywlabs/hal/internal/sandbox",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := credentialDeliveryImportBoundaryMessage("activation.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed activation boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"context",
		"io",
		"net/url",
		"os",
		"github.com/jywlabs/hal/internal/credentialdelivery/live",
		"github.com/jywlabs/hal/internal/sandboxruntime",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := credentialDeliveryImportBoundaryMessage("activation.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected activation import path %q", message, importPath)
			}
		})
	}
}

func TestCredentialDeliveryForbiddenImportListCoversLiveImplementationDependencies(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "factory orchestration package", importPath: "github.com/jywlabs/hal/internal/factory"},
		{name: "compound package", importPath: "github.com/jywlabs/hal/internal/compound"},
		{name: "worker client package", importPath: "github.com/jywlabs/hal/internal/sandboxworker"},
		{name: "sandbox execution package", importPath: "github.com/jywlabs/hal/internal/sandboxexec"},
		{name: "sandbox execution records", importPath: "github.com/jywlabs/hal/internal/sandboxexecution"},
		{name: "sandbox target package", importPath: "github.com/jywlabs/hal/internal/sandboxtarget"},
		{name: "sandbox workspace package", importPath: "github.com/jywlabs/hal/internal/sandboxworkspace"},
		{name: "concrete provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/hetzner"},
		{name: "runtime provider root", importPath: "github.com/jywlabs/hal/internal/sandboxruntime"},
		{name: "concrete SSH-machine runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"},
		{name: "concrete rootless Podman runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"},
		{name: "standard network client package", importPath: "net"},
		{name: "standard HTTP server client package", importPath: "net/http"},
		{name: "standard HTTP proxy utility package", importPath: "net/http/httputil"},
		{name: "external network client", importPath: "google.golang.org/grpc"},
		{name: "process execution", importPath: "os/exec"},
		{name: "HTTP proxy implementation", importPath: "golang.org/x/net/proxy"},
		{name: "third-party HTTP proxy implementation", importPath: "github.com/elazarl/goproxy"},
		{name: "SSH agent implementation", importPath: "golang.org/x/crypto/ssh/agent"},
		{name: "SSH implementation", importPath: "golang.org/x/crypto/ssh"},
		{name: "filesystem writer", importPath: "os"},
		{name: "filesystem path package", importPath: "path/filepath"},
		{name: "mount syscall package", importPath: "syscall"},
		{name: "unix mount package", importPath: "golang.org/x/sys/unix"},
		{name: "filesystem abstraction", importPath: "github.com/spf13/afero"},
		{name: "Docker client", importPath: "github.com/docker/docker/client"},
		{name: "Podman bindings", importPath: "github.com/containers/podman/v5/pkg/bindings"},
		{name: "libvirt binding", importPath: "libvirt.org/go/libvirt"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk"},
		{name: "KVM helper", importPath: "github.com/example/kvm-driver"},
		{name: "QEMU helper", importPath: "github.com/example/qemu-driver"},
		{name: "DigitalOcean SDK", importPath: "github.com/digitalocean/godo"},
		{name: "AWS SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/secretsmanager"},
		{name: "Azure SDK", importPath: "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"},
		{name: "Google Cloud SDK", importPath: "cloud.google.com/go/secretmanager/apiv1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := credentialDeliveryForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestCredentialDeliveryImportBoundaryAllowsPureMetadataDependenciesOnly(t *testing.T) {
	for _, importPath := range []string{
		"encoding/json",
		"errors",
		"fmt",
		"reflect",
		"slices",
		"sort",
		"strconv",
		"strings",
		"unicode",
		"unicode/utf8",
		"github.com/jywlabs/hal/internal/sandbox",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := credentialDeliveryImportBoundaryMessage("contracts.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"context",
		"io",
		"net/url",
		"os",
		"os/exec",
		"github.com/jywlabs/hal/internal/factory",
		"github.com/jywlabs/hal/internal/sandbox/provider/hetzner",
		"github.com/jywlabs/hal/internal/sandboxruntime",
		"github.com/jywlabs/hal/internal/template",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := credentialDeliveryImportBoundaryMessage("contracts.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func TestCredentialDeliveryImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := credentialDeliveryImportBoundaryMessage("contracts.go", importPath)
	if !strings.Contains(message, credentialDeliveryPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, credentialDeliveryPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func TestCredentialDeliverySourceGuardOmitsLiveBehaviorMarkers(t *testing.T) {
	for _, path := range credentialDeliveryBoundaryFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		if message := credentialDeliverySourceBoundaryMessage(path, string(source)); message != "" {
			t.Fatal(message)
		}
	}
}

func TestCredentialDeliverySourceGuardCoversLiveBehaviorMarkers(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{name: "live listener", source: `net.Listen("tcp", ":8080")`, want: "net.Listen"},
		{name: "HTTP server", source: `http.ListenAndServe(":8080", handler)`, want: "http.ListenAndServe"},
		{name: "network dial", source: `net.Dial("tcp", address)`, want: "net.Dial"},
		{name: "dial context", source: `dialer.DialContext(ctx, "tcp", address)`, want: "DialContext"},
		{name: "process execution", source: `exec.Command("sh", "-c", script)`, want: "exec.Command"},
		{name: "process execution with context", source: `exec.CommandContext(ctx, "sh", "-c", script)`, want: "exec.CommandContext"},
		{name: "tmpfs writer", source: `os.WriteFile(tmpfsPath, secret, 0600)`, want: "os.WriteFile"},
		{name: "mount helper", source: `unix.Mount("tmpfs", target, "tmpfs", 0, "")`, want: "unix.Mount"},
		{name: "mount function", source: `MountTmpfs(target, secret)`, want: "MountTmpfs"},
		{name: "SSH agent helper", source: `agent.NewClient(conn)`, want: "agent.NewClient"},
		{name: "SSH agent forwarding", source: `ForwardSSHAgent(conn)`, want: "ForwardSSHAgent"},
		{name: "environment injection", source: `cmd.Env = append(cmd.Env, "TOKEN="+secret)`, want: "Env assignment"},
		{name: "environment set", source: `os.Setenv("TOKEN", secret)`, want: "os.Setenv"},
		{name: "provider credential fetch", source: `FetchProviderCredential(ctx, ref)`, want: "FetchProviderCredential"},
		{name: "provider secret fetch", source: `client.GetSecretValue(ctx, input)`, want: "GetSecretValue"},
		{name: "Docker client", source: `docker.NewClientWithOpts()`, want: "docker.NewClient"},
		{name: "Podman bindings", source: `bindings.NewConnection(ctx, uri)`, want: "bindings.NewConnection"},
		{name: "Firecracker helper", source: `firecracker.NewMachine(ctx, cfg)`, want: "firecracker"},
		{name: "worker client", source: `sandboxworker.NewClientDriver(opts)`, want: "sandboxworker."},
		{name: "runtime provider", source: `NewRuntimeDriver(config)`, want: "NewRuntimeDriver"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := credentialDeliverySourceBoundaryMessage("contracts.go", credentialDeliveryFunctionSource(tt.source))
			if !strings.Contains(message, tt.want) {
				t.Fatalf("source boundary message = %q, want marker %q", message, tt.want)
			}
		})
	}
}

func TestCredentialDeliverySourceGuardAllowsFixtureStringsAndComments(t *testing.T) {
	source := `package credentialdelivery

// Fixture comments may mention net.Listen, http.ListenAndServe, unix.Mount,
// MountTmpfs, ForwardSSHAgent, InjectEnv, FetchProviderCredential, net.Dial,
// Docker, Podman, Firecracker, and worker clients without becoming behavior.
const (
	fixtureLiveListenerText = "net.Listen http.ListenAndServe"
	fixtureMountText = "unix.Mount MountTmpfs file_tmpfs"
	fixtureSSHAgentText = "ForwardSSHAgent ssh_agent"
	fixtureEnvText = "InjectEnv env"
	fixtureProviderText = "FetchProviderCredential provider credential fetch"
	fixtureDialText = "net.Dial DialContext"
	fixtureRuntimeText = "docker.NewClient firecracker.NewMachine sandboxworker.NewClientDriver"
)
`
	if message := credentialDeliverySourceBoundaryMessage("credentialdelivery_fixture_test.go", source); message != "" {
		t.Fatalf("fixture comments and strings unexpectedly failed source guard: %s", message)
	}
}

func TestCredentialDeliveryOptionalLiveHarnessGateIsBuildTaggedAndExplicit(t *testing.T) {
	sourceBytes, err := os.ReadFile("credential_delivery_live_test.go")
	if err != nil {
		t.Fatalf("ReadFile(credential_delivery_live_test.go) error: %v", err)
	}
	source := string(sourceBytes)
	for _, marker := range []string{
		"//go:build credential_delivery_live",
		"HAL_CREDENTIAL_DELIVERY_LIVE",
		"HAL_CREDENTIAL_DELIVERY_LIVE_HTTP_PROXY",
		"HAL_CREDENTIAL_DELIVERY_LIVE_FILE_TMPFS",
		"HAL_CREDENTIAL_DELIVERY_LIVE_SSH_AGENT",
		"HAL_CREDENTIAL_DELIVERY_LIVE_ENV",
		"t.Skip",
		"credential delivery live harness is an opt-in placeholder",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("credential delivery optional live harness missing marker %q", marker)
		}
	}
	for _, forbidden := range []string{
		"//go:build integration",
		"//go:build worker_integration",
		"//go:build podman_integration",
		"//go:build firecracker_live",
		"//go:build network_enforcement_live",
		"net.Listen(",
		"http.ListenAndServe(",
		"exec.Command(",
		"os.WriteFile(",
		"os.Setenv(",
		"agent.NewClient(",
		"MountTmpfs(",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("credential delivery optional live harness contains forbidden marker %q", forbidden)
		}
	}
}

func credentialDeliveryBoundaryFiles(t *testing.T) []string {
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
		t.Fatal("no credential delivery files matched import-boundary guard")
	}
	return out
}

func credentialDeliveryActivationBoundaryFiles(t *testing.T) []string {
	t.Helper()

	paths := []string{"activation.go", "activation_fake.go"}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("activation import-boundary guard should scan production files only, got %s", path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("activation import-boundary file %s unavailable: %v", path, err)
		}
	}
	return paths
}

func credentialDeliveryImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := credentialDeliveryForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", credentialDeliveryPackagePath, fileName, forbidden.name, importPath)
	}
	if credentialDeliveryAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unapproved dependency %q; credential delivery contracts must remain pure metadata and fake-only", credentialDeliveryPackagePath, fileName, importPath)
}

func credentialDeliveryForbiddenImportFor(importPath string) *credentialDeliveryForbiddenImport {
	for i := range forbiddenCredentialDeliveryImports {
		if forbiddenCredentialDeliveryImports[i].match(importPath) {
			return &forbiddenCredentialDeliveryImports[i]
		}
	}
	return nil
}

func credentialDeliveryAllowedImport(importPath string) bool {
	switch importPath {
	case "encoding/json",
		"errors",
		"fmt",
		"reflect",
		"slices",
		"sort",
		"strconv",
		"strings",
		"unicode",
		"unicode/utf8",
		"github.com/jywlabs/hal/internal/sandbox":
		return true
	default:
		return false
	}
}

func credentialDeliverySourceBoundaryMessage(fileName, source string) string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fileName, source, 0)
	if err != nil {
		return fmt.Sprintf("package %s file %s could not be parsed for source guard: %v", credentialDeliveryPackagePath, fileName, err)
	}

	var marker string
	ast.Inspect(file, func(node ast.Node) bool {
		if marker != "" {
			return false
		}
		switch n := node.(type) {
		case *ast.FuncDecl:
			marker = credentialDeliveryForbiddenIdentifierMarker(n.Name.Name)
		case *ast.AssignStmt:
			marker = credentialDeliveryForbiddenAssignmentMarker(n)
		case *ast.CallExpr:
			switch fn := n.Fun.(type) {
			case *ast.Ident:
				marker = credentialDeliveryForbiddenIdentifierMarker(fn.Name)
			case *ast.SelectorExpr:
				marker = credentialDeliveryForbiddenSelectorMarker(fn)
			}
		case *ast.SelectorExpr:
			marker = credentialDeliveryForbiddenSelectorMarker(n)
		}
		return marker == ""
	})
	if marker != "" {
		return fmt.Sprintf("package %s file %s contains forbidden live credential delivery behavior marker %q", credentialDeliveryPackagePath, fileName, marker)
	}
	return ""
}

func credentialDeliveryForbiddenAssignmentMarker(assign *ast.AssignStmt) string {
	for _, expr := range assign.Lhs {
		if selector, ok := expr.(*ast.SelectorExpr); ok && selector.Sel.Name == "Env" {
			return "Env assignment"
		}
	}
	return ""
}

func credentialDeliveryForbiddenSelectorMarker(selector *ast.SelectorExpr) string {
	qualifier, _ := selector.X.(*ast.Ident)
	if qualifier == nil {
		return credentialDeliveryForbiddenIdentifierMarker(selector.Sel.Name)
	}

	switch qualifier.Name {
	case "net":
		if selector.Sel.Name == "Listen" || credentialDeliveryDialSelector(selector.Sel.Name) {
			return "net." + selector.Sel.Name
		}
	case "http":
		if selector.Sel.Name == "ListenAndServe" ||
			selector.Sel.Name == "Serve" ||
			selector.Sel.Name == "Client" ||
			strings.HasPrefix(selector.Sel.Name, "Proxy") ||
			strings.HasPrefix(selector.Sel.Name, "Get") ||
			strings.HasPrefix(selector.Sel.Name, "Post") {
			return "http." + selector.Sel.Name
		}
	case "httputil":
		return "httputil"
	case "grpc":
		if credentialDeliveryDialSelector(selector.Sel.Name) {
			return "grpc." + selector.Sel.Name
		}
	case "exec":
		if selector.Sel.Name == "Command" || selector.Sel.Name == "CommandContext" {
			return "exec." + selector.Sel.Name
		}
	case "os":
		switch selector.Sel.Name {
		case "WriteFile", "Create", "Mkdir", "MkdirAll", "Setenv", "Environ", "Getenv", "LookupEnv":
			return "os." + selector.Sel.Name
		}
	case "syscall", "unix", "mount", "tmpfs":
		if selector.Sel.Name == "Mount" ||
			strings.HasPrefix(selector.Sel.Name, "Mount") ||
			strings.HasPrefix(selector.Sel.Name, "Write") {
			return qualifier.Name + "." + selector.Sel.Name
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
	case "podman", "kvm", "microvm", "qemu", "sandboxworker":
		return qualifier.Name + "."
	case "firecracker", "libvirt":
		return qualifier.Name
	case "agent", "sshagent":
		if selector.Sel.Name == "NewClient" ||
			selector.Sel.Name == "NewKeyring" ||
			strings.HasPrefix(selector.Sel.Name, "Forward") {
			return qualifier.Name + "." + selector.Sel.Name
		}
	case "provider":
		if credentialDeliveryProviderCredentialSelector(selector.Sel.Name) {
			return "provider." + selector.Sel.Name
		}
	}
	if selector.Sel.Name == "ListenAndServe" || credentialDeliveryDialSelector(selector.Sel.Name) {
		return selector.Sel.Name
	}
	if credentialDeliveryProviderCredentialSelector(selector.Sel.Name) {
		return selector.Sel.Name
	}
	return credentialDeliveryForbiddenIdentifierMarker(selector.Sel.Name)
}

func credentialDeliveryForbiddenIdentifierMarker(name string) string {
	switch name {
	case "ListenAndServe",
		"NewClientDriver",
		"NewProvider",
		"NewRuntimeDriver",
		"NewWorkerClient",
		"StartProxy",
		"RunProxy",
		"StartListener",
		"RunListener",
		"Mount",
		"MountTmpfs",
		"WriteTmpfs",
		"ForwardSSHAgent",
		"StartSSHAgent",
		"InjectEnv",
		"InjectEnvironment",
		"DeliverCredential",
		"DeliverCredentials",
		"InjectCredential",
		"InjectCredentials",
		"injectCredential",
		"injectCredentials",
		"FetchProviderCredential",
		"FetchProviderCredentials",
		"ResolveProviderCredential",
		"ResolveProviderCredentials":
		return name
	default:
		if credentialDeliveryDialSelector(name) || credentialDeliveryProviderCredentialSelector(name) {
			return name
		}
		return ""
	}
}

func credentialDeliveryDialSelector(name string) bool {
	switch name {
	case "Dial", "DialContext", "DialTCP", "DialUDP", "DialUnix":
		return true
	default:
		return false
	}
}

func credentialDeliveryProviderCredentialSelector(name string) bool {
	switch name {
	case "FetchCredential",
		"FetchCredentials",
		"GetCredential",
		"GetCredentials",
		"ResolveCredential",
		"ResolveCredentials",
		"FetchProviderCredential",
		"FetchProviderCredentials",
		"ResolveProviderCredential",
		"ResolveProviderCredentials",
		"GetSecretValue",
		"GetParameter":
		return true
	default:
		return false
	}
}

func credentialDeliveryFunctionSource(statement string) string {
	return "package credentialdelivery\nfunc forbiddenCredentialDeliverySourceMarker() {\n" + statement + "\n}\n"
}

func credentialDeliveryModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type credentialDeliveryForbiddenImport struct {
	name  string
	match func(string) bool
}
