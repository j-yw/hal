package sandbox

import (
	"fmt"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const sandboxNetworkPolicyPackagePath = "github.com/jywlabs/hal/internal/sandbox"

var forbiddenSandboxNetworkPolicyImports = []sandboxNetworkPolicyForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory orchestration package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "engine package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/internal/engine")},
	{name: "loop package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/internal/loop")},
	{name: "PRD package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/internal/prd")},
	{name: "compound package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "worker client package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "sandbox execution package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "sandbox execution record package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "sandbox target package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxtarget")},
	{name: "sandbox workspace package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworkspace")},
	{name: "concrete provider adapter package", match: sandboxNetworkPolicyModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
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
			case "net", "net/http", "net/rpc", "net/smtp":
				return true
			default:
				return strings.HasPrefix(importPath, "net/http/") ||
					strings.HasPrefix(importPath, "google.golang.org/grpc")
			}
		},
	},
	{
		name: "proxy/firewall implementation package",
		match: func(importPath string) bool {
			return strings.Contains(importPath, "proxy") || strings.Contains(importPath, "firewall")
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

func TestNetworkPolicyImportBoundaries(t *testing.T) {
	paths := sandboxNetworkPolicyBoundaryFiles(t)

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
			if message := sandboxNetworkPolicyImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestNetworkPolicyForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "factory orchestration packages", importPath: "github.com/jywlabs/hal/internal/factory"},
		{name: "engine packages", importPath: "github.com/jywlabs/hal/internal/engine"},
		{name: "loop packages", importPath: "github.com/jywlabs/hal/internal/loop"},
		{name: "PRD packages", importPath: "github.com/jywlabs/hal/internal/prd"},
		{name: "compound packages", importPath: "github.com/jywlabs/hal/internal/compound"},
		{name: "worker client packages", importPath: "github.com/jywlabs/hal/internal/sandboxworker"},
		{name: "sandbox execution packages", importPath: "github.com/jywlabs/hal/internal/sandboxexec"},
		{name: "sandbox execution record packages", importPath: "github.com/jywlabs/hal/internal/sandboxexecution"},
		{name: "sandbox target packages", importPath: "github.com/jywlabs/hal/internal/sandboxtarget"},
		{name: "sandbox workspace packages", importPath: "github.com/jywlabs/hal/internal/sandboxworkspace"},
		{name: "concrete provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/hetzner"},
		{name: "concrete SSH-machine runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"},
		{name: "concrete rootless Podman runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"},
		{name: "standard network client", importPath: "net/http"},
		{name: "external network client", importPath: "google.golang.org/grpc"},
		{name: "proxy package", importPath: "github.com/jywlabs/hal/internal/sandboxproxy"},
		{name: "firewall package", importPath: "github.com/jywlabs/hal/internal/sandbox/firewall"},
		{name: "Docker client", importPath: "github.com/docker/docker/client"},
		{name: "Podman bindings", importPath: "github.com/containers/podman/v5/pkg/bindings"},
		{name: "DigitalOcean SDK", importPath: "github.com/digitalocean/godo"},
		{name: "AWS SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2"},
		{name: "Google Cloud SDK", importPath: "cloud.google.com/go/compute/apiv1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := sandboxNetworkPolicyForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestNetworkPolicyImportBoundaryAllowsStandardLibraryOnly(t *testing.T) {
	for _, importPath := range []string{
		"strings",
		"strconv",
		"net/netip",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxNetworkPolicyImportBoundaryMessage("network_policy_validation.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"github.com/jywlabs/hal/internal/sandboxruntime",
		"github.com/jywlabs/hal/internal/template",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := sandboxNetworkPolicyImportBoundaryMessage("network_policy.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func TestNetworkPolicyImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := sandboxNetworkPolicyImportBoundaryMessage("network_policy.go", importPath)
	if !strings.Contains(message, sandboxNetworkPolicyPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, sandboxNetworkPolicyPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func TestNetworkPolicyImportBoundaryCoversSecurityIntentMapper(t *testing.T) {
	paths := sandboxNetworkPolicyBoundaryFiles(t)
	for _, path := range paths {
		if path == "security_intent.go" {
			return
		}
	}
	t.Fatalf("import-boundary guard files = %#v, want security_intent.go covered", paths)
}

func sandboxNetworkPolicyBoundaryFiles(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob("network_policy*.go")
	if err != nil {
		t.Fatalf("Glob(network_policy*.go) error: %v", err)
	}
	paths = append(paths, "security.go")
	securityIntentPaths, err := filepath.Glob("security_intent*.go")
	if err != nil {
		t.Fatalf("Glob(security_intent*.go) error: %v", err)
	}
	paths = append(paths, securityIntentPaths...)
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
		t.Fatal("no network policy files matched import-boundary guard")
	}
	return out
}

func sandboxNetworkPolicyImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxNetworkPolicyForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxNetworkPolicyPackagePath, fileName, forbidden.name, importPath)
	}
	if sandboxNetworkPolicyAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports non-standard-library dependency %q; network policy contracts and evaluators must remain pure data/metadata logic", sandboxNetworkPolicyPackagePath, fileName, importPath)
}

func sandboxNetworkPolicyForbiddenImportFor(importPath string) *sandboxNetworkPolicyForbiddenImport {
	for i := range forbiddenSandboxNetworkPolicyImports {
		if forbiddenSandboxNetworkPolicyImports[i].match(importPath) {
			return &forbiddenSandboxNetworkPolicyImports[i]
		}
	}
	return nil
}

func sandboxNetworkPolicyAllowedImport(importPath string) bool {
	return sandboxNetworkPolicyIsStandardLibraryImport(importPath)
}

func sandboxNetworkPolicyIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func sandboxNetworkPolicyModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type sandboxNetworkPolicyForbiddenImport struct {
	name  string
	match func(string) bool
}
