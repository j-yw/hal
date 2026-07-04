package networkenforcement

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

const networkEnforcementPackagePath = "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"

var forbiddenNetworkEnforcementImports = []networkEnforcementForbiddenImport{
	{name: "cmd package", match: networkEnforcementModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory package", match: networkEnforcementModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "worker package", match: networkEnforcementModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "Cobra package", match: networkEnforcementModuleImportMatcher("github.com/spf13/cobra")},
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
				importPath == "net/http/httputil" ||
				importPath == "net/rpc" ||
				importPath == "net/smtp" ||
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
		name: "proxy implementation package",
		match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return strings.Contains(lower, "proxy") ||
				strings.Contains(lower, "socks5")
		},
	},
	{
		name: "firewall implementation package",
		match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return strings.Contains(lower, "firewall") ||
				strings.Contains(lower, "iptables") ||
				strings.Contains(lower, "nftables") ||
				strings.Contains(lower, "pfctl")
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
				strings.HasPrefix(importPath, "github.com/linode/linodego") ||
				strings.HasPrefix(importPath, "github.com/vultr/govultr") ||
				strings.HasPrefix(importPath, "cloud.google.com/go") ||
				strings.HasPrefix(importPath, "google.golang.org/api")
		},
	},
}

func TestNetworkEnforcementProductionImportsStayDataOnly(t *testing.T) {
	paths := networkEnforcementProductionFiles(t)

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
			if message := networkEnforcementImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestNetworkEnforcementImportBoundaryCoversPlanningAndAdapterFiles(t *testing.T) {
	paths := networkEnforcementProductionFiles(t)
	found := make(map[string]bool, len(paths))
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("import-boundary guard should scan production files only, got %s", path)
		}
		found[path] = true
	}
	for _, path := range []string{
		"adapter.go",
		"aggregation.go",
		"allowlist_normalization.go",
		"doc.go",
		"listener_lifecycle.go",
		"live_contracts.go",
		"policy_proxy_decision_log.go",
		"policy_proxy_lifecycle.go",
		"plan.go",
		"policy_proxy_decision.go",
		"planner.go",
		"policy_proxy_service.go",
		"redaction.go",
		"rule_proof_adapter.go",
		"rule_proof_live.go",
		"rule_proof_live_default.go",
		"rule_lifecycle.go",
	} {
		if !found[path] {
			t.Fatalf("import-boundary guard files = %#v, want %s covered", paths, path)
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
		{name: "Cobra", importPath: "github.com/spf13/cobra", want: "Cobra package"},
		{name: "rootless Podman runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", want: "concrete runtime package"},
		{name: "microVM runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm", want: "concrete runtime package"},
		{name: "network", importPath: "net", want: "network package"},
		{name: "HTTP", importPath: "net/http", want: "network package"},
		{name: "HTTP utility", importPath: "net/http/httputil", want: "network package"},
		{name: "gRPC", importPath: "google.golang.org/grpc", want: "network package"},
		{name: "process", importPath: "os/exec", want: "process or privilege package"},
		{name: "HTTP proxy", importPath: "golang.org/x/net/proxy", want: "proxy implementation package"},
		{name: "SOCKS proxy", importPath: "github.com/armon/go-socks5", want: "proxy implementation package"},
		{name: "firewall package", importPath: "github.com/example/firewallctl", want: "firewall implementation package"},
		{name: "iptables", importPath: "github.com/coreos/go-iptables/iptables", want: "firewall implementation package"},
		{name: "nftables", importPath: "github.com/google/nftables", want: "firewall implementation package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "Docker or Podman package"},
		{name: "Podman", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman package"},
		{name: "Firecracker", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "microVM backend SDK package"},
		{name: "KVM helper", importPath: "github.com/example/kvm-driver", want: "microVM backend SDK package"},
		{name: "cloud SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "cloud SDK package"},
		{name: "Google Cloud SDK", importPath: "cloud.google.com/go/compute/apiv1", want: "cloud SDK package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := networkEnforcementImportBoundaryMessage("plan.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func TestNetworkEnforcementImportBoundaryAllowsMetadataHelpersOnly(t *testing.T) {
	for _, importPath := range []string{
		"context",
		"encoding/json",
		"fmt",
		"net/netip",
		"strconv",
		"strings",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := networkEnforcementImportBoundaryMessage("planner.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"os",
		"plugin",
		"github.com/jywlabs/hal/internal/template",
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := networkEnforcementImportBoundaryMessage("planner.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func networkEnforcementProductionFiles(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", networkEnforcementPackagePath, err)
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
		t.Fatal("no network enforcement production files matched import-boundary guard")
	}
	return paths
}

func networkEnforcementImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := networkEnforcementForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", networkEnforcementPackagePath, fileName, forbidden.name, importPath)
	}
	if !networkEnforcementAllowedImport(importPath) {
		return fmt.Sprintf("package %s file %s imports unsupported dependency %q; keep enforcement plan contracts on safe metadata helper imports only", networkEnforcementPackagePath, fileName, importPath)
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

func networkEnforcementAllowedImport(importPath string) bool {
	switch importPath {
	case "context",
		"encoding/json",
		"fmt",
		"net/netip",
		"strconv",
		"strings":
		return true
	default:
		return false
	}
}

type networkEnforcementForbiddenImport struct {
	name  string
	match func(string) bool
}
