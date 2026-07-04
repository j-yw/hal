package sandboxruntime

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

const sandboxruntimePackagePath = "github.com/jywlabs/hal/internal/sandboxruntime"
const sandboxruntimeNetworkEnforcementPackagePath = "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"

var forbiddenSandboxruntimeImports = []sandboxruntimeForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{
		name:  "cmd package",
		match: moduleImportMatcher("github.com/jywlabs/hal/cmd"),
	},
	{
		name:  "factory run record package",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/factory"),
	},
	{
		name:  "PRD package",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/prd"),
	},
	{
		name:  "command-specific auto code",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/compound"),
	},
	{
		name:  "command-specific loop code",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/loop"),
	},
}

var forbiddenSandboxruntimeNetworkEnforcementImports = []sandboxruntimeForbiddenImport{
	{name: "cmd package", match: moduleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "worker package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "execution package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "execution record package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "target package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxtarget")},
	{name: "workspace package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxworkspace")},
	{
		name: "concrete runtime package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/") &&
				importPath != sandboxruntimeNetworkEnforcementPackagePath
		},
	},
	{
		name: "network package",
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
		name: "process or privilege package",
		match: func(importPath string) bool {
			return importPath == "os" ||
				importPath == "os/exec" ||
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

var forbiddenSandboxruntimeCredentialDeliveryActivationImports = []sandboxruntimeForbiddenImport{
	{name: "cmd package", match: moduleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory orchestration package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "worker package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "credential delivery activation implementation package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/credentialdelivery")},
	{name: "concrete provider package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
	{name: "concrete runtime package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman")},
	{name: "concrete runtime package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/sshmachine")},
	{name: "concrete runtime package", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm")},
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
			case "io/fs", "os", "os/user", "path/filepath", "plugin", "syscall":
				return true
			default:
				return strings.HasPrefix(importPath, "github.com/spf13/afero") ||
					strings.HasPrefix(importPath, "golang.org/x/sys") ||
					strings.HasPrefix(importPath, "bazil.org/fuse") ||
					strings.HasPrefix(importPath, "github.com/hanwen/go-fuse")
			}
		},
	},
	{
		name: "Docker or Podman package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/docker/docker") ||
				strings.HasPrefix(importPath, "github.com/docker/go-connections") ||
				strings.HasPrefix(importPath, "github.com/containers/podman") ||
				strings.HasPrefix(importPath, "github.com/containers/image") ||
				strings.HasPrefix(importPath, "github.com/containers/storage") ||
				strings.HasPrefix(importPath, "github.com/containers/buildah")
		},
	},
	{
		name: "KVM or microVM SDK package",
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
	{
		name: "live credential provider package",
		match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return strings.Contains(lower, "credentialprovider") ||
				strings.Contains(lower, "credential-provider") ||
				strings.Contains(lower, "providercredential") ||
				strings.Contains(lower, "provider-credential")
		},
	},
	{
		name: "keychain or keyring package",
		match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return strings.Contains(lower, "keychain") ||
				strings.Contains(lower, "keyring")
		},
	},
	{
		name: "Vault package",
		match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return strings.Contains(lower, "hashicorp/vault") ||
				strings.Contains(lower, "/vault")
		},
	},
	{
		name: "1Password package",
		match: func(importPath string) bool {
			lower := strings.ToLower(importPath)
			return strings.Contains(lower, "1password") ||
				strings.Contains(lower, "onepassword")
		},
	},
}

func TestSandboxruntimeImportsStayCommandAgnostic(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", sandboxruntimePackagePath, err)
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
			if message := sandboxruntimeImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSandboxruntimeCredentialDeliveryActivationImportsStayMetadataOnly(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range []string{"credential_delivery.go"} {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := sandboxruntimeCredentialDeliveryActivationImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSandboxruntimeCredentialDeliveryActivationForbiddenImportListCoversLiveSurfaces(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd", want: "cmd package"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory orchestration package"},
		{name: "credential delivery activation implementation", importPath: "github.com/jywlabs/hal/internal/credentialdelivery", want: "credential delivery activation implementation package"},
		{name: "worker", importPath: "github.com/jywlabs/hal/internal/sandboxworker", want: "worker package"},
		{name: "provider", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/daytona", want: "concrete provider package"},
		{name: "rootless Podman runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", want: "concrete runtime package"},
		{name: "microVM runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker", want: "concrete runtime package"},
		{name: "network", importPath: "net", want: "network client or HTTP server package"},
		{name: "HTTP", importPath: "net/http", want: "network client or HTTP server package"},
		{name: "process", importPath: "os/exec", want: "process execution package"},
		{name: "filesystem mutation", importPath: "os", want: "tmpfs, mount, or filesystem mutation package"},
		{name: "path helper", importPath: "path/filepath", want: "tmpfs, mount, or filesystem mutation package"},
		{name: "tmpfs mount", importPath: "golang.org/x/sys/unix", want: "tmpfs, mount, or filesystem mutation package"},
		{name: "HTTP proxy", importPath: "golang.org/x/net/proxy", want: "HTTP proxy implementation package"},
		{name: "SSH agent", importPath: "golang.org/x/crypto/ssh/agent", want: "SSH agent implementation package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "Docker or Podman package"},
		{name: "Docker socket", importPath: "github.com/docker/go-connections/sockets", want: "Docker or Podman package"},
		{name: "Podman", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman package"},
		{name: "Firecracker", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "KVM or microVM SDK package"},
		{name: "cloud SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/secretsmanager", want: "cloud SDK package"},
		{name: "live credential provider", importPath: "github.com/jywlabs/hal/internal/providercredentials", want: "live credential provider package"},
		{name: "keychain", importPath: "github.com/keybase/go-keychain", want: "keychain or keyring package"},
		{name: "keyring", importPath: "github.com/zalando/go-keyring", want: "keychain or keyring package"},
		{name: "Vault", importPath: "github.com/hashicorp/vault/api", want: "Vault package"},
		{name: "1Password", importPath: "github.com/1Password/connect-sdk-go/onepassword", want: "1Password package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := sandboxruntimeCredentialDeliveryActivationImportBoundaryMessage("credential_delivery.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func TestSandboxruntimeCredentialDeliveryActivationAllowsMetadataHelpersOnly(t *testing.T) {
	for _, importPath := range []string{
		"encoding/json",
		"strings",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxruntimeCredentialDeliveryActivationImportBoundaryMessage("credential_delivery.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed activation metadata boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"context",
		"errors",
		"fmt",
		"io",
		"time",
		"github.com/jywlabs/hal/internal/credentialdelivery",
		"github.com/jywlabs/hal/internal/sandbox",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := sandboxruntimeCredentialDeliveryActivationImportBoundaryMessage("credential_delivery.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected activation metadata import path %q", message, importPath)
			}
		})
	}
}

func TestSandboxruntimeNetworkEnforcementProjectionImportsStayMetadataOnly(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range []string{"network_enforcement.go"} {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := sandboxruntimeNetworkEnforcementImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSandboxruntimeNetworkEnforcementForbiddenImportListCoversLiveSurfaces(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd", want: "cmd package"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory package"},
		{name: "worker", importPath: "github.com/jywlabs/hal/internal/sandboxworker", want: "worker package"},
		{name: "microVM runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm", want: "concrete runtime package"},
		{name: "network", importPath: "net", want: "network package"},
		{name: "HTTP", importPath: "net/http", want: "network package"},
		{name: "gRPC", importPath: "google.golang.org/grpc", want: "network package"},
		{name: "process", importPath: "os/exec", want: "process or privilege package"},
		{name: "proxy", importPath: "golang.org/x/net/proxy", want: "proxy implementation package"},
		{name: "firewall", importPath: "github.com/coreos/go-iptables/iptables", want: "firewall implementation package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "Docker or Podman package"},
		{name: "Podman", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman package"},
		{name: "Firecracker", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "microVM backend SDK package"},
		{name: "KVM", importPath: "github.com/example/kvm-driver", want: "microVM backend SDK package"},
		{name: "cloud SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "cloud SDK package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := sandboxruntimeNetworkEnforcementImportBoundaryMessage("network_enforcement.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func TestSandboxruntimeNetworkEnforcementAllowsProjectionContractsOnly(t *testing.T) {
	for _, importPath := range []string{
		"encoding/json",
		"strings",
		"github.com/jywlabs/hal/internal/sandbox",
		sandboxruntimeNetworkEnforcementPackagePath,
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxruntimeNetworkEnforcementImportBoundaryMessage("network_enforcement.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"context",
		"io",
		"os",
		"plugin",
		"github.com/jywlabs/hal/internal/template",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := sandboxruntimeNetworkEnforcementImportBoundaryMessage("network_enforcement.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func TestSandboxruntimeForbiddenImportListCoversCommandCouplingSurfaces(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "factory run record packages", importPath: "github.com/jywlabs/hal/internal/factory"},
		{name: "PRD packages", importPath: "github.com/jywlabs/hal/internal/prd"},
		{name: "command-specific auto code", importPath: "github.com/jywlabs/hal/internal/compound"},
		{name: "command-specific loop code", importPath: "github.com/jywlabs/hal/internal/loop"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := sandboxruntimeForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestSandboxruntimeImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := sandboxruntimeImportBoundaryMessage("types.go", importPath)
	if !strings.Contains(message, sandboxruntimePackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, sandboxruntimePackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func sandboxruntimeCredentialDeliveryActivationImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxruntimeCredentialDeliveryActivationForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxruntimePackagePath, fileName, forbidden.name, importPath)
	}
	if sandboxruntimeCredentialDeliveryActivationAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unsupported dependency %q; keep credential delivery activation metadata on approved standard-library helpers only", sandboxruntimePackagePath, fileName, importPath)
}

func sandboxruntimeCredentialDeliveryActivationForbiddenImportFor(importPath string) *sandboxruntimeForbiddenImport {
	for i := range forbiddenSandboxruntimeCredentialDeliveryActivationImports {
		if forbiddenSandboxruntimeCredentialDeliveryActivationImports[i].match(importPath) {
			return &forbiddenSandboxruntimeCredentialDeliveryActivationImports[i]
		}
	}
	return nil
}

func sandboxruntimeCredentialDeliveryActivationAllowedImport(importPath string) bool {
	switch importPath {
	case "encoding/json",
		"strings":
		return true
	default:
		return false
	}
}

func sandboxruntimeNetworkEnforcementImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxruntimeNetworkEnforcementForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxruntimePackagePath, fileName, forbidden.name, importPath)
	}
	if sandboxruntimeNetworkEnforcementAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unsupported dependency %q; keep network enforcement projection on safe metadata helpers and sandbox contract packages only", sandboxruntimePackagePath, fileName, importPath)
}

func sandboxruntimeNetworkEnforcementForbiddenImportFor(importPath string) *sandboxruntimeForbiddenImport {
	for i := range forbiddenSandboxruntimeNetworkEnforcementImports {
		if forbiddenSandboxruntimeNetworkEnforcementImports[i].match(importPath) {
			return &forbiddenSandboxruntimeNetworkEnforcementImports[i]
		}
	}
	return nil
}

func sandboxruntimeNetworkEnforcementAllowedImport(importPath string) bool {
	switch importPath {
	case "encoding/json",
		"strings",
		"github.com/jywlabs/hal/internal/sandbox",
		sandboxruntimeNetworkEnforcementPackagePath:
		return true
	default:
		return false
	}
}

func sandboxruntimeImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxruntimeForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxruntimePackagePath, fileName, forbidden.name, importPath)
	}
	if !isStandardLibraryImport(importPath) {
		return fmt.Sprintf("package %s file %s imports non-standard-library dependency %q; keep runtime boundary contracts standard-library only", sandboxruntimePackagePath, fileName, importPath)
	}
	return ""
}

func sandboxruntimeForbiddenImportFor(importPath string) *sandboxruntimeForbiddenImport {
	for i := range forbiddenSandboxruntimeImports {
		if forbiddenSandboxruntimeImports[i].match(importPath) {
			return &forbiddenSandboxruntimeImports[i]
		}
	}
	return nil
}

func isStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func moduleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type sandboxruntimeForbiddenImport struct {
	name  string
	match func(string) bool
}
