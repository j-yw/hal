package sandboxworker

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

const sandboxworkerPackagePath = "github.com/jywlabs/hal/internal/sandboxworker"

var forbiddenSandboxworkerImports = []sandboxworkerForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{
		name:  "cmd package",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/cmd"),
	},
	{
		name:  "factory run record package",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/factory"),
	},
	{
		name:  "PRD package",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/prd"),
	},
	{
		name:  "command-specific auto code",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/compound"),
	},
	{
		name:  "command-specific loop code",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/loop"),
	},
	{
		name:  "durable sandbox state package",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox"),
	},
	{
		name:  "concrete SSH-machine runtime adapter",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"),
	},
	{
		name:  "concrete rootless Podman runtime adapter",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"),
	},
}

var forbiddenSandboxworkerCredentialDeliveryDefaultImports = []sandboxworkerForbiddenImport{
	{name: "cmd package", match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory orchestration package", match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "credential delivery activation implementation package", match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/credentialdelivery")},
	{name: "concrete provider package", match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
	{name: "durable sandbox state package", match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox")},
	{name: "concrete runtime package", match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman")},
	{name: "concrete runtime package", match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/sshmachine")},
	{name: "concrete runtime package", match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm")},
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

func TestSandboxworkerImportsStayCommandAgnostic(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", sandboxworkerPackagePath, err)
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
			if message := sandboxworkerImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSandboxworkerCredentialDeliveryDefaultMetadataImportsStayFakeOnly(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range []string{"types.go"} {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := sandboxworkerCredentialDeliveryDefaultImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSandboxworkerCredentialDeliveryDefaultForbiddenImportListCoversLiveSurfaces(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd", want: "cmd package"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory orchestration package"},
		{name: "credential delivery activation implementation", importPath: "github.com/jywlabs/hal/internal/credentialdelivery", want: "credential delivery activation implementation package"},
		{name: "sandbox state", importPath: "github.com/jywlabs/hal/internal/sandbox", want: "durable sandbox state package"},
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
			message := sandboxworkerCredentialDeliveryDefaultImportBoundaryMessage("types.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func TestSandboxworkerCredentialDeliveryDefaultAllowsRuntimeContractsOnly(t *testing.T) {
	for _, importPath := range []string{
		"encoding/json",
		"fmt",
		"strings",
		"github.com/jywlabs/hal/internal/sandboxruntime",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxworkerCredentialDeliveryDefaultImportBoundaryMessage("types.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed credential delivery default boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"context",
		"errors",
		"io",
		"time",
		"github.com/jywlabs/hal/internal/credentialdelivery",
		"github.com/jywlabs/hal/internal/sandboxexecution",
		"github.com/jywlabs/hal/internal/sandboxtarget",
		"github.com/jywlabs/hal/internal/template",
		"gopkg.in/yaml.v3",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := sandboxworkerCredentialDeliveryDefaultImportBoundaryMessage("types.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected credential delivery default import path %q", message, importPath)
			}
		})
	}
}

func TestSandboxworkerForbiddenImportListCoversCommandCouplingSurfaces(t *testing.T) {
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
		{name: "durable sandbox state packages", importPath: "github.com/jywlabs/hal/internal/sandbox"},
		{name: "concrete SSH-machine runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"},
		{name: "concrete rootless Podman runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := sandboxworkerForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestSandboxworkerImportBoundaryAllowsRuntimeContractsOnly(t *testing.T) {
	for _, importPath := range []string{
		"fmt",
		"context",
		"github.com/jywlabs/hal/internal/sandboxruntime",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxworkerImportBoundaryMessage("types.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"github.com/jywlabs/hal/internal/sandbox",
		"github.com/jywlabs/hal/internal/sandboxexecution",
		"github.com/jywlabs/hal/internal/sandboxtarget",
		"github.com/jywlabs/hal/internal/template",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxworkerImportBoundaryMessage("types.go", importPath); !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want unapproved internal package %q", message, importPath)
			}
		})
	}
}

func TestSandboxworkerImportBoundaryRejectsExternalRuntimeProviders(t *testing.T) {
	for _, importPath := range []string{
		"github.com/docker/docker/client",
		"github.com/containers/podman/v5/pkg/bindings",
		"github.com/digitalocean/godo",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := sandboxworkerImportBoundaryMessage("types.go", importPath)
			if !strings.Contains(message, "non-standard-library dependency") || !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejection for external provider import %q", message, importPath)
			}
		})
	}
}

func TestSandboxworkerImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := sandboxworkerImportBoundaryMessage("types.go", importPath)
	if !strings.Contains(message, sandboxworkerPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, sandboxworkerPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func sandboxworkerCredentialDeliveryDefaultImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxworkerCredentialDeliveryDefaultForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxworkerPackagePath, fileName, forbidden.name, importPath)
	}
	if sandboxworkerCredentialDeliveryDefaultAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unsupported dependency %q; keep worker credential delivery defaults on approved metadata helpers and root runtime contracts only", sandboxworkerPackagePath, fileName, importPath)
}

func sandboxworkerCredentialDeliveryDefaultForbiddenImportFor(importPath string) *sandboxworkerForbiddenImport {
	for i := range forbiddenSandboxworkerCredentialDeliveryDefaultImports {
		if forbiddenSandboxworkerCredentialDeliveryDefaultImports[i].match(importPath) {
			return &forbiddenSandboxworkerCredentialDeliveryDefaultImports[i]
		}
	}
	return nil
}

func sandboxworkerCredentialDeliveryDefaultAllowedImport(importPath string) bool {
	switch importPath {
	case "encoding/json",
		"fmt",
		"strings",
		"github.com/jywlabs/hal/internal/sandboxruntime":
		return true
	default:
		return false
	}
}

func sandboxworkerImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxworkerForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxworkerPackagePath, fileName, forbidden.name, importPath)
	}
	if sandboxworkerAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports non-standard-library dependency %q; worker code may only depend on standard library packages and root sandboxruntime contracts", sandboxworkerPackagePath, fileName, importPath)
}

func sandboxworkerForbiddenImportFor(importPath string) *sandboxworkerForbiddenImport {
	for i := range forbiddenSandboxworkerImports {
		if forbiddenSandboxworkerImports[i].match(importPath) {
			return &forbiddenSandboxworkerImports[i]
		}
	}
	return nil
}

func sandboxworkerAllowedImport(importPath string) bool {
	return sandboxworkerIsStandardLibraryImport(importPath) ||
		importPath == "github.com/jywlabs/hal/internal/sandboxruntime"
}

func sandboxworkerIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func sandboxworkerModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type sandboxworkerForbiddenImport struct {
	name  string
	match func(string) bool
}
