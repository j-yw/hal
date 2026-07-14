package factory

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

const secretBrokerPackagePath = "github.com/jywlabs/hal/internal/factory"

var forbiddenSecretBrokerImports = []secretBrokerForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: secretBrokerModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{
		name: "factory orchestration subpackage",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, secretBrokerPackagePath+"/")
		},
	},
	{name: "engine package", match: secretBrokerModuleImportMatcher("github.com/jywlabs/hal/internal/engine")},
	{name: "loop package", match: secretBrokerModuleImportMatcher("github.com/jywlabs/hal/internal/loop")},
	{name: "PRD package", match: secretBrokerModuleImportMatcher("github.com/jywlabs/hal/internal/prd")},
	{name: "compound package", match: secretBrokerModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "worker client package", match: secretBrokerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "sandbox execution package", match: secretBrokerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "sandbox execution record package", match: secretBrokerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "sandbox target package", match: secretBrokerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxtarget")},
	{name: "sandbox workspace package", match: secretBrokerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworkspace")},
	{name: "concrete provider adapter package", match: secretBrokerModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
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
			case "net", "net/http", "net/http/httputil", "net/rpc", "net/smtp":
				return true
			default:
				return strings.HasPrefix(importPath, "net/http/") ||
					strings.HasPrefix(importPath, "google.golang.org/grpc")
			}
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
		name: "filesystem tmpfs writer package",
		match: func(importPath string) bool {
			switch importPath {
			case "io/fs", "os", "os/exec", "path/filepath":
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

func TestSecretBrokerImportBoundaries(t *testing.T) {
	paths := secretBrokerBoundaryFiles(t)

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
			if message := secretBrokerImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSecretBrokerForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "factory orchestration subpackages", importPath: "github.com/jywlabs/hal/internal/factory/bootstrap"},
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
		{name: "standard HTTP proxy client", importPath: "net/http/httputil"},
		{name: "external network client", importPath: "google.golang.org/grpc"},
		{name: "HTTP proxy implementation", importPath: "golang.org/x/net/proxy"},
		{name: "third-party HTTP proxy implementation", importPath: "github.com/elazarl/goproxy"},
		{name: "SSH agent implementation", importPath: "golang.org/x/crypto/ssh/agent"},
		{name: "SSH implementation", importPath: "golang.org/x/crypto/ssh"},
		{name: "filesystem writer", importPath: "os"},
		{name: "filesystem path package", importPath: "path/filepath"},
		{name: "filesystem abstraction", importPath: "github.com/spf13/afero"},
		{name: "Docker client", importPath: "github.com/docker/docker/client"},
		{name: "Podman bindings", importPath: "github.com/containers/podman/v5/pkg/bindings"},
		{name: "DigitalOcean SDK", importPath: "github.com/digitalocean/godo"},
		{name: "AWS SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/secretsmanager"},
		{name: "Google Cloud SDK", importPath: "cloud.google.com/go/secretmanager/apiv1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := secretBrokerForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestSecretBrokerImportBoundaryAllowsSecretMetadataDependencies(t *testing.T) {
	for _, importPath := range []string{
		"encoding/json",
		"errors",
		"fmt",
		"net/url",
		"reflect",
		"sort",
		"strconv",
		"strings",
		"sync",
		"github.com/jywlabs/hal/internal/sandbox",
		"github.com/jywlabs/hal/internal/verify",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := secretBrokerImportBoundaryMessage("secret_redactor.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"github.com/jywlabs/hal/internal/template",
		"gopkg.in/yaml.v3",
		"github.com/jywlabs/hal/internal/sandboxruntime",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := secretBrokerImportBoundaryMessage("secret_broker.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func TestSecretBrokerImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := secretBrokerImportBoundaryMessage("secret_broker.go", importPath)
	if !strings.Contains(message, secretBrokerPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, secretBrokerPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func secretBrokerBoundaryFiles(t *testing.T) []string {
	t.Helper()

	paths, err := filepath.Glob("secret*.go")
	if err != nil {
		t.Fatalf("Glob(secret*.go) error: %v", err)
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
		t.Fatal("no secret broker files matched import-boundary guard")
	}
	return out
}

func secretBrokerImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := secretBrokerForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", secretBrokerPackagePath, fileName, forbidden.name, importPath)
	}
	if secretBrokerAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports unapproved dependency %q; secret broker contracts and redaction helpers must remain metadata-only and fake-only", secretBrokerPackagePath, fileName, importPath)
}

func secretBrokerForbiddenImportFor(importPath string) *secretBrokerForbiddenImport {
	for i := range forbiddenSecretBrokerImports {
		if forbiddenSecretBrokerImports[i].match(importPath) {
			return &forbiddenSecretBrokerImports[i]
		}
	}
	return nil
}

func secretBrokerAllowedImport(importPath string) bool {
	if secretBrokerIsStandardLibraryImport(importPath) {
		return true
	}
	switch importPath {
	case "github.com/jywlabs/hal/internal/sandbox",
		"github.com/jywlabs/hal/internal/verify":
		return true
	default:
		return false
	}
}

func secretBrokerIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func secretBrokerModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type secretBrokerForbiddenImport struct {
	name  string
	match func(string) bool
}
