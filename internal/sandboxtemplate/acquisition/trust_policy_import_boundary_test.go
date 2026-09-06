package acquisition

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTrustPolicyProductionImportsStayDataOnly(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range trustPolicyProductionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := trustPolicyImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestTrustPolicyImportBoundaryCoversOnlyPolicyProductionFiles(t *testing.T) {
	paths := trustPolicyProductionFiles(t)
	if len(paths) == 0 {
		t.Fatal("trust policy import-boundary guard found no production files")
	}
	found := map[string]bool{}
	for _, path := range paths {
		base := filepath.Base(path)
		if strings.HasSuffix(base, "_test.go") {
			t.Fatalf("trust policy import-boundary guard should scan production files only, got %s", path)
		}
		if !strings.HasPrefix(base, "trust_policy") || !strings.HasSuffix(base, ".go") {
			t.Fatalf("trust policy import-boundary guard should scan only trust_policy*.go files, got %s", path)
		}
		found[base] = true
	}
	if !found["trust_policy.go"] {
		t.Fatalf("trust policy import-boundary guard files = %#v, want trust_policy.go covered", paths)
	}
}

func TestTrustPolicyForbiddenImportListCoversArchitectureBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra", want: "command package"},
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd", want: "command package"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory", want: "factory orchestration package"},
		{name: "compound", importPath: "github.com/jywlabs/hal/internal/compound", want: "factory orchestration package"},
		{name: "engine", importPath: "github.com/jywlabs/hal/internal/engine", want: "factory orchestration package"},
		{name: "sandbox exec", importPath: "github.com/jywlabs/hal/internal/sandboxexec", want: "runtime startup package"},
		{name: "sandbox execution", importPath: "github.com/jywlabs/hal/internal/sandboxexecution", want: "runtime startup package"},
		{name: "sandbox target", importPath: "github.com/jywlabs/hal/internal/sandboxtarget", want: "runtime startup package"},
		{name: "sandbox worker", importPath: "github.com/jywlabs/hal/internal/sandboxworker", want: "runtime startup package"},
		{name: "rootless Podman runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", want: "concrete runtime driver package"},
		{name: "SSH-machine runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine", want: "concrete runtime driver package"},
		{name: "microVM runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm", want: "concrete runtime driver package"},
		{name: "Firecracker runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker", want: "concrete runtime driver package"},
		{name: "Firecracker host runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost", want: "concrete runtime driver package"},
		{name: "credential delivery package", importPath: "github.com/jywlabs/hal/internal/credentialdelivery", want: "credential delivery package"},
		{name: "SSH agent", importPath: "golang.org/x/crypto/ssh/agent", want: "credential delivery package"},
		{name: "network enforcement package", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement", want: "network enforcement package"},
		{name: "net", importPath: "net", want: "network enforcement package"},
		{name: "HTTP", importPath: "net/http", want: "network enforcement package"},
		{name: "gRPC", importPath: "google.golang.org/grpc", want: "network enforcement package"},
		{name: "process execution", importPath: "os/exec", want: "process or runtime startup package"},
		{name: "syscall", importPath: "syscall", want: "process or runtime startup package"},
		{name: "plugin", importPath: "plugin", want: "process or runtime startup package"},
		{name: "x/sys", importPath: "golang.org/x/sys/unix", want: "process or runtime startup package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "container runtime client package"},
		{name: "Podman", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "container runtime client package"},
		{name: "OCI remote", importPath: "github.com/google/go-containerregistry/pkg/v1/remote", want: "live registry client package"},
		{name: "crane", importPath: "github.com/google/go-containerregistry/pkg/crane", want: "live registry client package"},
		{name: "ORAS", importPath: "oras.land/oras-go/v2/registry/remote", want: "live registry client package"},
		{name: "containerd remotes", importPath: "github.com/containerd/containerd/remotes/docker", want: "live registry client package"},
		{name: "regclient", importPath: "github.com/regclient/regclient", want: "live registry client package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := trustPolicyImportBoundaryMessage("trust_policy.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func TestTrustPolicyImportBoundaryAllowsOnlyDataContractDependencies(t *testing.T) {
	for _, importPath := range []string{
		"encoding/json",
		"errors",
		"fmt",
		"sort",
		"strconv",
		"strings",
		"time",
		"github.com/jywlabs/hal/internal/sandboxtemplate",
		"github.com/jywlabs/hal/internal/sandboxruntime",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := trustPolicyImportBoundaryMessage("trust_policy.go", importPath); message != "" {
				t.Fatalf("allowed trust policy import rejected: %s", message)
			}
		})
	}
}

func TestTrustPolicyImportBoundaryRejectsUnapprovedInternalAndThirdPartyPackages(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "sandbox root package", importPath: "github.com/jywlabs/hal/internal/sandbox", want: "unapproved internal package"},
		{name: "microvm assets", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets", want: "concrete runtime driver package"},
		{name: "YAML", importPath: "gopkg.in/yaml.v3", want: "unapproved dependency"},
		{name: "testify", importPath: "github.com/stretchr/testify/require", want: "unapproved dependency"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := trustPolicyImportBoundaryMessage("trust_policy.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func trustPolicyProductionFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.) error = %v", err)
	}
	var paths []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "trust_policy") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		paths = append(paths, name)
	}
	return paths
}

func trustPolicyImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := trustPolicyForbiddenImportFor(importPath); forbidden != nil {
		return sandboxTemplateAcquisitionPackagePath + " file " + fileName + " imports forbidden " + forbidden.name + " " + strconv.Quote(importPath)
	}
	if trustPolicyAllowedImport(importPath) {
		return ""
	}
	if strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/") {
		return sandboxTemplateAcquisitionPackagePath + " file " + fileName + " imports unapproved internal package " + strconv.Quote(importPath)
	}
	return sandboxTemplateAcquisitionPackagePath + " file " + fileName + " imports unapproved dependency " + strconv.Quote(importPath) + "; trust policy files must stay data-only"
}

func trustPolicyAllowedImport(importPath string) bool {
	switch importPath {
	case "github.com/jywlabs/hal/internal/sandboxtemplate",
		"github.com/jywlabs/hal/internal/sandboxruntime":
		return true
	default:
		return trustPolicyStandardLibraryImport(importPath)
	}
}

func trustPolicyStandardLibraryImport(importPath string) bool {
	root, _, _ := strings.Cut(importPath, "/")
	return !strings.Contains(root, ".")
}

func trustPolicyForbiddenImportFor(importPath string) *trustPolicyForbiddenImport {
	for i := range trustPolicyForbiddenImports {
		if trustPolicyForbiddenImports[i].match(importPath) {
			return &trustPolicyForbiddenImports[i]
		}
	}
	return nil
}

var trustPolicyForbiddenImports = []trustPolicyForbiddenImport{
	{
		name: "command package",
		match: func(importPath string) bool {
			return trustPolicyModuleImport("github.com/spf13/cobra")(importPath) ||
				trustPolicyModuleImport("github.com/jywlabs/hal/cmd")(importPath)
		},
	},
	{
		name: "factory orchestration package",
		match: func(importPath string) bool {
			return trustPolicyModuleImport("github.com/jywlabs/hal/internal/factory")(importPath) ||
				trustPolicyModuleImport("github.com/jywlabs/hal/internal/compound")(importPath) ||
				trustPolicyModuleImport("github.com/jywlabs/hal/internal/engine")(importPath) ||
				trustPolicyModuleImport("github.com/jywlabs/hal/internal/loop")(importPath) ||
				trustPolicyModuleImport("github.com/jywlabs/hal/internal/prd")(importPath)
		},
	},
	{
		name: "runtime startup package",
		match: func(importPath string) bool {
			return trustPolicyModuleImport("github.com/jywlabs/hal/internal/sandboxexec")(importPath) ||
				trustPolicyModuleImport("github.com/jywlabs/hal/internal/sandboxexecution")(importPath) ||
				trustPolicyModuleImport("github.com/jywlabs/hal/internal/sandboxtarget")(importPath) ||
				trustPolicyModuleImport("github.com/jywlabs/hal/internal/sandboxworker")(importPath) ||
				trustPolicyModuleImport("github.com/jywlabs/hal/internal/sandbox/provider")(importPath)
		},
	},
	{
		name: "concrete runtime driver package",
		match: func(importPath string) bool {
			return trustPolicyModuleImport("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman")(importPath) ||
				trustPolicyModuleImport("github.com/jywlabs/hal/internal/sandboxruntime/sshmachine")(importPath) ||
				trustPolicyModuleImport("github.com/jywlabs/hal/internal/sandboxruntime/microvm")(importPath)
		},
	},
	{
		name: "credential delivery package",
		match: func(importPath string) bool {
			return trustPolicyModuleImport("github.com/jywlabs/hal/internal/credentialdelivery")(importPath) ||
				strings.HasPrefix(importPath, "golang.org/x/crypto/ssh") ||
				strings.HasPrefix(importPath, "github.com/gliderlabs/ssh")
		},
	},
	{
		name: "network enforcement package",
		match: func(importPath string) bool {
			switch importPath {
			case "net", "net/http", "net/rpc", "net/smtp":
				return true
			default:
				return trustPolicyModuleImport("github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement")(importPath) ||
					strings.HasPrefix(importPath, "net/http/") ||
					strings.HasPrefix(importPath, "google.golang.org/grpc") ||
					strings.HasPrefix(importPath, "golang.org/x/net") ||
					strings.HasPrefix(importPath, "github.com/coreos/go-iptables") ||
					strings.HasPrefix(importPath, "github.com/vishvananda/netlink")
			}
		},
	},
	{
		name: "process or runtime startup package",
		match: func(importPath string) bool {
			return importPath == "os/exec" ||
				importPath == "syscall" ||
				importPath == "plugin" ||
				strings.HasPrefix(importPath, "golang.org/x/sys")
		},
	},
	{
		name: "container runtime client package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/docker/docker") ||
				strings.HasPrefix(importPath, "github.com/containers/podman") ||
				strings.HasPrefix(importPath, "github.com/containers/image") ||
				strings.HasPrefix(importPath, "github.com/containers/storage") ||
				strings.HasPrefix(importPath, "github.com/containers/buildah")
		},
	},
	{
		name: "live registry client package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/google/go-containerregistry") ||
				strings.HasPrefix(importPath, "oras.land/") ||
				strings.HasPrefix(importPath, "github.com/containerd/containerd/remotes") ||
				strings.HasPrefix(importPath, "github.com/containerd/containerd/client") ||
				strings.HasPrefix(importPath, "github.com/regclient/regclient")
		},
	},
}

func trustPolicyModuleImport(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type trustPolicyForbiddenImport struct {
	name  string
	match func(string) bool
}
