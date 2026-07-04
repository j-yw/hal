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

const sandboxTemplateAcquisitionPackagePath = "github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"

func TestSandboxTemplateAcquisitionProductionImportsStayFakeSafe(t *testing.T) {
	fset := token.NewFileSet()
	for _, path := range sandboxTemplateAcquisitionProductionFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := sandboxTemplateAcquisitionImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSandboxTemplateAcquisitionProductionSourceOmitsLiveBehaviorMarkers(t *testing.T) {
	for _, path := range sandboxTemplateAcquisitionProductionFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		if message := sandboxTemplateAcquisitionSourceBoundaryMessage(path, string(source)); message != "" {
			t.Fatal(message)
		}
	}
}

func TestSandboxTemplateAcquisitionImportBoundaryCoversProductionFiles(t *testing.T) {
	paths := sandboxTemplateAcquisitionProductionFiles(t)
	if len(paths) == 0 {
		t.Fatal("sandbox template acquisition import-boundary guard found no production files")
	}
	found := map[string]bool{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			t.Fatalf("sandbox template acquisition import-boundary guard should scan production files only, got %s", path)
		}
		found[filepath.Base(path)] = true
	}
	if !found["contracts.go"] {
		t.Fatalf("sandbox template acquisition import-boundary guard files = %#v, want contracts.go covered", paths)
	}
}

func TestSandboxTemplateAcquisitionForbiddenImportListCoversDefaultAcquisitionBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra", want: "command or orchestration package"},
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd", want: "command or orchestration package"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory", want: "command or orchestration package"},
		{name: "compound", importPath: "github.com/jywlabs/hal/internal/compound", want: "command or orchestration package"},
		{name: "sandbox execution", importPath: "github.com/jywlabs/hal/internal/sandboxexec", want: "sandbox execution or startup package"},
		{name: "sandbox execution records", importPath: "github.com/jywlabs/hal/internal/sandboxexecution", want: "sandbox execution or startup package"},
		{name: "worker daemon", importPath: "github.com/jywlabs/hal/internal/sandboxworker", want: "sandbox execution or startup package"},
		{name: "target scheduler", importPath: "github.com/jywlabs/hal/internal/sandboxtarget", want: "sandbox execution or startup package"},
		{name: "rootless Podman runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", want: "concrete runtime package"},
		{name: "SSH-machine runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine", want: "concrete runtime package"},
		{name: "Firecracker runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker", want: "concrete runtime package"},
		{name: "network enforcement runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement", want: "concrete runtime package"},
		{name: "process execution", importPath: "os/exec", want: "process execution or kernel package"},
		{name: "syscall", importPath: "syscall", want: "process execution or kernel package"},
		{name: "x/sys", importPath: "golang.org/x/sys/unix", want: "process execution or kernel package"},
		{name: "network", importPath: "net", want: "live network client package"},
		{name: "HTTP", importPath: "net/http", want: "live network client package"},
		{name: "gRPC", importPath: "google.golang.org/grpc", want: "live network client package"},
		{name: "Docker", importPath: "github.com/docker/docker/client", want: "Docker or Podman client package"},
		{name: "Podman", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman client package"},
		{name: "OCI remote", importPath: "github.com/google/go-containerregistry/pkg/v1/remote", want: "live OCI client package"},
		{name: "ORAS", importPath: "oras.land/oras-go/v2/registry/remote", want: "live OCI client package"},
		{name: "Git client", importPath: "github.com/go-git/go-git/v5", want: "Git client package"},
		{name: "SSH agent", importPath: "golang.org/x/crypto/ssh/agent", want: "credential delivery package"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "KVM or microVM SDK package"},
		{name: "KVM helper", importPath: "github.com/example/kvm-driver", want: "KVM or microVM SDK package"},
		{name: "cloud SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ecr", want: "cloud SDK package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := sandboxTemplateAcquisitionImportBoundaryMessage("contracts.go", tt.importPath)
			if !strings.Contains(message, tt.want) || !strings.Contains(message, tt.importPath) {
				t.Fatalf("boundary message = %q, want %q rejection for %q", message, tt.want, tt.importPath)
			}
		})
	}
}

func TestSandboxTemplateAcquisitionImportBoundaryAllowsFakeSafeParsingAndContracts(t *testing.T) {
	for _, importPath := range []string{
		"archive/tar",
		"bytes",
		"context",
		"crypto/sha256",
		"encoding/hex",
		"encoding/json",
		"errors",
		"fmt",
		"io",
		"io/fs",
		"net/url",
		"os",
		"path/filepath",
		"sort",
		"strconv",
		"strings",
		"time",
		"gopkg.in/yaml.v3",
		"github.com/jywlabs/hal/internal/sandboxtemplate",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxTemplateAcquisitionImportBoundaryMessage("contracts.go", importPath); message != "" {
				t.Fatalf("allowed fake-safe acquisition import rejected: %s", message)
			}
		})
	}
}

func TestSandboxTemplateAcquisitionImportBoundaryAllowsTrustPolicyRuntimeMetadataProjection(t *testing.T) {
	if message := sandboxTemplateAcquisitionImportBoundaryMessage("trust_policy_runtime.go", "github.com/jywlabs/hal/internal/sandboxruntime"); message != "" {
		t.Fatalf("trust policy runtime metadata import rejected: %s", message)
	}
	if message := sandboxTemplateAcquisitionImportBoundaryMessage("trust_policy_runtime.go", "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"); !strings.Contains(message, "concrete runtime package") {
		t.Fatalf("concrete runtime import message = %q, want rejection", message)
	}

	const metadataProjectionSource = `func f() { _ = sandboxruntime.RuntimeTemplateLockMetadata{} }`
	if message := sandboxTemplateAcquisitionSourceBoundaryMessage("trust_policy_runtime.go", metadataProjectionSource); message != "" {
		t.Fatalf("trust policy runtime metadata source rejected: %s", message)
	}
	if message := sandboxTemplateAcquisitionSourceBoundaryMessage("trust_policy_runtime.go", `func f() { _ = sandboxruntime.NewDriver(target) }`); !strings.Contains(message, "sandboxruntime.") {
		t.Fatalf("trust policy runtime startup source message = %q, want sandboxruntime marker rejection", message)
	}
	if message := sandboxTemplateAcquisitionSourceBoundaryMessage("contracts.go", metadataProjectionSource); !strings.Contains(message, "sandboxruntime.") {
		t.Fatalf("default acquisition source marker message = %q, want sandboxruntime marker rejection", message)
	}
}

func TestSandboxTemplateAcquisitionImportBoundaryDistinguishesFakeOCIContractsFromLiveClients(t *testing.T) {
	for _, importPath := range []string{
		"github.com/google/go-containerregistry/pkg/v1/remote",
		"github.com/google/go-containerregistry/pkg/crane",
		"oras.land/oras-go/v2/registry/remote",
		"github.com/containerd/containerd/remotes/docker",
		"github.com/regclient/regclient",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := sandboxTemplateAcquisitionImportBoundaryMessage("oci.go", importPath)
			if !strings.Contains(message, "live OCI client package") || !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want live OCI client rejection for %q", message, importPath)
			}
		})
	}

	const fakeOCISource = `
		type fakeOCIArtifactResolver struct{}
		func (fakeOCIArtifactResolver) ResolveOCIArtifact(context.Context, OCIArtifactResolveRequest) (OCIArtifactResolveResult, error) {
			return OCIArtifactResolveResult{
				TemplateBytes: []byte("fixture"),
				ReferenceDigests: []ReferenceDigestProof{{Field: "runtime.image", Ref: "ghcr.io/acme/go-agent:1.2.0"}},
			}, nil
		}
	`
	if message := sandboxTemplateAcquisitionSourceBoundaryMessage("oci_fixture.go", fakeOCISource); message != "" {
		t.Fatalf("fake OCI fixture source unexpectedly failed source guard: %s", message)
	}
}

func TestSandboxTemplateAcquisitionSourceGuardCoversForbiddenLiveBehaviorMarkers(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{name: "live pull", source: `crane.Pull(ref)`, want: "crane.Pull"},
		{name: "registry call", source: `remote.Get(ref)`, want: "remote.Get"},
		{name: "HTTP client", source: `http.NewRequest("GET", ref, nil)`, want: "http.NewRequest"},
		{name: "network dial", source: `net.Dial("tcp", endpoint)`, want: "net.Dial"},
		{name: "process execution", source: `exec.CommandContext(ctx, "git", "fetch")`, want: "exec.CommandContext"},
		{name: "Docker client", source: `docker.NewClientWithOpts()`, want: "docker.NewClient"},
		{name: "Podman client", source: `bindings.NewConnection(ctx, uri)`, want: "bindings.NewConnection"},
		{name: "Git clone", source: `git.PlainClone(path, false, opts)`, want: "PlainClone"},
		{name: "credential delivery", source: `DeliverCredentials(target, secrets)`, want: "DeliverCredentials"},
		{name: "SSH agent", source: `agent.NewClient(conn)`, want: "agent.NewClient"},
		{name: "sandbox startup", source: `StartSandbox(ctx, request)`, want: "StartSandbox"},
		{name: "runtime startup", source: `sandboxruntime.NewDriver(target)`, want: "sandboxruntime."},
		{name: "microVM startup", source: `firecracker.NewMachine(ctx, cfg)`, want: "firecracker.NewMachine"},
		{name: "KVM device", source: `os.Open("/dev/kvm")`, want: "/dev/kvm"},
		{name: "cloud SDK", source: `secretsmanager.NewFromConfig(cfg)`, want: "secretsmanager.NewFromConfig"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := sandboxTemplateAcquisitionSourceBoundaryMessage("fixture.go", tt.source)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("source boundary message = %q, want marker %q", message, tt.want)
			}
		})
	}
}

func TestSandboxTemplateAcquisitionSourceGuardAllowsFakeOCIInterfacesAndFixtureRefs(t *testing.T) {
	const safeFixtureSource = `
		const fixtureRef = "ghcr.io/acme/templates/codex-go:1.2.0"
		type OCIArtifactResolver interface {
			ResolveOCIArtifact(context.Context, OCIArtifactResolveRequest) (OCIArtifactResolveResult, error)
		}
		type fixtureOCIArtifactResolver struct {
			fixtures map[string]OCIArtifactResolveResult
		}
		var _ = SourceKindOCIArtifact
		var _ = LockReasonResolverUnavailable
	`
	if message := sandboxTemplateAcquisitionSourceBoundaryMessage("fixture.go", safeFixtureSource); message != "" {
		t.Fatalf("safe fake OCI fixture source unexpectedly failed source guard: %s", message)
	}
}

func TestSandboxTemplateAcquisitionBoundaryMessageIncludesPackageAndImport(t *testing.T) {
	const importPath = "github.com/google/go-containerregistry/pkg/v1/remote"
	message := sandboxTemplateAcquisitionImportBoundaryMessage("oci.go", importPath)
	if !strings.Contains(message, sandboxTemplateAcquisitionPackagePath) {
		t.Fatalf("message %q does not include package %q", message, sandboxTemplateAcquisitionPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include import path %q", message, importPath)
	}
}

func sandboxTemplateAcquisitionProductionFiles(t *testing.T) []string {
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

func sandboxTemplateAcquisitionImportBoundaryMessage(fileName, importPath string) string {
	if sandboxTemplateAcquisitionTrustPolicyRuntimeMetadataImport(fileName, importPath) {
		return ""
	}
	if forbidden := sandboxTemplateAcquisitionForbiddenImportFor(importPath); forbidden != nil {
		return sandboxTemplateAcquisitionPackagePath + " file " + fileName + " imports forbidden " + forbidden.name + " " + strconv.Quote(importPath)
	}
	if sandboxTemplateAcquisitionAllowedImport(importPath) {
		return ""
	}
	if strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/") {
		return sandboxTemplateAcquisitionPackagePath + " file " + fileName + " imports unapproved internal package " + strconv.Quote(importPath)
	}
	return sandboxTemplateAcquisitionPackagePath + " file " + fileName + " imports unapproved dependency " + strconv.Quote(importPath) + "; default acquisition must stay fake-safe"
}

func sandboxTemplateAcquisitionTrustPolicyRuntimeMetadataImport(fileName, importPath string) bool {
	return sandboxTemplateAcquisitionTrustPolicyFile(fileName) &&
		importPath == "github.com/jywlabs/hal/internal/sandboxruntime"
}

func sandboxTemplateAcquisitionTrustPolicyFile(fileName string) bool {
	base := filepath.Base(fileName)
	return strings.HasPrefix(base, "trust_policy") && strings.HasSuffix(base, ".go")
}

func sandboxTemplateAcquisitionAllowedImport(importPath string) bool {
	switch importPath {
	case "archive/tar",
		"archive/zip",
		"bytes",
		"context",
		"crypto/sha256",
		"crypto/sha384",
		"crypto/sha512",
		"encoding/hex",
		"encoding/json",
		"errors",
		"fmt",
		"hash",
		"io",
		"io/fs",
		"maps",
		"net/url",
		"os",
		"path",
		"path/filepath",
		"reflect",
		"sort",
		"strconv",
		"strings",
		"time",
		"unicode",
		"unicode/utf8",
		"gopkg.in/yaml.v3",
		"github.com/jywlabs/hal/internal/sandboxtemplate":
		return true
	default:
		return false
	}
}

func sandboxTemplateAcquisitionForbiddenImportFor(importPath string) *sandboxTemplateAcquisitionForbiddenImport {
	for i := range sandboxTemplateAcquisitionForbiddenImports {
		if sandboxTemplateAcquisitionForbiddenImports[i].match(importPath) {
			return &sandboxTemplateAcquisitionForbiddenImports[i]
		}
	}
	return nil
}

var sandboxTemplateAcquisitionForbiddenImports = []sandboxTemplateAcquisitionForbiddenImport{
	{
		name: "command or orchestration package",
		match: func(importPath string) bool {
			return sandboxTemplateAcquisitionModuleImport("github.com/spf13/cobra")(importPath) ||
				sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/cmd")(importPath) ||
				sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/factory")(importPath) ||
				sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/compound")(importPath) ||
				sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/engine")(importPath) ||
				sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/loop")(importPath) ||
				sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/prd")(importPath)
		},
	},
	{
		name: "sandbox execution or startup package",
		match: func(importPath string) bool {
			return sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/sandboxexec")(importPath) ||
				sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/sandboxexecution")(importPath) ||
				sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/sandboxtarget")(importPath) ||
				sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/sandboxworker")(importPath) ||
				sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/sandbox/provider")(importPath)
		},
	},
	{
		name: "concrete runtime package",
		match: func(importPath string) bool {
			return sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/sandboxruntime")(importPath)
		},
	},
	{
		name: "process execution or kernel package",
		match: func(importPath string) bool {
			return importPath == "os/exec" ||
				importPath == "syscall" ||
				importPath == "plugin" ||
				strings.HasPrefix(importPath, "golang.org/x/sys")
		},
	},
	{
		name: "live network client package",
		match: func(importPath string) bool {
			switch importPath {
			case "net", "net/http", "net/rpc", "net/smtp":
				return true
			default:
				return strings.HasPrefix(importPath, "net/http/") ||
					strings.HasPrefix(importPath, "google.golang.org/grpc") ||
					strings.HasPrefix(importPath, "golang.org/x/net/proxy") ||
					strings.HasPrefix(importPath, "github.com/gorilla/websocket") ||
					strings.HasPrefix(importPath, "github.com/hashicorp/go-retryablehttp") ||
					strings.HasPrefix(importPath, "github.com/go-resty/resty")
			}
		},
	},
	{
		name: "Docker or Podman client package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/docker/docker") ||
				strings.HasPrefix(importPath, "github.com/containers/podman") ||
				strings.HasPrefix(importPath, "github.com/containers/image") ||
				strings.HasPrefix(importPath, "github.com/containers/storage") ||
				strings.HasPrefix(importPath, "github.com/containers/buildah")
		},
	},
	{
		name: "live OCI client package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/google/go-containerregistry") ||
				strings.HasPrefix(importPath, "oras.land/") ||
				strings.HasPrefix(importPath, "github.com/containerd/containerd/remotes") ||
				strings.HasPrefix(importPath, "github.com/containerd/containerd/client") ||
				strings.HasPrefix(importPath, "github.com/regclient/regclient")
		},
	},
	{
		name: "Git client package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/go-git/") ||
				strings.HasPrefix(importPath, "github.com/libgit2/") ||
				strings.HasPrefix(importPath, "gopkg.in/src-d/go-git")
		},
	},
	{
		name: "credential delivery package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "golang.org/x/crypto/ssh") ||
				strings.HasPrefix(importPath, "github.com/gliderlabs/ssh") ||
				sandboxTemplateAcquisitionModuleImport("github.com/jywlabs/hal/internal/sandbox")(importPath)
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
				strings.Contains(lower, "microvm") ||
				strings.Contains(lower, "kvm") ||
				strings.Contains(lower, "qemu")
		},
	},
	{
		name: "cloud SDK package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go") ||
				strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go-v2") ||
				strings.HasPrefix(importPath, "github.com/Azure/azure-sdk-for-go") ||
				strings.HasPrefix(importPath, "github.com/digitalocean/godo") ||
				strings.HasPrefix(importPath, "github.com/hetznercloud/hcloud-go") ||
				strings.HasPrefix(importPath, "github.com/linode/linodego") ||
				strings.HasPrefix(importPath, "cloud.google.com/go") ||
				strings.HasPrefix(importPath, "google.golang.org/api")
		},
	},
}

func sandboxTemplateAcquisitionSourceBoundaryMessage(fileName, source string) string {
	for _, marker := range sandboxTemplateAcquisitionForbiddenSourceMarkers() {
		if marker == "sandboxruntime." && sandboxTemplateAcquisitionTrustPolicyFile(fileName) {
			if message := sandboxTemplateAcquisitionTrustPolicyRuntimeSourceBoundaryMessage(fileName, source); message != "" {
				return message
			}
			continue
		}
		if strings.Contains(source, marker) {
			return sandboxTemplateAcquisitionPackagePath + " file " + fileName + " contains forbidden default acquisition live behavior marker " + strconv.Quote(marker)
		}
	}
	return ""
}

func sandboxTemplateAcquisitionTrustPolicyRuntimeSourceBoundaryMessage(fileName, source string) string {
	candidate := source
	for _, selector := range []string{
		"sandboxruntime.RuntimeTemplateLockMetadata",
		"sandboxruntime.RuntimeTemplateLockEntryMetadata",
		"sandboxruntime.RuntimeTemplateTrustPolicyMetadata",
		"sandboxruntime.SanitizeRuntimeTemplateLockMetadata",
	} {
		candidate = strings.ReplaceAll(candidate, selector, "")
	}
	if strings.Contains(candidate, "sandboxruntime.") {
		return sandboxTemplateAcquisitionPackagePath + " file " + fileName + " contains forbidden default acquisition live behavior marker " + strconv.Quote("sandboxruntime.")
	}
	return ""
}

func sandboxTemplateAcquisitionForbiddenSourceMarkers() []string {
	return []string{
		"http.Get",
		"http.Post",
		"http.DefaultClient",
		"http.Client",
		"http.NewRequest",
		"net.Dial",
		"DialContext",
		"grpc.Dial",
		"websocket.DefaultDialer",
		"remote.Get",
		"remote.Image",
		"remote.Index",
		"remote.Head",
		"remote.Write",
		"crane.Pull",
		"crane.Get",
		"oras.Copy",
		"oras.Pull",
		"registry.NewClient",
		"docker.NewClient",
		"NewClientWithOpts",
		"bindings.NewConnection",
		"podman.New",
		"PlainClone",
		"git.Clone",
		"git clone",
		"git fetch",
		"exec.CommandContext",
		"exec.Command",
		"os.StartProcess",
		"syscall.Exec",
		"DeliverCredentials",
		"InjectCredential",
		"InjectCredentials",
		"CredentialInjector",
		"NewInMemorySecretBroker",
		"CreateSession(",
		"SSH_AUTH_SOCK",
		"agent.NewClient",
		"StartSandbox",
		"CreateSandbox",
		"runSandbox(",
		"sandboxruntime.",
		"NewBackend(",
		"StartVM",
		"StartMachine",
		"firecracker.NewMachine",
		"/dev/kvm",
		"KVM_CREATE_VM",
		"qemu.",
		"secretsmanager.NewFromConfig",
		"godo.New",
		"hcloud.New",
		"compute.New",
		"storage.NewClient",
	}
}

func sandboxTemplateAcquisitionModuleImport(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type sandboxTemplateAcquisitionForbiddenImport struct {
	name  string
	match func(string) bool
}
