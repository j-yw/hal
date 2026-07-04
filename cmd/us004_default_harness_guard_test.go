package cmd

import (
	"go/ast"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/livegate"
)

func TestUS004MicroVMLiveE2EActivationIsDisabledWithoutLiveBuildTags(t *testing.T) {
	input := livegate.GateEvaluationInput{
		Gate:                  livegate.MicroVME2ELiveGate(),
		PresentEnvVars:        append(livegate.MicroVME2ERequiredEnvVars(), livegate.CredentialDeliveryLiveModeEnvVars()...),
		AvailableCapabilities: livegate.MicroVME2ERequiredCapabilities(),
	}
	result := livegate.EvaluateGate(input)
	if result.CanRunLiveAction() {
		t.Fatalf("default live E2E gate allowed live action without live build tags: %#v", result)
	}
	if result.SkipReason != livegate.SkipReasonMissingBuildTag {
		t.Fatalf("default live E2E gate skip reason = %q, want %q", result.SkipReason, livegate.SkipReasonMissingBuildTag)
	}
	us004RequireMissingBuildTags(t, result, livegate.MicroVME2ERequiredBuildTags())

	input.EnabledBuildTags = []livegate.BuildTagName{livegate.BuildTagMicroVME2ELive}
	result = livegate.EvaluateGate(input)
	if result.CanRunLiveAction() {
		t.Fatalf("live E2E gate allowed live action with only the dedicated E2E tag: %#v", result)
	}
	us004RequireMissingBuildTags(t, result, []livegate.BuildTagName{
		livegate.BuildTagFirecrackerLive,
		livegate.BuildTagNetworkEnforcementLive,
		livegate.BuildTagCredentialDeliveryLive,
	})
}

func TestUS004MicroVMLiveE2EHarnessDoesNotRequireLiveInfrastructureByDefault(t *testing.T) {
	for _, path := range us004MicroVMLiveE2EHarnessFiles(t) {
		source := phase50ReadFile(t, path)
		file := phase50ParseGoSource(t, path, source)
		if message := us004LiveHarnessInfrastructureBoundaryMessage(path, file, source); message != "" {
			t.Fatal(message)
		}
	}
}

func TestUS004PureLiveE2EPackagesDoNotReadCredentialEnvironmentValues(t *testing.T) {
	for _, path := range us004PureLiveE2EProductionFiles(t) {
		source := phase50ReadFile(t, path)
		file := phase50ParseGoSource(t, path, source)
		if message := us004CredentialEnvironmentReadBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
	}
}

func TestUS004PureCredentialEnvironmentReadGuardRejectsFixtures(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "getenv credential",
			source: `package fixture; import "os"; func test() { _ = os.Getenv("GITHUB_TOKEN") }`,
			want:   "os.Getenv",
		},
		{
			name:   "lookup credential",
			source: `package fixture; import "os"; func test() { _, _ = os.LookupEnv("NPM_TOKEN") }`,
			want:   "os.LookupEnv",
		},
		{
			name:   "enumerate environment",
			source: `package fixture; import "os"; func test() { _ = os.Environ() }`,
			want:   "os.Environ",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file := phase50ParseGoSource(t, tt.name+".go", tt.source)
			message := us004CredentialEnvironmentReadBoundaryMessage(tt.name+".go", file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("credential environment guard message = %q, want marker %q", message, tt.want)
			}
			phase50AssertGuardMessageRedactionSafe(t, message)
		})
	}
}

func us004RequireMissingBuildTags(t *testing.T, result livegate.GatePreflightResult, want []livegate.BuildTagName) {
	t.Helper()
	missing := map[livegate.BuildTagName]bool{}
	for _, requirement := range result.Requirements {
		if requirement.Status == livegate.RequirementStatusMissing && requirement.ReasonCode == livegate.SkipReasonMissingBuildTag {
			missing[requirement.BuildTag] = true
		}
	}
	for _, tag := range want {
		if !missing[tag] {
			t.Fatalf("default live E2E gate missing build tags = %#v, want %q missing", missing, tag)
		}
	}
}

func us004MicroVMLiveE2EHarnessFiles(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "internal", "sandboxruntime", "microvm", "live_e2e*_test.go"))
	if err != nil {
		t.Fatalf("Glob(live_e2e*_test.go) error: %v", err)
	}
	paths = us004ExcludeMicroVMLiveE2EExecutionPath(paths)
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("US-004 default harness guard matched no live E2E harness files")
	}
	return paths
}

func us004ExcludeMicroVMLiveE2EExecutionPath(paths []string) []string {
	out := paths[:0]
	for _, path := range paths {
		if filepath.Base(path) == "live_e2e_execution_test.go" {
			continue
		}
		out = append(out, path)
	}
	return out
}

func us004LiveHarnessInfrastructureBoundaryMessage(fileName string, file *ast.File, source string) string {
	for _, imported := range file.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return us004DefaultHarnessGuardMessage(fileName, "unreadable import", "import")
		}
		if forbidden := us004ForbiddenLiveInfrastructureImport(importPath); forbidden != "" {
			return us004DefaultHarnessGuardMessage(fileName, forbidden, phase50ImportMarker(importPath))
		}
	}

	for _, marker := range us004ForbiddenLiveInfrastructureSourceMarkers() {
		if strings.Contains(source, marker.token) {
			return us004DefaultHarnessGuardMessage(fileName, marker.label, marker.safeMarker)
		}
	}

	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := phase50CallSelectorName(call.Fun)
		switch {
		case phase50CallAccessesKVM(selector) && phase50CallHasLiteralArg(call, "/dev/kvm"):
			message = us004DefaultHarnessGuardMessage(fileName, "KVM prerequisite", "KVM device")
		case us004CallRequiresRoot(selector):
			message = us004DefaultHarnessGuardMessage(fileName, "root privilege prerequisite", "root privilege")
		case us004CallLaunchesLiveInfrastructure(selector):
			message = us004DefaultHarnessGuardMessage(fileName, "live process prerequisite", "live process")
		case us004CallOpensRealNetwork(selector):
			message = us004DefaultHarnessGuardMessage(fileName, "real network prerequisite", "network")
		}
		return message == ""
	})
	return message
}

func us004ForbiddenLiveInfrastructureImport(importPath string) string {
	switch {
	case importPath == "os/exec" || importPath == "syscall" || strings.HasPrefix(importPath, "golang.org/x/sys"):
		return "process or root privilege import"
	case importPath == "net" || importPath == "net/http" || strings.HasPrefix(importPath, "net/http/") || strings.HasPrefix(importPath, "google.golang.org/grpc"):
		return "real network import"
	case importPath == "os/user":
		return "root privilege import"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"):
		return "Firecracker implementation import"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"):
		return "network enforcement implementation import"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/credentialdelivery"):
		return "credential delivery implementation import"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxworker"):
		return "sandboxd or worker implementation import"
	case strings.HasPrefix(importPath, "github.com/docker/docker") || strings.HasPrefix(importPath, "github.com/containers/podman"):
		return "Docker or Podman API import"
	case strings.HasPrefix(importPath, "github.com/google/go-containerregistry") ||
		strings.HasPrefix(importPath, "oras.land/") ||
		strings.HasPrefix(importPath, "github.com/containerd/containerd/remotes") ||
		strings.HasPrefix(importPath, "github.com/regclient/regclient"):
		return "registry client import"
	case strings.HasPrefix(importPath, "github.com/firecracker-microvm") || strings.Contains(strings.ToLower(importPath), "kvm"):
		return "Firecracker or KVM import"
	case strings.HasPrefix(importPath, "github.com/digitalocean/godo"),
		strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go"),
		strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go-v2"),
		strings.HasPrefix(importPath, "github.com/Azure/azure-sdk-for-go"),
		strings.HasPrefix(importPath, "github.com/hetznercloud/hcloud-go"),
		strings.HasPrefix(importPath, "cloud.google.com/go"),
		strings.HasPrefix(importPath, "google.golang.org/api"):
		return "cloud provider import"
	default:
		return ""
	}
}

func us004ForbiddenLiveInfrastructureSourceMarkers() []struct {
	token      string
	label      string
	safeMarker string
} {
	return []struct {
		token      string
		label      string
		safeMarker string
	}{
		{token: "NewOSExecProcessRunner", label: "Firecracker process runner prerequisite", safeMarker: "process runner"},
		{token: "firecracker.NewMachine", label: "Firecracker SDK prerequisite", safeMarker: "firecracker SDK"},
		{token: "docker.NewClient", label: "Docker API prerequisite", safeMarker: "docker API"},
		{token: "bindings.NewConnection", label: "Podman API prerequisite", safeMarker: "podman API"},
		{token: "crane.Pull", label: "registry client prerequisite", safeMarker: "registry client"},
		{token: "remote.Get", label: "registry client prerequisite", safeMarker: "registry client"},
		{token: "secretsmanager.NewFromConfig", label: "cloud provider prerequisite", safeMarker: "cloud provider"},
		{token: "godo.New", label: "cloud provider prerequisite", safeMarker: "cloud provider"},
		{token: "hcloud.New", label: "cloud provider prerequisite", safeMarker: "cloud provider"},
		{token: "sk-live-", label: "real secret prerequisite", safeMarker: "secret value"},
		{token: "ghp_", label: "real secret prerequisite", safeMarker: "secret value"},
	}
}

func us004CallRequiresRoot(selector string) bool {
	switch selector {
	case "os.Geteuid", "os.Getuid", "user.Current":
		return true
	default:
		return false
	}
}

func us004CallLaunchesLiveInfrastructure(selector string) bool {
	switch selector {
	case "exec.Command", "exec.CommandContext", "exec.LookPath", "os.StartProcess", "syscall.Exec":
		return true
	default:
		return false
	}
}

func us004CallOpensRealNetwork(selector string) bool {
	switch selector {
	case "net.Listen", "net.ListenPacket", "net.Dial", "net.DialTimeout",
		"http.Get", "http.Head", "http.Post", "http.PostForm",
		"http.ListenAndServe", "http.ListenAndServeTLS":
		return true
	default:
		return false
	}
}

func us004PureLiveE2EProductionFiles(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, root := range []string{
		filepath.Join("..", "internal", "livegate"),
		filepath.Join("..", "internal", "credentialdelivery"),
		filepath.Join("..", "internal", "sandboxtemplate"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets"),
	} {
		paths = append(paths, us004ProductionGoFilesUnder(t, root)...)
	}
	for _, path := range []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "live_e2e_metadata.go"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "live_e2e_diagnostics.go"),
	} {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("US-004 pure package guard matched no production files")
	}
	return paths
}

func us004ProductionGoFilesUnder(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkDir(%s) error: %v", root, err)
	}
	return paths
}

func us004CredentialEnvironmentReadBoundaryMessage(fileName string, file *ast.File) string {
	var message string
	ast.Inspect(file, func(node ast.Node) bool {
		if message != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector := phase50CallSelectorName(call.Fun)
		switch selector {
		case "os.Getenv", "os.LookupEnv", "os.Environ":
			message = us004DefaultHarnessGuardMessage(fileName, "process environment credential read", selector)
		}
		return message == ""
	})
	return message
}

func us004DefaultHarnessGuardMessage(fileName, category, marker string) string {
	return "US-004 default live E2E harness guard: " + phase50SafeDisplayPath(fileName) + " contains " + category + " marker " + strconv.Quote(marker)
}
