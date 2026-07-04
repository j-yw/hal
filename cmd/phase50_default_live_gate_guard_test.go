package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	phase50WorkerIntegrationEnvPrefix = "HAL_WORKER_" + "INTEGRATION_"
	phase50PodmanEnvPrefix            = "HAL_PODMAN_"
)

func TestPhase50DefaultGoTestSuiteDoesNotRequireLivePrerequisites(t *testing.T) {
	for _, path := range phase50RepositoryGoFiles(t) {
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}
		source := phase50ReadFile(t, path)
		if phase50HasOptionalLiveBuildTag(source) {
			continue
		}
		file := phase50ParseGoFile(t, path, source)
		if message := phase50DefaultLivePrerequisiteBoundaryMessage(path, file); message != "" {
			t.Fatal(message)
		}
	}
}

func TestPhase50OptionalLiveMarkersStayBehindBuildTagsOrApprovedFiles(t *testing.T) {
	for _, path := range phase50RepositoryGoFiles(t) {
		source := phase50ReadFile(t, path)
		marker := phase50FirstLiveOnlyMarker(source)
		if marker == nil {
			continue
		}
		if phase50HasOptionalLiveBuildTag(source) {
			continue
		}
		rel := phase50RepositoryRelativePath(t, path)
		if phase50ApprovedLiveMarkerFile(rel) {
			continue
		}
		t.Fatalf("Phase 50 live marker boundary: %s contains %s outside optional live build tags or approved guard/helper files", rel, marker.label)
	}
}

func TestPhase50OptionalLiveTestFilesStayBuildTagged(t *testing.T) {
	for _, req := range []struct {
		path string
		tag  string
	}{
		{path: filepath.Join("..", "cmd", "auto_integration_test.go"), tag: "integration"},
		{path: filepath.Join("..", "cmd", "convert_integration_test.go"), tag: "integration"},
		{path: filepath.Join("..", "cmd", "explode_integration_test.go"), tag: "integration"},
		{path: filepath.Join("..", "cmd", "worker_integration_test.go"), tag: "worker_integration"},
		{path: filepath.Join("..", "internal", "engine", "codex", "integration_test.go"), tag: "integration"},
		{path: filepath.Join("..", "internal", "engine", "pi", "live_test.go"), tag: "integration"},
		{path: filepath.Join("..", "internal", "sandboxruntime", "rootlesspodman", "podman_integration_test.go"), tag: "podman_integration"},
		{path: filepath.Join("..", "internal", "sandboxruntime", "microvm", "live_e2e_test.go"), tag: "microvm_e2e_live"},
		{path: filepath.Join("..", "internal", "sandboxruntime", "microvm", "live_e2e_execution_test.go"), tag: "microvm_e2e_live"},
		{path: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "real_process_runner_live_test.go"), tag: "firecracker_live"},
		{path: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go"), tag: "firecracker_live"},
		{path: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "network_enforcement_live_test.go"), tag: "network_enforcement_live"},
		{path: filepath.Join("..", "internal", "credentialdelivery", "credential_delivery_live_test.go"), tag: "credential_delivery_live"},
	} {
		source := phase50ReadFile(t, req.path)
		if !phase50HasBuildTag(source, req.tag) {
			t.Fatalf("%s must stay behind optional build tag %q", phase50RepositoryRelativePath(t, req.path), req.tag)
		}
	}
}

func TestPhase50DefaultGuardRejectsUnsafeFixturePatterns(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "optional live env marker lookup",
			source: `package fixture; import "os"; func test() { _ = os.Getenv("HAL_FIRECRACKER_LIVE") }`,
			want:   "optional live env lookup",
		},
		{
			name:   "live env value setup",
			source: `package fixture; func test(t interface{ Setenv(string, string) }) { t.Setenv("HAL_NETWORK_ENFORCEMENT_LIVE", "secret-value") }`,
			want:   "optional live env setup",
		},
		{
			name:   "KVM access",
			source: `package fixture; import "os"; func test() { _, _ = os.Open("/dev/kvm") }`,
			want:   "KVM prerequisite",
		},
		{
			name:   "Firecracker process launch",
			source: `package fixture; import "os/exec"; func test() { _ = exec.Command("firecracker", "--api-sock", "/tmp/private.sock") }`,
			want:   "Firecracker process",
		},
		{
			name:   "Podman lookup",
			source: `package fixture; import "os/exec"; func test() { _, _ = exec.LookPath("podman") }`,
			want:   "Podman process",
		},
		{
			name:   "Docker SDK import",
			source: `package fixture; import _ "github.com/docker/docker/client"`,
			want:   "Docker or Podman API",
		},
		{
			name:   "provider SDK import",
			source: `package fixture; import _ "github.com/digitalocean/godo"`,
			want:   "provider API",
		},
		{
			name:   "default TCP listener",
			source: `package fixture; import "net"; func test() { _, _ = net.Listen("tcp", "127.0.0.1:0") }`,
			want:   "default network access",
		},
		{
			name:   "HTTP client",
			source: `package fixture; import "net/http"; func test() { _, _ = http.Get("https://provider.internal.example.com?token=secret") }`,
			want:   "default network access",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file := phase50ParseGoSource(t, tt.name+".go", tt.source)
			message := phase50DefaultLivePrerequisiteBoundaryMessage(tt.name+".go", file)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want marker %q", message, tt.want)
			}
			phase50AssertGuardMessageRedactionSafe(t, message)
		})
	}
}

func TestPhase50LiveGatePackageStaysPureMetadataOnly(t *testing.T) {
	for _, path := range phase50LiveGateProductionFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", phase50RepositoryRelativePath(t, path), err)
		}
		for _, imported := range file.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", phase50RepositoryRelativePath(t, path), err)
			}
			if message := phase50LiveGateImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestPhase50LiveGatePurityGuardRejectsFixtures(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
		want       string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra", want: "Cobra package"},
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd", want: "cmd package"},
		{name: "command test helper", importPath: "github.com/jywlabs/hal/internal/cmdtest", want: "command test helper package"},
		{name: "concrete provider", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/daytona", want: "concrete provider adapter package"},
		{name: "worker daemon/client", importPath: "github.com/jywlabs/hal/internal/sandboxworker", want: "worker daemon package"},
		{name: "rootless Podman runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", want: "live runtime package"},
		{name: "Firecracker runtime", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker", want: "live runtime package"},
		{name: "network client", importPath: "net/http", want: "network package"},
		{name: "process execution", importPath: "os/exec", want: "process execution package"},
		{name: "Docker client", importPath: "github.com/docker/docker/client", want: "Docker or Podman API package"},
		{name: "Podman bindings", importPath: "github.com/containers/podman/v5/pkg/bindings", want: "Docker or Podman API package"},
		{name: "Firecracker SDK", importPath: "github.com/firecracker-microvm/firecracker-go-sdk", want: "Firecracker or KVM package"},
		{name: "cloud provider SDK", importPath: "github.com/aws/aws-sdk-go-v2/service/ec2", want: "provider API package"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := phase50LiveGateImportBoundaryMessage("contracts.go", tt.importPath)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("livegate import boundary message = %q, want %q", message, tt.want)
			}
			phase50AssertGuardMessageRedactionSafe(t, message)
		})
	}
}

func TestPhase50LiveMarkerAllowlistStaysExplicitAndExercised(t *testing.T) {
	for rel := range phase50ApprovedLiveMarkerFiles() {
		path := filepath.Join("..", filepath.FromSlash(rel))
		source := phase50ReadFile(t, path)
		if phase50FirstLiveOnlyMarker(source) == nil {
			t.Fatalf("Phase 50 live marker allowlist entry %s no longer contains a guarded marker", rel)
		}
		if phase50HasOptionalLiveBuildTag(source) {
			t.Fatalf("Phase 50 live marker allowlist entry %s is build-tagged and should not need a default-suite allowlist", rel)
		}
	}
}

func TestPhase50GuardMessagesStayRedactionSafe(t *testing.T) {
	source := `package fixture
import (
	"net/http"
	"os"
)
func test() {
	_ = os.Getenv("HAL_FIRECRACKER_LIVE=secret-live-value")
	_, _ = os.Open("/Users/alice/private/kvm-token.sock")
	_, _ = http.Get("https://provider.internal.example.com/api?token=secret")
	_ = "providerConfig={\"apiKey\":\"secret\"} --api-sock /tmp/private.sock iptables proxy.internal.example.com"
}
`
	file := phase50ParseGoSource(t, "fixture.go", source)
	message := phase50DefaultLivePrerequisiteBoundaryMessage("fixture.go", file)
	if message == "" {
		t.Fatal("fixture should fail the Phase 50 guard")
	}
	phase50AssertGuardMessageRedactionSafe(t, message)
	phase50AssertGuardMessageRedactionSafe(t, phase50LiveGateImportBoundaryMessage("fixture.go", "github.com/private/provider/token=secret"))
}

func phase50DefaultLivePrerequisiteBoundaryMessage(fileName string, file *ast.File) string {
	for _, imported := range file.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return phase50DefaultGuardMessage(fileName, "unreadable import", "import")
		}
		if forbidden := phase50DefaultForbiddenLiveImport(importPath); forbidden != "" {
			return phase50DefaultGuardMessage(fileName, forbidden, phase50ImportMarker(importPath))
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
		case phase50CallReadsLiveEnv(selector) && phase50CallHasOptionalLiveEnvArg(call):
			message = phase50DefaultGuardMessage(fileName, "optional live env lookup", phase50FirstOptionalLiveEnvArg(call))
		case phase50CallSetsLiveEnv(selector) && phase50CallHasOptionalLiveEnvArg(call):
			message = phase50DefaultGuardMessage(fileName, "optional live env setup", phase50FirstOptionalLiveEnvArg(call))
		case phase50CallAccessesKVM(selector) && phase50CallHasLiteralArg(call, "/dev/kvm"):
			message = phase50DefaultGuardMessage(fileName, "KVM prerequisite", "KVM device")
		case phase50CallLaunchesLiveProcess(selector, call):
			message = phase50DefaultGuardMessage(fileName, phase50LiveProcessLabel(call), phase50LiveProcessMarker(call))
		case phase50CallOpensDefaultNetwork(selector, call):
			message = phase50DefaultGuardMessage(fileName, "default network access", phase50NetworkMarker(selector))
		}
		return message == ""
	})
	return message
}

func phase50DefaultForbiddenLiveImport(importPath string) string {
	switch {
	case strings.HasPrefix(importPath, "github.com/docker/docker"),
		strings.HasPrefix(importPath, "github.com/containers/podman"):
		return "Docker or Podman API import"
	case strings.HasPrefix(importPath, "github.com/firecracker-microvm"):
		return "Firecracker or KVM import"
	case strings.HasPrefix(importPath, "github.com/digitalocean/godo"),
		strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go"),
		strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go-v2"),
		strings.HasPrefix(importPath, "github.com/hetznercloud/hcloud-go"),
		strings.HasPrefix(importPath, "cloud.google.com/go"),
		strings.HasPrefix(importPath, "google.golang.org/api"):
		return "provider API import"
	default:
		return ""
	}
}

func phase50CallReadsLiveEnv(selector string) bool {
	switch selector {
	case "os.Getenv", "os.LookupEnv":
		return true
	default:
		return false
	}
}

func phase50CallSetsLiveEnv(selector string) bool {
	return selector == "Setenv" || selector == "t.Setenv"
}

func phase50CallAccessesKVM(selector string) bool {
	switch selector {
	case "os.Open", "os.OpenFile", "os.Stat", "os.Lstat":
		return true
	default:
		return false
	}
}

func phase50CallLaunchesLiveProcess(selector string, call *ast.CallExpr) bool {
	switch selector {
	case "exec.Command", "exec.CommandContext", "exec.LookPath", "os.StartProcess", "syscall.Exec":
		return phase50CallHasAnyLiteralArg(call, []string{"docker", "podman", "firecracker", "/usr/bin/firecracker"})
	default:
		return false
	}
}

func phase50LiveProcessLabel(call *ast.CallExpr) string {
	switch {
	case phase50CallHasAnyLiteralArg(call, []string{"docker"}):
		return "Docker process"
	case phase50CallHasAnyLiteralArg(call, []string{"podman"}):
		return "Podman process"
	case phase50CallHasAnyLiteralArg(call, []string{"firecracker", "/usr/bin/firecracker"}):
		return "Firecracker process"
	default:
		return "live process"
	}
}

func phase50LiveProcessMarker(call *ast.CallExpr) string {
	switch {
	case phase50CallHasAnyLiteralArg(call, []string{"docker"}):
		return "docker"
	case phase50CallHasAnyLiteralArg(call, []string{"podman"}):
		return "podman"
	case phase50CallHasAnyLiteralArg(call, []string{"firecracker", "/usr/bin/firecracker"}):
		return "firecracker"
	default:
		return "process"
	}
}

func phase50CallOpensDefaultNetwork(selector string, call *ast.CallExpr) bool {
	switch selector {
	case "net.Listen", "net.ListenPacket", "net.Dial", "net.DialTimeout":
		network := phase50FirstStringLiteralArg(call)
		return network != "" && network != "unix" && network != "unixpacket"
	case "http.Get", "http.Head", "http.Post", "http.PostForm", "http.ListenAndServe", "http.ListenAndServeTLS":
		return true
	default:
		return false
	}
}

func phase50NetworkMarker(selector string) string {
	if strings.HasPrefix(selector, "http.") {
		return "http client/server"
	}
	return "network socket"
}

func phase50CallHasOptionalLiveEnvArg(call *ast.CallExpr) bool {
	return phase50FirstOptionalLiveEnvArg(call) != ""
}

func phase50FirstOptionalLiveEnvArg(call *ast.CallExpr) string {
	for _, value := range phase50StringLiteralArgs(call) {
		if phase50OptionalLiveEnvMarker(value) {
			return phase50SafeEnvMarker(value)
		}
	}
	return ""
}

func phase50OptionalLiveEnvMarker(value string) bool {
	return value == "HAL_FIRECRACKER_LIVE" ||
		strings.HasPrefix(value, "HAL_FIRECRACKER_LIVE_") ||
		value == "HAL_NETWORK_ENFORCEMENT_LIVE" ||
		strings.HasPrefix(value, "HAL_NETWORK_ENFORCEMENT_LIVE_") ||
		value == "HAL_CREDENTIAL_DELIVERY_LIVE" ||
		strings.HasPrefix(value, "HAL_CREDENTIAL_DELIVERY_LIVE_") ||
		strings.HasPrefix(value, phase50WorkerIntegrationEnvPrefix) ||
		strings.HasPrefix(value, phase50PodmanEnvPrefix)
}

func phase50SafeEnvMarker(value string) string {
	if idx := strings.IndexAny(value, " ="); idx >= 0 {
		return value[:idx]
	}
	return value
}

func phase50CallHasLiteralArg(call *ast.CallExpr, want string) bool {
	for _, value := range phase50StringLiteralArgs(call) {
		if value == want {
			return true
		}
	}
	return false
}

func phase50CallHasAnyLiteralArg(call *ast.CallExpr, wants []string) bool {
	for _, value := range phase50StringLiteralArgs(call) {
		for _, want := range wants {
			if value == want || strings.HasSuffix(value, "/"+want) || strings.Contains(value, want+" ") {
				return true
			}
		}
	}
	return false
}

func phase50FirstStringLiteralArg(call *ast.CallExpr) string {
	for _, value := range phase50StringLiteralArgs(call) {
		return value
	}
	return ""
}

func phase50StringLiteralArgs(call *ast.CallExpr) []string {
	var values []string
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(lit.Value)
		if err == nil {
			values = append(values, value)
		}
	}
	return values
}

func phase50CallSelectorName(expr ast.Expr) string {
	switch fn := expr.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if ident, ok := fn.X.(*ast.Ident); ok {
			return ident.Name + "." + fn.Sel.Name
		}
		return fn.Sel.Name
	default:
		return ""
	}
}

func phase50DefaultGuardMessage(fileName, category, marker string) string {
	return fmt.Sprintf("Phase 50 default fake-only guard: %s contains %s marker %q outside optional live build tags or approved helper files", phase50SafeDisplayPath(fileName), category, marker)
}

func phase50LiveGateProductionFiles(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "internal", "livegate", "*.go"))
	if err != nil {
		t.Fatalf("Glob(internal/livegate/*.go) error: %v", err)
	}
	var out []string
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		out = append(out, path)
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("Phase 50 livegate purity guard matched no production files")
	}
	return out
}

func phase50LiveGateImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := phase50LiveGateForbiddenImportLabel(importPath); forbidden != "" {
		return fmt.Sprintf("Phase 50 livegate purity guard: %s imports forbidden %s %q", phase50SafeDisplayPath(fileName), forbidden, phase50ImportMarker(importPath))
	}
	switch importPath {
	case "encoding/json", "strings":
		return ""
	default:
		return fmt.Sprintf("Phase 50 livegate purity guard: %s imports unapproved dependency %q", phase50SafeDisplayPath(fileName), phase50ImportMarker(importPath))
	}
}

func phase50LiveGateForbiddenImportLabel(importPath string) string {
	switch {
	case importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra"):
		return "Cobra package"
	case phase50ModuleImportMatcher("github.com/jywlabs/hal/cmd")(importPath):
		return "cmd package"
	case phase50ModuleImportMatcher("github.com/jywlabs/hal/internal/cmdtest")(importPath):
		return "command test helper package"
	case phase50ModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")(importPath):
		return "concrete provider adapter package"
	case phase50ModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")(importPath):
		return "worker daemon package"
	case phase50ModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman")(importPath),
		phase50ModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/microvm")(importPath),
		phase50ModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement")(importPath),
		phase50ModuleImportMatcher("github.com/jywlabs/hal/internal/credentialdelivery")(importPath):
		return "live runtime package"
	case importPath == "net" || importPath == "net/http" || strings.HasPrefix(importPath, "net/http/") || strings.HasPrefix(importPath, "google.golang.org/grpc"):
		return "network package"
	case importPath == "os/exec":
		return "process execution package"
	case strings.HasPrefix(importPath, "github.com/docker/docker") || strings.HasPrefix(importPath, "github.com/containers/podman"):
		return "Docker or Podman API package"
	case strings.HasPrefix(importPath, "github.com/firecracker-microvm") || strings.Contains(strings.ToLower(importPath), "kvm"):
		return "Firecracker or KVM package"
	case strings.HasPrefix(importPath, "github.com/digitalocean/godo"),
		strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go"),
		strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go-v2"),
		strings.HasPrefix(importPath, "github.com/hetznercloud/hcloud-go"),
		strings.HasPrefix(importPath, "cloud.google.com/go"),
		strings.HasPrefix(importPath, "google.golang.org/api"):
		return "provider API package"
	default:
		return ""
	}
}

func phase50ModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

func phase50ImportMarker(importPath string) string {
	switch {
	case strings.HasPrefix(importPath, "github.com/docker/docker"):
		return "docker-api"
	case strings.HasPrefix(importPath, "github.com/containers/podman"):
		return "podman-api"
	case strings.HasPrefix(importPath, "github.com/firecracker-microvm"):
		return "firecracker-sdk"
	case strings.HasPrefix(importPath, "github.com/digitalocean/godo"):
		return "provider-api"
	case strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go-v2"):
		return "provider-api"
	case strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go"):
		return "provider-api"
	case strings.HasPrefix(importPath, "github.com/hetznercloud/hcloud-go"):
		return "provider-api"
	case strings.HasPrefix(importPath, "cloud.google.com/go"):
		return "provider-api"
	case strings.HasPrefix(importPath, "google.golang.org/api"):
		return "provider-api"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/cmd"):
		return "cmd-package"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/cmdtest"):
		return "command-test-helper"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandbox/provider"):
		return "provider-adapter"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxworker"):
		return "worker-daemon"
	case strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime"):
		return "live-runtime"
	default:
		return "dependency"
	}
}

func phase50FirstLiveOnlyMarker(source string) *phase50LiveOnlyMarker {
	for _, marker := range phase50LiveOnlyMarkers() {
		if strings.Contains(source, marker.token) {
			return &marker
		}
	}
	return nil
}

func phase50LiveOnlyMarkers() []phase50LiveOnlyMarker {
	return []phase50LiveOnlyMarker{
		{token: "HAL_FIRECRACKER_LIVE", label: "Firecracker optional live env marker"},
		{token: "HAL_NETWORK_ENFORCEMENT_LIVE", label: "network enforcement optional live env marker"},
		{token: "HAL_CREDENTIAL_DELIVERY_LIVE", label: "credential delivery optional live env marker"},
		{token: phase50WorkerIntegrationEnvPrefix, label: "worker integration env marker"},
		{token: phase50PodmanEnvPrefix, label: "Podman optional live env marker"},
		{token: "microvm_e2e_live", label: "microVM live E2E optional build-tag marker"},
		{token: "firecracker_live", label: "Firecracker optional live build-tag marker"},
		{token: "network_enforcement_live", label: "network enforcement optional live build-tag marker"},
		{token: "credential_delivery_live", label: "credential delivery optional live build-tag marker"},
		{token: "worker_integration", label: "worker integration build-tag marker"},
		{token: "podman_integration", label: "Podman integration build-tag marker"},
		{token: "/dev/kvm", label: "KVM device marker"},
		{token: "docker.NewClient", label: "Docker API marker"},
		{token: "bindings.NewConnection", label: "Podman API marker"},
		{token: "firecracker.NewMachine", label: "Firecracker SDK marker"},
		{token: "NewOSExecProcessRunner", label: "Firecracker host process runner marker"},
		{token: "DefaultCommandRunner", label: "rootless Podman command runner marker"},
	}
}

func phase50HasOptionalLiveBuildTag(source string) bool {
	for _, tag := range []string{
		"integration",
		"microvm_e2e_live",
		"worker_integration",
		"podman_integration",
		"firecracker_live",
		"network_enforcement_live",
		"credential_delivery_live",
	} {
		if phase50HasBuildTag(source, tag) {
			return true
		}
	}
	return false
}

func phase50HasBuildTag(source, tag string) bool {
	header := phase19SourceHeader(source)
	for _, line := range strings.Split(header, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//go:build") || strings.HasPrefix(line, "// +build") {
			if strings.Contains(line, tag) {
				return true
			}
		}
	}
	return false
}

func phase50ApprovedLiveMarkerFile(rel string) bool {
	return phase50ApprovedLiveMarkerFiles()[filepath.ToSlash(filepath.Clean(rel))]
}

func phase50ApprovedLiveMarkerFiles() map[string]bool {
	return map[string]bool{
		"cmd/credential_proxy_manifest_test.go":                      true,
		"cmd/phase22_policy_secret_docs_test.go":                     true,
		"cmd/phase24_network_proxy_docs_test.go":                     true,
		"cmd/phase25_credential_proxy_docs_test.go":                  true,
		"cmd/phase26_credential_proxy_docs_test.go":                  true,
		"cmd/phase27_security_capability_docs_test.go":               true,
		"cmd/phase28_security_capability_docs_test.go":               true,
		"cmd/phase29_security_readiness_diagnostics_docs_test.go":    true,
		"cmd/phase30_security_readiness_gate_docs_test.go":           true,
		"cmd/phase31_microvm_docs_test.go":                           true,
		"cmd/phase32_firecracker_docs_test.go":                       true,
		"cmd/phase33_firecracker_docs_test.go":                       true,
		"cmd/phase34_firecracker_docs_test.go":                       true,
		"cmd/phase35_firecracker_host_adapter_default_guard_test.go": true,
		"cmd/phase35_firecracker_host_adapter_docs_test.go":          true,
		"cmd/phase36_firecracker_live_driver_docs_test.go":           true,
		"cmd/phase37_firecracker_guest_readiness_docs_test.go":       true,
		"cmd/phase40_microvm_guest_agent_transport_docs_test.go":     true,
		"cmd/phase40_microvm_guest_agent_transport_guard_test.go":    true,
		"cmd/phase41_microvm_image_pipeline_docs_test.go":            true,
		"cmd/phase42_network_proxy_enforcement_docs_test.go":         true,
		"cmd/phase43_credential_delivery_docs_test.go":               true,
		"cmd/phase45_final_fake_only_verification_test.go":           true,
		"cmd/phase45_network_enforcement_live_guard_test.go":         true,
		"cmd/phase46_final_fake_only_verification_test.go":           true,
		"cmd/phase46_runtime_worker_docs_test.go":                    true,
		"cmd/phase47_template_acquisition_docs_test.go":              true,
		"cmd/phase48_final_fake_only_verification_test.go":           true,
		"cmd/phase49_final_code_verification_test.go":                true,
		"cmd/phase49_live_provider_gates_test.go":                    true,
		"cmd/phase50_default_live_gate_guard_test.go":                true,
		"cmd/phase50_final_code_only_verification_test.go":           true,
		"cmd/phase50_manual_live_opt_in_docs_test.go":                true,
		"cmd/phase50_optional_live_placeholders_test.go":             true,
		"cmd/phase52_template_provenance_docs_test.go":               true,
		"cmd/phase53_final_verification_test.go":                     true,
		"cmd/phase53_live_e2e_docs_test.go":                          true,
		"cmd/phase53_live_marker_guard_test.go":                      true,
		"cmd/phase54_optional_live_matrix_docs_test.go":              true,
		"cmd/phase56_live_gate_docs_test.go":                         true,
		"cmd/sandbox_default_fake_only_guard_test.go":                true,
		"cmd/sandbox_runtime_compat.go":                              true,
		"cmd/sandbox_worker_execution_documentation_test.go":         true,
		"cmd/sandboxd.go":                                                                      true,
		"cmd/sandboxd_safety_test.go":                                                          true,
		"cmd/secure_default_runtime_docs_red_test.go":                                          true,
		"cmd/us004_default_harness_guard_test.go":                                              true,
		"internal/credentialdelivery/activation_diagnostics_test.go":                           true,
		"internal/credentialdelivery/import_boundary_test.go":                                  true,
		"internal/livegate/contracts.go":                                                       true,
		"internal/livegate/contracts_test.go":                                                  true,
		"internal/livegate/evaluator_test.go":                                                  true,
		"internal/livegate/helpers_test.go":                                                    true,
		"internal/livegate/import_boundary_test.go":                                            true,
		"internal/sandbox/credential_proxy_import_boundary_test.go":                            true,
		"internal/sandbox/network_proxy_import_boundary_test.go":                               true,
		"internal/sandbox/security_capability_import_boundary_test.go":                         true,
		"internal/sandboxruntime/microvm/capability.go":                                        true,
		"internal/sandboxruntime/microvm/capability_test.go":                                   true,
		"internal/sandboxruntime/microvm/firecracker/backend.go":                               true,
		"internal/sandboxruntime/microvm/firecracker/backend_test.go":                          true,
		"internal/sandboxruntime/microvm/firecracker/import_boundary_test.go":                  true,
		"internal/sandboxruntime/microvm/firecracker/render.go":                                true,
		"internal/sandboxruntime/microvm/firecrackerhost/live_driver.go":                       true,
		"internal/sandboxruntime/microvm/firecrackerhost/real_process_runner.go":               true,
		"internal/sandboxruntime/microvm/firecrackerhost/real_process_runner_test.go":          true,
		"internal/sandboxruntime/microvm/firecrackerhost/real_process_runner_boundary_test.go": true,
		"internal/sandboxruntime/rootlesspodman/command_runner.go":                             true,
		"internal/sandboxtemplate/acquisition/import_boundary_test.go":                         true,
		"internal/sandboxtemplate/import_boundary_test.go":                                     true,
	}
}

func phase50RepositoryGoFiles(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, root := range []string{filepath.Join("..", "cmd"), filepath.Join("..", "internal")} {
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				switch entry.Name() {
				case ".git", ".hal", "vendor":
					return filepath.SkipDir
				default:
					return nil
				}
			}
			if strings.HasSuffix(path, ".go") {
				paths = append(paths, path)
			}
			return nil
		}); err != nil {
			t.Fatalf("WalkDir(%s) error: %v", root, err)
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatal("Phase 50 repository guard matched no Go files")
	}
	return paths
}

func phase50ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", phase50SafeDisplayPath(path), err)
	}
	return string(data)
}

func phase50ParseGoFile(t *testing.T, path, source string) *ast.File {
	t.Helper()
	return phase50ParseGoSource(t, path, source)
}

func phase50ParseGoSource(t *testing.T, path, source string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", phase50SafeDisplayPath(path), err)
	}
	return file
}

func phase50RepositoryRelativePath(t *testing.T, path string) string {
	t.Helper()
	rel, err := filepath.Rel("..", path)
	if err != nil {
		t.Fatalf("Rel(%s) error: %v", phase50SafeDisplayPath(path), err)
	}
	return filepath.ToSlash(rel)
}

func phase50SafeDisplayPath(path string) string {
	clean := filepath.ToSlash(filepath.Clean(path))
	if strings.HasPrefix(clean, "../") {
		return strings.TrimPrefix(clean, "../")
	}
	return clean
}

func phase50AssertGuardMessageRedactionSafe(t *testing.T, message string) {
	t.Helper()
	for _, forbidden := range []string{
		"secret-live-value",
		"secret-value",
		"/Users/alice",
		"/tmp/private.sock",
		"private.sock",
		"provider.internal.example.com",
		"https://",
		"unix://",
		"token=secret",
		"apiKey",
		"providerConfig",
		"--api-sock",
		"iptables",
		"proxy.internal.example.com",
	} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("Phase 50 guard message leaked unsafe fragment %q: %s", forbidden, message)
		}
	}
}

type phase50LiveOnlyMarker struct {
	token string
	label string
}
