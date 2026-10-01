package cmd

import (
	"go/ast"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
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
	} {
		source := phase50ReadFile(t, req.path)
		if !phase50HasBuildTag(source, req.tag) {
			t.Fatalf("%s must stay behind optional build tag %q", phase50RepositoryRelativePath(t, req.path), req.tag)
		}
	}
}

func phase50ApprovedLiveMarkerFile(rel string) bool {
	return phase50ApprovedLiveMarkerFiles()[filepath.ToSlash(filepath.Clean(rel))]
}

func phase50ApprovedLiveMarkerFiles() map[string]bool {
	return map[string]bool{
		"cmd/credential_proxy_manifest_test.go":                                 true,
		"cmd/l3_prepared_linux_verification_test.go":                            true,
		"cmd/l2_worker_job_docs_test.go":                                        true,
		"cmd/phase22_policy_secret_docs_test.go":                                true,
		"cmd/phase24_network_proxy_docs_test.go":                                true,
		"cmd/phase25_credential_proxy_docs_test.go":                             true,
		"cmd/phase26_credential_proxy_docs_test.go":                             true,
		"cmd/phase27_security_capability_docs_test.go":                          true,
		"cmd/phase28_security_capability_docs_test.go":                          true,
		"cmd/phase29_security_readiness_diagnostics_docs_test.go":               true,
		"cmd/phase30_security_readiness_gate_docs_test.go":                      true,
		"cmd/phase47_template_acquisition_docs_test.go":                         true,
		"cmd/phase49_live_provider_gates_test.go":                               true,
		"cmd/phase50_default_live_gate_guard_test.go":                           true,
		"cmd/phase52_template_provenance_docs_test.go":                          true,
		"cmd/sandbox_default_fake_only_guard_test.go":                           true,
		"cmd/sandbox_runtime_compat.go":                                         true,
		"cmd/sandbox_worker_execution_documentation_test.go":                    true,
		"cmd/verification_docs_helpers_test.go":                                 true,
		"cmd/sandboxd.go":                                                       true,
		"internal/credentialdelivery/import_boundary_test.go":                   true,
		"internal/sandbox/credential_proxy_import_boundary_test.go":             true,
		"internal/sandbox/network_proxy_import_boundary_test.go":                true,
		"internal/sandbox/security_capability_import_boundary_test.go":          true,
		"internal/sandboxruntime/rootlesspodman/command_runner.go":              true,
		"internal/sandboxruntime/rootlesspodman/l2_process_group_linux_test.go": true,
		"internal/sandboxtemplate/acquisition/import_boundary_test.go":          true,
		"internal/sandboxtemplate/import_boundary_test.go":                      true,
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

func phase50ParseGoFile(t *testing.T, path, source string) *ast.File {
	t.Helper()
	return phase50ParseGoSource(t, path, source)
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

func phase50RepositoryRelativePath(t *testing.T, path string) string {
	t.Helper()
	rel, err := filepath.Rel("..", path)
	if err != nil {
		t.Fatalf("Rel(%s) error: %v", phase50SafeDisplayPath(path), err)
	}
	return filepath.ToSlash(rel)
}

type phase50LiveOnlyMarker struct {
	token string
	label string
}
