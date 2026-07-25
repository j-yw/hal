package cmd

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	l4GuestAgentServerVerificationDoc = "sandbox-runtime-v2-l4-guest-agent-server-verification.md"
	l4GuestAgentServerBuildTag        = "l4_guest_agent_server_integration"
	l4GuestAgentServerLiveTest        = "l4_linux_backend_integration_test.go"
	l4GuestAgentServerLiveTestName    = "TestL4PreparedLinuxLocalServerE2E"
)

func TestL4GuestAgentServerVerificationDocumentation(t *testing.T) {
	doc := readL4GuestAgentServerVerificationFile(t, filepath.Join("..", "docs", "design", l4GuestAgentServerVerificationDoc))
	normalized := strings.Join(strings.Fields(doc), " ")
	for _, required := range []string{
		"Sandbox Runtime v2 L4 Guest-Agent Server Verification",
		"red-first verification boundary for issue #49 phase L4",
		"production guest-agent protocol server and Linux operation backend behind an injected in-memory transport",
		"does not add a listener, vsock, a guest image, Firecracker machine configuration, network enforcement, credential delivery, OCI acquisition, or a strict-security claim",
		"MicroVM worker capabilities remain lifecycle-only throughout L4.",
		"strict host response decoder",
		"duplicate, trailing, oversized, canceled, busy, not-ready, and unsupported-version requests make zero backend calls",
		"process-group termination, reap, work-directory descriptor pinning, and descriptor non-inheritance",
		"exact lowercase SHA-256",
		"coordinated parent swap",
		"multiply-linked file, FIFO, socket, and device rejection",
		"Default and tagged L4 tests must not call `t.Skip` or `t.Skipf`.",
		"selecting the tag on a non-Linux host runs the test and fails rather than silently matching no tests",
		"A skipped or zero-match prepared test is a blocker, never a pass.",
		"No L4 result is Firecracker, image, vsock, microVM-isolation, network-enforcement, credential, OCI, or strict-default evidence.",
	} {
		if !strings.Contains(doc, required) && !strings.Contains(normalized, required) {
			t.Fatalf("L4 guest-agent server verification documentation missing %q", required)
		}
	}

	commands := l4GuestAgentServerDocumentedShellCommands(doc)
	for _, required := range []string{
		`test "$(go env GOOS)" = linux`,
		"go test -list '^TestL4PreparedLinuxLocalServerE2E$' -tags=l4_guest_agent_server_integration ./internal/sandboxruntime/microvm/guestagent/server | grep -qx 'TestL4PreparedLinuxLocalServerE2E'",
		"go test -race -count=1 -timeout=180s -tags=l4_guest_agent_server_integration ./internal/sandboxruntime/microvm/guestagent/server -run '^TestL4PreparedLinuxLocalServerE2E$'",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/guestagent ./internal/sandboxruntime/microvm/guestagent/server",
		"go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm/firecrackerhost -run '^Test(GuestAgent|L4)'",
		"go test -count=1 -timeout=180s ./cmd -run '^Test(L4GuestAgent|Phase40MicroVM|Sandboxd.*GuestAgent)'",
		"go test -race -count=1 -timeout=240s ./internal/sandboxruntime/microvm/guestagent ./internal/sandboxruntime/microvm/guestagent/server ./internal/sandboxruntime/microvm/firecrackerhost",
		"GOOS=darwin GOARCH=amd64 go test -exec=true -count=1 -run '^$' ./internal/sandboxruntime/microvm/guestagent ./internal/sandboxruntime/microvm/guestagent/server ./internal/sandboxruntime/microvm/firecrackerhost",
		"GOOS=windows GOARCH=amd64 go test -exec=true -count=1 -run '^$' ./internal/sandboxruntime/microvm/guestagent ./internal/sandboxruntime/microvm/guestagent/server ./internal/sandboxruntime/microvm/firecrackerhost",
		"go test -count=1 -timeout=420s ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		`test -z "$(gofmt -l cmd internal)"`,
		"git diff --check",
	} {
		if !commands[required] {
			t.Fatalf("L4 guest-agent server verification documentation missing command %q", required)
		}
	}

	l4AssertGuestAgentServerSelectors(t, doc)
}

func TestL4GuestAgentServerDefaultTestsStayFakeOnly(t *testing.T) {
	serverDir := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "server")
	entries, err := os.ReadDir(serverDir)
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", serverDir, err)
	}
	foundDefault := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") || name == l4GuestAgentServerLiveTest || name == "import_boundary_test.go" {
			continue
		}
		foundDefault = true
		path := filepath.Join(serverDir, name)
		source := readL4GuestAgentServerVerificationFile(t, path)
		header := phase19SourceHeader(source)
		if strings.Contains(header, "//go:build") {
			t.Fatalf("%s must stay untagged for default verification", phase34FirecrackerDisplayPath(t, path))
		}
		for _, forbidden := range []string{
			"t.Skip(",
			"t.Skipf(",
			"/dev/kvm",
			"firecracker_live",
			"podman_integration",
			"worker_integration",
			"HAL_PODMAN_TEST_IMAGE",
			"HAL_FIRECRACKER_LIVE",
			"DOCKER_HOST",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s contains forbidden fake-only marker %q", phase34FirecrackerDisplayPath(t, path), forbidden)
			}
		}
		l4AssertGuestAgentServerDefaultTestImports(t, path)
	}
	if !foundDefault {
		t.Fatal("no default L4 guest-agent server tests found")
	}
}

func TestL4GuestAgentServerPreparedLinuxAcceptanceGuard(t *testing.T) {
	path := filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "server", l4GuestAgentServerLiveTest)
	source := readL4GuestAgentServerVerificationFile(t, path)
	header := phase19SourceHeader(source)
	wantBuild := "//go:build " + l4GuestAgentServerBuildTag
	if !strings.Contains(header, wantBuild) {
		t.Fatalf("%s build header = %q, want exact explicit tag %q without a Linux exclusion", phase34FirecrackerDisplayPath(t, path), header, wantBuild)
	}
	if strings.Contains(header, "linux &&") || strings.Contains(header, "&& linux") {
		t.Fatalf("%s must compile when explicitly selected off Linux so the test fails instead of matching zero tests", phase34FirecrackerDisplayPath(t, path))
	}
	for _, required := range []string{
		"func " + l4GuestAgentServerLiveTestName + "(",
		"runtime.GOOS",
		`"linux"`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("%s missing prepared-Linux acceptance marker %q", phase34FirecrackerDisplayPath(t, path), required)
		}
	}
	for _, forbidden := range []string{
		"t.Skip(",
		"t.Skipf(",
		"firecracker",
		"/dev/kvm",
		"podman",
		"docker",
		"net.Listen",
		"HAL_",
	} {
		if strings.Contains(strings.ToLower(source), strings.ToLower(forbidden)) {
			t.Fatalf("%s contains forbidden prepared-Linux marker %q", phase34FirecrackerDisplayPath(t, path), forbidden)
		}
	}
}

func TestL4GuestAgentServerGuardRejectsFixtures(t *testing.T) {
	if got := l4ForbiddenDefaultTestImport("github.com/firecracker-microvm/firecracker-go-sdk"); got == "" {
		t.Fatal("fake-only import guard did not reject Firecracker SDK fixture")
	}
	if got := l4ForbiddenDefaultTestImport("github.com/containers/podman/v5/pkg/bindings"); got == "" {
		t.Fatal("fake-only import guard did not reject Podman fixture")
	}
	if got := l4ForbiddenDefaultTestImport("os/exec"); got != "" {
		t.Fatalf("fake-only import guard rejected local process test import: %s", got)
	}
}

func readL4GuestAgentServerVerificationFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}

func l4GuestAgentServerDocumentedShellCommands(doc string) map[string]bool {
	commands := make(map[string]bool)
	inShell := false
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		switch line {
		case "```sh":
			inShell = true
			continue
		case "```":
			inShell = false
			continue
		}
		if inShell && line != "" {
			commands[line] = true
		}
	}
	return commands
}

func l4AssertGuestAgentServerSelectors(t *testing.T, doc string) {
	t.Helper()
	commands := phase34AllGoTestCommands(doc)
	for _, required := range []phase34FocusedTest{
		{pkg: "./internal/sandboxruntime/microvm/guestagent", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "contracts_test.go"), testName: "TestL4ProtocolErrorCodesAndGenericEnvelopeJSON"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "client_test.go"), testName: "TestClientRejectsUnknownDuplicateNonObjectAndTrailingResponses"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent/server", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "server", "server_test.go"), testName: "TestL4ServerCanonicalReadinessAndVersionHandling"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent/server", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "server", "server_test.go"), testName: "TestL4ServerStrictDispatchRejectsMalformedUnknownAndOversizedRequests"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent/server", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "server", "server_test.go"), testName: "TestL4ServerRoutesOnlyTheEncodedOperation"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent/server", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "server", "server_lifecycle_test.go"), testName: "TestL4ServerShutdownAndTransportFailureCleanupAreExactlyOnce"},
		{pkg: "./internal/sandboxruntime/microvm/guestagent/server", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "server", l4GuestAgentServerLiveTest), testName: l4GuestAgentServerLiveTestName},
		{pkg: "./internal/sandboxruntime/microvm/guestagent/server", file: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "server", "import_boundary_test.go"), testName: "TestL4GuestAgentServerProductionImportsStayBounded"},
		{pkg: "./cmd", file: "phase40_microvm_guest_agent_transport_guard_test.go", testName: "TestPhase40MicroVMDefaultCapabilitiesStayLifecycleOnlyWithoutGuestTransport"},
		{pkg: "./cmd", file: "sandboxd_test.go", testName: "TestSandboxdCommandConfiguredMicroVMGuestAgentEndpointKeepsCapabilitiesLifecycleOnly"},
		{pkg: "./cmd", file: "l4_guest_agent_server_docs_test.go", testName: "TestL4GuestAgentServerVerificationDocumentation"},
	} {
		command := phase34FocusedCommandCoveringTest(t, commands, required.pkg, required.testName)
		if command == "" {
			t.Fatalf("L4 verification documentation missing focused command covering %s in %s", required.testName, required.pkg)
		}
		if !phase34TestFileDefinesFunction(t, required.file, required.testName) {
			t.Fatalf("%s does not define required L4 verification test %s", phase34FirecrackerDisplayPath(t, required.file), required.testName)
		}
	}
}

func l4AssertGuestAgentServerDefaultTestImports(t *testing.T, path string) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("Unquote(%s in %s) error: %v", spec.Path.Value, path, err)
		}
		if forbidden := l4ForbiddenDefaultTestImport(importPath); forbidden != "" {
			t.Fatalf("%s imports %q; default L4 tests must not require %s", phase34FirecrackerDisplayPath(t, path), importPath, forbidden)
		}
	}
}

func l4ForbiddenDefaultTestImport(importPath string) string {
	for _, forbidden := range []struct {
		prefix string
		label  string
	}{
		{prefix: "github.com/firecracker-microvm", label: "Firecracker SDKs"},
		{prefix: "github.com/containers/podman", label: "Podman"},
		{prefix: "github.com/docker/docker", label: "Docker"},
		{prefix: "github.com/digitalocean/godo", label: "cloud SDKs"},
		{prefix: "github.com/aws/aws-sdk-go", label: "cloud SDKs"},
		{prefix: "github.com/hetznercloud/hcloud-go", label: "cloud SDKs"},
		{prefix: "cloud.google.com/go", label: "cloud SDKs"},
		{prefix: "google.golang.org/api", label: "cloud SDKs"},
	} {
		if strings.HasPrefix(importPath, forbidden.prefix) {
			return forbidden.label
		}
	}
	switch importPath {
	case "net", "net/http", "net/rpc":
		return "network listeners or clients"
	default:
		return ""
	}
}
