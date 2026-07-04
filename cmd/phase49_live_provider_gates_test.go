package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const phase49LiveProviderGatesDocPath = "sandbox-runtime-v2-phase49-live-provider-gates-verification.md"

func TestPhase49LiveProviderGateDocumentation(t *testing.T) {
	doc := readPhase49LiveProviderGatesDoc(t)
	normalizedDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"Phase 49 live-provider gate verification is fake-only by default.",
		"Fake-only verification remains the documented default path.",
		"Default Phase 49 verification does not require live credentials, KVM, Firecracker, Podman, Docker, worker daemons, provider APIs, network access, or optional live build tags.",
		"Optional live-provider paths are explicit opt-in only and are not part of default Phase 49 verification:",
		"Missing live configuration must skip optional live tests or report redaction-safe diagnostics before any live-provider attempt.",
		"`firecracker_live` build tag plus `HAL_FIRECRACKER_LIVE=1`",
		"`network_enforcement_live` build tag plus `HAL_NETWORK_ENFORCEMENT_LIVE=1`",
		"`credential_delivery_live` build tag plus `HAL_CREDENTIAL_DELIVERY_LIVE=1`",
		"`worker_integration` build tag plus the `HAL_WORKER_INTEGRATION_*` environment set",
		"`podman_integration` build tag plus `HAL_PODMAN_" + "TEST_IMAGE`",
		"go test -count=1 ./cmd -run 'Test(US006DefaultFakeOnly|Phase49LiveProvider)'",
		"go test ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	}
	for _, want := range required {
		if !strings.Contains(doc, want) && !strings.Contains(normalizedDoc, want) {
			t.Fatalf("phase 49 live-provider gate documentation missing %q", want)
		}
	}

	phase49AssertDocumentedDefaultCommands(t, doc)
}

func TestPhase49LiveProviderGatesAreExplicitOptInOnly(t *testing.T) {
	doc := readPhase49LiveProviderGatesDoc(t)
	for _, marker := range []string{
		"HAL_FIRECRACKER_LIVE",
		"HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_CREDENTIAL_DELIVERY_LIVE",
		"worker_integration",
		"podman_integration",
		"firecracker_live",
	} {
		if !strings.Contains(doc, marker) {
			t.Fatalf("phase 49 documentation missing optional live gate marker %q", marker)
		}
		if !phase49MarkerWindowContains(doc, marker, "explicit opt-in") {
			t.Fatalf("phase 49 documentation mentions %q without nearby explicit opt-in language", marker)
		}
	}
}

func TestPhase49DefaultVerificationCommandsStayFakeOnly(t *testing.T) {
	doc := readPhase49LiveProviderGatesDoc(t)
	commands := phase49DocumentedDefaultCommands(doc)
	if len(commands) == 0 {
		t.Fatal("phase 49 documentation must list default verification commands")
	}

	for _, command := range commands {
		for _, forbidden := range phase49ForbiddenDefaultCommandMarkers() {
			if strings.Contains(command, forbidden) {
				t.Fatalf("phase 49 default verification command %q contains forbidden live/default dependency marker %q", command, forbidden)
			}
		}
	}
}

func TestPhase49OptionalLiveTestFilesStayGatedAndSkipWithoutConfig(t *testing.T) {
	for _, req := range []struct {
		path    string
		markers []string
	}{
		{
			path: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost", "real_process_runner_live_test.go"),
			markers: []string{
				"//go:build firecracker_live",
				"HAL_FIRECRACKER_LIVE",
				"HAL_FIRECRACKER_LIVE_FIRECRACKER",
				"t.Skip",
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker", "firecracker_live_integration_test.go"),
			markers: []string{
				"//go:build firecracker_live",
				"HAL_FIRECRACKER_LIVE_FIRECRACKER",
				"HAL_FIRECRACKER_LIVE_KERNEL",
				"HAL_FIRECRACKER_LIVE_ROOTFS",
				"TestFirecrackerLivePrerequisiteSkipMessagesAreClearAndRedacted",
				"t.Skip",
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxruntime", "networkenforcement", "network_enforcement_live_test.go"),
			markers: []string{
				"//go:build network_enforcement_live",
				"HAL_NETWORK_ENFORCEMENT_LIVE",
				"HAL_NETWORK_ENFORCEMENT_LIVE_PROXY",
				"HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL",
				"TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted",
				"t.Skip",
			},
		},
		{
			path: filepath.Join("..", "internal", "credentialdelivery", "credential_delivery_live_test.go"),
			markers: []string{
				"//go:build credential_delivery_live",
				"HAL_CREDENTIAL_DELIVERY_LIVE",
				"HAL_CREDENTIAL_DELIVERY_LIVE_HTTP_PROXY",
				"HAL_CREDENTIAL_DELIVERY_LIVE_FILE_TMPFS",
				"HAL_CREDENTIAL_DELIVERY_LIVE_SSH_AGENT",
				"HAL_CREDENTIAL_DELIVERY_LIVE_ENV",
				"TestCredentialDeliveryLivePrerequisiteSkipMessagesAreSanitized",
				"t.Skip",
			},
		},
		{
			path: filepath.Join("worker_integration_test.go"),
			markers: []string{
				"//go:build worker_integration",
				"HAL_WORKER_INTEGRATION_ENDPOINT",
				"HAL_WORKER_INTEGRATION_HOST_NAME",
				"HAL_WORKER_INTEGRATION_RUNTIME_DRIVER",
				"HAL_WORKER_INTEGRATION_IMAGE",
				"t.Skipf",
			},
		},
		{
			path: filepath.Join("..", "internal", "sandboxruntime", "rootlesspodman", "podman_integration_test.go"),
			markers: []string{
				"//go:build podman_integration",
				"HAL_PODMAN_" + "TEST_IMAGE",
				"podman executable not found; skipping Podman integration test",
				"HAL_PODMAN_" + "TEST_IMAGE is unset",
				"t.Skip",
			},
		},
	} {
		source := phase49ReadFile(t, req.path)
		for _, marker := range req.markers {
			if !strings.Contains(source, marker) {
				t.Fatalf("%s missing live-gate or skip marker %q", phase34FirecrackerDisplayPath(t, req.path), marker)
			}
		}
	}
}

func TestPhase49DefaultGuardFilesStayInDefaultSuite(t *testing.T) {
	for _, path := range []string{
		"default_fake_only_e2e_test.go",
		"phase49_live_provider_gates_test.go",
	} {
		source := phase49ReadFile(t, path)
		header := phase19SourceHeader(source)
		for _, tag := range []string{
			"integration",
			"worker_integration",
			"podman_integration",
			"firecracker_live",
			"network_enforcement_live",
			"credential_delivery_live",
		} {
			if strings.Contains(header, tag) {
				t.Fatalf("%s uses build tag %q; Phase 49 default live-gate guards must run under go test ./cmd", path, tag)
			}
		}
	}
}

func TestPhase49LiveProviderGatesDocPathStable(t *testing.T) {
	if got, want := phase49LiveProviderGatesDocPath, "sandbox-runtime-v2-phase49-live-provider-gates-verification.md"; got != want {
		t.Fatalf("phase49 live-provider gates doc path = %q, want %q", got, want)
	}
}

func readPhase49LiveProviderGatesDoc(t *testing.T) string {
	t.Helper()
	return phase49ReadFile(t, filepath.Join("..", "docs", "design", phase49LiveProviderGatesDocPath))
}

func phase49ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}

func phase49AssertDocumentedDefaultCommands(t *testing.T, doc string) {
	t.Helper()
	commands := phase34DocumentedShellCommands(doc)
	for _, want := range []string{
		"go test -count=1 ./cmd -run 'Test(US006DefaultFakeOnly|Phase49LiveProvider)'",
		"go test ./...",
		"go test -count=1 -run '^$' ./...",
		"go vet ./...",
		"make docs-check",
		"make build",
		"git diff --check",
	} {
		if !commands[want] {
			t.Fatalf("phase 49 live-provider gate documentation missing command line %q", want)
		}
	}
}

func phase49DocumentedDefaultCommands(doc string) []string {
	var commands []string
	for _, command := range phase34AllGoTestCommands(doc) {
		commands = append(commands, command)
	}
	return commands
}

func phase49ForbiddenDefaultCommandMarkers() []string {
	return []string{
		"-tags=integration",
		"-tags=worker_integration",
		"-tags=podman_integration",
		"-tags=firecracker_live",
		"-tags=network_enforcement_live",
		"-tags=credential_delivery_live",
		"worker_integration",
		"podman_integration",
		"firecracker_live",
		"network_enforcement_live",
		"credential_delivery_live",
		"HAL_FIRECRACKER_LIVE",
		"HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_CREDENTIAL_DELIVERY_LIVE",
		"HAL_WORKER_INTEGRATION_",
		"HAL_PODMAN_" + "TEST_IMAGE",
		"DOCKER_HOST",
		"SSH_AUTH_SOCK",
		"OPENAI_API_KEY=",
		"Authorization:",
		"Bearer ",
		"token=",
		"secret=",
		"docker ",
		"podman ",
		"firecracker ",
		"/dev/kvm",
		"curl ",
		"hal sandboxd",
		"--live",
	}
}

func phase49MarkerWindowContains(doc, marker, want string) bool {
	index := strings.Index(doc, marker)
	if index < 0 {
		return false
	}
	start := index - 160
	if start < 0 {
		start = 0
	}
	end := index + len(marker) + 220
	if end > len(doc) {
		end = len(doc)
	}
	return strings.Contains(strings.ToLower(doc[start:end]), strings.ToLower(want))
}
