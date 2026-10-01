package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestPhase49OptionalLiveTestFilesStayGatedAndSkipWithoutConfig(t *testing.T) {
	for _, req := range []struct {
		path    string
		markers []string
	}{
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

func phase49ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}
