package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL6PolicyProxyArchitectureAndVerificationDocs(t *testing.T) {
	for _, tt := range []struct {
		path    string
		markers []string
	}{
		{
			path: filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l6-policy-proxy-architecture.md"),
			markers: []string{
				"issue #49",
				"policyproxy",
				"DNS-rebinding",
				"All resolved addresses must pass",
				"ambient proxy discovery disabled",
				"proxy-only",
				"L7",
				"Non-Linux builds",
			},
		},
		{
			path: filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l6-policy-proxy-verification.md"),
			markers: []string{
				"TestL6PolicyProxyLiveHTTPAndConnect",
				"never skips",
				"HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=1",
				"go test -race",
				"go vet ./...",
				"make docs-check",
				"cross-platform",
			},
		},
	} {
		payload, err := os.ReadFile(tt.path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", tt.path, err)
		}
		text := string(payload)
		for _, marker := range tt.markers {
			if !strings.Contains(text, marker) {
				t.Errorf("%s missing %q", tt.path, marker)
			}
		}
	}
}
