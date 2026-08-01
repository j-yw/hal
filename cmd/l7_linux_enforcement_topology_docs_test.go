package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL7LinuxEnforcementTopologyFocusedDocsRunHostPackageTests(t *testing.T) {
	path := filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l7-linux-enforcement-topology-verification.md")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const packageSelector = "./internal/sandboxruntime/microvm/firecrackerhost/l7network"
	if got := strings.Count(string(payload), packageSelector); got < 2 {
		t.Fatalf("L7 verification docs contain host topology package selector %d times, want focused and race gates", got)
	}
	for _, selector := range []string{"TestFirecrackerHostTopology", "TestLinuxTAP", "TestProductionProxy"} {
		if !strings.Contains(string(payload), selector) {
			t.Fatalf("L7 verification docs focused selector omits %q host topology tests", selector)
		}
	}
}
