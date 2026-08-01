package cmd

import (
	"os"
	"os/exec"
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
	command := exec.Command("go", "test", "-list", "TestFirecrackerHostTopology|TestLinuxTAP|TestProductionProxy",
		"./internal/sandboxruntime/microvm/firecrackerhost/l7network")
	command.Dir = ".."
	listed, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("list documented L7 host selectors: %v", err)
	}
	for _, selector := range []string{"TestFirecrackerHostTopology", "TestLinuxTAP", "TestProductionProxy"} {
		if !strings.Contains(string(listed), selector) {
			t.Fatalf("documented L7 host selector %q matched no tests: %s", selector, listed)
		}
	}
}
