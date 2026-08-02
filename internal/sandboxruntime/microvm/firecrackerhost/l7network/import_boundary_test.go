package l7network_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFirecrackerHostTopologyImportBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(".", entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(path, "github.com/jywlabs/hal/") && !allowedHostTopologyImport(path) {
				t.Fatalf("production file %s imports forbidden cross-lane package %q", entry.Name(), path)
			}
		}
	}
}

func allowedHostTopologyImport(path string) bool {
	return path == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement" ||
		path == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules" ||
		path == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology" ||
		path == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
}

func TestFirecrackerHostTopologyIsNotWiredIntoDefaultPaths(t *testing.T) {
	parent := ".."
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		if entry.Name() == "l7_runtime_controller.go" {
			continue
		}
		payload, err := os.ReadFile(filepath.Join(parent, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(payload), "firecrackerhost/l7network") || strings.Contains(string(payload), "l7network.New(") {
			t.Fatalf("default Firecracker host path %s wires explicit L7 topology", entry.Name())
		}
	}
}

func TestFirecrackerHostTopologyProductionSourceForbidsGlobalNetworkMutation(t *testing.T) {
	for _, name := range []string{"tap.go", "tap_command_linux.go"} {
		payload, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(payload))
		for _, forbidden := range []string{"iptables", "masquerade", " snat", " dnat", "sudo", "0.0.0.0", "listen("} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("production file %s contains forbidden marker %q", name, forbidden)
			}
		}
	}
}
