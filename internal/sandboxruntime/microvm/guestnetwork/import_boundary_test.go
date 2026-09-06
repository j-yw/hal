package guestnetwork

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL7GuestNetworkProductionBoundaryExcludesOrchestrationAndArbitraryTransport(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(".", entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"github.com/jywlabs/hal/cmd",
				"github.com/jywlabs/hal/internal/factory",
				"github.com/jywlabs/hal/internal/sandboxworker",
				"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker",
				"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman",
				"os/exec", "net/http",
			} {
				if strings.HasPrefix(importPath, forbidden) {
					t.Fatalf("%s imports forbidden dependency %q", path, importPath)
				}
			}
		}
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"os.LookupEnv", "os.Environ", "exec.Command", "CommandContext", "HAL_L7_"} {
			if strings.Contains(string(source), forbidden) {
				t.Fatalf("%s contains arbitrary transport marker %q", path, forbidden)
			}
		}
	}
}
