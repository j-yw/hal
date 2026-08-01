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

const modulePrefix = "github.com/jywlabs/hal/"

func TestL7NetworkCompositionImportBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if (strings.HasPrefix(path, modulePrefix) || strings.HasPrefix(path, "golang.org/")) && !allowedCompositionImport(path) {
				t.Fatalf("composition file %s imports unrelated package %q", name, path)
			}
		}
	}
}

func TestL7NetworkCompositionBoundaryForbidsCrossLayerPackages(t *testing.T) {
	for _, path := range []string{
		"github.com/jywlabs/hal/cmd", "github.com/jywlabs/hal/internal/factory", "github.com/jywlabs/hal/internal/sandboxworker",
		"github.com/jywlabs/hal/internal/sandboxexecution", "github.com/jywlabs/hal/internal/sandboxworkspace",
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm", "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker",
		"github.com/jywlabs/hal/internal/sandboxruntime/sshmachine", "github.com/jywlabs/hal/internal/sandbox/provider",
	} {
		if allowedCompositionImport(path) {
			t.Fatalf("guard unexpectedly allows cross-layer import %q", path)
		}
	}
}

func allowedCompositionImport(path string) bool {
	switch path {
	case "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman", "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement", "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules", "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy", "golang.org/x/sys/unix":
		return true
	default:
		return false
	}
}
