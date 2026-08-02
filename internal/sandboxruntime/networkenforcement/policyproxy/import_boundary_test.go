package policyproxy

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL6PolicyProxyImportBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if allowedL6PolicyProxyImport(importPath) {
				continue
			}
			t.Errorf("%s imports out-of-scope dependency %q", name, importPath)
		}
	}
}

func allowedL6PolicyProxyImport(importPath string) bool {
	if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement" {
		return true
	}
	return !strings.Contains(importPath, ".") && importPath != "os/exec" && importPath != "syscall"
}
