package sandboxexecution

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPackageImportBoundaries(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(package) error: %v", err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", name, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, name, err)
			}
			assertAllowedImport(t, name, importPath)
		}
	}
}

func assertAllowedImport(t *testing.T, fileName, importPath string) {
	t.Helper()
	const internalPrefix = "github.com/jywlabs/hal/internal/"
	allowedInternalImports := map[string]bool{
		"github.com/jywlabs/hal/internal/sandbox":        true,
		"github.com/jywlabs/hal/internal/sandboxruntime": true,
		"github.com/jywlabs/hal/internal/template":       true,
	}
	if strings.HasPrefix(importPath, internalPrefix) && !allowedInternalImports[importPath] {
		t.Fatalf("%s imports forbidden internal package %q", fileName, importPath)
	}
	switch {
	case importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra"):
		t.Fatalf("%s imports Cobra package %q", fileName, importPath)
	case importPath == "net" || strings.HasPrefix(importPath, "net/"):
		t.Fatalf("%s imports network package %q", fileName, importPath)
	case strings.Contains(strings.ToLower(importPath), "docker"):
		t.Fatalf("%s imports Docker-related package %q", fileName, importPath)
	case strings.Contains(strings.ToLower(importPath), "podman"):
		t.Fatalf("%s imports Podman-related package %q", fileName, importPath)
	}
}
