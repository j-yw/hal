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
	if forbidden := sandboxexecutionForbiddenImportFor(importPath); forbidden != nil {
		t.Fatalf("%s imports forbidden %s package %q", fileName, forbidden.name, importPath)
	}
	if strings.HasPrefix(importPath, internalPrefix) && !allowedInternalImports[importPath] {
		t.Fatalf("%s imports forbidden internal package %q", fileName, importPath)
	}
}

func TestSandboxexecutionForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "factory", importPath: "github.com/jywlabs/hal/internal/factory"},
		{name: "prd", importPath: "github.com/jywlabs/hal/internal/prd"},
		{name: "compound", importPath: "github.com/jywlabs/hal/internal/compound"},
		{name: "concrete provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/daytona"},
		{name: "concrete runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := sandboxexecutionForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

type sandboxexecutionForbiddenImport struct {
	name  string
	match func(string) bool
}

var sandboxexecutionForbiddenImports = []sandboxexecutionForbiddenImport{
	{
		name: "Cobra",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd", match: moduleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "compound", match: moduleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "factory", match: moduleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "prd", match: moduleImportMatcher("github.com/jywlabs/hal/internal/prd")},
	{name: "concrete sandbox provider adapter", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
	{name: "concrete sandbox runtime adapter", match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/sshmachine")},
	{
		name: "network",
		match: func(importPath string) bool {
			return importPath == "net" || strings.HasPrefix(importPath, "net/")
		},
	},
	{
		name: "Docker-related",
		match: func(importPath string) bool {
			return strings.Contains(strings.ToLower(importPath), "docker")
		},
	},
	{
		name: "Podman-related",
		match: func(importPath string) bool {
			return strings.Contains(strings.ToLower(importPath), "podman")
		},
	},
}

func sandboxexecutionForbiddenImportFor(importPath string) *sandboxexecutionForbiddenImport {
	for i := range sandboxexecutionForbiddenImports {
		if sandboxexecutionForbiddenImports[i].match(importPath) {
			return &sandboxexecutionForbiddenImports[i]
		}
	}
	return nil
}

func moduleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}
