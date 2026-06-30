package sandboxruntime

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const sandboxruntimePackagePath = "github.com/jywlabs/hal/internal/sandboxruntime"

var forbiddenSandboxruntimeImports = []sandboxruntimeForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{
		name:  "cmd package",
		match: moduleImportMatcher("github.com/jywlabs/hal/cmd"),
	},
	{
		name:  "factory run record package",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/factory"),
	},
	{
		name:  "PRD package",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/prd"),
	},
	{
		name:  "command-specific auto code",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/compound"),
	},
	{
		name:  "command-specific loop code",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/loop"),
	},
}

func TestSandboxruntimeImportsStayCommandAgnostic(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", sandboxruntimePackagePath, err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := sandboxruntimeImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSandboxruntimeForbiddenImportListCoversCommandCouplingSurfaces(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "factory run record packages", importPath: "github.com/jywlabs/hal/internal/factory"},
		{name: "PRD packages", importPath: "github.com/jywlabs/hal/internal/prd"},
		{name: "command-specific auto code", importPath: "github.com/jywlabs/hal/internal/compound"},
		{name: "command-specific loop code", importPath: "github.com/jywlabs/hal/internal/loop"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := sandboxruntimeForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestSandboxruntimeImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := sandboxruntimeImportBoundaryMessage("types.go", importPath)
	if !strings.Contains(message, sandboxruntimePackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, sandboxruntimePackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func sandboxruntimeImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxruntimeForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxruntimePackagePath, fileName, forbidden.name, importPath)
	}
	if !isStandardLibraryImport(importPath) {
		return fmt.Sprintf("package %s file %s imports non-standard-library dependency %q; keep runtime boundary contracts standard-library only", sandboxruntimePackagePath, fileName, importPath)
	}
	return ""
}

func sandboxruntimeForbiddenImportFor(importPath string) *sandboxruntimeForbiddenImport {
	for i := range forbiddenSandboxruntimeImports {
		if forbiddenSandboxruntimeImports[i].match(importPath) {
			return &forbiddenSandboxruntimeImports[i]
		}
	}
	return nil
}

func isStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func moduleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type sandboxruntimeForbiddenImport struct {
	name  string
	match func(string) bool
}
