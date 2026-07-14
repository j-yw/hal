package rootlesspodman

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

const rootlessPodmanPackagePath = "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"

var forbiddenRootlessPodmanImports = []rootlessPodmanForbiddenImport{
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
	{
		name:  "sandbox execution record package",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution"),
	},
	{
		name:  "sandbox target selection package",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxtarget"),
	},
	{
		name:  "worker protocol package",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker"),
	},
	{
		name:  "concrete SSH-machine runtime adapter",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"),
	},
	{
		name:  "concrete provider adapter",
		match: moduleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider"),
	},
}

func TestRootlessPodmanImportsStayCommandAgnostic(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", rootlessPodmanPackagePath, err)
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
			if message := rootlessPodmanImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestRootlessPodmanForbiddenImportListCoversCommandCouplingSurfaces(t *testing.T) {
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
		{name: "sandbox execution record packages", importPath: "github.com/jywlabs/hal/internal/sandboxexecution"},
		{name: "sandbox target selection packages", importPath: "github.com/jywlabs/hal/internal/sandboxtarget"},
		{name: "worker protocol packages", importPath: "github.com/jywlabs/hal/internal/sandboxworker"},
		{name: "SSH-machine runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"},
		{name: "concrete provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/hetzner"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := rootlessPodmanForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestRootlessPodmanImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := rootlessPodmanImportBoundaryMessage("driver.go", importPath)
	if !strings.Contains(message, rootlessPodmanPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, rootlessPodmanPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func rootlessPodmanImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := rootlessPodmanForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", rootlessPodmanPackagePath, fileName, forbidden.name, importPath)
	}
	return ""
}

func rootlessPodmanForbiddenImportFor(importPath string) *rootlessPodmanForbiddenImport {
	for i := range forbiddenRootlessPodmanImports {
		if forbiddenRootlessPodmanImports[i].match(importPath) {
			return &forbiddenRootlessPodmanImports[i]
		}
	}
	return nil
}

func moduleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type rootlessPodmanForbiddenImport struct {
	name  string
	match func(string) bool
}
