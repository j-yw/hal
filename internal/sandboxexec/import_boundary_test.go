package sandboxexec

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

const sandboxexecPackagePath = "github.com/jywlabs/hal/internal/sandboxexec"

var sandboxexecForbiddenImports = []sandboxexecForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: sandboxexecModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "engine package", match: sandboxexecModuleImportMatcher("github.com/jywlabs/hal/internal/engine")},
	{name: "compound package", match: sandboxexecModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "loop package", match: sandboxexecModuleImportMatcher("github.com/jywlabs/hal/internal/loop")},
	{name: "factory package", match: sandboxexecModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "PRD package", match: sandboxexecModuleImportMatcher("github.com/jywlabs/hal/internal/prd")},
	{name: "template package", match: sandboxexecModuleImportMatcher("github.com/jywlabs/hal/internal/template")},
	{name: "worker protocol package", match: sandboxexecModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{
		name: "concrete sandbox runtime adapter package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/")
		},
	},
	{name: "concrete sandbox provider adapter package", match: sandboxexecModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
}

func TestSandboxexecDoesNotImportCommandOrProviderLayers(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", sandboxexecPackagePath, err)
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
			if message := sandboxexecImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSandboxexecForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "engine packages", importPath: "github.com/jywlabs/hal/internal/engine"},
		{name: "factory packages", importPath: "github.com/jywlabs/hal/internal/factory"},
		{name: "PRD packages", importPath: "github.com/jywlabs/hal/internal/prd"},
		{name: "template packages", importPath: "github.com/jywlabs/hal/internal/template"},
		{name: "command-specific auto code", importPath: "github.com/jywlabs/hal/internal/compound"},
		{name: "command-specific loop code", importPath: "github.com/jywlabs/hal/internal/loop"},
		{name: "worker protocol packages", importPath: "github.com/jywlabs/hal/internal/sandboxworker"},
		{name: "concrete SSH-machine runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"},
		{name: "concrete rootless Podman runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"},
		{name: "concrete provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/hetzner"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := sandboxexecForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestSandboxexecImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := sandboxexecImportBoundaryMessage("executor.go", importPath)
	if !strings.Contains(message, sandboxexecPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, sandboxexecPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func sandboxexecImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxexecForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxexecPackagePath, fileName, forbidden.name, importPath)
	}
	return ""
}

func sandboxexecForbiddenImportFor(importPath string) *sandboxexecForbiddenImport {
	for i := range sandboxexecForbiddenImports {
		if sandboxexecForbiddenImports[i].match(importPath) {
			return &sandboxexecForbiddenImports[i]
		}
	}
	return nil
}

func sandboxexecModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type sandboxexecForbiddenImport struct {
	name  string
	match func(string) bool
}
