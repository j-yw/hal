package sandboxworker

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

const sandboxworkerPackagePath = "github.com/jywlabs/hal/internal/sandboxworker"

var forbiddenSandboxworkerImports = []sandboxworkerForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{
		name:  "cmd package",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/cmd"),
	},
	{
		name:  "factory run record package",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/factory"),
	},
	{
		name:  "PRD package",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/prd"),
	},
	{
		name:  "command-specific auto code",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/compound"),
	},
	{
		name:  "command-specific loop code",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/loop"),
	},
	{
		name:  "durable sandbox state package",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox"),
	},
	{
		name:  "concrete SSH-machine runtime adapter",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"),
	},
	{
		name:  "concrete rootless Podman runtime adapter",
		match: sandboxworkerModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"),
	},
}

func TestSandboxworkerImportsStayCommandAgnostic(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", sandboxworkerPackagePath, err)
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
			if message := sandboxworkerImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSandboxworkerForbiddenImportListCoversCommandCouplingSurfaces(t *testing.T) {
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
		{name: "durable sandbox state packages", importPath: "github.com/jywlabs/hal/internal/sandbox"},
		{name: "concrete SSH-machine runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"},
		{name: "concrete rootless Podman runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := sandboxworkerForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestSandboxworkerImportBoundaryAllowsRuntimeContractsOnly(t *testing.T) {
	for _, importPath := range []string{
		"fmt",
		"context",
		"github.com/jywlabs/hal/internal/sandboxruntime",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxworkerImportBoundaryMessage("types.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	const unapprovedInternalPackage = "github.com/jywlabs/hal/internal/template"
	if message := sandboxworkerImportBoundaryMessage("types.go", unapprovedInternalPackage); !strings.Contains(message, unapprovedInternalPackage) {
		t.Fatalf("boundary message = %q, want unapproved internal package %q", message, unapprovedInternalPackage)
	}
}

func TestSandboxworkerImportBoundaryRejectsExternalRuntimeProviders(t *testing.T) {
	for _, importPath := range []string{
		"github.com/docker/docker/client",
		"github.com/containers/podman/v5/pkg/bindings",
		"github.com/digitalocean/godo",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := sandboxworkerImportBoundaryMessage("types.go", importPath)
			if !strings.Contains(message, "non-standard-library dependency") || !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejection for external provider import %q", message, importPath)
			}
		})
	}
}

func TestSandboxworkerImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := sandboxworkerImportBoundaryMessage("types.go", importPath)
	if !strings.Contains(message, sandboxworkerPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, sandboxworkerPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func sandboxworkerImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxworkerForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxworkerPackagePath, fileName, forbidden.name, importPath)
	}
	if sandboxworkerAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports non-standard-library dependency %q; worker code may only depend on standard library packages and root sandboxruntime contracts", sandboxworkerPackagePath, fileName, importPath)
}

func sandboxworkerForbiddenImportFor(importPath string) *sandboxworkerForbiddenImport {
	for i := range forbiddenSandboxworkerImports {
		if forbiddenSandboxworkerImports[i].match(importPath) {
			return &forbiddenSandboxworkerImports[i]
		}
	}
	return nil
}

func sandboxworkerAllowedImport(importPath string) bool {
	return sandboxworkerIsStandardLibraryImport(importPath) ||
		importPath == "github.com/jywlabs/hal/internal/sandboxruntime"
}

func sandboxworkerIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func sandboxworkerModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type sandboxworkerForbiddenImport struct {
	name  string
	match func(string) bool
}
