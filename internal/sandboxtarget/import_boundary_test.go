package sandboxtarget

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

const sandboxtargetPackagePath = "github.com/jywlabs/hal/internal/sandboxtarget"

var forbiddenSandboxtargetImports = []sandboxtargetForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: sandboxtargetModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory package", match: sandboxtargetModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "engine package", match: sandboxtargetModuleImportMatcher("github.com/jywlabs/hal/internal/engine")},
	{name: "loop package", match: sandboxtargetModuleImportMatcher("github.com/jywlabs/hal/internal/loop")},
	{name: "PRD package", match: sandboxtargetModuleImportMatcher("github.com/jywlabs/hal/internal/prd")},
	{name: "compound package", match: sandboxtargetModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "worker client package", match: sandboxtargetModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "sandbox execution package", match: sandboxtargetModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexec")},
	{name: "sandbox execution record package", match: sandboxtargetModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxexecution")},
	{name: "sandbox workspace package", match: sandboxtargetModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworkspace")},
	{
		name: "concrete runtime adapter package",
		match: func(importPath string) bool {
			return strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/")
		},
	},
	{
		name: "network-only package",
		match: func(importPath string) bool {
			switch importPath {
			case "net", "net/http", "net/rpc":
				return true
			default:
				return strings.HasPrefix(importPath, "net/http/") ||
					strings.HasPrefix(importPath, "google.golang.org/grpc") ||
					strings.HasPrefix(importPath, "github.com/docker/docker") ||
					strings.HasPrefix(importPath, "github.com/containers/podman") ||
					strings.HasPrefix(importPath, "github.com/digitalocean/godo") ||
					strings.HasPrefix(importPath, "cloud.google.com/go") ||
					strings.HasPrefix(importPath, "github.com/aws/aws-sdk-go")
			}
		},
	},
}

func TestSandboxtargetImportsStayCommandAgnostic(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(%s) error: %v", sandboxtargetPackagePath, err)
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
			if message := sandboxtargetImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSandboxtargetForbiddenImportListCoversCommandCouplingSurfaces(t *testing.T) {
	for _, tt := range []struct {
		name       string
		importPath string
	}{
		{name: "Cobra", importPath: "github.com/spf13/cobra"},
		{name: "cmd packages", importPath: "github.com/jywlabs/hal/cmd"},
		{name: "factory packages", importPath: "github.com/jywlabs/hal/internal/factory"},
		{name: "engine packages", importPath: "github.com/jywlabs/hal/internal/engine"},
		{name: "loop packages", importPath: "github.com/jywlabs/hal/internal/loop"},
		{name: "PRD packages", importPath: "github.com/jywlabs/hal/internal/prd"},
		{name: "compound packages", importPath: "github.com/jywlabs/hal/internal/compound"},
		{name: "worker client packages", importPath: "github.com/jywlabs/hal/internal/sandboxworker"},
		{name: "sandbox execution packages", importPath: "github.com/jywlabs/hal/internal/sandboxexec"},
		{name: "sandbox execution record packages", importPath: "github.com/jywlabs/hal/internal/sandboxexecution"},
		{name: "sandbox workspace packages", importPath: "github.com/jywlabs/hal/internal/sandboxworkspace"},
		{name: "concrete SSH-machine runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"},
		{name: "concrete rootless Podman runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"},
		{name: "standard network client", importPath: "net/http"},
		{name: "external Docker client", importPath: "github.com/docker/docker/client"},
		{name: "external cloud provider client", importPath: "github.com/digitalocean/godo"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := sandboxtargetForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestSandboxtargetImportBoundaryAllowsStableContractsOnly(t *testing.T) {
	for _, importPath := range []string{
		"context",
		"fmt",
		"github.com/jywlabs/hal/internal/sandbox",
		"github.com/jywlabs/hal/internal/sandboxruntime",
		"github.com/jywlabs/hal/internal/strictcomposition",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := sandboxtargetImportBoundaryMessage("types.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"github.com/jywlabs/hal/internal/template",
		"github.com/docker/docker/client",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := sandboxtargetImportBoundaryMessage("types.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func TestSandboxtargetImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := sandboxtargetImportBoundaryMessage("types.go", importPath)
	if !strings.Contains(message, sandboxtargetPackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, sandboxtargetPackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func sandboxtargetImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := sandboxtargetForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxtargetPackagePath, fileName, forbidden.name, importPath)
	}
	if sandboxtargetAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports non-standard-library dependency %q; target selection may only depend on standard library packages and stable sandbox metadata/runtime contracts", sandboxtargetPackagePath, fileName, importPath)
}

func sandboxtargetForbiddenImportFor(importPath string) *sandboxtargetForbiddenImport {
	for i := range forbiddenSandboxtargetImports {
		if forbiddenSandboxtargetImports[i].match(importPath) {
			return &forbiddenSandboxtargetImports[i]
		}
	}
	return nil
}

func sandboxtargetAllowedImport(importPath string) bool {
	return sandboxtargetIsStandardLibraryImport(importPath) ||
		importPath == "github.com/jywlabs/hal/internal/sandbox" ||
		importPath == "github.com/jywlabs/hal/internal/sandboxruntime" ||
		importPath == "github.com/jywlabs/hal/internal/strictcomposition"
}

func sandboxtargetIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func sandboxtargetModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type sandboxtargetForbiddenImport struct {
	name  string
	match func(string) bool
}
