package sandboxworkspace

import (
	"fmt"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const sandboxworkspacePackagePath = "github.com/jywlabs/hal/internal/sandboxworkspace"

var forbiddenSyncOutImports = []syncOutForbiddenImport{
	{
		name: "Cobra package",
		match: func(importPath string) bool {
			return importPath == "github.com/spf13/cobra" || strings.Contains(importPath, "/cobra")
		},
	},
	{name: "cmd package", match: syncOutModuleImportMatcher("github.com/jywlabs/hal/cmd")},
	{name: "factory package", match: syncOutModuleImportMatcher("github.com/jywlabs/hal/internal/factory")},
	{name: "engine package", match: syncOutModuleImportMatcher("github.com/jywlabs/hal/internal/engine")},
	{name: "loop package", match: syncOutModuleImportMatcher("github.com/jywlabs/hal/internal/loop")},
	{name: "PRD package", match: syncOutModuleImportMatcher("github.com/jywlabs/hal/internal/prd")},
	{name: "compound package", match: syncOutModuleImportMatcher("github.com/jywlabs/hal/internal/compound")},
	{name: "worker client package", match: syncOutModuleImportMatcher("github.com/jywlabs/hal/internal/sandboxworker")},
	{name: "concrete provider adapter package", match: syncOutModuleImportMatcher("github.com/jywlabs/hal/internal/sandbox/provider")},
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

func TestSyncOutImportBoundaries(t *testing.T) {
	paths, err := filepath.Glob("sync_out*.go")
	if err != nil {
		t.Fatalf("Glob(sync_out*.go) error: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no sync-out contract files matched sync_out*.go")
	}

	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := syncOutImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
	}
}

func TestSyncOutForbiddenImportListCoversRequiredBoundaries(t *testing.T) {
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
		{name: "concrete provider adapter", importPath: "github.com/jywlabs/hal/internal/sandbox/provider/daytona"},
		{name: "concrete SSH-machine runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"},
		{name: "concrete rootless Podman runtime adapter", importPath: "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"},
		{name: "standard network client", importPath: "net/http"},
		{name: "external Docker client", importPath: "github.com/docker/docker/client"},
		{name: "external Podman bindings", importPath: "github.com/containers/podman/v5/pkg/bindings"},
		{name: "external cloud provider client", importPath: "github.com/digitalocean/godo"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if forbidden := syncOutForbiddenImportFor(tt.importPath); forbidden == nil {
				t.Fatalf("forbidden import list does not include %s import path %q", tt.name, tt.importPath)
			}
		})
	}
}

func TestSyncOutImportBoundaryAllowsStableContractsOnly(t *testing.T) {
	for _, importPath := range []string{
		"context",
		"fmt",
		"github.com/jywlabs/hal/internal/sandbox",
		"github.com/jywlabs/hal/internal/sandboxruntime",
	} {
		t.Run(importPath, func(t *testing.T) {
			if message := syncOutImportBoundaryMessage("sync_out.go", importPath); message != "" {
				t.Fatalf("import %q unexpectedly failed boundary check: %s", importPath, message)
			}
		})
	}

	for _, importPath := range []string{
		"github.com/jywlabs/hal/internal/sandboxexec",
		"github.com/jywlabs/hal/internal/sandboxexecution",
		"github.com/jywlabs/hal/internal/template",
		"github.com/docker/docker/client",
	} {
		t.Run(importPath, func(t *testing.T) {
			message := syncOutImportBoundaryMessage("sync_out.go", importPath)
			if !strings.Contains(message, importPath) {
				t.Fatalf("boundary message = %q, want rejected import path %q", message, importPath)
			}
		})
	}
}

func TestSyncOutImportBoundaryMessageIncludesPackageAndForbiddenImport(t *testing.T) {
	const importPath = "github.com/spf13/cobra"
	message := syncOutImportBoundaryMessage("sync_out.go", importPath)
	if !strings.Contains(message, sandboxworkspacePackagePath) {
		t.Fatalf("message %q does not include offending package %q", message, sandboxworkspacePackagePath)
	}
	if !strings.Contains(message, importPath) {
		t.Fatalf("message %q does not include forbidden import path %q", message, importPath)
	}
}

func syncOutImportBoundaryMessage(fileName, importPath string) string {
	if forbidden := syncOutForbiddenImportFor(importPath); forbidden != nil {
		return fmt.Sprintf("package %s file %s imports forbidden %s %q", sandboxworkspacePackagePath, fileName, forbidden.name, importPath)
	}
	if syncOutAllowedImport(importPath) {
		return ""
	}
	return fmt.Sprintf("package %s file %s imports non-standard-library dependency %q; sync-out contracts may only depend on standard library packages and stable sandbox metadata/runtime contracts", sandboxworkspacePackagePath, fileName, importPath)
}

func syncOutForbiddenImportFor(importPath string) *syncOutForbiddenImport {
	for i := range forbiddenSyncOutImports {
		if forbiddenSyncOutImports[i].match(importPath) {
			return &forbiddenSyncOutImports[i]
		}
	}
	return nil
}

func syncOutAllowedImport(importPath string) bool {
	return syncOutIsStandardLibraryImport(importPath) ||
		importPath == "github.com/jywlabs/hal/internal/sandbox" ||
		importPath == "github.com/jywlabs/hal/internal/sandboxruntime"
}

func syncOutIsStandardLibraryImport(importPath string) bool {
	firstSegment := strings.Split(importPath, "/")[0]
	return !strings.Contains(firstSegment, ".")
}

func syncOutModuleImportMatcher(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

type syncOutForbiddenImport struct {
	name  string
	match func(string) bool
}
