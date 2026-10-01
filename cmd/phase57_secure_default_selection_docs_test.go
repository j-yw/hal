package cmd

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestPhase57CommandFactoryStatusSurfacesRemainRenderOnlyConsumers(t *testing.T) {
	for _, path := range phase57CommandFactoryStatusProductionFiles(t) {
		if filepath.Base(path) == "sandbox_template_selection.go" {

			continue
		}
		source := phase50ReadFile(t, path)
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", phase50SafeDisplayPath(path), err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, phase50SafeDisplayPath(path), err)
			}
			if message := phase57RenderOnlyImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
		if message := phase57RenderOnlySourceBoundaryMessage(path, source); message != "" {
			t.Fatal(message)
		}
	}
}

func TestPhase57RenderOnlyBoundaryRejectsUnsafeFixtures(t *testing.T) {
	for _, tt := range []struct {
		name       string
		source     string
		importPath string
		want       string
	}{
		{
			name:   "secure default policy evaluator",
			source: `package cmd; func run() { _ = sandbox.EvaluateSandboxSecureDefaultReadiness }`,
			want:   "EvaluateSandboxSecureDefaultReadiness",
		},
		{
			name:   "secure default diagnostic projection",
			source: `package cmd; func run() { _ = sandbox.ProjectSandboxSecureDefaultReadinessDiagnostics }`,
			want:   "ProjectSandboxSecureDefaultReadinessDiagnostics",
		},
		{
			name:   "target proof construction",
			source: `package cmd; func run() { _ = targetSelectionRequestedSecureDefaultReadinessInput }`,
			want:   "targetSelectionRequestedSecureDefaultReadinessInput",
		},
		{
			name:       "template acquisition implementation import",
			importPath: "github.com/jywlabs/hal/internal/sandboxtemplate/acquisition",
			want:       "template acquisition implementation",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.importPath != "" {
				message := phase57RenderOnlyImportBoundaryMessage("fixture.go", tt.importPath)
				if !strings.Contains(message, tt.want) {
					t.Fatalf("import boundary message = %q, want %q", message, tt.want)
				}
				return
			}
			message := phase57RenderOnlySourceBoundaryMessage("fixture.go", tt.source)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("source boundary message = %q, want %q", message, tt.want)
			}
		})
	}
}

func phase57CommandFactoryStatusProductionFiles(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, root := range []string{".", filepath.Join("..", "internal", "factory")} {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("ReadDir(%s) error: %v", phase50SafeDisplayPath(root), err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			paths = append(paths, filepath.Join(root, name))
		}
	}
	if len(paths) == 0 {
		t.Fatal("Phase 57 render-only boundary matched no command/factory production files")
	}
	sort.Strings(paths)
	return paths
}

func phase57RenderOnlyImportBoundaryMessage(fileName, importPath string) string {
	switch {
	case importPath == "github.com/jywlabs/hal/internal/sandboxtemplate/acquisition" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/"):
		return phase50SafeDisplayPath(fileName) + " imports forbidden Phase 59 template acquisition implementation package " + importPath
	}
	return ""
}

func phase57RenderOnlySourceBoundaryMessage(fileName, source string) string {
	for _, forbidden := range []struct {
		token  string
		reason string
	}{
		{token: "EvaluateSandboxSecureDefaultReadiness", reason: "secure-default policy evaluation"},
		{token: "ProjectSandboxSecureDefaultReadinessDiagnostics", reason: "secure-default diagnostic projection"},
		{token: "targetSelectionRequestedSecureDefaultReadinessInput", reason: "target-selection proof construction"},
		{token: "EvaluateTrustPolicy", reason: "Phase 59 template trust policy evaluation"},
		{token: "ResolveOCIArtifact", reason: "Phase 59 template acquisition"},
	} {
		if strings.Contains(source, forbidden.token) {
			return phase50SafeDisplayPath(fileName) + " contains forbidden " + forbidden.reason + " marker " + forbidden.token
		}
	}
	return ""
}
