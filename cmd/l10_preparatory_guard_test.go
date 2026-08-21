package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	l10PreparatoryDocument = "../docs/design/sandbox-runtime-v2-l10-strict-composition.md"
	l10AggregateBase       = "c3922c2dc0b11d2e731d451e669d8c3c1ba1444b"
)

var l10ForbiddenProductionCalls = map[string]map[string]struct{}{
	"github.com/jywlabs/hal/internal/strictcomposition": {
		"EvaluateActive":   {},
		"EvaluateTerminal": {},
	},
	"github.com/jywlabs/hal/internal/sandboxruntime": {
		"NewJobCredentialActiveProof":  {},
		"NewJobCredentialCleanupProof": {},
	},
}

func TestL10PreparatoryStateIsExplicit(t *testing.T) {
	payload, err := os.ReadFile(l10PreparatoryDocument)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(payload)
	for _, required := range []string{
		l10AggregateBase,
		"L10 remains unaccepted and default-off.",
		"No selected L10 live lane exists in this preparatory slice.",
		"No production caller invokes `EvaluateActive` or `EvaluateTerminal`.",
		"Production code does not construct `JobCredentialActiveProof` or `JobCredentialCleanupProof` for L10.",
		"L11 remains dependency-blocked on accepted L8 and L10 live authority.",
	} {
		if !strings.Contains(doc, required) {
			t.Errorf("L10 preparatory document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"357090101f8479ed11a6a84976787a9c09a1f4ff",
		"accepted L3, L5, L7, L8, and L9 handoffs",
		"-tags=l10_strict_composition_integration",
		"TestL10PreparedLinuxStrictCompositionE2E",
	} {
		if strings.Contains(doc, forbidden) {
			t.Errorf("L10 preparatory document retains unavailable-live claim %q", forbidden)
		}
	}
}

func TestL10PreparatoryRepositoryHasNoSelectedLiveLaneOrProductionAuthorityMinting(t *testing.T) {
	repositoryRoot := filepath.Clean("..")
	integrationTag := "l10_strict_" + "composition_integration"
	selectedTest := "TestL10PreparedLinux" + "StrictCompositionE2E"
	selectedFile := "l10_prepared_linux_" + "integration_test.go"

	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || filepath.Ext(path) != ".go" {
			return nil
		}
		if entry.Name() == selectedFile {
			t.Errorf("selected L10 live file exists: %s", filepath.ToSlash(path))
		}

		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		for _, commentGroup := range parsed.Comments {
			for _, comment := range commentGroup.List {
				if strings.HasPrefix(comment.Text, "//go:build") && strings.Contains(comment.Text, integrationTag) {
					t.Errorf("selected L10 live build tag exists in %s", filepath.ToSlash(path))
				}
			}
		}
		for _, declaration := range parsed.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == selectedTest {
				t.Errorf("selected L10 live test exists in %s", filepath.ToSlash(path))
			}
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if call := l10ForbiddenProductionCall(parsed, filepath.ToSlash(path)); call != "" {
			t.Errorf("production file %s calls unavailable authority %s", filepath.ToSlash(path), call)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan L10 preparatory boundary: %v", err)
	}
}

func TestL10PreparatoryGuardRejectsEveryAuthorityReference(t *testing.T) {
	tests := []struct {
		name, path, source string
		wantForbidden      bool
	}{
		{
			name: "evaluator function alias", path: "../cmd/wire.go", wantForbidden: true,
			source: "package cmd\nimport composition \"github.com/jywlabs/hal/internal/strictcomposition\"\nvar evaluate = composition.EvaluateActive\n",
		},
		{
			name: "evaluator passed indirectly", path: "../cmd/wire.go", wantForbidden: true,
			source: "package cmd\nimport . \"github.com/jywlabs/hal/internal/strictcomposition\"\nfunc accept(any) {}\nfunc wire() { accept((EvaluateTerminal)) }\n",
		},
		{
			name: "proof constructor method value", path: "../internal/factory/wire.go", wantForbidden: true,
			source: "package factory\nimport runtimeproof \"github.com/jywlabs/hal/internal/sandboxruntime\"\nvar mint = runtimeproof.NewJobCredentialActiveProof\n",
		},
		{
			name: "proof constructor indirect argument", path: "../internal/factory/wire.go", wantForbidden: true,
			source: "package factory\nimport runtimeproof \"github.com/jywlabs/hal/internal/sandboxruntime\"\nfunc accept(any) {}\nfunc wire() { accept(runtimeproof.NewJobCredentialCleanupProof) }\n",
		},
		{
			name: "same package evaluator alias", path: "../internal/strictcomposition/wire.go", wantForbidden: true,
			source: "package strictcomposition\nfunc EvaluateActive() {}\nvar evaluate = EvaluateActive\n",
		},
		{
			name: "shadowed import alias", path: "../cmd/safe.go",
			source: "package cmd\nimport composition \"github.com/jywlabs/hal/internal/strictcomposition\"\ntype fake struct{}\nfunc (fake) EvaluateActive() {}\nfunc safe() { composition := fake{}; _ = composition.EvaluateActive }\n",
		},
		{
			name: "unrelated method value", path: "../cmd/safe.go",
			source: "package cmd\ntype fake struct{}\nfunc (fake) EvaluateTerminal() {}\nvar safe = fake{}.EvaluateTerminal\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := parser.ParseFile(token.NewFileSet(), test.path, test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			forbidden := l10ForbiddenProductionCall(parsed, filepath.ToSlash(test.path)) != ""
			if forbidden != test.wantForbidden {
				t.Fatalf("guard forbidden = %t, want %t", forbidden, test.wantForbidden)
			}
		})
	}
}

func l10ForbiddenProductionCall(file *ast.File, path string) string {
	imports := make(map[string]string, len(file.Imports))
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		if _, guarded := l10ForbiddenProductionCalls[importPath]; !guarded {
			continue
		}
		name := filepath.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports[name] = importPath
	}

	var forbidden string
	ast.Inspect(file, func(node ast.Node) bool {
		if forbidden != "" {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch function := call.Fun.(type) {
		case *ast.SelectorExpr:
			qualifier, ok := function.X.(*ast.Ident)
			if !ok {
				return true
			}
			importPath := imports[qualifier.Name]
			if _, blocked := l10ForbiddenProductionCalls[importPath][function.Sel.Name]; blocked {
				forbidden = importPath + "." + function.Sel.Name
			}
		case *ast.Ident:
			for importName, importPath := range imports {
				if importName == "." {
					if _, blocked := l10ForbiddenProductionCalls[importPath][function.Name]; blocked {
						forbidden = importPath + "." + function.Name
					}
				}
			}
			if strings.Contains(path, "/internal/strictcomposition/") {
				if _, blocked := l10ForbiddenProductionCalls["github.com/jywlabs/hal/internal/strictcomposition"][function.Name]; blocked {
					forbidden = "strictcomposition." + function.Name
				}
			}
			if strings.Contains(path, "/internal/sandboxruntime/") {
				if _, blocked := l10ForbiddenProductionCalls["github.com/jywlabs/hal/internal/sandboxruntime"][function.Name]; blocked {
					forbidden = "sandboxruntime." + function.Name
				}
			}
		}
		return true
	})
	return forbidden
}
