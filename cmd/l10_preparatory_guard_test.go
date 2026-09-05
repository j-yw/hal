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
		"No production code references `EvaluateActive` or `EvaluateTerminal`.",
		"Production code does not reference or construct `JobCredentialActiveProof` or `JobCredentialCleanupProof` for L10.",
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
		if reference := l10ForbiddenProductionReference(parsed, filepath.ToSlash(path)); reference != "" {
			t.Errorf("production file %s references unavailable authority %s", filepath.ToSlash(path), reference)
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
			name: "qualified evaluator call", path: "../cmd/wire.go", wantForbidden: true,
			source: "package cmd\nimport composition \"github.com/jywlabs/hal/internal/strictcomposition\"\nfunc wire() { _, _ = composition.EvaluateActive(nil, composition.ActiveRequest{}) }\n",
		},
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
			name: "same package proof alias", path: "../internal/sandboxruntime/wire.go", wantForbidden: true,
			source: "package sandboxruntime\nfunc NewJobCredentialCleanupProof() {}\nvar mint = NewJobCredentialCleanupProof\n",
		},
		{
			name: "linkname evaluator", path: "../cmd/wire.go", wantForbidden: true,
			source: "package cmd\nimport _ \"unsafe\"\n//go:linkname evaluate github.com/jywlabs/hal/internal/strictcomposition.EvaluateActive\nfunc evaluate()\n",
		},
		{
			name: "shadowed import alias", path: "../cmd/safe.go",
			source: "package cmd\nimport composition \"github.com/jywlabs/hal/internal/strictcomposition\"\ntype fake struct{}\nfunc (fake) EvaluateActive() {}\nfunc safe() { composition := fake{}; _ = composition.EvaluateActive }\n",
		},
		{
			name: "unrelated method value", path: "../cmd/safe.go",
			source: "package cmd\ntype fake struct{}\nfunc (fake) EvaluateTerminal() {}\nvar safe = fake{}.EvaluateTerminal\n",
		},
		{
			name: "unrelated package selector", path: "../cmd/safe.go",
			source: "package cmd\nimport other \"example.invalid/unrelated\"\nvar safe = other.EvaluateActive\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := parser.ParseFile(token.NewFileSet(), test.path, test.source, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			forbidden := l10ForbiddenProductionReference(parsed, filepath.ToSlash(test.path)) != ""
			if forbidden != test.wantForbidden {
				t.Fatalf("guard forbidden = %t, want %t", forbidden, test.wantForbidden)
			}
		})
	}
}

func l10ForbiddenProductionReference(file *ast.File, path string) string {
	imports := make(map[string]string, len(file.Imports))
	dotImports := make(map[string]bool)
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
		if name == "." {
			dotImports[importPath] = true
		} else if name != "_" {
			imports[name] = importPath
		}
	}

	var forbidden string
	for _, comments := range file.Comments {
		for _, comment := range comments.List {
			if !strings.HasPrefix(comment.Text, "//go:linkname") {
				continue
			}
			for importPath, names := range l10ForbiddenProductionCalls {
				for name := range names {
					if strings.Contains(comment.Text, importPath+"."+name) {
						return importPath + "." + name
					}
				}
			}
		}
	}

	definitions := make(map[*ast.Ident]bool)
	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			definitions[declaration.Name] = true
		case *ast.GenDecl:
			for _, spec := range declaration.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					definitions[spec.Name] = true
				case *ast.ValueSpec:
					for _, name := range spec.Names {
						definitions[name] = true
					}
				case *ast.ImportSpec:
					if spec.Name != nil {
						definitions[spec.Name] = true
					}
				}
			}
		}
	}

	currentPackage := l10GuardedPackageForPath(path)
	var stack []ast.Node
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if forbidden != "" {
			return false
		}
		var parent ast.Node
		if len(stack) != 0 {
			parent = stack[len(stack)-1]
		}
		stack = append(stack, node)

		switch expression := node.(type) {
		case *ast.SelectorExpr:
			qualifier := l10UnwrapIdentifier(expression.X)
			if qualifier == nil || qualifier.Obj != nil {
				return true
			}
			importPath := imports[qualifier.Name]
			if _, blocked := l10ForbiddenProductionCalls[importPath][expression.Sel.Name]; blocked {
				forbidden = importPath + "." + expression.Sel.Name
			}
		case *ast.Ident:
			if definitions[expression] || l10IdentifierIsSelectorName(parent, expression) {
				return true
			}
			if currentPackage != "" {
				if _, blocked := l10ForbiddenProductionCalls[currentPackage][expression.Name]; blocked && (expression.Obj == nil || expression.Obj.Kind == ast.Fun) {
					forbidden = currentPackage + "." + expression.Name
					return true
				}
			}
			if expression.Obj == nil {
				for importPath := range dotImports {
					if _, blocked := l10ForbiddenProductionCalls[importPath][expression.Name]; blocked {
						forbidden = importPath + "." + expression.Name
						return true
					}
				}
			}
		}
		return true
	})
	return forbidden
}

func l10UnwrapIdentifier(expression ast.Expr) *ast.Ident {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			identifier, _ := expression.(*ast.Ident)
			return identifier
		}
		expression = parenthesized.X
	}
}

func l10IdentifierIsSelectorName(parent ast.Node, identifier *ast.Ident) bool {
	selector, ok := parent.(*ast.SelectorExpr)
	return ok && selector.Sel == identifier
}

func l10GuardedPackageForPath(path string) string {
	path = filepath.ToSlash(filepath.Clean(path))
	for importPath := range l10ForbiddenProductionCalls {
		directory := strings.TrimPrefix(importPath, "github.com/jywlabs/hal/")
		if strings.Contains(path, "/"+directory+"/") {
			return importPath
		}
	}
	return ""
}
