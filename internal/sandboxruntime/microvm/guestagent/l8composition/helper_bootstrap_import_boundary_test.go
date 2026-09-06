package l8composition

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestHelperBootstrapCodecExactFileImportBoundary(t *testing.T) {
	t.Parallel()

	const source = "helper_bootstrap.go"
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	allowedImports := []string{
		"bytes",
		"crypto/sha256",
		"encoding/binary",
		"errors",
		"fmt",
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol",
	}
	if len(file.Imports) != len(allowedImports) {
		t.Fatalf("%s imports %d packages, want exact %d", source, len(file.Imports), len(allowedImports))
	}
	for index, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %d: %v", index, err)
		}
		if imported.Name != nil || path != allowedImports[index] {
			t.Errorf("import %d = %q, want exact %q with no alias", index, path, allowedImports[index])
		}
	}
}

func TestHelperBootstrapCodecHasNoGenericMutableOrLiveSurface(t *testing.T) {
	t.Parallel()

	const source = "helper_bootstrap.go"
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if typed.Name.Name == "init" {
				t.Error("helper bootstrap codec declares init")
			}
			if typed.Type.TypeParams != nil && len(typed.Type.TypeParams.List) != 0 {
				t.Errorf("helper bootstrap codec declares generic function %s", typed.Name)
			}
		case *ast.GenDecl:
			if typed.Tok == token.TYPE {
				for _, specification := range typed.Specs {
					typeSpecification := specification.(*ast.TypeSpec)
					if typeSpecification.TypeParams != nil && len(typeSpecification.TypeParams.List) != 0 {
						t.Errorf("helper bootstrap codec declares generic type %s", typeSpecification.Name)
					}
				}
			}
			if typed.Tok == token.VAR {
				for _, specification := range typed.Specs {
					valueSpecification := specification.(*ast.ValueSpec)
					for _, value := range valueSpecification.Values {
						call, ok := value.(*ast.CallExpr)
						if !ok || len(call.Args) != 1 {
							t.Error("helper bootstrap codec has mutable package-global state")
							continue
						}
						selector, ok := call.Fun.(*ast.SelectorExpr)
						packageName, packageOK := selector.X.(*ast.Ident)
						if !ok || !packageOK || packageName.Name != "errors" || selector.Sel.Name != "New" {
							t.Error("helper bootstrap codec package globals must be stable errors only")
						}
					}
				}
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.MapType:
			t.Errorf("helper bootstrap codec declares map at %d", typed.Pos())
		case *ast.InterfaceType:
			t.Errorf("helper bootstrap codec declares interface/any at %d", typed.Pos())
		}
		return true
	})
}
