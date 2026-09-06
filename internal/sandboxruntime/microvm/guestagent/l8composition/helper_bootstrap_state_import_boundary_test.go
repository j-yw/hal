package l8composition

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestHelperBootstrapStateExactPureImportBoundary(t *testing.T) {
	t.Parallel()

	const source = "helper_bootstrap_state.go"
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{
		"bytes",
		"crypto/sha256",
		"errors",
		"fmt",
		"sync",
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol",
	}
	if len(file.Imports) != len(allowed) {
		t.Fatalf("imports = %d, want exact %d", len(file.Imports), len(allowed))
	}
	for index, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if imported.Name != nil || path != allowed[index] {
			t.Errorf("import %d = %q, want exact %q without alias", index, path, allowed[index])
		}
	}
}

func TestHelperBootstrapStateHasNoLiveGenericDurableOrMutableGlobalSurface(t *testing.T) {
	t.Parallel()

	const source = "helper_bootstrap_state.go"
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if typed.Name.Name == "init" {
				t.Error("helper bootstrap state declares init")
			}
			if typed.Type.TypeParams != nil && len(typed.Type.TypeParams.List) != 0 {
				t.Errorf("helper bootstrap state declares generic function %s", typed.Name)
			}
		case *ast.GenDecl:
			if typed.Tok == token.TYPE {
				for _, specification := range typed.Specs {
					typeSpecification := specification.(*ast.TypeSpec)
					if typeSpecification.TypeParams != nil && len(typeSpecification.TypeParams.List) != 0 {
						t.Errorf("helper bootstrap state declares generic type %s", typeSpecification.Name)
					}
				}
			}
			if typed.Tok == token.VAR {
				for _, specification := range typed.Specs {
					valueSpecification := specification.(*ast.ValueSpec)
					for _, value := range valueSpecification.Values {
						call, ok := value.(*ast.CallExpr)
						if !ok || len(call.Args) != 1 {
							t.Error("helper bootstrap state has mutable package-global state")
							continue
						}
						selector, ok := call.Fun.(*ast.SelectorExpr)
						packageName, packageOK := selector.X.(*ast.Ident)
						if !ok || !packageOK || packageName.Name != "errors" || selector.Sel.Name != "New" {
							t.Error("helper bootstrap state globals must be stable errors only")
						}
					}
				}
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.MapType:
			t.Errorf("helper bootstrap state declares map at %d", typed.Pos())
		case *ast.InterfaceType:
			t.Errorf("helper bootstrap state declares interface/any at %d", typed.Pos())
		case *ast.StructType:
			for _, field := range typed.Fields.List {
				if field.Tag != nil {
					t.Errorf("helper bootstrap state field has durable tag %s", field.Tag.Value)
				}
				for _, name := range field.Names {
					if name.IsExported() && (name.Name == "Body" || name.Name == "Raw" || name.Name == "Bytes" || name.Name == "FD") {
						t.Errorf("helper bootstrap state exposes generic/live field %s", name.Name)
					}
				}
			}
		}
		return true
	})
}
