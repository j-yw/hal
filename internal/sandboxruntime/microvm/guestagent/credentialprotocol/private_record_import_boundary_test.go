package credentialprotocol

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestPrivateRecordCodecUsesOnlyExactPureDependenciesAndConcreteOwners(t *testing.T) {
	t.Parallel()

	const name = "private_record.go"
	file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	allowed := map[string]bool{
		"crypto/sha256": true, "encoding/binary": true, "fmt": true, "runtime": true,
	}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import: %v", err)
		}
		if imported.Name != nil || !allowed[path] {
			t.Errorf("private-record codec imports %q; only the exact pure codec/hash/opaque-format set is allowed", path)
		}
		delete(allowed, path)
	}
	for missing := range allowed {
		t.Errorf("private-record codec exact import %q is missing", missing)
	}
	for _, declaration := range file.Decls {
		global, ok := declaration.(*ast.GenDecl)
		if ok && global.Tok == token.VAR {
			t.Errorf("private-record codec declares mutable package state")
		}
	}

	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.InterfaceType:
			t.Errorf("private-record codec declares a generic interface owner")
		case *ast.MapType:
			t.Errorf("private-record codec declares a map owner")
		case *ast.TypeSpec:
			if typed.TypeParams != nil && len(typed.TypeParams.List) != 0 {
				t.Errorf("private-record codec declares generic type %s", typed.Name)
			}
		case *ast.FuncDecl:
			if typed.Type.TypeParams != nil && len(typed.Type.TypeParams.List) != 0 {
				t.Errorf("private-record codec declares generic function %s", typed.Name)
			}
		case *ast.Field:
			for _, fieldName := range typed.Names {
				if fieldName.IsExported() && (fieldName.Name == "Body" || fieldName.Name == "Raw" || fieldName.Name == "Bytes" || fieldName.Name == "Payload") {
					t.Errorf("private-record codec exposes generic private field %s", fieldName.Name)
				}
			}
		}
		return true
	})
}
