package credentialprotocol

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestHelperExecCodecsUseOnlyPureConcreteDependencies(t *testing.T) {
	t.Parallel()

	const name = "helper_exec_body.go"
	file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	allowed := map[string]bool{
		"crypto/sha256": true, "encoding/binary": true, "errors": true,
		"fmt": true, "path": true, "runtime": true, "strings": true,
		"unicode/utf8": true,
	}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import: %v", err)
		}
		if imported.Name != nil || !allowed[path] {
			t.Errorf("helper exec codec imports %q; only exact pure codec dependencies are allowed", path)
		}
		delete(allowed, path)
	}
	for missing := range allowed {
		t.Errorf("helper exec codec exact import %q is missing", missing)
	}

	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.InterfaceType:
			t.Errorf("helper exec codec declares interface owner")
		case *ast.MapType:
			t.Errorf("helper exec codec declares map owner")
		case *ast.TypeSpec:
			if typed.TypeParams != nil && len(typed.TypeParams.List) != 0 {
				t.Errorf("helper exec codec declares generic type %s", typed.Name)
			}
		case *ast.FuncDecl:
			if typed.Type.TypeParams != nil && len(typed.Type.TypeParams.List) != 0 {
				t.Errorf("helper exec codec declares generic function %s", typed.Name)
			}
		case *ast.Field:
			for _, fieldName := range typed.Names {
				if fieldName.IsExported() && (fieldName.Name == "Body" || fieldName.Name == "Raw" || fieldName.Name == "Bytes" || fieldName.Name == "Payload") {
					t.Errorf("helper exec codec exposes generic field %s", fieldName)
				}
			}
		}
		return true
	})
}
