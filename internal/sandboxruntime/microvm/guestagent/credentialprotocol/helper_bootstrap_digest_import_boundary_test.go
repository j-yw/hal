package credentialprotocol

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestCanonicalHelperBootstrapDigestPureImportBoundary(t *testing.T) {
	t.Parallel()

	const source = "helper_bootstrap_digest.go"
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	wantImports := []string{"crypto/sha256", "encoding/binary", "errors"}
	if len(file.Imports) != len(wantImports) {
		t.Fatalf("%s imports %d packages, want exact %d", source, len(file.Imports), len(wantImports))
	}
	for index, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %d: %v", index, err)
		}
		if imported.Name != nil || path != wantImports[index] {
			t.Errorf("import %d = %q, want exact %q with no alias", index, path, wantImports[index])
		}
	}

	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.FuncDecl:
			if typed.Name.Name == "init" {
				t.Error("canonical bootstrap digest declares init")
			}
			if typed.Type.TypeParams != nil && len(typed.Type.TypeParams.List) != 0 {
				t.Errorf("canonical bootstrap digest declares generic function %s", typed.Name)
			}
		case *ast.TypeSpec:
			if typed.TypeParams != nil && len(typed.TypeParams.List) != 0 {
				t.Errorf("canonical bootstrap digest declares generic type %s", typed.Name)
			}
		case *ast.MapType:
			t.Error("canonical bootstrap digest declares map storage")
		case *ast.InterfaceType:
			t.Error("canonical bootstrap digest declares interface storage")
		}
		return true
	})
}
