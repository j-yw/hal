package l8composition

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestControllerMonitorPureImportAndTypeBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"bytes": true, "crypto/sha256": true, "encoding/base64": true, "encoding/binary": true, "errors": true, "fmt": true, "runtime": true, "sync": true, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol": true}
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "controller_monitor") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files++
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(name), nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if !allowed[path] {
				t.Errorf("%s imports forbidden package %q", name, path)
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.MapType:
				t.Errorf("%s declares a map", name)
			case *ast.InterfaceType:
				t.Errorf("%s declares an interface", name)
			case *ast.TypeSpec:
				if typed.TypeParams != nil && typed.TypeParams.NumFields() != 0 {
					t.Errorf("%s declares generics", name)
				}
			case *ast.Field:
				if typed.Tag != nil && strings.Contains(typed.Tag.Value, "json") {
					t.Errorf("%s declares JSON tag", name)
				}
			}
			return true
		})
	}
	if files < 5 {
		t.Fatalf("scanned %d controller-monitor production files", files)
	}
}
