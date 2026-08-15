package credentialprotocol

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestHelperPrepareTransactionStatePureImportAndLiveBehaviorBoundary(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "helper_prepare_transaction_state") && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if !reflectStringSlicesEqual(names, []string{"helper_prepare_transaction_state.go", "helper_prepare_transaction_state_format.go"}) {
		t.Fatalf("production prepare transaction files = %v", names)
	}
	allowed := map[string]bool{
		"crypto/sha256":   true,
		"encoding/binary": true,
		"errors":          true,
		"fmt":             true,
		"runtime":         true,
		"sync":            true,
	}
	used := make(map[string]bool)
	for _, name := range names {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{
			"net.", "http.", "os.", "exec.", "syscall.", "unix.", "context.", "time.Now", "time.After",
			"Listen(", "Dial(", "Open(", "ReadFile(", "WriteFile(", "Command(", "ForkExec(", "Mount(", "go func",
		} {
			if strings.Contains(string(content), marker) {
				t.Errorf("%s contains forbidden live behavior marker %q", name, marker)
			}
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, content, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if imported.Name != nil || !allowed[path] {
				t.Errorf("%s imports %q; only exact pure standard-library dependencies are allowed", name, path)
			}
			used[path] = true
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.GoStmt:
				t.Errorf("%s starts a goroutine", name)
			case *ast.ChanType:
				t.Errorf("%s declares a channel", name)
			case *ast.MapType:
				t.Errorf("%s declares a map", name)
			case *ast.InterfaceType:
				t.Errorf("%s declares an interface", name)
			case *ast.TypeSpec:
				if typed.TypeParams != nil && len(typed.TypeParams.List) != 0 {
					t.Errorf("%s declares generic type %s", name, typed.Name)
				}
			case *ast.FuncDecl:
				if typed.Type.TypeParams != nil && len(typed.Type.TypeParams.List) != 0 {
					t.Errorf("%s declares generic function %s", name, typed.Name)
				}
			}
			return true
		})
	}
	for required := range allowed {
		if !used[required] {
			t.Errorf("exact pure import %q is missing", required)
		}
	}
}

func reflectStringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
