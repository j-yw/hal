package credentialmemory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestL8CredentialMemoryImportAndFormattingBoundaries(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	production := 0
	productionSource := strings.Builder{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		production++
		source, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		productionSource.Write(source)
		productionSource.WriteByte('\n')
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if importPath == "encoding/json" || importPath == "encoding/gob" || importPath == "encoding/xml" ||
				importPath == "fmt" || importPath == "log" || importPath == "log/slog" ||
				importPath == "net" || importPath == "net/http" || importPath == "os/exec" ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/cmd") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/factory") ||
				strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/credentialdelivery") {
				t.Errorf("production credential memory %s imports forbidden package %q", entry.Name(), importPath)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			function, ok := node.(*ast.FuncDecl)
			if !ok || function.Recv == nil {
				return true
			}
			switch function.Name.Name {
			case "String", "GoString", "MarshalJSON", "MarshalText", "MarshalBinary", "GobEncode":
				t.Errorf("production credential memory %s defines forbidden formatting/marshal method %s", entry.Name(), function.Name.Name)
			}
			return true
		})
	}
	if production == 0 {
		t.Fatal("L8 credential memory production package does not exist")
	}
	for _, required := range []string{
		"unix.Mmap(", "unix.MAP_ANON", "unix.MAP_PRIVATE", "unix.Mlock(",
		"unix.Munlock(", "unix.Munmap(", "unix.RLIMIT_CORE", "unix.PR_SET_DUMPABLE",
	} {
		if !strings.Contains(productionSource.String(), required) {
			t.Errorf("production credential memory omits direct fail-closed OS marker %q", required)
		}
	}
}
