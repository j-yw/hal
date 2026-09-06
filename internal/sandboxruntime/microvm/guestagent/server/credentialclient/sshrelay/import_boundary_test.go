package sshrelay

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

func TestClientSSHRelayImportAndRegistrationBoundary(t *testing.T) {
	allowedInternal := map[string]bool{
		"github.com/jywlabs/hal/internal/credentialmemory":                                          true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol":      true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(): %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Clean(entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil && function.Name.Name == "init" {
				t.Errorf("%s declares forbidden init", path)
			}
		}
		for _, imported := range file.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("Unquote(%s): %v", imported.Path.Value, err)
			}
			if imported.Name != nil && (imported.Name.Name == "_" || imported.Name.Name == ".") {
				t.Errorf("%s has forbidden side-effect or dot import %s", path, importPath)
			}
			if strings.Contains(importPath, "/internal/") && !allowedInternal[importPath] {
				t.Errorf("%s imports forbidden internal package %s", path, importPath)
			}
			if importPath == "net" || strings.HasPrefix(importPath, "net/") || importPath == "os" ||
				importPath == "syscall" || strings.Contains(importPath, "golang.org/x/sys") {
				t.Errorf("%s imports forbidden live transport package %s", path, importPath)
			}
		}
	}
}
