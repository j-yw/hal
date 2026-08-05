package credentialprotocol

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestCredentialProtocolImportBoundary(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	const approvedMemoryContract = "github.com/jywlabs/hal/internal/credentialmemory"
	forbiddenStandardLibrary := map[string]bool{
		"net": true, "net/http": true, "net/url": true,
		"os": true, "os/exec": true, "path/filepath": true,
		"syscall": true,
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Clean(entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imported := range file.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", path, err)
			}
			if imported.Name != nil && imported.Name.Name == "_" {
				t.Errorf("production file %s uses blank import %q", path, name)
				continue
			}
			if name == approvedMemoryContract {
				continue
			}
			standardPackage, standardErr := build.Default.Import(name, ".", build.FindOnly)
			if standardErr != nil || !standardPackage.Goroot || forbiddenStandardLibrary[name] {
				t.Errorf("production file %s imports %q; credentialprotocol permits non-live standard library plus credentialmemory only", path, name)
			}
		}
	}
}

func TestCredentialProtocolCatalogHasNoLiveOrDurableSurface(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, declaration := range file.Decls {
			global, ok := declaration.(*ast.GenDecl)
			if !ok || global.Tok != token.VAR {
				continue
			}
			for _, spec := range global.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if _, ok := valueSpec.Type.(*ast.ArrayType); ok {
					t.Errorf("production file %s declares mutable package-global slice/array", entry.Name())
				}
				if _, ok := valueSpec.Type.(*ast.MapType); ok {
					t.Errorf("production file %s declares mutable package-global map", entry.Name())
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if typed, ok := node.(*ast.FuncDecl); ok && typed.Name.Name == "init" {
				t.Errorf("production file %s declares init", entry.Name())
			}
			return true
		})
	}

	typeOfDescriptor := reflect.TypeOf(ExtensionDescriptor{})
	for index := 0; index < typeOfDescriptor.NumField(); index++ {
		field := typeOfDescriptor.Field(index)
		if field.Tag != "" {
			t.Errorf("ExtensionDescriptor.%s tag = %q, want none", field.Name, field.Tag)
		}
	}
}
