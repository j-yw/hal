package l8composition

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

func TestL8CompositionDescriptorImportBoundary(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	const approvedCatalog = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	forbiddenStandardLibrary := map[string]bool{
		"encoding/json": true,
		"net":           true,
		"net/http":      true,
		"os":            true,
		"os/exec":       true,
		"path/filepath": true,
		"syscall":       true,
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "descriptor") || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
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
			if imported.Name != nil && (imported.Name.Name == "_" || imported.Name.Name == ".") {
				t.Errorf("production file %s uses side-effecting import %q", path, name)
				continue
			}
			if name == approvedCatalog {
				continue
			}
			standardPackage, standardErr := build.Default.Import(name, ".", build.FindOnly)
			if standardErr != nil || !standardPackage.Goroot || forbiddenStandardLibrary[name] {
				t.Errorf("production file %s imports %q; descriptor seam permits non-live standard library plus credentialprotocol only", path, name)
			}
		}
	}
}

func TestL8CompositionDescriptorHasNoLiveDurableOrGlobalSurface(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "descriptor") || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "init" {
				t.Errorf("production file %s declares init", entry.Name())
			}
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
					t.Errorf("production file %s declares mutable package-global array", entry.Name())
				}
				if _, ok := valueSpec.Type.(*ast.MapType); ok {
					t.Errorf("production file %s declares mutable package-global map", entry.Name())
				}
			}
		}
	}

	for _, value := range []any{ProcessDescriptor{}, CompositionDescriptor{}} {
		typeOfValue := reflect.TypeOf(value)
		for index := 0; index < typeOfValue.NumField(); index++ {
			field := typeOfValue.Field(index)
			if field.Tag != "" {
				t.Errorf("%s.%s tag = %q, want none", typeOfValue.Name(), field.Name, field.Tag)
			}
		}
	}
}
