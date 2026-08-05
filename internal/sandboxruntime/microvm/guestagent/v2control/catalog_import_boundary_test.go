package v2control

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestV2ControlCatalogProductionImportsStayDataOnly(t *testing.T) {
	allowed := map[string]bool{
		"bytes": true, "encoding/base64": true, "encoding/json": true,
		"errors": true, "fmt": true,
	}
	for _, path := range v2ControlCatalogProductionFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		for _, spec := range parsed.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if spec.Name != nil && (spec.Name.Name == "_" || spec.Name.Name == ".") {
				t.Errorf("production file %s uses special import %q", path, name)
			}
			if !allowed[name] {
				t.Errorf("production file %s imports non-data dependency %q", path, name)
			}
		}
	}
}

func TestV2ControlCatalogHasNoExpandedOrGenericBodySurface(t *testing.T) {
	for _, path := range v2ControlCatalogProductionFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{
			"json.RawMessage", "map[string]", "interface{}", " any", "Body ",
			"RequestEnvelope", "ResponseEnvelope", "net.", "http.", "os.",
			"exec.", "syscall.", "unsafe.", "Listen", "Dial", "Mount",
			"ForkExec", "internal/sandboxworker", "internal/factory", "cmd/",
		} {
			if strings.Contains(string(source), marker) {
				t.Errorf("production file %s contains forbidden marker %q", path, marker)
			}
		}
	}
}

func TestV2ControlCatalogProductionHasNoMutableGlobalOrInit(t *testing.T) {
	for _, path := range v2ControlCatalogProductionFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range parsed.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "init" {
				t.Errorf("production file %s declares init", path)
			}
			global, ok := declaration.(*ast.GenDecl)
			if !ok || global.Tok != token.VAR {
				continue
			}
			for _, spec := range global.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if _, ok := value.Type.(*ast.ArrayType); ok {
					t.Errorf("production file %s declares mutable global array/slice", path)
				}
				if _, ok := value.Type.(*ast.MapType); ok {
					t.Errorf("production file %s declares mutable global map", path)
				}
			}
		}
	}
}

func v2ControlCatalogProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{"catalog.go", "control_error.go", "scalars.go", "scalars_format.go"}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("catalog guard file %q: %v", path, err)
		}
		if info.IsDir() {
			t.Fatalf("catalog guard path %q is a directory", path)
		}
	}
	return paths
}
