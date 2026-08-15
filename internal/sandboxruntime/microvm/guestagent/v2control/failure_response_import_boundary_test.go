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

func TestFailureResponseProductionImportsStayDataOnly(t *testing.T) {
	allowed := map[string]bool{
		"bytes": true, "encoding/json": true, "fmt": true, "io": true,
		"unicode/utf8": true,
	}
	for _, path := range failureResponseProductionFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
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

func TestFailureResponseHasNoGenericBodyOrLiveSurface(t *testing.T) {
	for _, path := range failureResponseProductionFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{
			"json.RawMessage", "map[", "interface{}", "interface {", " any", "reflect.",
			"Body ", "RequestEnvelope", "SuccessResponse", "net.", "http.", "os.",
			"exec.", "syscall.", "unsafe.", "Listen", "Dial", "Mount", "ForkExec",
			"internal/sandboxworker", "internal/factory", "cmd/",
		} {
			if strings.Contains(string(source), marker) {
				t.Errorf("production file %s contains forbidden marker %q", path, marker)
			}
		}
	}
}

func TestFailureResponseProductionHasNoMutableGlobalOrInit(t *testing.T) {
	for _, path := range failureResponseProductionFiles(t) {
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

func TestFailureResponseGuardIsExactFileScoped(t *testing.T) {
	for _, name := range []string{
		"readiness.go", "credential_prepare.go", "credential_renew.go",
		"credential_revoke.go", "exec.go", "request_envelope.go", "response_envelope.go",
	} {
		if isFailureResponseProductionFile(name) {
			t.Errorf("unrelated file %q was swept into failure guard", name)
		}
	}
}

func failureResponseProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{"failure_response.go", "failure_response_format.go"}
	for _, path := range paths {
		if !isFailureResponseProductionFile(path) {
			t.Fatalf("guard path %q is not exact-scoped", path)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("failure response guard file %q: %v", path, err)
		}
		if info.IsDir() {
			t.Fatalf("failure response guard path %q is a directory", path)
		}
	}
	return paths
}

func isFailureResponseProductionFile(name string) bool {
	return name == "failure_response.go" || name == "failure_response_format.go"
}
