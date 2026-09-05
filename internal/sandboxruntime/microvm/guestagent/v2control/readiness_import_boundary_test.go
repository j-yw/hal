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

func TestReadinessCodecProductionImportsStayDataOnly(t *testing.T) {
	allowed := []string{
		"bytes", "encoding/json", "errors", "fmt", "io", "unicode/utf8",
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol",
	}
	for _, path := range readinessCodecProductionFiles(t) {
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
			if !containsReadinessString(allowed, name) {
				t.Errorf("production file %s imports non-data dependency %q", path, name)
			}
		}
	}
}

func TestReadinessCodecHasNoGenericOrLiveSurface(t *testing.T) {
	for _, path := range readinessCodecProductionFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{
			"json.RawMessage", "map[", "interface{}", "interface {", " any", "reflect.",
			"net.", "http.", "os.", "exec.", "syscall.", "unsafe.", "Listen", "Dial",
			"Mount", "ForkExec", "internal/sandboxworker", "internal/factory", "cmd/",
		} {
			if strings.Contains(string(source), marker) {
				t.Errorf("production file %s contains forbidden marker %q", path, marker)
			}
		}
	}
}

func TestReadinessCodecHasNoMutableGlobalOrInit(t *testing.T) {
	for _, path := range readinessCodecProductionFiles(t) {
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

func TestReadinessCodecGuardIsExactFileScoped(t *testing.T) {
	for _, name := range []string{
		"request_envelope.go", "response_envelope.go", "readiness_failure.go",
		"credential_prepare.go", "credential_renew.go", "credential_revoke.go", "exec.go",
	} {
		if isReadinessCodecProductionFile(name) {
			t.Errorf("future file %q was swept into readiness guard", name)
		}
	}
}

func readinessCodecProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{"readiness.go", "readiness_format.go"}
	for _, path := range paths {
		if !isReadinessCodecProductionFile(path) {
			t.Fatalf("guard path %q is not exact-scoped", path)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("readiness guard file %q: %v", path, err)
		}
		if info.IsDir() {
			t.Fatalf("readiness guard path %q is a directory", path)
		}
	}
	return paths
}

func isReadinessCodecProductionFile(name string) bool {
	return name == "readiness.go" || name == "readiness_format.go"
}

func containsReadinessString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
