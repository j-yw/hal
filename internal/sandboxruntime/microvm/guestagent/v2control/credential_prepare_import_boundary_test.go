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

func TestCredentialPrepareCodecProductionImportsStayDataOnly(t *testing.T) {
	allowed := []string{
		"bytes", "encoding/hex", "encoding/json", "errors", "fmt", "io", "strconv", "time", "unicode/utf8",
		"github.com/jywlabs/hal/internal/sandboxruntime",
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol",
	}
	for _, path := range credentialPrepareProductionFiles(t) {
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
			if !containsCredentialPrepareString(allowed, name) {
				t.Errorf("production file %s imports non-data dependency %q", path, name)
			}
		}
	}
}

func TestCredentialPrepareCodecHasNoGenericOwnerOrLiveSurface(t *testing.T) {
	for _, path := range credentialPrepareProductionFiles(t) {
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

func TestCredentialPrepareCodecProductionHasNoMutableGlobalOrInit(t *testing.T) {
	for _, path := range credentialPrepareProductionFiles(t) {
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

func TestCredentialPrepareCodecGuardIsExactFileScoped(t *testing.T) {
	for _, name := range []string{"readiness.go", "failure_response.go", "credential_renew.go", "credential_revoke.go", "exec.go"} {
		if isCredentialPrepareProductionFile(name) {
			t.Errorf("unrelated file %q was swept into prepare guard", name)
		}
	}
}

func credentialPrepareProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{
		"credential_prepare.go", "credential_prepare_accessors.go",
		"credential_prepare_format.go", "credential_prepare_json.go",
	}
	for _, path := range paths {
		if !isCredentialPrepareProductionFile(path) {
			t.Fatalf("prepare guard path %q is not exact-scoped", path)
		}
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			t.Fatalf("prepare guard file %q is not a regular file: %v", path, err)
		}
	}
	return paths
}

func isCredentialPrepareProductionFile(name string) bool {
	return name == "credential_prepare.go" || name == "credential_prepare_accessors.go" ||
		name == "credential_prepare_format.go" || name == "credential_prepare_json.go"
}

func containsCredentialPrepareString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
