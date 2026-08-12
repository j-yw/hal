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

func TestCredentialLifecycleCodecProductionImportsStayPure(t *testing.T) {
	allowed := map[string]bool{
		"bytes": true, "encoding/base64": true, "encoding/json": true,
		"errors": true, "fmt": true, "io": true, "unicode/utf8": true,
		"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol": true,
	}
	for _, path := range credentialLifecycleProductionFiles(t) {
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
				t.Errorf("production file %s imports non-pure dependency %q", path, name)
			}
		}
	}
}

func TestCredentialLifecycleCodecHasNoGenericPrivateOrLiveSurface(t *testing.T) {
	for _, path := range credentialLifecycleProductionFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{
			"json.RawMessage", "map[", "interface{}", "interface {", " any", "reflect.",
			"privateRecordCount", "privateAggregateBytes", "privateAggregateSha256",
			"time.Now", "net.", "http.", "os.", "exec.", "syscall.", "unsafe.",
			"Listen", "Dial", "Mount", "ForkExec", "internal/sandboxworker",
			"internal/factory", "cmd/", "Save", "Load", "WriteFile", "ReadFile",
		} {
			if strings.Contains(string(source), marker) {
				t.Errorf("production file %s contains forbidden marker %q", path, marker)
			}
		}
	}
}

func TestCredentialLifecycleCodecHasNoMutableGlobalOrInit(t *testing.T) {
	for _, path := range credentialLifecycleProductionFiles(t) {
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

func credentialLifecycleProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{"lifecycle.go", "lifecycle_format.go"}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("lifecycle guard file %q: %v", path, err)
		}
		if info.IsDir() {
			t.Fatalf("lifecycle guard path %q is a directory", path)
		}
	}
	return paths
}
