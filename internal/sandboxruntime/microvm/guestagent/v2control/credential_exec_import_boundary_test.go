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

func TestCredentialExecCodecProductionImportsStayDataOnly(t *testing.T) {
	allowed := []string{
		"bytes", "encoding/json", "errors", "fmt", "io", "path", "strings", "unicode/utf8",
	}
	for _, file := range credentialExecProductionFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if spec.Name != nil && (spec.Name.Name == "_" || spec.Name.Name == ".") {
				t.Errorf("production file %s uses special import %q", file, name)
			}
			if !containsCredentialExecString(allowed, name) {
				t.Errorf("production file %s imports non-v2control dependency %q", file, name)
			}
		}
	}
}

func TestCredentialExecCodecHasNoGenericOwnerOrLiveSurface(t *testing.T) {
	for _, file := range credentialExecProductionFiles(t) {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{
			"json.RawMessage", "map[", "interface{}", "interface {", " any", "reflect.",
			"net.", "http.", "os.", "exec.Command", "syscall.", "unsafe.", "Listen", "Dial",
			"Mount", "ForkExec", "internal/", "time.Now", "privatePayload", "privateBytes []byte",
		} {
			if strings.Contains(string(source), marker) {
				t.Errorf("production file %s contains forbidden marker %q", file, marker)
			}
		}
	}
}

func TestCredentialExecCodecProductionHasNoMutableGlobalOrInit(t *testing.T) {
	for _, file := range credentialExecProductionFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range parsed.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "init" {
				t.Errorf("production file %s declares init", file)
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
					t.Errorf("production file %s declares mutable global array/slice", file)
				}
				if _, ok := value.Type.(*ast.MapType); ok {
					t.Errorf("production file %s declares mutable global map", file)
				}
			}
		}
	}
}

func TestCredentialExecCodecGuardIsExactFileScoped(t *testing.T) {
	for _, name := range []string{
		"readiness.go", "failure_response.go", "credential_prepare.go",
		"credential_renew.go", "credential_revoke.go", "credential_exec_state.go",
	} {
		if isCredentialExecProductionFile(name) {
			t.Errorf("unrelated file %q was swept into exec codec guard", name)
		}
	}
}

func credentialExecProductionFiles(t *testing.T) []string {
	t.Helper()
	files := []string{
		"credential_exec.go", "credential_exec_accessors.go",
		"credential_exec_format.go", "credential_exec_json.go",
	}
	for _, file := range files {
		if !isCredentialExecProductionFile(file) {
			t.Fatalf("guard file %q is not exact-scoped", file)
		}
		info, err := os.Stat(file)
		if err != nil || info.IsDir() {
			t.Fatalf("guard file %q is not a regular file: %v", file, err)
		}
	}
	return files
}

func isCredentialExecProductionFile(name string) bool {
	return name == "credential_exec.go" || name == "credential_exec_accessors.go" ||
		name == "credential_exec_format.go" || name == "credential_exec_json.go"
}

func containsCredentialExecString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
