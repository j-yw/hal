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

func TestV2ControlIdentityProductionImportsStayDataOnly(t *testing.T) {
	allowed := map[string]bool{
		"bytes": true, "crypto/sha256": true, "encoding/base64": true,
		"encoding/binary": true, "encoding/json": true, "errors": true,
		"fmt": true, "io": true, "time": true, "unicode/utf8": true,
		"github.com/jywlabs/hal/internal/sandboxruntime": true,
	}
	for _, path := range v2ControlIdentityProductionFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		for _, spec := range parsed.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if spec.Name != nil && spec.Name.Name == "_" {
				t.Errorf("production file %s uses blank import %q", path, name)
			}
			if !allowed[name] {
				t.Errorf("production file %s imports non-data dependency %q", path, name)
			}
		}
	}
}

func TestV2ControlIdentityHasNoLiveOrExpandedProtocolSurface(t *testing.T) {
	for _, path := range v2ControlIdentityProductionFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{
			"net.", "http.", "os.", "exec.", "syscall.", "unix.", "unsafe.",
			"Listen", "Dial", "Mount", "ForkExec", "Readiness", "RequestEnvelope",
			"ResponseEnvelope", "PrivateFrame", "StreamFrame", "map[string]any",
			"internal/sandboxworker", "internal/factory", "cmd/",
		} {
			if strings.Contains(string(source), marker) {
				t.Errorf("production file %s contains forbidden marker %q", path, marker)
			}
		}
	}
}

func TestV2ControlIdentityProductionHasNoMutableGlobalOrInit(t *testing.T) {
	for _, path := range v2ControlIdentityProductionFiles(t) {
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

func TestV2ControlIdentityGuardsExcludeFutureControlFiles(t *testing.T) {
	for _, unrelated := range []string{
		"readiness.go",
		"request_envelope.go",
		"response_envelope.go",
		"private_frame.go",
		"stream_frame.go",
	} {
		if isV2ControlIdentityProductionFile(unrelated) {
			t.Errorf("future production file %q was silently swept into the identity-only guard", unrelated)
		}
	}
}

func isV2ControlIdentityProductionFile(name string) bool {
	for _, approved := range v2ControlIdentityProductionFileNames() {
		if name == approved {
			return true
		}
	}
	return false
}

func v2ControlIdentityProductionFileNames() []string {
	return []string{
		"errors.go",
		"identity.go",
		"identity_json.go",
		"session_identity.go",
		"session_identity_format.go",
	}
}

func v2ControlIdentityProductionFiles(t *testing.T) []string {
	t.Helper()
	paths := v2ControlIdentityProductionFileNames()
	for _, path := range paths {
		if !isV2ControlIdentityProductionFile(path) {
			t.Fatalf("identity guard list contains unapproved file %q", path)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("identity guard file %q: %v", path, err)
		}
		if info.IsDir() {
			t.Fatalf("identity guard path %q is a directory", path)
		}
	}
	return paths
}
