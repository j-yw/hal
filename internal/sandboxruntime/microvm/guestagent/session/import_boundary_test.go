package session

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestProductionImportsStayNarrowAndStandardLibraryOnly(t *testing.T) {
	allowed := map[string]bool{
		"bytes": true, "crypto/aes": true, "crypto/cipher": true,
		"crypto/ecdh": true, "crypto/ed25519": true, "crypto/hmac": true,
		"crypto/rand": true, "crypto/sha256": true, "crypto/subtle": true,
		"encoding/binary": true, "errors": true, "io": true, "sort": true,
		"sync": true, "time": true,
	}
	for _, path := range productionFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote %s: %v", spec.Path.Value, err)
			}
			if !allowed[importPath] {
				t.Fatalf("production file %s imports non-session dependency %q", path, importPath)
			}
		}
	}
}

func TestProductionSourceHasNoLiveOrGenericPayloadBehavior(t *testing.T) {
	for _, path := range productionFiles(t) {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{
			"net.Listen", "net.Dial", "ListenUnix", "SockaddrVM", "AF_VSOCK",
			"os/exec", "syscall.", "unix.", "unsafe.", "filepath.",
			"json.", "base64.", "RawMessage", "map[string]any",
			"guestagent/frame", "guestagent/server", "cmd/", "internal/factory",
		} {
			if strings.Contains(string(source), marker) {
				t.Fatalf("production file %s contains forbidden live/generic marker %q", path, marker)
			}
		}
	}
}

func TestProductionGuardCoversEveryFile(t *testing.T) {
	got := productionFiles(t)
	want := []string{"codec.go", "contracts.go", "errors.go", "gate.go", "handshake.go", "state.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("guarded production files = %#v, want %#v", got, want)
	}
}

func TestProductionHasNoForbiddenCallSelectors(t *testing.T) {
	for _, path := range productionFiles(t) {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if ok && (identifier.Name == "net" || identifier.Name == "os" || identifier.Name == "exec" || identifier.Name == "syscall" || identifier.Name == "unix") {
				t.Errorf("production file %s calls forbidden live selector %s.%s", path, identifier.Name, selector.Sel.Name)
			}
			return true
		})
	}
}

func productionFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		paths = append(paths, filepath.Clean(entry.Name()))
	}
	sort.Strings(paths)
	return paths
}
