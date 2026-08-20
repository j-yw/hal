package syscallpolicy

import (
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL8SyscallPolicyProductionImportBoundaryIsNeutral(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{
		"net": true, "net/http": true, "os": true, "os/exec": true,
		"path/filepath": true, "syscall": true, "unsafe": true,
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), filepath.Clean(entry.Name()), nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", entry.Name(), parseErr)
		}
		for _, imported := range file.Imports {
			path, unquoteErr := strconv.Unquote(imported.Path.Value)
			if unquoteErr != nil {
				t.Fatalf("unquote %s: %v", entry.Name(), unquoteErr)
			}
			standard, standardErr := build.Default.Import(path, ".", build.FindOnly)
			if standardErr != nil || !standard.Goroot || forbidden[path] {
				t.Errorf("production file %s imports %q; want safe standard library only", entry.Name(), path)
			}
			if imported.Name != nil && (imported.Name.Name == "." || imported.Name.Name == "_") {
				t.Errorf("production file %s uses implicit import %q", entry.Name(), path)
			}
		}
	}
}
