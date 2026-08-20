package rolebootstrap

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestRoleBootstrapProductionGoFilesHaveNoImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error = %v", name, err)
		}
		if len(parsed.Imports) != 0 {
			t.Errorf("%s imports %d Go packages, want freestanding source-contract seam", name, len(parsed.Imports))
		}
	}
}

func TestRoleBootstrapExactPlatformSplit(t *testing.T) {
	tests := []struct {
		name string
		tag  string
	}{
		{name: "installer_linux_amd64.go", tag: "linux && amd64"},
		{name: "installer_other.go", tag: "!linux || !amd64"},
	}
	for _, test := range tests {
		payload, err := os.ReadFile(test.name)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", test.name, err)
		}
		first, _, _ := strings.Cut(string(payload), "\n")
		if first != "//go:build "+test.tag {
			t.Errorf("%s first line = %q, want exact %q split", test.name, first, test.tag)
		}
	}
}
