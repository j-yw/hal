package linuxrules

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLinuxRulesProductionImportBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Clean(entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if allowedLinuxRulesImport(importPath) {
				continue
			}
			t.Fatalf("production file %s imports forbidden package %s", path, importPath)
		}
	}
}

func TestLinuxRulesUnsafeProcessMarkersAreAbsent(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		payload, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(payload))
		for _, marker := range []string{"flush ruleset", "iptables", "sudo", "sh -c", "/bin/sh"} {
			if strings.Contains(lower, marker) {
				t.Fatalf("production file %s contains forbidden marker %q", entry.Name(), marker)
			}
		}
		if entry.Name() != "executor_linux.go" &&
			(strings.Contains(lower, "exec.command") || strings.Contains(lower, `"nft"`) || strings.Contains(lower, `"nsenter"`)) {
			t.Fatalf("production file %s owns Linux process execution outside executor_linux.go", entry.Name())
		}
	}
}

func allowedLinuxRulesImport(importPath string) bool {
	if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement" ||
		importPath == "golang.org/x/sys/unix" {
		return true
	}
	return !strings.Contains(importPath, ".") &&
		!strings.HasPrefix(importPath, "github.com/jywlabs/hal/")
}
