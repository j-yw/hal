package linuxtopology

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL7LinuxTopologyImportBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(importPath, ".") {
				t.Errorf("%s imports non-standard or out-of-scope dependency %q", name, importPath)
			}
		}
	}
}

func TestL7LinuxTopologyProductionSourceGuards(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		for _, forbidden := range []string{
			"rootlesspodman", "firecrackerhost", "linuxrules", "tools/microvm",
			"exec.Command(\"sh\"", "exec.CommandContext(\"sh\"", "sudo", "iptables",
			"sysctl", "setns(", "CLONE_NEW", "--map-guest-addr",
		} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s contains forbidden production marker %q", name, forbidden)
			}
		}
	}
}
