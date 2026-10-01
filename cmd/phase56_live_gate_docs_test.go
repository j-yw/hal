package cmd

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPhase56CommandImplementationBoundaryRejectsFixtures(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "firewall implementation import",
			source: `package cmd; import "github.com/coreos/go-iptables/iptables"; func run() {}`,
			want:   "firewall implementation package",
		},
		{
			name:   "firewall command",
			source: `package cmd; func run() { _ = "pfctl -f <redacted>" }`,
			want:   "pfctl",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tt.name+".go", []byte(tt.source), parser.ImportsOnly)
			if err != nil {
				t.Fatalf("ParseFile(%s) error: %v", tt.name, err)
			}
			for _, spec := range file.Imports {
				importPath, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatalf("unquote import %s: %v", spec.Path.Value, err)
				}
				if message := phase56CommandImplementationImportBoundaryMessage(tt.name+".go", importPath); message != "" {
					if !strings.Contains(message, tt.want) {
						t.Fatalf("boundary message = %q, want marker %q", message, tt.want)
					}
					return
				}
			}
			message := phase56CommandImplementationSourceBoundaryMessage(tt.name+".go", tt.source)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want marker %q", message, tt.want)
			}
		})
	}
}

func TestPhase56CommandProductionCodeDoesNotOwnFirewallProxyOrRuntimeImplementation(t *testing.T) {
	for _, path := range phase55CommandProductionFiles(t) {
		source := phase55ReadCommandProductionFile(t, path)
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s) error: %v", path, err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, path, err)
			}
			if message := phase56CommandImplementationImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
		if message := phase56CommandImplementationSourceBoundaryMessage(path, string(source)); message != "" {
			t.Fatal(message)
		}
	}
}

func phase55CommandProductionFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(cmd) error: %v", err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		paths = append(paths, filepath.Join(".", name))
	}
	if len(paths) == 0 {
		t.Fatal("phase55 command boundary matched no production files")
	}
	return paths
}

func phase55ReadCommandProductionFile(t *testing.T, path string) []byte {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return source
}

func phase56CommandImplementationImportBoundaryMessage(fileName, importPath string) string {
	lower := strings.ToLower(importPath)
	for _, marker := range []string{"iptables", "nftables", "pfctl", "firewallctl"} {
		if strings.Contains(lower, marker) {
			return "cmd file " + fileName + " imports forbidden firewall implementation package " + importPath
		}
	}
	return ""
}

func phase56CommandImplementationSourceBoundaryMessage(fileName, source string) string {
	for _, forbidden := range []struct {
		token  string
		reason string
	}{
		{token: "iptables", reason: "firewall command"},
		{token: "nftables", reason: "firewall command"},
		{token: "pfctl", reason: "firewall command"},
		{token: "firewall.Apply", reason: "firewall mutation"},
		{token: "EnforceFirewall", reason: "firewall mutation"},
	} {
		if strings.Contains(source, forbidden.token) {
			return "cmd file " + fileName + " contains forbidden " + forbidden.reason + " marker " + forbidden.token
		}
	}
	return ""
}
