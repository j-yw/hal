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

func TestPhase55CommandProductionCodeDoesNotOwnPolicyProxyImplementation(t *testing.T) {
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
			if message := phase55CommandPolicyProxyImportBoundaryMessage(path, importPath); message != "" {
				t.Fatal(message)
			}
		}
		if message := phase55CommandPolicyProxySourceBoundaryMessage(path, string(source)); message != "" {
			t.Fatal(message)
		}
	}
}

func TestPhase55CommandPolicyProxyBoundaryRejectsImplementationFixtures(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "decision evaluator",
			source: `package cmd; func run() { _ = EvaluatePolicyProxyDecision }`,
			want:   "EvaluatePolicyProxyDecision",
		},
		{
			name:   "lifecycle service",
			source: `package cmd; func run() { _ = PolicyProxyLifecycleService{} }`,
			want:   "PolicyProxyLifecycleService",
		},
		{
			name:   "adapter constructor",
			source: `package cmd; func run() { _ = NewPolicyProxyEnforcementAdapter }`,
			want:   "NewPolicyProxyEnforcementAdapter",
		},
		{
			name:   "start lifecycle",
			source: `package cmd; func run() { _ = service.StartPolicyProxy }`,
			want:   "StartPolicyProxy",
		},
		{
			name:   "network enforcement import",
			source: `package cmd; import "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"; func run() {}`,
			want:   "network enforcement implementation package",
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
				if message := phase55CommandPolicyProxyImportBoundaryMessage(tt.name+".go", importPath); message != "" {
					if !strings.Contains(message, tt.want) {
						t.Fatalf("boundary message = %q, want marker %q", message, tt.want)
					}
					return
				}
			}
			message := phase55CommandPolicyProxySourceBoundaryMessage(tt.name+".go", tt.source)
			if !strings.Contains(message, tt.want) {
				t.Fatalf("boundary message = %q, want marker %q", message, tt.want)
			}
		})
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

func phase55CommandPolicyProxyImportBoundaryMessage(fileName, importPath string) string {
	if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement" ||
		strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/") {
		return "cmd file " + fileName + " imports forbidden network enforcement implementation package " + importPath
	}
	return ""
}

func phase55CommandPolicyProxySourceBoundaryMessage(fileName, source string) string {
	for _, forbidden := range []struct {
		token  string
		reason string
	}{
		{token: "EvaluatePolicyProxyDecision", reason: "policy proxy decision evaluation"},
		{token: "EvaluatePolicyProxyServiceDecisionResult", reason: "policy proxy service decision evaluation"},
		{token: "BuildPolicyProxyDecisionLogRecord", reason: "policy proxy decision logging"},
		{token: "SummarizePolicyProxyDecisionLogRecords", reason: "policy proxy decision log aggregation"},
		{token: "PolicyProxyLifecycleService", reason: "policy proxy lifecycle service"},
		{token: "NewPolicyProxyEnforcementAdapter", reason: "policy proxy adapter construction"},
		{token: "StartPolicyProxy", reason: "policy proxy start lifecycle"},
		{token: "ActivePolicyProxy", reason: "policy proxy active lifecycle"},
		{token: "StopPolicyProxy", reason: "policy proxy stop lifecycle"},
	} {
		if strings.Contains(source, forbidden.token) {
			return "cmd file " + fileName + " contains forbidden " + forbidden.reason + " marker " + forbidden.token
		}
	}
	return ""
}
