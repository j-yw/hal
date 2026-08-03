package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL8CredentialDeliverySourceGuardsMetadataLayersRemainLiveBehaviorFree(t *testing.T) {
	targets := l8CredentialMetadataFiles(t)
	for _, path := range targets {
		source := readL8CredentialDeliveryFile(t, path)
		for _, marker := range []string{
			"LiveSecretSource",
			"JobCredentialRuntime",
			"guest-agent-v2",
			"sandboxjob-v2",
			"keyctl_read",
			"tls.Conn",
			"net.Listen",
			"SOCK_SEQPACKET",
			"cgroup.kill",
		} {
			if strings.Contains(source, marker) {
				t.Fatalf("metadata-only production file %s contains L8 live marker %q", filepath.ToSlash(path), marker)
			}
		}

		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse metadata-only production file %s: %v", filepath.ToSlash(path), err)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", filepath.ToSlash(path), err)
			}
			for _, forbidden := range []string{
				"github.com/jywlabs/hal/internal/credentialmemory",
				"github.com/jywlabs/hal/internal/credentialsource",
				"github.com/jywlabs/hal/internal/credentialproxy",
				"github.com/jywlabs/hal/internal/sandboxworker",
				"github.com/jywlabs/hal/internal/sandboxruntime",
				"crypto/tls",
				"net",
				"net/http",
				"os/exec",
				"golang.org/x/sys/unix",
			} {
				if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
					t.Fatalf("metadata-only production file %s imports L8 live dependency %q", filepath.ToSlash(path), importPath)
				}
			}
		}
	}
}

func TestL8CredentialDeliverySourceGuardsV1SchemasCannotCarryProductionIntent(t *testing.T) {
	checks := []struct {
		path  string
		types []string
	}{
		{
			path:  filepath.Join("..", "internal", "sandboxworker", "job_types.go"),
			types: []string{"JobStartRequest", "JobResolveRequest", "JobStatusRequest", "JobLogsRequest", "JobCancelRequest"},
		},
		{
			path: filepath.Join("..", "internal", "sandboxruntime", "microvm", "guestagent", "contracts.go"),
			types: []string{
				"ReadinessRequest",
				"ExecRequest",
				"CopyInRequest",
				"CopyOutRequest",
			},
		},
	}

	for _, check := range checks {
		parsed, err := parser.ParseFile(token.NewFileSet(), check.path, nil, 0)
		if err != nil {
			t.Fatalf("parse v1 schema %s: %v", filepath.ToSlash(check.path), err)
		}
		wanted := make(map[string]bool, len(check.types))
		for _, name := range check.types {
			wanted[name] = true
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			typeSpec, ok := node.(*ast.TypeSpec)
			if !ok || !wanted[typeSpec.Name.Name] {
				return true
			}
			wanted[typeSpec.Name.Name] = false
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("v1 schema %s in %s is not a struct", typeSpec.Name.Name, filepath.ToSlash(check.path))
			}
			for _, field := range structure.Fields.List {
				for _, name := range field.Names {
					lower := strings.ToLower(name.Name)
					for _, forbidden := range []string{
						"productioncredential",
						"credentialsource",
						"credentialbinding",
						"credentialticket",
						"livecredential",
					} {
						if strings.Contains(lower, forbidden) {
							t.Fatalf("v1 schema %s.%s in %s contains L8 production intent", typeSpec.Name.Name, name.Name, filepath.ToSlash(check.path))
						}
					}
				}
			}
			return false
		})
		for name, missing := range wanted {
			if missing {
				t.Fatalf("v1 schema guard did not find %s in %s", name, filepath.ToSlash(check.path))
			}
		}
	}
}

func TestL8CredentialDeliverySourceGuardsLiveMarkerIsolation(t *testing.T) {
	liveTag := "l8_production_" + "credential_" + "delivery_live"
	for _, root := range []string{"cmd", "internal", "tools"} {
		err := filepath.WalkDir(filepath.Join("..", root), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !strings.Contains(string(source), liveTag) {
				return nil
			}
			rel, err := filepath.Rel("..", path)
			if err != nil {
				return err
			}
			if !strings.HasSuffix(path, "_live_test.go") {
				t.Errorf("%s contains the L8 live marker outside an isolated live test", filepath.ToSlash(rel))
				return nil
			}
			lines := strings.Split(string(source), "\n")
			if len(lines) > 8 {
				lines = lines[:8]
			}
			header := strings.Join(lines, "\n")
			if !strings.Contains(header, "//go:build") || !strings.Contains(header, liveTag) {
				t.Errorf("%s contains the L8 live marker without an exact build constraint", filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk L8 live-marker scope %s: %v", root, err)
		}
	}
}

func TestL8CredentialDeliverySourceGuardsFixtureConstructorsStayInTests(t *testing.T) {
	for _, root := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join("..", root), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, marker := range []string{
				"NewL8Fixture",
				"newL8Fixture",
				"L8FixtureRegistry",
				"l8FixtureRegistry",
			} {
				if strings.Contains(string(source), marker) {
					t.Errorf("production file %s contains test-only L8 fixture marker %q", filepath.ToSlash(path), marker)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk L8 fixture scope %s: %v", root, err)
		}
	}
}

func l8CredentialMetadataFiles(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, pattern := range []string{
		filepath.Join("..", "internal", "credentialdelivery", "*.go"),
		filepath.Join("..", "internal", "sandbox", "credential_proxy*.go"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob L8 metadata files %s: %v", pattern, err)
		}
		for _, path := range matches {
			if !strings.HasSuffix(path, "_test.go") {
				paths = append(paths, path)
			}
		}
	}
	if len(paths) == 0 {
		t.Fatal("L8 metadata source guard matched no production files")
	}
	return paths
}
