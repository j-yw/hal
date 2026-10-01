package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase45NetworkEnforcementDocsAvoidDefaultLiveClaims(t *testing.T) {
	for _, path := range phase45MarkdownDocumentationFiles(t) {
		normalized := strings.ToLower(strings.Join(strings.Fields(phase45ReadFile(t, path)), " "))
		for _, claim := range []string{
			"secure enforcement by default",
			"default secure enforcement is enabled",
			"default firewall mutation is enabled",
			"firewall mutation by default",
			"default listener binding is enabled",
			"listener binding by default",
			"default microvm worker availability is guaranteed",
			"microvm worker availability by default",
			"default `hal sandboxd` starts microvm workers",
			"default `hal run` applies firewall",
			"default `hal auto` applies firewall",
			"default test runs execute network_enforcement_live",
		} {
			if strings.Contains(normalized, claim) {
				t.Fatalf("%s contains unsupported default live-enforcement claim %q", phase34FirecrackerDisplayPath(t, path), claim)
			}
		}
	}
}

func phase45MarkdownDocumentationFiles(t *testing.T) []string {
	t.Helper()
	paths := []string{filepath.Join("..", "README.md")}
	for _, root := range []string{filepath.Join("..", "docs"), filepath.Join("..", "sandbox")} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Ext(path), ".md") {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("WalkDir(%s) error: %v", root, err)
		}
	}
	return paths
}

func phase45ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", path, err)
	}
	return string(data)
}
