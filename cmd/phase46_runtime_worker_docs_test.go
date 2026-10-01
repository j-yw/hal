package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase46CLIExamplesAvoidDefaultAvailabilityClaims(t *testing.T) {
	for _, path := range phase46CLIDocFiles(t) {
		doc := strings.ToLower(strings.Join(strings.Fields(phase46ReadFile(t, path)), " "))
		for _, claim := range phase46ForbiddenDefaultAvailabilityClaims() {
			if strings.Contains(doc, claim) {
				t.Fatalf("%s contains unsupported default availability claim %q", phase34FirecrackerDisplayPath(t, path), claim)
			}
		}
	}
}

func phase46CLIDocFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	root := filepath.Join("..", "docs", "cli")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir(%s) error = %v", root, err)
	}
	return files
}

func phase46ForbiddenDefaultAvailabilityClaims() []string {
	return []string{
		"secure credential delivery is enabled by default",
		"secure credential delivery is available by default",
		"secure credential delivery is generally available",
		"credential delivery is enabled by default",
		"credential delivery is production ready",
		"credential delivery is production-ready",
		"network enforcement is enabled by default",
		"network enforcement is available by default",
		"network enforcement is generally available",
		"microvm worker enforcement is enabled by default",
		"microvm worker enforcement is available by default",
		"microvm worker enforcement is generally available",
		"default secure credential delivery",
		"default network enforcement",
		"default microvm worker enforcement",
	}
}

func phase46ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}
