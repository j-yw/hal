package cmd

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL6ProductionPolicyProxyIsNotActivatedByDefaultPaths(t *testing.T) {
	const importMarker = "internal/sandboxruntime/networkenforcement/policyproxy"
	for _, root := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join("..", root), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel("..", path)
			if err != nil {
				return err
			}
			if strings.HasPrefix(filepath.ToSlash(rel), "internal/sandboxruntime/networkenforcement/policyproxy/") {
				return nil
			}
			if strings.HasPrefix(filepath.ToSlash(rel), "internal/sandboxruntime/rootlesspodman/l7network/") {
				return nil
			}
			payload, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(payload), importMarker) {
				t.Errorf("%s imports the L6 production proxy; L7 owns explicit runtime topology wiring", rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("WalkDir(%s) error: %v", root, err)
		}
	}
}
