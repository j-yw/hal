package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL6ProductionPolicyProxyIsNotActivatedByDefaultPaths(t *testing.T) {
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
			payload, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := validateL6ProductionProxySource(filepath.ToSlash(rel), payload); err != nil {
				t.Error(err)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("WalkDir(%s) error: %v", root, err)
		}
	}
}

func validateL6ProductionProxySource(path string, payload []byte) error {
	for _, prefix := range []string{"internal/sandboxruntime/networkenforcement/policyproxy/", "internal/sandboxruntime/rootlesspodman/l7network/", "internal/sandboxruntime/microvm/firecrackerhost/l7network/"} {
		if strings.HasPrefix(path, prefix) {
			return nil
		}
	}
	if strings.Contains(string(payload), "internal/sandboxruntime/networkenforcement/policyproxy") {
		return fmt.Errorf("%s imports the L6 production proxy; L7 owns explicit runtime topology wiring", path)
	}
	return nil
}
