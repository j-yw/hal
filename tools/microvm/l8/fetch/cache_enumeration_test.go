//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCacheEnumerationRefreshesRetainedDirectory(t *testing.T) {
	for _, scenario := range []string{"exact_194", "missing", "extra", "symlink", "replaced_path"} {
		t.Run(scenario, func(t *testing.T) {
			parent := t.TempDir()
			name := filepath.Join(parent, "stage")
			if err := os.Mkdir(name, 0700); err != nil {
				t.Fatal(err)
			}
			dir, err := openCacheDir(name)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			// A retained directory can have an exhausted cursor before entries
			// are created. Btrfs also snapshots its directory extent at open;
			// draining explicitly makes the regression deterministic on tmpfs.
			if entries, err := dir.Readdirnames(1); err != io.EOF || len(entries) != 0 {
				t.Fatalf("empty retained directory=%v %v", entries, err)
			}
			pins := map[string]lockedFile{}
			for i := range 194 {
				base := fmt.Sprintf("entry-%03d.tgz", i)
				pins[base] = testPin(base, "locked bytes")
				if err := os.WriteFile(filepath.Join(name, base), []byte("locked bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "missing":
				if err := os.Remove(filepath.Join(name, "entry-000.tgz")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(name, "extra"), []byte("extra"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(filepath.Join(name, "entry-000.tgz"), filepath.Join(parent, "saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(parent, "saved"), filepath.Join(name, "entry-000.tgz")); err != nil {
					t.Fatal(err)
				}
			case "replaced_path":
				if err := os.Rename(name, name+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(name, "foreign"), []byte("foreign canary"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			valid := scenario == "exact_194" || scenario == "replaced_path"
			for attempt := range 2 {
				err := verifyCacheDir(context.Background(), dir, pins)
				if (err == nil) != valid {
					t.Fatalf("verification %d accepted=%v want=%v: %v", attempt, err == nil, valid, err)
				}
			}
			if scenario == "replaced_path" {
				data, err := os.ReadFile(filepath.Join(name, "foreign"))
				if err != nil || string(data) != "foreign canary" {
					t.Fatalf("foreign file changed: %q %v", data, err)
				}
				entries, err := os.ReadDir(name)
				if err != nil || len(entries) != 1 {
					t.Fatal("foreign directory changed")
				}
				if sameDirectory(dir, name) {
					t.Fatal("replaced pathname passed publication currentness")
				}
			}
		})
	}
}
