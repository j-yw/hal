package sandboxworker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMinimalLaunchStartupRequiresExactHeldLockEntry(t *testing.T) {
	for _, kind := range []string{"original", "replacement", "symlink", "directory", "closed"} {
		t.Run(kind, func(t *testing.T) {
			store, err := newJobStoreV2(filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			lock, err := acquireJobStateLock(store.root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = lock.Close() })
			path := filepath.Join(store.root, jobStateLockFileName)
			if kind == "closed" {
				if err := lock.Close(); err != nil {
					t.Fatal(err)
				}
			} else if kind != "original" {
				// Move outside the store: directory enumeration still observes only
				// the expected name, so rejection must inspect its held identity.
				retained := filepath.Join(t.TempDir(), "original-lock")
				if err := os.Rename(path, retained); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "replacement":
					err = os.WriteFile(path, []byte("successor-canary"), 0o600)
				case "symlink":
					err = os.Symlink(retained, path)
				case "directory":
					err = os.Mkdir(path, 0o700)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			got := store.requireMinimalLaunchEmpty(lock)
			t.Cleanup(store.closeMinimalStore)
			if (got == nil) != (kind == "original") {
				t.Fatalf("startup held lock %s: %v", kind, got)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatalf("startup altered lock entry: %v", err)
			}
			if kind == "replacement" {
				payload, err := os.ReadFile(path)
				if err != nil || string(payload) != "successor-canary" {
					t.Fatalf("startup touched successor bytes: %v", err)
				}
			}
		})
	}
}
