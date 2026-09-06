package sandboxworkspace

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLockManagerAcquireReleaseAllowsReacquire(t *testing.T) {
	manager := NewLockManager(t.TempDir())
	first, err := manager.Acquire("workspace:/work/repo")
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if first.ResourceKey != "workspace:/work/repo" {
		t.Fatalf("ResourceKey = %q", first.ResourceKey)
	}
	if _, err := os.Stat(first.Path); err != nil {
		t.Fatalf("lock file stat error = %v", err)
	}

	second, err := manager.Acquire("workspace:/work/repo")
	if !errors.Is(err, ErrDirectLockActive) {
		t.Fatalf("second Acquire() error = %v, want ErrDirectLockActive", err)
	}
	if second != nil {
		t.Fatalf("second lock = %#v, want nil", second)
	}

	if err := first.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if _, err := os.Stat(first.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock file after release stat error = %v, want not exist", err)
	}

	third, err := manager.Acquire("workspace:/work/repo")
	if err != nil {
		t.Fatalf("third Acquire() error = %v", err)
	}
	if err := third.Release(); err != nil {
		t.Fatalf("third Release() error = %v", err)
	}
}

func TestLockManagerWorkspaceAliasesContend(t *testing.T) {
	for _, aliasKind := range []string{"workspace symlink", "symlinked parent"} {
		for _, order := range []string{"canonical first", "alias first"} {
			t.Run(aliasKind+"/"+order, func(t *testing.T) {
				parent := t.TempDir()
				repo := filepath.Join(parent, "repo")
				if err := os.Mkdir(repo, 0o700); err != nil {
					t.Fatal(err)
				}
				alias := filepath.Join(t.TempDir(), "alias")
				target := repo
				if aliasKind == "symlinked parent" {
					target = parent
				}
				if err := os.Symlink(target, alias); err != nil {
					t.Fatal(err)
				}
				if aliasKind == "symlinked parent" {
					alias = filepath.Join(alias, "repo")
				}
				canonical, err := filepath.EvalSymlinks(repo)
				if err != nil {
					t.Fatal(err)
				}
				firstKey, otherKey := "workspace:"+canonical, "workspace:"+alias
				if order == "alias first" {
					firstKey, otherKey = otherKey, firstKey
				}
				manager := NewLockManager(t.TempDir())
				first, err := manager.Acquire(firstKey)
				if err != nil {
					t.Fatal(err)
				}
				defer first.Release()
				other, err := manager.Acquire(otherKey)
				if other != nil {
					_ = other.Release()
				}
				if !errors.Is(err, ErrDirectLockActive) || other != nil {
					t.Errorf("workspace alias bypassed active lock: error=%v", err)
				}
				if first.ResourceKey != "workspace:"+canonical {
					t.Errorf("noncanonical workspace identity: %q", first.ResourceKey)
				}
				if err := first.Release(); err != nil {
					t.Fatal(err)
				}
				again, err := manager.Acquire(otherKey)
				if err != nil {
					t.Fatal(err)
				}
				defer again.Release()
				if again.Path != first.Path {
					t.Error("aliases did not reuse one lock identity")
				}
				entries, err := os.ReadDir(repo)
				if err != nil || len(entries) != 0 {
					t.Error("workspace lock dirtied repository")
				}
			})
		}
	}
}

func TestLockManagerPreservesOpaqueAndAbsentWorkspaceKeys(t *testing.T) {
	for _, key := range []string{"workspace:custom", "custom:/work/repo", "other-resource", "workspace:" + filepath.Join(t.TempDir(), "absent", "repo")} {
		manager := NewLockManager(t.TempDir())
		lock, err := manager.Acquire(key)
		if err != nil {
			t.Fatal(err)
		}
		if lock.ResourceKey != key || filepath.Base(lock.Path) != directLockFilename(key) {
			t.Errorf("opaque/absent resource identity changed: %q -> %q", key, lock.ResourceKey)
		}
		if err := lock.Release(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLockManagerAllowsDifferentResourceKeys(t *testing.T) {
	manager := NewLockManager(t.TempDir())
	first, err := manager.Acquire("workspace:/work/repo-a")
	if err != nil {
		t.Fatalf("first Acquire() error = %v", err)
	}
	defer first.Release()

	second, err := manager.Acquire("workspace:/work/repo-b")
	if err != nil {
		t.Fatalf("second Acquire() error = %v", err)
	}
	defer second.Release()

	if first.Path == second.Path {
		t.Fatalf("lock paths should differ for different resource keys: %q", first.Path)
	}
}

func TestDirectLockReleaseIsIdempotent(t *testing.T) {
	manager := NewLockManager(t.TempDir())
	lock, err := manager.Acquire("workspace:/work/repo")
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("first Release() error = %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("second Release() error = %v", err)
	}
}
