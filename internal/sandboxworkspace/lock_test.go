package sandboxworkspace

import (
	"errors"
	"os"
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
