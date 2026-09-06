package sandbox

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHostAndLeaseStoresUseGlobalDirNotProjectHal(t *testing.T) {
	global := t.TempDir()
	project := t.TempDir()
	t.Setenv(halConfigHomeEnv, global)
	t.Setenv(xdgConfigHomeEnv, "")
	t.Setenv("HOME", t.TempDir())

	projectHal := filepath.Join(project, ".hal")
	if err := os.MkdirAll(projectHal, 0o700); err != nil {
		t.Fatalf("MkdirAll(project .hal) failed: %v", err)
	}
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() failed: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Fatalf("restore working dir: %v", err)
		}
	})
	if err := os.Chdir(project); err != nil {
		t.Fatalf("Chdir() failed: %v", err)
	}

	if err := SaveHost(&SandboxHost{
		ID:   "host-01",
		Name: "builder-01",
		Kind: SandboxHostKindLocal,
	}); err != nil {
		t.Fatalf("SaveHost() failed: %v", err)
	}

	store := NewSandboxLeaseStore(func() time.Time {
		return time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	})
	if _, err := store.Acquire(SandboxLeaseAcquireRequest{
		ID:          "lease-01",
		SandboxName: "api-backend",
		ResourceKey: "sandbox:api-backend",
		Holder:      "worker-01",
		Purpose:     SandboxLeasePurposeRun,
	}, 30*time.Minute); err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	assertFileExists(t, filepath.Join(global, sandboxHostsDirName, "host-01.json"))
	assertFileExists(t, filepath.Join(global, sandboxLeasesDirName, "lease-01.json"))

	entries, err := os.ReadDir(projectHal)
	if err != nil {
		t.Fatalf("ReadDir(project .hal) failed: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("project .hal entries = %v, want empty", entries)
	}
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected %q to exist: %v", path, err)
	}
	if info.IsDir() {
		t.Fatalf("expected %q to be a file", path)
	}
}
