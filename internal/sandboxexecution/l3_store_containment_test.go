package sandboxexecution

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestL3ExecutionStoreRejectsUnsafeExistingLayoutWithoutMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory modes are not enforced on Windows")
	}

	t.Run("broad store root", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "sandbox-executions")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatalf("Mkdir(root) error: %v", err)
		}
		canary := filepath.Join(root, "unrelated")
		if err := os.WriteFile(canary, []byte("preserve"), 0o600); err != nil {
			t.Fatalf("WriteFile(canary) error: %v", err)
		}

		err := NewStore(root).Ensure("exec-private")
		if err == nil {
			t.Fatal("Ensure() accepted a broadly accessible existing store")
		}
		info, statErr := os.Stat(root)
		if statErr != nil {
			t.Fatalf("Stat(root) error: %v", statErr)
		}
		if got := info.Mode().Perm(); got != 0o755 {
			t.Fatalf("root mode = %#o, want unchanged 0755", got)
		}
		data, readErr := os.ReadFile(canary)
		if readErr != nil || string(data) != "preserve" {
			t.Fatalf("unrelated root content was mutated: data=%q err=%v", data, readErr)
		}
	})

	t.Run("symlinked execution directory", func(t *testing.T) {
		store := newTestStore(t)
		if err := os.Mkdir(store.Root(), 0o700); err != nil {
			t.Fatalf("Mkdir(store root) error: %v", err)
		}
		external := t.TempDir()
		executionDir := filepath.Join(store.Root(), "exec-linked")
		if err := os.Symlink(external, executionDir); err != nil {
			t.Fatalf("Symlink(execution) error: %v", err)
		}

		err := store.Ensure("exec-linked")
		if err == nil {
			t.Fatal("Ensure() accepted a symlinked execution directory")
		}
		if info, statErr := os.Lstat(executionDir); statErr != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("execution symlink was mutated: info=%v err=%v", info, statErr)
		}
		entries, readErr := os.ReadDir(external)
		if readErr != nil {
			t.Fatalf("ReadDir(external) error: %v", readErr)
		}
		if len(entries) != 0 {
			t.Fatalf("Ensure() wrote through execution symlink: %#v", entries)
		}
	})

	t.Run("symlinked payload area", func(t *testing.T) {
		store := newTestStore(t)
		if err := os.MkdirAll(filepath.Join(store.Root(), "exec-linked-area"), 0o700); err != nil {
			t.Fatalf("MkdirAll(execution) error: %v", err)
		}
		external := t.TempDir()
		area := filepath.Join(store.Root(), "exec-linked-area", artifactsDirName)
		if err := os.Symlink(external, area); err != nil {
			t.Fatalf("Symlink(artifact area) error: %v", err)
		}

		err := store.Ensure("exec-linked-area")
		if err == nil {
			t.Fatal("Ensure() accepted a symlinked payload area")
		}
		entries, readErr := os.ReadDir(external)
		if readErr != nil {
			t.Fatalf("ReadDir(external) error: %v", readErr)
		}
		if len(entries) != 0 {
			t.Fatalf("Ensure() wrote through payload symlink: %#v", entries)
		}
	})
}

func TestL3LoadManifestRejectsSymlinkAndUnknownFields(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 5, 0, 0, 0, time.UTC)

	t.Run("manifest symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires privileges on some Windows setups")
		}
		store := newTestStore(t)
		if err := store.Ensure("exec-linked-manifest"); err != nil {
			t.Fatalf("Ensure() error: %v", err)
		}
		externalDir := t.TempDir()
		external := filepath.Join(externalDir, "outside-token=manifest-secret.json")
		payload := `{"id":"exec-linked-manifest","purpose":"run","status":"running","startedAt":"` +
			startedAt.Format(time.RFC3339) + `"}`
		if err := os.WriteFile(external, []byte(payload), 0o600); err != nil {
			t.Fatalf("WriteFile(external) error: %v", err)
		}
		manifestPath, err := store.ManifestPath("exec-linked-manifest")
		if err != nil {
			t.Fatalf("ManifestPath() error: %v", err)
		}
		if err := os.Symlink(external, manifestPath); err != nil {
			t.Fatalf("Symlink(manifest) error: %v", err)
		}

		loaded, err := store.LoadManifest("exec-linked-manifest")
		if err == nil || loaded != nil {
			t.Fatalf("LoadManifest() = %#v, %v; want symlink rejection", loaded, err)
		}
		for _, unsafe := range []string{external, externalDir, "manifest-secret"} {
			if strings.Contains(err.Error(), unsafe) {
				t.Fatalf("LoadManifest() error exposed unsafe external value %q: %v", unsafe, err)
			}
		}
	})

	t.Run("unknown JSON field", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Ensure("exec-unknown-field"); err != nil {
			t.Fatalf("Ensure() error: %v", err)
		}
		path, err := store.ManifestPath("exec-unknown-field")
		if err != nil {
			t.Fatalf("ManifestPath() error: %v", err)
		}
		const secret = "must-not-be-accepted"
		payload := `{"id":"exec-unknown-field","purpose":"run","status":"running","startedAt":"` +
			startedAt.Format(time.RFC3339) + `","futureCommand":"` + secret + `"}`
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatalf("WriteFile(manifest) error: %v", err)
		}

		loaded, err := store.LoadManifest("exec-unknown-field")
		if err == nil || loaded != nil {
			t.Fatalf("LoadManifest() = %#v, %v; want unknown-field rejection", loaded, err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("LoadManifest() error exposed unknown field value: %v", err)
		}
	})
}

func TestL3ResolveStoredPathRejectsSymlinkPayload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on some Windows setups")
	}
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-resolve", time.Now().UTC())); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	externalDir := t.TempDir()
	external := filepath.Join(externalDir, "payload-token=outside-secret")
	if err := os.WriteFile(external, []byte("outside"), 0o600); err != nil {
		t.Fatalf("WriteFile(external) error: %v", err)
	}
	payload := filepath.Join(store.Root(), "exec-resolve", artifactsDirName, "output.patch")
	if err := os.Symlink(external, payload); err != nil {
		t.Fatalf("Symlink(payload) error: %v", err)
	}

	resolved, err := store.ResolveStoredPath("exec-resolve", "exec-resolve/artifacts/output.patch")
	if err == nil || resolved != "" {
		t.Fatalf("ResolveStoredPath() = %q, %v; want symlink rejection", resolved, err)
	}
	for _, unsafe := range []string{external, externalDir, "outside-secret"} {
		if strings.Contains(err.Error(), unsafe) {
			t.Fatalf("ResolveStoredPath() error exposed unsafe external value %q: %v", unsafe, err)
		}
	}

	info, statErr := os.Lstat(payload)
	if statErr != nil {
		t.Fatalf("Lstat(payload) error: %v", statErr)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("ResolveStoredPath() mutated the untrusted payload")
	}
	data, readErr := os.ReadFile(external)
	if readErr != nil || string(data) != "outside" {
		t.Fatalf("external payload was mutated: data=%q err=%v", data, readErr)
	}
}
