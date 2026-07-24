package sandboxexecution

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestL3EnsureRejectsSymlinkedRootAndPrivateLayoutViolations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode and symlink assertions")
	}

	t.Run("symlinked root", func(t *testing.T) {
		parent := t.TempDir()
		external := t.TempDir()
		root := filepath.Join(parent, "store")
		if err := os.Symlink(external, root); err != nil {
			t.Fatalf("Symlink(root) error: %v", err)
		}

		err := NewStore(root).Ensure("exec-1")
		if err == nil {
			t.Fatal("Ensure() accepted symlinked store root")
		}
		if _, statErr := os.Stat(filepath.Join(external, "exec-1")); !errors.Is(statErr, fs.ErrNotExist) {
			t.Fatalf("external execution path was touched: %v", statErr)
		}
	})

	t.Run("broad payload directory", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Ensure("exec-1"); err != nil {
			t.Fatalf("Ensure() error: %v", err)
		}
		artifacts := filepath.Join(store.Root(), "exec-1", artifactsDirName)
		if err := os.Chmod(artifacts, 0o755); err != nil {
			t.Fatalf("Chmod(artifacts) error: %v", err)
		}

		err := store.Ensure("exec-1")
		if err == nil {
			t.Fatal("Ensure() accepted broad payload directory")
		}
		assertMode(t, artifacts, 0o755)
	})
}

func TestL3LoadManifestRejectsTrailingAndInvalidSemanticState(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{
			name: "trailing JSON",
			data: `{"id":"exec-1","purpose":"run","status":"running","startedAt":"2026-07-25T01:02:03Z"} {"secret":"do-not-leak"}`,
		},
		{
			name: "invalid core state",
			data: `{"id":"exec-1","purpose":"unexpected","status":"running","startedAt":"2026-07-25T01:02:03Z"}`,
		},
		{
			name: "invalid finalization state",
			data: `{"id":"exec-1","purpose":"run","status":"running","startedAt":"2026-07-25T01:02:03Z","finalization":{"contractVersion":"sandbox-finalization-v1","state":"surprise","checkpoints":{"artifacts":{"completed":false},"syncOut":{"completed":false},"leaseRelease":{"completed":false},"terminalPublication":{"completed":false}},"updatedAt":"2026-07-25T01:02:03Z"}}`,
		},
		{
			name: "invalid worker job state",
			data: `{"id":"exec-1","purpose":"run","status":"running","startedAt":"2026-07-25T01:02:03Z","workerJob":{"contractVersion":"sandboxjob-v1","jobId":"job-1","workerId":"worker-1","runtimeDriver":"rootless","state":"surprise","submittedAt":"2026-07-25T01:02:03Z","logCursor":0}}`,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			if err := store.Ensure("exec-1"); err != nil {
				t.Fatalf("Ensure() error: %v", err)
			}
			path, err := store.ManifestPath("exec-1")
			if err != nil {
				t.Fatalf("ManifestPath() error: %v", err)
			}
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatalf("WriteFile(manifest) error: %v", err)
			}

			manifest, err := store.LoadManifest("exec-1")
			if err == nil || manifest != nil {
				t.Fatalf("LoadManifest() = (%+v, %v), want rejection", manifest, err)
			}
			if strings.Contains(err.Error(), "do-not-leak") {
				t.Fatalf("LoadManifest() error leaked trailing data: %v", err)
			}
		})
	}
}

func TestL3ResolveStoredPathRequiresPrivateRegularPayload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode assertions")
	}
	store := newTestStore(t)
	if err := store.Ensure("exec-1"); err != nil {
		t.Fatalf("Ensure() error: %v", err)
	}

	cases := []struct {
		name  string
		setup func(string) error
	}{
		{name: "missing", setup: func(string) error { return nil }},
		{name: "directory", setup: func(path string) error { return os.Mkdir(path, 0o700) }},
		{name: "broad regular file", setup: func(path string) error { return os.WriteFile(path, []byte("payload"), 0o644) }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(store.Root(), "exec-1", artifactsDirName, tt.name)
			if err := tt.setup(path); err != nil {
				t.Fatalf("setup error: %v", err)
			}
			resolved, err := store.ResolveStoredPath("exec-1", filepath.ToSlash(filepath.Join("exec-1", artifactsDirName, tt.name)))
			if err == nil || resolved != "" {
				t.Fatalf("ResolveStoredPath() = (%q, %v), want rejection", resolved, err)
			}
		})
	}
}

func TestL3OpenStoredFileReturnsVerifiedContainedRegularFile(t *testing.T) {
	store := newTestStore(t)
	stored, err := store.WriteArtifactPayload("exec-1", "nested/payload.txt", []byte("payload"))
	if err != nil {
		t.Fatalf("WriteArtifactPayload() error: %v", err)
	}

	file, err := store.OpenStoredFile("exec-1", stored.Path)
	if err != nil {
		t.Fatalf("OpenStoredFile() error: %v", err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll(opened payload) error: %v", err)
	}
	if string(data) != "payload" {
		t.Fatalf("opened payload = %q, want payload", data)
	}
}

func TestL3ExecutionLockRejectsUnsafeExistingLockWithoutMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode and symlink assertions")
	}

	t.Run("symlink", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Ensure("exec-1"); err != nil {
			t.Fatalf("Ensure() error: %v", err)
		}
		external := filepath.Join(t.TempDir(), "external.lock")
		if err := os.WriteFile(external, []byte("canary"), 0o600); err != nil {
			t.Fatalf("WriteFile(external) error: %v", err)
		}
		lockPath := filepath.Join(store.Root(), "exec-1", executionLockFileName)
		if err := os.Symlink(external, lockPath); err != nil {
			t.Fatalf("Symlink(lock) error: %v", err)
		}
		called := false
		err := store.WithExecutionLock("exec-1", func() error {
			called = true
			return nil
		})
		if err == nil || called {
			t.Fatalf("WithExecutionLock() = %v, called=%v, want rejection", err, called)
		}
		data, readErr := os.ReadFile(external)
		if readErr != nil || string(data) != "canary" {
			t.Fatalf("external lock changed: data=%q err=%v", data, readErr)
		}
	})

	t.Run("broad regular file", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Ensure("exec-1"); err != nil {
			t.Fatalf("Ensure() error: %v", err)
		}
		lockPath := filepath.Join(store.Root(), "exec-1", executionLockFileName)
		if err := os.WriteFile(lockPath, []byte("canary"), 0o644); err != nil {
			t.Fatalf("WriteFile(lock) error: %v", err)
		}
		called := false
		err := store.WithExecutionLock("exec-1", func() error {
			called = true
			return nil
		})
		if err == nil || called {
			t.Fatalf("WithExecutionLock() = %v, called=%v, want rejection", err, called)
		}
		assertMode(t, lockPath, 0o644)
	})
}
