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
	"time"
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

func TestL3StoreRejectsSymlinkedRootAncestorWithoutExternalMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on some Windows setups")
	}

	type operation struct {
		name string
		run  func(Store) error
	}
	operations := []operation{
		{
			name: "ensure",
			run: func(store Store) error {
				return store.Ensure("exec-new")
			},
		},
		{
			name: "save manifest",
			run: func(store Store) error {
				return store.SaveManifest(testManifest("exec-new", time.Date(2026, 7, 25, 2, 0, 0, 0, time.UTC)))
			},
		},
		{
			name: "load manifest",
			run: func(store Store) error {
				_, err := store.LoadManifest("exec-existing")
				return err
			},
		},
		{
			name: "open stored file",
			run: func(store Store) error {
				file, err := store.OpenStoredFile("exec-existing", "exec-existing/artifacts/payload.txt")
				if file != nil {
					_ = file.Close()
				}
				return err
			},
		},
		{
			name: "execution lock",
			run: func(store Store) error {
				return store.WithExecutionLock("exec-existing", func() error {
					return errors.New("callback must not run")
				})
			},
		},
	}

	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			parent := t.TempDir()
			realParent := filepath.Join(parent, "private-real")
			if err := os.Mkdir(realParent, 0o700); err != nil {
				t.Fatalf("Mkdir(real parent) error: %v", err)
			}
			realRoot := filepath.Join(realParent, "store")
			realStore := NewStore(realRoot)
			if err := realStore.SaveManifest(testManifest("exec-existing", time.Date(2026, 7, 25, 1, 0, 0, 0, time.UTC))); err != nil {
				t.Fatalf("SaveManifest(real store) error: %v", err)
			}
			if _, err := realStore.WriteArtifactPayload("exec-existing", "payload.txt", []byte("canary")); err != nil {
				t.Fatalf("WriteArtifactPayload(real store) error: %v", err)
			}

			aliasParent := filepath.Join(parent, "ancestor-token=secret")
			if err := os.Symlink(realParent, aliasParent); err != nil {
				t.Fatalf("Symlink(ancestor) error: %v", err)
			}
			store := NewStore(filepath.Join(aliasParent, "store"))
			err := operation.run(store)
			if err == nil {
				t.Fatalf("%s accepted a symlinked store-root ancestor", operation.name)
			}
			for _, unsafe := range []string{parent, realParent, aliasParent, "ancestor-token=secret"} {
				if strings.Contains(err.Error(), unsafe) {
					t.Fatalf("%s error exposed unsafe path %q: %v", operation.name, unsafe, err)
				}
			}
			if _, statErr := os.Lstat(filepath.Join(realRoot, "exec-new")); !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatalf("%s mutated external store: %v", operation.name, statErr)
			}
			if _, statErr := os.Lstat(filepath.Join(realRoot, "exec-existing", executionLockFileName)); !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatalf("%s created an external lock: %v", operation.name, statErr)
			}
			payload, readErr := os.ReadFile(filepath.Join(realRoot, "exec-existing", artifactsDirName, "payload.txt"))
			if readErr != nil || string(payload) != "canary" {
				t.Fatalf("%s mutated external payload: data=%q err=%v", operation.name, payload, readErr)
			}
		})
	}
}

func TestL3StoreCreatesMissingPrivateRootSuffixForFirstUse(t *testing.T) {
	parent := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(parent); err == nil {
		parent = resolved
	}
	root := filepath.Join(parent, "fresh-config", "hal", storeDirName)
	store := NewStore(root)
	if err := store.SaveManifest(testManifest("exec-first-use", time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("SaveManifest(first use) error: %v", err)
	}
	if err := store.Ensure("exec-second"); err != nil {
		t.Fatalf("Ensure(second execution) error: %v", err)
	}

	for _, created := range []string{
		filepath.Join(parent, "fresh-config"),
		filepath.Join(parent, "fresh-config", "hal"),
		root,
		filepath.Join(root, "exec-first-use"),
		filepath.Join(root, "exec-second"),
	} {
		info, err := os.Lstat(created)
		if err != nil {
			t.Fatalf("Lstat(%s) error: %v", filepath.Base(created), err)
		}
		if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
			t.Fatalf("%s is not a real directory", filepath.Base(created))
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode = %#o, want 0700", filepath.Base(created), info.Mode().Perm())
		}
	}
}

func TestL3StoreRejectsUnsafeExistingRootComponentBeforeCreatingSuffix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on some Windows setups")
	}
	parent := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(parent); err == nil {
		parent = resolved
	}
	external := filepath.Join(parent, "external")
	if err := os.Mkdir(external, 0o700); err != nil {
		t.Fatalf("Mkdir(external) error: %v", err)
	}
	unsafeComponent := filepath.Join(parent, "unsafe-component")
	if err := os.Symlink(external, unsafeComponent); err != nil {
		t.Fatalf("Symlink(unsafe component) error: %v", err)
	}
	store := NewStore(filepath.Join(unsafeComponent, "missing-config", storeDirName))

	err := store.Ensure("exec-unsafe")
	if err == nil {
		t.Fatal("Ensure() accepted unsafe existing root component")
	}
	if _, statErr := os.Lstat(filepath.Join(external, "missing-config")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("Ensure() created suffix through unsafe component: %v", statErr)
	}
	for _, unsafe := range []string{parent, external, unsafeComponent} {
		if strings.Contains(err.Error(), unsafe) {
			t.Fatalf("Ensure() error exposed unsafe path %q: %v", unsafe, err)
		}
	}
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

func TestL3OpenStoredFileDescriptorSurvivesRootPathReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on some Windows setups")
	}
	store := newTestStore(t)
	stored, err := store.WriteArtifactPayload("exec-1", "payload.txt", []byte("trusted"))
	if err != nil {
		t.Fatalf("WriteArtifactPayload() error: %v", err)
	}
	file, err := store.OpenStoredFile("exec-1", stored.Path)
	if err != nil {
		t.Fatalf("OpenStoredFile() error: %v", err)
	}
	defer file.Close()

	movedRoot := store.Root() + "-moved"
	if err := os.Rename(store.Root(), movedRoot); err != nil {
		t.Fatalf("Rename(store root) error: %v", err)
	}
	externalRoot := filepath.Join(t.TempDir(), "external-store")
	externalStore := NewStore(externalRoot)
	if _, err := externalStore.WriteArtifactPayload("exec-1", "payload.txt", []byte("untrusted")); err != nil {
		t.Fatalf("WriteArtifactPayload(external) error: %v", err)
	}
	if err := os.Symlink(externalRoot, store.Root()); err != nil {
		t.Fatalf("Symlink(replacement root) error: %v", err)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll(opened payload) error: %v", err)
	}
	if string(data) != "trusted" {
		t.Fatalf("opened descriptor read %q after root replacement, want trusted", data)
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
