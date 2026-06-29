package sandboxexecution

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDefaultStoreUsesSandboxGlobalDir(t *testing.T) {
	globalDir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", globalDir)

	if got, want := StoreDir(), filepath.Join(globalDir, storeDirName); got != want {
		t.Fatalf("StoreDir() = %q, want %q", got, want)
	}
	store, err := DefaultStore()
	if err != nil {
		t.Fatalf("DefaultStore() error: %v", err)
	}
	if got, want := store.Root(), filepath.Join(globalDir, storeDirName); got != want {
		t.Fatalf("DefaultStore().Root() = %q, want %q", got, want)
	}
}

func TestEnsureCreatesExecutionLayoutWithPrivateModes(t *testing.T) {
	store := newTestStore(t)
	if err := store.Ensure("exec-1"); err != nil {
		t.Fatalf("Ensure() error: %v", err)
	}

	for _, path := range []string{
		store.Root(),
		filepath.Join(store.Root(), "exec-1"),
		filepath.Join(store.Root(), "exec-1", logsDirName),
		filepath.Join(store.Root(), "exec-1", artifactsDirName),
		filepath.Join(store.Root(), "exec-1", handoffDirName),
		filepath.Join(store.Root(), "exec-1", recoveryDirName),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", path)
		}
		assertMode(t, path, 0o700)
	}
}

func TestEnsureRejectsInvalidExecutionIDsBeforeMutation(t *testing.T) {
	for _, id := range []string{"", "/absolute", "../escape", "a/../b", "a/b", `a\b`, " exec"} {
		t.Run(id, func(t *testing.T) {
			store := newTestStore(t)
			err := store.Ensure(id)
			if err == nil {
				t.Fatalf("Ensure(%q) expected error", id)
			}
			assertPathMissing(t, store.Root())
		})
	}
}

func TestSaveManifestValidatesBeforeCreatingDirectories(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		manifest *Manifest
	}{
		{name: "nil", manifest: nil},
		{name: "empty id", manifest: &Manifest{Purpose: PurposeRun, Status: StatusRunning, StartedAt: startedAt}},
		{name: "bad purpose", manifest: &Manifest{ID: "exec-1", Purpose: "factory", Status: StatusRunning, StartedAt: startedAt}},
		{name: "bad status", manifest: &Manifest{ID: "exec-1", Purpose: PurposeRun, Status: "pending", StartedAt: startedAt}},
		{name: "zero startedAt", manifest: &Manifest{ID: "exec-1", Purpose: PurposeRun, Status: StatusRunning}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			err := store.SaveManifest(tt.manifest)
			if err == nil {
				t.Fatalf("SaveManifest() expected validation error")
			}
			assertPathMissing(t, store.Root())
			assertNoTempFiles(t, filepath.Dir(store.Root()))
		})
	}
}

func TestSaveManifestAtomicallyWritesManifest(t *testing.T) {
	store := newTestStore(t)
	manifest := testManifest("exec-1", time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC))
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}

	path, err := store.ManifestPath("exec-1")
	if err != nil {
		t.Fatalf("ManifestPath() error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(manifest) error: %v", err)
	}
	if !strings.Contains(string(data), `"id": "exec-1"`) {
		t.Fatalf("manifest contents = %s, want exec ID", data)
	}
	assertMode(t, path, 0o600)
	assertNoTempFiles(t, store.Root())
}

func TestSaveManifestRejectsUnsafeArtifactMetadataBeforeMutation(t *testing.T) {
	for _, storedPath := range []string{"/tmp/secret", "../escape", "other-exec/artifacts/out.txt", `exec-1\artifacts\out.txt`} {
		t.Run(storedPath, func(t *testing.T) {
			store := newTestStore(t)
			manifest := testManifest("exec-1", time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC))
			manifest.Artifacts = []Artifact{{
				ID:         "artifact",
				Name:       "Artifact",
				Type:       "text",
				StoredPath: storedPath,
			}}
			err := store.SaveManifest(manifest)
			if err == nil {
				t.Fatalf("SaveManifest() expected artifact path validation error")
			}
			assertPathMissing(t, store.Root())
		})
	}
}

func TestLoadManifestMissingWrapsNotExist(t *testing.T) {
	store := newTestStore(t)
	_, err := store.LoadManifest("missing")
	if err == nil {
		t.Fatalf("LoadManifest() expected missing error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadManifest() error = %v, want fs.ErrNotExist", err)
	}
}

func TestLoadManifestRejectsInvalidIDBeforeRead(t *testing.T) {
	store := newTestStore(t)
	_, err := store.LoadManifest("../escape")
	if err == nil {
		t.Fatalf("LoadManifest() expected invalid ID error")
	}
	assertPathMissing(t, store.Root())
}

func TestLoadManifestCorruptReturnsParseAndPreservesBytes(t *testing.T) {
	store := newTestStore(t)
	if err := store.Ensure("exec-1"); err != nil {
		t.Fatalf("Ensure() error: %v", err)
	}
	path, err := store.ManifestPath("exec-1")
	if err != nil {
		t.Fatalf("ManifestPath() error: %v", err)
	}
	corrupt := []byte(`{"id":`)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt) error: %v", err)
	}

	_, err = store.LoadManifest("exec-1")
	if err == nil || !strings.Contains(err.Error(), "parse sandbox execution manifest") {
		t.Fatalf("LoadManifest() error = %v, want parse error", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile(corrupt) error: %v", readErr)
	}
	if string(got) != string(corrupt) {
		t.Fatalf("corrupt manifest bytes changed: got %q want %q", got, corrupt)
	}
}

func TestListManifestsMissingRootIsEmpty(t *testing.T) {
	store := newTestStore(t)
	got, err := store.ListManifests()
	if err != nil {
		t.Fatalf("ListManifests() error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListManifests() = %#v, want empty", got)
	}
	assertPathMissing(t, store.Root())
}

func TestListManifestsSortsAndSkipsNonDirectories(t *testing.T) {
	store := newTestStore(t)
	early := time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC)
	late := time.Date(2026, 6, 30, 2, 0, 0, 0, time.UTC)
	for _, manifest := range []*Manifest{
		testManifest("b-late", late),
		testManifest("c-early", early),
		testManifest("a-early", early),
	} {
		if err := store.SaveManifest(manifest); err != nil {
			t.Fatalf("SaveManifest(%s) error: %v", manifest.ID, err)
		}
	}
	if err := os.WriteFile(filepath.Join(store.Root(), "README.md"), []byte("ignore\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(non-directory) error: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(store.Root(), "empty-dir"), 0o700); err != nil {
		t.Fatalf("MkdirAll(empty-dir) error: %v", err)
	}

	got, err := store.ListManifests()
	if err != nil {
		t.Fatalf("ListManifests() error: %v", err)
	}
	gotIDs := manifestIDs(got)
	wantIDs := []string{"a-early", "c-early", "b-late"}
	if !reflectStringSlicesEqual(gotIDs, wantIDs) {
		t.Fatalf("ListManifests() IDs = %v, want %v", gotIDs, wantIDs)
	}
}

func TestListManifestsCorruptReturnsParseAndPreservesBytes(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("valid", time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	if err := store.Ensure("corrupt"); err != nil {
		t.Fatalf("Ensure(corrupt) error: %v", err)
	}
	path, err := store.ManifestPath("corrupt")
	if err != nil {
		t.Fatalf("ManifestPath() error: %v", err)
	}
	corrupt := []byte("{not-json")
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt) error: %v", err)
	}

	_, err = store.ListManifests()
	if err == nil || !strings.Contains(err.Error(), "parse sandbox execution manifest") {
		t.Fatalf("ListManifests() error = %v, want parse error", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile(corrupt) error: %v", readErr)
	}
	if string(got) != string(corrupt) {
		t.Fatalf("corrupt manifest bytes changed: got %q want %q", got, corrupt)
	}
}

func TestRemoveExecutionRecord(t *testing.T) {
	store := newTestStore(t)
	for _, id := range []string{"exec-1", "exec-2"} {
		if err := store.SaveManifest(testManifest(id, time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC))); err != nil {
			t.Fatalf("SaveManifest(%s) error: %v", id, err)
		}
	}
	if err := store.Remove("exec-1"); err != nil {
		t.Fatalf("Remove() error: %v", err)
	}
	assertPathMissing(t, filepath.Join(store.Root(), "exec-1"))
	if _, err := os.Stat(filepath.Join(store.Root(), "exec-2")); err != nil {
		t.Fatalf("sibling execution missing after remove: %v", err)
	}

	err := store.Remove("exec-1")
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Remove(missing) error = %v, want fs.ErrNotExist", err)
	}

	if err := store.Remove("../escape"); err == nil {
		t.Fatalf("Remove(invalid) expected error")
	}
	if _, err := os.Stat(filepath.Join(store.Root(), "exec-2")); err != nil {
		t.Fatalf("sibling execution changed after invalid remove: %v", err)
	}
}

func newTestStore(t *testing.T) Store {
	t.Helper()
	return NewStore(filepath.Join(t.TempDir(), storeDirName))
}

func testManifest(id string, startedAt time.Time) *Manifest {
	return &Manifest{
		ID:          id,
		Purpose:     PurposeRun,
		SandboxName: "dev",
		ProjectDir:  "/repo",
		Command:     []string{"go", "test", "./..."},
		WorkDir:     "/repo",
		Status:      StatusRunning,
		StartedAt:   startedAt,
	}
}

func manifestIDs(manifests []Manifest) []string {
	ids := make([]string, 0, len(manifests))
	for _, manifest := range manifests {
		ids = append(ids, manifest.ID)
	}
	return ids
}

func reflectStringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func assertMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("%s exists, want missing", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat %s error = %v, want missing", path, err)
	}
}

func assertNoTempFiles(t *testing.T, root string) {
	t.Helper()
	if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
		return
	}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if strings.HasSuffix(entry.Name(), tempFileSuffix) {
			t.Fatalf("unexpected temp file left behind: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir(%s) error: %v", root, err)
	}
}
