package factory

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestStoreDirReusesGlobalConfigPrecedence(t *testing.T) {
	tests := []struct {
		name string
		set  func(t *testing.T) string
	}{
		{
			name: "uses HAL_CONFIG_HOME when set",
			set: func(t *testing.T) string {
				halHome := filepath.Join(t.TempDir(), "hal-home")
				t.Setenv("HAL_CONFIG_HOME", halHome)
				t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "xdg-home"))
				t.Setenv("HOME", t.TempDir())
				return filepath.Join(halHome, factoryStoreDirName)
			},
		},
		{
			name: "uses XDG_CONFIG_HOME when HAL_CONFIG_HOME is unset",
			set: func(t *testing.T) string {
				xdgHome := filepath.Join(t.TempDir(), "xdg-home")
				t.Setenv("HAL_CONFIG_HOME", "")
				t.Setenv("XDG_CONFIG_HOME", xdgHome)
				t.Setenv("HOME", t.TempDir())
				return filepath.Join(xdgHome, "hal", factoryStoreDirName)
			},
		},
		{
			name: "falls back to HOME/.config/hal",
			set: func(t *testing.T) string {
				home := t.TempDir()
				t.Setenv("HAL_CONFIG_HOME", "")
				t.Setenv("XDG_CONFIG_HOME", "")
				t.Setenv("HOME", home)
				return filepath.Join(home, ".config", "hal", factoryStoreDirName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.set(t)
			got := StoreDir()
			if got != want {
				t.Fatalf("StoreDir() = %q, want %q", got, want)
			}
		})
	}
}

func TestDefaultStorePaths(t *testing.T) {
	global := filepath.Join(t.TempDir(), "global-hal")
	t.Setenv("HAL_CONFIG_HOME", global)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())

	store, err := DefaultStore()
	if err != nil {
		t.Fatalf("DefaultStore() unexpected error: %v", err)
	}

	root := filepath.Join(global, factoryStoreDirName)
	if store.Root() != root {
		t.Fatalf("Root() = %q, want %q", store.Root(), root)
	}
	if store.RunsDir() != filepath.Join(root, runsDirName) {
		t.Fatalf("RunsDir() = %q, want %q", store.RunsDir(), filepath.Join(root, runsDirName))
	}
	if store.TimelinesDir() != filepath.Join(root, timelinesDirName) {
		t.Fatalf("TimelinesDir() = %q, want %q", store.TimelinesDir(), filepath.Join(root, timelinesDirName))
	}
}

func TestEnsureStoreDirCreatesRestrictiveDirectories(t *testing.T) {
	global := filepath.Join(t.TempDir(), "global-hal")
	t.Setenv("HAL_CONFIG_HOME", global)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())

	if err := EnsureStoreDir(); err != nil {
		t.Fatalf("EnsureStoreDir() unexpected error: %v", err)
	}

	for _, path := range []string{
		global,
		filepath.Join(global, factoryStoreDirName),
		filepath.Join(global, factoryStoreDirName, runsDirName),
		filepath.Join(global, factoryStoreDirName, timelinesDirName),
	} {
		assertFactoryDirExists(t, path)
		if runtime.GOOS != "windows" {
			assertFactoryDirPerm(t, path, 0o700)
		}
	}

	if err := EnsureStoreDir(); err != nil {
		t.Fatalf("EnsureStoreDir() should be idempotent, got error: %v", err)
	}
}

func TestListRunIDsTreatsMissingStoreAsEmpty(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))

	got, err := store.ListRunIDs()
	if err != nil {
		t.Fatalf("ListRunIDs() unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListRunIDs() = %v, want empty", got)
	}
}

func TestListRunIDsReturnsDeterministicOrder(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	if err := store.Ensure(); err != nil {
		t.Fatalf("Ensure() unexpected error: %v", err)
	}
	for _, name := range []string{"run-c.json", "README.md", "run-a.json", "run-b"} {
		path := filepath.Join(store.RunsDir(), name)
		if filepath.Ext(name) == "" {
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatalf("mkdir %q: %v", path, err)
			}
			continue
		}
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("write %q: %v", path, err)
		}
	}

	got, err := store.ListRunIDs()
	if err != nil {
		t.Fatalf("ListRunIDs() unexpected error: %v", err)
	}
	want := []string{"run-a", "run-b", "run-c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListRunIDs() = %v, want %v", got, want)
	}
}

func TestSaveRunAndLoadRunRoundTripWithNewStore(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := testRunRecord("run-001")

	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() unexpected error: %v", err)
	}

	recordPath := filepath.Join(store.RunsDir(), record.RunID+runRecordFileExt)
	info, err := os.Stat(recordPath)
	if err != nil {
		t.Fatalf("expected committed run record: %v", err)
	}
	if info.IsDir() {
		t.Fatalf("run record path should be a file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("run record permissions = %o, want %o", info.Mode().Perm(), 0o600)
	}
	if _, err := os.Stat(recordPath + storeTempFileExt); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("temp file should not remain after SaveRun(), stat error = %v", err)
	}

	reloadedStore := NewStore(store.Root())
	loaded, err := reloadedStore.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(*loaded, record) {
		t.Fatalf("LoadRun() = %#v, want %#v", *loaded, record)
	}
}

func TestSaveRunUpdatesExistingRunRecord(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := testRunRecord("run-002")

	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun(initial) unexpected error: %v", err)
	}

	record.Status = RunStatusSucceeded
	record.CurrentStep = "done"
	record.UpdatedAt = record.UpdatedAt.Add(5 * time.Minute)
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun(update) unexpected error: %v", err)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() unexpected error: %v", err)
	}
	if loaded.Status != RunStatusSucceeded {
		t.Fatalf("loaded status = %q, want %q", loaded.Status, RunStatusSucceeded)
	}
	if loaded.CurrentStep != "done" {
		t.Fatalf("loaded current step = %q, want done", loaded.CurrentStep)
	}
	if !loaded.UpdatedAt.Equal(record.UpdatedAt) {
		t.Fatalf("loaded updatedAt = %s, want %s", loaded.UpdatedAt, record.UpdatedAt)
	}
}

func TestLoadRunMissingReturnsNotExist(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))

	_, err := store.LoadRun("missing-run")
	if err == nil {
		t.Fatalf("LoadRun() expected error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadRun() error = %v, want errors.Is(..., fs.ErrNotExist)", err)
	}
}

func TestSaveRunRequiresStableRunID(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := testRunRecord("")

	if err := store.SaveRun(&record); err == nil {
		t.Fatalf("SaveRun() expected missing run ID error")
	}
}

func TestSaveRunRejectsInvalidRunID(t *testing.T) {
	tests := []string{
		" run-003",
		"run-003 ",
		"../run-003",
		`run\003`,
		".",
		"..",
	}

	for _, runID := range tests {
		t.Run(runID, func(t *testing.T) {
			store := NewStore(filepath.Join(t.TempDir(), "factory"))
			record := testRunRecord(runID)

			if err := store.SaveRun(&record); err == nil {
				t.Fatalf("SaveRun() expected invalid run ID error")
			}
		})
	}
}

func assertFactoryDirExists(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected %q to exist: %v", path, err)
	}
	if !info.IsDir() {
		t.Fatalf("expected %q to be a directory", path)
	}
}

func assertFactoryDirPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("permissions for %q = %o, want %o", path, info.Mode().Perm(), want)
	}
}

func testRunRecord(runID string) RunRecord {
	createdAt := time.Date(2026, 6, 20, 15, 0, 0, 0, time.UTC)
	updatedAt := createdAt.Add(2 * time.Minute)

	return RunRecord{
		RunID:  runID,
		Status: RunStatusRunning,
		Source: SourceMetadata{
			Kind:  "markdown",
			Path:  ".hal/prd-factory.md",
			Title: "Factory run records",
		},
		RepoPath:    "/work/hal",
		RepoRemote:  "git@github.com:jywlabs/hal.git",
		BranchName:  "hal/factory-run-records",
		BaseBranch:  "develop",
		CurrentStep: "run",
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
		Artifacts: []ArtifactReference{
			{Name: "prd", Type: "json", Path: ".hal/prd.json"},
		},
	}
}
