package factory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCollectSandboxArtifactsCopiesFilesAndDirectoriesThroughAbstraction(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := testRunRecord("run-sandbox-artifacts")
	record.Artifacts = nil
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() unexpected error: %v", err)
	}

	copier := &fakeSandboxArtifactCopier{
		files: map[string]string{
			"/workspace/.hal/reports/factory.log": "factory log\n",
		},
		dirs: map[string]map[string]string{
			"/workspace/.hal/reports/verify": {
				"test/stdout.txt": "stdout\n",
				"test-stdout.txt": "flat stdout\n",
				"summary.json":    `{"passed":1}` + "\n",
			},
		},
	}

	artifacts, err := CollectSandboxArtifacts(context.Background(), store, record.RunID, copier, []SandboxArtifactRequest{
		{
			ID:         "factory-log",
			Name:       "factory-log",
			Type:       "text",
			RemotePath: "/workspace/.hal/reports/factory.log",
			Path:       ".hal/reports/factory.log",
			Summary:    map[string]any{"source": "sandbox"},
		},
		{
			ID:         "verify",
			Name:       "verify",
			Type:       "directory",
			RemotePath: "/workspace/.hal/reports/verify",
			Path:       ".hal/reports/verify",
			Directory:  true,
			Summary:    map[string]any{"source": "sandbox"},
		},
	})
	if err != nil {
		t.Fatalf("CollectSandboxArtifacts() unexpected error: %v", err)
	}
	if len(artifacts) != 4 {
		t.Fatalf("artifacts len = %d, want 4: %#v", len(artifacts), artifacts)
	}

	if !reflect.DeepEqual(copier.fileCalls, []copyCall{{
		remotePath: "/workspace/.hal/reports/factory.log",
	}}) {
		t.Fatalf("CopyFile calls = %#v", copier.fileCalls)
	}
	if !reflect.DeepEqual(copier.dirCalls, []copyCall{{
		remotePath: "/workspace/.hal/reports/verify",
	}}) {
		t.Fatalf("CopyDir calls = %#v", copier.dirCalls)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() unexpected error: %v", err)
	}
	for _, wantPath := range []string{
		".hal/reports/factory.log",
		".hal/reports/verify/summary.json",
		".hal/reports/verify/test/stdout.txt",
		".hal/reports/verify/test-stdout.txt",
	} {
		artifact := requireStoredArtifact(t, store, record.RunID, loaded.Artifacts, wantPath)
		if artifact.SourcePath != "" {
			t.Fatalf("sandbox artifact %q SourcePath = %q, want empty", wantPath, artifact.SourcePath)
		}
		if artifact.Summary["source"] != "sandbox" {
			t.Fatalf("sandbox artifact %q summary = %#v", wantPath, artifact.Summary)
		}
	}

	logArtifact := requireStoredArtifact(t, store, record.RunID, loaded.Artifacts, ".hal/reports/factory.log")
	logData := readStoredArtifact(t, store, record.RunID, logArtifact)
	if logData != "factory log\n" {
		t.Fatalf("stored log data = %q", logData)
	}
	summaryArtifact := requireStoredArtifact(t, store, record.RunID, loaded.Artifacts, ".hal/reports/verify/summary.json")
	summaryData := readStoredArtifact(t, store, record.RunID, summaryArtifact)
	if !strings.Contains(summaryData, `"passed":1`) {
		t.Fatalf("stored summary data = %q", summaryData)
	}
	flatStdoutArtifact := requireStoredArtifact(t, store, record.RunID, loaded.Artifacts, ".hal/reports/verify/test-stdout.txt")
	if got := readStoredArtifact(t, store, record.RunID, flatStdoutArtifact); got != "flat stdout\n" {
		t.Fatalf("stored flat stdout data = %q", got)
	}

	encoded, err := json.Marshal(loaded)
	if err != nil {
		t.Fatalf("Marshal(run) error: %v", err)
	}
	if strings.Contains(string(encoded), "/workspace/") {
		t.Fatalf("run metadata should not expose remote workspace paths: %s", encoded)
	}
}

func TestCollectSandboxArtifactsKeepsDotDirectoryIDInTempChild(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := testRunRecord("run-sandbox-dot-directory-id")
	record.Artifacts = nil
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() unexpected error: %v", err)
	}

	copier := &fakeSandboxArtifactCopier{
		files: map[string]string{
			"/workspace/.hal/reports/factory.log": "factory log\n",
		},
		dirs: map[string]map[string]string{
			"/workspace/.hal/reports/dot": {
				"payload.txt": "payload\n",
			},
		},
	}

	_, err := CollectSandboxArtifacts(context.Background(), store, record.RunID, copier, []SandboxArtifactRequest{
		{
			ID:         "factory-log",
			Name:       "factory-log",
			Type:       "text",
			RemotePath: "/workspace/.hal/reports/factory.log",
			Path:       ".hal/reports/factory.log",
		},
		{
			ID:         ".",
			Name:       "dot",
			Type:       "directory",
			RemotePath: "/workspace/.hal/reports/dot",
			Path:       ".hal/reports/dot",
			Directory:  true,
		},
	})
	if err != nil {
		t.Fatalf("CollectSandboxArtifacts() unexpected error: %v", err)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() unexpected error: %v", err)
	}
	requireStoredArtifact(t, store, record.RunID, loaded.Artifacts, ".hal/reports/factory.log")
	requireStoredArtifact(t, store, record.RunID, loaded.Artifacts, ".hal/reports/dot/payload.txt")
	if len(loaded.Artifacts) != 2 {
		t.Fatalf("artifacts len = %d, want 2: %#v", len(loaded.Artifacts), loaded.Artifacts)
	}
}

func TestCollectSandboxArtifactsRecordsMissingOptionalWarnings(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := testRunRecord("run-sandbox-missing")
	record.Artifacts = nil
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() unexpected error: %v", err)
	}

	_, err := CollectSandboxArtifacts(context.Background(), store, record.RunID, &fakeSandboxArtifactCopier{
		fileErrs: map[string]error{
			"/workspace/.hal/reports/missing.log": ErrSandboxArtifactNotFound,
		},
	}, []SandboxArtifactRequest{
		{
			ID:         "missing-log",
			Name:       "missing-log",
			Type:       "text",
			RemotePath: "/workspace/.hal/reports/missing.log",
			Path:       ".hal/reports/missing.log",
			Optional:   true,
		},
	})
	if err != nil {
		t.Fatalf("CollectSandboxArtifacts() unexpected error: %v", err)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() unexpected error: %v", err)
	}
	artifact := requireArtifactPath(t, loaded.Artifacts, ".hal/reports/missing.log")
	if !artifact.Partial {
		t.Fatalf("missing artifact Partial = false, want true")
	}
	if artifact.StoredPath != "" || artifact.SourcePath != "" {
		t.Fatalf("missing artifact should not have stored/source paths: %#v", artifact)
	}
	if len(artifact.Warnings) != 1 || !strings.Contains(artifact.Warnings[0], "optional sandbox artifact not found") {
		t.Fatalf("missing artifact warnings = %#v", artifact.Warnings)
	}
	if artifact.Summary["collectionStatus"] != "missing" {
		t.Fatalf("missing artifact summary = %#v", artifact.Summary)
	}

	encoded, err := json.Marshal(loaded)
	if err != nil {
		t.Fatalf("Marshal(run) error: %v", err)
	}
	if strings.Contains(string(encoded), "/workspace/") {
		t.Fatalf("missing artifact metadata should not expose remote workspace paths: %s", encoded)
	}
}

func TestCollectSandboxArtifactsFailsRequiredCopyErrors(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := testRunRecord("run-sandbox-copy-error")
	record.Artifacts = nil
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() unexpected error: %v", err)
	}
	copyErr := errors.New("permission denied")

	_, err := CollectSandboxArtifacts(context.Background(), store, record.RunID, &fakeSandboxArtifactCopier{
		fileErrs: map[string]error{
			"/workspace/.hal/reports/factory.log": copyErr,
		},
	}, []SandboxArtifactRequest{
		{
			ID:         "factory-log",
			Name:       "factory-log",
			Type:       "text",
			RemotePath: "/workspace/.hal/reports/factory.log",
			Path:       ".hal/reports/factory.log",
		},
	})
	if !errors.Is(err, copyErr) {
		t.Fatalf("CollectSandboxArtifacts() error = %v, want wrapped copy error", err)
	}
	if !strings.Contains(err.Error(), `copy sandbox artifact "factory-log"`) {
		t.Fatalf("CollectSandboxArtifacts() error = %q, want actionable artifact context", err.Error())
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() unexpected error: %v", err)
	}
	if len(loaded.Artifacts) != 0 {
		t.Fatalf("artifacts = %#v, want none after required copy failure", loaded.Artifacts)
	}
}

func TestCollectSandboxArtifactsSanitizesSavedArtifactBeforeLaterFailure(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := testRunRecord("run-sandbox-later-copy-error")
	record.Artifacts = nil
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() unexpected error: %v", err)
	}
	copyErr := errors.New("permission denied")

	_, err := CollectSandboxArtifacts(context.Background(), store, record.RunID, &fakeSandboxArtifactCopier{
		files: map[string]string{
			"/workspace/.hal/reports/factory.log": "factory log\n",
		},
		fileErrs: map[string]error{
			"/workspace/.hal/reports/later.log": copyErr,
		},
	}, []SandboxArtifactRequest{
		{
			ID:         "factory-log",
			Name:       "factory-log",
			Type:       "text",
			RemotePath: "/workspace/.hal/reports/factory.log",
			Path:       ".hal/reports/factory.log",
		},
		{
			ID:         "later-log",
			Name:       "later-log",
			Type:       "text",
			RemotePath: "/workspace/.hal/reports/later.log",
			Path:       ".hal/reports/later.log",
		},
	})
	if !errors.Is(err, copyErr) {
		t.Fatalf("CollectSandboxArtifacts() error = %v, want wrapped copy error", err)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() unexpected error: %v", err)
	}
	artifact := requireArtifactPath(t, loaded.Artifacts, ".hal/reports/factory.log")
	if artifact.SourcePath != "" {
		t.Fatalf("sandbox artifact SourcePath = %q, want empty after later failure", artifact.SourcePath)
	}

	encoded, err := json.Marshal(loaded)
	if err != nil {
		t.Fatalf("Marshal(run) error: %v", err)
	}
	if strings.Contains(string(encoded), "hal-factory-sandbox-artifacts-") {
		t.Fatalf("run metadata should not expose temp sandbox paths after later failure: %s", encoded)
	}
}

func TestStoreSandboxArtifactDirSkipsSymlinks(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := testRunRecord("run-sandbox-symlink")
	record.Artifacts = nil
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() unexpected error: %v", err)
	}

	localDir := filepath.Join(t.TempDir(), "copied")
	if err := os.MkdirAll(localDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() unexpected error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "regular.txt"), []byte("regular\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() unexpected error: %v", err)
	}
	secretPath := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secretPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(secret) unexpected error: %v", err)
	}
	if err := os.Symlink(secretPath, filepath.Join(localDir, "leak.txt")); err != nil {
		t.Skipf("Symlink() unavailable: %v", err)
	}

	artifacts, _, err := storeSandboxArtifactDir(store, record.RunID, SandboxArtifactRequest{
		ID:   "verify",
		Name: "verify",
		Type: "directory",
		Path: ".hal/reports/verify",
	}, localDir)
	if err != nil {
		t.Fatalf("storeSandboxArtifactDir() unexpected error: %v", err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("artifacts len = %d, want 1: %#v", len(artifacts), artifacts)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() unexpected error: %v", err)
	}
	regular := requireStoredArtifact(t, store, record.RunID, loaded.Artifacts, ".hal/reports/verify/regular.txt")
	if got := readStoredArtifact(t, store, record.RunID, regular); got != "regular\n" {
		t.Fatalf("stored regular data = %q", got)
	}
	for _, artifact := range loaded.Artifacts {
		if strings.Contains(artifact.Path, "leak") {
			t.Fatalf("symlink artifact should not be stored: %#v", loaded.Artifacts)
		}
		if artifact.StoredPath == "" {
			continue
		}
		storedPath, err := store.ResolveArtifactPath(record.RunID, artifact.StoredPath)
		if err != nil {
			t.Fatalf("ResolveArtifactPath(%q) error: %v", artifact.StoredPath, err)
		}
		data, err := os.ReadFile(storedPath)
		if err != nil {
			t.Fatalf("ReadFile(%q) error: %v", storedPath, err)
		}
		if strings.Contains(string(data), "secret") {
			t.Fatalf("stored artifact %q leaked symlink target data", artifact.Path)
		}
	}
}

type copyCall struct {
	remotePath string
}

type fakeSandboxArtifactCopier struct {
	files    map[string]string
	dirs     map[string]map[string]string
	fileErrs map[string]error
	dirErrs  map[string]error

	fileCalls []copyCall
	dirCalls  []copyCall
}

func (f *fakeSandboxArtifactCopier) CopyFile(_ context.Context, remotePath, localPath string) error {
	f.fileCalls = append(f.fileCalls, copyCall{remotePath: remotePath})
	if err := f.fileErrs[remotePath]; err != nil {
		return err
	}
	data, ok := f.files[remotePath]
	if !ok {
		return ErrSandboxArtifactNotFound
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(localPath, []byte(data), 0o600)
}

func (f *fakeSandboxArtifactCopier) CopyDir(_ context.Context, remotePath, localPath string) error {
	f.dirCalls = append(f.dirCalls, copyCall{remotePath: remotePath})
	if err := f.dirErrs[remotePath]; err != nil {
		return err
	}
	files, ok := f.dirs[remotePath]
	if !ok {
		return ErrSandboxArtifactNotFound
	}
	for relPath, data := range files {
		path := filepath.Join(localPath, filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func requireArtifactPath(t *testing.T, artifacts []ArtifactReference, wantPath string) ArtifactReference {
	t.Helper()
	for _, artifact := range artifacts {
		if artifact.Path == wantPath {
			return artifact
		}
	}
	t.Fatalf("artifact path %q missing from %#v", wantPath, artifacts)
	return ArtifactReference{}
}

func requireStoredArtifact(t *testing.T, store Store, runID string, artifacts []ArtifactReference, wantPath string) ArtifactReference {
	t.Helper()
	artifact := requireArtifactPath(t, artifacts, wantPath)
	if artifact.StoredPath == "" {
		t.Fatalf("artifact %q StoredPath should be set", wantPath)
	}
	storedPath, err := store.ResolveArtifactPath(runID, artifact.StoredPath)
	if err != nil {
		t.Fatalf("ResolveArtifactPath(%q) error: %v", artifact.StoredPath, err)
	}
	if _, err := os.Stat(storedPath); err != nil {
		t.Fatalf("stored artifact %q missing: %v", storedPath, err)
	}
	return artifact
}

func readStoredArtifact(t *testing.T, store Store, runID string, artifact ArtifactReference) string {
	t.Helper()
	storedPath, err := store.ResolveArtifactPath(runID, artifact.StoredPath)
	if err != nil {
		t.Fatalf("ResolveArtifactPath(%q) error: %v", artifact.StoredPath, err)
	}
	data, err := os.ReadFile(storedPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error: %v", storedPath, err)
	}
	return string(data)
}
