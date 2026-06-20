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
	if len(artifacts) != 3 {
		t.Fatalf("artifacts len = %d, want 3: %#v", len(artifacts), artifacts)
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

	encoded, err := json.Marshal(loaded)
	if err != nil {
		t.Fatalf("Marshal(run) error: %v", err)
	}
	if strings.Contains(string(encoded), "/workspace/") {
		t.Fatalf("run metadata should not expose remote workspace paths: %s", encoded)
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
