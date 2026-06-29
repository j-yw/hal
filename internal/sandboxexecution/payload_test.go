package sandboxexecution

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWritePayloadHelpersStoreUnderAreas(t *testing.T) {
	store := newTestStore(t)
	cases := []struct {
		name      string
		write     func() (StoredFile, error)
		wantPath  string
		wantBytes string
	}{
		{
			name: "log",
			write: func() (StoredFile, error) {
				return store.WriteLog("exec-1", "stdout.log", []byte("log\n"))
			},
			wantPath:  "exec-1/logs/stdout.log",
			wantBytes: "log\n",
		},
		{
			name: "artifact",
			write: func() (StoredFile, error) {
				return store.WriteArtifactPayload("exec-1", "reports/out.txt", []byte("artifact\n"))
			},
			wantPath:  "exec-1/artifacts/reports/out.txt",
			wantBytes: "artifact\n",
		},
		{
			name: "handoff",
			write: func() (StoredFile, error) {
				return store.WriteHandoff("exec-1", "handoff.md", []byte("handoff\n"))
			},
			wantPath:  "exec-1/handoff/handoff.md",
			wantBytes: "handoff\n",
		},
		{
			name: "recovery",
			write: func() (StoredFile, error) {
				return store.WriteRecovery("exec-1", "patches/recovery.patch", []byte("patch\n"))
			},
			wantPath:  "exec-1/recovery/patches/recovery.patch",
			wantBytes: "patch\n",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			stored, err := tt.write()
			if err != nil {
				t.Fatalf("write payload error: %v", err)
			}
			if stored.Path != tt.wantPath {
				t.Fatalf("stored path = %q, want %q", stored.Path, tt.wantPath)
			}
			if filepath.IsAbs(stored.Path) || strings.Contains(stored.Path, "\\") {
				t.Fatalf("stored path %q is not store-relative slash form", stored.Path)
			}
			if stored.SizeBytes != int64(len(tt.wantBytes)) {
				t.Fatalf("stored size = %d, want %d", stored.SizeBytes, len(tt.wantBytes))
			}
			absolute := filepath.Join(store.Root(), filepath.FromSlash(stored.Path))
			got, readErr := os.ReadFile(absolute)
			if readErr != nil {
				t.Fatalf("ReadFile(%s) error: %v", absolute, readErr)
			}
			if string(got) != tt.wantBytes {
				t.Fatalf("payload bytes = %q, want %q", got, tt.wantBytes)
			}
			assertMode(t, absolute, 0o600)
		})
	}
	assertMode(t, filepath.Join(store.Root(), "exec-1", artifactsDirName, "reports"), 0o700)
	assertMode(t, filepath.Join(store.Root(), "exec-1", recoveryDirName, "patches"), 0o700)
	assertNoTempFiles(t, store.Root())
}

func TestWritePayloadRejectsUnsafePathsBeforeMutation(t *testing.T) {
	for _, payloadPath := range []string{"", "/absolute", "../escape", "a/../b", `a\b`, " path"} {
		t.Run(payloadPath, func(t *testing.T) {
			store := newTestStore(t)
			_, err := store.WriteLog("exec-1", payloadPath, []byte("data"))
			if err == nil {
				t.Fatalf("WriteLog(%q) expected error", payloadPath)
			}
			assertPathMissing(t, store.Root())
		})
	}
}

func TestCopyPayloadCopiesRegularFile(t *testing.T) {
	store := newTestStore(t)
	sourcePath := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(sourcePath, []byte("source\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(source) error: %v", err)
	}

	stored, err := store.CopyRecovery("exec-1", "nested/recovery.txt", sourcePath)
	if err != nil {
		t.Fatalf("CopyRecovery() error: %v", err)
	}
	if stored.Path != "exec-1/recovery/nested/recovery.txt" {
		t.Fatalf("stored path = %q, want recovery path", stored.Path)
	}
	if stored.SizeBytes != int64(len("source\n")) {
		t.Fatalf("stored size = %d, want %d", stored.SizeBytes, len("source\n"))
	}
	absolute := filepath.Join(store.Root(), filepath.FromSlash(stored.Path))
	got, err := os.ReadFile(absolute)
	if err != nil {
		t.Fatalf("ReadFile(copied) error: %v", err)
	}
	if string(got) != "source\n" {
		t.Fatalf("copied bytes = %q, want source", got)
	}
	assertMode(t, absolute, 0o600)
	assertMode(t, filepath.Dir(absolute), 0o700)
	assertNoTempFiles(t, store.Root())
}

func TestCopyPayloadRejectsSymlinkAndNonRegularSources(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires privileges on some Windows setups")
		}
		store := newTestStore(t)
		dir := t.TempDir()
		target := filepath.Join(dir, "target.txt")
		if err := os.WriteFile(target, []byte("target\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(target) error: %v", err)
		}
		link := filepath.Join(dir, "link.txt")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink() error: %v", err)
		}

		_, err := store.CopyLog("exec-1", "stdout.log", link)
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("CopyLog(symlink) error = %v, want symlink rejection", err)
		}
		assertPathMissing(t, store.Root())
	})

	t.Run("directory", func(t *testing.T) {
		store := newTestStore(t)
		sourceDir := t.TempDir()
		_, err := store.CopyHandoff("exec-1", "handoff.md", sourceDir)
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("CopyHandoff(directory) error = %v, want non-regular rejection", err)
		}
		assertPathMissing(t, store.Root())
	})
}

func TestSaveArtifactUpsertsMetadataByID(t *testing.T) {
	store := newTestStore(t)
	manifest := testManifest("exec-1", time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC))
	manifest.Artifacts = []Artifact{{ID: "keep", Name: "Keep", Type: "text", StoredPath: "exec-1/artifacts/keep.txt"}}
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	createdAt := time.Date(2026, 6, 30, 2, 0, 0, 0, time.UTC)
	first, err := store.SaveArtifact("exec-1", Artifact{
		ID:        "report",
		Name:      "Report",
		Type:      "markdown",
		CreatedAt: &createdAt,
	}, "reports/report.md", []byte("first\n"))
	if err != nil {
		t.Fatalf("SaveArtifact(first) error: %v", err)
	}
	if first.StoredPath != "exec-1/artifacts/reports/report.md" {
		t.Fatalf("first stored path = %q, want store-relative path", first.StoredPath)
	}

	second, err := store.SaveArtifact("exec-1", Artifact{
		ID:        "report",
		Name:      "Report v2",
		Type:      "markdown",
		CreatedAt: &createdAt,
	}, "reports/report-v2.md", []byte("second\n"))
	if err != nil {
		t.Fatalf("SaveArtifact(second) error: %v", err)
	}
	if second.StoredPath != "exec-1/artifacts/reports/report-v2.md" || second.Path != second.StoredPath {
		t.Fatalf("second paths = path:%q stored:%q, want same store-relative path", second.Path, second.StoredPath)
	}
	if second.SizeBytes == nil || *second.SizeBytes != int64(len("second\n")) {
		t.Fatalf("second size = %v, want %d", second.SizeBytes, len("second\n"))
	}

	loaded, err := store.LoadManifest("exec-1")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if len(loaded.Artifacts) != 2 {
		t.Fatalf("artifacts len = %d, want 2: %#v", len(loaded.Artifacts), loaded.Artifacts)
	}
	report := requireArtifact(t, loaded.Artifacts, "report")
	if report.Name != "Report v2" {
		t.Fatalf("report artifact name = %q, want replacement", report.Name)
	}
	if report.StoredPath != "exec-1/artifacts/reports/report-v2.md" {
		t.Fatalf("report stored path = %q, want replacement path", report.StoredPath)
	}
	_ = requireArtifact(t, loaded.Artifacts, "keep")
	got, readErr := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(report.StoredPath)))
	if readErr != nil {
		t.Fatalf("ReadFile(report) error: %v", readErr)
	}
	if string(got) != "second\n" {
		t.Fatalf("report bytes = %q, want second", got)
	}
	assertNoTempFiles(t, store.Root())
}

func TestCopyArtifactCopiesAndUpsertsMetadata(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-1", time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	sourcePath := filepath.Join(t.TempDir(), "artifact.txt")
	if err := os.WriteFile(sourcePath, []byte("artifact\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(source) error: %v", err)
	}

	artifact, err := store.CopyArtifact("exec-1", Artifact{ID: "log", Name: "Log", Type: "text"}, "logs/log.txt", sourcePath)
	if err != nil {
		t.Fatalf("CopyArtifact() error: %v", err)
	}
	if artifact.StoredPath != "exec-1/artifacts/logs/log.txt" {
		t.Fatalf("artifact stored path = %q, want store-relative path", artifact.StoredPath)
	}
	loaded, err := store.LoadManifest("exec-1")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if len(loaded.Artifacts) != 1 || loaded.Artifacts[0].ID != "log" {
		t.Fatalf("manifest artifacts = %#v, want copied artifact", loaded.Artifacts)
	}
}

func TestSaveArtifactRequiresExistingManifestBeforeWritingPayload(t *testing.T) {
	store := newTestStore(t)
	_, err := store.SaveArtifact("exec-1", Artifact{ID: "report", Name: "Report", Type: "markdown"}, "report.md", []byte("payload"))
	if err == nil {
		t.Fatalf("SaveArtifact() expected missing manifest error")
	}
	assertPathMissing(t, store.Root())
}

func requireArtifact(t *testing.T, artifacts []Artifact, id string) Artifact {
	t.Helper()
	var found []Artifact
	for _, artifact := range artifacts {
		if artifact.ID == id {
			found = append(found, artifact)
		}
	}
	if len(found) != 1 {
		t.Fatalf("artifact ID %q count = %d, want 1 in %#v", id, len(found), artifacts)
	}
	return found[0]
}
