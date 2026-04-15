package product

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestLoadExistingFiles_EmptyState(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	got, err := LoadExistingFiles(dir)
	if err != nil {
		t.Fatalf("LoadExistingFiles() error = %v", err)
	}

	assertFileState(t, got.Mission, false, "")
	assertFileState(t, got.Roadmap, false, "")
	assertFileState(t, got.TechStack, false, "")

	productDir := filepath.Join(dir, template.HalDir, template.ProductDir)
	if _, err := os.Stat(productDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadExistingFiles() created %s unexpectedly (stat error: %v)", productDir, err)
	}
}

func TestLoadExistingFiles_PartialState(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeProductFile(t, dir, template.ProductMissionFile, "Mission content")
	writeProductFile(t, dir, template.ProductTechStackFile, "Tech stack content")

	got, err := LoadExistingFiles(dir)
	if err != nil {
		t.Fatalf("LoadExistingFiles() error = %v", err)
	}

	assertFileState(t, got.Mission, true, "Mission content")
	assertFileState(t, got.Roadmap, false, "")
	assertFileState(t, got.TechStack, true, "Tech stack content")
}

func TestLoadExistingFiles_AllFilesPresent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeProductFile(t, dir, template.ProductMissionFile, "Mission")
	writeProductFile(t, dir, template.ProductRoadmapFile, "Roadmap")
	writeProductFile(t, dir, template.ProductTechStackFile, "Tech stack")

	got, err := LoadExistingFiles(dir)
	if err != nil {
		t.Fatalf("LoadExistingFiles() error = %v", err)
	}

	assertFileState(t, got.Mission, true, "Mission")
	assertFileState(t, got.Roadmap, true, "Roadmap")
	assertFileState(t, got.TechStack, true, "Tech stack")
}

func writeProductFile(t *testing.T, dir, name, content string) {
	t.Helper()

	productDir := filepath.Join(dir, template.HalDir, template.ProductDir)
	if err := os.MkdirAll(productDir, 0755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", productDir, err)
	}
	path := filepath.Join(productDir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func assertFileState(t *testing.T, got FileState, wantExists bool, wantContent string) {
	t.Helper()
	if got.Exists != wantExists {
		t.Fatalf("Exists = %v, want %v (content=%q)", got.Exists, wantExists, got.Content)
	}
	if got.Content != wantContent {
		t.Fatalf("Content = %q, want %q", got.Content, wantContent)
	}
}
