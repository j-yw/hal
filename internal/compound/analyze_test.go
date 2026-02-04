package compound

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFindLatestReport(t *testing.T) {
	t.Run("single report file returns its path", func(t *testing.T) {
		dir := t.TempDir()
		report := filepath.Join(dir, "review-2026-01-01.md")
		if err := os.WriteFile(report, []byte("# Report"), 0644); err != nil {
			t.Fatalf("Failed to create report: %v", err)
		}

		got, err := FindLatestReport(dir)
		if err != nil {
			t.Fatalf("FindLatestReport() unexpected error: %v", err)
		}
		if got != report {
			t.Errorf("FindLatestReport() = %q, want %q", got, report)
		}
	})

	t.Run("multiple files returns most recently modified", func(t *testing.T) {
		dir := t.TempDir()

		older := filepath.Join(dir, "review-old.md")
		newer := filepath.Join(dir, "review-new.md")

		if err := os.WriteFile(older, []byte("old"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(newer, []byte("new"), 0644); err != nil {
			t.Fatal(err)
		}

		// Set older file to the past
		oldTime := time.Now().Add(-48 * time.Hour)
		if err := os.Chtimes(older, oldTime, oldTime); err != nil {
			t.Fatal(err)
		}

		got, err := FindLatestReport(dir)
		if err != nil {
			t.Fatalf("FindLatestReport() unexpected error: %v", err)
		}
		if got != newer {
			t.Errorf("FindLatestReport() = %q, want %q", got, newer)
		}
	})

	t.Run("empty directory with only gitkeep returns error", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".gitkeep"), []byte{}, 0644); err != nil {
			t.Fatal(err)
		}

		_, err := FindLatestReport(dir)
		if err == nil {
			t.Fatal("FindLatestReport() expected error, got nil")
		}
		if !strings.Contains(err.Error(), "no reports") {
			t.Errorf("error = %q, want substring %q", err.Error(), "no reports")
		}
	})

	t.Run("non-existent directory returns error", func(t *testing.T) {
		_, err := FindLatestReport(filepath.Join(t.TempDir(), "nonexistent"))
		if err == nil {
			t.Fatal("FindLatestReport() expected error, got nil")
		}
	})

	t.Run("hidden files are skipped", func(t *testing.T) {
		dir := t.TempDir()

		// Only create hidden files
		if err := os.WriteFile(filepath.Join(dir, ".hidden.md"), []byte("hidden"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".gitkeep"), []byte{}, 0644); err != nil {
			t.Fatal(err)
		}

		_, err := FindLatestReport(dir)
		if err == nil {
			t.Fatal("FindLatestReport() expected error when only hidden files, got nil")
		}
		if !strings.Contains(err.Error(), "no reports") {
			t.Errorf("error = %q, want substring %q", err.Error(), "no reports")
		}
	})
}

func TestFindRecentPRDs(t *testing.T) {
	t.Run("returns recent PRD files within N days", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, ".hal")
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatal(err)
		}

		recentPRD := filepath.Join(halDir, "prd-feature-a.md")
		if err := os.WriteFile(recentPRD, []byte("# PRD A"), 0644); err != nil {
			t.Fatal(err)
		}

		got, err := FindRecentPRDs(dir, 7)
		if err != nil {
			t.Fatalf("FindRecentPRDs() unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != recentPRD {
			t.Errorf("FindRecentPRDs() = %v, want [%s]", got, recentPRD)
		}
	})

	t.Run("excludes PRD files older than N days", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, ".hal")
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatal(err)
		}

		oldPRD := filepath.Join(halDir, "prd-old-feature.md")
		if err := os.WriteFile(oldPRD, []byte("# Old PRD"), 0644); err != nil {
			t.Fatal(err)
		}
		// Set mtime to 30 days ago
		oldTime := time.Now().AddDate(0, 0, -30)
		if err := os.Chtimes(oldPRD, oldTime, oldTime); err != nil {
			t.Fatal(err)
		}

		got, err := FindRecentPRDs(dir, 7)
		if err != nil {
			t.Fatalf("FindRecentPRDs() unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("FindRecentPRDs() = %v, want empty slice", got)
		}
	})

	t.Run("returns nil when hal directory does not exist", func(t *testing.T) {
		dir := t.TempDir()
		got, err := FindRecentPRDs(dir, 7)
		if err != nil {
			t.Fatalf("FindRecentPRDs() unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("FindRecentPRDs() = %v, want nil", got)
		}
	})

	t.Run("only matches prd- prefix and .md suffix", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, ".hal")
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatal(err)
		}

		// Valid PRD file
		validPRD := filepath.Join(halDir, "prd-valid.md")
		if err := os.WriteFile(validPRD, []byte("# PRD"), 0644); err != nil {
			t.Fatal(err)
		}
		// Non-matching files
		for _, name := range []string{"notes.md", "prd-foo.txt", "readme.md", "config.yaml"} {
			if err := os.WriteFile(filepath.Join(halDir, name), []byte("content"), 0644); err != nil {
				t.Fatal(err)
			}
		}

		got, err := FindRecentPRDs(dir, 7)
		if err != nil {
			t.Fatalf("FindRecentPRDs() unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != validPRD {
			t.Errorf("FindRecentPRDs() = %v, want [%s]", got, validPRD)
		}
	})
}
