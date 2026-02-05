package compound

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

// mockDisplay is a simple DisplayWriter implementation for testing.
type mockDisplay struct {
	messages []string
}

func (m *mockDisplay) ShowInfo(format string, args ...any) {
	// Not used in these tests but satisfies interface
}

func TestMigrateAutoProgress_MergeBothHaveContent(t *testing.T) {
	// Create temp directory
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create hal dir: %v", err)
	}

	// Create progress.txt with existing content
	progressPath := filepath.Join(halDir, template.ProgressFile)
	existingContent := "Existing progress notes"
	if err := os.WriteFile(progressPath, []byte(existingContent), 0644); err != nil {
		t.Fatalf("failed to write progress.txt: %v", err)
	}

	// Create auto-progress.txt with content to migrate
	autoProgressPath := filepath.Join(halDir, "auto-progress.txt")
	autoContent := "Auto progress notes"
	if err := os.WriteFile(autoProgressPath, []byte(autoContent), 0644); err != nil {
		t.Fatalf("failed to write auto-progress.txt: %v", err)
	}

	// Run migration
	display := &mockDisplay{}
	err := MigrateAutoProgress(dir, display)
	if err != nil {
		t.Fatalf("MigrateAutoProgress returned error: %v", err)
	}

	// Verify progress.txt contains merged content
	merged, err := os.ReadFile(progressPath)
	if err != nil {
		t.Fatalf("failed to read merged progress.txt: %v", err)
	}
	mergedStr := string(merged)

	// Check original content is present
	if !strings.Contains(mergedStr, existingContent) {
		t.Errorf("merged content missing original progress: got %q", mergedStr)
	}

	// Check separator is present
	if !strings.Contains(mergedStr, "---") {
		t.Errorf("merged content missing separator: got %q", mergedStr)
	}

	// Check migration header is present
	if !strings.Contains(mergedStr, "Migrated from auto-progress.txt") {
		t.Errorf("merged content missing migration header: got %q", mergedStr)
	}

	// Check auto-progress content is present
	if !strings.Contains(mergedStr, autoContent) {
		t.Errorf("merged content missing auto-progress content: got %q", mergedStr)
	}

	// Verify auto-progress.txt was deleted
	if _, err := os.Stat(autoProgressPath); !os.IsNotExist(err) {
		t.Errorf("auto-progress.txt should be deleted after merge")
	}
}

func TestMigrateAutoProgress_ReplaceWhenEmpty(t *testing.T) {
	// Create temp directory
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create hal dir: %v", err)
	}

	// Create empty progress.txt file
	progressPath := filepath.Join(halDir, template.ProgressFile)
	if err := os.WriteFile(progressPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write empty progress.txt: %v", err)
	}

	// Create auto-progress.txt with content to migrate
	autoProgressPath := filepath.Join(halDir, "auto-progress.txt")
	autoContent := "Auto progress content"
	if err := os.WriteFile(autoProgressPath, []byte(autoContent), 0644); err != nil {
		t.Fatalf("failed to write auto-progress.txt: %v", err)
	}

	// Run migration
	display := &mockDisplay{}
	err := MigrateAutoProgress(dir, display)
	if err != nil {
		t.Fatalf("MigrateAutoProgress returned error: %v", err)
	}

	// Verify progress.txt contains exactly the auto-progress content (no separator)
	result, err := os.ReadFile(progressPath)
	if err != nil {
		t.Fatalf("failed to read progress.txt: %v", err)
	}
	resultStr := string(result)

	if resultStr != autoContent {
		t.Errorf("progress.txt should contain exactly auto-progress content, got %q, want %q", resultStr, autoContent)
	}

	// Verify no separator is present (replacement, not merge)
	if strings.Contains(resultStr, "---") {
		t.Errorf("progress.txt should not contain separator for replacement: got %q", resultStr)
	}

	// Verify auto-progress.txt was deleted
	if _, err := os.Stat(autoProgressPath); !os.IsNotExist(err) {
		t.Errorf("auto-progress.txt should be deleted after replacement")
	}
}

func TestMigrateAutoProgress_ReplaceWhenDefault(t *testing.T) {
	// Create temp directory
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create hal dir: %v", err)
	}

	// Create progress.txt with default template content
	progressPath := filepath.Join(halDir, template.ProgressFile)
	if err := os.WriteFile(progressPath, []byte(template.DefaultProgress), 0644); err != nil {
		t.Fatalf("failed to write progress.txt with default content: %v", err)
	}

	// Create auto-progress.txt with meaningful content to migrate
	autoProgressPath := filepath.Join(halDir, "auto-progress.txt")
	autoContent := "Meaningful auto progress content"
	if err := os.WriteFile(autoProgressPath, []byte(autoContent), 0644); err != nil {
		t.Fatalf("failed to write auto-progress.txt: %v", err)
	}

	// Run migration
	display := &mockDisplay{}
	err := MigrateAutoProgress(dir, display)
	if err != nil {
		t.Fatalf("MigrateAutoProgress returned error: %v", err)
	}

	// Verify progress.txt contains exactly the auto-progress content (no separator)
	result, err := os.ReadFile(progressPath)
	if err != nil {
		t.Fatalf("failed to read progress.txt: %v", err)
	}
	resultStr := string(result)

	if resultStr != autoContent {
		t.Errorf("progress.txt should contain exactly auto-progress content, got %q, want %q", resultStr, autoContent)
	}

	// Verify no separator is present (replacement, not merge)
	if strings.Contains(resultStr, "---") {
		t.Errorf("progress.txt should not contain separator for replacement: got %q", resultStr)
	}

	// Verify default content is NOT present
	if strings.Contains(resultStr, "Codebase Patterns") {
		t.Errorf("progress.txt should not contain default template content after replacement: got %q", resultStr)
	}

	// Verify auto-progress.txt was deleted
	if _, err := os.Stat(autoProgressPath); !os.IsNotExist(err) {
		t.Errorf("auto-progress.txt should be deleted after replacement")
	}
}
