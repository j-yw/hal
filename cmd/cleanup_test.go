package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCleanupFn_DryRun(t *testing.T) {
	// Create temp directory to simulate .hal/
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create .hal directory: %v", err)
	}

	// Create auto-progress.txt file (orphaned file)
	autoProgressPath := filepath.Join(halDir, "auto-progress.txt")
	if err := os.WriteFile(autoProgressPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create auto-progress.txt: %v", err)
	}

	// Run cleanup with dry-run
	var out bytes.Buffer
	err := runCleanupFn(halDir, true, &out)
	if err != nil {
		t.Fatalf("runCleanupFn returned error: %v", err)
	}

	output := out.String()

	// Verify output contains "Would remove:" and the file path
	if !strings.Contains(output, "Would remove:") {
		t.Errorf("expected output to contain 'Would remove:', got: %s", output)
	}
	if !strings.Contains(output, autoProgressPath) {
		t.Errorf("expected output to contain file path %s, got: %s", autoProgressPath, output)
	}

	// Verify file still exists after dry-run
	if _, err := os.Stat(autoProgressPath); os.IsNotExist(err) {
		t.Error("auto-progress.txt should still exist after dry-run")
	}

	// Verify summary of how many files would be removed
	if !strings.Contains(output, "Would remove 1 file(s)") {
		t.Errorf("expected output to contain summary 'Would remove 1 file(s)', got: %s", output)
	}
}

func TestRunCleanupFn_ActualDeletion(t *testing.T) {
	// Create temp directory to simulate .hal/
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create .hal directory: %v", err)
	}

	// Create auto-progress.txt file (orphaned file)
	autoProgressPath := filepath.Join(halDir, "auto-progress.txt")
	if err := os.WriteFile(autoProgressPath, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create auto-progress.txt: %v", err)
	}

	// Verify file exists before cleanup
	if _, err := os.Stat(autoProgressPath); os.IsNotExist(err) {
		t.Fatal("auto-progress.txt should exist before cleanup")
	}

	// Run cleanup with dryRun=false (actual deletion)
	var out bytes.Buffer
	err := runCleanupFn(halDir, false, &out)
	if err != nil {
		t.Fatalf("runCleanupFn returned error: %v", err)
	}

	output := out.String()

	// Verify output contains "Removed:" and the file path
	if !strings.Contains(output, "Removed:") {
		t.Errorf("expected output to contain 'Removed:', got: %s", output)
	}
	if !strings.Contains(output, autoProgressPath) {
		t.Errorf("expected output to contain file path %s, got: %s", autoProgressPath, output)
	}

	// Verify file no longer exists after cleanup
	if _, err := os.Stat(autoProgressPath); !os.IsNotExist(err) {
		t.Error("auto-progress.txt should not exist after cleanup")
	}

	// Verify summary of how many files were removed
	if !strings.Contains(output, "Removed 1 file(s)") {
		t.Errorf("expected output to contain summary 'Removed 1 file(s)', got: %s", output)
	}
}

func TestRunCleanupFn_NoOrphanedFiles(t *testing.T) {
	// Create temp directory to simulate .hal/
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create .hal directory: %v", err)
	}

	// Create a config.yaml file (not an orphaned file)
	configPath := filepath.Join(halDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("version: 1"), 0644); err != nil {
		t.Fatalf("failed to create config.yaml: %v", err)
	}

	// Run cleanup with dryRun=false
	var out bytes.Buffer
	err := runCleanupFn(halDir, false, &out)
	if err != nil {
		t.Fatalf("runCleanupFn returned error: %v", err)
	}

	output := out.String()

	// Verify output contains "No orphaned files found."
	if !strings.Contains(output, "No orphaned files found.") {
		t.Errorf("expected output to contain 'No orphaned files found.', got: %s", output)
	}

	// Verify config.yaml still exists (was not deleted)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("config.yaml should still exist after cleanup")
	}
}
