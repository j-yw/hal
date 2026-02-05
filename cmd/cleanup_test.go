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
