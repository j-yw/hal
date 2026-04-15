package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/template"
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

	// Verify summary of how many items would be removed
	if !strings.Contains(output, "Would remove 1 item(s)") {
		t.Errorf("expected output to contain summary 'Would remove 1 item(s)', got: %s", output)
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

	// Verify summary of how many items were removed
	if !strings.Contains(output, "Removed 1 item(s)") {
		t.Errorf("expected output to contain summary 'Removed 1 item(s)', got: %s", output)
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

func TestRunCleanupFn_OrphanedDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create .hal directory: %v", err)
	}

	// Create rules/ directory (orphaned)
	rulesDir := filepath.Join(halDir, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("failed to create rules dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "test.md"), []byte("# Rule"), 0644); err != nil {
		t.Fatalf("failed to write rule file: %v", err)
	}

	var out bytes.Buffer
	if err := runCleanupFn(halDir, false, &out); err != nil {
		t.Fatalf("runCleanupFn() error = %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Removed:") {
		t.Fatalf("expected 'Removed:' in output, got: %s", output)
	}

	if _, err := os.Stat(rulesDir); !os.IsNotExist(err) {
		t.Fatal("rules/ directory should be removed after cleanup")
	}
}

func TestRunCleanupFn_OrphanedDirectoryDryRun(t *testing.T) {
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create .hal directory: %v", err)
	}

	rulesDir := filepath.Join(halDir, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("failed to create rules dir: %v", err)
	}

	var out bytes.Buffer
	if err := runCleanupFn(halDir, true, &out); err != nil {
		t.Fatalf("runCleanupFn() error = %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Would remove:") {
		t.Fatalf("expected 'Would remove:' in output, got: %s", output)
	}

	// Directory should still exist after dry-run
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Fatal("rules/ directory should still exist after dry-run")
	}
}

func TestRunCleanupFn_DeprecatedSkillLinks(t *testing.T) {
	tmpDir := t.TempDir()
	halDir := filepath.Join(tmpDir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create deprecated ralph link
	claudeSkills := filepath.Join(tmpDir, ".claude", "skills")
	os.MkdirAll(claudeSkills, 0755)
	os.Symlink("../../.hal/skills/hal", filepath.Join(claudeSkills, "ralph"))

	var out bytes.Buffer
	if err := runCleanupFn(halDir, false, &out); err != nil {
		t.Fatalf("runCleanupFn() error = %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "ralph") {
		t.Fatalf("output should mention ralph removal\n%s", output)
	}

	// Verify link was removed
	if _, err := os.Lstat(filepath.Join(claudeSkills, "ralph")); !os.IsNotExist(err) {
		t.Fatal(".claude/skills/ralph should be removed after cleanup")
	}
}

func TestRunCleanupFn_LegacyAutoPRDArtifacts(t *testing.T) {
	tests := []struct {
		name                   string
		dryRun                 bool
		createLegacyArtifacts  bool
		wantOutputContains     []string
		wantAutoPRDExists      bool
		wantLegacyBackupExists bool
	}{
		{
			name:                  "dry-run lists legacy auto-prd artifacts",
			dryRun:                true,
			createLegacyArtifacts: true,
			wantOutputContains: []string{
				"Would remove:",
				"Would remove 2 item(s)",
			},
			wantAutoPRDExists:      true,
			wantLegacyBackupExists: true,
		},
		{
			name:                  "cleanup removes legacy auto-prd artifacts",
			dryRun:                false,
			createLegacyArtifacts: true,
			wantOutputContains: []string{
				"Removed:",
				"Removed 2 item(s)",
			},
			wantAutoPRDExists:      false,
			wantLegacyBackupExists: false,
		},
		{
			name:                  "cleanup skips when legacy auto-prd artifacts are absent",
			dryRun:                false,
			createLegacyArtifacts: false,
			wantOutputContains: []string{
				"No orphaned files found.",
			},
			wantAutoPRDExists:      false,
			wantLegacyBackupExists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			halDir := filepath.Join(tmpDir, template.HalDir)
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("failed to create .hal directory: %v", err)
			}

			prdPath := filepath.Join(halDir, template.PRDFile)
			prdContent := `{"branchName":"hal/current"}`
			if err := os.WriteFile(prdPath, []byte(prdContent), 0644); err != nil {
				t.Fatalf("failed to create prd.json: %v", err)
			}

			autoPRDPath := filepath.Join(halDir, template.AutoPRDFile)
			legacyBackupPath := filepath.Join(halDir, "auto-prd.legacy-20260329-120000.json")
			if tt.createLegacyArtifacts {
				if err := os.WriteFile(autoPRDPath, []byte(`{"branchName":"hal/legacy"}`), 0644); err != nil {
					t.Fatalf("failed to create auto-prd.json: %v", err)
				}
				if err := os.WriteFile(legacyBackupPath, []byte(`{"branchName":"hal/legacy-backup"}`), 0644); err != nil {
					t.Fatalf("failed to create legacy auto-prd backup: %v", err)
				}
			}

			var out bytes.Buffer
			if err := runCleanupFn(halDir, tt.dryRun, &out); err != nil {
				t.Fatalf("runCleanupFn() error = %v", err)
			}

			output := out.String()
			for _, want := range tt.wantOutputContains {
				if !strings.Contains(output, want) {
					t.Fatalf("expected output to contain %q, got: %s", want, output)
				}
			}

			if tt.createLegacyArtifacts {
				if !strings.Contains(output, autoPRDPath) {
					t.Fatalf("expected output to contain auto-prd path %q, got: %s", autoPRDPath, output)
				}
				if !strings.Contains(output, legacyBackupPath) {
					t.Fatalf("expected output to contain legacy backup path %q, got: %s", legacyBackupPath, output)
				}
			}

			_, autoPRDErr := os.Stat(autoPRDPath)
			if tt.wantAutoPRDExists {
				if os.IsNotExist(autoPRDErr) {
					t.Fatalf("auto-prd.json should exist")
				}
			} else if !os.IsNotExist(autoPRDErr) {
				t.Fatalf("auto-prd.json should not exist")
			}

			_, legacyBackupErr := os.Stat(legacyBackupPath)
			if tt.wantLegacyBackupExists {
				if os.IsNotExist(legacyBackupErr) {
					t.Fatalf("legacy auto-prd backup should exist")
				}
			} else if !os.IsNotExist(legacyBackupErr) {
				t.Fatalf("legacy auto-prd backup should not exist")
			}

			gotPRD, err := os.ReadFile(prdPath)
			if err != nil {
				t.Fatalf("failed to read prd.json: %v", err)
			}
			if string(gotPRD) != prdContent {
				t.Fatalf("prd.json should remain unchanged, got: %s", string(gotPRD))
			}
		})
	}
}
