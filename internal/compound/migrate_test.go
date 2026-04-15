package compound

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/template"
)

// mockDisplay is a simple DisplayWriter implementation for testing.
type mockDisplay struct{}

func (m *mockDisplay) ShowInfo(format string, args ...any) {}

func TestMigrateLegacyAutoPRD(t *testing.T) {
	fixedNow := time.Date(2026, time.March, 29, 13, 45, 20, 0, time.UTC)

	tests := []struct {
		name                 string
		prdContent           string
		autoContent          string
		wantPRDContent       string
		wantLegacyCount      int
		wantWarningSubstring string
		wantWarningPrefix    string
	}{
		{
			name:            "renames auto-prd to prd when canonical file is missing",
			autoContent:     `{"project":"legacy","branchName":"hal/legacy","userStories":[]}`,
			wantPRDContent:  `{"project":"legacy","branchName":"hal/legacy","userStories":[]}`,
			wantLegacyCount: 0,
		},
		{
			name:                 "deletes auto-prd when both files are semantically equal",
			prdContent:           "{\n  \"project\": \"equal\",\n  \"branchName\": \"hal/equal\",\n  \"userStories\": []\n}\n",
			autoContent:          `{"branchName":"hal/equal","project":"equal","userStories":[]}`,
			wantPRDContent:       "{\n  \"project\": \"equal\",\n  \"branchName\": \"hal/equal\",\n  \"userStories\": []\n}\n",
			wantLegacyCount:      0,
			wantWarningSubstring: "",
		},
		{
			name:              "preserves differing auto-prd as timestamped legacy file",
			prdContent:        `{"project":"new","branchName":"hal/new","userStories":[]}`,
			autoContent:       `{"project":"old","branchName":"hal/old","userStories":[]}`,
			wantPRDContent:    `{"project":"new","branchName":"hal/new","userStories":[]}`,
			wantLegacyCount:   1,
			wantWarningPrefix: "warning: auto-prd.json differs from prd.json; preserved legacy file at .hal/auto-prd.legacy-",
		},
		{
			name:                 "preserves auto-prd when semantic comparison fails",
			prdContent:           `{"project":"new","branchName":"hal/new","userStories":[]}`,
			autoContent:          `{"project":"broken"`,
			wantPRDContent:       `{"project":"new","branchName":"hal/new","userStories":[]}`,
			wantLegacyCount:      1,
			wantWarningPrefix:    "warning: could not compare auto-prd.json to prd.json",
			wantWarningSubstring: ".hal/auto-prd.legacy-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, template.HalDir)
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("mkdir .hal: %v", err)
			}

			prdPath := filepath.Join(halDir, template.PRDFile)
			autoPath := filepath.Join(halDir, template.AutoPRDFile)
			if tt.prdContent != "" {
				if err := os.WriteFile(prdPath, []byte(tt.prdContent), 0644); err != nil {
					t.Fatalf("write prd.json: %v", err)
				}
			}
			if tt.autoContent != "" {
				if err := os.WriteFile(autoPath, []byte(tt.autoContent), 0644); err != nil {
					t.Fatalf("write auto-prd.json: %v", err)
				}
			}

			var errOut bytes.Buffer
			err := migrateLegacyAutoPRDWithNow(dir, &errOut, func() time.Time { return fixedNow })
			if err != nil {
				t.Fatalf("migrateLegacyAutoPRDWithNow returned error: %v", err)
			}

			prdData, err := os.ReadFile(prdPath)
			if err != nil {
				t.Fatalf("read prd.json: %v", err)
			}
			if string(prdData) != tt.wantPRDContent {
				t.Fatalf("prd.json content mismatch:\n got: %q\nwant: %q", string(prdData), tt.wantPRDContent)
			}

			if _, err := os.Stat(autoPath); !os.IsNotExist(err) {
				t.Fatalf("auto-prd.json should not exist after migration")
			}

			legacyMatches, err := filepath.Glob(filepath.Join(halDir, "auto-prd.legacy-*.json"))
			if err != nil {
				t.Fatalf("glob legacy auto-prd files: %v", err)
			}
			if len(legacyMatches) != tt.wantLegacyCount {
				t.Fatalf("legacy file count = %d, want %d", len(legacyMatches), tt.wantLegacyCount)
			}
			if tt.wantLegacyCount > 0 {
				legacyData, err := os.ReadFile(legacyMatches[0])
				if err != nil {
					t.Fatalf("read preserved legacy file: %v", err)
				}
				if string(legacyData) != tt.autoContent {
					t.Fatalf("legacy file content mismatch:\n got: %q\nwant: %q", string(legacyData), tt.autoContent)
				}
			}

			warning := errOut.String()
			if tt.wantWarningPrefix == "" {
				if warning != "" {
					t.Fatalf("unexpected warning output: %q", warning)
				}
			} else {
				if !strings.HasPrefix(warning, tt.wantWarningPrefix) {
					t.Fatalf("warning prefix mismatch:\n got: %q\nwant prefix: %q", warning, tt.wantWarningPrefix)
				}
				if tt.wantWarningSubstring != "" && !strings.Contains(warning, tt.wantWarningSubstring) {
					t.Fatalf("warning %q does not contain %q", warning, tt.wantWarningSubstring)
				}
			}
		})
	}
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

func TestMigrateAutoProgress_RemoveEmptyLegacy(t *testing.T) {
	t.Run("empty auto-progress.txt", func(t *testing.T) {
		// Create temp directory
		dir := t.TempDir()
		halDir := filepath.Join(dir, template.HalDir)
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("failed to create hal dir: %v", err)
		}

		// Create progress.txt with existing content
		progressPath := filepath.Join(halDir, template.ProgressFile)
		existingContent := "Existing content"
		if err := os.WriteFile(progressPath, []byte(existingContent), 0644); err != nil {
			t.Fatalf("failed to write progress.txt: %v", err)
		}

		// Create empty auto-progress.txt
		autoProgressPath := filepath.Join(halDir, "auto-progress.txt")
		if err := os.WriteFile(autoProgressPath, []byte(""), 0644); err != nil {
			t.Fatalf("failed to write empty auto-progress.txt: %v", err)
		}

		// Run migration
		display := &mockDisplay{}
		err := MigrateAutoProgress(dir, display)
		if err != nil {
			t.Fatalf("MigrateAutoProgress returned error: %v", err)
		}

		// Verify progress.txt is unchanged
		result, err := os.ReadFile(progressPath)
		if err != nil {
			t.Fatalf("failed to read progress.txt: %v", err)
		}
		resultStr := string(result)

		if resultStr != existingContent {
			t.Errorf("progress.txt should be unchanged, got %q, want %q", resultStr, existingContent)
		}

		// Verify auto-progress.txt was deleted
		if _, err := os.Stat(autoProgressPath); !os.IsNotExist(err) {
			t.Errorf("empty auto-progress.txt should be deleted")
		}
	})

	t.Run("auto-progress.txt with default content", func(t *testing.T) {
		// Create temp directory
		dir := t.TempDir()
		halDir := filepath.Join(dir, template.HalDir)
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("failed to create hal dir: %v", err)
		}

		// Create progress.txt with existing content
		progressPath := filepath.Join(halDir, template.ProgressFile)
		existingContent := "Existing content"
		if err := os.WriteFile(progressPath, []byte(existingContent), 0644); err != nil {
			t.Fatalf("failed to write progress.txt: %v", err)
		}

		// Create auto-progress.txt with only default template content
		autoProgressPath := filepath.Join(halDir, "auto-progress.txt")
		if err := os.WriteFile(autoProgressPath, []byte(template.DefaultProgress), 0644); err != nil {
			t.Fatalf("failed to write auto-progress.txt with default content: %v", err)
		}

		// Run migration
		display := &mockDisplay{}
		err := MigrateAutoProgress(dir, display)
		if err != nil {
			t.Fatalf("MigrateAutoProgress returned error: %v", err)
		}

		// Verify progress.txt is unchanged
		result, err := os.ReadFile(progressPath)
		if err != nil {
			t.Fatalf("failed to read progress.txt: %v", err)
		}
		resultStr := string(result)

		if resultStr != existingContent {
			t.Errorf("progress.txt should be unchanged, got %q, want %q", resultStr, existingContent)
		}

		// Verify auto-progress.txt was deleted
		if _, err := os.Stat(autoProgressPath); !os.IsNotExist(err) {
			t.Errorf("auto-progress.txt with default content should be deleted")
		}
	})
}

func TestMigrateAutoProgress_NoOpWhenNoLegacyFile(t *testing.T) {
	// Create temp directory
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create hal dir: %v", err)
	}

	// Create only progress.txt with content (no auto-progress.txt)
	progressPath := filepath.Join(halDir, template.ProgressFile)
	existingContent := "Existing content"
	if err := os.WriteFile(progressPath, []byte(existingContent), 0644); err != nil {
		t.Fatalf("failed to write progress.txt: %v", err)
	}

	// Run migration
	display := &mockDisplay{}
	err := MigrateAutoProgress(dir, display)

	// Function should return nil (no error)
	if err != nil {
		t.Errorf("MigrateAutoProgress should return nil when no legacy file exists, got: %v", err)
	}

	// Verify progress.txt is unchanged
	result, err := os.ReadFile(progressPath)
	if err != nil {
		t.Fatalf("failed to read progress.txt: %v", err)
	}
	resultStr := string(result)

	if resultStr != existingContent {
		t.Errorf("progress.txt should be unchanged, got %q, want %q", resultStr, existingContent)
	}
}
