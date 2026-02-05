package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestMigrateConfigDir(t *testing.T) {
	tests := []struct {
		name       string
		setupFn    func(t *testing.T, dir string)
		wantResult migrateResult
		wantOutput string
		wantErr    bool
		checkFn    func(t *testing.T, dir string)
	}{
		{
			name: "only old dir exists - migrates",
			setupFn: func(t *testing.T, dir string) {
				old := filepath.Join(dir, ".goralph")
				os.MkdirAll(old, 0755)
				os.WriteFile(filepath.Join(old, "marker.txt"), []byte("hello"), 0644)
			},
			wantResult: migrateDone,
			wantOutput: "Migrated",
			checkFn: func(t *testing.T, dir string) {
				if _, err := os.Stat(filepath.Join(dir, ".goralph")); !os.IsNotExist(err) {
					t.Error(".goralph should not exist after migration")
				}
				data, err := os.ReadFile(filepath.Join(dir, ".hal", "marker.txt"))
				if err != nil {
					t.Fatalf(".hal/marker.txt should exist: %v", err)
				}
				if string(data) != "hello" {
					t.Errorf("marker content = %q, want %q", string(data), "hello")
				}
			},
		},
		{
			name: "migration updates legacy config and prompt",
			setupFn: func(t *testing.T, dir string) {
				old := filepath.Join(dir, ".goralph")
				os.MkdirAll(old, 0755)
				legacyConfig := `# legacy config
auto:
  reportsDir: .goralph/reports # old path
  branchPrefix: compound/
`
				legacyPrompt := "Read `.goralph/{{PRD_FILE}}` and `.goralph/{{PROGRESS_FILE}}`"
				os.WriteFile(filepath.Join(old, "config.yaml"), []byte(legacyConfig), 0644)
				os.WriteFile(filepath.Join(old, "prompt.md"), []byte(legacyPrompt), 0644)
			},
			wantResult: migrateDone,
			wantOutput: "Migrated",
			checkFn: func(t *testing.T, dir string) {
				updatedConfig, err := os.ReadFile(filepath.Join(dir, ".hal", "config.yaml"))
				if err != nil {
					t.Fatalf(".hal/config.yaml should exist: %v", err)
				}
				if strings.Contains(string(updatedConfig), ".goralph/reports") {
					t.Errorf("config.yaml should not reference .goralph/reports")
				}
				if !strings.Contains(string(updatedConfig), ".hal/reports") {
					t.Errorf("config.yaml should reference .hal/reports")
				}

				updatedPrompt, err := os.ReadFile(filepath.Join(dir, ".hal", "prompt.md"))
				if err != nil {
					t.Fatalf(".hal/prompt.md should exist: %v", err)
				}
				if strings.Contains(string(updatedPrompt), ".goralph/") {
					t.Errorf("prompt.md should not reference .goralph/")
				}
				if !strings.Contains(string(updatedPrompt), ".hal/") {
					t.Errorf("prompt.md should reference .hal/")
				}
			},
		},
		{
			name: "both dirs exist - warning",
			setupFn: func(t *testing.T, dir string) {
				old := filepath.Join(dir, ".goralph")
				os.MkdirAll(old, 0755)
				os.WriteFile(filepath.Join(old, "marker-old.txt"), []byte("old"), 0644)
				newD := filepath.Join(dir, ".hal")
				os.MkdirAll(newD, 0755)
				os.WriteFile(filepath.Join(newD, "marker-new.txt"), []byte("new"), 0644)
			},
			wantResult: migrateWarning,
			wantOutput: "Warning: both",
			checkFn: func(t *testing.T, dir string) {
				dataOld, err := os.ReadFile(filepath.Join(dir, ".goralph", "marker-old.txt"))
				if err != nil {
					t.Fatalf(".goralph/marker-old.txt should exist: %v", err)
				}
				if string(dataOld) != "old" {
					t.Errorf("old marker content = %q, want %q", string(dataOld), "old")
				}
				dataNew, err := os.ReadFile(filepath.Join(dir, ".hal", "marker-new.txt"))
				if err != nil {
					t.Fatalf(".hal/marker-new.txt should exist: %v", err)
				}
				if string(dataNew) != "new" {
					t.Errorf("new marker content = %q, want %q", string(dataNew), "new")
				}
			},
		},
		{
			name: "neither dir exists - fresh init",
			setupFn: func(t *testing.T, dir string) {
				// no setup — neither directory exists
			},
			wantResult: migrateNone,
			wantOutput: "",
			checkFn: func(t *testing.T, dir string) {
				if _, err := os.Stat(filepath.Join(dir, ".goralph")); !os.IsNotExist(err) {
					t.Error(".goralph should not exist")
				}
				if _, err := os.Stat(filepath.Join(dir, ".hal")); !os.IsNotExist(err) {
					t.Error(".hal should not have been created by migrateConfigDir")
				}
			},
		},
		{
			name: "rename fails - returns error",
			setupFn: func(t *testing.T, dir string) {
				old := filepath.Join(dir, ".goralph")
				os.MkdirAll(old, 0755)
				os.WriteFile(filepath.Join(old, "marker.txt"), []byte("data"), 0644)
				// Remove write permission on parent dir so os.Rename fails
				os.Chmod(dir, 0555)
				t.Cleanup(func() {
					// Restore permissions so t.TempDir() cleanup can remove the dir
					os.Chmod(dir, 0755)
				})
				probe := filepath.Join(dir, "probe.txt")
				if err := os.WriteFile(probe, []byte("probe"), 0644); err == nil {
					os.Remove(probe)
					t.Skip("chmod did not prevent writes; skipping rename failure test")
				}
			},
			wantResult: migrateNone,
			wantErr:    true,
			checkFn: func(t *testing.T, dir string) {
				// Restore permissions for checkFn stat calls
				os.Chmod(dir, 0755)
				if _, err := os.Stat(filepath.Join(dir, ".goralph")); os.IsNotExist(err) {
					t.Error(".goralph should still exist on rename failure")
				}
			},
		},
		{
			name: "only new dir exists - no-op",
			setupFn: func(t *testing.T, dir string) {
				newD := filepath.Join(dir, ".hal")
				os.MkdirAll(newD, 0755)
				os.WriteFile(filepath.Join(newD, "marker.txt"), []byte("existing"), 0644)
			},
			wantResult: migrateNone,
			wantOutput: "",
			checkFn: func(t *testing.T, dir string) {
				data, err := os.ReadFile(filepath.Join(dir, ".hal", "marker.txt"))
				if err != nil {
					t.Fatalf(".hal/marker.txt should exist: %v", err)
				}
				if string(data) != "existing" {
					t.Errorf("marker content = %q, want %q", string(data), "existing")
				}
				if _, err := os.Stat(filepath.Join(dir, ".goralph")); !os.IsNotExist(err) {
					t.Error(".goralph should not exist")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if tt.setupFn != nil {
				tt.setupFn(t, tmpDir)
			}

			oldDir := filepath.Join(tmpDir, ".goralph")
			newDir := filepath.Join(tmpDir, ".hal")
			var buf bytes.Buffer

			result, err := migrateConfigDir(oldDir, newDir, &buf)

			if (err != nil) != tt.wantErr {
				t.Fatalf("migrateConfigDir() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil {
				if !strings.Contains(err.Error(), "failed to migrate") {
					t.Errorf("error %q should contain 'failed to migrate'", err.Error())
				}
			}
			if result != tt.wantResult {
				t.Errorf("migrateConfigDir() result = %v, want %v", result, tt.wantResult)
			}
			if tt.wantOutput != "" && !bytes.Contains(buf.Bytes(), []byte(tt.wantOutput)) {
				t.Errorf("output %q does not contain %q", buf.String(), tt.wantOutput)
			}
			if tt.wantOutput == "" && buf.Len() > 0 {
				t.Errorf("expected no output, got %q", buf.String())
			}
			if tt.checkFn != nil {
				tt.checkFn(t, tmpDir)
			}
		})
	}
}

func TestRunInit(t *testing.T) {
	// Save and restore working directory
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	t.Run("creates reports directory and gitkeep", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("Failed to chdir: %v", err)
		}

		if err := runInit(nil, nil); err != nil {
			t.Fatalf("runInit() error: %v", err)
		}

		// Verify .hal/reports/ exists
		reportsDir := filepath.Join(dir, ".hal", "reports")
		info, err := os.Stat(reportsDir)
		if err != nil {
			t.Fatalf(".hal/reports/ should exist: %v", err)
		}
		if !info.IsDir() {
			t.Error(".hal/reports/ should be a directory")
		}

		// Verify .hal/reports/.gitkeep exists
		gitkeep := filepath.Join(reportsDir, ".gitkeep")
		if _, err := os.Stat(gitkeep); err != nil {
			t.Fatalf(".hal/reports/.gitkeep should exist: %v", err)
		}
	})

	t.Run("creates config.yaml matching template", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("Failed to chdir: %v", err)
		}

		if err := runInit(nil, nil); err != nil {
			t.Fatalf("runInit() error: %v", err)
		}

		configPath := filepath.Join(dir, ".hal", "config.yaml")
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config.yaml: %v", err)
		}

		if string(data) != template.DefaultConfig {
			t.Errorf("config.yaml content does not match template.DefaultConfig\ngot:  %q\nwant: %q", string(data), template.DefaultConfig)
		}
	})

	t.Run("second run does not overwrite existing config", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("Failed to chdir: %v", err)
		}

		// First run
		if err := runInit(nil, nil); err != nil {
			t.Fatalf("first runInit() error: %v", err)
		}

		// Write custom content to config.yaml
		configPath := filepath.Join(dir, ".hal", "config.yaml")
		customContent := "# custom config\nengine: codex\n"
		if err := os.WriteFile(configPath, []byte(customContent), 0644); err != nil {
			t.Fatalf("Failed to write custom config: %v", err)
		}

		// Second run
		if err := runInit(nil, nil); err != nil {
			t.Fatalf("second runInit() error: %v", err)
		}

		// Verify custom content is preserved
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config.yaml: %v", err)
		}
		if string(data) != customContent {
			t.Errorf("config.yaml was overwritten\ngot:  %q\nwant: %q", string(data), customContent)
		}
	})
}

func TestEnsureGitignore(t *testing.T) {
	tests := []struct {
		name            string
		existingContent string
		wantContains    string
		wantSkip        bool // true if .hal/ already present (no output expected)
	}{
		{
			name:            "creates new gitignore",
			existingContent: "",
			wantContains:    ".hal/",
		},
		{
			name:            "appends to existing",
			existingContent: "node_modules/\n",
			wantContains:    ".hal/",
		},
		{
			name:            "appends to existing without trailing newline",
			existingContent: "node_modules/",
			wantContains:    ".hal/",
		},
		{
			name:            "skips if .hal/ present",
			existingContent: ".hal/\n",
			wantSkip:        true,
		},
		{
			name:            "skips if .hal present (no slash)",
			existingContent: ".hal\n",
			wantSkip:        true,
		},
		{
			name:            "skips if .hal/ present with other entries",
			existingContent: "node_modules/\n.hal/\nbuild/\n",
			wantSkip:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			gitignorePath := filepath.Join(tmpDir, ".gitignore")

			// Setup existing .gitignore if specified
			if tt.existingContent != "" {
				if err := os.WriteFile(gitignorePath, []byte(tt.existingContent), 0644); err != nil {
					t.Fatalf("failed to write initial .gitignore: %v", err)
				}
			}

			var buf bytes.Buffer
			err := ensureGitignore(tmpDir, &buf)
			if err != nil {
				t.Fatalf("ensureGitignore() error = %v", err)
			}

			// Read result
			content, err := os.ReadFile(gitignorePath)
			if err != nil {
				t.Fatalf("failed to read .gitignore: %v", err)
			}

			if tt.wantSkip {
				// Should not have modified the file or produced output
				if buf.Len() > 0 {
					t.Errorf("expected no output for skip case, got %q", buf.String())
				}
				if string(content) != tt.existingContent {
					t.Errorf("content should be unchanged\ngot:  %q\nwant: %q", string(content), tt.existingContent)
				}
			} else {
				// Should contain .hal/
				if !strings.Contains(string(content), tt.wantContains) {
					t.Errorf("content should contain %q\ngot: %q", tt.wantContains, string(content))
				}
				// Should have output message
				if !strings.Contains(buf.String(), "Added .hal/ to .gitignore") {
					t.Errorf("expected output message, got %q", buf.String())
				}
				// Should preserve existing content
				if tt.existingContent != "" {
					// Check that original entries are preserved (without trailing newline for comparison)
					originalEntries := strings.TrimRight(tt.existingContent, "\n")
					if !strings.Contains(string(content), originalEntries) {
						t.Errorf("should preserve existing content %q in %q", originalEntries, string(content))
					}
				}
			}
		})
	}
}

func TestEnsureGitignoreIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	gitignorePath := filepath.Join(tmpDir, ".gitignore")

	var buf bytes.Buffer

	// First call - should add .hal/
	if err := ensureGitignore(tmpDir, &buf); err != nil {
		t.Fatalf("first ensureGitignore() error = %v", err)
	}

	content1, _ := os.ReadFile(gitignorePath)
	count1 := strings.Count(string(content1), ".hal")

	// Second call - should be no-op
	buf.Reset()
	if err := ensureGitignore(tmpDir, &buf); err != nil {
		t.Fatalf("second ensureGitignore() error = %v", err)
	}

	content2, _ := os.ReadFile(gitignorePath)
	count2 := strings.Count(string(content2), ".hal")

	// Should have same count (idempotent)
	if count1 != count2 {
		t.Errorf("not idempotent: first call added %d .hal entries, second call has %d", count1, count2)
	}
	if count2 != 1 {
		t.Errorf("expected exactly 1 .hal entry, got %d", count2)
	}

	// Second call should produce no output
	if buf.Len() > 0 {
		t.Errorf("second call should produce no output, got %q", buf.String())
	}
}

func TestRunInitAddsGitignore(t *testing.T) {
	// Save and restore working directory
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	t.Run("adds .hal/ to new gitignore", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("Failed to chdir: %v", err)
		}

		if err := runInit(nil, nil); err != nil {
			t.Fatalf("runInit() error: %v", err)
		}

		gitignorePath := filepath.Join(dir, ".gitignore")
		content, err := os.ReadFile(gitignorePath)
		if err != nil {
			t.Fatalf(".gitignore should exist: %v", err)
		}
		if !strings.Contains(string(content), ".hal/") {
			t.Errorf(".gitignore should contain .hal/, got: %q", string(content))
		}
	})

	t.Run("adds .hal/ to existing gitignore", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("Failed to chdir: %v", err)
		}

		// Create existing .gitignore
		gitignorePath := filepath.Join(dir, ".gitignore")
		if err := os.WriteFile(gitignorePath, []byte("node_modules/\n"), 0644); err != nil {
			t.Fatalf("Failed to write .gitignore: %v", err)
		}

		if err := runInit(nil, nil); err != nil {
			t.Fatalf("runInit() error: %v", err)
		}

		content, err := os.ReadFile(gitignorePath)
		if err != nil {
			t.Fatalf("Failed to read .gitignore: %v", err)
		}
		if !strings.Contains(string(content), "node_modules/") {
			t.Errorf(".gitignore should preserve node_modules/, got: %q", string(content))
		}
		if !strings.Contains(string(content), ".hal/") {
			t.Errorf(".gitignore should contain .hal/, got: %q", string(content))
		}
	})

	t.Run("does not duplicate .hal/ on second init", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("Failed to chdir: %v", err)
		}

		// First init
		if err := runInit(nil, nil); err != nil {
			t.Fatalf("first runInit() error: %v", err)
		}

		// Second init
		if err := runInit(nil, nil); err != nil {
			t.Fatalf("second runInit() error: %v", err)
		}

		gitignorePath := filepath.Join(dir, ".gitignore")
		content, err := os.ReadFile(gitignorePath)
		if err != nil {
			t.Fatalf("Failed to read .gitignore: %v", err)
		}

		count := strings.Count(string(content), ".hal")
		if count != 1 {
			t.Errorf("expected exactly 1 .hal entry, got %d in: %q", count, string(content))
		}
	})
}
