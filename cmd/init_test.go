package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
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

	t.Run("second run does not overwrite existing config and migrates prompt branch guidance", func(t *testing.T) {
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

		// Simulate legacy prompt branch guidance and ensure migration updates it.
		promptPath := filepath.Join(dir, ".hal", template.PromptFile)
		canonicalBranchLine := "3. Check you're on the correct branch from PRD `branchName`. If not, check it out or create it from `{{BASE_BRANCH}}` (never default to `main` unless `{{BASE_BRANCH}}` is `main`)."
		legacyBranchLine := "3. Check you're on the correct branch from PRD `branchName`. If not, check it out or create from main."
		legacyPrompt := strings.Replace(template.DefaultPrompt, canonicalBranchLine, legacyBranchLine, 1)
		if legacyPrompt == template.DefaultPrompt {
			t.Fatal("failed to construct legacy prompt fixture")
		}
		if err := os.WriteFile(promptPath, []byte(legacyPrompt), 0644); err != nil {
			t.Fatalf("Failed to write legacy prompt: %v", err)
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

		// Verify prompt branch guidance is migrated away from implicit main.
		promptData, err := os.ReadFile(promptPath)
		if err != nil {
			t.Fatalf("Failed to read prompt.md: %v", err)
		}
		gotPrompt := string(promptData)
		if !strings.Contains(gotPrompt, canonicalBranchLine) {
			t.Fatalf("prompt.md should contain canonical branch guidance\nwant contains: %q\ngot: %s", canonicalBranchLine, gotPrompt)
		}
		if strings.Contains(gotPrompt, legacyBranchLine) {
			t.Fatalf("prompt.md should not keep legacy 'create from main' guidance\ngot: %s", gotPrompt)
		}
	})
}

func TestEnsureGitignore(t *testing.T) {
	tests := []struct {
		name            string
		existingContent string
		wantContains    []string
		wantMsgSubstr   string // expected output message substring
		wantSkip        bool   // true if already correct (no changes)
	}{
		{
			name:            "creates new gitignore",
			existingContent: "",
			wantContains:    []string{".hal/*", "!.hal/standards/", "!.hal/commands/"},
			wantMsgSubstr:   "Added .hal/*",
		},
		{
			name:            "appends to existing",
			existingContent: "node_modules/\n",
			wantContains:    []string{".hal/*", "!.hal/standards/", "!.hal/commands/", "node_modules/"},
			wantMsgSubstr:   "Added .hal/*",
		},
		{
			name:            "appends to existing without trailing newline",
			existingContent: "node_modules/",
			wantContains:    []string{".hal/*", "!.hal/standards/", "!.hal/commands/", "node_modules/"},
			wantMsgSubstr:   "Added .hal/*",
		},
		{
			name:            "migrates old .hal/ to .hal/* with exceptions",
			existingContent: ".hal/\n",
			wantContains:    []string{".hal/*", "!.hal/standards/", "!.hal/commands/"},
			wantMsgSubstr:   "Updated .gitignore",
		},
		{
			name:            "migrates old .hal (no slash) to .hal/* with exceptions",
			existingContent: ".hal\n",
			wantContains:    []string{".hal/*", "!.hal/standards/", "!.hal/commands/"},
			wantMsgSubstr:   "Updated .gitignore",
		},
		{
			name:            "migrates .hal/ preserving other entries",
			existingContent: "node_modules/\n.hal/\nbuild/\n",
			wantContains:    []string{".hal/*", "!.hal/standards/", "!.hal/commands/", "node_modules/", "build/"},
			wantMsgSubstr:   "Updated .gitignore",
		},
		{
			name:            "migrates .hal/* with only standards exception to add commands",
			existingContent: ".hal/*\n!.hal/standards/\n",
			wantContains:    []string{".hal/*", "!.hal/standards/", "!.hal/commands/"},
			wantMsgSubstr:   "Updated .gitignore",
		},
		{
			name:            "skips if already correct",
			existingContent: ".hal/*\n!.hal/standards/\n!.hal/commands/\n",
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
				if buf.Len() > 0 {
					t.Errorf("expected no output for skip case, got %q", buf.String())
				}
				if string(content) != tt.existingContent {
					t.Errorf("content should be unchanged\ngot:  %q\nwant: %q", string(content), tt.existingContent)
				}
			} else {
				for _, want := range tt.wantContains {
					if !strings.Contains(string(content), want) {
						t.Errorf("content should contain %q\ngot: %q", want, string(content))
					}
				}
				if !strings.Contains(buf.String(), tt.wantMsgSubstr) {
					t.Errorf("expected output containing %q, got %q", tt.wantMsgSubstr, buf.String())
				}
			}
		})
	}
}

func TestEnsureGitignoreIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	gitignorePath := filepath.Join(tmpDir, ".gitignore")

	var buf bytes.Buffer

	// First call - should add .hal/* and !.hal/standards/
	if err := ensureGitignore(tmpDir, &buf); err != nil {
		t.Fatalf("first ensureGitignore() error = %v", err)
	}

	content1, _ := os.ReadFile(gitignorePath)

	// Second call - should be no-op
	buf.Reset()
	if err := ensureGitignore(tmpDir, &buf); err != nil {
		t.Fatalf("second ensureGitignore() error = %v", err)
	}

	content2, _ := os.ReadFile(gitignorePath)

	// Content should be identical
	if string(content1) != string(content2) {
		t.Errorf("not idempotent\nfirst:  %q\nsecond: %q", string(content1), string(content2))
	}

	// Should contain exactly one .hal/* entry
	count := strings.Count(string(content2), ".hal/*")
	if count != 1 {
		t.Errorf("expected exactly 1 .hal/* entry, got %d", count)
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

	t.Run("adds .hal/* to new gitignore", func(t *testing.T) {
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
		if !strings.Contains(string(content), ".hal/*") {
			t.Errorf(".gitignore should contain .hal/*, got: %q", string(content))
		}
		if !strings.Contains(string(content), "!.hal/standards/") {
			t.Errorf(".gitignore should contain !.hal/standards/, got: %q", string(content))
		}
		if !strings.Contains(string(content), "!.hal/commands/") {
			t.Errorf(".gitignore should contain !.hal/commands/, got: %q", string(content))
		}
	})

	t.Run("adds .hal/* to existing gitignore", func(t *testing.T) {
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
		if !strings.Contains(string(content), ".hal/*") {
			t.Errorf(".gitignore should contain .hal/*, got: %q", string(content))
		}
	})

	t.Run("does not duplicate on second init", func(t *testing.T) {
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

		count := strings.Count(string(content), ".hal/*")
		if count != 1 {
			t.Errorf("expected exactly 1 .hal/* entry, got %d in: %q", count, string(content))
		}
	})
}

func newInitTestRootCmd(out, errOut io.Writer) *cobra.Command {
	root := &cobra.Command{Use: "hal"}
	init := &cobra.Command{
		Use: "init",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInitWithWriters(cmd, args, out, errOut)
		},
	}
	addInitFlags(init)
	root.AddCommand(init)
	return root
}

func TestInitRefreshTemplatesCobra(t *testing.T) {
	// Save and restore working directory
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	// Pre-populate .hal/ with custom content so refresh has diffs to detect
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create .hal: %v", err)
	}
	sortedNames := []string{template.ConfigFile, template.ProgressFile, template.PromptFile}
	for _, name := range sortedNames {
		writeFile(t, halDir, name, "custom "+name)
	}

	var stdout, stderr bytes.Buffer

	// Execute through isolated Cobra command tree
	testRoot := newInitTestRootCmd(&stdout, &stderr)
	testRoot.SetArgs([]string{"init", "--refresh-templates"})
	if err := testRoot.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() error: %v", err)
	}
	if stderr.Len() > 0 {
		t.Fatalf("unexpected stderr output: %s", stderr.String())
	}

	output := stdout.String()
	if strings.Contains(output, "All files already exist. No changes made.") {
		t.Fatalf("output should not claim no changes when templates were refreshed, got: %s", output)
	}

	// Verify output contains refreshed entries in sorted filename order
	for _, name := range sortedNames {
		if !strings.Contains(output, name) {
			t.Errorf("output should contain %q, got: %s", name, output)
		}
	}

	// Verify sorted order: config.yaml before progress.txt before prompt.md
	idxConfig := strings.Index(output, "refreshed .hal/"+template.ConfigFile)
	idxProgress := strings.Index(output, "refreshed .hal/"+template.ProgressFile)
	idxPrompt := strings.Index(output, "refreshed .hal/"+template.PromptFile)

	if idxConfig < 0 || idxProgress < 0 || idxPrompt < 0 {
		t.Fatalf("expected all 3 refreshed lines in output, got: %s", output)
	}
	if idxConfig >= idxProgress {
		t.Errorf("config.yaml (%d) should appear before progress.txt (%d)", idxConfig, idxProgress)
	}
	if idxProgress >= idxPrompt {
		t.Errorf("progress.txt (%d) should appear before prompt.md (%d)", idxProgress, idxPrompt)
	}

	// Verify actual files are refreshed on disk with embedded content
	defaults := template.DefaultFiles()
	for _, name := range sortedNames {
		data, err := os.ReadFile(filepath.Join(halDir, name))
		if err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
		if string(data) != defaults[name] {
			t.Errorf("%s should contain embedded content after refresh, got: %q", name, string(data))
		}
		// Verify backup file was created
		bakPattern := filepath.Join(halDir, name+".*.bak")
		matches, _ := filepath.Glob(bakPattern)
		if len(matches) < 1 {
			t.Errorf("expected backup file for %s", name)
		}
	}
}

func TestInitDryRunCobra(t *testing.T) {
	// Save and restore working directory
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	// Run init first so .hal/ exists with default files and infrastructure
	if err := runInit(nil, nil); err != nil {
		t.Fatalf("initial runInit() error: %v", err)
	}

	// Overwrite templates with custom content so dry-run has diffs to detect
	halDir := filepath.Join(dir, ".hal")
	sortedNames := []string{template.ConfigFile, template.ProgressFile, template.PromptFile}
	for _, name := range sortedNames {
		writeFile(t, halDir, name, "custom "+name)
	}

	var stdout, stderr bytes.Buffer

	// Execute through isolated Cobra command tree with both flags
	testRoot := newInitTestRootCmd(&stdout, &stderr)
	testRoot.SetArgs([]string{"init", "--refresh-templates", "--dry-run"})
	if err := testRoot.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() error: %v", err)
	}
	if stderr.Len() > 0 {
		t.Fatalf("unexpected stderr output: %s", stderr.String())
	}

	output := stdout.String()

	// Verify output contains [dry-run] prefix
	if !strings.Contains(output, "[dry-run]") {
		t.Fatalf("output should contain [dry-run], got: %s", output)
	}

	// Verify output lines appear in sorted filename order
	for _, name := range sortedNames {
		if !strings.Contains(output, name) {
			t.Errorf("output should contain %q, got: %s", name, output)
		}
	}

	// Verify sorted order: config.yaml before progress.txt before prompt.md (with [dry-run] prefix)
	idxConfig := strings.Index(output, "[dry-run] refreshed .hal/"+template.ConfigFile)
	idxProgress := strings.Index(output, "[dry-run] refreshed .hal/"+template.ProgressFile)
	idxPrompt := strings.Index(output, "[dry-run] refreshed .hal/"+template.PromptFile)

	if idxConfig < 0 || idxProgress < 0 || idxPrompt < 0 {
		t.Fatalf("expected all 3 [dry-run] refreshed lines in output, got: %s", output)
	}
	if idxConfig >= idxProgress {
		t.Errorf("config.yaml (%d) should appear before progress.txt (%d)", idxConfig, idxProgress)
	}
	if idxProgress >= idxPrompt {
		t.Errorf("progress.txt (%d) should appear before prompt.md (%d)", idxProgress, idxPrompt)
	}

	// Verify no template files were modified (still have custom content)
	for _, name := range sortedNames {
		data, err := os.ReadFile(filepath.Join(halDir, name))
		if err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
		if string(data) != "custom "+name {
			t.Errorf("%s should NOT be modified in dry-run, got: %q", name, string(data))
		}
		// Verify no backup files were created
		bakPattern := filepath.Join(halDir, name+".*.bak")
		matches, _ := filepath.Glob(bakPattern)
		if len(matches) > 0 {
			t.Errorf("dry-run should not create backup files for %s: %v", name, matches)
		}
	}
}

func TestInitDryRunDoesNotRunTemplateMigrations(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	if err := runInit(nil, nil); err != nil {
		t.Fatalf("initial runInit() error: %v", err)
	}

	promptPath := filepath.Join(dir, ".hal", template.PromptFile)
	canonicalBranchLine := "3. Check you're on the correct branch from PRD `branchName`. If not, check it out or create it from `{{BASE_BRANCH}}` (never default to `main` unless `{{BASE_BRANCH}}` is `main`)."
	legacyBranchLine := "3. Check you're on the correct branch from PRD `branchName`. If not, check it out or create from main."

	promptData, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("Failed to read prompt.md: %v", err)
	}
	legacyPrompt := strings.Replace(string(promptData), canonicalBranchLine, legacyBranchLine, 1)
	if legacyPrompt == string(promptData) {
		t.Fatal("failed to construct legacy prompt fixture")
	}
	if err := os.WriteFile(promptPath, []byte(legacyPrompt), 0644); err != nil {
		t.Fatalf("Failed to write legacy prompt: %v", err)
	}

	var stdout, stderr bytes.Buffer
	testRoot := newInitTestRootCmd(&stdout, &stderr)
	testRoot.SetArgs([]string{"init", "--refresh-templates", "--dry-run"})
	if err := testRoot.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() error: %v", err)
	}
	if stderr.Len() > 0 {
		t.Fatalf("unexpected stderr output: %s", stderr.String())
	}

	after, err := os.ReadFile(promptPath)
	if err != nil {
		t.Fatalf("Failed to read prompt.md after dry-run: %v", err)
	}
	if string(after) != legacyPrompt {
		t.Fatalf("dry-run should not apply prompt migrations\nwant: %q\ngot:  %q", legacyPrompt, string(after))
	}
}

func normalizeRefreshOutput(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "(backup: "); idx >= 0 {
			lines[i] = line[:idx] + "(backup: <redacted>)"
		}
	}
	return strings.Join(lines, "\n")
}

func assertRefreshLineOrder(t *testing.T, output string, sortedNames []string, dryRun bool) {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != len(sortedNames) {
		t.Fatalf("expected %d output lines, got %d: %q", len(sortedNames), len(lines), output)
	}

	for i, name := range sortedNames {
		expected := "refreshed .hal/" + name
		if dryRun {
			expected = "[dry-run] " + expected
		}
		if !strings.Contains(lines[i], expected) {
			t.Fatalf("line %d should contain %q, got %q", i, expected, lines[i])
		}
		if !strings.Contains(lines[i], "(backup: ") {
			t.Fatalf("refresh output should contain backup metadata, got %q", lines[i])
		}
	}
}

func TestRefreshTemplatesDeterministic(t *testing.T) {
	// Sorted order of template.DefaultFiles() keys
	sortedNames := []string{template.ConfigFile, template.ProgressFile, template.PromptFile}

	for _, dryRun := range []bool{false, true} {
		label := "real"
		if dryRun {
			label = "dry-run"
		}
		t.Run(label, func(t *testing.T) {
			var normalizedOutputs []string
			for i := 0; i < 3; i++ {
				halDir := filepath.Join(t.TempDir(), ".hal")
				if err := os.MkdirAll(halDir, 0755); err != nil {
					t.Fatalf("failed to create halDir: %v", err)
				}
				// Pre-populate with custom content so refresh has something to diff
				for _, name := range sortedNames {
					writeFile(t, halDir, name, "custom "+name)
				}

				var buf bytes.Buffer
				if _, err := refreshTemplates(halDir, dryRun, &buf); err != nil {
					t.Fatalf("refreshTemplates() iteration %d error: %v", i, err)
				}

				output := buf.String()
				assertRefreshLineOrder(t, output, sortedNames, dryRun)
				normalizedOutputs = append(normalizedOutputs, normalizeRefreshOutput(output))
			}

			for i := 1; i < len(normalizedOutputs); i++ {
				if normalizedOutputs[i] != normalizedOutputs[0] {
					t.Fatalf("output mismatch between run 0 and run %d:\nrun 0: %q\nrun %d: %q", i, normalizedOutputs[0], i, normalizedOutputs[i])
				}
			}
		})
	}
}

func TestRefreshTemplatesBackupNameCollision(t *testing.T) {
	halDir := filepath.Join(t.TempDir(), ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("failed to create halDir: %v", err)
	}

	defaults := template.DefaultFiles()
	for filename := range defaults {
		writeFile(t, halDir, filename, "custom content for "+filename)
	}

	fixed := time.Date(2026, time.February, 10, 1, 0, 0, 0, time.UTC)
	origNow := nowForRefresh
	nowForRefresh = func() time.Time { return fixed }
	t.Cleanup(func() { nowForRefresh = origNow })

	if _, err := refreshTemplates(halDir, false, &bytes.Buffer{}); err != nil {
		t.Fatalf("first refreshTemplates() error: %v", err)
	}

	writeFile(t, halDir, template.ConfigFile, "second custom content")
	if _, err := refreshTemplates(halDir, false, &bytes.Buffer{}); err != nil {
		t.Fatalf("second refreshTemplates() error: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(halDir, template.ConfigFile+".*.bak"))
	if err != nil {
		t.Fatalf("glob error: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 backups for %s, got %d: %v", template.ConfigFile, len(matches), matches)
	}
}

func TestRefreshTemplates(t *testing.T) {
	defaults := template.DefaultFiles()

	tests := []struct {
		name   string
		dryRun bool
		setup  func(t *testing.T, halDir string)
		check  func(t *testing.T, halDir string, output string)
	}{
		{
			name:   "creates templates when none exist",
			dryRun: false,
			setup:  func(t *testing.T, halDir string) { /* no files */ },
			check: func(t *testing.T, halDir string, output string) {
				for filename, embedded := range defaults {
					// File should be created
					data, err := os.ReadFile(filepath.Join(halDir, filename))
					if err != nil {
						t.Fatalf("expected %s to be created: %v", filename, err)
					}
					if string(data) != embedded {
						t.Errorf("%s content mismatch", filename)
					}
					// Output should say "created"
					if !strings.Contains(output, "created .hal/"+filename) {
						t.Errorf("output should contain 'created .hal/%s', got: %s", filename, output)
					}
					// No backup files
					bakPattern := filepath.Join(halDir, filename+".*.bak")
					matches, _ := filepath.Glob(bakPattern)
					if len(matches) > 0 {
						t.Errorf("unexpected backup files for %s: %v", filename, matches)
					}
				}
			},
		},
		{
			name:   "creates backups when templates differ",
			dryRun: false,
			setup: func(t *testing.T, halDir string) {
				for filename := range defaults {
					writeFile(t, halDir, filename, "custom content for "+filename)
				}
			},
			check: func(t *testing.T, halDir string, output string) {
				for filename, embedded := range defaults {
					// File should be overwritten with embedded content
					data, err := os.ReadFile(filepath.Join(halDir, filename))
					if err != nil {
						t.Fatalf("expected %s to exist: %v", filename, err)
					}
					if string(data) != embedded {
						t.Errorf("%s should contain embedded content after refresh", filename)
					}
					// Output should say "refreshed" with backup path
					if !strings.Contains(output, "refreshed .hal/"+filename) {
						t.Errorf("output should contain 'refreshed .hal/%s', got: %s", filename, output)
					}
					if !strings.Contains(output, "(backup:") {
						t.Errorf("output should contain '(backup:', got: %s", output)
					}
					// Backup file should exist with old content
					bakPattern := filepath.Join(halDir, filename+".*.bak")
					matches, _ := filepath.Glob(bakPattern)
					if len(matches) != 1 {
						t.Fatalf("expected 1 backup for %s, got %d", filename, len(matches))
					}
					bakData, err := os.ReadFile(matches[0])
					if err != nil {
						t.Fatalf("failed to read backup: %v", err)
					}
					if string(bakData) != "custom content for "+filename {
						t.Errorf("backup content mismatch for %s", filename)
					}
				}
			},
		},
		{
			name:   "unchanged when templates match embedded",
			dryRun: false,
			setup: func(t *testing.T, halDir string) {
				for filename, embedded := range defaults {
					writeFile(t, halDir, filename, embedded)
				}
			},
			check: func(t *testing.T, halDir string, output string) {
				for filename := range defaults {
					if !strings.Contains(output, "unchanged .hal/"+filename) {
						t.Errorf("output should contain 'unchanged .hal/%s', got: %s", filename, output)
					}
					// No backup files
					bakPattern := filepath.Join(halDir, filename+".*.bak")
					matches, _ := filepath.Glob(bakPattern)
					if len(matches) > 0 {
						t.Errorf("unexpected backup files for %s: %v", filename, matches)
					}
				}
			},
		},
		{
			name:   "dry-run does not write files",
			dryRun: true,
			setup: func(t *testing.T, halDir string) {
				for filename := range defaults {
					writeFile(t, halDir, filename, "custom content for "+filename)
				}
			},
			check: func(t *testing.T, halDir string, output string) {
				for filename := range defaults {
					// Output should be prefixed with [dry-run]
					if !strings.Contains(output, "[dry-run]") {
						t.Errorf("output should contain '[dry-run]', got: %s", output)
					}
					// Files should NOT be overwritten
					data, err := os.ReadFile(filepath.Join(halDir, filename))
					if err != nil {
						t.Fatalf("expected %s to exist: %v", filename, err)
					}
					if string(data) != "custom content for "+filename {
						t.Errorf("%s should not be modified in dry-run mode", filename)
					}
					// No backup files should be created
					bakPattern := filepath.Join(halDir, filename+".*.bak")
					matches, _ := filepath.Glob(bakPattern)
					if len(matches) > 0 {
						t.Errorf("dry-run should not create backup files for %s: %v", filename, matches)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			halDir := filepath.Join(t.TempDir(), ".hal")
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("failed to create halDir: %v", err)
			}
			tt.setup(t, halDir)

			var buf bytes.Buffer
			_, err := refreshTemplates(halDir, tt.dryRun, &buf)
			if err != nil {
				t.Fatalf("refreshTemplates() error: %v", err)
			}

			tt.check(t, halDir, buf.String())
		})
	}
}
