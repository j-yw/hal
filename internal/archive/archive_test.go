package archive

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

// helper to write a minimal PRD JSON file.
func writePRD(t *testing.T, dir, filename, branchName string, stories []engine.UserStory) {
	t.Helper()
	prd := engine.PRD{
		Project:     "test",
		BranchName:  branchName,
		Description: "test",
		UserStories: stories,
	}
	data, err := json.MarshalIndent(prd, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), data, 0644); err != nil {
		t.Fatal(err)
	}
}

// helper to create a file with content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestCreate(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, halDir string)
		archName  string
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, halDir, archDir string)
	}{
		{
			name: "successful archive with manual and auto files",
			setup: func(t *testing.T, halDir string) {
				writePRD(t, halDir, template.PRDFile, "hal/my-feature", nil)
				writePRD(t, halDir, template.AutoPRDFile, "hal/my-feature", nil)
				writeFile(t, filepath.Join(halDir, template.ProgressFile), "progress")
				writeFile(t, filepath.Join(halDir, template.AutoProgressFile), "auto-progress")
				writeFile(t, filepath.Join(halDir, template.AutoStateFile), `{"step":"done"}`)
			},
			archName: "my-feature",
			check: func(t *testing.T, halDir, archDir string) {
				// Files should be in archive
				for _, f := range []string{template.PRDFile, template.AutoPRDFile, template.ProgressFile, template.AutoProgressFile, template.AutoStateFile} {
					if !fileExists(filepath.Join(archDir, f)) {
						t.Errorf("expected %s in archive", f)
					}
					if fileExists(filepath.Join(halDir, f)) {
						t.Errorf("expected %s removed from halDir", f)
					}
				}
			},
		},
		{
			name: "prd-*.md globs picked up",
			setup: func(t *testing.T, halDir string) {
				writePRD(t, halDir, template.PRDFile, "hal/feat", nil)
				writeFile(t, filepath.Join(halDir, "prd-my-feature.md"), "# PRD")
				writeFile(t, filepath.Join(halDir, "prd-another.md"), "# Another")
			},
			archName: "feat",
			check: func(t *testing.T, halDir, archDir string) {
				if !fileExists(filepath.Join(archDir, "prd-my-feature.md")) {
					t.Error("prd-my-feature.md not archived")
				}
				if !fileExists(filepath.Join(archDir, "prd-another.md")) {
					t.Error("prd-another.md not archived")
				}
			},
		},
		{
			name: "reports moved but .gitkeep preserved",
			setup: func(t *testing.T, halDir string) {
				writePRD(t, halDir, template.PRDFile, "hal/feat", nil)
				reportsDir := filepath.Join(halDir, "reports")
				os.MkdirAll(reportsDir, 0755)
				writeFile(t, filepath.Join(reportsDir, "review.md"), "# Review")
				writeFile(t, filepath.Join(reportsDir, ".gitkeep"), "")
			},
			archName: "feat",
			check: func(t *testing.T, halDir, archDir string) {
				if !fileExists(filepath.Join(archDir, "reports", "review.md")) {
					t.Error("reports/review.md not archived")
				}
				// .gitkeep should still be in original reports
				if !fileExists(filepath.Join(halDir, "reports", ".gitkeep")) {
					t.Error(".gitkeep should not be moved")
				}
			},
		},
		{
			name: "config/skills/rules never touched",
			setup: func(t *testing.T, halDir string) {
				writePRD(t, halDir, template.PRDFile, "hal/feat", nil)
				writeFile(t, filepath.Join(halDir, template.ConfigFile), "config")
				writeFile(t, filepath.Join(halDir, template.PromptFile), "prompt")
				os.MkdirAll(filepath.Join(halDir, "skills"), 0755)
				writeFile(t, filepath.Join(halDir, "skills", "test.md"), "skill")
				os.MkdirAll(filepath.Join(halDir, "rules"), 0755)
				writeFile(t, filepath.Join(halDir, "rules", "rule.md"), "rule")
			},
			archName: "feat",
			check: func(t *testing.T, halDir, archDir string) {
				if !fileExists(filepath.Join(halDir, template.ConfigFile)) {
					t.Error("config.yaml should not be archived")
				}
				if !fileExists(filepath.Join(halDir, template.PromptFile)) {
					t.Error("prompt.md should not be archived")
				}
				if !fileExists(filepath.Join(halDir, "skills", "test.md")) {
					t.Error("skills should not be archived")
				}
				if !fileExists(filepath.Join(halDir, "rules", "rule.md")) {
					t.Error("rules should not be archived")
				}
			},
		},
		{
			name: "name collision handling",
			setup: func(t *testing.T, halDir string) {
				writePRD(t, halDir, template.PRDFile, "hal/feat", nil)
				// Pre-create a collision dir
				os.MkdirAll(filepath.Join(halDir, "archive"), 0755)
				// We'll need to match the date, but the collision dir just needs to exist
			},
			archName: "feat",
			check: func(t *testing.T, halDir, archDir string) {
				if !dirExists(archDir) {
					t.Error("archive dir should exist")
				}
			},
		},
		{
			name:      "error when no prd.json or auto-prd.json",
			setup:     func(t *testing.T, halDir string) {},
			archName:  "nothing",
			wantErr:   true,
			errSubstr: "no feature state to archive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			halDir := t.TempDir()
			tt.setup(t, halDir)

			var buf bytes.Buffer
			archDir, err := Create(halDir, tt.archName, &buf)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, halDir, archDir)
			}
		})
	}
}

func TestCreate_NameCollisionSuffix(t *testing.T) {
	halDir := t.TempDir()

	// Create two archives with the same name on the same day
	writePRD(t, halDir, template.PRDFile, "hal/feat", nil)
	var buf bytes.Buffer
	dir1, err := Create(halDir, "feat", &buf)
	if err != nil {
		t.Fatal(err)
	}

	// Create prd.json again for second archive
	writePRD(t, halDir, template.PRDFile, "hal/feat", nil)
	dir2, err := Create(halDir, "feat", &buf)
	if err != nil {
		t.Fatal(err)
	}

	if dir1 == dir2 {
		t.Error("second archive should have a different name")
	}
	if !strings.HasSuffix(dir2, "-2") {
		t.Errorf("expected -2 suffix, got %s", filepath.Base(dir2))
	}

	// Third collision
	writePRD(t, halDir, template.PRDFile, "hal/feat", nil)
	dir3, err := Create(halDir, "feat", &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(dir3, "-3") {
		t.Errorf("expected -3 suffix, got %s", filepath.Base(dir3))
	}
}

func TestList(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, halDir string)
		wantCount  int
		wantFirst  string
		checkStats func(t *testing.T, archives []ArchiveInfo)
	}{
		{
			name: "multiple archives with completion stats",
			setup: func(t *testing.T, halDir string) {
				// Archive 1: 2 of 3 complete
				dir1 := filepath.Join(halDir, "archive", "2026-01-01-feat-a")
				os.MkdirAll(dir1, 0755)
				writePRD(t, dir1, template.PRDFile, "hal/feat-a", []engine.UserStory{
					{ID: "US-001", Passes: true},
					{ID: "US-002", Passes: true},
					{ID: "US-003", Passes: false},
				})

				// Archive 2: 0 of 1 complete
				dir2 := filepath.Join(halDir, "archive", "2026-01-02-feat-b")
				os.MkdirAll(dir2, 0755)
				writePRD(t, dir2, template.PRDFile, "hal/feat-b", []engine.UserStory{
					{ID: "US-001", Passes: false},
				})
			},
			wantCount: 2,
			wantFirst: "2026-01-01-feat-a",
			checkStats: func(t *testing.T, archives []ArchiveInfo) {
				if archives[0].Completed != 2 || archives[0].Total != 3 {
					t.Errorf("archive 0: want 2/3, got %d/%d", archives[0].Completed, archives[0].Total)
				}
				if archives[1].Completed != 0 || archives[1].Total != 1 {
					t.Errorf("archive 1: want 0/1, got %d/%d", archives[1].Completed, archives[1].Total)
				}
				if archives[0].BranchName != "hal/feat-a" {
					t.Errorf("archive 0 branch: want hal/feat-a, got %s", archives[0].BranchName)
				}
			},
		},
		{
			name:      "empty archive dir returns empty slice",
			setup:     func(t *testing.T, halDir string) {},
			wantCount: 0,
		},
		{
			name: "malformed prd.json handled gracefully",
			setup: func(t *testing.T, halDir string) {
				dir := filepath.Join(halDir, "archive", "2026-01-01-bad")
				os.MkdirAll(dir, 0755)
				writeFile(t, filepath.Join(dir, template.PRDFile), "not json")
			},
			wantCount: 1,
			checkStats: func(t *testing.T, archives []ArchiveInfo) {
				// Should not crash, stats should be zero
				if archives[0].Total != 0 {
					t.Errorf("expected 0 total for malformed PRD, got %d", archives[0].Total)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			halDir := t.TempDir()
			tt.setup(t, halDir)

			archives, err := List(halDir)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(archives) != tt.wantCount {
				t.Fatalf("expected %d archives, got %d", tt.wantCount, len(archives))
			}
			if tt.wantFirst != "" && len(archives) > 0 && archives[0].Name != tt.wantFirst {
				t.Errorf("first archive: want %s, got %s", tt.wantFirst, archives[0].Name)
			}
			if tt.checkStats != nil {
				tt.checkStats(t, archives)
			}
		})
	}
}

func TestRestore(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, halDir string) string // returns archive name
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, halDir string)
	}{
		{
			name: "successful restore removes archive dir",
			setup: func(t *testing.T, halDir string) string {
				archDir := filepath.Join(halDir, "archive", "2026-01-01-feat")
				os.MkdirAll(archDir, 0755)
				writePRD(t, archDir, template.PRDFile, "hal/feat", nil)
				writeFile(t, filepath.Join(archDir, template.ProgressFile), "progress")
				return "2026-01-01-feat"
			},
			check: func(t *testing.T, halDir string) {
				if !fileExists(filepath.Join(halDir, template.PRDFile)) {
					t.Error("prd.json should be restored")
				}
				if !fileExists(filepath.Join(halDir, template.ProgressFile)) {
					t.Error("progress.txt should be restored")
				}
				if dirExists(filepath.Join(halDir, "archive", "2026-01-01-feat")) {
					t.Error("archive dir should be removed")
				}
			},
		},
		{
			name: "auto-archives current state first",
			setup: func(t *testing.T, halDir string) string {
				// Create current state
				writePRD(t, halDir, template.PRDFile, "hal/current", nil)
				writeFile(t, filepath.Join(halDir, template.ProgressFile), "current progress")

				// Create archive to restore
				archDir := filepath.Join(halDir, "archive", "2026-01-01-old")
				os.MkdirAll(archDir, 0755)
				writePRD(t, archDir, template.PRDFile, "hal/old", nil)
				return "2026-01-01-old"
			},
			check: func(t *testing.T, halDir string) {
				// Restored PRD should be the old one
				data, _ := os.ReadFile(filepath.Join(halDir, template.PRDFile))
				var prd engine.PRD
				json.Unmarshal(data, &prd)
				if prd.BranchName != "hal/old" {
					t.Errorf("expected restored branch hal/old, got %s", prd.BranchName)
				}

				// Auto-saved archive should exist
				archives, _ := List(halDir)
				found := false
				for _, a := range archives {
					if strings.Contains(a.Name, "auto-saved") {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected auto-saved archive")
				}
			},
		},
		{
			name: "error on non-existent archive name",
			setup: func(t *testing.T, halDir string) string {
				return "does-not-exist"
			},
			wantErr:   true,
			errSubstr: "does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			halDir := t.TempDir()
			archName := tt.setup(t, halDir)

			var buf bytes.Buffer
			err := Restore(halDir, archName, &buf)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, halDir)
			}
		})
	}
}

func TestFeatureFromBranch(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hal/my-feature", "my-feature"},
		{"hal/archive-command", "archive-command"},
		{"no-prefix", "no-prefix"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := FeatureFromBranch(tt.input)
			if got != tt.want {
				t.Errorf("FeatureFromBranch(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
