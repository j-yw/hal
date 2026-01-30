package skills

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCodexLinkerName(t *testing.T) {
	linker := &CodexLinker{}
	if got := linker.Name(); got != "codex" {
		t.Errorf("Name() = %q, want %q", got, "codex")
	}
}

func TestCodexLinkerSkillsDir(t *testing.T) {
	linker := &CodexLinker{}
	home, _ := os.UserHomeDir()
	want := filepath.Join(home, ".codex", "skills")

	if got := linker.SkillsDir(); got != want {
		t.Errorf("SkillsDir() = %q, want %q", got, want)
	}
}

func TestCodexLinkerLink(t *testing.T) {
	// Create temp directories
	projectDir := t.TempDir()
	goralphSkillsDir := filepath.Join(projectDir, ".goralph", "skills")
	if err := os.MkdirAll(goralphSkillsDir, 0755); err != nil {
		t.Fatalf("failed to create .goralph/skills: %v", err)
	}

	// Create a test skill directory
	testSkillDir := filepath.Join(goralphSkillsDir, "testskill")
	if err := os.MkdirAll(testSkillDir, 0755); err != nil {
		t.Fatalf("failed to create test skill dir: %v", err)
	}

	// Create temp codex skills dir (we don't want to modify real ~/.codex)
	codexSkillsDir := t.TempDir()

	// Create a custom linker that uses our temp dir
	linker := &testCodexLinker{skillsDir: codexSkillsDir}

	// Test linking
	err := linker.Link(projectDir, []string{"testskill"})
	if err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	// Verify symlink was created
	linkPath := filepath.Join(codexSkillsDir, "testskill")
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("Symlink not created: %v", err)
	}

	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("Created file is not a symlink")
	}

	// Verify symlink target
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Could not read symlink: %v", err)
	}

	absProjectDir, _ := filepath.Abs(projectDir)
	expectedTarget := filepath.Join(absProjectDir, ".goralph", "skills", "testskill")
	if target != expectedTarget {
		t.Errorf("Symlink target = %q, want %q", target, expectedTarget)
	}
}

func TestCodexLinkerLinkIdempotent(t *testing.T) {
	projectDir := t.TempDir()
	goralphSkillsDir := filepath.Join(projectDir, ".goralph", "skills")
	if err := os.MkdirAll(goralphSkillsDir, 0755); err != nil {
		t.Fatalf("failed to create .goralph/skills: %v", err)
	}

	testSkillDir := filepath.Join(goralphSkillsDir, "testskill")
	if err := os.MkdirAll(testSkillDir, 0755); err != nil {
		t.Fatalf("failed to create test skill dir: %v", err)
	}

	codexSkillsDir := t.TempDir()
	linker := &testCodexLinker{skillsDir: codexSkillsDir}

	// Link twice - should not error
	if err := linker.Link(projectDir, []string{"testskill"}); err != nil {
		t.Fatalf("First Link() error = %v", err)
	}
	if err := linker.Link(projectDir, []string{"testskill"}); err != nil {
		t.Fatalf("Second Link() error = %v", err)
	}
}

func TestCodexLinkerUnlink(t *testing.T) {
	projectDir := t.TempDir()
	goralphSkillsDir := filepath.Join(projectDir, ".goralph", "skills")
	if err := os.MkdirAll(goralphSkillsDir, 0755); err != nil {
		t.Fatalf("failed to create .goralph/skills: %v", err)
	}

	// Use a skill name that's in SkillNames (e.g., "prd")
	testSkillDir := filepath.Join(goralphSkillsDir, "prd")
	if err := os.MkdirAll(testSkillDir, 0755); err != nil {
		t.Fatalf("failed to create test skill dir: %v", err)
	}

	codexSkillsDir := t.TempDir()
	linker := &testCodexLinker{skillsDir: codexSkillsDir}

	// Link first
	if err := linker.Link(projectDir, []string{"prd"}); err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	// Unlink
	if err := linker.Unlink(projectDir); err != nil {
		t.Fatalf("Unlink() error = %v", err)
	}

	// Verify symlink was removed
	linkPath := filepath.Join(codexSkillsDir, "prd")
	if _, err := os.Lstat(linkPath); !os.IsNotExist(err) {
		t.Error("Symlink should have been removed")
	}
}

func TestCodexLinkerUnlinkOnlyOwnLinks(t *testing.T) {
	projectDir1 := t.TempDir()
	projectDir2 := t.TempDir()
	codexSkillsDir := t.TempDir()

	// Set up both projects
	for _, dir := range []string{projectDir1, projectDir2} {
		goralphSkillsDir := filepath.Join(dir, ".goralph", "skills")
		if err := os.MkdirAll(goralphSkillsDir, 0755); err != nil {
			t.Fatalf("failed to create .goralph/skills: %v", err)
		}
		testSkillDir := filepath.Join(goralphSkillsDir, "testskill")
		if err := os.MkdirAll(testSkillDir, 0755); err != nil {
			t.Fatalf("failed to create test skill dir: %v", err)
		}
	}

	linker := &testCodexLinker{skillsDir: codexSkillsDir}

	// Link from project1
	if err := linker.Link(projectDir1, []string{"testskill"}); err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	// Unlink from project2 (different project) - should NOT remove the link
	if err := linker.Unlink(projectDir2); err != nil {
		t.Fatalf("Unlink() error = %v", err)
	}

	// Verify symlink still exists (because it points to project1, not project2)
	linkPath := filepath.Join(codexSkillsDir, "testskill")
	if _, err := os.Lstat(linkPath); err != nil {
		t.Error("Symlink should still exist (it belongs to project1)")
	}
}

func TestCodexLinkerRegistered(t *testing.T) {
	linker := GetLinker("codex")
	if linker == nil {
		t.Error("CodexLinker should be registered via init()")
	}
}

// testCodexLinker is a test helper that uses a custom skills dir
type testCodexLinker struct {
	skillsDir string
}

func (c *testCodexLinker) Name() string {
	return "codex"
}

func (c *testCodexLinker) SkillsDir() string {
	return c.skillsDir
}

func (c *testCodexLinker) Link(projectDir string, skills []string) error {
	if err := os.MkdirAll(c.skillsDir, 0755); err != nil {
		return err
	}

	for _, skill := range skills {
		absProjectDir, err := filepath.Abs(projectDir)
		if err != nil {
			return err
		}
		target := filepath.Join(absProjectDir, ".goralph", "skills", skill)
		link := filepath.Join(c.skillsDir, skill)

		if existing, err := os.Readlink(link); err == nil && existing == target {
			continue
		}

		os.RemoveAll(link)

		if err := os.Symlink(target, link); err != nil {
			return err
		}
	}
	return nil
}

func (c *testCodexLinker) Unlink(projectDir string) error {
	absProjectDir, _ := filepath.Abs(projectDir)

	for _, skill := range SkillNames {
		link := filepath.Join(c.skillsDir, skill)
		target := filepath.Join(absProjectDir, ".goralph", "skills", skill)

		if existing, err := os.Readlink(link); err == nil && existing == target {
			os.RemoveAll(link)
		}
	}
	return nil
}
