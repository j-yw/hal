package skills

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestLoadSkillPrd(t *testing.T) {
	content, err := LoadSkill("prd")
	if err != nil {
		t.Fatalf("LoadSkill(prd) error = %v", err)
	}
	if content == "" {
		t.Fatal("prd skill content should not be empty")
	}
}

func TestInstallSkillsCreatesManagedSkills(t *testing.T) {
	projectDir := t.TempDir()

	if err := InstallSkills(projectDir); err != nil {
		t.Fatalf("InstallSkills() error = %v", err)
	}

	for _, name := range ManagedSkillNames {
		path := filepath.Join(projectDir, template.HalDir, "skills", name, "SKILL.md")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected managed skill %s to be installed: %v", name, err)
		}
	}
}

func TestLinkAllEnginesPreservesCustomSkillLink(t *testing.T) {
	projectDir := t.TempDir()

	// Create a custom user-managed skill (e.g. a project-local browser tool).
	customSkillName := "my-browser-tool"
	customTarget := filepath.Join(projectDir, template.HalDir, "skills", customSkillName)
	if err := os.MkdirAll(customTarget, 0755); err != nil {
		t.Fatalf("failed to create custom skill target: %v", err)
	}
	customSkillPath := filepath.Join(customTarget, "SKILL.md")
	if err := os.WriteFile(customSkillPath, []byte("custom browser tool"), 0644); err != nil {
		t.Fatalf("failed to write custom skill: %v", err)
	}

	linker := &testSkillDirLinker{skillsDir: ".pi/skills"}
	linkPath := filepath.Join(projectDir, linker.skillsDir, customSkillName)
	if err := os.MkdirAll(filepath.Dir(linkPath), 0755); err != nil {
		t.Fatalf("failed to create skills dir: %v", err)
	}
	if err := os.Symlink(filepath.Join("..", "..", template.HalDir, "skills", customSkillName), linkPath); err != nil {
		t.Fatalf("failed to create custom skill symlink: %v", err)
	}

	originalLinkers := linkers
	linkers = map[string]EngineLinker{linker.Name(): linker}
	t.Cleanup(func() {
		linkers = originalLinkers
	})

	if err := LinkAllEngines(projectDir); err != nil {
		t.Fatalf("LinkAllEngines() error = %v", err)
	}

	// Custom link should be preserved.
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("custom skill link should be preserved: %v", err)
	}
	if target != filepath.Join("..", "..", template.HalDir, "skills", customSkillName) {
		t.Fatalf("custom skill link target changed: %s", target)
	}

	data, err := os.ReadFile(customSkillPath)
	if err != nil {
		t.Fatalf("custom skill should remain readable: %v", err)
	}
	if string(data) != "custom browser tool" {
		t.Fatalf("custom skill should be preserved, got: %s", string(data))
	}
}

type testSkillDirLinker struct {
	skillsDir string
}

func (t *testSkillDirLinker) Name() string {
	return "test"
}

func (t *testSkillDirLinker) SkillsDir() string {
	return t.skillsDir
}

func (t *testSkillDirLinker) CommandsDir() string {
	return ""
}

func (t *testSkillDirLinker) Link(projectDir string, skills []string) error {
	skillsDir := filepath.Join(projectDir, t.skillsDir)
	if err := os.MkdirAll(skillsDir, 0755); err != nil {
		return err
	}

	for _, skill := range skills {
		target := filepath.Join("..", "..", template.HalDir, "skills", skill)
		link := filepath.Join(skillsDir, skill)

		if err := os.RemoveAll(link); err != nil {
			return err
		}
		if err := os.Symlink(target, link); err != nil {
			return err
		}
	}

	return nil
}

func (t *testSkillDirLinker) LinkCommands(projectDir string) error {
	return nil
}

func (t *testSkillDirLinker) Unlink(projectDir string) error {
	return nil
}
