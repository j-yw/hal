package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestLoadSkillHalPinchtab(t *testing.T) {
	content, err := LoadSkill(template.BrowserVerificationSkillName)
	if err != nil {
		t.Fatalf("LoadSkill(%s) error = %v", template.BrowserVerificationSkillName, err)
	}
	if !strings.Contains(content, "name: "+template.BrowserVerificationSkillName) {
		t.Fatalf("%s skill should contain frontmatter, got: %s", template.BrowserVerificationSkillName, content)
	}
}

func TestInstallSkillsIncludesHalPinchtab(t *testing.T) {
	projectDir := t.TempDir()

	if err := InstallSkills(projectDir); err != nil {
		t.Fatalf("InstallSkills() error = %v", err)
	}

	path := filepath.Join(projectDir, template.HalDir, "skills", template.BrowserVerificationSkillName, "SKILL.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected %s skill to be installed: %v", template.BrowserVerificationSkillName, err)
	}
	if !strings.Contains(string(data), "Pinchtab Browser Verification") {
		t.Fatalf("installed %s skill should contain instructions, got: %s", template.BrowserVerificationSkillName, string(data))
	}
}

func TestLinkAllEnginesPreservesProjectLocalPinchtabLink(t *testing.T) {
	projectDir := t.TempDir()
	managedTarget := filepath.Join(projectDir, template.HalDir, "skills", template.BrowserVerificationSkillName)
	if err := os.MkdirAll(managedTarget, 0755); err != nil {
		t.Fatalf("failed to create managed target: %v", err)
	}

	customTarget := filepath.Join(projectDir, template.HalDir, "skills", "pinchtab")
	if err := os.MkdirAll(customTarget, 0755); err != nil {
		t.Fatalf("failed to create custom pinchtab target: %v", err)
	}
	customSkillPath := filepath.Join(customTarget, "SKILL.md")
	if err := os.WriteFile(customSkillPath, []byte("custom pinchtab"), 0644); err != nil {
		t.Fatalf("failed to write custom pinchtab skill: %v", err)
	}

	linker := &testSkillDirLinker{skillsDir: ".pi/skills"}
	linkPath := filepath.Join(projectDir, linker.skillsDir, "pinchtab")
	if err := os.MkdirAll(filepath.Dir(linkPath), 0755); err != nil {
		t.Fatalf("failed to create skills dir: %v", err)
	}
	if err := os.Symlink(filepath.Join("..", "..", template.HalDir, "skills", "pinchtab"), linkPath); err != nil {
		t.Fatalf("failed to create custom pinchtab symlink: %v", err)
	}

	originalLinkers := linkers
	linkers = map[string]EngineLinker{linker.Name(): linker}
	t.Cleanup(func() {
		linkers = originalLinkers
	})

	if err := LinkAllEngines(projectDir); err != nil {
		t.Fatalf("LinkAllEngines() error = %v", err)
	}

	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("custom pinchtab link should be preserved: %v", err)
	}
	if target != filepath.Join("..", "..", template.HalDir, "skills", "pinchtab") {
		t.Fatalf("custom pinchtab link target changed: %s", target)
	}

	data, err := os.ReadFile(customSkillPath)
	if err != nil {
		t.Fatalf("custom pinchtab skill should remain readable: %v", err)
	}
	if string(data) != "custom pinchtab" {
		t.Fatalf("custom pinchtab skill should be preserved, got: %s", string(data))
	}

	managedLinkPath := filepath.Join(projectDir, linker.skillsDir, template.BrowserVerificationSkillName)
	managedInfo, err := os.Lstat(managedLinkPath)
	if err != nil {
		t.Fatalf("managed %s link should be created: %v", template.BrowserVerificationSkillName, err)
	}
	if managedInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("managed %s entry should be a symlink", template.BrowserVerificationSkillName)
	}

	managedTargetLink, err := os.Readlink(managedLinkPath)
	if err != nil {
		t.Fatalf("managed %s link should be readable: %v", template.BrowserVerificationSkillName, err)
	}
	if managedTargetLink != filepath.Join("..", "..", template.HalDir, "skills", template.BrowserVerificationSkillName) {
		t.Fatalf("managed %s link target = %s", template.BrowserVerificationSkillName, managedTargetLink)
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
