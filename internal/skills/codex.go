package skills

import (
	"os"
	"path/filepath"
)

// CodexLinker creates symlinks for Codex skill discovery.
// Codex uses a global skills directory at ~/.codex/skills/.
type CodexLinker struct{}

func init() {
	RegisterLinker(&CodexLinker{})
}

// Name returns the engine identifier.
func (c *CodexLinker) Name() string {
	return "codex"
}

// SkillsDir returns where Codex looks for skills.
// Unlike Claude (project-local), Codex uses global ~/.codex/skills/.
func (c *CodexLinker) SkillsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".codex", "skills")
}

// Link creates symlinks from ~/.codex/skills/ to .goralph/skills/.
// Uses absolute paths since the link target is outside ~/.codex/.
func (c *CodexLinker) Link(projectDir string, skills []string) error {
	skillsDir := c.SkillsDir()
	if err := os.MkdirAll(skillsDir, 0755); err != nil {
		return err
	}

	for _, skill := range skills {
		// Absolute path required (can't use relative - different tree)
		absProjectDir, err := filepath.Abs(projectDir)
		if err != nil {
			return err
		}
		target := filepath.Join(absProjectDir, ".goralph", "skills", skill)
		link := filepath.Join(skillsDir, skill)

		// Skip if already correctly linked
		if existing, err := os.Readlink(link); err == nil && existing == target {
			continue
		}

		// Remove existing link/dir if present
		os.RemoveAll(link)

		if err := os.Symlink(target, link); err != nil {
			return err
		}
	}
	return nil
}

// Unlink removes skill symlinks from ~/.codex/skills/.
// Only removes links that point to this project.
func (c *CodexLinker) Unlink(projectDir string) error {
	skillsDir := c.SkillsDir()
	absProjectDir, _ := filepath.Abs(projectDir)

	for _, skill := range SkillNames {
		link := filepath.Join(skillsDir, skill)
		target := filepath.Join(absProjectDir, ".goralph", "skills", skill)

		// Only remove if this symlink points to our project
		if existing, err := os.Readlink(link); err == nil && existing == target {
			os.RemoveAll(link)
		}
	}
	return nil
}
