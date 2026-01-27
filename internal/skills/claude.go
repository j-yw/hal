package skills

import (
	"os"
	"path/filepath"
)

// ClaudeLinker creates symlinks for Claude Code skill discovery.
type ClaudeLinker struct{}

func init() {
	RegisterLinker(&ClaudeLinker{})
}

// Name returns the engine identifier.
func (c *ClaudeLinker) Name() string {
	return "claude"
}

// SkillsDir returns where Claude Code looks for skills.
func (c *ClaudeLinker) SkillsDir() string {
	return ".claude/skills"
}

// Link creates symlinks from .claude/skills/ to .goralph/skills/.
func (c *ClaudeLinker) Link(projectDir string, skills []string) error {
	skillsDir := filepath.Join(projectDir, c.SkillsDir())
	if err := os.MkdirAll(skillsDir, 0755); err != nil {
		return err
	}

	for _, skill := range skills {
		// Use relative path for symlink (portable across machines)
		target := filepath.Join("..", "..", ".goralph", "skills", skill)
		link := filepath.Join(skillsDir, skill)

		// Remove existing link/dir if present
		os.RemoveAll(link)

		if err := os.Symlink(target, link); err != nil {
			return err
		}
	}

	return nil
}

// Unlink removes skill symlinks from .claude/skills/.
func (c *ClaudeLinker) Unlink(projectDir string) error {
	skillsDir := filepath.Join(projectDir, c.SkillsDir())

	for _, skill := range SkillNames {
		link := filepath.Join(skillsDir, skill)
		os.RemoveAll(link)
	}

	return nil
}
