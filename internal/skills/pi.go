package skills

import (
	"os"
	"path/filepath"
)

// PiLinker creates symlinks for pi coding agent skill discovery.
type PiLinker struct{}

func init() {
	RegisterLinker(&PiLinker{})
}

// Name returns the engine identifier.
func (p *PiLinker) Name() string {
	return "pi"
}

// SkillsDir returns where pi looks for project-level skills.
func (p *PiLinker) SkillsDir() string {
	return ".pi/skills"
}

// Link creates symlinks from .pi/skills/ to .hal/skills/.
func (p *PiLinker) Link(projectDir string, skills []string) error {
	skillsDir := filepath.Join(projectDir, p.SkillsDir())
	if err := os.MkdirAll(skillsDir, 0755); err != nil {
		return err
	}

	for _, skill := range skills {
		// Use relative path for symlink (portable across machines)
		target := filepath.Join("..", "..", ".hal", "skills", skill)
		link := filepath.Join(skillsDir, skill)

		// Remove existing link/dir if present
		os.RemoveAll(link)

		if err := os.Symlink(target, link); err != nil {
			return err
		}
	}

	return nil
}

// Unlink removes skill symlinks from .pi/skills/.
func (p *PiLinker) Unlink(projectDir string) error {
	skillsDir := filepath.Join(projectDir, p.SkillsDir())

	for _, skill := range SkillNames {
		link := filepath.Join(skillsDir, skill)
		os.RemoveAll(link)
	}

	return nil
}
