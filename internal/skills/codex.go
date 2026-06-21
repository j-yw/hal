package skills

import (
	"os"
	"path/filepath"
)

var userHomeDir = os.UserHomeDir

// CodexLinker creates symlinks for Codex skill discovery.
// Codex uses global directories under the active Codex home.
type CodexLinker struct{}

func init() {
	RegisterLinker(&CodexLinker{})
}

// Name returns the engine identifier.
func (c *CodexLinker) Name() string {
	return "codex"
}

// codexHome returns the root directory for Codex global paths.
// It prefers $CODEX_HOME, then $HOME/.codex, then os.UserHomeDir()/.codex
// so callers share one path resolution contract.
func codexHome() string {
	if h := os.Getenv("CODEX_HOME"); h != "" {
		return h
	}
	if h := os.Getenv("HOME"); h != "" {
		return filepath.Join(h, ".codex")
	}
	home, _ := userHomeDir()
	return filepath.Join(home, ".codex")
}

// SkillsDir returns where Codex looks for skills.
// Unlike Claude (project-local), Codex uses the active Codex home.
func (c *CodexLinker) SkillsDir() string {
	return filepath.Join(codexHome(), "skills")
}

// CommandsDir returns where Codex looks for user-invocable commands.
// Uses the active Codex home, parallel to skills.
func (c *CodexLinker) CommandsDir() string {
	return filepath.Join(codexHome(), "commands", "hal")
}

// LinkCommands creates a symlink from Codex commands/hal to .hal/commands/.
// Uses absolute paths since the link target is outside the Codex home.
func (c *CodexLinker) LinkCommands(projectDir string) error {
	link := c.CommandsDir()

	absProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		return err
	}
	target := filepath.Join(absProjectDir, ".hal", "commands")

	// Skip if already correctly linked
	if existing, err := os.Readlink(link); err == nil && existing == target {
		return nil
	}

	os.RemoveAll(link)

	if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
		return err
	}

	return os.Symlink(target, link)
}

// Link creates symlinks from Codex skills to .hal/skills/.
// Uses absolute paths since the link target is outside the Codex home.
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
		target := filepath.Join(absProjectDir, ".hal", "skills", skill)
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

// Unlink removes skill and command symlinks from the active Codex home.
// Only removes links that point to this project.
func (c *CodexLinker) Unlink(projectDir string) error {
	absProjectDir, _ := filepath.Abs(projectDir)

	// Unlink skills
	skillsDir := c.SkillsDir()
	for _, skill := range ManagedSkillNames {
		link := filepath.Join(skillsDir, skill)
		target := filepath.Join(absProjectDir, ".hal", "skills", skill)

		if existing, err := os.Readlink(link); err == nil && existing == target {
			os.RemoveAll(link)
		}
	}

	// Unlink commands
	cmdLink := c.CommandsDir()
	cmdTarget := filepath.Join(absProjectDir, ".hal", "commands")
	if existing, err := os.Readlink(cmdLink); err == nil && existing == cmdTarget {
		os.RemoveAll(cmdLink)
	}

	return nil
}
