package skills

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// LoadSkill returns the embedded SKILL.md content for a skill by name.
func LoadSkill(name string) (string, error) {
	content, err := fs.ReadFile(skillsFS, name+"/SKILL.md")
	if err != nil {
		return "", fmt.Errorf("unknown skill: %s", name)
	}
	return string(content), nil
}

// InstallSkills writes embedded skills to .hal/skills/ directory.
// Existing files are preserved to keep user customizations.
func InstallSkills(projectDir string) error {
	skillsDir := filepath.Join(projectDir, ".hal", "skills")

	return fs.WalkDir(skillsFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}

		destPath := filepath.Join(skillsDir, path)

		if d.IsDir() {
			return os.MkdirAll(destPath, 0755)
		}

		// Preserve existing files (user customizations)
		if _, err := os.Stat(destPath); err == nil {
			return nil
		}

		content, err := fs.ReadFile(skillsFS, path)
		if err != nil {
			return fmt.Errorf("failed to read embedded file %s: %w", path, err)
		}

		return os.WriteFile(destPath, content, 0644)
	})
}

// LinkAllEngines creates skill links for all registered engines.
func LinkAllEngines(projectDir string) error {
	var lastErr error
	for _, linker := range linkers {
		if err := linker.Link(projectDir, SkillNames); err != nil {
			// Log warning but continue with other engines
			fmt.Fprintf(os.Stderr, "warning: failed to link skills for %s: %v\n", linker.Name(), err)
			lastErr = err
		}
	}
	return lastErr
}

// UnlinkAllEngines removes skill links for all registered engines.
func UnlinkAllEngines(projectDir string) error {
	var lastErr error
	for _, linker := range linkers {
		if err := linker.Unlink(projectDir); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
