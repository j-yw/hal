package skills

import (
	"fmt"
	"os"
	"path/filepath"
)

// LoadSkill returns the embedded content of a skill by name.
func LoadSkill(name string) (string, error) {
	content, ok := SkillContent[name]
	if !ok {
		return "", fmt.Errorf("unknown skill: %s", name)
	}
	return content, nil
}

// InstallSkills writes embedded skills to .goralph/skills/ directory.
// Existing skill files are preserved to keep user customizations.
func InstallSkills(projectDir string) error {
	skillsDir := filepath.Join(projectDir, ".goralph", "skills")

	for _, name := range SkillNames {
		content, err := LoadSkill(name)
		if err != nil {
			return err
		}

		dir := filepath.Join(skillsDir, name)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create skill directory %s: %w", name, err)
		}

		filePath := filepath.Join(dir, "SKILL.md")
		if _, err := os.Stat(filePath); err == nil {
			// File exists, preserve user customizations
			continue
		}
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write skill %s: %w", name, err)
		}
	}

	return nil
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
