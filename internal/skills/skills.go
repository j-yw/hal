package skills

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/template"
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

// InstallCommands writes embedded commands to .hal/commands/ directory.
// Commands are interactive tools users invoke directly in their agent.
// After installation, call LinkAllCommands to create engine-specific links.
func InstallCommands(projectDir string) error {
	commandsDir := filepath.Join(projectDir, template.HalDir, template.CommandsDir)
	if err := os.MkdirAll(commandsDir, 0755); err != nil {
		return fmt.Errorf("failed to create commands dir: %w", err)
	}

	for _, name := range CommandNames {
		srcPath := "commands/" + name + ".md"
		content, err := fs.ReadFile(commandsFS, srcPath)
		if err != nil {
			return fmt.Errorf("failed to read embedded command %s: %w", name, err)
		}

		destPath := filepath.Join(commandsDir, name+".md")
		// Always overwrite (commands are hal-managed, not user-customized)
		if err := os.WriteFile(destPath, content, 0644); err != nil {
			return fmt.Errorf("failed to write command %s: %w", name, err)
		}
	}

	return nil
}

// LinkAllCommands creates command links for all registered engines.
// Each engine gets a symlink from its commands directory to .hal/commands/.
func LinkAllCommands(projectDir string) error {
	var lastErr error
	for _, linker := range linkers {
		if err := linker.LinkCommands(projectDir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to link commands for %s: %v\n", linker.Name(), err)
			lastErr = err
		}
	}
	return lastErr
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
