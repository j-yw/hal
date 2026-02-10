package skills

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/template"
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

// CommandsDir returns where pi looks for prompt templates.
func (p *PiLinker) CommandsDir() string {
	return ".pi/prompts"
}

// LinkCommands creates symlinks from .pi/prompts/*.md to .hal/commands/*.md.
//
// Pi discovers templates non-recursively from .pi/prompts/*.md, so we link
// individual files instead of linking a subdirectory.
func (p *PiLinker) LinkCommands(projectDir string) error {
	promptsDir := filepath.Join(projectDir, p.CommandsDir())
	halCommandsDir := filepath.Join(projectDir, template.HalDir, template.CommandsDir)

	if err := os.MkdirAll(promptsDir, 0755); err != nil {
		return err
	}

	targets := map[string]string{}
	entries, err := os.ReadDir(halCommandsDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".md" {
				continue
			}
			targets[entry.Name()] = filepath.Join("..", "..", template.HalDir, template.CommandsDir, entry.Name())
		}
	}

	promptEntries, err := os.ReadDir(promptsDir)
	if err != nil {
		return err
	}

	// Remove stale managed links for prompts that are no longer hal commands.
	for _, entry := range promptEntries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".md" {
			continue
		}
		if _, ok := targets[entry.Name()]; ok {
			continue
		}

		link := filepath.Join(promptsDir, entry.Name())
		managed, err := isManagedPiPromptLink(projectDir, link)
		if err != nil {
			return err
		}
		if managed {
			if err := os.Remove(link); err != nil {
				return err
			}
		}
	}

	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		link := filepath.Join(promptsDir, name)
		target := targets[name]

		if info, err := os.Lstat(link); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				existingTarget, err := os.Readlink(link)
				if err == nil && existingTarget == target {
					continue
				}
			}
			// Managed command prompt names are hal-owned; replace stale files/symlinks.
			if err := os.RemoveAll(link); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}

		if err := os.Symlink(target, link); err != nil {
			return err
		}
	}

	// Remove legacy location from older hal versions.
	_ = os.RemoveAll(filepath.Join(projectDir, ".pi", "commands", "hal"))

	return nil
}

// Link creates symlinks from .pi/skills/ to .hal/skills/.
func (p *PiLinker) Link(projectDir string, skills []string) error {
	skillsDir := filepath.Join(projectDir, p.SkillsDir())
	if err := os.MkdirAll(skillsDir, 0755); err != nil {
		return err
	}

	for _, skill := range skills {
		// Use relative path for symlink (portable across machines)
		target := filepath.Join("..", "..", template.HalDir, "skills", skill)
		link := filepath.Join(skillsDir, skill)

		// Remove existing link/dir if present
		os.RemoveAll(link)

		if err := os.Symlink(target, link); err != nil {
			return err
		}
	}

	return nil
}

// Unlink removes skill and command symlinks from .pi/.
func (p *PiLinker) Unlink(projectDir string) error {
	skillsDir := filepath.Join(projectDir, p.SkillsDir())

	for _, skill := range SkillNames {
		link := filepath.Join(skillsDir, skill)
		os.RemoveAll(link)
	}

	promptsDir := filepath.Join(projectDir, p.CommandsDir())
	entries, err := os.ReadDir(promptsDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".md" {
				continue
			}
			link := filepath.Join(promptsDir, entry.Name())
			managed, err := isManagedPiPromptLink(projectDir, link)
			if err != nil || !managed {
				continue
			}
			_ = os.Remove(link)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	// Remove legacy location from older hal versions.
	_ = os.RemoveAll(filepath.Join(projectDir, ".pi", "commands", "hal"))

	return nil
}

func isManagedPiPromptLink(projectDir, link string) (bool, error) {
	info, err := os.Lstat(link)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return false, nil
	}

	target, err := os.Readlink(link)
	if err != nil {
		return false, err
	}
	resolvedTarget := filepath.Clean(filepath.Join(filepath.Dir(link), target))
	managedDir := filepath.Clean(filepath.Join(projectDir, template.HalDir, template.CommandsDir))
	rel, err := filepath.Rel(managedDir, resolvedTarget)
	if err != nil {
		return false, nil
	}
	if rel == "." {
		return true, nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false, nil
	}
	return true, nil
}
