package skills

import (
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/template"
)

// removeLegacyManagedSkillSymlinks prunes legacy managed skill links only when
// they point at this project's managed skill directory.
func removeLegacyManagedSkillSymlinks(skillsDir, projectDir string) error {
	absProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		return err
	}

	for _, skill := range legacyManagedSkillNames {
		link := filepath.Join(skillsDir, skill)
		target := filepath.Join(absProjectDir, template.HalDir, "skills", skill)
		info, err := os.Lstat(link)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		existing, err := os.Readlink(link)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		existingTarget := existing
		if !filepath.IsAbs(existingTarget) {
			existingTarget = filepath.Join(filepath.Dir(link), existingTarget)
		}
		existingTarget, err = filepath.Abs(existingTarget)
		if err != nil {
			return err
		}
		if filepath.Clean(existingTarget) == filepath.Clean(target) {
			if err := os.Remove(link); err != nil {
				return err
			}
		}
	}
	return nil
}
