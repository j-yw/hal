package skills

import (
	_ "embed"
)

//go:embed prd/SKILL.md
var prdSkillContent string

//go:embed ralph/SKILL.md
var ralphSkillContent string

//go:embed autospec/SKILL.md
var autospecSkillContent string

//go:embed explode/SKILL.md
var explodeSkillContent string

// SkillContent holds embedded skill content by name.
var SkillContent = map[string]string{
	"prd":      prdSkillContent,
	"ralph":    ralphSkillContent,
	"autospec": autospecSkillContent,
	"explode":  explodeSkillContent,
}

// SkillNames returns the list of available skill names.
var SkillNames = []string{"prd", "ralph", "autospec", "explode"}
