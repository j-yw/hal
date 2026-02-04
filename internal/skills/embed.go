package skills

import (
	_ "embed"
)

//go:embed prd/SKILL.md
var prdSkillContent string

//go:embed hal/SKILL.md
var halSkillContent string

//go:embed autospec/SKILL.md
var autospecSkillContent string

//go:embed explode/SKILL.md
var explodeSkillContent string

//go:embed review/SKILL.md
var reviewSkillContent string

// SkillContent holds embedded skill content by name.
var SkillContent = map[string]string{
	"prd":      prdSkillContent,
	"hal":      halSkillContent,
	"autospec": autospecSkillContent,
	"explode":  explodeSkillContent,
	"review":   reviewSkillContent,
}

// SkillNames returns the list of available skill names.
var SkillNames = []string{"prd", "hal", "autospec", "explode", "review"}
