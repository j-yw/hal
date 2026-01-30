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

// SkillContent holds embedded skill content by name.
var SkillContent = map[string]string{
	"prd":      prdSkillContent,
	"ralph":    ralphSkillContent,
	"autospec": autospecSkillContent,
}

// SkillNames returns the list of available skill names.
var SkillNames = []string{"prd", "ralph", "autospec"}
