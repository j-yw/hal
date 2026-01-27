package skills

import (
	_ "embed"
)

//go:embed prd/SKILL.md
var prdSkillContent string

//go:embed ralph/SKILL.md
var ralphSkillContent string

// SkillContent holds embedded skill content by name.
var SkillContent = map[string]string{
	"prd":   prdSkillContent,
	"ralph": ralphSkillContent,
}

// SkillNames returns the list of available skill names.
var SkillNames = []string{"prd", "ralph"}
