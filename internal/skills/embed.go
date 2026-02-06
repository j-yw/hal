package skills

import "embed"

//go:embed hal prd autospec explode review
var skillsFS embed.FS

// SkillNames returns the list of available skill names.
var SkillNames = []string{"prd", "hal", "autospec", "explode", "review"}
