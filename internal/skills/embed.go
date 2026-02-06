package skills

import "embed"

//go:embed hal prd autospec explode review
var skillsFS embed.FS

// SkillNames returns the list of available skill names.
var SkillNames = []string{"prd", "hal", "autospec", "explode", "review"}

//go:embed commands/discover-standards.md commands/index-standards.md commands/inject-standards.md
var commandsFS embed.FS

// CommandNames returns the list of available command names.
var CommandNames = []string{"discover-standards", "index-standards", "inject-standards"}
