package skills

import (
	"embed"
)

//go:embed hal prd plan-product autospec factory explode review review-loop
var skillsFS embed.FS

// ManagedSkillNames lists the Hal-owned skill names safe to link into engine skill directories.
var ManagedSkillNames = []string{"prd", "hal", "plan-product", "autospec", "factory", "explode", "review", "review-loop"}

// legacyManagedSkillNames are previously-managed names retained for cleanup/migration only.
var legacyManagedSkillNames = []string{"product"}

//go:embed commands/discover-standards.md commands/index-standards.md commands/inject-standards.md
var commandsFS embed.FS

// CommandNames returns the list of available command names.
var CommandNames = []string{"discover-standards", "index-standards", "inject-standards"}
