package skills

import (
	"embed"

	"github.com/jywlabs/hal/internal/template"
)

//go:embed hal prd autospec explode review review-loop hal-pinchtab
var skillsFS embed.FS

// ManagedSkillNames lists the Hal-owned skill names safe to link into engine skill directories.
var ManagedSkillNames = []string{"prd", "hal", "autospec", "explode", "review", "review-loop", template.BrowserVerificationSkillName}

//go:embed commands/discover-standards.md commands/index-standards.md commands/inject-standards.md
var commandsFS embed.FS

// CommandNames returns the list of available command names.
var CommandNames = []string{"discover-standards", "index-standards", "inject-standards"}
