package sandbox

import "strings"

// SandboxNameFromBranch derives a sandbox name from a git branch name.
// Slashes are replaced with hyphens (e.g., "hal/feature-auth" becomes "hal-feature-auth").
func SandboxNameFromBranch(branch string) string {
	branch = strings.TrimSpace(branch)
	replacer := strings.NewReplacer("/", "-", "\\", "-")
	return replacer.Replace(branch)
}
