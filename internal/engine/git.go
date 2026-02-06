package engine

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// GetGitInfo returns the repo basename and current branch.
// Returns empty strings on any failure (git not installed, not a repo, etc).
func GetGitInfo() (repo, branch string) {
	// Get repo root
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", ""
	}
	repoRoot := strings.TrimSpace(string(out))
	if repoRoot != "" {
		repo = filepath.Base(repoRoot)
	}

	// Get current branch
	out, err = exec.Command("git", "branch", "--show-current").Output()
	if err != nil {
		return repo, ""
	}
	branch = strings.TrimSpace(string(out))

	return repo, branch
}
