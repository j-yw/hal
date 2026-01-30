package compound

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// CreateBranch creates and checks out a new branch from current HEAD.
func CreateBranch(branchName string) error {
	cmd := exec.Command("git", "checkout", "-b", branchName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create branch %q: %w (stderr: %s)", branchName, err, stderr.String())
	}
	return nil
}

// CurrentBranch returns the name of the current git branch.
func CurrentBranch() (string, error) {
	cmd := exec.Command("git", "branch", "--show-current")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to get current branch: %w (stderr: %s)", err, stderr.String())
	}

	branch := strings.TrimSpace(stdout.String())
	if branch == "" {
		return "", fmt.Errorf("not on a branch (possibly detached HEAD)")
	}
	return branch, nil
}

// PushBranch pushes the branch to the remote origin with upstream tracking.
func PushBranch(branchName string) error {
	cmd := exec.Command("git", "push", "-u", "origin", branchName)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to push branch %q: %w (stderr: %s)", branchName, err, stderr.String())
	}
	return nil
}

// CreatePR creates a draft pull request using the GitHub CLI.
// Returns the URL of the created PR.
func CreatePR(title, body, base string) (string, error) {
	args := []string{"pr", "create", "--draft", "--title", title, "--body", body}
	if base != "" {
		args = append(args, "--base", base)
	}

	cmd := exec.Command("gh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to create PR: %w (stderr: %s)", err, stderr.String())
	}

	prURL := strings.TrimSpace(stdout.String())
	return prURL, nil
}
