package compound

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// CreateBranch creates and checks out a new branch from baseBranch.
// If baseBranch is empty, git uses the current HEAD.
func CreateBranch(branchName, baseBranch string) error {
	args := []string{"checkout", "-b", branchName}
	if baseBranch != "" {
		args = append(args, baseBranch)
	}

	cmd := exec.Command("git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if baseBranch != "" {
			return fmt.Errorf("failed to create branch %q from %q: %w (stderr: %s)", branchName, baseBranch, err, stderr.String())
		}
		return fmt.Errorf("failed to create branch %q: %w (stderr: %s)", branchName, err, stderr.String())
	}
	return nil
}

// CurrentBranch returns the name of the current git branch.
// Returns an error when HEAD is detached.
func CurrentBranch() (string, error) {
	branch, err := currentBranch()
	if err != nil {
		return "", err
	}
	if branch == "" {
		return "", fmt.Errorf("not on a branch (possibly detached HEAD)")
	}
	return branch, nil
}

// CurrentBranchOptional returns the current branch name.
// Returns an empty branch with nil error when HEAD is detached.
func CurrentBranchOptional() (string, error) {
	return currentBranch()
}

func currentBranch() (string, error) {
	cmd := exec.Command("git", "branch", "--show-current")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to get current branch: %w (stderr: %s)", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
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
func CreatePR(title, body, base, head string) (string, error) {
	args := []string{"pr", "create", "--draft", "--title", title, "--body", body}
	if base != "" {
		args = append(args, "--base", base)
	}
	if head != "" {
		args = append(args, "--head", head)
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
