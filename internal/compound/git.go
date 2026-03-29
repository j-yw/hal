package compound

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// EnsureBranchInDir ensures branchName is checked out in dir.
// Behavior is idempotent across retries:
//   - If already on branchName: no-op success
//   - If local branch exists: checkout existing branch
//   - If local branch is missing: create from baseBranch (or current HEAD when empty)
func EnsureBranchInDir(dir, branchName, baseBranch string) error {
	branchName = strings.TrimSpace(branchName)
	baseBranch = strings.TrimSpace(baseBranch)
	if branchName == "" {
		return fmt.Errorf("branch name must not be empty")
	}

	currentBranch, err := CurrentBranchOptionalInDir(dir)
	if err != nil {
		return fmt.Errorf("failed to determine current branch: %w", err)
	}
	if currentBranch == branchName {
		return nil
	}

	exists, err := localBranchExistsInDir(dir, branchName)
	if err != nil {
		return err
	}
	if exists {
		if err := checkoutBranchInDir(dir, branchName); err != nil {
			return err
		}
		return nil
	}

	return createBranchInDir(dir, branchName, baseBranch)
}

// CreateBranch creates and checks out a new branch from baseBranch.
// If baseBranch is empty, git uses the current HEAD.
func CreateBranch(branchName, baseBranch string) error {
	return createBranchInDir("", branchName, baseBranch)
}

func createBranchInDir(dir, branchName, baseBranch string) error {
	args := []string{"checkout", "-b", branchName}
	if baseBranch != "" {
		args = append(args, baseBranch)
	}

	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
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

func checkoutBranchInDir(dir, branchName string) error {
	cmd := exec.Command("git", "checkout", branchName)
	if dir != "" {
		cmd.Dir = dir
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to checkout branch %q: %w (stderr: %s)", branchName, err, stderr.String())
	}
	return nil
}

func localBranchExistsInDir(dir, branchName string) (bool, error) {
	cmd := exec.Command("git", "show-ref", "--verify", "--quiet", "refs/heads/"+branchName)
	if dir != "" {
		cmd.Dir = dir
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("failed to check branch %q existence: %w (stderr: %s)", branchName, err, stderr.String())
	}

	return true, nil
}

// CurrentBranch returns the name of the current git branch.
// Returns an error when HEAD is detached.
func CurrentBranch() (string, error) {
	return CurrentBranchInDir("")
}

// CurrentBranchInDir returns the current branch in the given directory.
// Returns an error when HEAD is detached.
func CurrentBranchInDir(dir string) (string, error) {
	branch, err := currentBranchInDir(dir)
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
	return CurrentBranchOptionalInDir("")
}

// CurrentBranchOptionalInDir returns the current branch in the given directory.
// Returns an empty branch with nil error when HEAD is detached.
func CurrentBranchOptionalInDir(dir string) (string, error) {
	return currentBranchInDir(dir)
}

func currentBranchInDir(dir string) (string, error) {
	cmd := exec.Command("git", "branch", "--show-current")
	if dir != "" {
		cmd.Dir = dir
	}
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
