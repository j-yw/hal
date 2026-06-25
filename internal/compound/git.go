package compound

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

var readWorkingTreeStatusInDir = defaultReadWorkingTreeStatusInDir

func defaultReadWorkingTreeStatusInDir(dir string) (string, error) {
	cmd := exec.Command("git", "status", "--porcelain", "--untracked-files=all")
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// WorkingTreeChangesInDir returns sorted unique changed paths from git porcelain status.
func WorkingTreeChangesInDir(dir string) ([]string, error) {
	out, err := readWorkingTreeStatusInDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read git working tree status: %w", err)
	}
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}

	lines := strings.Split(out, "\n")
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		if path := parsePorcelainPath(line); path != "" {
			paths = append(paths, path)
		}
	}
	return uniqueSortedPaths(paths), nil
}

// WorkingTreeSnapshotInDir returns a comparable snapshot of HEAD, tracked
// changes, and untracked file contents for mutation detection.
func WorkingTreeSnapshotInDir(dir string) (string, error) {
	head, err := gitCommandOutputInDir(dir, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("read git HEAD: %w", err)
	}
	status, err := gitCommandOutputInDir(dir, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return "", fmt.Errorf("read git working tree status: %w", err)
	}
	diff, err := gitCommandOutputInDir(dir, "diff", "--binary", "HEAD", "--")
	if err != nil {
		return "", fmt.Errorf("read git working tree diff: %w", err)
	}
	untracked, err := gitCommandOutputInDir(dir, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return "", fmt.Errorf("list untracked files: %w", err)
	}
	untrackedHashes, err := hashUntrackedFilesInDir(dir, untracked)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{
		"HEAD\x00" + head,
		"STATUS\x00" + status,
		"DIFF\x00" + diff,
		"UNTRACKED\x00" + untrackedHashes,
	}, "\x00SECTION\x00"), nil
}

func gitCommandOutputInDir(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s failed: %w (stderr: %s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func hashUntrackedFilesInDir(dir, gitOutput string) (string, error) {
	paths := splitNULFields(gitOutput)
	sort.Strings(paths)

	var sb strings.Builder
	for _, path := range paths {
		fullPath := path
		if strings.TrimSpace(dir) != "" {
			fullPath = filepath.Join(dir, path)
		}
		info, err := os.Lstat(fullPath)
		if err != nil {
			return "", fmt.Errorf("inspect untracked file %q: %w", path, err)
		}
		if info.IsDir() {
			continue
		}

		sb.WriteString(path)
		sb.WriteByte('\x00')
		sb.WriteString(info.Mode().String())
		sb.WriteByte('\x00')
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(fullPath)
			if err != nil {
				return "", fmt.Errorf("read untracked symlink %q: %w", path, err)
			}
			sum := sha256.Sum256([]byte(target))
			sb.WriteString("symlink:")
			sb.WriteString(fmt.Sprintf("%x", sum))
			sb.WriteByte('\x00')
			continue
		}

		content, err := os.ReadFile(fullPath)
		if err != nil {
			return "", fmt.Errorf("read untracked file %q: %w", path, err)
		}
		sum := sha256.Sum256(content)
		sb.WriteString("file:")
		sb.WriteString(fmt.Sprintf("%x", sum))
		sb.WriteByte('\x00')
	}
	return sb.String(), nil
}

func splitNULFields(output string) []string {
	parts := strings.Split(output, "\x00")
	fields := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			fields = append(fields, part)
		}
	}
	return fields
}

func defaultGitAddAllInDir(ctx context.Context, dir string) error {
	return GitAddAllInDir(ctx, dir)
}

func defaultGitCommitInDir(ctx context.Context, dir, message string) error {
	return GitCommitInDir(ctx, dir, message)
}

// GitAddAllInDir stages all working tree changes in the given repository.
func GitAddAllInDir(ctx context.Context, dir string) error {
	cmd := exec.CommandContext(ctx, "git", "add", "-A")
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

// GitCommitInDir creates a commit in the given repository.
func GitCommitInDir(ctx context.Context, dir, message string) error {
	cmd := exec.CommandContext(ctx, "git", "commit", "-m", message)
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

func parsePorcelainPath(line string) string {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" || len(line) < 3 {
		return ""
	}

	status := line[:2]
	path := strings.TrimSpace(line[3:])
	if path == "" {
		return ""
	}
	if isPorcelainRenameOrCopy(status) && strings.Contains(path, " -> ") {
		parts := strings.SplitN(path, " -> ", 2)
		path = strings.TrimSpace(parts[1])
	}
	return strings.Trim(path, "\"")
}

func isPorcelainRenameOrCopy(status string) bool {
	if len(status) < 2 {
		return false
	}
	return status[0] == 'R' || status[0] == 'C' || status[1] == 'R' || status[1] == 'C'
}

func uniqueSortedPaths(paths []string) []string {
	set := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		set[path] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for path := range set {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

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
