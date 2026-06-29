package sandboxworkspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// GitCLIInspector inspects Git state using local Git commands only. It does not
// fetch, push, or contact remotes.
type GitCLIInspector struct{}

func (GitCLIInspector) InspectGit(ctx context.Context, projectDir string) (GitStatus, error) {
	inside, err := gitOutput(ctx, projectDir, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) {
			return GitStatus{}, err
		}
		return GitStatus{IsGitWorktree: false}, nil
	}
	if strings.TrimSpace(inside) != "true" {
		return GitStatus{IsGitWorktree: false}, nil
	}

	status := GitStatus{IsGitWorktree: true}
	rawStatus, err := gitOutput(ctx, projectDir, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return GitStatus{}, err
	}
	status.RawStatusLines = splitLines(rawStatus)
	status.Dirty = parsePorcelainDirty(rawStatus)

	status.Branch, _ = optionalGitOutput(ctx, projectDir, "branch", "--show-current")
	status.Upstream, _ = optionalGitOutput(ctx, projectDir, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
	status.UpstreamRef, _ = optionalGitOutput(ctx, projectDir, "rev-parse", "--symbolic-full-name", "@{upstream}")
	status.HeadRef, _ = optionalGitOutput(ctx, projectDir, "rev-parse", "HEAD")
	status.Repository = repositoryRemote(ctx, projectDir, status.Upstream)

	if strings.TrimSpace(status.Upstream) != "" {
		contained, err := gitMergeBaseIsAncestor(ctx, projectDir, "HEAD", "@{upstream}")
		if err != nil {
			return GitStatus{}, err
		}
		status.HeadContainedInUpstream = contained
	}

	return status, nil
}

func repositoryRemote(ctx context.Context, projectDir string, upstream string) string {
	if remote := upstreamRemote(upstream); remote != "" {
		if repo, err := optionalGitOutput(ctx, projectDir, "remote", "get-url", remote); err == nil && repo != "" {
			return repo
		}
	}
	repo, _ := optionalGitOutput(ctx, projectDir, "remote", "get-url", "origin")
	return repo
}

func upstreamRemote(upstream string) string {
	upstream = strings.TrimSpace(upstream)
	if upstream == "" || strings.HasPrefix(upstream, "refs/") {
		return ""
	}
	remote, _, ok := strings.Cut(upstream, "/")
	if !ok {
		return ""
	}
	return remote
}

func parsePorcelainDirty(raw string) DirtyState {
	var dirty DirtyState
	for _, line := range splitLines(raw) {
		if strings.HasPrefix(line, "??") {
			dirty.Untracked = true
			continue
		}
		if len(line) < 2 {
			continue
		}
		if line[0] != ' ' && line[0] != '?' {
			dirty.Staged = true
		}
		if line[1] != ' ' && line[1] != '?' {
			dirty.Unstaged = true
		}
	}
	return dirty
}

func splitLines(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\n")
}

func optionalGitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	out, err := gitOutput(ctx, dir, args...)
	if err != nil {
		return "", err
	}
	return out, nil
}

func gitMergeBaseIsAncestor(ctx context.Context, dir string, ancestor string, descendant string) (bool, error) {
	err := gitRun(ctx, dir, "merge-base", "--is-ancestor", ancestor, descendant)
	if err == nil {
		return true, nil
	}
	if exitCode(err) == 1 {
		return false, nil
	}
	return false, err
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", gitCommandError(args, stderr.String(), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func gitRun(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return gitCommandError(args, stderr.String(), err)
	}
	return nil
}

func gitCommandError(args []string, stderr string, err error) error {
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		return fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, detail)
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
