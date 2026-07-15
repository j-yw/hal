package sandboxworkspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// GitCLIInspector inspects Git state and prepares bundles using local Git
// commands only. It does not fetch, push, or contact remotes.
type GitCLIInspector struct{}

var (
	absolutePathPattern     = regexp.MustCompile(`(^|[[:space:]'"])(/[^\s'"]+)`)
	unixEndpointPattern     = regexp.MustCompile(`(?i)\bunix://[^\s'";,]+`)
	urlUserInfoPattern      = regexp.MustCompile(`(?i)\b(https?://)[^/@\s]+@`)
	secretAssignmentPattern = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(TOKEN|SECRET|PASSWORD|API[_-]?KEY|AUTH)[A-Z0-9_]*)=([^;\s]+)`)
	commonSecretPattern     = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]+|tskey-[A-Za-z0-9_-]+)\b`)
)

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
	rawStatus, err := gitOutputUntrimmed(ctx, projectDir, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return GitStatus{}, err
	}
	status.RawStatusLines = splitPorcelainLines(rawStatus)
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

func (GitCLIInspector) CreateBundle(ctx context.Context, req CreateBundleRequest) (CreateBundleResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	plan := req.Plan
	projectDir := strings.TrimSpace(plan.ProjectDir)
	if projectDir == "" {
		return CreateBundleResult{}, fmt.Errorf("git bundle create failed: project directory is required")
	}
	destination := strings.TrimSpace(req.DestinationPath)
	if destination == "" {
		return CreateBundleResult{}, fmt.Errorf("git bundle create failed: destination path is required")
	}

	args := []string{"bundle", "create", destination}
	args = append(args, bundleCreateRevisions(plan)...)
	if err := gitRunSafe(ctx, projectDir, "git bundle create", args...); err != nil {
		return CreateBundleResult{}, err
	}

	syncRef := firstNonEmpty(plan.SyncRef, bundlePositiveRef(plan))
	return CreateBundleResult{
		Path:    destination,
		ID:      safeBundleSegment(syncRef),
		SyncRef: syncRef,
	}, nil
}

func (GitCLIInspector) VerifyBundle(ctx context.Context, req VerifyBundleRequest) error {
	if ctx == nil {
		ctx = context.Background()
	}
	projectDir := strings.TrimSpace(req.Plan.ProjectDir)
	if projectDir == "" {
		return fmt.Errorf("git bundle verify failed: project directory is required")
	}
	path := strings.TrimSpace(req.Path)
	if path == "" {
		return fmt.Errorf("git bundle verify failed: bundle path is required")
	}

	if err := gitRunSafe(ctx, projectDir, "git bundle verify", "bundle", "verify", path); err != nil {
		return err
	}
	heads, err := gitOutputSafe(ctx, projectDir, "git bundle list-heads", "bundle", "list-heads", path)
	if err != nil {
		return err
	}
	expected, err := plannedBundleCommit(ctx, req.Plan, req.SyncRef)
	if err != nil {
		return err
	}
	if !bundleHeadsContainCommit(heads, expected) {
		return fmt.Errorf("git bundle verify failed: bundle does not contain planned sync ref %q", safeBundleRef(firstNonEmpty(req.SyncRef, req.Plan.SyncRef, "HEAD")))
	}
	return nil
}

func bundleCreateRevisions(plan Plan) []string {
	return []string{bundlePositiveRef(plan)}
}

func bundlePositiveRef(plan Plan) string {
	if branch := strings.TrimSpace(plan.Branch); branch != "" {
		return branch
	}
	return "HEAD"
}

func plannedBundleCommit(ctx context.Context, plan Plan, syncRef string) (string, error) {
	ref := firstNonEmpty(syncRef, plan.SyncRef, bundlePositiveRef(plan))
	commit, err := gitOutputSafe(ctx, plan.ProjectDir, "git rev-parse", "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("git bundle verify failed: resolve planned sync ref %q: %w", safeBundleRef(ref), err)
	}
	return commit, nil
}

func bundleHeadsContainCommit(heads string, commit string) bool {
	commit = strings.TrimSpace(commit)
	if commit == "" {
		return false
	}
	for _, line := range splitLines(heads) {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == commit {
			return true
		}
	}
	return false
}

func safeBundleRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "HEAD"
	}
	return safeBundleSegment(ref)
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
	for _, line := range splitPorcelainLines(raw) {
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

func splitPorcelainLines(raw string) []string {
	raw = strings.TrimRight(raw, "\r\n")
	if raw == "" {
		return nil
	}
	lines := strings.Split(raw, "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
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

func gitOutputUntrimmed(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", gitCommandError(args, stderr.String(), err)
	}
	return stdout.String(), nil
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

func gitRunSafe(ctx context.Context, dir string, operation string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return gitSafeCommandError(operation, stderr.String(), err)
	}
	return nil
}

func gitOutputSafe(ctx context.Context, dir string, operation string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", gitSafeCommandError(operation, stderr.String(), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func gitCommandError(args []string, stderr string, err error) error {
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		return fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, detail)
}

func gitSafeCommandError(operation string, stderr string, err error) error {
	detail := sanitizeGitDetail(stderr)
	if detail == "" {
		return fmt.Errorf("%s failed: %w", operation, err)
	}
	return fmt.Errorf("%s failed: %w: %s", operation, err, detail)
}

func sanitizeGitDetail(stderr string) string {
	return sanitizePathDetail(stderr)
}

func sanitizePathDetail(raw string) string {
	detail := strings.Join(splitLines(raw), "; ")
	if detail == "" {
		return ""
	}
	detail = unixEndpointPattern.ReplaceAllString(detail, "local Unix socket")
	detail = urlUserInfoPattern.ReplaceAllString(detail, "${1}[redacted]@")
	detail = secretAssignmentPattern.ReplaceAllString(detail, "$1=[redacted]")
	detail = commonSecretPattern.ReplaceAllString(detail, "[redacted]")
	return absolutePathPattern.ReplaceAllString(detail, "${1}[path]")
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
