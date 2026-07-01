package worktree

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	DefaultRoot         = ".worktrees/hal-runs"
	DefaultBranchPrefix = "hal/runs"
)

var (
	ErrBranchExists       = errors.New("worker branch already exists")
	ErrDirtyRepository    = errors.New("canonical repository has uncommitted changes")
	ErrInvalidConfig      = errors.New("invalid worktree manager configuration")
	ErrInvalidRequest     = errors.New("invalid worktree request")
	ErrNotGitWorktree     = errors.New("canonical repository is not a git worktree")
	ErrWorktreePathExists = errors.New("worker worktree path already exists")
)

// GitRunner executes git commands in a repository-local working directory.
// Tests can replace it to validate command sequencing without spawning git.
type GitRunner interface {
	Run(ctx context.Context, dir string, args ...string) (string, error)
}

// ExecGitRunner executes git through os/exec.
type ExecGitRunner struct{}

func (ExecGitRunner) Run(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg != "" {
			return "", fmt.Errorf("git %s failed: %w: %s", strings.Join(args, " "), err, msg)
		}
		return "", fmt.Errorf("git %s failed: %w", strings.Join(args, " "), err)
	}
	return stdout.String(), nil
}

// Manager owns local worker branch and worktree lifecycle for one canonical
// repository.
type Manager struct {
	repoPath     string
	worktreeRoot string
	branchPrefix string
	git          GitRunner
}

type Config struct {
	RepoPath     string
	WorktreeRoot string
	BranchPrefix string
	Git          GitRunner
}

func NewManager(config Config) *Manager {
	root := strings.TrimSpace(config.WorktreeRoot)
	if root == "" {
		root = DefaultRoot
	}
	prefix := strings.Trim(strings.TrimSpace(config.BranchPrefix), "/")
	if prefix == "" {
		prefix = DefaultBranchPrefix
	}
	git := config.Git
	if git == nil {
		git = ExecGitRunner{}
	}
	return &Manager{
		repoPath:     strings.TrimSpace(config.RepoPath),
		worktreeRoot: root,
		branchPrefix: prefix,
		git:          git,
	}
}

type CreateRequest struct {
	RunID      string
	TaskID     string
	BaseRef    string
	BranchName string
	AllowDirty bool
}

type CreateResult struct {
	RepoPath     string
	WorktreeRoot string
	WorktreePath string
	BranchName   string
	BaseRef      string
}

func (m *Manager) Create(ctx context.Context, request CreateRequest) (CreateResult, error) {
	repoPath, err := m.canonicalRepoPath(ctx)
	if err != nil {
		return CreateResult{}, err
	}
	rootPath, err := m.rootPath(repoPath)
	if err != nil {
		return CreateResult{}, err
	}
	branchName, err := m.branchName(ctx, repoPath, request)
	if err != nil {
		return CreateResult{}, err
	}
	worktreePath, err := workerPath(rootPath, request.RunID, request.TaskID)
	if err != nil {
		return CreateResult{}, err
	}
	baseRef := strings.TrimSpace(request.BaseRef)
	if baseRef == "" {
		return CreateResult{}, fmt.Errorf("%w: base ref is required", ErrInvalidRequest)
	}

	if _, err := m.EnsureRootExcluded(ctx); err != nil {
		return CreateResult{}, err
	}
	if !request.AllowDirty {
		if err := m.requireClean(ctx, repoPath); err != nil {
			return CreateResult{}, err
		}
	}
	if err := m.requireBaseRef(ctx, repoPath, baseRef); err != nil {
		return CreateResult{}, err
	}
	if exists, err := m.localBranchExists(ctx, repoPath, branchName); err != nil {
		return CreateResult{}, err
	} else if exists {
		return CreateResult{}, fmt.Errorf("%w: %q", ErrBranchExists, branchName)
	}
	if err := requirePathAvailable(worktreePath); err != nil {
		return CreateResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(worktreePath), 0o755); err != nil {
		return CreateResult{}, fmt.Errorf("create worker worktree parent: %w", err)
	}

	if _, err := m.git.Run(ctx, repoPath, "worktree", "add", "-b", branchName, worktreePath, baseRef); err != nil {
		return CreateResult{}, fmt.Errorf("create worker worktree %q on branch %q from %q: %w", worktreePath, branchName, baseRef, err)
	}

	return CreateResult{
		RepoPath:     repoPath,
		WorktreeRoot: rootPath,
		WorktreePath: worktreePath,
		BranchName:   branchName,
		BaseRef:      baseRef,
	}, nil
}

type ExcludeResult struct {
	RepoPath    string
	ExcludePath string
	Pattern     string
	Changed     bool
}

func (m *Manager) EnsureRootExcluded(ctx context.Context) (ExcludeResult, error) {
	repoPath, err := m.canonicalRepoPath(ctx)
	if err != nil {
		return ExcludeResult{}, err
	}
	rootPath, err := m.rootPath(repoPath)
	if err != nil {
		return ExcludeResult{}, err
	}
	pattern, err := excludePattern(repoPath, rootPath)
	if err != nil {
		return ExcludeResult{}, err
	}
	excludePath, err := m.gitPath(ctx, repoPath, "info/exclude")
	if err != nil {
		return ExcludeResult{}, err
	}

	content, err := os.ReadFile(excludePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ExcludeResult{}, fmt.Errorf("read git local exclude: %w", err)
	}
	if hasExcludePattern(content, pattern) {
		return ExcludeResult{
			RepoPath:    repoPath,
			ExcludePath: excludePath,
			Pattern:     pattern,
			Changed:     false,
		}, nil
	}
	if err := os.MkdirAll(filepath.Dir(excludePath), 0o755); err != nil {
		return ExcludeResult{}, fmt.Errorf("create git local exclude parent: %w", err)
	}
	next := appendExcludePattern(content, pattern)
	if err := os.WriteFile(excludePath, next, 0o644); err != nil {
		return ExcludeResult{}, fmt.Errorf("write git local exclude: %w", err)
	}
	return ExcludeResult{
		RepoPath:    repoPath,
		ExcludePath: excludePath,
		Pattern:     pattern,
		Changed:     true,
	}, nil
}

type CleanupRequest struct {
	RunID          string
	TaskID         string
	WorktreePath   string
	BranchName     string
	Failed         bool
	PreserveFailed bool
	RemoveBranch   bool
	Force          bool
}

type CleanupResult struct {
	WorktreePath  string
	BranchName    string
	Removed       bool
	Preserved     bool
	BranchRemoved bool
}

func (m *Manager) Cleanup(ctx context.Context, request CleanupRequest) (CleanupResult, error) {
	repoPath, err := m.canonicalRepoPath(ctx)
	if err != nil {
		return CleanupResult{}, err
	}
	worktreePath := strings.TrimSpace(request.WorktreePath)
	if worktreePath == "" {
		rootPath, err := m.rootPath(repoPath)
		if err != nil {
			return CleanupResult{}, err
		}
		worktreePath, err = workerPath(rootPath, request.RunID, request.TaskID)
		if err != nil {
			return CleanupResult{}, err
		}
	}
	if !filepath.IsAbs(worktreePath) {
		worktreePath, err = filepath.Abs(worktreePath)
		if err != nil {
			return CleanupResult{}, fmt.Errorf("resolve worker worktree path: %w", err)
		}
	}

	result := CleanupResult{
		WorktreePath: worktreePath,
		BranchName:   strings.TrimSpace(request.BranchName),
	}
	if request.Failed && request.PreserveFailed {
		result.Preserved = true
		return result, nil
	}

	if _, err := os.Stat(worktreePath); err == nil {
		args := []string{"worktree", "remove"}
		if request.Force {
			args = append(args, "--force")
		}
		args = append(args, worktreePath)
		if _, err := m.git.Run(ctx, repoPath, args...); err != nil {
			return result, fmt.Errorf("remove worker worktree %q: %w", worktreePath, err)
		}
		result.Removed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, fmt.Errorf("inspect worker worktree %q: %w", worktreePath, err)
	}

	if request.RemoveBranch && result.BranchName != "" {
		flag := "-d"
		if request.Force {
			flag = "-D"
		}
		if _, err := m.git.Run(ctx, repoPath, "branch", flag, result.BranchName); err != nil {
			return result, fmt.Errorf("remove worker branch %q: %w", result.BranchName, err)
		}
		result.BranchRemoved = true
	}
	return result, nil
}

func (m *Manager) canonicalRepoPath(ctx context.Context) (string, error) {
	repoPath := m.repoPath
	if repoPath == "" {
		repoPath = "."
	}
	absRepo, err := filepath.Abs(repoPath)
	if err != nil {
		return "", fmt.Errorf("%w: resolve repo path: %w", ErrInvalidConfig, err)
	}
	inside, err := m.git.Run(ctx, absRepo, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(inside) != "true" {
		return "", fmt.Errorf("%w: %q", ErrNotGitWorktree, absRepo)
	}
	root, err := m.git.Run(ctx, absRepo, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("resolve canonical repository root: %w", err)
	}
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("%w: git returned an empty repository root", ErrNotGitWorktree)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve canonical repository root: %w", err)
	}
	return filepath.Clean(absRoot), nil
}

func (m *Manager) rootPath(repoPath string) (string, error) {
	root := strings.TrimSpace(m.worktreeRoot)
	if root == "" {
		root = DefaultRoot
	}
	if !filepath.IsAbs(root) {
		root = filepath.Join(repoPath, root)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("%w: resolve worktree root: %w", ErrInvalidConfig, err)
	}
	return filepath.Clean(absRoot), nil
}

func (m *Manager) branchName(ctx context.Context, repoPath string, request CreateRequest) (string, error) {
	branch := strings.Trim(strings.TrimSpace(request.BranchName), "/")
	if branch == "" {
		runID, err := validatePathSegment("run ID", request.RunID)
		if err != nil {
			return "", err
		}
		taskID, err := validatePathSegment("task ID", request.TaskID)
		if err != nil {
			return "", err
		}
		branch = strings.Trim(m.branchPrefix, "/") + "/" + runID + "/" + taskID
	}
	if _, err := m.git.Run(ctx, repoPath, "check-ref-format", "refs/heads/"+branch); err != nil {
		return "", fmt.Errorf("%w: invalid worker branch %q: %w", ErrInvalidRequest, branch, err)
	}
	return branch, nil
}

func (m *Manager) requireClean(ctx context.Context, repoPath string) error {
	status, err := m.git.Run(ctx, repoPath, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return fmt.Errorf("read canonical repository status: %w", err)
	}
	if strings.TrimSpace(status) == "" {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrDirtyRepository, summarizeStatus(status))
}

func (m *Manager) requireBaseRef(ctx context.Context, repoPath, baseRef string) error {
	if _, err := m.git.Run(ctx, repoPath, "rev-parse", "--verify", baseRef+"^{commit}"); err != nil {
		return fmt.Errorf("%w: base ref %q does not resolve to a commit: %w", ErrInvalidRequest, baseRef, err)
	}
	return nil
}

func (m *Manager) localBranchExists(ctx context.Context, repoPath, branchName string) (bool, error) {
	_, err := m.git.Run(ctx, repoPath, "show-ref", "--verify", "--quiet", "refs/heads/"+branchName)
	if err == nil {
		return true, nil
	}
	if isExitCode(err, 1) {
		return false, nil
	}
	return false, fmt.Errorf("check worker branch collision for %q: %w", branchName, err)
}

func isExitCode(err error, code int) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode() == code
	}
	return false
}

func (m *Manager) gitPath(ctx context.Context, repoPath, path string) (string, error) {
	out, err := m.git.Run(ctx, repoPath, "rev-parse", "--git-path", path)
	if err != nil {
		return "", fmt.Errorf("resolve git path %q: %w", path, err)
	}
	gitPath := strings.TrimSpace(out)
	if gitPath == "" {
		return "", fmt.Errorf("resolve git path %q: empty path", path)
	}
	if !filepath.IsAbs(gitPath) {
		gitPath = filepath.Join(repoPath, gitPath)
	}
	return filepath.Clean(gitPath), nil
}

func workerPath(rootPath, runID, taskID string) (string, error) {
	run, err := validatePathSegment("run ID", runID)
	if err != nil {
		return "", err
	}
	task, err := validatePathSegment("task ID", taskID)
	if err != nil {
		return "", err
	}
	return filepath.Join(rootPath, run, task), nil
}

func validatePathSegment(label, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: %s is required", ErrInvalidRequest, label)
	}
	if value == "." || value == ".." || strings.ContainsAny(value, `/\`) {
		return "", fmt.Errorf("%w: %s %q must be a single path segment", ErrInvalidRequest, label, value)
	}
	return value, nil
}

func requirePathAvailable(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: %q", ErrWorktreePathExists, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect worker worktree path %q: %w", path, err)
	}
	return nil
}

func excludePattern(repoPath, rootPath string) (string, error) {
	rel, err := filepath.Rel(repoPath, rootPath)
	if err != nil {
		return "", fmt.Errorf("resolve worktree root relative to repository: %w", err)
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	if rel == "." || strings.HasPrefix(rel, "../") || rel == ".." {
		return "", fmt.Errorf("%w: worktree root %q must be inside canonical repository %q to be locally excluded", ErrInvalidConfig, rootPath, repoPath)
	}
	if rel == ".worktrees" || strings.HasPrefix(rel, ".worktrees/") {
		return ".worktrees/", nil
	}
	return strings.TrimSuffix(rel, "/") + "/", nil
}

func hasExcludePattern(content []byte, pattern string) bool {
	for _, line := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(line) == pattern {
			return true
		}
	}
	return false
}

func appendExcludePattern(content []byte, pattern string) []byte {
	next := append([]byte(nil), content...)
	if len(next) > 0 && next[len(next)-1] != '\n' {
		next = append(next, '\n')
	}
	next = append(next, []byte(pattern+"\n")...)
	return next
}

func summarizeStatus(status string) string {
	lines := strings.Split(strings.TrimSpace(status), "\n")
	const maxLines = 5
	if len(lines) > maxLines {
		lines = append(lines[:maxLines], fmt.Sprintf("... and %d more", len(lines)-maxLines))
	}
	return strings.Join(lines, "; ")
}
