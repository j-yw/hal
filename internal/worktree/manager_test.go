package worktree

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateCreatesWorkerBranchAndWorktree(t *testing.T) {
	ctx := context.Background()
	repo := initTempRepo(t)
	manager := NewManager(Config{RepoPath: repo})

	result, err := manager.Create(ctx, CreateRequest{
		RunID:   "run-1",
		TaskID:  "US-001",
		BaseRef: "main",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	wantPath := filepath.Join(repo, ".worktrees", "hal-runs", "run-1", "US-001")
	if result.WorktreePath != wantPath {
		t.Fatalf("WorktreePath = %q, want %q", result.WorktreePath, wantPath)
	}
	if result.BranchName != "hal/runs/run-1/US-001" {
		t.Fatalf("BranchName = %q", result.BranchName)
	}
	if _, err := os.Stat(filepath.Join(result.WorktreePath, "README.md")); err != nil {
		t.Fatalf("worker checkout missing README.md: %v", err)
	}
	if got := runGit(t, result.WorktreePath, "branch", "--show-current"); strings.TrimSpace(got) != result.BranchName {
		t.Fatalf("worker branch = %q, want %q", strings.TrimSpace(got), result.BranchName)
	}

	exclude := readFile(t, filepath.Join(repo, ".git", "info", "exclude"))
	if !strings.Contains(exclude, ".worktrees/\n") {
		t.Fatalf("local exclude does not contain .worktrees/: %q", exclude)
	}
	if _, err := os.Stat(filepath.Join(repo, ".gitignore")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Create() touched project .gitignore, stat error = %v", err)
	}
	if status := runGit(t, repo, "status", "--porcelain=v1", "--untracked-files=all"); strings.TrimSpace(status) != "" {
		t.Fatalf("canonical repo status after create = %q, want clean", status)
	}
}

func TestCreateRejectsDirtyRepoUnlessAllowed(t *testing.T) {
	ctx := context.Background()
	repo := initTempRepo(t)
	manager := NewManager(Config{RepoPath: repo})
	if _, err := manager.EnsureRootExcluded(ctx); err != nil {
		t.Fatalf("EnsureRootExcluded() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "dirty.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatalf("write dirty file: %v", err)
	}

	_, err := manager.Create(ctx, CreateRequest{
		RunID:   "run-1",
		TaskID:  "US-001",
		BaseRef: "main",
	})
	if !errors.Is(err, ErrDirtyRepository) {
		t.Fatalf("Create() error = %v, want ErrDirtyRepository", err)
	}

	result, err := manager.Create(ctx, CreateRequest{
		RunID:      "run-1",
		TaskID:     "US-002",
		BaseRef:    "main",
		AllowDirty: true,
	})
	if err != nil {
		t.Fatalf("Create(AllowDirty) error = %v", err)
	}
	if _, err := os.Stat(result.WorktreePath); err != nil {
		t.Fatalf("allowed dirty create did not create worktree: %v", err)
	}
}

func TestCreateReportsBranchCollision(t *testing.T) {
	ctx := context.Background()
	repo := initTempRepo(t)
	manager := NewManager(Config{RepoPath: repo})
	runGit(t, repo, "branch", "hal/runs/run-1/US-001", "main")

	_, err := manager.Create(ctx, CreateRequest{
		RunID:   "run-1",
		TaskID:  "US-001",
		BaseRef: "main",
	})
	if !errors.Is(err, ErrBranchExists) {
		t.Fatalf("Create() error = %v, want ErrBranchExists", err)
	}
}

func TestCreateReportsPathCollision(t *testing.T) {
	ctx := context.Background()
	repo := initTempRepo(t)
	manager := NewManager(Config{RepoPath: repo})
	path := filepath.Join(repo, ".worktrees", "hal-runs", "run-1", "US-001")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("create colliding path: %v", err)
	}

	_, err := manager.Create(ctx, CreateRequest{
		RunID:   "run-1",
		TaskID:  "US-001",
		BaseRef: "main",
	})
	if !errors.Is(err, ErrWorktreePathExists) {
		t.Fatalf("Create() error = %v, want ErrWorktreePathExists", err)
	}
}

func TestEnsureRootExcludedIsLocalAndIdempotent(t *testing.T) {
	ctx := context.Background()
	repo := initTempRepo(t)
	manager := NewManager(Config{
		RepoPath:     repo,
		WorktreeRoot: ".worktrees/custom",
	})

	first, err := manager.EnsureRootExcluded(ctx)
	if err != nil {
		t.Fatalf("EnsureRootExcluded() error = %v", err)
	}
	if !first.Changed {
		t.Fatalf("first EnsureRootExcluded().Changed = false, want true")
	}
	if first.Pattern != ".worktrees/" {
		t.Fatalf("Pattern = %q, want .worktrees/", first.Pattern)
	}
	second, err := manager.EnsureRootExcluded(ctx)
	if err != nil {
		t.Fatalf("second EnsureRootExcluded() error = %v", err)
	}
	if second.Changed {
		t.Fatalf("second EnsureRootExcluded().Changed = true, want false")
	}

	exclude := readFile(t, filepath.Join(repo, ".git", "info", "exclude"))
	if count := strings.Count(exclude, ".worktrees/"); count != 1 {
		t.Fatalf("exclude pattern count = %d, want 1; content %q", count, exclude)
	}
	if _, err := os.Stat(filepath.Join(repo, ".gitignore")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("EnsureRootExcluded() touched project .gitignore, stat error = %v", err)
	}
}

func TestEnsureRootExcludedUsesConfiguredRootOutsideDotWorktrees(t *testing.T) {
	ctx := context.Background()
	repo := initTempRepo(t)
	manager := NewManager(Config{
		RepoPath:     repo,
		WorktreeRoot: "hal-worker-trees",
	})

	result, err := manager.EnsureRootExcluded(ctx)
	if err != nil {
		t.Fatalf("EnsureRootExcluded() error = %v", err)
	}
	if result.Pattern != "hal-worker-trees/" {
		t.Fatalf("Pattern = %q, want hal-worker-trees/", result.Pattern)
	}
	exclude := readFile(t, filepath.Join(repo, ".git", "info", "exclude"))
	if !strings.Contains(exclude, "hal-worker-trees/\n") {
		t.Fatalf("local exclude does not contain configured root: %q", exclude)
	}
}

func TestCreateRejectsNonGitWorktree(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	manager := NewManager(Config{RepoPath: dir})

	_, err := manager.Create(ctx, CreateRequest{
		RunID:   "run-1",
		TaskID:  "US-001",
		BaseRef: "main",
	})
	if !errors.Is(err, ErrNotGitWorktree) {
		t.Fatalf("Create() error = %v, want ErrNotGitWorktree", err)
	}
}

func TestCleanupRemovesSuccessfulAndCanPreserveFailed(t *testing.T) {
	ctx := context.Background()
	repo := initTempRepo(t)
	manager := NewManager(Config{RepoPath: repo})

	success, err := manager.Create(ctx, CreateRequest{
		RunID:   "run-1",
		TaskID:  "US-001",
		BaseRef: "main",
	})
	if err != nil {
		t.Fatalf("Create(success) error = %v", err)
	}
	cleaned, err := manager.Cleanup(ctx, CleanupRequest{
		WorktreePath: success.WorktreePath,
		BranchName:   success.BranchName,
	})
	if err != nil {
		t.Fatalf("Cleanup(success) error = %v", err)
	}
	if !cleaned.Removed || cleaned.Preserved {
		t.Fatalf("Cleanup(success) = %+v, want removed and not preserved", cleaned)
	}
	if _, err := os.Stat(success.WorktreePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful worktree still exists, stat error = %v", err)
	}

	failed, err := manager.Create(ctx, CreateRequest{
		RunID:   "run-1",
		TaskID:  "US-002",
		BaseRef: "main",
	})
	if err != nil {
		t.Fatalf("Create(failed) error = %v", err)
	}
	preserved, err := manager.Cleanup(ctx, CleanupRequest{
		WorktreePath:   failed.WorktreePath,
		BranchName:     failed.BranchName,
		Failed:         true,
		PreserveFailed: true,
	})
	if err != nil {
		t.Fatalf("Cleanup(failed preserve) error = %v", err)
	}
	if !preserved.Preserved || preserved.Removed {
		t.Fatalf("Cleanup(failed preserve) = %+v, want preserved and not removed", preserved)
	}
	if _, err := os.Stat(failed.WorktreePath); err != nil {
		t.Fatalf("preserved failed worktree missing: %v", err)
	}
}

func TestCreateUsesInjectedGitRunner(t *testing.T) {
	ctx := context.Background()
	repo := initTempRepo(t)
	git := &recordingGitRunner{delegate: ExecGitRunner{}}
	manager := NewManager(Config{RepoPath: repo, Git: git})

	if _, err := manager.Create(ctx, CreateRequest{
		RunID:   "run-1",
		TaskID:  "US-001",
		BaseRef: "main",
	}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if !git.saw("worktree", "add") {
		t.Fatalf("injected git runner did not observe worktree add; calls = %#v", git.calls)
	}
	if !git.saw("status", "--porcelain=v1") {
		t.Fatalf("injected git runner did not observe status check; calls = %#v", git.calls)
	}
}

type recordingGitRunner struct {
	delegate GitRunner
	calls    [][]string
}

func (r *recordingGitRunner) Run(ctx context.Context, dir string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	return r.delegate.Run(ctx, dir, args...)
}

func (r *recordingGitRunner) saw(prefix ...string) bool {
	for _, call := range r.calls {
		if len(call) < len(prefix) {
			continue
		}
		matches := true
		for i := range prefix {
			if call[i] != prefix[i] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func initTempRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "hal@example.test")
	runGit(t, repo, "config", "user.name", "Hal Test")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	runGit(t, repo, "add", "README.md")
	runGit(t, repo, "commit", "-m", "initial commit")
	runGit(t, repo, "branch", "-M", "main")
	return strings.TrimSpace(runGit(t, repo, "rev-parse", "--show-toplevel"))
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(out))
	}
	return string(out)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}
