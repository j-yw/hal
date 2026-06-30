package sandboxworkspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestGitCLIInspectorCreateBundleProducesUsableBundleForCleanUnpushedCommit(t *testing.T) {
	requireGitCLI(t)
	ctx := context.Background()
	fixture := setupCleanUnpushedBundleRepo(t)

	plan, err := (Planner{Git: GitCLIInspector{}}).Plan(ctx, Request{
		ProjectDir:    fixture.projectDir,
		WorkspaceMode: sandbox.SandboxWorkspaceModeClone,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if plan.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle {
		t.Fatalf("InputSource = %q, want git_bundle", plan.InputSource)
	}
	if plan.SyncRef != fixture.head {
		t.Fatalf("SyncRef = %q, want %q", plan.SyncRef, fixture.head)
	}

	result, err := PrepareLocalBundle(ctx, GitCLIInspector{}, PrepareLocalBundleRequest{
		Plan:      plan,
		BundleDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("PrepareLocalBundle() error = %v", err)
	}
	if _, err := os.Stat(result.LocalPath); err != nil {
		t.Fatalf("bundle stat error = %v", err)
	}
	if result.SyncRef != fixture.head {
		t.Fatalf("result SyncRef = %q, want %q", result.SyncRef, fixture.head)
	}

	sandboxDir := filepath.Join(t.TempDir(), "sandbox")
	runGitTest(t, "", "clone", "--branch", "phase/workspace", fixture.remoteDir, sandboxDir)
	runGitTest(t, sandboxDir, "fetch", result.LocalPath, "refs/heads/phase/workspace:refs/heads/bundled")
	gotHead := gitOutputTest(t, sandboxDir, "rev-parse", "refs/heads/bundled")
	if gotHead != fixture.head {
		t.Fatalf("bundled head = %q, want %q", gotHead, fixture.head)
	}
}

func TestGitCLIInspectorVerifyBundleRejectsBundleWithoutPlannedCommit(t *testing.T) {
	requireGitCLI(t)
	ctx := context.Background()
	fixture := setupCleanUnpushedBundleRepo(t)
	baseBundle := filepath.Join(t.TempDir(), "base.bundle")
	runGitTest(t, fixture.projectDir, "bundle", "create", baseBundle, "origin/phase/workspace")

	err := (GitCLIInspector{}).VerifyBundle(ctx, VerifyBundleRequest{
		Plan: Plan{
			ProjectDir: fixture.projectDir,
			Branch:     "phase/workspace",
			Upstream:   "origin/phase/workspace",
			SyncRef:    fixture.head,
		},
		Path:    baseBundle,
		SyncRef: fixture.head,
	})
	if err == nil {
		t.Fatal("VerifyBundle() error = nil, want missing planned commit error")
	}
	if !strings.Contains(err.Error(), "git bundle verify failed") ||
		!strings.Contains(err.Error(), "does not contain planned sync ref") {
		t.Fatalf("VerifyBundle() error = %q, want clear planned sync ref failure", err)
	}
	if strings.Contains(err.Error(), baseBundle) || strings.Contains(err.Error(), fixture.projectDir) {
		t.Fatalf("VerifyBundle() error leaked host path: %q", err)
	}
}

func TestPrepareLocalBundleCreateFailureIsPhaseSpecificAndPathSafe(t *testing.T) {
	requireGitCLI(t)
	fixture := setupCleanUnpushedBundleRepo(t)
	bundleDir := t.TempDir()
	plan := Plan{
		Mode:           sandbox.SandboxWorkspaceModeClone,
		InputSource:    sandbox.SandboxWorkspaceInputSourceGitBundle,
		ProjectDir:     fixture.projectDir,
		Repository:     "https://user:secret@example.test/repo.git",
		Branch:         "missing-ref",
		Upstream:       "origin/phase/workspace",
		SyncRef:        fixture.head,
		RequiresBundle: true,
	}

	_, err := PrepareLocalBundle(context.Background(), GitCLIInspector{}, PrepareLocalBundleRequest{
		Plan:      plan,
		BundleDir: bundleDir,
	})
	if err == nil {
		t.Fatal("PrepareLocalBundle() error = nil, want create failure")
	}
	if !strings.Contains(err.Error(), "workspace bundle create") {
		t.Fatalf("PrepareLocalBundle() error = %q, want bundle create phase", err)
	}
	if strings.Contains(err.Error(), fixture.projectDir) ||
		strings.Contains(err.Error(), bundleDir) ||
		strings.Contains(err.Error(), "secret") {
		t.Fatalf("PrepareLocalBundle() error leaked unsafe detail: %q", err)
	}
}

type gitBundleFixture struct {
	projectDir string
	remoteDir  string
	base       string
	head       string
}

func setupCleanUnpushedBundleRepo(t *testing.T) gitBundleFixture {
	t.Helper()
	root := t.TempDir()
	remoteDir := filepath.Join(root, "remote.git")
	projectDir := filepath.Join(root, "project")

	runGitTest(t, "", "init", "--bare", remoteDir)
	runGitTest(t, "", "clone", remoteDir, projectDir)
	runGitTest(t, projectDir, "config", "user.email", "test@example.com")
	runGitTest(t, projectDir, "config", "user.name", "Test User")
	if err := os.WriteFile(filepath.Join(projectDir, "README.md"), []byte("base\n"), 0o600); err != nil {
		t.Fatalf("write base file: %v", err)
	}
	runGitTest(t, projectDir, "add", "README.md")
	runGitTest(t, projectDir, "commit", "-m", "base")
	runGitTest(t, projectDir, "branch", "-M", "phase/workspace")
	runGitTest(t, projectDir, "push", "-u", "origin", "phase/workspace")
	runGitTest(t, remoteDir, "symbolic-ref", "HEAD", "refs/heads/phase/workspace")
	base := gitOutputTest(t, projectDir, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(projectDir, "README.md"), []byte("base\nlocal\n"), 0o600); err != nil {
		t.Fatalf("write local file: %v", err)
	}
	runGitTest(t, projectDir, "commit", "-am", "local")
	head := gitOutputTest(t, projectDir, "rev-parse", "HEAD")
	if head == base {
		t.Fatal("test setup did not create an unpushed commit")
	}

	return gitBundleFixture{
		projectDir: projectDir,
		remoteDir:  remoteDir,
		base:       base,
		head:       head,
	}
}

func requireGitCLI(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git executable not found: %v", err)
	}
}

func runGitTest(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s error = %v\n%s", strings.Join(args, " "), err, out)
	}
}

func gitOutputTest(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s error = %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}
