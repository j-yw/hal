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

func TestGitCLIInspectorInspectGitPreservesFirstPorcelainStatusColumn(t *testing.T) {
	requireGitCLI(t)
	projectDir := t.TempDir()
	runGitTest(t, projectDir, "init")
	runGitTest(t, projectDir, "config", "user.email", "hal-test@example.com")
	runGitTest(t, projectDir, "config", "user.name", "Hal Test")
	trackedPath := filepath.Join(projectDir, "tracked.txt")
	if err := os.WriteFile(trackedPath, []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, projectDir, "add", "tracked.txt")
	runGitTest(t, projectDir, "commit", "-m", "initial")
	if err := os.WriteFile(trackedPath, []byte("after\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	status, err := (GitCLIInspector{}).InspectGit(context.Background(), projectDir)
	if err != nil {
		t.Fatalf("InspectGit() error = %v", err)
	}
	if status.Dirty != (DirtyState{Unstaged: true}) {
		t.Fatalf("Dirty = %#v, want unstaged only", status.Dirty)
	}
	if len(status.RawStatusLines) != 1 || status.RawStatusLines[0] != " M tracked.txt" {
		t.Fatalf("RawStatusLines = %#v, want preserved first XY column", status.RawStatusLines)
	}
}

func TestParsePorcelainDirtyPreservesXYColumns(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want DirtyState
	}{
		{name: "clean", raw: "", want: DirtyState{}},
		{name: "first entry unstaged", raw: " M first.txt\n", want: DirtyState{Unstaged: true}},
		{name: "first entry staged", raw: "M  first.txt\n", want: DirtyState{Staged: true}},
		{name: "untracked", raw: "?? first.txt\n", want: DirtyState{Untracked: true}},
		{name: "staged rename", raw: "R  old.txt -> new.txt\n", want: DirtyState{Staged: true}},
		{name: "unstaged rename", raw: " R old.txt -> new.txt\n", want: DirtyState{Unstaged: true}},
		{name: "staged copy", raw: "C  source.txt -> copy.txt\n", want: DirtyState{Staged: true}},
		{
			name: "mixed entries",
			raw:  " M first.txt\r\nM  second.txt\r\n?? third.txt\r\n",
			want: DirtyState{Staged: true, Unstaged: true, Untracked: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parsePorcelainDirty(tt.raw); got != tt.want {
				t.Fatalf("parsePorcelainDirty() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

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

func TestGitCLIInspectorPlansBundleForCleanPublishedLocalOrigins(t *testing.T) {
	requireGitCLI(t)
	tests := []struct {
		name          string
		repositoryURL func(remoteDir, projectDir string) string
	}{
		{
			name: "absolute path",
			repositoryURL: func(remoteDir, _ string) string {
				return remoteDir
			},
		},
		{
			name: "relative path",
			repositoryURL: func(remoteDir, projectDir string) string {
				relative, err := filepath.Rel(projectDir, remoteDir)
				if err != nil {
					t.Fatal(err)
				}
				return relative
			},
		},
		{
			name: "file URL",
			repositoryURL: func(remoteDir, _ string) string {
				return "file://" + filepath.ToSlash(remoteDir)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := setupCleanPublishedLocalOriginRepo(t)
			repositoryURL := tt.repositoryURL(fixture.remoteDir, fixture.projectDir)
			runGitTest(t, fixture.projectDir, "remote", "set-url", "origin", repositoryURL)

			status, err := (GitCLIInspector{}).InspectGit(context.Background(), fixture.projectDir)
			if err != nil {
				t.Fatalf("InspectGit() error = %v", err)
			}
			if status.Repository != repositoryURL {
				t.Fatalf("Repository = %q, want %q", status.Repository, repositoryURL)
			}
			if !status.HeadContainedInUpstream {
				t.Fatal("HeadContainedInUpstream = false, want clean published HEAD")
			}

			plan, err := (Planner{Git: GitCLIInspector{}}).Plan(context.Background(), Request{
				ProjectDir:    fixture.projectDir,
				WorkspaceMode: sandbox.SandboxWorkspaceModeClone,
			})
			if err != nil {
				t.Fatalf("Plan() error = %v", err)
			}
			if plan.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle || !plan.RequiresBundle {
				t.Fatalf("plan = %#v, want required git bundle", plan)
			}
			if plan.SyncRef != fixture.head {
				t.Fatalf("SyncRef = %q, want %q", plan.SyncRef, fixture.head)
			}
			bundle, err := PrepareLocalBundle(context.Background(), GitCLIInspector{}, PrepareLocalBundleRequest{
				Plan:      plan,
				BundleDir: t.TempDir(),
			})
			if err != nil {
				t.Fatalf("PrepareLocalBundle() error = %v", err)
			}
			if _, err := os.Stat(bundle.LocalPath); err != nil {
				t.Fatalf("bundle stat error = %v", err)
			}
		})
	}
}

func TestGitCLIInspectorCreateBundleImportsIntoEmptyRepository(t *testing.T) {
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
	result, err := PrepareLocalBundle(ctx, GitCLIInspector{}, PrepareLocalBundleRequest{
		Plan:      plan,
		BundleDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("PrepareLocalBundle() error = %v", err)
	}

	sandboxDir := filepath.Join(t.TempDir(), "sandbox")
	runGitTest(t, "", "init", sandboxDir)
	runGitTest(t, sandboxDir, "fetch", result.LocalPath, result.SyncRef+":refs/heads/bundled")
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

func setupCleanPublishedLocalOriginRepo(t *testing.T) gitBundleFixture {
	t.Helper()
	root := t.TempDir()
	remoteDir := filepath.Join(root, "remote.git")
	projectDir := filepath.Join(root, "project")
	runGitTest(t, "", "init", "--bare", remoteDir)
	runGitTest(t, "", "clone", remoteDir, projectDir)
	runGitTest(t, projectDir, "config", "user.email", "test@example.com")
	runGitTest(t, projectDir, "config", "user.name", "Test User")
	if err := os.WriteFile(filepath.Join(projectDir, "README.md"), []byte("published\n"), 0o600); err != nil {
		t.Fatalf("write published file: %v", err)
	}
	runGitTest(t, projectDir, "add", "README.md")
	runGitTest(t, projectDir, "commit", "-m", "published")
	runGitTest(t, projectDir, "branch", "-M", "main")
	runGitTest(t, projectDir, "push", "-u", "origin", "main")
	return gitBundleFixture{
		projectDir: projectDir,
		remoteDir:  remoteDir,
		head:       gitOutputTest(t, projectDir, "rev-parse", "HEAD"),
	}
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
