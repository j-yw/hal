//go:build linux && integration

package cmd

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

// These tests execute only local Git and shell processes in test-owned dirs.
// No repository remote is contacted; the configured remote is deliberately
// unavailable. A missing Git binary is a failed tagged gate, not a pass/skip.
func factoryBundleGitFixture(t *testing.T) (string, factory.RunRecord) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'commit.gpgsign=false'")
	dir := t.TempDir()
	factoryBundleGit(t, dir, "init", "-b", "local-base")
	factoryBundleGit(t, dir, "commit", "--allow-empty", "-m", "base fixture")
	factoryBundleGit(t, dir, "checkout", "-b", "local-source")
	factoryBundleGit(t, dir, "commit", "--allow-empty", "-m", "local source fixture")
	factoryBundleGit(t, dir, "remote", "add", "origin", "https://example.invalid/private/repo.git")
	return dir, factory.RunRecord{RepoRemote: "https://example.invalid/private/repo.git", BaseBranch: "local-base", BranchName: "hal/factory-output"}
}

func factoryBundleGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-c", "commit.gpgsign=false", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid"}, args...)...)
	command.Dir = dir
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("local Git fixture failed: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestFactoryRootlessBundleRealGitPreservesSourceBaseAndRun(t *testing.T) {
	dir, record := factoryBundleGitFixture(t)
	// Even a cached upstream containing HEAD must not trigger a private fetch.
	factoryBundleGit(t, dir, "update-ref", "refs/remotes/origin/local-source", "HEAD")
	factoryBundleGit(t, dir, "config", "branch.local-source.remote", "origin")
	factoryBundleGit(t, dir, "config", "branch.local-source.merge", "refs/heads/local-source")
	plan, err := planFactorySandboxBundle(context.Background(), dir, record)
	if err != nil {
		t.Fatal(err)
	}
	head := factoryBundleGit(t, dir, "rev-parse", "HEAD")
	base := factoryBundleGit(t, dir, "rev-parse", "local-base")
	if plan.Workspace.SyncRef != head || plan.BaseCommit != base || head == base || !plan.Workspace.RequiresBundle {
		t.Fatal("source/base evidence was conflated")
	}
	guestDir := filepath.Join(t.TempDir(), "workspace")
	var copiedBundle string
	driver := fakeRunSandboxRuntimeDriver{id: sandboxruntime.DriverRootlessPodman,
		copyIn: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			payload, err := os.ReadFile(req.SourcePath)
			if err != nil {
				return err
			}
			copiedBundle = req.DestinationPath
			if err := os.MkdirAll(filepath.Dir(req.DestinationPath), 0700); err != nil {
				return err
			}
			return os.WriteFile(req.DestinationPath, payload, 0600)
		},
		exec: func(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if len(req.Args) == 0 {
				t.Fatal("empty command")
			}
			for _, arg := range req.Args {
				if arg == "clone" || arg == "ls-remote" {
					t.Fatal("local bundle path attempted remote operation")
				}
			}
			if req.Args[0] == "git" && len(req.Args) > 4 && req.Args[3] == "fetch" && req.Args[4] != copiedBundle {
				t.Fatal("fetch source is not copied bundle")
			}
			command := exec.CommandContext(ctx, req.Args[0], req.Args[1:]...)
			command.Dir, command.Stdout, command.Stderr, command.Stdin = req.WorkDir, req.Stdout, req.Stderr, req.Stdin
			err := command.Run()
			result := &sandboxruntime.ExecResult{}
			if command.ProcessState != nil {
				result.ExitCode = command.ProcessState.ExitCode()
			}
			return result, err
		},
	}
	prep := sandboxexec.PrepareContext{Driver: driver}
	_, err = sandboxexec.MaterializeBundleWorkspace(context.Background(), prep, sandboxexec.WorkspaceMaterializationRequest{
		Workspace: sandboxworkspace.ToSandboxWorkspace(plan.Workspace), Plan: &plan.Workspace,
		ProjectDir: dir, WorkspaceDir: guestDir, BundleDir: t.TempDir(), BundleDestinationDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	heads := factoryBundleGit(t, dir, "bundle", "list-heads", copiedBundle)
	if heads != head+" refs/heads/local-source" {
		t.Fatalf("actual bundle heads=%q", heads)
	}
	if err := prepareFactorySandboxBundleBranches(context.Background(), prep, guestDir, plan); err != nil {
		t.Fatal(err)
	}
	if factoryBundleGit(t, guestDir, "rev-parse", "HEAD") != head || factoryBundleGit(t, guestDir, "branch", "--show-current") != record.BranchName || factoryBundleGit(t, guestDir, "rev-parse", record.BaseBranch) != base {
		t.Fatal("materialized source/base/run differs from selected facts")
	}
	if factoryBundleGit(t, dir, "branch", "--show-current") != "local-source" || factoryBundleGit(t, dir, "status", "--porcelain") != "" {
		t.Fatal("host source workspace was mutated")
	}
}

func TestFactoryRootlessBundleRealGitPreflightNegatives(t *testing.T) {
	for _, scenario := range []string{"dirty", "missing_base", "unrelated_base", "same_base_run", "detached", "remote_mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			dir, record := factoryBundleGitFixture(t)
			switch scenario {
			case "dirty":
				if err := os.WriteFile(filepath.Join(dir, "dirty"), []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing_base":
				record.BaseBranch = "missing"
			case "unrelated_base":
				factoryBundleGit(t, dir, "checkout", "--orphan", "unrelated")
				factoryBundleGit(t, dir, "commit", "--allow-empty", "-m", "unrelated fixture")
				factoryBundleGit(t, dir, "checkout", "local-source")
				record.BaseBranch = "unrelated"
			case "same_base_run":
				record.BranchName = record.BaseBranch
			case "detached":
				factoryBundleGit(t, dir, "checkout", "--detach", "HEAD")
			case "remote_mismatch":
				record.RepoRemote = "https://example.invalid/other.git"
			}
			if _, err := planFactorySandboxBundle(context.Background(), dir, record); err == nil {
				t.Fatal("invalid local input passed preflight")
			} else if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), record.RepoRemote) {
				t.Fatal("preflight error leaked host path/remote")
			}
		})
	}
}

func TestFactoryRootlessBundleRealGitRejectsChangedSourceBeforeExport(t *testing.T) {
	for _, change := range []string{"head", "base", "dirty"} {
		t.Run(change, func(t *testing.T) {
			dir, record := factoryBundleGitFixture(t)
			plan, err := planFactorySandboxBundle(context.Background(), dir, record)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "head":
				factoryBundleGit(t, dir, "commit", "--allow-empty", "-m", "changed source")
			case "base":
				factoryBundleGit(t, dir, "update-ref", "refs/heads/local-base", "HEAD")
			case "dirty":
				if err := os.WriteFile(filepath.Join(dir, "dirty"), []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			export := filepath.Join(t.TempDir(), "export.bundle")
			deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{materializeWorkspace: func(ctx context.Context, _ sandboxexec.PrepareContext, req sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
				_, err := req.LocalGit.CreateBundle(ctx, sandboxworkspace.CreateBundleRequest{Plan: *req.Plan, DestinationPath: export})
				return sandboxworkspace.MaterializationResult{}, err
			}})
			err = prepareFactorySandboxBundle(context.Background(), deps, factorySandboxExecutorRequest{ProjectDir: dir, RunRecord: record, RemoteOutput: io.Discard}, sandboxexec.PrepareContext{}, plan)
			if err == nil {
				t.Fatal("changed input was exported")
			}
			if _, err := os.Stat(export); !os.IsNotExist(err) {
				t.Fatal("failed revalidation created bundle")
			}
		})
	}
}

func TestFactoryRootlessBundleRealGitRejectsChangedExportHead(t *testing.T) {
	dir, record := factoryBundleGitFixture(t)
	plan, err := planFactorySandboxBundle(context.Background(), dir, record)
	if err != nil {
		t.Fatal(err)
	}
	// Model a ref move after the pre-export check, before Git reads the source
	// branch. The existing verifier must reject the newly advertised head.
	factoryBundleGit(t, dir, "commit", "--allow-empty", "-m", "moved export head")
	localGit := sandboxworkspace.GitCLIInspector{}
	bundle, err := localGit.CreateBundle(context.Background(), sandboxworkspace.CreateBundleRequest{Plan: plan.Workspace, DestinationPath: filepath.Join(t.TempDir(), "changed.bundle")})
	if err != nil {
		t.Fatal(err)
	}
	if err := localGit.VerifyBundle(context.Background(), sandboxworkspace.VerifyBundleRequest{Plan: plan.Workspace, Path: bundle.Path, SyncRef: plan.Workspace.SyncRef}); err == nil {
		t.Fatal("changed exported head passed original source pin")
	}
}
