package factory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBootstrapRepositoryCheckoutClonesMissingRepoAndChecksOutBase(t *testing.T) {
	startedAt := time.Date(2026, 6, 21, 5, 0, 0, 0, time.UTC)
	now := incrementingClock(t, startedAt)
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "repository cloned"},
			{ExitCode: 0, OutputSummary: "base checked out"},
		},
	}

	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "develop",
		WorkspaceDir:  "/workspace/hal",
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      now,
		RepoExists: func(path string) (bool, error) {
			if path != "/workspace/hal" {
				t.Fatalf("repo existence path = %q, want /workspace/hal", path)
			}
			return false, nil
		},
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}
	if result.RepoPath != "/workspace/hal" {
		t.Fatalf("repo path = %q, want /workspace/hal", result.RepoPath)
	}
	if result.CheckedOutBranch != "develop" {
		t.Fatalf("checked out branch = %q, want develop", result.CheckedOutBranch)
	}
	if result.Failure != nil {
		t.Fatalf("failure = %#v, want nil", result.Failure)
	}

	wantCalls := []BootstrapCommand{
		{
			Name: "git",
			Args: []string{"clone", "git@github.com:jywlabs/hal.git", "/workspace/hal"},
			Dir:  "/workspace",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-B", "develop", "origin/develop"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	wantSteps := []string{BootstrapStepCloneRepository, BootstrapStepCheckoutBase}
	assertBootstrapStepNames(t, result.Steps, wantSteps)
	for _, step := range result.Steps {
		if step.Status != RunStatusSucceeded {
			t.Fatalf("step %q status = %q, want %q", step.Name, step.Status, RunStatusSucceeded)
		}
	}
}

func TestBootstrapRepositoryCheckoutFetchesExistingRepoInsteadOfRecloning(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "repository fetched"},
			{ExitCode: 0, OutputSummary: "base checked out"},
		},
	}

	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		WorkspaceDir:  "/workspace/hal",
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 5, 10, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == "/workspace/hal", nil
		},
		RepoRemoteURL: bootstrapRepoRemoteURL("git@github.com:jywlabs/hal.git"),
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}

	wantCalls := []BootstrapCommand{
		{
			Name: "git",
			Args: []string{"fetch", "--prune", "origin"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-B", "main", "origin/main"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepFetchRepository, BootstrapStepCheckoutBase})
	for _, call := range executor.calls {
		if call.Args[0] == "clone" {
			t.Fatalf("existing repository should not be recloned: %#v", executor.calls)
		}
	}
}

func TestBootstrapRepositoryCheckoutRejectsExistingRepoWithUnexpectedRemote(t *testing.T) {
	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		WorkspaceDir:  "/workspace/hal",
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Now: incrementingClock(t, time.Date(2026, 6, 21, 5, 10, 30, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == "/workspace/hal", nil
		},
		RepoRemoteURL: func(path string) (string, error) {
			if path != "/workspace/hal" {
				t.Fatalf("repo remote path = %q, want /workspace/hal", path)
			}
			return "git@github.com:other/project.git", nil
		},
	})
	if err == nil {
		t.Fatal("BootstrapRepositoryCheckout() error = nil, want remote mismatch")
	}
	if !strings.Contains(err.Error(), "does not match requested URL") {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}
	if result.Failure == nil {
		t.Fatal("failure = nil, want classified repository failure")
	}
	if result.Failure.Category != BootstrapFailureCategoryRepo {
		t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryRepo)
	}
	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepCloneRepository})
}

func TestBootstrapRepositoryCheckoutValidatesInjectedExistingRepoRemoteFromGitConfig(t *testing.T) {
	workspaceDir := filepath.Join(t.TempDir(), "hal")
	gitDir := filepath.Join(workspaceDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	config := `[remote "origin"]
	url = git@github.com:other/project.git
`
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(config), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	executor := &fakeBootstrapExecutor{}
	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		WorkspaceDir:  workspaceDir,
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 5, 10, 45, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == workspaceDir, nil
		},
	})
	if err == nil {
		t.Fatal("BootstrapRepositoryCheckout() error = nil, want remote mismatch")
	}
	if !strings.Contains(err.Error(), "does not match requested URL") {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}
	if len(executor.calls) != 0 {
		t.Fatalf("executor calls = %#v, want none", executor.calls)
	}
	if result.Failure == nil || result.Failure.Category != BootstrapFailureCategoryRepo {
		t.Fatalf("failure = %#v, want repository failure", result.Failure)
	}
}

func TestBootstrapRepositoryCheckoutValidatesLinkedWorktreeRemoteFromCommonGitConfig(t *testing.T) {
	root := t.TempDir()
	workspaceDir := filepath.Join(root, "worktree")
	commonGitDir := filepath.Join(root, "main", ".git")
	worktreeGitDir := filepath.Join(commonGitDir, "worktrees", "feature")
	if err := os.MkdirAll(worktreeGitDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspaceDir, ".git"), []byte("gitdir: "+worktreeGitDir+"\n"), 0644); err != nil {
		t.Fatalf("WriteFile(.git) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(worktreeGitDir, "commondir"), []byte("../..\n"), 0644); err != nil {
		t.Fatalf("WriteFile(commondir) error = %v", err)
	}
	config := `[remote "origin"]
	url = git@github.com:jywlabs/hal.git
`
	if err := os.WriteFile(filepath.Join(commonGitDir, "config"), []byte(config), 0644); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "repository fetched"},
			{ExitCode: 0, OutputSummary: "base checked out"},
		},
	}
	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		WorkspaceDir:  workspaceDir,
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 5, 10, 50, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == workspaceDir, nil
		},
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}
	if result.Failure != nil {
		t.Fatalf("failure = %#v, want nil", result.Failure)
	}
	wantCalls := []BootstrapCommand{
		{
			Name: "git",
			Args: []string{"fetch", "--prune", "origin"},
			Dir:  workspaceDir,
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-B", "main", "origin/main"},
			Dir:  workspaceDir,
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}
}

func TestBootstrapRepositoryCheckoutClonesIntoEmptyExistingDirectory(t *testing.T) {
	workspaceDir := filepath.Join(t.TempDir(), "hal")
	if err := os.Mkdir(workspaceDir, 0755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "repository cloned"},
			{ExitCode: 0, OutputSummary: "base checked out"},
		},
	}

	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		WorkspaceDir:  workspaceDir,
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 5, 11, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}

	wantCalls := []BootstrapCommand{
		{
			Name: "git",
			Args: []string{"clone", "git@github.com:jywlabs/hal.git", workspaceDir},
			Dir:  filepath.Dir(workspaceDir),
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-B", "main", "origin/main"},
			Dir:  workspaceDir,
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}
	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepCloneRepository, BootstrapStepCheckoutBase})
}

func TestBootstrapRepositoryCheckoutRejectsNonEmptyNonGitDirectory(t *testing.T) {
	workspaceDir := filepath.Join(t.TempDir(), "hal")
	if err := os.Mkdir(workspaceDir, 0755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspaceDir, "README.md"), []byte("not a checkout"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		WorkspaceDir:  workspaceDir,
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{})
	if err == nil {
		t.Fatal("BootstrapRepositoryCheckout() error = nil, want non-git directory error")
	}
	if !strings.Contains(err.Error(), "repository path exists but is not a git checkout and is not empty") {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}
	if result.Failure == nil {
		t.Fatal("failure = nil, want classified repository failure")
	}
	if result.Failure.Category != BootstrapFailureCategoryRepo {
		t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryRepo)
	}
	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepCloneRepository})
	if len(result.Timeline) != 1 {
		t.Fatalf("timeline events = %d, want 1", len(result.Timeline))
	}
	if result.Timeline[0].Metadata[bootstrapTimelineFailureCategoryKey] != BootstrapFailureCategoryRepo {
		t.Fatalf("timeline failure category = %q, want %q", result.Timeline[0].Metadata[bootstrapTimelineFailureCategoryKey], BootstrapFailureCategoryRepo)
	}
}

func TestBootstrapRepositoryCheckoutCreatesMissingRunBranchFromBase(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "repository fetched"},
			{ExitCode: 0, OutputSummary: "base checked out"},
			{ExitCode: 0, OutputSummary: "run branch created"},
		},
	}

	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		RunBranch:     "hal/factory-remote-workspace-bootstrap",
		WorkspaceDir:  "/workspace/hal",
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 5, 12, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == "/workspace/hal", nil
		},
		RepoRemoteURL: bootstrapRepoRemoteURL("git@github.com:jywlabs/hal.git"),
		LocalBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			if repoPath != "/workspace/hal" || branch != "hal/factory-remote-workspace-bootstrap" {
				t.Fatalf("local branch probe = (%q, %q)", repoPath, branch)
			}
			return false, nil
		},
		RemoteBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			if repoPath != "/workspace/hal" || branch != "hal/factory-remote-workspace-bootstrap" {
				t.Fatalf("remote branch probe = (%q, %q)", repoPath, branch)
			}
			return false, nil
		},
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}
	if result.CheckedOutBranch != "hal/factory-remote-workspace-bootstrap" {
		t.Fatalf("checked out branch = %q", result.CheckedOutBranch)
	}

	wantCalls := []BootstrapCommand{
		{
			Name: "git",
			Args: []string{"fetch", "--prune", "origin"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-B", "main", "origin/main"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-b", "hal/factory-remote-workspace-bootstrap", "main"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepCreateRunBranch,
	})
}

func TestBootstrapRepositoryCheckoutReusesExistingLocalRunBranch(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "repository fetched"},
			{ExitCode: 0, OutputSummary: "base checked out"},
			{ExitCode: 0, OutputSummary: "run branch checked out"},
		},
	}

	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		RunBranch:     "hal/factory-remote-workspace-bootstrap",
		WorkspaceDir:  "/workspace/hal",
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 5, 14, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == "/workspace/hal", nil
		},
		RepoRemoteURL: bootstrapRepoRemoteURL("git@github.com:jywlabs/hal.git"),
		LocalBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			if repoPath != "/workspace/hal" || branch != "hal/factory-remote-workspace-bootstrap" {
				t.Fatalf("local branch probe = (%q, %q)", repoPath, branch)
			}
			return true, nil
		},
		RemoteBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			t.Fatalf("remote branch probe should not run when local branch exists: (%q, %q)", repoPath, branch)
			return false, nil
		},
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}
	if result.CheckedOutBranch != "hal/factory-remote-workspace-bootstrap" {
		t.Fatalf("checked out branch = %q", result.CheckedOutBranch)
	}

	wantCalls := []BootstrapCommand{
		{
			Name: "git",
			Args: []string{"fetch", "--prune", "origin"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-B", "main", "origin/main"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "hal/factory-remote-workspace-bootstrap"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepCheckoutRun,
	})
}

func TestBootstrapRepositoryCheckoutResumesRemoteRunBranch(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "repository fetched"},
			{ExitCode: 0, OutputSummary: "base checked out"},
			{ExitCode: 0, OutputSummary: "remote run branch fetched"},
			{ExitCode: 0, OutputSummary: "remote run branch checked out"},
		},
	}

	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		RunBranch:     "hal/factory-remote-workspace-bootstrap",
		WorkspaceDir:  "/workspace/hal",
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 5, 16, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == "/workspace/hal", nil
		},
		RepoRemoteURL: bootstrapRepoRemoteURL("git@github.com:jywlabs/hal.git"),
		LocalBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			if repoPath != "/workspace/hal" || branch != "hal/factory-remote-workspace-bootstrap" {
				t.Fatalf("local branch probe = (%q, %q)", repoPath, branch)
			}
			return false, nil
		},
		RemoteBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			if repoPath != "/workspace/hal" || branch != "hal/factory-remote-workspace-bootstrap" {
				t.Fatalf("remote branch probe = (%q, %q)", repoPath, branch)
			}
			return true, nil
		},
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}
	if result.CheckedOutBranch != "hal/factory-remote-workspace-bootstrap" {
		t.Fatalf("checked out branch = %q", result.CheckedOutBranch)
	}

	wantCalls := []BootstrapCommand{
		{
			Name: "git",
			Args: []string{"fetch", "--prune", "origin"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-B", "main", "origin/main"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"fetch", "origin", "hal/factory-remote-workspace-bootstrap:refs/remotes/origin/hal/factory-remote-workspace-bootstrap"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "--track", "origin/hal/factory-remote-workspace-bootstrap"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepFetchRunBranch,
		BootstrapStepCheckoutRun,
	})
}

func TestBootstrapRepositoryCheckoutRecordsDefaultRunBranchProbeSteps(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "repository fetched"},
			{ExitCode: 0, OutputSummary: "base checked out"},
			{ExitCode: 1, OutputSummary: "local run branch missing"},
			{ExitCode: 0, OutputSummary: "remote run branch exists"},
			{ExitCode: 0, OutputSummary: "remote run branch fetched"},
			{ExitCode: 0, OutputSummary: "remote run branch checked out"},
		},
	}

	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		RunBranch:     "hal/factory-remote-workspace-bootstrap",
		WorkspaceDir:  "/workspace/hal",
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 5, 18, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == "/workspace/hal", nil
		},
		RepoRemoteURL: bootstrapRepoRemoteURL("git@github.com:jywlabs/hal.git"),
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}

	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepCheckLocalRun,
		BootstrapStepCheckRemoteRun,
		BootstrapStepFetchRunBranch,
		BootstrapStepCheckoutRun,
	})
	if result.Steps[2].Status != RunStatusSucceeded {
		t.Fatalf("local probe status = %q, want %q", result.Steps[2].Status, RunStatusSucceeded)
	}
	if result.Steps[2].ExitCode != 1 {
		t.Fatalf("local probe exit code = %d, want 1", result.Steps[2].ExitCode)
	}
	if result.Steps[3].Status != RunStatusSucceeded {
		t.Fatalf("remote probe status = %q, want %q", result.Steps[3].Status, RunStatusSucceeded)
	}
	if len(result.Timeline) != len(result.Steps) {
		t.Fatalf("timeline events = %d, want %d", len(result.Timeline), len(result.Steps))
	}

	wantProbeCalls := []BootstrapCommand{
		{
			Name: "git",
			Args: []string{"show-ref", "--verify", "--quiet", "refs/heads/hal/factory-remote-workspace-bootstrap"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"ls-remote", "--exit-code", "--heads", "origin", "hal/factory-remote-workspace-bootstrap"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls[2:4], wantProbeCalls) {
		t.Fatalf("probe calls mismatch\n got: %#v\nwant: %#v", executor.calls[2:4], wantProbeCalls)
	}
}

func TestBootstrapBranchProbePropagatesExecutorErrorWithoutExitCode(t *testing.T) {
	probeErr := errors.New("probe failed")
	deps := BootstrapRepositoryDeps{
		Executor: &fakeBootstrapExecutor{
			errs: []error{probeErr},
		},
	}

	exists, err := deps.probeBranch(context.Background(), BootstrapRequest{}, BootstrapCommand{
		Name: "git",
		Args: []string{"show-ref", "--verify", "--quiet", "refs/heads/hal/run"},
		Dir:  "/workspace/hal",
	}, BootstrapStepCheckLocalRun, 1)
	if !errors.Is(err, probeErr) {
		t.Fatalf("probeBranch() error = %v, want %v", err, probeErr)
	}
	if exists {
		t.Fatal("probeBranch() exists = true, want false")
	}
}

func TestBootstrapBranchProbeReceivesRequestEnvironment(t *testing.T) {
	secret := "ghp_branch_probe_secret_value"
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0},
		},
	}
	deps := BootstrapRepositoryDeps{
		Executor: executor,
	}

	exists, err := deps.probeBranch(context.Background(), BootstrapRequest{
		Env: map[string]string{
			"GITHUB_TOKEN": secret,
			"HAL_ENGINE":   "codex",
		},
	}, BootstrapCommand{
		Name: "git",
		Args: []string{"show-ref", "--verify", "--quiet", "refs/heads/hal/run"},
		Dir:  "/workspace/hal",
		Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
	}, BootstrapStepCheckLocalRun, 1)
	if err != nil {
		t.Fatalf("probeBranch() error = %v", err)
	}
	if !exists {
		t.Fatal("probeBranch() exists = false, want true")
	}
	if len(executor.calls) != 1 {
		t.Fatalf("executor calls = %d, want 1", len(executor.calls))
	}
	gotEnv := executor.calls[0].Env
	if gotEnv["GITHUB_TOKEN"] != secret {
		t.Fatalf("GITHUB_TOKEN = %q, want request secret", gotEnv["GITHUB_TOKEN"])
	}
	if gotEnv["HAL_ENGINE"] != "codex" {
		t.Fatalf("HAL_ENGINE = %q, want codex", gotEnv["HAL_ENGINE"])
	}
	if gotEnv["GIT_TERMINAL_PROMPT"] != "0" {
		t.Fatalf("GIT_TERMINAL_PROMPT = %q, want 0", gotEnv["GIT_TERMINAL_PROMPT"])
	}
}

func TestBootstrapRepositoryCheckoutDryRunPlansCommandsWithoutExecutor(t *testing.T) {
	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "develop",
		WorkspaceDir:  "/workspace/hal",
		Options: BootstrapOptions{
			DryRun: true,
		},
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Now: incrementingClock(t, time.Date(2026, 6, 21, 5, 20, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}

	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepCloneRepository, BootstrapStepCheckoutBase})
	for _, step := range result.Steps {
		if step.Status != RunStatusPending {
			t.Fatalf("planned step %q status = %q, want %q", step.Name, step.Status, RunStatusPending)
		}
		if step.CommandSummary == "" {
			t.Fatalf("planned step %q missing command summary", step.Name)
		}
	}
}

func TestBootstrapRepositoryCheckoutRedactsRepositoryURLCredentialsInDryRun(t *testing.T) {
	repositoryURL := "https://oauth2:ghp_repository_url_secret_value@github.com/jywlabs/hal.git"
	req := BootstrapRequest{
		RepositoryURL: repositoryURL,
		BaseBranch:    "develop",
		WorkspaceDir:  "/workspace/hal",
		Options: BootstrapOptions{
			DryRun: true,
		},
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Now: incrementingClock(t, time.Date(2026, 6, 21, 5, 21, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return false, nil
		},
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}

	summary := result.Steps[0].CommandSummary
	for _, leaked := range []string{"oauth2", "ghp_repository_url_secret_value"} {
		if strings.Contains(summary, leaked) {
			t.Fatalf("command summary leaked repository URL credentials: %q", summary)
		}
	}
	if !strings.Contains(summary, bootstrapRedactedValue) {
		t.Fatalf("command summary did not redact credentials: %q", summary)
	}
}

func TestBootstrapRepositoryCheckoutClassifiesRepositoryFailure(t *testing.T) {
	executorErr := errors.New("exit status 128")
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{
				ExitCode:      128,
				StderrSummary: "fatal: repository unavailable",
			},
		},
		errs: []error{executorErr},
	}

	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "develop",
		WorkspaceDir:  "/workspace/hal",
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 5, 30, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return false, nil
		},
	})
	if !errors.Is(err, executorErr) {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v, want %v", err, executorErr)
	}
	if result.Failure == nil {
		t.Fatal("failure = nil, want classified failure")
	}
	if result.Failure.Category != BootstrapFailureCategoryRepo {
		t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryRepo)
	}
	if result.Failure.Message != "repository bootstrap failed while running git clone" {
		t.Fatalf("failure message = %q", result.Failure.Message)
	}
}

func TestBootstrapRepositoryCheckoutClassifiesAuthFailure(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{
				ExitCode:      128,
				StderrSummary: "remote: Authentication failed",
			},
		},
		errs: []error{errors.New("exit status 128")},
	}

	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "develop",
		WorkspaceDir:  "/workspace/hal",
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 5, 40, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return false, nil
		},
	})
	if err == nil {
		t.Fatal("BootstrapRepositoryCheckout() error = nil, want failure")
	}
	if result.Failure == nil {
		t.Fatal("failure = nil, want classified failure")
	}
	if result.Failure.Category != BootstrapFailureCategoryAuth {
		t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryAuth)
	}
	if result.Failure.Message != "authentication failed while running git clone" {
		t.Fatalf("failure message = %q", result.Failure.Message)
	}
}

func TestBootstrapRepositoryCheckoutClassifiesRunBranchProbeFailure(t *testing.T) {
	probeErr := errors.New("probe failed")
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "repository fetched"},
			{ExitCode: 0, OutputSummary: "base checked out"},
		},
	}

	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		RunBranch:     "hal/factory-remote-workspace-bootstrap",
		WorkspaceDir:  "/workspace/hal",
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 5, 50, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == "/workspace/hal", nil
		},
		RepoRemoteURL: bootstrapRepoRemoteURL("git@github.com:jywlabs/hal.git"),
		LocalBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			return false, probeErr
		},
	})
	if !errors.Is(err, probeErr) {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v, want %v", err, probeErr)
	}
	if result.Failure == nil {
		t.Fatal("failure = nil, want classified failure")
	}
	if result.Failure.Step != BootstrapStepCheckLocalRun {
		t.Fatalf("failure step = %q, want %q", result.Failure.Step, BootstrapStepCheckLocalRun)
	}
	if result.Failure.Category != BootstrapFailureCategoryRepo {
		t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryRepo)
	}
	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepCheckLocalRun,
	})
	lastEvent := result.Timeline[len(result.Timeline)-1]
	if lastEvent.Status != RunStatusFailed {
		t.Fatalf("last event status = %q, want %q", lastEvent.Status, RunStatusFailed)
	}
	if lastEvent.Metadata[bootstrapTimelineFailureCategoryKey] != BootstrapFailureCategoryRepo {
		t.Fatalf("last event failure category = %q, want %q", lastEvent.Metadata[bootstrapTimelineFailureCategoryKey], BootstrapFailureCategoryRepo)
	}
}

func assertBootstrapStepNames(t *testing.T, steps []BootstrapStepResult, want []string) {
	t.Helper()
	got := make([]string, 0, len(steps))
	for _, step := range steps {
		got = append(got, step.Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("step names = %#v, want %#v", got, want)
	}
}

func incrementingClock(t *testing.T, start time.Time) func() time.Time {
	t.Helper()
	next := start
	return func() time.Time {
		current := next
		next = next.Add(time.Second)
		return current
	}
}

func bootstrapRepoRemoteURL(remote string) func(path string) (string, error) {
	return func(string) (string, error) {
		return remote, nil
	}
}
