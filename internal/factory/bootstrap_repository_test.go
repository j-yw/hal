package factory

import (
	"context"
	"errors"
	"os"
	"os/exec"
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
			{ExitCode: 0, OutputSummary: "workspace root created"},
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
			Name: "mkdir",
			Args: []string{"-p", "/workspace"},
		},
		{
			Name: "git",
			Args: []string{"clone", "git@github.com:jywlabs/hal.git", "/workspace/hal"},
			Dir:  "/workspace",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-f", "develop"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	wantSteps := []string{BootstrapStepEnsureWorkspace, BootstrapStepCloneRepository, BootstrapStepCheckoutBase}
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
			{ExitCode: 0, OutputSummary: "managed engine links cleaned"},
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
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}

	wantCalls := []BootstrapCommand{
		{
			Name: "sh",
			Args: []string{"-lc", bootstrapCleanEngineLinksScript},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"fetch", "--prune", "origin"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-f", "-B", "main", "origin/main"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepCleanEngineLinks, BootstrapStepFetchRepository, BootstrapStepCheckoutBase})
	for _, call := range executor.calls {
		if call.Args[0] == "clone" {
			t.Fatalf("existing repository should not be recloned: %#v", executor.calls)
		}
	}
}

func TestBootstrapRepositoryCheckoutClonesIntoEmptyExistingDirectory(t *testing.T) {
	workspaceDir := filepath.Join(t.TempDir(), "hal")
	if err := os.Mkdir(workspaceDir, 0755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "workspace root created"},
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
			Name: "mkdir",
			Args: []string{"-p", filepath.Dir(workspaceDir)},
		},
		{
			Name: "git",
			Args: []string{"clone", "git@github.com:jywlabs/hal.git", workspaceDir},
			Dir:  filepath.Dir(workspaceDir),
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-f", "main"},
			Dir:  workspaceDir,
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}
	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepEnsureWorkspace, BootstrapStepCloneRepository, BootstrapStepCheckoutBase})
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
	_, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{})
	if err == nil {
		t.Fatal("BootstrapRepositoryCheckout() error = nil, want non-git directory error")
	}
	if !strings.Contains(err.Error(), "repository path exists but is not a git checkout and is not empty") {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}
}

func TestBootstrapRepositoryCheckoutCreatesMissingRunBranchFromBase(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "managed engine links cleaned"},
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
			Name: "sh",
			Args: []string{"-lc", bootstrapCleanEngineLinksScript},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"fetch", "--prune", "origin"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-f", "-B", "main", "origin/main"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-f", "-b", "hal/factory-remote-workspace-bootstrap", "main"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepCleanEngineLinks,
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepCreateRunBranch,
	})
}

func TestBootstrapRepositoryCheckoutReusesExistingLocalRunBranch(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "managed engine links cleaned"},
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
			Name: "sh",
			Args: []string{"-lc", bootstrapCleanEngineLinksScript},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"fetch", "--prune", "origin"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-f", "-B", "main", "origin/main"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-f", "hal/factory-remote-workspace-bootstrap"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepCleanEngineLinks,
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepCheckoutRun,
	})
}

func TestBootstrapRepositoryCheckoutExactUpstreamReconcilesExistingLocalRunBranch(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "workspace is clean"},
			{ExitCode: 0, OutputSummary: "managed engine links cleaned"},
			{ExitCode: 0, OutputSummary: "repository fetched"},
			{ExitCode: 0, OutputSummary: "base checked out"},
			{ExitCode: 0, OutputSummary: "remote run branch fetched"},
			{ExitCode: 0, OutputSummary: "run branch reconciled"},
		},
	}

	const runBranch = "hal/direct-sandbox-run"
	req := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		RunBranch:     runBranch,
		WorkspaceDir:  "/workspace/hal",
		Options: BootstrapOptions{
			ExactUpstream: true,
		},
	}
	remoteProbes := 0
	result, err := BootstrapRepositoryCheckout(context.Background(), req, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 7, 14, 5, 14, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == "/workspace/hal", nil
		},
		LocalBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			if repoPath != "/workspace/hal" || branch != runBranch {
				t.Fatalf("local branch probe = (%q, %q)", repoPath, branch)
			}
			return true, nil
		},
		RemoteBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			remoteProbes++
			if repoPath != "/workspace/hal" || branch != runBranch {
				t.Fatalf("remote branch probe = (%q, %q)", repoPath, branch)
			}
			return true, nil
		},
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}
	if remoteProbes != 1 {
		t.Fatalf("remote branch probes = %d, want 1", remoteProbes)
	}
	if result.CheckedOutBranch != runBranch {
		t.Fatalf("checked out branch = %q, want %q", result.CheckedOutBranch, runBranch)
	}
	assertBootstrapCommand(t, executor.calls[0], BootstrapCommand{
		Name: "sh",
		Args: []string{"-c", bootstrapRequireCleanWorkspaceScript, "hal-bootstrap-clean-check", "73"},
		Dir:  "/workspace/hal",
		Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
	})

	wantTail := []BootstrapCommand{
		{
			Name: "git",
			Args: []string{"fetch", "origin", "+" + runBranch + ":refs/remotes/origin/" + runBranch},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-B", runBranch, "origin/" + runBranch},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls[len(executor.calls)-2:], wantTail) {
		t.Fatalf("executor tail mismatch\n got: %#v\nwant: %#v", executor.calls[len(executor.calls)-2:], wantTail)
	}
	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepCheckWorkspaceClean,
		BootstrapStepCleanEngineLinks,
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepFetchRunBranch,
		BootstrapStepCheckoutRun,
	})
}

func TestBootstrapRepositoryCheckoutExactUpstreamPreservesEditIntroducedBeforeBaseCheckout(t *testing.T) {
	repository := newExactUpstreamRaceRepository(t, false)
	runGitCommand(t, repository.seedDir, "checkout", "main")
	if err := os.WriteFile(repository.seedFile, []byte("upstream main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCommand(t, repository.seedDir, "commit", "-am", "update main")
	runGitCommand(t, repository.seedDir, "push", "origin", "main")

	const interveningEdit = "intervening base edit\n"
	executor := &mutatingGitBootstrapExecutor{
		mutateBefore: func(command BootstrapCommand) error {
			if reflect.DeepEqual(command.Args, []string{"checkout", "-B", "main", "origin/main"}) {
				return os.WriteFile(repository.workspaceFile, []byte(interveningEdit), 0o644)
			}
			return nil
		},
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), BootstrapRequest{
		RepositoryURL: repository.remoteDir,
		BaseBranch:    "main",
		WorkspaceDir:  repository.workspaceDir,
		Options:       BootstrapOptions{ExactUpstream: true},
	}, BootstrapRepositoryDeps{Executor: executor})
	if err == nil {
		t.Fatal("BootstrapRepositoryCheckout() error = nil, want intervening edit rejection")
	}
	assertFileContent(t, repository.workspaceFile, interveningEdit)
	if result.Failure == nil || result.Failure.Step != BootstrapStepCheckoutBase {
		t.Fatalf("failure = %#v, want checkout-base failure", result.Failure)
	}
	assertBootstrapCheckoutHasNoForceFlag(t, executor.calls, "main", "origin/main")
}

func TestBootstrapRepositoryCheckoutExactUpstreamPreservesEditIntroducedBeforeRemoteRunCheckout(t *testing.T) {
	const runBranch = "hal/direct-sandbox-run"
	repository := newExactUpstreamRaceRepository(t, true)

	const interveningEdit = "intervening run edit\n"
	executor := &mutatingGitBootstrapExecutor{
		mutateBefore: func(command BootstrapCommand) error {
			if reflect.DeepEqual(command.Args, []string{"checkout", "-B", runBranch, "origin/" + runBranch}) {
				return os.WriteFile(repository.workspaceFile, []byte(interveningEdit), 0o644)
			}
			return nil
		},
	}
	result, err := BootstrapRepositoryCheckout(context.Background(), BootstrapRequest{
		RepositoryURL: repository.remoteDir,
		BaseBranch:    "main",
		RunBranch:     runBranch,
		WorkspaceDir:  repository.workspaceDir,
		Options:       BootstrapOptions{ExactUpstream: true},
	}, BootstrapRepositoryDeps{Executor: executor})
	if err == nil {
		t.Fatal("BootstrapRepositoryCheckout() error = nil, want intervening edit rejection")
	}
	assertFileContent(t, repository.workspaceFile, interveningEdit)
	if result.Failure == nil || result.Failure.Step != BootstrapStepCheckoutRun {
		t.Fatalf("failure = %#v, want checkout-run failure", result.Failure)
	}
	assertBootstrapCheckoutHasNoForceFlag(t, executor.calls, runBranch, "origin/"+runBranch)
}

func TestBootstrapRepositoryCheckoutExactUpstreamRejectsDirtyWorkspaceBeforeMutation(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{{
			ExitCode:      bootstrapWorkspaceDirtyExitCode,
			OutputSummary: "workspace has local changes",
		}},
	}
	remoteProbes := 0
	result, err := BootstrapRepositoryCheckout(context.Background(), BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		RunBranch:     "hal/direct-sandbox-run",
		WorkspaceDir:  "/workspace/hal",
		Options:       BootstrapOptions{ExactUpstream: true},
	}, BootstrapRepositoryDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 7, 14, 5, 15, 0, 0, time.UTC)),
		RepoExists: func(string) (bool, error) {
			return true, nil
		},
		LocalBranchExists: func(context.Context, string, string) (bool, error) {
			t.Fatal("local branch probe must not run after dirty workspace rejection")
			return false, nil
		},
		RemoteBranchExists: func(context.Context, string, string) (bool, error) {
			remoteProbes++
			return true, nil
		},
	})
	if !errors.Is(err, ErrBootstrapWorkspaceDirty) {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v, want ErrBootstrapWorkspaceDirty", err)
	}
	for _, want := range []string{"changes were preserved", "commit or stash", "reset/remove"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("BootstrapRepositoryCheckout() error = %q, want guidance %q", err, want)
		}
	}
	if remoteProbes != 0 {
		t.Fatalf("remote branch probes = %d, want zero", remoteProbes)
	}
	if len(executor.calls) != 1 {
		t.Fatalf("executor calls = %#v, want clean check only", executor.calls)
	}
	if len(result.Steps) != 1 || result.Steps[0].Name != BootstrapStepCheckWorkspaceClean {
		t.Fatalf("steps = %#v, want failed clean check only", result.Steps)
	}
	if result.Failure == nil || result.Failure.Category != BootstrapFailureCategoryRepo {
		t.Fatalf("failure = %#v, want repository failure", result.Failure)
	}
	if !strings.Contains(result.Failure.Message, "changes were preserved") {
		t.Fatalf("failure message = %q, want preservation guidance", result.Failure.Message)
	}
}

func TestBootstrapRepositoryCommandsExactUpstreamChecksCleanBeforeMutation(t *testing.T) {
	commands, err := bootstrapRepositoryCommands(BootstrapRequest{
		BaseBranch:   "main",
		WorkspaceDir: "/workspace/hal",
		Options:      BootstrapOptions{ExactUpstream: true},
	}, BootstrapRepositoryDeps{
		RepoExists: func(string) (bool, error) { return true, nil },
	}, "/workspace/hal")
	if err != nil {
		t.Fatalf("bootstrapRepositoryCommands() error = %v", err)
	}
	if len(commands) < 2 {
		t.Fatalf("commands = %#v, want clean check before mutations", commands)
	}
	if commands[0].stepName != BootstrapStepCheckWorkspaceClean {
		t.Fatalf("first step = %q, want %q", commands[0].stepName, BootstrapStepCheckWorkspaceClean)
	}
	assertBootstrapCommand(t, commands[0].command, BootstrapCommand{
		Name: "sh",
		Args: []string{"-c", bootstrapRequireCleanWorkspaceScript, "hal-bootstrap-clean-check", "73"},
		Dir:  "/workspace/hal",
		Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
	})
	if commands[1].stepName != BootstrapStepCleanEngineLinks {
		t.Fatalf("second step = %q, want first mutation %q", commands[1].stepName, BootstrapStepCleanEngineLinks)
	}
}

func TestBootstrapRepositoryCheckoutResumesRemoteRunBranch(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "managed engine links cleaned"},
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
			Name: "sh",
			Args: []string{"-lc", bootstrapCleanEngineLinksScript},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"fetch", "--prune", "origin"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
		{
			Name: "git",
			Args: []string{"checkout", "-f", "-B", "main", "origin/main"},
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
			Args: []string{"checkout", "-f", "--track", "origin/hal/factory-remote-workspace-bootstrap"},
			Dir:  "/workspace/hal",
			Env:  map[string]string{"GIT_TERMINAL_PROMPT": "0"},
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepCleanEngineLinks,
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepFetchRunBranch,
		BootstrapStepCheckoutRun,
	})
}

func TestBootstrapRepositoryCheckoutRecordsDefaultRunBranchProbeSteps(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "managed engine links cleaned"},
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
	})
	if err != nil {
		t.Fatalf("BootstrapRepositoryCheckout() error = %v", err)
	}

	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepCleanEngineLinks,
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepCheckLocalRun,
		BootstrapStepCheckRemoteRun,
		BootstrapStepFetchRunBranch,
		BootstrapStepCheckoutRun,
	})
	if result.Steps[3].Status != RunStatusSucceeded {
		t.Fatalf("local probe status = %q, want %q", result.Steps[3].Status, RunStatusSucceeded)
	}
	if result.Steps[3].ExitCode != 1 {
		t.Fatalf("local probe exit code = %d, want 1", result.Steps[3].ExitCode)
	}
	if result.Steps[4].Status != RunStatusSucceeded {
		t.Fatalf("remote probe status = %q, want %q", result.Steps[4].Status, RunStatusSucceeded)
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
	if !reflect.DeepEqual(executor.calls[3:5], wantProbeCalls) {
		t.Fatalf("probe calls mismatch\n got: %#v\nwant: %#v", executor.calls[3:5], wantProbeCalls)
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

func TestBootstrapGitEnvUsesGitHubTokenForGitHubSSHRemotes(t *testing.T) {
	secret := "ghp_repository_bootstrap_secret"
	for _, repositoryURL := range []string{
		"git@github.com:jywlabs/hal.git",
		"ssh://git@github.com/jywlabs/hal.git",
	} {
		t.Run(repositoryURL, func(t *testing.T) {
			got := bootstrapGitEnv(BootstrapRequest{
				RepositoryURL: repositoryURL,
				Env: map[string]string{
					bootstrapGitHubTokenEnvKey: secret,
				},
			})

			want := map[string]string{
				"GIT_TERMINAL_PROMPT": "0",
				"GIT_CONFIG_COUNT":    "3",
				"GIT_CONFIG_KEY_0":    bootstrapGitHubExtraHeaderKey,
				"GIT_CONFIG_VALUE_0":  bootstrapGitHubAuthHeader(secret),
				"GIT_CONFIG_KEY_1":    bootstrapGitHubURLRewriteKey,
				"GIT_CONFIG_VALUE_1":  "git@github.com:",
				"GIT_CONFIG_KEY_2":    bootstrapGitHubURLRewriteKey,
				"GIT_CONFIG_VALUE_2":  "ssh://git@github.com/",
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("bootstrapGitEnv() mismatch\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}

func TestBootstrapRepositoryCommandsUseGHTokenForGitHubCloneAndFetch(t *testing.T) {
	const secret = "ghp_repository_bootstrap_gh_token"
	tests := []struct {
		name     string
		exists   bool
		wantStep string
	}{
		{name: "private clone", exists: false, wantStep: BootstrapStepCloneRepository},
		{name: "private fetch", exists: true, wantStep: BootstrapStepFetchRepository},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := BootstrapRequest{
				RepositoryURL: "https://github.com/jywlabs/private-repo.git",
				BaseBranch:    "main",
				WorkspaceDir:  "/workspace/private-repo",
				Env: map[string]string{
					"GH_TOKEN": secret,
				},
			}
			commands, err := bootstrapRepositoryCommands(request, BootstrapRepositoryDeps{
				RepoExists: func(string) (bool, error) { return tt.exists, nil },
			}, request.WorkspaceDir)
			if err != nil {
				t.Fatalf("bootstrapRepositoryCommands() error: %v", err)
			}

			var got *BootstrapCommand
			for i := range commands {
				if commands[i].stepName == tt.wantStep {
					got = &commands[i].command
					break
				}
			}
			if got == nil {
				t.Fatalf("step %q not found in %#v", tt.wantStep, commands)
			}
			wantEnv := map[string]string{
				"GIT_TERMINAL_PROMPT": "0",
				"GIT_CONFIG_COUNT":    "1",
				"GIT_CONFIG_KEY_0":    bootstrapGitHubExtraHeaderKey,
				"GIT_CONFIG_VALUE_0":  bootstrapGitHubAuthHeader(secret),
			}
			if !reflect.DeepEqual(got.Env, wantEnv) {
				t.Fatalf("%s env mismatch\n got: %#v\nwant: %#v", tt.wantStep, got.Env, wantEnv)
			}
		})
	}
}

func TestBootstrapGitEnvGitHubTokenPrecedenceAndEmptyFallback(t *testing.T) {
	const (
		githubToken = "ghp_repository_bootstrap_github_token"
		ghToken     = "ghp_repository_bootstrap_gh_token"
	)
	tests := []struct {
		name      string
		env       map[string]string
		wantToken string
	}{
		{name: "GH_TOKEN fallback", env: map[string]string{"GH_TOKEN": ghToken}, wantToken: ghToken},
		{name: "GITHUB_TOKEN precedence", env: map[string]string{"GITHUB_TOKEN": githubToken, "GH_TOKEN": ghToken}, wantToken: githubToken},
		{name: "empty GITHUB_TOKEN falls back", env: map[string]string{"GITHUB_TOKEN": " \t ", "GH_TOKEN": ghToken}, wantToken: ghToken},
		{name: "both empty", env: map[string]string{"GITHUB_TOKEN": " ", "GH_TOKEN": "\t"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bootstrapGitEnv(BootstrapRequest{
				RepositoryURL: "git@github.com:jywlabs/private-repo.git",
				Env:           tt.env,
			})
			if tt.wantToken == "" {
				want := map[string]string{"GIT_TERMINAL_PROMPT": "0"}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("bootstrapGitEnv() mismatch\n got: %#v\nwant: %#v", got, want)
				}
				return
			}
			want := map[string]string{
				"GIT_TERMINAL_PROMPT": "0",
				"GIT_CONFIG_COUNT":    "3",
				"GIT_CONFIG_KEY_0":    bootstrapGitHubExtraHeaderKey,
				"GIT_CONFIG_VALUE_0":  bootstrapGitHubAuthHeader(tt.wantToken),
				"GIT_CONFIG_KEY_1":    bootstrapGitHubURLRewriteKey,
				"GIT_CONFIG_VALUE_1":  "git@github.com:",
				"GIT_CONFIG_KEY_2":    bootstrapGitHubURLRewriteKey,
				"GIT_CONFIG_VALUE_2":  "ssh://git@github.com/",
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("bootstrapGitEnv() mismatch\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}

func TestBootstrapGitEnvDoesNotUseGitHubTokenForUntrustedSSHRemote(t *testing.T) {
	got := bootstrapGitEnv(BootstrapRequest{
		RepositoryURL: "git@example.com:jywlabs/hal.git",
		Env: map[string]string{
			bootstrapGitHubTokenEnvKey: "ghp_repository_bootstrap_secret",
		},
	})
	want := map[string]string{"GIT_TERMINAL_PROMPT": "0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bootstrapGitEnv() mismatch\n got: %#v\nwant: %#v", got, want)
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

	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepEnsureWorkspace, BootstrapStepCloneRepository, BootstrapStepCheckoutBase})
	for _, step := range result.Steps {
		if step.Status != RunStatusPending {
			t.Fatalf("planned step %q status = %q, want %q", step.Name, step.Status, RunStatusPending)
		}
		if step.CommandSummary == "" {
			t.Fatalf("planned step %q missing command summary", step.Name)
		}
	}
}

func TestBootstrapRepositoryCheckoutClassifiesRepositoryFailure(t *testing.T) {
	executorErr := errors.New("exit status 128")
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "workspace root created"},
			{
				ExitCode:      128,
				StderrSummary: "fatal: repository unavailable",
			},
		},
		errs: []error{nil, executorErr},
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
			{ExitCode: 0, OutputSummary: "workspace root created"},
			{
				ExitCode:      128,
				StderrSummary: "remote: Authentication failed",
			},
		},
		errs: []error{nil, errors.New("exit status 128")},
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
			{ExitCode: 0, OutputSummary: "managed engine links cleaned"},
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
		BootstrapStepCleanEngineLinks,
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

type exactUpstreamRaceRepository struct {
	remoteDir     string
	seedDir       string
	seedFile      string
	workspaceDir  string
	workspaceFile string
}

func newExactUpstreamRaceRepository(t *testing.T, withRunBranch bool) exactUpstreamRaceRepository {
	t.Helper()
	root := t.TempDir()
	remoteDir := filepath.Join(root, "origin.git")
	seedDir := filepath.Join(root, "seed")
	workspaceDir := filepath.Join(root, "workspace")
	runGitCommand(t, "", "init", "--bare", remoteDir)
	runGitCommand(t, "", "init", seedDir)
	runGitCommand(t, seedDir, "config", "user.email", "hal-test@example.com")
	runGitCommand(t, seedDir, "config", "user.name", "Hal Test")
	seedFile := filepath.Join(seedDir, "tracked.txt")
	if err := os.WriteFile(seedFile, []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCommand(t, seedDir, "add", "tracked.txt")
	runGitCommand(t, seedDir, "commit", "-m", "base")
	runGitCommand(t, seedDir, "branch", "-M", "main")
	runGitCommand(t, seedDir, "remote", "add", "origin", remoteDir)
	runGitCommand(t, seedDir, "push", "-u", "origin", "main")
	if withRunBranch {
		runGitCommand(t, seedDir, "checkout", "-b", "hal/direct-sandbox-run")
		if err := os.WriteFile(seedFile, []byte("upstream run\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		runGitCommand(t, seedDir, "commit", "-am", "add run branch")
		runGitCommand(t, seedDir, "push", "origin", "hal/direct-sandbox-run")
		runGitCommand(t, seedDir, "checkout", "main")
	}
	runGitCommand(t, "", "clone", "--branch", "main", remoteDir, workspaceDir)
	return exactUpstreamRaceRepository{
		remoteDir:     remoteDir,
		seedDir:       seedDir,
		seedFile:      seedFile,
		workspaceDir:  workspaceDir,
		workspaceFile: filepath.Join(workspaceDir, "tracked.txt"),
	}
}

type mutatingGitBootstrapExecutor struct {
	calls        []BootstrapCommand
	mutateBefore func(BootstrapCommand) error
}

func (executor *mutatingGitBootstrapExecutor) Run(ctx context.Context, command BootstrapCommand) (BootstrapCommandResult, error) {
	executor.calls = append(executor.calls, command)
	if executor.mutateBefore != nil {
		if err := executor.mutateBefore(command); err != nil {
			return BootstrapCommandResult{}, err
		}
	}
	process := exec.CommandContext(ctx, command.Name, command.Args...)
	process.Dir = command.Dir
	process.Env = append([]string(nil), os.Environ()...)
	for key, value := range command.Env {
		process.Env = append(process.Env, key+"="+value)
	}
	output, err := process.CombinedOutput()
	result := BootstrapCommandResult{OutputSummary: string(output)}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	return result, err
}

func runGitCommand(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func assertFileContent(t *testing.T, filePath, want string) {
	t.Helper()
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != want {
		t.Fatalf("file content = %q, want %q", content, want)
	}
}

func assertBootstrapCheckoutHasNoForceFlag(t *testing.T, calls []BootstrapCommand, branch, upstream string) {
	t.Helper()
	for _, call := range calls {
		if call.Name != "git" || len(call.Args) == 0 || call.Args[0] != "checkout" || !testStringSliceContains(call.Args, branch) || !testStringSliceContains(call.Args, upstream) {
			continue
		}
		if testStringSliceContains(call.Args, "-f") {
			t.Fatalf("exact-upstream checkout args = %#v, must not force", call.Args)
		}
		return
	}
	t.Fatalf("exact-upstream checkout for %q from %q not found in %#v", branch, upstream, calls)
}

func testStringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertBootstrapCommand(t *testing.T, got BootstrapCommand, want BootstrapCommand) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bootstrap command mismatch\n got: %#v\nwant: %#v", got, want)
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
