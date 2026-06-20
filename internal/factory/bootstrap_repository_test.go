package factory

import (
	"context"
	"errors"
	"reflect"
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
			Args: []string{"checkout", "develop"},
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
			Args: []string{"checkout", "main"},
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
			Args: []string{"checkout", "main"},
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
			Args: []string{"checkout", "main"},
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
			Args: []string{"checkout", "main"},
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
	}, 1)
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
	}, 1)
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
