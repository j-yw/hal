package factory

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBootstrapWorkspaceRunsDeterministicOrchestration(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "managed engine links cleaned"},
			{ExitCode: 0, OutputSummary: "repository fetched"},
			{ExitCode: 0, OutputSummary: "base checked out"},
			{ExitCode: 0, OutputSummary: "run branch created"},
			{ExitCode: 0, OutputSummary: "hal found"},
			{ExitCode: 0, OutputSummary: "codex found"},
			{ExitCode: 0, OutputSummary: "hal installed from checkout"},
			{ExitCode: 0, OutputSummary: "hal refreshed"},
			{ExitCode: 0, OutputSummary: "links refreshed"},
			{ExitCode: 0, OutputSummary: "doctor passed"},
		},
	}
	request := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		RunBranch:     "hal/factory-remote-workspace-bootstrap",
		WorkspaceDir:  "/workspace/hal",
		RequiredEnvKeys: []string{
			"HAL_ENGINE",
		},
		Env: map[string]string{
			"HAL_ENGINE": "codex",
		},
		Options: BootstrapOptions{
			RefreshHal: true,
		},
	}

	result, err := BootstrapWorkspace(context.Background(), request, BootstrapDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 8, 30, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == "/workspace/hal", nil
		},
		LocalBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			return false, nil
		},
		RemoteBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			return false, nil
		},
		EngineChecks: []BootstrapToolingCheck{
			{
				Name: "codex",
				Command: BootstrapCommand{
					Name: "codex",
					Args: []string{"--version"},
					Dir:  "/workspace/hal",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("BootstrapWorkspace() error = %v", err)
	}
	if result.RepoPath != "/workspace/hal" {
		t.Fatalf("repo path = %q, want /workspace/hal", result.RepoPath)
	}
	if result.CheckedOutBranch != "hal/factory-remote-workspace-bootstrap" {
		t.Fatalf("checked out branch = %q", result.CheckedOutBranch)
	}
	if result.Failure != nil {
		t.Fatalf("failure = %#v, want nil", result.Failure)
	}

	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepCleanEngineLinks,
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepCreateRunBranch,
		BootstrapStepVerifyHal,
		"verify_engine_codex",
		BootstrapStepInstallHal,
		BootstrapStepSetupHalTemplates,
		BootstrapStepRefreshHalSkills,
		BootstrapStepFinalCheckHalDoctor,
	})
	if len(result.Timeline) != len(result.Steps) {
		t.Fatalf("timeline events = %d, want one per step %d", len(result.Timeline), len(result.Steps))
	}

	gotSummaries := bootstrapCommandSummaries(executor.calls)
	wantSummaries := []string{
		"sh -lc " + bootstrapCleanEngineLinksScript,
		"git fetch --prune origin",
		"git checkout -f -B main origin/main",
		"git checkout -f -b hal/factory-remote-workspace-bootstrap main",
		"hal version",
		"codex --version",
		"sh -lc " + bootstrapInstallHalScript,
		"hal init --refresh-templates",
		"hal links refresh",
		"hal doctor --json",
	}
	if !reflect.DeepEqual(gotSummaries, wantSummaries) {
		t.Fatalf("command summaries mismatch\n got: %#v\nwant: %#v", gotSummaries, wantSummaries)
	}
	finalEnv := executor.calls[len(executor.calls)-1].Env
	if finalEnv["HAL_ENGINE"] != "codex" {
		t.Fatalf("final check HAL_ENGINE = %q, want codex", finalEnv["HAL_ENGINE"])
	}
}

func TestBootstrapWorkspaceIsIdempotentForPreparedFakeWorkspace(t *testing.T) {
	repoExists := false
	localBranches := map[string]bool{}
	executor := &statefulBootstrapExecutor{
		repoExists:    &repoExists,
		localBranches: localBranches,
	}
	request := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		RunBranch:     "hal/factory-remote-workspace-bootstrap",
		WorkspaceDir:  "/workspace/hal",
	}
	deps := BootstrapDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 8, 45, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return repoExists, nil
		},
		LocalBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			return localBranches[branch], nil
		},
		RemoteBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			return false, nil
		},
	}

	first, err := BootstrapWorkspace(context.Background(), request, deps)
	if err != nil {
		t.Fatalf("first BootstrapWorkspace() error = %v", err)
	}
	firstCalls := bootstrapCommandSummaries(executor.calls)
	if !containsCommandSummary(firstCalls, "git clone git@github.com:jywlabs/hal.git /workspace/hal") {
		t.Fatalf("first bootstrap did not clone missing repo: %#v", firstCalls)
	}
	if !containsCommandSummary(firstCalls, "git checkout -f -b hal/factory-remote-workspace-bootstrap main") {
		t.Fatalf("first bootstrap did not create run branch: %#v", firstCalls)
	}
	if first.CheckedOutBranch != "hal/factory-remote-workspace-bootstrap" {
		t.Fatalf("first checked out branch = %q", first.CheckedOutBranch)
	}

	firstCallCount := len(executor.calls)
	second, err := BootstrapWorkspace(context.Background(), request, deps)
	if err != nil {
		t.Fatalf("second BootstrapWorkspace() error = %v", err)
	}
	secondCalls := bootstrapCommandSummaries(executor.calls[firstCallCount:])
	if containsCommandPrefix(secondCalls, "git clone ") {
		t.Fatalf("second bootstrap recloned existing repo: %#v", secondCalls)
	}
	if containsCommandSummary(secondCalls, "git checkout -f -b hal/factory-remote-workspace-bootstrap main") {
		t.Fatalf("second bootstrap recreated local run branch: %#v", secondCalls)
	}
	if !containsCommandSummary(secondCalls, "git fetch --prune origin") {
		t.Fatalf("second bootstrap did not fetch existing repo: %#v", secondCalls)
	}
	if !containsCommandSummary(secondCalls, "git checkout -f hal/factory-remote-workspace-bootstrap") {
		t.Fatalf("second bootstrap did not reuse local run branch: %#v", secondCalls)
	}
	if second.CheckedOutBranch != "hal/factory-remote-workspace-bootstrap" {
		t.Fatalf("second checked out branch = %q", second.CheckedOutBranch)
	}
}

func TestBootstrapWorkspaceStopsOnFirstBlockingFailure(t *testing.T) {
	engineErr := errors.New("exit status 1")
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "managed engine links cleaned"},
			{ExitCode: 0, OutputSummary: "repository fetched"},
			{ExitCode: 0, OutputSummary: "base checked out"},
			{ExitCode: 0, OutputSummary: "run branch created"},
			{ExitCode: 0, OutputSummary: "hal found"},
			{ExitCode: 1, StderrSummary: "codex setup failed"},
		},
		errs: []error{nil, nil, nil, nil, nil, engineErr},
	}
	request := BootstrapRequest{
		RepositoryURL: "git@github.com:jywlabs/hal.git",
		BaseBranch:    "main",
		RunBranch:     "hal/factory-remote-workspace-bootstrap",
		WorkspaceDir:  "/workspace/hal",
	}

	result, err := BootstrapWorkspace(context.Background(), request, BootstrapDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 9, 0, 0, 0, time.UTC)),
		RepoExists: func(path string) (bool, error) {
			return path == "/workspace/hal", nil
		},
		LocalBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			return false, nil
		},
		RemoteBranchExists: func(_ context.Context, repoPath string, branch string) (bool, error) {
			return false, nil
		},
		EngineChecks: []BootstrapToolingCheck{
			{
				Name: "codex",
				Command: BootstrapCommand{
					Name: "codex",
					Args: []string{"--version"},
					Dir:  "/workspace/hal",
				},
			},
		},
	})
	if !errors.Is(err, engineErr) {
		t.Fatalf("BootstrapWorkspace() error = %v, want %v", err, engineErr)
	}
	if result.Failure == nil {
		t.Fatal("failure = nil, want classified failure")
	}
	if result.Failure.Category != BootstrapFailureCategoryEngineSetup {
		t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryEngineSetup)
	}
	assertBootstrapStepNames(t, result.Steps, []string{
		BootstrapStepCleanEngineLinks,
		BootstrapStepFetchRepository,
		BootstrapStepCheckoutBase,
		BootstrapStepCreateRunBranch,
		BootstrapStepVerifyHal,
		"verify_engine_codex",
	})

	gotSummaries := bootstrapCommandSummaries(executor.calls)
	if containsCommandSummary(gotSummaries, "hal init") || containsCommandSummary(gotSummaries, "hal doctor --json") {
		t.Fatalf("bootstrap continued after first failure: %#v", gotSummaries)
	}
}

func TestBootstrapWorkspaceValidatesRequiredEnvBeforeCommands(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "missing"},
		{name: "empty", env: map[string]string{"GITHUB_TOKEN": " \t "}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := &fakeBootstrapExecutor{}
			request := BootstrapRequest{
				RepositoryURL:   "git@github.com:jywlabs/hal.git",
				BaseBranch:      "main",
				RunBranch:       "hal/factory-remote-workspace-bootstrap",
				WorkspaceDir:    "/workspace/hal",
				RequiredEnvKeys: []string{"GITHUB_TOKEN"},
				Env:             tt.env,
			}

			result, err := BootstrapWorkspace(context.Background(), request, BootstrapDeps{
				Executor: executor,
				Now:      incrementingClock(t, time.Date(2026, 6, 21, 9, 15, 0, 0, time.UTC)),
				RepoExists: func(path string) (bool, error) {
					return path == "/workspace/hal", nil
				},
			})
			if !errors.Is(err, errBootstrapRequiredEnvMissing) {
				t.Fatalf("BootstrapWorkspace() error = %v, want %v", err, errBootstrapRequiredEnvMissing)
			}
			if len(executor.calls) != 0 {
				t.Fatalf("executor calls = %#v, want none", bootstrapCommandSummaries(executor.calls))
			}
			if result.Failure == nil {
				t.Fatal("failure = nil, want validation failure")
			}
			if result.Failure.Category != BootstrapFailureCategoryValidation {
				t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryValidation)
			}
			assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepValidateRequest})
		})
	}
}

func TestBootstrapWorkspaceClassifiesRepositoryPlanningValidationFailures(t *testing.T) {
	tests := []struct {
		name       string
		request    BootstrapRequest
		wantErr    error
		repoExists func(path string) (bool, error)
	}{
		{
			name: "missing base branch",
			request: BootstrapRequest{
				RepositoryURL: "git@github.com:jywlabs/hal.git",
				WorkspaceDir:  "/workspace/hal",
			},
			wantErr: errBootstrapBaseBranchRequired,
		},
		{
			name: "missing repository url",
			request: BootstrapRequest{
				BaseBranch:   "main",
				WorkspaceDir: "/workspace/hal",
			},
			wantErr: errBootstrapRepositoryURLRequired,
			repoExists: func(path string) (bool, error) {
				return false, nil
			},
		},
		{
			name: "missing workspace dir",
			request: BootstrapRequest{
				RepositoryURL: "git@github.com:jywlabs/hal.git",
				BaseBranch:    "main",
			},
			wantErr: errBootstrapWorkspaceDirRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := &fakeBootstrapExecutor{}
			repoExists := tt.repoExists
			if repoExists == nil {
				repoExists = func(path string) (bool, error) {
					t.Fatalf("repoExists(%q) called before request validation completed", path)
					return false, nil
				}
			}

			result, err := BootstrapWorkspace(context.Background(), tt.request, BootstrapDeps{
				Executor:   executor,
				Now:        incrementingClock(t, time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)),
				RepoExists: repoExists,
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("BootstrapWorkspace() error = %v, want %v", err, tt.wantErr)
			}
			if len(executor.calls) != 0 {
				t.Fatalf("executor calls = %#v, want none", bootstrapCommandSummaries(executor.calls))
			}
			if result.Failure == nil {
				t.Fatal("failure = nil, want validation failure")
			}
			if result.Failure.Category != BootstrapFailureCategoryValidation {
				t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryValidation)
			}
			assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepValidateRequest})
			if len(result.Timeline) != 1 {
				t.Fatalf("timeline events = %d, want 1", len(result.Timeline))
			}
			if result.Timeline[0].Metadata[bootstrapTimelineFailureCategoryKey] != BootstrapFailureCategoryValidation {
				t.Fatalf("timeline failure category = %q, want %q", result.Timeline[0].Metadata[bootstrapTimelineFailureCategoryKey], BootstrapFailureCategoryValidation)
			}
		})
	}
}

type statefulBootstrapExecutor struct {
	calls         []BootstrapCommand
	repoExists    *bool
	localBranches map[string]bool
}

func (f *statefulBootstrapExecutor) Run(_ context.Context, command BootstrapCommand) (BootstrapCommandResult, error) {
	f.calls = append(f.calls, command)
	if command.Name == "git" && len(command.Args) > 0 {
		switch command.Args[0] {
		case "clone":
			*f.repoExists = true
		case "checkout":
			for i, arg := range command.Args {
				if arg == "-b" && i+1 < len(command.Args) {
					f.localBranches[command.Args[i+1]] = true
					break
				}
			}
		}
	}
	return BootstrapCommandResult{ExitCode: 0}, nil
}

func bootstrapCommandSummaries(commands []BootstrapCommand) []string {
	summaries := make([]string, 0, len(commands))
	for _, command := range commands {
		summaries = append(summaries, command.Summary())
	}
	return summaries
}

func containsCommandSummary(summaries []string, want string) bool {
	for _, summary := range summaries {
		if summary == want {
			return true
		}
	}
	return false
}

func containsCommandPrefix(summaries []string, prefix string) bool {
	for _, summary := range summaries {
		if strings.HasPrefix(summary, prefix) {
			return true
		}
	}
	return false
}
