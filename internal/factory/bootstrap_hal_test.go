package factory

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func TestBootstrapRefreshHalRefreshesTemplatesAndSkillLinks(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "hal installed from checkout"},
			{ExitCode: 0, OutputSummary: "hal templates refreshed"},
			{ExitCode: 0, OutputSummary: "hal skill links refreshed"},
		},
	}
	req := BootstrapRequest{
		WorkspaceDir: "/workspace/hal",
		Options: BootstrapOptions{
			RefreshHal: true,
		},
	}

	result, err := BootstrapRefreshHal(context.Background(), req, BootstrapHalDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 7, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("BootstrapRefreshHal() error = %v", err)
	}
	if result.RepoPath != "/workspace/hal" {
		t.Fatalf("repo path = %q, want /workspace/hal", result.RepoPath)
	}
	if result.Failure != nil {
		t.Fatalf("failure = %#v, want nil", result.Failure)
	}

	wantCalls := []BootstrapCommand{
		{
			Name: "sh",
			Args: []string{"-lc", bootstrapInstallHalScript},
			Dir:  "/workspace/hal",
		},
		{
			Name: "hal",
			Args: []string{"init", "--refresh-templates"},
			Dir:  "/workspace/hal",
		},
		{
			Name: "hal",
			Args: []string{"links", "refresh"},
			Dir:  "/workspace/hal",
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepInstallHal, BootstrapStepSetupHalTemplates, BootstrapStepRefreshHalSkills})
	for _, step := range result.Steps {
		if step.Status != RunStatusSucceeded {
			t.Fatalf("step %q status = %q, want %q", step.Name, step.Status, RunStatusSucceeded)
		}
		if step.CommandSummary == "" {
			t.Fatalf("step %q missing command summary", step.Name)
		}
	}
}

func TestBootstrapRefreshHalInitializesWithoutRefreshFlagByDefault(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0},
			{ExitCode: 0},
			{ExitCode: 0},
		},
	}

	_, err := BootstrapRefreshHal(context.Background(), BootstrapRequest{WorkspaceDir: "/workspace/hal"}, BootstrapHalDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 7, 10, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("BootstrapRefreshHal() error = %v", err)
	}

	wantCalls := []BootstrapCommand{
		{
			Name: "sh",
			Args: []string{"-lc", bootstrapInstallHalScript},
			Dir:  "/workspace/hal",
		},
		{
			Name: "hal",
			Args: []string{"init"},
			Dir:  "/workspace/hal",
		},
		{
			Name: "hal",
			Args: []string{"links", "refresh"},
			Dir:  "/workspace/hal",
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}
}

func TestBootstrapRefreshHalDryRunPlansCommandsWithoutExecutor(t *testing.T) {
	req := BootstrapRequest{
		WorkspaceDir: "/workspace/hal",
		Options: BootstrapOptions{
			DryRun:     true,
			RefreshHal: true,
		},
	}

	result, err := BootstrapRefreshHal(context.Background(), req, BootstrapHalDeps{
		Now: incrementingClock(t, time.Date(2026, 6, 21, 7, 20, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("BootstrapRefreshHal() error = %v", err)
	}
	if result.Failure != nil {
		t.Fatalf("failure = %#v, want nil", result.Failure)
	}
	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepInstallHal, BootstrapStepSetupHalTemplates, BootstrapStepRefreshHalSkills})
	for _, step := range result.Steps {
		if step.Status != RunStatusPending {
			t.Fatalf("step %q status = %q, want %q", step.Name, step.Status, RunStatusPending)
		}
	}
	if result.Steps[0].CommandSummary != "sh -lc "+bootstrapInstallHalScript {
		t.Fatalf("first command summary = %q", result.Steps[0].CommandSummary)
	}
	if result.Steps[1].CommandSummary != "hal init --refresh-templates" {
		t.Fatalf("second command summary = %q", result.Steps[1].CommandSummary)
	}
	if result.Steps[2].CommandSummary != "hal links refresh" {
		t.Fatalf("third command summary = %q", result.Steps[2].CommandSummary)
	}
}

func TestBootstrapRefreshHalClassifiesInstallFailureAsEngineSetup(t *testing.T) {
	setupErr := errors.New("exit status 1")
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 1, StderrSummary: "failed to install hal"},
		},
		errs: []error{setupErr},
	}

	result, err := BootstrapRefreshHal(context.Background(), BootstrapRequest{WorkspaceDir: "/workspace/hal"}, BootstrapHalDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 7, 30, 0, 0, time.UTC)),
	})
	if !errors.Is(err, setupErr) {
		t.Fatalf("BootstrapRefreshHal() error = %v, want %v", err, setupErr)
	}
	if result.Failure == nil {
		t.Fatal("failure = nil, want classified failure")
	}
	if result.Failure.Category != BootstrapFailureCategoryEngineSetup {
		t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryEngineSetup)
	}
	if result.Failure.Message != "Hal or engine setup failed while running sh" {
		t.Fatalf("failure message = %q", result.Failure.Message)
	}
	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepInstallHal})
}

func TestBootstrapRefreshHalClassifiesMissingHalAsDependency(t *testing.T) {
	missingHal := &exec.Error{Name: "hal", Err: exec.ErrNotFound}
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "hal installed"},
			{ExitCode: 0, StderrSummary: "executable file not found"},
		},
		errs: []error{nil, missingHal},
	}

	result, err := BootstrapRefreshHal(context.Background(), BootstrapRequest{WorkspaceDir: "/workspace/hal"}, BootstrapHalDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 7, 40, 0, 0, time.UTC)),
	})
	if !errors.Is(err, missingHal) {
		t.Fatalf("BootstrapRefreshHal() error = %v, want %v", err, missingHal)
	}
	if result.Failure == nil {
		t.Fatal("failure = nil, want classified failure")
	}
	if result.Failure.Category != BootstrapFailureCategoryDependency {
		t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryDependency)
	}
	if result.Failure.Message != "required bootstrap command not found: hal" {
		t.Fatalf("failure message = %q", result.Failure.Message)
	}
}

func TestBootstrapRefreshHalRequiresWorkspaceDir(t *testing.T) {
	_, err := BootstrapRefreshHal(context.Background(), BootstrapRequest{}, BootstrapHalDeps{})
	if !errors.Is(err, errBootstrapWorkspaceDirRequired) {
		t.Fatalf("BootstrapRefreshHal() error = %v, want %v", err, errBootstrapWorkspaceDirRequired)
	}
}
