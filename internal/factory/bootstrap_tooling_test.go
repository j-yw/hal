package factory

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func TestBootstrapVerifyToolingChecksHalAndEngineCommands(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "hal version found"},
			{ExitCode: 0, OutputSummary: "codex version found"},
		},
	}
	req := BootstrapRequest{
		WorkspaceDir: "/workspace/hal",
	}

	result, err := BootstrapVerifyTooling(context.Background(), req, BootstrapToolingDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 6, 0, 0, 0, time.UTC)),
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
		t.Fatalf("BootstrapVerifyTooling() error = %v", err)
	}
	if result.RepoPath != "/workspace/hal" {
		t.Fatalf("repo path = %q, want /workspace/hal", result.RepoPath)
	}
	if result.Failure != nil {
		t.Fatalf("failure = %#v, want nil", result.Failure)
	}

	wantCalls := []BootstrapCommand{
		{
			Name: "hal",
			Args: []string{"--version"},
			Dir:  "/workspace/hal",
		},
		{
			Name: "codex",
			Args: []string{"--version"},
			Dir:  "/workspace/hal",
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepVerifyHal, "verify_engine_codex"})
	for _, step := range result.Steps {
		if step.Status != RunStatusSucceeded {
			t.Fatalf("step %q status = %q, want %q", step.Name, step.Status, RunStatusSucceeded)
		}
		if step.CommandSummary == "" {
			t.Fatalf("step %q missing command summary", step.Name)
		}
	}
}

func TestBootstrapVerifyToolingInstallsMissingHalWhenEnabled(t *testing.T) {
	missingHal := &exec.Error{Name: "hal", Err: exec.ErrNotFound}
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, StderrSummary: "executable file not found"},
			{ExitCode: 0, OutputSummary: "hal installed"},
			{ExitCode: 0, OutputSummary: "hal version found"},
		},
		errs: []error{missingHal},
	}
	req := BootstrapRequest{
		WorkspaceDir: "/workspace/hal",
		Options: BootstrapOptions{
			InstallMissingCLIs: true,
		},
	}

	result, err := BootstrapVerifyTooling(context.Background(), req, BootstrapToolingDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 6, 10, 0, 0, time.UTC)),
		HalCheck: BootstrapToolingCheck{
			Name: "hal",
			Command: BootstrapCommand{
				Name: "hal",
				Args: []string{"--version"},
				Dir:  "/workspace/hal",
			},
			InstallCommand: &BootstrapCommand{
				Name: "brew",
				Args: []string{"install", "hal"},
				Dir:  "/workspace/hal",
			},
		},
	})
	if err != nil {
		t.Fatalf("BootstrapVerifyTooling() error = %v", err)
	}
	if result.Failure != nil {
		t.Fatalf("failure = %#v, want nil", result.Failure)
	}

	wantCalls := []BootstrapCommand{
		{
			Name: "hal",
			Args: []string{"--version"},
			Dir:  "/workspace/hal",
		},
		{
			Name: "brew",
			Args: []string{"install", "hal"},
			Dir:  "/workspace/hal",
		},
		{
			Name: "hal",
			Args: []string{"--version"},
			Dir:  "/workspace/hal",
		},
	}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}

	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepVerifyHal, BootstrapStepInstallHal, BootstrapStepVerifyHal + "_after_install"})
	if result.Steps[0].Status != RunStatusFailed {
		t.Fatalf("initial hal step status = %q, want %q", result.Steps[0].Status, RunStatusFailed)
	}
	for _, step := range result.Steps[1:] {
		if step.Status != RunStatusSucceeded {
			t.Fatalf("step %q status = %q, want %q", step.Name, step.Status, RunStatusSucceeded)
		}
	}
}

func TestBootstrapVerifyToolingClassifiesMissingEngineDependency(t *testing.T) {
	missingCodex := &exec.Error{Name: "codex", Err: exec.ErrNotFound}
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, OutputSummary: "hal version found"},
			{ExitCode: 0, StderrSummary: "executable file not found"},
		},
		errs: []error{nil, missingCodex},
	}

	result, err := BootstrapVerifyTooling(context.Background(), BootstrapRequest{}, BootstrapToolingDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 6, 20, 0, 0, time.UTC)),
		EngineChecks: []BootstrapToolingCheck{
			{
				Name: "codex",
				Command: BootstrapCommand{
					Name: "codex",
					Args: []string{"--version"},
				},
			},
		},
	})
	if !errors.Is(err, missingCodex) {
		t.Fatalf("BootstrapVerifyTooling() error = %v, want %v", err, missingCodex)
	}
	if result.Failure == nil {
		t.Fatal("failure = nil, want classified failure")
	}
	if result.Failure.Category != BootstrapFailureCategoryDependency {
		t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryDependency)
	}
	if result.Failure.Message != "required bootstrap command not found: codex" {
		t.Fatalf("failure message = %q", result.Failure.Message)
	}
	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepVerifyHal, "verify_engine_codex"})
}

func TestBootstrapVerifyToolingClassifiesFailedHalInstallAsEngineSetup(t *testing.T) {
	missingHal := &exec.Error{Name: "hal", Err: exec.ErrNotFound}
	installErr := errors.New("exit status 1")
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{ExitCode: 0, StderrSummary: "executable file not found"},
			{ExitCode: 1, StderrSummary: "failed to install hal"},
		},
		errs: []error{missingHal, installErr},
	}
	req := BootstrapRequest{
		Options: BootstrapOptions{
			InstallMissingCLIs: true,
		},
	}

	result, err := BootstrapVerifyTooling(context.Background(), req, BootstrapToolingDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 6, 30, 0, 0, time.UTC)),
		HalCheck: BootstrapToolingCheck{
			Name: "hal",
			Command: BootstrapCommand{
				Name: "hal",
				Args: []string{"--version"},
			},
			InstallCommand: &BootstrapCommand{
				Name: "brew",
				Args: []string{"install", "hal"},
			},
		},
	})
	if !errors.Is(err, installErr) {
		t.Fatalf("BootstrapVerifyTooling() error = %v, want %v", err, installErr)
	}
	if result.Failure == nil {
		t.Fatal("failure = nil, want classified failure")
	}
	if result.Failure.Category != BootstrapFailureCategoryEngineSetup {
		t.Fatalf("failure category = %q, want %q", result.Failure.Category, BootstrapFailureCategoryEngineSetup)
	}
	if result.Failure.Message != "Hal or engine setup failed while running brew" {
		t.Fatalf("failure message = %q", result.Failure.Message)
	}
	assertBootstrapStepNames(t, result.Steps, []string{BootstrapStepVerifyHal, BootstrapStepInstallHal})
}
