package factory

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type fakeBootstrapExecutor struct {
	calls   []BootstrapCommand
	results []BootstrapCommandResult
	errs    []error
}

func (f *fakeBootstrapExecutor) Run(_ context.Context, command BootstrapCommand) (BootstrapCommandResult, error) {
	f.calls = append(f.calls, command)

	var result BootstrapCommandResult
	if len(f.results) > 0 {
		result = f.results[0]
		f.results = f.results[1:]
	}

	var err error
	if len(f.errs) > 0 {
		err = f.errs[0]
		f.errs = f.errs[1:]
	}

	return result, err
}

func TestRunBootstrapStepUsesInjectedExecutor(t *testing.T) {
	startedAt := time.Date(2026, 6, 21, 1, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)
	times := []time.Time{startedAt, finishedAt, finishedAt.Add(time.Second), finishedAt.Add(3 * time.Second)}
	now := func() time.Time {
		t.Helper()
		if len(times) == 0 {
			t.Fatal("unexpected clock call")
		}
		next := times[0]
		times = times[1:]
		return next
	}

	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{
				ExitCode:      0,
				OutputSummary: "cloned repository",
				Metadata: map[string]string{
					"remote": "origin",
				},
			},
			{
				ExitCode:      0,
				OutputSummary: "checked out branch",
			},
		},
	}
	deps := BootstrapStepDeps{
		Executor: executor,
		Now:      now,
	}

	clone := BootstrapCommand{
		Name: "git",
		Args: []string{"clone", "git@github.com:jywlabs/hal.git", "/workspace/hal"},
		Dir:  "/workspace",
		Env: map[string]string{
			"GIT_TERMINAL_PROMPT": "0",
		},
	}
	step, result, failure, err := RunBootstrapStep(context.Background(), deps, "clone", clone)
	if err != nil {
		t.Fatalf("RunBootstrapStep() error = %v", err)
	}
	if failure != nil {
		t.Fatalf("failure = %#v, want nil", failure)
	}
	if step.Name != "clone" {
		t.Fatalf("step name = %q, want clone", step.Name)
	}
	if step.Status != RunStatusSucceeded {
		t.Fatalf("step status = %q, want %q", step.Status, RunStatusSucceeded)
	}
	if step.CommandSummary != "git clone git@github.com:jywlabs/hal.git /workspace/hal" {
		t.Fatalf("command summary = %q", step.CommandSummary)
	}
	if !step.StartedAt.Equal(startedAt) {
		t.Fatalf("startedAt = %s, want %s", step.StartedAt, startedAt)
	}
	if step.FinishedAt == nil || !step.FinishedAt.Equal(finishedAt) {
		t.Fatalf("finishedAt = %v, want %s", step.FinishedAt, finishedAt)
	}
	if result.OutputSummary != "cloned repository" {
		t.Fatalf("result output summary = %q", result.OutputSummary)
	}

	checkout := BootstrapCommand{
		Name: "git",
		Args: []string{"checkout", "main"},
		Dir:  "/workspace/hal",
		Env: map[string]string{
			"GIT_TERMINAL_PROMPT": "0",
		},
	}
	if _, _, _, err := RunBootstrapStep(context.Background(), deps, "checkout_base", checkout); err != nil {
		t.Fatalf("RunBootstrapStep(checkout) error = %v", err)
	}

	wantCalls := []BootstrapCommand{clone, checkout}
	if !reflect.DeepEqual(executor.calls, wantCalls) {
		t.Fatalf("executor calls mismatch\n got: %#v\nwant: %#v", executor.calls, wantCalls)
	}
}

func TestRunBootstrapStepClassifiesExecutorFailure(t *testing.T) {
	startedAt := time.Date(2026, 6, 21, 2, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	times := []time.Time{startedAt, finishedAt}
	now := func() time.Time {
		t.Helper()
		if len(times) == 0 {
			t.Fatal("unexpected clock call")
		}
		next := times[0]
		times = times[1:]
		return next
	}

	executorErr := errors.New("exit status 128")
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{
				ExitCode:      128,
				StderrSummary: "fatal: couldn't find remote ref missing",
			},
		},
		errs: []error{executorErr},
	}

	command := BootstrapCommand{
		Name: "git",
		Args: []string{"fetch", "origin", "missing"},
		Dir:  "/workspace/hal",
	}
	step, result, failure, err := RunBootstrapStep(context.Background(), BootstrapStepDeps{Executor: executor, Now: now}, "fetch", command)
	if !errors.Is(err, executorErr) {
		t.Fatalf("RunBootstrapStep() error = %v, want %v", err, executorErr)
	}
	if step.Status != RunStatusFailed {
		t.Fatalf("step status = %q, want %q", step.Status, RunStatusFailed)
	}
	if step.ExitCode != 128 {
		t.Fatalf("step exit code = %d, want 128", step.ExitCode)
	}
	if result.StderrSummary == "" {
		t.Fatal("expected sanitized stderr summary in result")
	}
	if failure == nil {
		t.Fatal("failure = nil, want classified failure")
	}
	if failure.Category != BootstrapFailureCategoryRepo {
		t.Fatalf("failure category = %q, want %q", failure.Category, BootstrapFailureCategoryRepo)
	}
	if failure.Message != "repository bootstrap failed while running git fetch" {
		t.Fatalf("failure message = %q", failure.Message)
	}
}

func TestRunBootstrapStepTreatsNonzeroExitCodeAsFailure(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{
				ExitCode:      2,
				OutputSummary: "unexpected process failure",
			},
		},
	}

	step, _, failure, err := RunBootstrapStep(
		context.Background(),
		BootstrapStepDeps{Executor: executor, Now: func() time.Time { return time.Date(2026, 6, 21, 2, 30, 0, 0, time.UTC) }},
		"custom",
		BootstrapCommand{Name: "make", Args: []string{"bootstrap"}},
	)
	if err == nil {
		t.Fatal("RunBootstrapStep() error = nil, want nonzero exit error")
	}
	if step.Status != RunStatusFailed {
		t.Fatalf("step status = %q, want %q", step.Status, RunStatusFailed)
	}
	if failure == nil {
		t.Fatal("failure = nil, want classified failure")
	}
	if failure.Category != BootstrapFailureCategoryUnknown {
		t.Fatalf("failure category = %q, want %q", failure.Category, BootstrapFailureCategoryUnknown)
	}
}

func TestRunBootstrapStepRequiresExecutor(t *testing.T) {
	now := func() time.Time {
		return time.Date(2026, 6, 21, 3, 0, 0, 0, time.UTC)
	}

	step, _, failure, err := RunBootstrapStep(context.Background(), BootstrapStepDeps{Now: now}, "verify", BootstrapCommand{Name: "hal", Args: []string{"version"}})
	if !errors.Is(err, errBootstrapExecutorRequired) {
		t.Fatalf("RunBootstrapStep() error = %v, want %v", err, errBootstrapExecutorRequired)
	}
	if step.Status != RunStatusFailed {
		t.Fatalf("step status = %q, want %q", step.Status, RunStatusFailed)
	}
	if failure == nil {
		t.Fatal("failure = nil, want classified failure")
	}
	if failure.Category != BootstrapFailureCategoryUnknown {
		t.Fatalf("failure category = %q, want %q", failure.Category, BootstrapFailureCategoryUnknown)
	}
}
