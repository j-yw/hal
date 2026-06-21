package factory

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
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

func TestRunBootstrapStepInjectsRequestEnvironmentAndSanitizesResult(t *testing.T) {
	secret := "ghp_fixture_secret_value_12345"
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{
				ExitCode:      0,
				OutputSummary: "using GITHUB_TOKEN=" + secret,
				Metadata: map[string]string{
					"GITHUB_TOKEN": secret,
					"engine":       "codex",
				},
			},
		},
	}
	request := BootstrapRequest{
		RequiredEnvKeys: []string{"GITHUB_TOKEN"},
		Env: map[string]string{
			"GITHUB_TOKEN": secret,
			"HAL_ENGINE":   "codex",
		},
	}

	command := BootstrapCommand{
		Name: "hal",
		Args: []string{"init"},
		Dir:  "/workspace/hal",
		Env: map[string]string{
			"HAL_ENGINE": "override-engine",
		},
	}
	step, result, failure, err := RunBootstrapStep(
		context.Background(),
		BootstrapStepDeps{
			Executor: executor,
			Now:      incrementingClock(t, time.Date(2026, 6, 21, 8, 0, 0, 0, time.UTC)),
			Request:  request,
		},
		"setup_hal_templates",
		command,
	)
	if err != nil {
		t.Fatalf("RunBootstrapStep() error = %v", err)
	}
	if failure != nil {
		t.Fatalf("failure = %#v, want nil", failure)
	}

	if len(executor.calls) != 1 {
		t.Fatalf("executor calls = %d, want 1", len(executor.calls))
	}
	gotEnv := executor.calls[0].Env
	if gotEnv["GITHUB_TOKEN"] != secret {
		t.Fatalf("GITHUB_TOKEN = %q, want secret value", gotEnv["GITHUB_TOKEN"])
	}
	if gotEnv["HAL_ENGINE"] != "override-engine" {
		t.Fatalf("HAL_ENGINE = %q, want command env to override request env", gotEnv["HAL_ENGINE"])
	}
	if strings.Contains(step.CommandSummary, secret) || strings.Contains(step.CommandSummary, "GITHUB_TOKEN") {
		t.Fatalf("command summary leaked sensitive environment data: %q", step.CommandSummary)
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(result) error = %v", err)
	}
	assertDoesNotContainSensitiveFixture(t, data, secret)
}

func TestBootstrapSanitizersRedactTimelineAndCommandRecords(t *testing.T) {
	secret := "github_pat_fixture_secret_value_67890"
	request := BootstrapRequest{
		RequiredEnvKeys: []string{"GITHUB_TOKEN"},
		Env: map[string]string{
			"GITHUB_TOKEN": secret,
			"HAL_ENGINE":   "codex",
		},
	}

	command := SanitizeBootstrapCommand(request, BootstrapCommand{
		Name: "git",
		Args: []string{"clone", "https://" + secret + "@github.com/jywlabs/hal.git"},
		Dir:  "/workspace/hal",
		Env: map[string]string{
			"GITHUB_TOKEN": secret,
			"HAL_ENGINE":   "codex",
		},
	})
	commandData, err := json.Marshal(command)
	if err != nil {
		t.Fatalf("json.Marshal(command) error = %v", err)
	}
	assertDoesNotContainSensitiveFixture(t, commandData, secret)

	event := SanitizeBootstrapTimelineEvent(request, BootstrapTimelineEvent{
		Timestamp:      time.Date(2026, 6, 21, 8, 10, 0, 0, time.UTC),
		Step:           "clone_repository",
		Status:         RunStatusFailed,
		Message:        "GITHUB_TOKEN failed authentication",
		CommandSummary: "git clone https://" + secret + "@github.com/jywlabs/hal.git",
		OutputSummary:  "remote rejected " + secret,
		Metadata: map[string]string{
			"GITHUB_TOKEN": secret,
			"engine":       "codex",
		},
	})
	eventData, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal(event) error = %v", err)
	}
	assertDoesNotContainSensitiveFixture(t, eventData, secret)
}

func TestRunBootstrapStepRedactsResolvedRunSecretValuesFromRecords(t *testing.T) {
	secret := "ghp_run_scoped_bootstrap_secret_12345"
	request := BootstrapRequestWithResolvedSecrets(BootstrapRequest{}, []ResolvedRunSecret{{
		Name:     "GITHUB_TOKEN",
		Source:   RunSecretSourceEnv,
		Required: true,
		Value:    secret,
	}})
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{{
			ExitCode:      0,
			OutputSummary: "bootstrap output used " + secret,
			Metadata: map[string]string{
				"remote": "https://" + secret + "@github.com/example/repo.git",
			},
		}},
	}

	step, result, failure, err := RunBootstrapStep(
		context.Background(),
		BootstrapStepDeps{
			Executor: executor,
			Now:      incrementingClock(t, time.Date(2026, 6, 21, 8, 20, 0, 0, time.UTC)),
			Request:  request,
		},
		"clone_repository",
		BootstrapCommand{
			Name: "git",
			Args: []string{"clone", "https://" + secret + "@github.com/example/repo.git"},
		},
	)
	if err != nil {
		t.Fatalf("RunBootstrapStep() error = %v", err)
	}
	if failure != nil {
		t.Fatalf("failure = %#v, want nil", failure)
	}
	if strings.Contains(step.CommandSummary, secret) {
		t.Fatalf("command summary leaked secret: %q", step.CommandSummary)
	}
	if !strings.Contains(step.CommandSummary, bootstrapRedactedValue) {
		t.Fatalf("command summary missing redaction marker: %q", step.CommandSummary)
	}

	resultData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(result) error = %v", err)
	}
	if strings.Contains(string(resultData), secret) {
		t.Fatalf("bootstrap command result leaked secret: %s", string(resultData))
	}
	if !strings.Contains(string(resultData), bootstrapRedactedValue) {
		t.Fatalf("bootstrap command result missing redaction marker: %s", string(resultData))
	}

	event := BootstrapTimelineEventFromStep(request, step, result, nil)
	eventData, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal(event) error = %v", err)
	}
	if strings.Contains(string(eventData), secret) {
		t.Fatalf("bootstrap timeline event leaked secret: %s", string(eventData))
	}

	requestData, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("json.Marshal(request) error = %v", err)
	}
	if strings.Contains(string(requestData), secret) {
		t.Fatalf("bootstrap request JSON leaked in-memory secret value: %s", string(requestData))
	}
}

func TestRunBootstrapStepRedactsMultilineSecretFragments(t *testing.T) {
	envFragment := "env_private_key_fragment"
	resolvedFragment := "resolved_private_key_fragment"
	envSecret := "-----BEGIN PRIVATE KEY-----\n" + envFragment + "\n-----END PRIVATE KEY-----"
	resolvedSecret := "-----BEGIN PRIVATE KEY-----\n" + resolvedFragment + "\n-----END PRIVATE KEY-----"
	request := BootstrapRequestWithResolvedSecrets(BootstrapRequest{
		Env: map[string]string{
			"PRIVATE_KEY": envSecret,
		},
	}, []ResolvedRunSecret{{
		Name:     "SSH_PRIVATE_KEY",
		Source:   RunSecretSourceEnv,
		Required: true,
		Value:    resolvedSecret,
	}})
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{{
			ExitCode:      0,
			OutputSummary: "bootstrap emitted " + envFragment + " and " + resolvedFragment,
			Metadata: map[string]string{
				"envFragment":      envFragment,
				"resolvedFragment": resolvedFragment,
			},
		}},
	}

	step, result, failure, err := RunBootstrapStep(
		context.Background(),
		BootstrapStepDeps{
			Executor: executor,
			Now:      incrementingClock(t, time.Date(2026, 6, 21, 8, 30, 0, 0, time.UTC)),
			Request:  request,
		},
		"setup_private_key",
		BootstrapCommand{
			Name: "sh",
			Args: []string{"-c", "printf %s " + envFragment + " " + resolvedFragment},
		},
	)
	if err != nil {
		t.Fatalf("RunBootstrapStep() error = %v", err)
	}
	if failure != nil {
		t.Fatalf("failure = %#v, want nil", failure)
	}

	event := SanitizeBootstrapTimelineEvent(request, BootstrapTimelineEvent{
		Timestamp:      time.Date(2026, 6, 21, 8, 31, 0, 0, time.UTC),
		Step:           "setup_private_key",
		Status:         RunStatusSucceeded,
		CommandSummary: "sh -c printf %s " + envFragment + " " + resolvedFragment,
		OutputSummary:  "bootstrap emitted " + envFragment + " and " + resolvedFragment,
		Metadata: map[string]string{
			"envFragment":      envFragment,
			"resolvedFragment": resolvedFragment,
		},
	})

	for name, value := range map[string]string{
		"step":   step.CommandSummary,
		"result": result.OutputSummary + " " + result.Metadata["envFragment"] + " " + result.Metadata["resolvedFragment"],
		"event":  event.CommandSummary + " " + event.OutputSummary + " " + event.Metadata["envFragment"] + " " + event.Metadata["resolvedFragment"],
	} {
		if strings.Contains(value, envFragment) || strings.Contains(value, resolvedFragment) {
			t.Fatalf("%s leaked multiline secret fragment: %q", name, value)
		}
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

func assertDoesNotContainSensitiveFixture(t *testing.T, data []byte, secret string) {
	t.Helper()
	payload := string(data)
	for _, unexpected := range []string{secret, "GITHUB_TOKEN"} {
		if strings.Contains(payload, unexpected) {
			t.Fatalf("serialized payload leaked %q: %s", unexpected, payload)
		}
	}
	if !strings.Contains(payload, bootstrapRedactedValue) {
		t.Fatalf("serialized payload missing redaction marker: %s", payload)
	}
}
