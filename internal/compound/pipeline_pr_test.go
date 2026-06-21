package compound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/engine"
)

func newPRStepTestPipeline(t *testing.T) (*Pipeline, *bytes.Buffer) {
	t.Helper()

	origCheckCIDependencies := checkCIDependencies
	checkCIDependencies = func() error { return nil }
	t.Cleanup(func() { checkCIDependencies = origCheckCIDependencies })

	var out bytes.Buffer
	display := engine.NewDisplay(&out)
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, display, t.TempDir())

	return pipeline, &out
}

// stubCIWaitPassing replaces the package-level waitForChecksInDirFn with a stub
// that returns passing status. Returns a cleanup function.
func stubCIWaitPassing(t *testing.T) {
	t.Helper()
	orig := waitForChecksInDirFn
	waitForChecksInDirFn = func(_ context.Context, _ string, _ ci.WaitOptions) (ci.StatusResult, error) {
		return ci.StatusResult{
			Status:           ci.StatusPassing,
			ChecksDiscovered: true,
		}, nil
	}
	t.Cleanup(func() { waitForChecksInDirFn = orig })
}

// stubCIWaitFailing replaces waitForChecksInDirFn with a stub that returns failing
// status on the first call, then passing on subsequent calls.
func stubCIWaitFailThenPass(t *testing.T) {
	t.Helper()
	orig := waitForChecksInDirFn
	calls := 0
	waitForChecksInDirFn = func(_ context.Context, _ string, _ ci.WaitOptions) (ci.StatusResult, error) {
		calls++
		if calls == 1 {
			return ci.StatusResult{
				Status:           ci.StatusFailing,
				ChecksDiscovered: true,
				Summary:          "status=failing (passing=0, failing=1, pending=0)",
				Checks: []ci.StatusCheck{
					{Key: "check:build", Name: "build", Status: ci.StatusFailing},
				},
			}, nil
		}
		return ci.StatusResult{
			Status:           ci.StatusPassing,
			ChecksDiscovered: true,
		}, nil
	}
	t.Cleanup(func() { waitForChecksInDirFn = orig })
}

func stubCIFixSuccess(t *testing.T) {
	t.Helper()
	orig := fixWithEngineInDirFn
	fixWithEngineInDirFn = func(_ context.Context, _ string, _ ci.StatusResult, opts ci.FixOptions) (ci.FixResult, error) {
		return ci.FixResult{
			Applied:      true,
			Attempt:      opts.Attempt,
			FilesChanged: []string{"main.go"},
			Pushed:       true,
		}, nil
	}
	t.Cleanup(func() { fixWithEngineInDirFn = orig })
}

func stubCIWaitNoChecks(t *testing.T) {
	t.Helper()
	orig := waitForChecksInDirFn
	waitForChecksInDirFn = func(_ context.Context, _ string, _ ci.WaitOptions) (ci.StatusResult, error) {
		return ci.StatusResult{
			Status:           ci.StatusPending,
			ChecksDiscovered: false,
		}, nil
	}
	t.Cleanup(func() { waitForChecksInDirFn = orig })
}

func stubCIWaitAlwaysFailing(t *testing.T) {
	t.Helper()
	orig := waitForChecksInDirFn
	waitForChecksInDirFn = func(_ context.Context, _ string, _ ci.WaitOptions) (ci.StatusResult, error) {
		return ci.StatusResult{
			Status:           ci.StatusFailing,
			ChecksDiscovered: true,
			Summary:          "status=failing (passing=0, failing=1, pending=0)",
			Checks: []ci.StatusCheck{
				{Key: "check:build", Name: "build", Status: ci.StatusFailing},
			},
		}, nil
	}
	t.Cleanup(func() { waitForChecksInDirFn = orig })
}

func stubCIWaitFailThenPending(t *testing.T) {
	t.Helper()
	orig := waitForChecksInDirFn
	calls := 0
	waitForChecksInDirFn = func(_ context.Context, _ string, _ ci.WaitOptions) (ci.StatusResult, error) {
		calls++
		if calls == 1 {
			return ci.StatusResult{
				Status:           ci.StatusFailing,
				ChecksDiscovered: true,
				Summary:          "status=failing (passing=0, failing=1, pending=0)",
				Checks: []ci.StatusCheck{
					{Key: "check:build", Name: "build", Status: ci.StatusFailing},
				},
			}, nil
		}
		return ci.StatusResult{
			Status:           ci.StatusPending,
			ChecksDiscovered: true,
		}, nil
	}
	t.Cleanup(func() { waitForChecksInDirFn = orig })
}

func pushStub(prURL string) func(context.Context, ci.PushOptions) (ci.PushResult, error) {
	return func(_ context.Context, _ ci.PushOptions) (ci.PushResult, error) {
		return ci.PushResult{
			Branch:      "compound/ci-flow",
			PullRequest: ci.PullRequest{URL: prURL},
		}, nil
	}
}

func branchStub(name string) func(string) (string, error) {
	return func(string) (string, error) { return name, nil }
}

func TestRunPRStep_SkipCI_PersistsStateAndAdvancesToReport(t *testing.T) {
	pipeline, out := newPRStepTestPipeline(t)
	if err := pipeline.saveState(&PipelineState{Step: StepCI}); err != nil {
		t.Fatalf("saveState: %v", err)
	}

	pipeline.pushAndCreatePR = pushStub("https://example.com/pr/1")

	state := &PipelineState{Step: StepCI}
	err := pipeline.runPRStep(context.Background(), state, RunOptions{SkipCI: true})
	if err != nil {
		t.Fatalf("runPRStep: %v", err)
	}
	if state.Step != StepReport {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepReport)
	}
	if !pipeline.HasState() {
		t.Fatalf("expected state to be persisted")
	}
	if !strings.Contains(out.String(), "Skipping CI step (--no-ci)") {
		t.Fatalf("output = %q, want no-ci message", out.String())
	}
}

func TestRunPRStep_DryRun_ShowsFullCIFlow(t *testing.T) {
	tests := []struct {
		name      string
		base      string
		wantInLog string
	}{
		{
			name:      "with base branch",
			base:      "main",
			wantInLog: "Would push branch compound/test-feature, create draft PR against main, wait for CI, and auto-fix if failing",
		},
		{
			name:      "without base branch",
			base:      "",
			wantInLog: "Would push branch compound/test-feature, create draft PR, wait for CI, and auto-fix if failing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline, out := newPRStepTestPipeline(t)

			called := false
			pipeline.pushAndCreatePR = func(ctx context.Context, opts ci.PushOptions) (ci.PushResult, error) {
				called = true
				return ci.PushResult{}, nil
			}

			state := &PipelineState{Step: StepCI, BranchName: "compound/test-feature", BaseBranch: tt.base}
			err := pipeline.runPRStep(context.Background(), state, RunOptions{DryRun: true})
			if err != nil {
				t.Fatalf("runPRStep: %v", err)
			}
			if called {
				t.Fatalf("pushAndCreatePR was called in dry-run mode")
			}
			if state.Step != StepReport {
				t.Fatalf("state.Step = %q, want %q", state.Step, StepReport)
			}
			if !strings.Contains(out.String(), tt.wantInLog) {
				t.Fatalf("output = %q, want %q", out.String(), tt.wantInLog)
			}
		})
	}
}

func TestRunPRStep_PushAndWaitPassing(t *testing.T) {
	stubCIWaitPassing(t)

	pipeline, out := newPRStepTestPipeline(t)
	if err := pipeline.saveState(&PipelineState{Step: StepCI}); err != nil {
		t.Fatalf("saveState: %v", err)
	}

	var gotOpts ci.PushOptions
	pipeline.pushAndCreatePR = func(_ context.Context, opts ci.PushOptions) (ci.PushResult, error) {
		gotOpts = opts
		return ci.PushResult{
			Branch:      "compound/ci-flow",
			PullRequest: ci.PullRequest{Number: 42, URL: "https://github.com/acme/repo/pull/42", Title: "Implement deterministic CI flow", HeadRef: "compound/ci-flow", BaseRef: "main"},
		}, nil
	}
	pipeline.currentBranch = branchStub("compound/ci-flow")

	state := &PipelineState{
		Step:       StepCI,
		BranchName: "compound/ci-flow",
		BaseBranch: "main",
		CI: &CIState{
			Status: ci.StatusPending,
			Reason: ci.WaitTerminalReasonNoChecksDetected,
		},
		Analysis: &AnalysisResult{
			PriorityItem:       "Implement deterministic CI flow",
			Description:        "Ship CI command foundation",
			Rationale:          "Safer PR automation",
			AcceptanceCriteria: []string{"Push branch", "Open draft PR"},
		},
	}

	expectedBody := buildPRBody(state, "")

	err := pipeline.runPRStep(context.Background(), state, RunOptions{})
	if err != nil {
		t.Fatalf("runPRStep: %v", err)
	}
	if state.Step != StepReport {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepReport)
	}
	if state.CI == nil || state.CI.Status != "passed" {
		t.Fatalf("state.CI.Status = %v, want passed", state.CI)
	}
	if state.CI.Reason != "" {
		t.Fatalf("state.CI.Reason = %q, want empty", state.CI.Reason)
	}
	if state.CI.PRURL != "https://github.com/acme/repo/pull/42" {
		t.Fatalf("state.CI.PRURL = %q, want PR URL", state.CI.PRURL)
	}
	if state.CI.PRNumber != 42 {
		t.Fatalf("state.CI.PRNumber = %d, want 42", state.CI.PRNumber)
	}
	if state.CI.PRHeadRef != "compound/ci-flow" || state.CI.PRBaseRef != "main" {
		t.Fatalf("state.CI PR refs = %q/%q, want compound/ci-flow/main", state.CI.PRHeadRef, state.CI.PRBaseRef)
	}

	if gotOpts.BaseRef != "main" {
		t.Fatalf("push options base = %q, want %q", gotOpts.BaseRef, "main")
	}
	if gotOpts.Title != "Implement deterministic CI flow" {
		t.Fatalf("push options title = %q, want %q", gotOpts.Title, "Implement deterministic CI flow")
	}
	if gotOpts.Body != expectedBody {
		t.Fatalf("push options body mismatch\n--- got ---\n%s\n--- want ---\n%s", gotOpts.Body, expectedBody)
	}
	if gotOpts.Draft == nil || !*gotOpts.Draft {
		t.Fatalf("push options draft = %v, want true", gotOpts.Draft)
	}

	output := out.String()
	if !strings.Contains(output, "PR created: https://github.com/acme/repo/pull/42") {
		t.Fatalf("output = %q, want PR URL", output)
	}
	if !strings.Contains(output, "CI checks passing") {
		t.Fatalf("output = %q, want passing message", output)
	}
}

func TestRunPRStep_FallbackTitle(t *testing.T) {
	stubCIWaitPassing(t)

	pipeline, _ := newPRStepTestPipeline(t)
	pipeline.pushAndCreatePR = func(_ context.Context, opts ci.PushOptions) (ci.PushResult, error) {
		if opts.Title != "Compound: compound/ci-flow" {
			return ci.PushResult{}, fmt.Errorf("unexpected title: %q", opts.Title)
		}
		return ci.PushResult{
			Branch:      "compound/ci-flow",
			PullRequest: ci.PullRequest{URL: "https://example.com/pr/1"},
		}, nil
	}
	pipeline.currentBranch = branchStub("compound/ci-flow")

	state := &PipelineState{
		Step:       StepCI,
		BranchName: "compound/ci-flow",
		BaseBranch: "main",
		Analysis:   &AnalysisResult{PriorityItem: ""}, // empty → fallback title
	}

	err := pipeline.runPRStep(context.Background(), state, RunOptions{})
	if err != nil {
		t.Fatalf("runPRStep: %v", err)
	}
}

func TestRunPRStep_PersistsPRMetadataBeforeWaitingForCI(t *testing.T) {
	pipeline, _ := newPRStepTestPipeline(t)
	pipeline.pushAndCreatePR = func(_ context.Context, _ ci.PushOptions) (ci.PushResult, error) {
		return ci.PushResult{
			Branch: "compound/ci-flow",
			PullRequest: ci.PullRequest{
				Number:   42,
				URL:      "https://github.com/acme/repo/pull/42",
				Title:    "Implement deterministic CI flow",
				HeadRef:  "compound/ci-flow",
				BaseRef:  "main",
				Existing: true,
			},
		}, nil
	}
	pipeline.currentBranch = branchStub("compound/ci-flow")

	orig := waitForChecksInDirFn
	waitForChecksInDirFn = func(_ context.Context, _ string, _ ci.WaitOptions) (ci.StatusResult, error) {
		saved := pipeline.loadState()
		if saved == nil || saved.CI == nil {
			t.Fatalf("PR metadata was not saved before waiting for CI: %#v", saved)
		}
		if saved.CI.PRURL != "https://github.com/acme/repo/pull/42" || saved.CI.PRNumber != 42 {
			t.Fatalf("saved PR metadata = %+v, want PR URL and number before wait", saved.CI)
		}
		if saved.CI.PRHeadRef != "compound/ci-flow" || saved.CI.PRBaseRef != "main" || !saved.CI.PRReused {
			t.Fatalf("saved PR refs = %+v, want complete PR metadata before wait", saved.CI)
		}
		return ci.StatusResult{Status: ci.StatusPassing, ChecksDiscovered: true}, nil
	}
	t.Cleanup(func() { waitForChecksInDirFn = orig })

	state := &PipelineState{
		Step:       StepCI,
		BranchName: "compound/ci-flow",
		BaseBranch: "main",
	}

	if err := pipeline.runPRStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runPRStep: %v", err)
	}
}

func TestRunPRStep_WaitNoChecks_StopsAtCI(t *testing.T) {
	stubCIWaitNoChecks(t)

	pipeline, out := newPRStepTestPipeline(t)
	pipeline.pushAndCreatePR = pushStub("https://example.com/pr/1")
	pipeline.currentBranch = branchStub("compound/ci-flow")

	state := &PipelineState{
		Step:       StepCI,
		BranchName: "compound/ci-flow",
		BaseBranch: "main",
		CI: &CIState{
			Status: ci.StatusPending,
			Reason: "wait_error",
		},
	}

	err := pipeline.runPRStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected no-checks CI gate error")
	}
	if !strings.Contains(err.Error(), "no CI checks detected yet") {
		t.Fatalf("err = %v, want no-checks gate message", err)
	}
	if state.Step != StepCI {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepCI)
	}
	if state.CI.Status != ci.StatusPending || state.CI.Reason != ci.WaitTerminalReasonNoChecksDetected {
		t.Fatalf("state.CI = %+v, want pending/%s", state.CI, ci.WaitTerminalReasonNoChecksDetected)
	}
	if !strings.Contains(out.String(), "No CI checks discovered; stopping at CI step") {
		t.Fatalf("output = %q, want no-checks stop message", out.String())
	}
	if !pipeline.HasState() {
		t.Fatal("expected state to be persisted when no checks are detected")
	}
}

func TestRunPRStep_FailingThenFixedToPassing(t *testing.T) {
	stubCIWaitFailThenPass(t)
	stubCIFixSuccess(t)

	pipeline, out := newPRStepTestPipeline(t)
	pipeline.pushAndCreatePR = pushStub("https://example.com/pr/1")
	pipeline.currentBranch = branchStub("compound/ci-flow")

	state := &PipelineState{
		Step:       StepCI,
		BranchName: "compound/ci-flow",
		BaseBranch: "main",
	}

	err := pipeline.runPRStep(context.Background(), state, RunOptions{})
	if err != nil {
		t.Fatalf("runPRStep: %v", err)
	}
	if state.Step != StepReport {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepReport)
	}
	if state.CI.Status != "passed" {
		t.Fatalf("state.CI.Status = %q, want passed", state.CI.Status)
	}
	if state.CI.Reason != "" {
		t.Fatalf("state.CI.Reason = %q, want empty", state.CI.Reason)
	}
	if state.CI.FixAttempts != 1 {
		t.Fatalf("state.CI.FixAttempts = %d, want 1", state.CI.FixAttempts)
	}
	if state.CI.FixesApplied != 1 {
		t.Fatalf("state.CI.FixesApplied = %d, want 1", state.CI.FixesApplied)
	}

	output := out.String()
	if !strings.Contains(output, "Fix attempt 1/3") {
		t.Fatalf("output = %q, want fix attempt message", output)
	}
	if !strings.Contains(output, "CI checks passing after fix attempt 1") {
		t.Fatalf("output = %q, want passing-after-fix message", output)
	}
}

func TestRunPRStep_ReservesCIFixAttemptBeforeEngineFix(t *testing.T) {
	stubCIWaitFailThenPass(t)

	pipeline, _ := newPRStepTestPipeline(t)
	pipeline.pushAndCreatePR = pushStub("https://example.com/pr/1")
	pipeline.currentBranch = branchStub("compound/ci-flow")

	origFix := fixWithEngineInDirFn
	fixWithEngineInDirFn = func(_ context.Context, _ string, _ ci.StatusResult, opts ci.FixOptions) (ci.FixResult, error) {
		saved := pipeline.loadState()
		if saved == nil || saved.CI == nil || saved.CI.FixAttempts != opts.Attempt {
			t.Fatalf("saved CI fix attempts before engine fix = %+v, want attempt %d", saved, opts.Attempt)
		}
		return ci.FixResult{
			Applied:      true,
			Attempt:      opts.Attempt,
			FilesChanged: []string{"main.go"},
			Pushed:       true,
		}, nil
	}
	t.Cleanup(func() {
		fixWithEngineInDirFn = origFix
	})

	state := &PipelineState{
		Step:       StepCI,
		BranchName: "compound/ci-flow",
		BaseBranch: "main",
	}

	if err := pipeline.runPRStep(context.Background(), state, RunOptions{MaxCIFixAttempts: 1}); err != nil {
		t.Fatalf("runPRStep: %v", err)
	}
}

func TestRunPRStep_FailingThenPendingStopsAtCI(t *testing.T) {
	stubCIWaitFailThenPending(t)
	stubCIFixSuccess(t)

	pipeline, out := newPRStepTestPipeline(t)
	pipeline.pushAndCreatePR = pushStub("https://example.com/pr/1")
	pipeline.currentBranch = branchStub("compound/ci-flow")

	state := &PipelineState{
		Step:       StepCI,
		BranchName: "compound/ci-flow",
		BaseBranch: "main",
	}

	err := pipeline.runPRStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected pending CI gate error")
	}
	if !strings.Contains(err.Error(), "CI status is pending") {
		t.Fatalf("err = %v, want pending status gate message", err)
	}
	if state.Step != StepCI {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepCI)
	}
	if state.CI.Status != ci.StatusPending {
		t.Fatalf("state.CI.Status = %q, want %q", state.CI.Status, ci.StatusPending)
	}
	if state.CI.FixAttempts != 1 {
		t.Fatalf("state.CI.FixAttempts = %d, want 1", state.CI.FixAttempts)
	}
	if state.CI.FixesApplied != 1 {
		t.Fatalf("state.CI.FixesApplied = %d, want 1", state.CI.FixesApplied)
	}

	output := out.String()
	if !strings.Contains(output, "CI status is pending after fix attempt 1") {
		t.Fatalf("output = %q, want pending-after-fix message", output)
	}
}

func TestRunPRStep_FailingExhaustsFixAttempts(t *testing.T) {
	stubCIWaitAlwaysFailing(t)
	stubCIFixSuccess(t)

	pipeline, out := newPRStepTestPipeline(t)
	pipeline.pushAndCreatePR = pushStub("https://example.com/pr/1")
	pipeline.currentBranch = branchStub("compound/ci-flow")

	state := &PipelineState{
		Step:       StepCI,
		BranchName: "compound/ci-flow",
		BaseBranch: "main",
	}

	err := pipeline.runPRStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected CI gate error after exhausting fix attempts")
	}
	if !strings.Contains(err.Error(), "CI still failing after") {
		t.Fatalf("err = %q, want exhausted gate message", err.Error())
	}
	if state.Step != StepCI {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepCI)
	}
	if state.CI.Status != "fix_exhausted" {
		t.Fatalf("state.CI.Status = %q, want fix_exhausted", state.CI.Status)
	}
	if state.CI.FixAttempts != maxCIFixAttempts {
		t.Fatalf("state.CI.FixAttempts = %d, want %d", state.CI.FixAttempts, maxCIFixAttempts)
	}
	if state.CI.FixesApplied != maxCIFixAttempts {
		t.Fatalf("state.CI.FixesApplied = %d, want %d", state.CI.FixesApplied, maxCIFixAttempts)
	}

	output := out.String()
	if !strings.Contains(output, "CI still failing after") {
		t.Fatalf("output = %q, want exhausted message", output)
	}
}

func TestRunPRStep_DefaultCIFixAttemptsDoNotCarryAcrossResume(t *testing.T) {
	stubCIWaitAlwaysFailing(t)

	fixCalls := 0
	origFix := fixWithEngineInDirFn
	fixWithEngineInDirFn = func(_ context.Context, _ string, _ ci.StatusResult, opts ci.FixOptions) (ci.FixResult, error) {
		fixCalls++
		return ci.FixResult{
			Applied:      true,
			Attempt:      opts.Attempt,
			FilesChanged: []string{"main.go"},
			Pushed:       true,
		}, nil
	}
	t.Cleanup(func() {
		fixWithEngineInDirFn = origFix
	})

	pipeline, _ := newPRStepTestPipeline(t)
	pipeline.pushAndCreatePR = pushStub("https://example.com/pr/1")
	pipeline.currentBranch = branchStub("compound/ci-flow")

	state := &PipelineState{
		Step:       StepCI,
		BranchName: "compound/ci-flow",
		BaseBranch: "main",
		CI: &CIState{
			FixAttempts: maxCIFixAttempts,
		},
	}

	err := pipeline.runPRStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected CI gate error after exhausting fix attempts")
	}
	if fixCalls != maxCIFixAttempts {
		t.Fatalf("fix calls = %d, want default per-invocation attempts %d", fixCalls, maxCIFixAttempts)
	}
	if state.CI.FixesApplied != maxCIFixAttempts {
		t.Fatalf("state.CI.FixesApplied = %d, want %d", state.CI.FixesApplied, maxCIFixAttempts)
	}
}

func TestRunPRStep_MaxCIFixAttemptsBlocksBeforeNextFix(t *testing.T) {
	stubCIWaitAlwaysFailing(t)

	origFix := fixWithEngineInDirFn
	fixWithEngineInDirFn = func(context.Context, string, ci.StatusResult, ci.FixOptions) (ci.FixResult, error) {
		t.Fatal("CI fix should not be called after maxCiFixAttempts is reached")
		return ci.FixResult{}, nil
	}
	t.Cleanup(func() {
		fixWithEngineInDirFn = origFix
	})

	pipeline, _ := newPRStepTestPipeline(t)
	pipeline.pushAndCreatePR = pushStub("https://example.com/pr/1")
	pipeline.currentBranch = branchStub("compound/ci-flow")

	state := &PipelineState{
		Step:       StepCI,
		BranchName: "compound/ci-flow",
		BaseBranch: "main",
		CI: &CIState{
			FixAttempts: 1,
		},
	}

	err := pipeline.runPRStep(context.Background(), state, RunOptions{MaxCIFixAttempts: 1})
	var limitErr *PolicyLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("runPRStep() error = %v, want PolicyLimitError", err)
	}
	if limitErr.PolicyField != "factory.policy.maxCiFixAttempts" || limitErr.Step != StepCI || limitErr.Attempts != 1 || limitErr.Limit != 1 {
		t.Fatalf("limit error = %+v, want maxCiFixAttempts CI limit", limitErr)
	}
	if state.CI.Status != "policy_blocked" || state.CI.Reason != "max_ci_fix_attempts" {
		t.Fatalf("state.CI = %+v, want policy_blocked/max_ci_fix_attempts", state.CI)
	}
}

func TestRunPRStep_FailsWhenCurrentBranchDoesNotMatchState(t *testing.T) {
	pipeline, _ := newPRStepTestPipeline(t)

	called := false
	pipeline.pushAndCreatePR = func(ctx context.Context, opts ci.PushOptions) (ci.PushResult, error) {
		called = true
		return ci.PushResult{}, nil
	}
	pipeline.currentBranch = branchStub("compound/other-branch")

	state := &PipelineState{
		Step:       StepCI,
		BranchName: "compound/ci-flow",
		BaseBranch: "main",
	}

	err := pipeline.runPRStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected branch mismatch error")
	}
	if !strings.Contains(err.Error(), `current branch "compound/other-branch" does not match pipeline state branch "compound/ci-flow"`) {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatal("pushAndCreatePR should not be called on branch mismatch")
	}
}
