package compound

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/engine"
)

func newPRStepTestPipeline(t *testing.T) (*Pipeline, *bytes.Buffer) {
	t.Helper()

	var out bytes.Buffer
	display := engine.NewDisplay(&out)
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, display, t.TempDir())

	return pipeline, &out
}

func TestRunPRStep_SkipPR_PreservesBehavior(t *testing.T) {
	pipeline, out := newPRStepTestPipeline(t)
	if err := pipeline.saveState(&PipelineState{Step: StepPR}); err != nil {
		t.Fatalf("saveState: %v", err)
	}

	called := false
	pipeline.pushAndCreatePR = func(ctx context.Context, opts ci.PushOptions) (ci.PushResult, error) {
		called = true
		return ci.PushResult{}, nil
	}

	state := &PipelineState{Step: StepPR}
	err := pipeline.runPRStep(context.Background(), state, RunOptions{SkipPR: true})
	if err != nil {
		t.Fatalf("runPRStep: %v", err)
	}
	if called {
		t.Fatalf("pushAndCreatePR was called with --skip-pr")
	}
	if state.Step != StepDone {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepDone)
	}
	if pipeline.HasState() {
		t.Fatalf("expected state to be cleared")
	}
	if !strings.Contains(out.String(), "Skipping PR creation (--skip-pr)") {
		t.Fatalf("output = %q, want skip-pr message", out.String())
	}
}

func TestRunPRStep_DryRun_PreservesBehavior(t *testing.T) {
	tests := []struct {
		name      string
		base      string
		wantInLog string
	}{
		{
			name:      "with base branch",
			base:      "main",
			wantInLog: "[dry-run] Would push branch compound/test-feature and create draft PR against main",
		},
		{
			name:      "without base branch",
			base:      "",
			wantInLog: "[dry-run] Would push branch compound/test-feature and create draft PR",
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

			state := &PipelineState{Step: StepPR, BranchName: "compound/test-feature", BaseBranch: tt.base}
			err := pipeline.runPRStep(context.Background(), state, RunOptions{DryRun: true})
			if err != nil {
				t.Fatalf("runPRStep: %v", err)
			}
			if called {
				t.Fatalf("pushAndCreatePR was called in dry-run mode")
			}
			if state.Step != StepDone {
				t.Fatalf("state.Step = %q, want %q", state.Step, StepDone)
			}
			if !strings.Contains(out.String(), tt.wantInLog) {
				t.Fatalf("output = %q, want %q", out.String(), tt.wantInLog)
			}
		})
	}
}

func TestRunPRStep_DelegatesToCIAndPreservesPRContent(t *testing.T) {
	tests := []struct {
		name         string
		priorityItem string
		wantTitle    string
	}{
		{
			name:         "analysis title",
			priorityItem: "Implement deterministic CI flow",
			wantTitle:    "Implement deterministic CI flow",
		},
		{
			name:         "fallback title",
			priorityItem: "",
			wantTitle:    "Compound: compound/ci-flow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline, out := newPRStepTestPipeline(t)
			if err := pipeline.saveState(&PipelineState{Step: StepPR}); err != nil {
				t.Fatalf("saveState: %v", err)
			}

			state := &PipelineState{
				Step:       StepPR,
				BranchName: "compound/ci-flow",
				BaseBranch: "main",
				Analysis: &AnalysisResult{
					PriorityItem:       tt.priorityItem,
					Description:        "Ship CI command foundation",
					Rationale:          "Safer PR automation",
					AcceptanceCriteria: []string{"Push branch", "Open draft PR"},
				},
			}

			expectedBody := buildPRBody(state, "")

			var gotOpts ci.PushOptions
			pipeline.pushAndCreatePR = func(ctx context.Context, opts ci.PushOptions) (ci.PushResult, error) {
				gotOpts = opts
				return ci.PushResult{
					Branch: "compound/ci-flow",
					PullRequest: ci.PullRequest{
						URL: "https://github.com/acme/repo/pull/42",
					},
				}, nil
			}

			err := pipeline.runPRStep(context.Background(), state, RunOptions{})
			if err != nil {
				t.Fatalf("runPRStep: %v", err)
			}
			if state.Step != StepDone {
				t.Fatalf("state.Step = %q, want %q", state.Step, StepDone)
			}
			if pipeline.HasState() {
				t.Fatalf("expected state to be cleared")
			}

			if gotOpts.BaseRef != "main" {
				t.Fatalf("push options base = %q, want %q", gotOpts.BaseRef, "main")
			}
			if gotOpts.Title != tt.wantTitle {
				t.Fatalf("push options title = %q, want %q", gotOpts.Title, tt.wantTitle)
			}
			if gotOpts.Body != expectedBody {
				t.Fatalf("push options body mismatch\n--- got ---\n%s\n--- want ---\n%s", gotOpts.Body, expectedBody)
			}
			if gotOpts.Draft == nil || !*gotOpts.Draft {
				t.Fatalf("push options draft = %v, want true", gotOpts.Draft)
			}

			output := out.String()
			if !strings.Contains(output, "Pushing branch: compound/ci-flow") {
				t.Fatalf("output = %q, want push message", output)
			}
			if !strings.Contains(output, "Creating draft PR...") {
				t.Fatalf("output = %q, want create message", output)
			}
			if !strings.Contains(output, "PR created: https://github.com/acme/repo/pull/42") {
				t.Fatalf("output = %q, want PR URL", output)
			}
			if strings.Contains(output, "Waiting for CI") || strings.Contains(output, "CI green") {
				t.Fatalf("unexpected CI loop output in StepPR: %q", output)
			}
		})
	}
}
