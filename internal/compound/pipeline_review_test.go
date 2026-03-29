package compound

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

func TestRun_ReviewFailureBlocksReportStep(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)

	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "develop",
		BranchName: "hal/review-failure",
		StartedAt:  time.Now(),
	}
	if err := pipeline.saveState(state); err != nil {
		t.Fatalf("saveState: %v", err)
	}

	origReviewLoop := runReviewLoopWithDisplay
	runReviewLoopWithDisplay = func(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
		return nil, errors.New("review loop exploded")
	}
	t.Cleanup(func() {
		runReviewLoopWithDisplay = origReviewLoop
	})

	var reportCalled bool
	origReport := runReportWithEngine
	runReportWithEngine = func(ctx context.Context, eng engine.Engine, display *engine.Display, dir string, opts ReviewOptions) (*ReviewResult, error) {
		reportCalled = true
		return &ReviewResult{ReportPath: filepath.Join(dir, template.HalDir, "reports", "unexpected.md")}, nil
	}
	t.Cleanup(func() {
		runReportWithEngine = origReport
	})

	err := pipeline.Run(context.Background(), RunOptions{Resume: true})
	if err == nil {
		t.Fatal("expected pipeline.Run to fail, got nil")
	}
	if !strings.Contains(err.Error(), "step review failed") {
		t.Fatalf("error = %q, want substring %q", err.Error(), "step review failed")
	}
	if !strings.Contains(err.Error(), "failed to run review loop") {
		t.Fatalf("error = %q, want substring %q", err.Error(), "failed to run review loop")
	}
	if reportCalled {
		t.Fatal("report step should not execute when review fails")
	}

	saved := pipeline.loadState()
	if saved == nil {
		t.Fatal("expected state to be saved on review failure")
	}
	if saved.Step != StepReview {
		t.Fatalf("saved.Step = %q, want %q", saved.Step, StepReview)
	}
	if saved.Review == nil {
		t.Fatal("saved.Review is nil")
	}
	if saved.Review.Status != "failed" {
		t.Fatalf("saved.Review.Status = %q, want %q", saved.Review.Status, "failed")
	}
}

func TestRunReviewAndReportSteps_SuccessPersistsReportPath(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)

	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "develop",
		BranchName: "hal/review-success",
		StartedAt:  time.Now(),
	}

	var gotBaseBranch string
	var gotIterations int
	origReviewLoop := runReviewLoopWithDisplay
	runReviewLoopWithDisplay = func(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
		gotBaseBranch = baseBranch
		gotIterations = requestedIterations
		return &ReviewLoopResult{
			CompletedIterations: 2,
			Totals: ReviewLoopTotals{
				IssuesFound:  3,
				FixesApplied: 2,
			},
		}, nil
	}
	t.Cleanup(func() {
		runReviewLoopWithDisplay = origReviewLoop
	})

	reportPath := filepath.Join(dir, template.HalDir, "reports", "review-20260329.md")
	var reportCalled bool
	origReport := runReportWithEngine
	runReportWithEngine = func(ctx context.Context, eng engine.Engine, display *engine.Display, gotDir string, opts ReviewOptions) (*ReviewResult, error) {
		reportCalled = true
		if gotDir != dir {
			t.Fatalf("report dir = %q, want %q", gotDir, dir)
		}
		if opts.DryRun {
			t.Fatal("report options should run with DryRun=false")
		}
		if opts.SkipAgents {
			t.Fatal("report options should run with SkipAgents=false")
		}
		return &ReviewResult{ReportPath: reportPath}, nil
	}
	t.Cleanup(func() {
		runReportWithEngine = origReport
	})

	if err := pipeline.runReviewStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runReviewStep returned error: %v", err)
	}
	if gotBaseBranch != state.BaseBranch {
		t.Fatalf("review base branch = %q, want %q", gotBaseBranch, state.BaseBranch)
	}
	if gotIterations != defaultReviewIterations {
		t.Fatalf("review iterations = %d, want %d", gotIterations, defaultReviewIterations)
	}
	if state.Step != StepReport {
		t.Fatalf("state.Step after review = %q, want %q", state.Step, StepReport)
	}
	if state.Review == nil {
		t.Fatal("state.Review is nil after review step")
	}
	if state.Review.Status != "passed" {
		t.Fatalf("state.Review.Status = %q, want %q", state.Review.Status, "passed")
	}

	savedAfterReview := pipeline.loadState()
	if savedAfterReview == nil {
		t.Fatal("expected state save after review step")
	}
	if savedAfterReview.Step != StepReport {
		t.Fatalf("savedAfterReview.Step = %q, want %q", savedAfterReview.Step, StepReport)
	}

	if err := pipeline.runReportStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runReportStep returned error: %v", err)
	}
	if !reportCalled {
		t.Fatal("expected report gate to execute after successful review")
	}
	if state.Step != StepCI {
		t.Fatalf("state.Step after report = %q, want %q", state.Step, StepCI)
	}
	if state.ReportPath != reportPath {
		t.Fatalf("state.ReportPath = %q, want %q", state.ReportPath, reportPath)
	}

	saved := pipeline.loadState()
	if saved == nil {
		t.Fatal("expected state save after report step")
	}
	if saved.Step != StepCI {
		t.Fatalf("saved.Step = %q, want %q", saved.Step, StepCI)
	}
	if saved.ReportPath != reportPath {
		t.Fatalf("saved.ReportPath = %q, want %q", saved.ReportPath, reportPath)
	}
}
