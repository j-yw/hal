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
	if !strings.Contains(err.Error(), "failed to run review cycle") {
		t.Fatalf("error = %q, want substring %q", err.Error(), "failed to run review cycle")
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
	stubCleanReviewFinalVerification(t, pipeline, "hal/review-success")

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
			CompletedIterations: 1,
			StopReason:          "single_iteration",
			Totals: ReviewLoopTotals{
				IssuesFound:  0,
				ValidIssues:  0,
				FixesApplied: 0,
			},
			Iterations: []ReviewLoopIteration{{
				Iteration:     1,
				IssuesFound:   0,
				ValidIssues:   0,
				InvalidIssues: 0,
				FixesApplied:  0,
			}},
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
		if !opts.SkipAgents {
			t.Fatal("report options should run with SkipAgents=true")
		}
		if len(opts.Verification) == 0 {
			t.Fatal("report options should include verification facts")
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
	if gotIterations != 1 {
		t.Fatalf("review iterations = %d, want %d", gotIterations, 1)
	}
	if state.Step != StepCI {
		t.Fatalf("state.Step after review = %q, want %q", state.Step, StepCI)
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
	if savedAfterReview.Step != StepCI {
		t.Fatalf("savedAfterReview.Step = %q, want %q", savedAfterReview.Step, StepCI)
	}

	state.Step = StepReport
	if err := pipeline.runReportStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runReportStep returned error: %v", err)
	}
	if !reportCalled {
		t.Fatal("expected report gate to execute after successful review")
	}
	if state.Step != StepArchive {
		t.Fatalf("state.Step after report = %q, want %q", state.Step, StepArchive)
	}
	if state.ReportPath != reportPath {
		t.Fatalf("state.ReportPath = %q, want %q", state.ReportPath, reportPath)
	}

	saved := pipeline.loadState()
	if saved == nil {
		t.Fatal("expected state save after report step")
	}
	if saved.Step != StepArchive {
		t.Fatalf("saved.Step = %q, want %q", saved.Step, StepArchive)
	}
	if saved.ReportPath != reportPath {
		t.Fatalf("saved.ReportPath = %q, want %q", saved.ReportPath, reportPath)
	}
}

func TestRunReviewStep_BlocksWhenValidIssuesRemain(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)

	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "develop",
		BranchName: "hal/review-blocked",
		StartedAt:  time.Now(),
	}

	origReviewLoop := runReviewLoopWithDisplay
	runReviewLoopWithDisplay = func(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
		return &ReviewLoopResult{
			CompletedIterations: 1,
			StopReason:          "single_iteration",
			Totals: ReviewLoopTotals{
				IssuesFound:  4,
				ValidIssues:  2,
				FixesApplied: 1,
			},
			Iterations: []ReviewLoopIteration{{
				Iteration:     1,
				IssuesFound:   4,
				ValidIssues:   2,
				InvalidIssues: 0,
				FixesApplied:  1,
			}},
		}, nil
	}
	t.Cleanup(func() {
		runReviewLoopWithDisplay = origReviewLoop
	})

	err := pipeline.runReviewStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected review step to fail when valid issues remain")
	}
	if !strings.Contains(err.Error(), "review gate blocked") {
		t.Fatalf("error = %q, want review gate blocked", err.Error())
	}
	if !strings.Contains(err.Error(), "clean streak") {
		t.Fatalf("error = %q, want clean streak guidance", err.Error())
	}
	if state.Step != StepReview {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepReview)
	}
	if state.Review == nil {
		t.Fatal("state.Review is nil")
	}
	if state.Review.Status != "failed" {
		t.Fatalf("state.Review.Status = %q, want %q", state.Review.Status, "failed")
	}

	saved := pipeline.loadState()
	if saved == nil {
		t.Fatal("expected review failure state to be saved")
	}
	if saved.Step != StepReview {
		t.Fatalf("saved.Step = %q, want %q", saved.Step, StepReview)
	}
	if saved.Review == nil || saved.Review.Status != "failed" {
		t.Fatalf("saved.Review = %+v, want failed status", saved.Review)
	}
}

func TestRunReviewStep_PassesWhenReviewCycleHasNoValidIssues(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)
	stubCleanReviewFinalVerification(t, pipeline, "hal/review-no-valid-issues")

	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "develop",
		BranchName: "hal/review-no-valid-issues",
		StartedAt:  time.Now(),
	}

	origReviewLoop := runReviewLoopWithDisplay
	runReviewLoopWithDisplay = func(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
		return &ReviewLoopResult{
			CompletedIterations: 1,
			StopReason:          "single_iteration",
			Totals: ReviewLoopTotals{
				IssuesFound:  0,
				ValidIssues:  0,
				FixesApplied: 0,
			},
			Iterations: []ReviewLoopIteration{{
				Iteration:     1,
				IssuesFound:   0,
				ValidIssues:   0,
				InvalidIssues: 0,
				FixesApplied:  0,
			}},
		}, nil
	}
	t.Cleanup(func() {
		runReviewLoopWithDisplay = origReviewLoop
	})

	if err := pipeline.runReviewStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runReviewStep returned error: %v", err)
	}
	if state.Step != StepCI {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepCI)
	}
	if state.Review == nil {
		t.Fatal("state.Review is nil")
	}
	if state.Review.Status != "passed" {
		t.Fatalf("state.Review.Status = %q, want %q", state.Review.Status, "passed")
	}
}

func TestRunReviewStep_RequiresConfiguredCleanStreak(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)
	stubCleanReviewFinalVerification(t, pipeline, "hal/review-clean-streak")

	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "develop",
		BranchName: "hal/review-clean-streak",
		StartedAt:  time.Now(),
	}

	origReviewLoop := runReviewLoopWithDisplay
	calls := 0
	runReviewLoopWithDisplay = func(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
		calls++
		return &ReviewLoopResult{
			CompletedIterations: 1,
			StopReason:          "single_iteration",
			Totals:              ReviewLoopTotals{IssuesFound: 0, ValidIssues: 0, FixesApplied: 0},
			Iterations: []ReviewLoopIteration{{
				Iteration:     1,
				IssuesFound:   0,
				ValidIssues:   0,
				InvalidIssues: 0,
				FixesApplied:  0,
			}},
		}, nil
	}
	t.Cleanup(func() {
		runReviewLoopWithDisplay = origReviewLoop
	})

	opts := RunOptions{ReviewCleanStreak: 3, ReviewMaxCycles: 5}
	if err := pipeline.runReviewStep(context.Background(), state, opts); err != nil {
		t.Fatalf("runReviewStep returned error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("review cycles called = %d, want %d", calls, 3)
	}
	if state.Step != StepCI {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepCI)
	}
	if state.Review == nil || state.Review.Status != "passed" {
		t.Fatalf("state.Review = %+v, want passed", state.Review)
	}
}

func TestRunReviewStep_SkipReviewPolicy(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)

	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "develop",
		BranchName: "hal/review-skip",
		StartedAt:  time.Now(),
	}

	if err := pipeline.runReviewStep(context.Background(), state, RunOptions{SkipReview: true}); err != nil {
		t.Fatalf("runReviewStep returned error: %v", err)
	}
	if state.Step != StepCI {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepCI)
	}
	if state.Review == nil || state.Review.Status != "skipped" {
		t.Fatalf("state.Review = %+v, want skipped", state.Review)
	}
}

func TestRunReviewStep_CommitsReviewFixesBeforePassing(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)

	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "develop",
		BranchName: "hal/review-finalize",
		StartedAt:  time.Now(),
	}
	pipeline.currentBranch = func(string) (string, error) {
		return state.BranchName, nil
	}

	origReviewLoop := runReviewLoopWithDisplay
	calls := 0
	runReviewLoopWithDisplay = func(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
		calls++
		switch calls {
		case 1:
			return &ReviewLoopResult{Iterations: []ReviewLoopIteration{{Iteration: 1, ValidIssues: 1, FixesApplied: 1}}}, nil
		case 2:
			return &ReviewLoopResult{Iterations: []ReviewLoopIteration{{Iteration: 2, ValidIssues: 0, FixesApplied: 0}}}, nil
		default:
			t.Fatalf("unexpected review cycle %d", calls)
			return nil, nil
		}
	}
	t.Cleanup(func() {
		runReviewLoopWithDisplay = origReviewLoop
	})

	origChanges := workingTreeChangesInDirFn
	changeCalls := 0
	workingTreeChangesInDirFn = func(string) ([]string, error) {
		changeCalls++
		switch changeCalls {
		case 1:
			return []string{"app/page.tsx"}, nil
		case 2:
			return nil, nil
		default:
			return nil, nil
		}
	}
	t.Cleanup(func() {
		workingTreeChangesInDirFn = origChanges
	})

	addCalled := false
	origAdd := gitAddAllInDirFn
	gitAddAllInDirFn = func(ctx context.Context, gotDir string) error {
		addCalled = true
		if gotDir != dir {
			t.Fatalf("git add dir = %q, want %q", gotDir, dir)
		}
		return nil
	}
	t.Cleanup(func() {
		gitAddAllInDirFn = origAdd
	})

	commitCalled := false
	origCommit := gitCommitInDirFn
	gitCommitInDirFn = func(ctx context.Context, gotDir, message string) error {
		commitCalled = true
		if gotDir != dir {
			t.Fatalf("git commit dir = %q, want %q", gotDir, dir)
		}
		if message != reviewFixCommitMessage {
			t.Fatalf("git commit message = %q, want %q", message, reviewFixCommitMessage)
		}
		return nil
	}
	t.Cleanup(func() {
		gitCommitInDirFn = origCommit
	})

	if err := pipeline.runReviewStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runReviewStep returned error: %v", err)
	}
	if !addCalled {
		t.Fatal("expected review fixes to be staged before passing")
	}
	if !commitCalled {
		t.Fatal("expected review fixes to be committed before passing")
	}
	if state.Step != StepCI {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepCI)
	}
	if state.Review == nil || state.Review.Status != "passed" {
		t.Fatalf("state.Review = %+v, want passed", state.Review)
	}
}

func TestRunReviewStep_FinalizeReviewFixesFailure_BlocksGate(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)

	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "develop",
		BranchName: "hal/review-finalize-fail",
		StartedAt:  time.Now(),
	}

	origReviewLoop := runReviewLoopWithDisplay
	runReviewLoopWithDisplay = func(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
		return &ReviewLoopResult{Iterations: []ReviewLoopIteration{{Iteration: 1, ValidIssues: 0, FixesApplied: 1}}}, nil
	}
	t.Cleanup(func() {
		runReviewLoopWithDisplay = origReviewLoop
	})

	origChanges := workingTreeChangesInDirFn
	workingTreeChangesInDirFn = func(string) ([]string, error) {
		return []string{"app/page.tsx"}, nil
	}
	t.Cleanup(func() {
		workingTreeChangesInDirFn = origChanges
	})

	origAdd := gitAddAllInDirFn
	gitAddAllInDirFn = func(ctx context.Context, dir string) error {
		return errors.New("git add failed")
	}
	t.Cleanup(func() {
		gitAddAllInDirFn = origAdd
	})

	commitCalled := false
	origCommit := gitCommitInDirFn
	gitCommitInDirFn = func(ctx context.Context, dir, message string) error {
		commitCalled = true
		return nil
	}
	t.Cleanup(func() {
		gitCommitInDirFn = origCommit
	})

	err := pipeline.runReviewStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected runReviewStep to fail when finalizeReviewFixes fails")
	}
	if !strings.Contains(err.Error(), "finalize review fixes failed") {
		t.Fatalf("error = %q, want finalize review fixes failed", err.Error())
	}
	if commitCalled {
		t.Fatal("commit should not run when staging review fixes fails")
	}
	if state.Step != StepReview {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepReview)
	}
	if state.Review == nil || state.Review.Status != "failed" {
		t.Fatalf("state.Review = %+v, want failed", state.Review)
	}
	saved := pipeline.loadState()
	if saved == nil || saved.Review == nil || saved.Review.Status != "failed" {
		t.Fatalf("saved state = %+v, want failed review status", saved)
	}
}

func TestRunReviewStep_FinalVerificationFailure_BlocksGate(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)

	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "develop",
		BranchName: "hal/review-verify-fail",
		StartedAt:  time.Now(),
	}

	origReviewLoop := runReviewLoopWithDisplay
	runReviewLoopWithDisplay = func(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
		return &ReviewLoopResult{Iterations: []ReviewLoopIteration{{Iteration: 1, ValidIssues: 0, FixesApplied: 0}}}, nil
	}
	t.Cleanup(func() {
		runReviewLoopWithDisplay = origReviewLoop
	})

	origChanges := workingTreeChangesInDirFn
	workingTreeChangesInDirFn = func(string) ([]string, error) {
		return []string{"app/page.tsx"}, nil
	}
	t.Cleanup(func() {
		workingTreeChangesInDirFn = origChanges
	})

	err := pipeline.runReviewStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected runReviewStep to fail when final verification fails")
	}
	if !strings.Contains(err.Error(), "final verification failed") {
		t.Fatalf("error = %q, want final verification failed", err.Error())
	}
	if state.Step != StepReview {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepReview)
	}
	if state.Review == nil || state.Review.Status != "failed" {
		t.Fatalf("state.Review = %+v, want failed", state.Review)
	}
	saved := pipeline.loadState()
	if saved == nil || saved.Review == nil || saved.Review.Status != "failed" {
		t.Fatalf("saved state = %+v, want failed review status", saved)
	}
}

func TestRunReviewStep_MaxReviewFixAttemptsBlocksBeforeNextCycle(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)

	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "develop",
		BranchName: "hal/review-policy",
		StartedAt:  time.Now(),
		Review: &ReviewState{
			FixAttempts: 1,
		},
	}

	origReviewLoop := runReviewLoopWithDisplay
	runReviewLoopWithDisplay = func(context.Context, engine.Engine, *engine.Display, string, int) (*ReviewLoopResult, error) {
		t.Fatal("review loop should not be called after maxReviewFixAttempts is reached")
		return nil, nil
	}
	t.Cleanup(func() {
		runReviewLoopWithDisplay = origReviewLoop
	})

	err := pipeline.runReviewStep(context.Background(), state, RunOptions{MaxReviewFixAttempts: 1})
	var limitErr *PolicyLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("runReviewStep() error = %v, want PolicyLimitError", err)
	}
	if limitErr.PolicyField != "factory.policy.maxReviewFixAttempts" || limitErr.Step != StepReview || limitErr.Attempts != 1 || limitErr.Limit != 1 {
		t.Fatalf("limit error = %+v, want maxReviewFixAttempts review limit", limitErr)
	}
	if state.Review.Status != "failed" {
		t.Fatalf("review status = %q, want failed", state.Review.Status)
	}
}

func TestRunReviewStep_CountsReviewFixAttempts(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)

	state := &PipelineState{
		Step:       StepReview,
		BaseBranch: "develop",
		BranchName: "hal/review-policy-count",
		StartedAt:  time.Now(),
	}

	origReviewLoop := runReviewLoopWithDisplay
	runReviewLoopWithDisplay = func(context.Context, engine.Engine, *engine.Display, string, int) (*ReviewLoopResult, error) {
		return &ReviewLoopResult{
			Iterations: []ReviewLoopIteration{{
				Iteration:    1,
				IssuesFound:  2,
				ValidIssues:  1,
				FixesApplied: 1,
			}},
		}, nil
	}
	t.Cleanup(func() {
		runReviewLoopWithDisplay = origReviewLoop
	})

	err := pipeline.runReviewStep(context.Background(), state, RunOptions{MaxReviewFixAttempts: 1})
	var limitErr *PolicyLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("runReviewStep() error = %v, want PolicyLimitError after consumed fix attempt", err)
	}
	if state.Review == nil || state.Review.FixAttempts != 1 {
		t.Fatalf("state.Review = %+v, want one fix attempt", state.Review)
	}
}

func stubCleanReviewFinalVerification(t *testing.T, pipeline *Pipeline, branch string) {
	t.Helper()
	origChanges := workingTreeChangesInDirFn
	workingTreeChangesInDirFn = func(string) ([]string, error) { return nil, nil }
	t.Cleanup(func() { workingTreeChangesInDirFn = origChanges })
	pipeline.currentBranch = func(string) (string, error) { return branch, nil }
}
