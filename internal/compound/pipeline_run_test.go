package compound

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/loop"
	"github.com/jywlabs/hal/internal/parallelrun"
	"github.com/jywlabs/hal/internal/template"
)

type runStepTestEngine struct{}

func (runStepTestEngine) Name() string {
	return "run-step-test"
}

func TestRunLoopStep_MaxRunAttemptsCapsLoopIterations(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	cfg.MaxIterations = 7

	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{Step: StepRun, BaseBranch: "develop"}

	var gotLoopConfig loop.Config
	origRunLoopWithConfig := runLoopWithConfig
	runLoopWithConfig = func(ctx context.Context, cfg loop.Config) (loop.Result, error) {
		gotLoopConfig = cfg
		return loop.Result{
			Success:    true,
			Complete:   false,
			Iterations: 2,
		}, nil
	}
	t.Cleanup(func() {
		runLoopWithConfig = origRunLoopWithConfig
	})

	err := pipeline.runLoopStep(context.Background(), state, RunOptions{MaxRunAttempts: 2})
	var limitErr *PolicyLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("runLoopStep() error = %v, want PolicyLimitError after consuming final attempt", err)
	}
	if limitErr.PolicyField != "factory.policy.maxRunAttempts" || limitErr.Step != StepRun || limitErr.Attempts != 2 || limitErr.Limit != 2 {
		t.Fatalf("limit error = %+v, want consumed maxRunAttempts run limit", limitErr)
	}
	if gotLoopConfig.MaxIterations != 2 {
		t.Fatalf("loop max iterations = %d, want policy cap 2", gotLoopConfig.MaxIterations)
	}
	if state.Run == nil || state.Run.MaxIterations != 2 {
		t.Fatalf("state.Run = %+v, want maxIterations 2", state.Run)
	}
}

func TestRunLoopStep_MaxRunAttemptsAppliesToLoopExecutionError(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	cfg.MaxIterations = 7

	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{Step: StepRun, BaseBranch: "develop"}
	loopErr := errors.New("agent failed")

	origRunLoopWithConfig := runLoopWithConfig
	runLoopWithConfig = func(ctx context.Context, cfg loop.Config) (loop.Result, error) {
		return loop.Result{
			Success:    false,
			Complete:   false,
			Iterations: 2,
			Error:      loopErr,
		}, nil
	}
	t.Cleanup(func() {
		runLoopWithConfig = origRunLoopWithConfig
	})

	err := pipeline.runLoopStep(context.Background(), state, RunOptions{MaxRunAttempts: 2})
	var limitErr *PolicyLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("runLoopStep() error = %v, want PolicyLimitError after loop error consumes final attempt", err)
	}
	if !errors.Is(err, loopErr) {
		t.Fatalf("runLoopStep() error = %v, want wrapped loop error", err)
	}
	if limitErr.PolicyField != "factory.policy.maxRunAttempts" || limitErr.Step != StepRun || limitErr.Attempts != 2 || limitErr.Limit != 2 {
		t.Fatalf("limit error = %+v, want consumed maxRunAttempts run limit", limitErr)
	}
	saved := pipeline.loadState()
	if saved == nil || saved.Run == nil {
		t.Fatalf("saved state = %+v, want run telemetry", saved)
	}
	if saved.Run.Iterations != 2 || saved.Run.Complete {
		t.Fatalf("saved.Run = %+v, want incomplete run with 2 iterations", saved.Run)
	}
}

func TestRunLoopStep_MaxRunAttemptsBlocksBeforeLoop(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{
		Step: StepRun,
		Run: &RunState{
			Iterations: 1,
			Complete:   false,
		},
	}

	origRunLoopWithConfig := runLoopWithConfig
	runLoopWithConfig = func(context.Context, loop.Config) (loop.Result, error) {
		t.Fatal("run loop should not be called after maxRunAttempts is reached")
		return loop.Result{}, nil
	}
	t.Cleanup(func() {
		runLoopWithConfig = origRunLoopWithConfig
	})

	err := pipeline.runLoopStep(context.Background(), state, RunOptions{MaxRunAttempts: 1})
	var limitErr *PolicyLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("runLoopStep() error = %v, want PolicyLimitError", err)
	}
	if limitErr.PolicyField != "factory.policy.maxRunAttempts" || limitErr.Step != StepRun || limitErr.Attempts != 1 || limitErr.Limit != 1 {
		t.Fatalf("limit error = %+v, want maxRunAttempts run limit", limitErr)
	}
}

func TestRunLoopStep_MaxRunAttemptsUsesRemainingBudgetOnResume(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	cfg.MaxIterations = 7
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{
		Step: StepRun,
		Run: &RunState{
			Iterations: 3,
			Complete:   false,
		},
	}

	var gotLoopConfig loop.Config
	origRunLoopWithConfig := runLoopWithConfig
	runLoopWithConfig = func(ctx context.Context, cfg loop.Config) (loop.Result, error) {
		gotLoopConfig = cfg
		return loop.Result{
			Success:    true,
			Complete:   false,
			Iterations: 2,
		}, nil
	}
	t.Cleanup(func() {
		runLoopWithConfig = origRunLoopWithConfig
	})

	err := pipeline.runLoopStep(context.Background(), state, RunOptions{MaxRunAttempts: 5})
	if err == nil {
		t.Fatal("expected incomplete run gate error")
	}
	if gotLoopConfig.MaxIterations != 2 {
		t.Fatalf("loop max iterations = %d, want remaining policy budget 2", gotLoopConfig.MaxIterations)
	}
	if state.Run == nil || state.Run.Iterations != 5 {
		t.Fatalf("state.Run = %+v, want cumulative iterations 5", state.Run)
	}
	if state.Run.MaxIterations != 2 {
		t.Fatalf("state.Run.MaxIterations = %d, want remaining policy budget 2", state.Run.MaxIterations)
	}
}

func TestRunLoopStep_DispatchesParallelRunnerAndSavesTelemetry(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()
	cfg.MaxIterations = 7
	pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{Step: StepRun, BaseBranch: "develop"}

	origRunLoopWithConfig := runLoopWithConfig
	runLoopWithConfig = func(context.Context, loop.Config) (loop.Result, error) {
		t.Fatal("sequential loop should not be called for parallel run step")
		return loop.Result{}, nil
	}
	origRunParallelWithConfig := runParallelWithConfig
	var gotParallelConfig parallelrun.Config
	runParallelWithConfig = func(ctx context.Context, cfg parallelrun.Config) (parallelrun.Result, error) {
		gotParallelConfig = cfg
		return parallelrun.Result{
			Success:          true,
			Complete:         true,
			Iterations:       3,
			CompletedStories: 3,
			TotalStories:     3,
			Parallel: parallelrun.Summary{
				RunID:                "run-test",
				RequestedParallelism: 4,
				Batches:              2,
				Started:              3,
				Integrated:           3,
			},
		}, nil
	}
	t.Cleanup(func() {
		runLoopWithConfig = origRunLoopWithConfig
		runParallelWithConfig = origRunParallelWithConfig
	})

	if err := pipeline.runLoopStep(context.Background(), state, RunOptions{Parallelism: 4, MaxRunAttempts: 3}); err != nil {
		t.Fatalf("runLoopStep() error = %v", err)
	}
	if gotParallelConfig.Parallelism != 4 {
		t.Fatalf("parallelism = %d, want 4", gotParallelConfig.Parallelism)
	}
	if gotParallelConfig.MaxIterations != 3 {
		t.Fatalf("max iterations = %d, want policy cap 3", gotParallelConfig.MaxIterations)
	}
	if gotParallelConfig.RepoDir != dir {
		t.Fatalf("repo dir = %q, want %q", gotParallelConfig.RepoDir, dir)
	}
	if gotParallelConfig.CleanupFailedWorktrees {
		t.Fatal("parallel run config should preserve failed worker worktrees by default")
	}
	if state.Run == nil || state.Run.Parallel == nil {
		t.Fatalf("state.Run = %+v, want parallel telemetry", state.Run)
	}
	if state.Run.Parallel.RequestedParallelism != 4 || state.Run.Parallel.Batches != 2 || state.Run.Parallel.Integrated != 3 {
		t.Fatalf("state.Run.Parallel = %+v, want requested=4 batches=2 integrated=3", state.Run.Parallel)
	}

	saved := pipeline.loadState()
	if saved == nil || saved.Run == nil || saved.Run.Parallel == nil {
		t.Fatalf("saved state = %+v, want parallel run telemetry", saved)
	}
	if saved.Run.Parallel.RunID != "run-test" {
		t.Fatalf("saved run ID = %q, want run-test", saved.Run.Parallel.RunID)
	}

	if err := pipeline.clearState(); err != nil {
		t.Fatalf("clearState() error = %v", err)
	}
	lastRun := pipeline.LastRunState()
	if lastRun == nil || lastRun.Parallel == nil {
		t.Fatalf("LastRunState() after clear = %+v, want retained parallel run telemetry", lastRun)
	}
	if lastRun.Parallel.RunID != "run-test" || lastRun.Parallel.RequestedParallelism != 4 {
		t.Fatalf("LastRunState().Parallel = %+v, want retained run-test telemetry", lastRun.Parallel)
	}
}

func (runStepTestEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (runStepTestEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	return "", nil
}

func (runStepTestEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	return "", nil
}

func TestRunLoopStep_CompletionGateAndTelemetry(t *testing.T) {
	tests := []struct {
		name       string
		loopResult loop.Result
		wantErr    string
		wantStep   string
	}{
		{
			name: "complete run advances to review",
			loopResult: loop.Result{
				Success:          true,
				Complete:         true,
				Iterations:       4,
				CompletedStories: 5,
				TotalStories:     5,
			},
			wantStep: StepReview,
		},
		{
			name: "incomplete run blocks progression",
			loopResult: loop.Result{
				Success:          true,
				Complete:         false,
				Iterations:       4,
				CompletedStories: 3,
				TotalStories:     5,
			},
			wantErr:  "run gate blocked: PRD completion incomplete (3/5 complete)",
			wantStep: StepRun,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := DefaultAutoConfig()
			cfg.MaxIterations = 7

			pipeline := NewPipeline(&cfg, runStepTestEngine{}, engine.NewDisplay(io.Discard), dir)
			state := &PipelineState{Step: StepRun, BaseBranch: "develop"}

			var gotLoopConfig loop.Config
			origRunLoopWithConfig := runLoopWithConfig
			runLoopWithConfig = func(ctx context.Context, cfg loop.Config) (loop.Result, error) {
				gotLoopConfig = cfg
				return tt.loopResult, nil
			}
			t.Cleanup(func() {
				runLoopWithConfig = origRunLoopWithConfig
			})

			err := pipeline.runLoopStep(context.Background(), state, RunOptions{})
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("runLoopStep returned error: %v", err)
			}

			if gotLoopConfig.PRDFile != template.PRDFile {
				t.Fatalf("loop config PRDFile = %q, want %q", gotLoopConfig.PRDFile, template.PRDFile)
			}
			if gotLoopConfig.ProgressFile != template.ProgressFile {
				t.Fatalf("loop config ProgressFile = %q, want %q", gotLoopConfig.ProgressFile, template.ProgressFile)
			}
			wantLoopDir := filepath.Join(dir, template.HalDir)
			if gotLoopConfig.Dir != wantLoopDir {
				t.Fatalf("loop config Dir = %q, want %q", gotLoopConfig.Dir, wantLoopDir)
			}

			if state.Step != tt.wantStep {
				t.Fatalf("state.Step = %q, want %q", state.Step, tt.wantStep)
			}
			if state.Run == nil {
				t.Fatal("state.Run is nil")
			}
			if state.Run.Iterations != tt.loopResult.Iterations {
				t.Fatalf("state.Run.Iterations = %d, want %d", state.Run.Iterations, tt.loopResult.Iterations)
			}
			if state.Run.Complete != tt.loopResult.Complete {
				t.Fatalf("state.Run.Complete = %v, want %v", state.Run.Complete, tt.loopResult.Complete)
			}
			if state.Run.MaxIterations != cfg.MaxIterations {
				t.Fatalf("state.Run.MaxIterations = %d, want %d", state.Run.MaxIterations, cfg.MaxIterations)
			}

			saved := pipeline.loadState()
			if saved == nil {
				t.Fatal("saved state is nil")
			}
			if saved.Step != tt.wantStep {
				t.Fatalf("saved.Step = %q, want %q", saved.Step, tt.wantStep)
			}
			if saved.Run == nil {
				t.Fatal("saved.Run is nil")
			}
			if saved.Run.Iterations != tt.loopResult.Iterations {
				t.Fatalf("saved.Run.Iterations = %d, want %d", saved.Run.Iterations, tt.loopResult.Iterations)
			}
			if saved.Run.Complete != tt.loopResult.Complete {
				t.Fatalf("saved.Run.Complete = %v, want %v", saved.Run.Complete, tt.loopResult.Complete)
			}
			if saved.Run.MaxIterations != cfg.MaxIterations {
				t.Fatalf("saved.Run.MaxIterations = %d, want %d", saved.Run.MaxIterations, cfg.MaxIterations)
			}
		})
	}
}
