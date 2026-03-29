package compound

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/loop"
	"github.com/jywlabs/hal/internal/template"
)

type runStepTestEngine struct{}

func (runStepTestEngine) Name() string {
	return "run-step-test"
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
