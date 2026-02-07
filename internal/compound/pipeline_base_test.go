package compound

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
)

func TestInitializeBaseBranch_AllowsDetachedHead(t *testing.T) {
	var out bytes.Buffer
	display := engine.NewDisplay(&out)

	config := DefaultAutoConfig()
	pipeline := NewPipeline(&config, nil, display, t.TempDir())
	pipeline.currentBranchFn = func() (string, error) {
		return "", nil
	}

	state := &PipelineState{Step: StepAnalyze}
	if err := pipeline.initializeBaseBranch(state, RunOptions{}); err != nil {
		t.Fatalf("initializeBaseBranch returned error: %v", err)
	}
	if state.BaseBranch != "" {
		t.Fatalf("BaseBranch = %q, want empty", state.BaseBranch)
	}
}

func TestInitializeBaseBranch_UsesOverrideWithoutGitLookup(t *testing.T) {
	var out bytes.Buffer
	display := engine.NewDisplay(&out)

	config := DefaultAutoConfig()
	pipeline := NewPipeline(&config, nil, display, t.TempDir())

	called := false
	pipeline.currentBranchFn = func() (string, error) {
		called = true
		return "main", nil
	}

	state := &PipelineState{Step: StepAnalyze}
	opts := RunOptions{BaseBranch: "  develop  "}
	if err := pipeline.initializeBaseBranch(state, opts); err != nil {
		t.Fatalf("initializeBaseBranch returned error: %v", err)
	}
	if called {
		t.Fatal("current branch resolver should not be called when --base is set")
	}
	if state.BaseBranch != "develop" {
		t.Fatalf("BaseBranch = %q, want %q", state.BaseBranch, "develop")
	}
}

func TestInitializeBaseBranch_PropagatesLookupError(t *testing.T) {
	var out bytes.Buffer
	display := engine.NewDisplay(&out)

	config := DefaultAutoConfig()
	pipeline := NewPipeline(&config, nil, display, t.TempDir())
	pipeline.currentBranchFn = func() (string, error) {
		return "", errors.New("git unavailable")
	}

	state := &PipelineState{Step: StepAnalyze}
	err := pipeline.initializeBaseBranch(state, RunOptions{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to determine current branch") {
		t.Fatalf("error = %q, missing context", err.Error())
	}
}

func TestRunBranchStep_DryRun_AllowsEmptyBase(t *testing.T) {
	var out bytes.Buffer
	display := engine.NewDisplay(&out)

	config := DefaultAutoConfig()
	pipeline := NewPipeline(&config, nil, display, t.TempDir())

	state := &PipelineState{
		Step:       StepBranch,
		BranchName: "compound/test-feature",
		BaseBranch: "",
	}
	if err := pipeline.runBranchStep(context.Background(), state, RunOptions{DryRun: true}); err != nil {
		t.Fatalf("runBranchStep returned error: %v", err)
	}
	if state.Step != StepPRD {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepPRD)
	}
	if !strings.Contains(out.String(), "from current HEAD") {
		t.Fatalf("output = %q, want current HEAD message", out.String())
	}
}
