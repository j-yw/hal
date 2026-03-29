package compound

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

func TestRunPRStep_SkipCIFlagMarksSkipped(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()

	var out bytes.Buffer
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(&out), dir)
	state := &PipelineState{
		Step:       StepCI,
		BaseBranch: "develop",
		BranchName: "hal/skip-ci",
		StartedAt:  time.Now(),
	}

	if err := pipeline.runPRStep(context.Background(), state, RunOptions{SkipCI: true}); err != nil {
		t.Fatalf("runPRStep returned error: %v", err)
	}

	if state.Step != StepDone {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepDone)
	}
	if state.CI == nil {
		t.Fatal("state.CI is nil")
	}
	if state.CI.Status != "skipped" {
		t.Fatalf("state.CI.Status = %q, want %q", state.CI.Status, "skipped")
	}
	if state.CI.Reason != "skip_ci_flag" {
		t.Fatalf("state.CI.Reason = %q, want %q", state.CI.Reason, "skip_ci_flag")
	}
	if !strings.Contains(out.String(), "Skipping CI step (--skip-ci)") {
		t.Fatalf("expected skip-ci output message, got %q", out.String())
	}
	if pipeline.HasState() {
		t.Fatal("pipeline state should be cleared after skip-ci completion")
	}
}

func TestRunPRStep_CIDependenciesUnavailableMarksSkipped(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()

	var out bytes.Buffer
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(&out), dir)
	state := &PipelineState{
		Step:       StepCI,
		BaseBranch: "develop",
		BranchName: "hal/ci-unavailable",
		StartedAt:  time.Now(),
	}

	origCheckCIDependencies := checkCIDependencies
	checkCIDependencies = func() error {
		return errors.New("gh CLI not found in PATH")
	}
	t.Cleanup(func() {
		checkCIDependencies = origCheckCIDependencies
	})

	if err := pipeline.runPRStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runPRStep returned error: %v", err)
	}

	if state.Step != StepDone {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepDone)
	}
	if state.CI == nil {
		t.Fatal("state.CI is nil")
	}
	if state.CI.Status != "skipped" {
		t.Fatalf("state.CI.Status = %q, want %q", state.CI.Status, "skipped")
	}
	if state.CI.Reason != "ci_unavailable" {
		t.Fatalf("state.CI.Reason = %q, want %q", state.CI.Reason, "ci_unavailable")
	}
	if !strings.Contains(out.String(), "dependencies unavailable") {
		t.Fatalf("expected dependency-unavailable output message, got %q", out.String())
	}
	if pipeline.HasState() {
		t.Fatal("pipeline state should be cleared after ci_unavailable skip")
	}
}
