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
		BranchName: "hal/no-ci",
		StartedAt:  time.Now(),
	}

	if err := pipeline.runPRStep(context.Background(), state, RunOptions{SkipCI: true}); err != nil {
		t.Fatalf("runPRStep returned error: %v", err)
	}

	if state.Step != StepReport {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepReport)
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
	if !strings.Contains(out.String(), "Skipping CI step (--no-ci)") {
		t.Fatalf("expected no-ci output message, got %q", out.String())
	}
	if !pipeline.HasState() {
		t.Fatal("pipeline state should be saved after no-ci to allow report step")
	}
}

func TestRunPRStep_SkipCIFlagDryRunPreservesSavedState(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultAutoConfig()

	var out bytes.Buffer
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(&out), dir)
	state := &PipelineState{
		Step:       StepCI,
		BaseBranch: "develop",
		BranchName: "hal/no-ci",
		StartedAt:  time.Now(),
	}

	if err := pipeline.saveState(state); err != nil {
		t.Fatalf("saveState returned error: %v", err)
	}

	if err := pipeline.runPRStep(context.Background(), state, RunOptions{SkipCI: true, DryRun: true}); err != nil {
		t.Fatalf("runPRStep returned error: %v", err)
	}

	if state.Step != StepReport {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepReport)
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
	if !pipeline.HasState() {
		t.Fatal("pipeline state should be preserved during dry-run no-ci")
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

	err := pipeline.runPRStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected CI dependency gate error")
	}
	if !strings.Contains(err.Error(), "CI dependencies unavailable") {
		t.Fatalf("err = %v, want dependency gate message", err)
	}

	if state.Step != StepCI {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepCI)
	}
	if state.CI == nil {
		t.Fatal("state.CI is nil")
	}
	if state.CI.Status != "failed" {
		t.Fatalf("state.CI.Status = %q, want %q", state.CI.Status, "failed")
	}
	if state.CI.Reason != "ci_unavailable" {
		t.Fatalf("state.CI.Reason = %q, want %q", state.CI.Reason, "ci_unavailable")
	}
	if !strings.Contains(out.String(), "dependencies unavailable") {
		t.Fatalf("expected dependency-unavailable output message, got %q", out.String())
	}
	if !strings.Contains(out.String(), "stopping at CI step") {
		t.Fatalf("expected stop-at-ci output message, got %q", out.String())
	}
	if !pipeline.HasState() {
		t.Fatal("pipeline state should be saved when CI gate blocks on missing dependencies")
	}
}
