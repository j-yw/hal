package compound

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
)

func TestInitializeBaseBranch_UsesSavedBaseAndIgnoresOverride(t *testing.T) {
	var out bytes.Buffer
	display := engine.NewDisplay(&out)

	config := DefaultAutoConfig()
	pipeline := NewPipeline(&config, nil, display, t.TempDir())

	state := &PipelineState{Step: StepPRD, BaseBranch: "main"}
	opts := RunOptions{Resume: true, BaseBranch: "develop"}

	if err := pipeline.initializeBaseBranch(state, opts); err != nil {
		t.Fatalf("initializeBaseBranch returned error: %v", err)
	}
	if state.BaseBranch != "main" {
		t.Fatalf("BaseBranch = %q, want %q", state.BaseBranch, "main")
	}
	if !strings.Contains(out.String(), "ignoring --base") {
		t.Fatalf("expected override warning in output, got %q", out.String())
	}
}

func TestInitializeBaseBranch_UsesOverrideWhenStateEmpty(t *testing.T) {
	var out bytes.Buffer
	display := engine.NewDisplay(&out)

	config := DefaultAutoConfig()
	pipeline := NewPipeline(&config, nil, display, t.TempDir())

	state := &PipelineState{Step: StepAnalyze}
	opts := RunOptions{BaseBranch: "  develop  "}

	if err := pipeline.initializeBaseBranch(state, opts); err != nil {
		t.Fatalf("initializeBaseBranch returned error: %v", err)
	}
	if state.BaseBranch != "develop" {
		t.Fatalf("BaseBranch = %q, want %q", state.BaseBranch, "develop")
	}
}

func TestInitializeBaseBranch_FallsBackWhenLookupFails(t *testing.T) {
	var out bytes.Buffer
	display := engine.NewDisplay(&out)

	config := DefaultAutoConfig()
	pipeline := NewPipeline(&config, nil, display, t.TempDir())

	state := &PipelineState{Step: StepAnalyze}
	if err := pipeline.initializeBaseBranch(state, RunOptions{}); err != nil {
		t.Fatalf("initializeBaseBranch returned error: %v", err)
	}
	if state.BaseBranch != "" {
		t.Fatalf("BaseBranch = %q, want empty", state.BaseBranch)
	}
	if !strings.Contains(out.String(), "defaulting to current HEAD") {
		t.Fatalf("expected fallback warning in output, got %q", out.String())
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

func TestRun_DryRun_AllowsDetachedHeadEndToEnd(t *testing.T) {
	dir := t.TempDir()
	reportsDir := filepath.Join(dir, ".hal", "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("mkdir reports: %v", err)
	}
	reportPath := filepath.Join(reportsDir, "report.md")
	if err := os.WriteFile(reportPath, []byte("# report"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	var out bytes.Buffer
	display := engine.NewDisplay(&out)

	config := DefaultAutoConfig()
	pipeline := NewPipeline(&config, nil, display, dir)

	err := pipeline.Run(context.Background(), RunOptions{DryRun: true})
	if err != nil {
		t.Fatalf("pipeline.Run should succeed in detached-HEAD dry-run: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Would create branch: compound/dry-run (from current HEAD)") {
		t.Fatalf("output = %q, expected current HEAD branch message", output)
	}
}
