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

	state := &PipelineState{Step: StepSpec, BaseBranch: "main"}
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

func TestNewInitialState_WithSourceMarkdownStartsAtBranch(t *testing.T) {
	dir := t.TempDir()
	mdPath := filepath.Join(dir, "prd-entry.md")
	if err := os.WriteFile(mdPath, []byte("# PRD: Entry Resolution\n"), 0644); err != nil {
		t.Fatalf("write markdown: %v", err)
	}

	pipeline := NewPipeline(&AutoConfig{}, nil, engine.NewDisplay(&bytes.Buffer{}), dir)
	state, err := pipeline.newInitialState(RunOptions{SourceMarkdown: mdPath})
	if err != nil {
		t.Fatalf("newInitialState returned error: %v", err)
	}

	if state.Step != StepBranch {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepBranch)
	}
	if state.SourceMarkdown != mdPath {
		t.Fatalf("state.SourceMarkdown = %q, want %q", state.SourceMarkdown, mdPath)
	}
	if state.BranchName != "hal/entry-resolution" {
		t.Fatalf("state.BranchName = %q, want %q", state.BranchName, "hal/entry-resolution")
	}
}

func TestNewInitialState_WithoutSourceMarkdownStartsAnalyze(t *testing.T) {
	pipeline := NewPipeline(&AutoConfig{}, nil, engine.NewDisplay(&bytes.Buffer{}), t.TempDir())
	state, err := pipeline.newInitialState(RunOptions{})
	if err != nil {
		t.Fatalf("newInitialState returned error: %v", err)
	}

	if state.Step != StepAnalyze {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepAnalyze)
	}
	if state.SourceMarkdown != "" {
		t.Fatalf("state.SourceMarkdown = %q, want empty", state.SourceMarkdown)
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
	if state.Step != StepSpec {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepSpec)
	}
	if !strings.Contains(out.String(), "from current HEAD") {
		t.Fatalf("output = %q, want current HEAD message", out.String())
	}
}

func TestRunBranchStep_DryRun_SkipsSpecWhenSourceMarkdownIsPreset(t *testing.T) {
	var out bytes.Buffer
	display := engine.NewDisplay(&out)

	config := DefaultAutoConfig()
	pipeline := NewPipeline(&config, nil, display, t.TempDir())

	state := &PipelineState{
		Step:           StepBranch,
		BranchName:     "hal/test-feature",
		SourceMarkdown: ".hal/prd-test-feature.md",
	}
	if err := pipeline.runBranchStep(context.Background(), state, RunOptions{DryRun: true}); err != nil {
		t.Fatalf("runBranchStep returned error: %v", err)
	}
	if state.Step != StepConvert {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepConvert)
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
