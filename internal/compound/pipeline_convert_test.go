package compound

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/jywlabs/hal/internal/template"
)

func TestRunConvertStep_UsesGranularPinnedBranchAndPersistsState(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir hal dir: %v", err)
	}

	sourceMarkdown := filepath.Join(halDir, "prd-source.md")
	if err := os.WriteFile(sourceMarkdown, []byte("# PRD: Convert Branch Invariant\n"), 0644); err != nil {
		t.Fatalf("write source markdown: %v", err)
	}

	state := &PipelineState{
		Step:           StepConvert,
		SourceMarkdown: sourceMarkdown,
		BranchName:     "hal/convert-branch-invariant",
		ConvertMode:    AutoConvertModeGranular,
	}

	var out bytes.Buffer
	display := engine.NewDisplay(&out)
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, display, dir)

	var gotSourcePath string
	var gotOutPath string
	var gotOpts prd.ConvertOptions

	origConvertWithEngine := convertWithEngine
	convertWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, outPath string, opts prd.ConvertOptions, display *engine.Display) error {
		gotSourcePath = mdPath
		gotOutPath = outPath
		gotOpts = opts

		payload := `{"project":"test","branchName":"hal/convert-branch-invariant","description":"desc","userStories":[]}`
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return err
		}
		return os.WriteFile(outPath, []byte(payload), 0644)
	}
	t.Cleanup(func() {
		convertWithEngine = origConvertWithEngine
	})

	if err := pipeline.runExplodeStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runExplodeStep returned error: %v", err)
	}

	if gotSourcePath != sourceMarkdown {
		t.Fatalf("convert source = %q, want %q", gotSourcePath, sourceMarkdown)
	}

	wantOutPath := filepath.Join(dir, template.HalDir, template.PRDFile)
	if gotOutPath != wantOutPath {
		t.Fatalf("convert output = %q, want %q", gotOutPath, wantOutPath)
	}

	if !gotOpts.Granular {
		t.Fatal("convert options should set Granular=true")
	}
	if gotOpts.BranchName != state.BranchName {
		t.Fatalf("convert BranchName = %q, want %q", gotOpts.BranchName, state.BranchName)
	}

	if state.Step != StepValidate {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepValidate)
	}

	saved := pipeline.loadState()
	if saved == nil {
		t.Fatal("expected pipeline state to be saved")
	}
	if saved.Step != StepValidate {
		t.Fatalf("saved.Step = %q, want %q", saved.Step, StepValidate)
	}
	if saved.BranchName != state.BranchName {
		t.Fatalf("saved.BranchName = %q, want %q", saved.BranchName, state.BranchName)
	}
}

func TestRunConvertStep_UsesStandardModeWhenRequested(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir hal dir: %v", err)
	}

	sourceMarkdown := filepath.Join(halDir, "prd-source.md")
	if err := os.WriteFile(sourceMarkdown, []byte("# PRD: Convert Standard Mode\n"), 0644); err != nil {
		t.Fatalf("write source markdown: %v", err)
	}

	state := &PipelineState{
		Step:           StepConvert,
		SourceMarkdown: sourceMarkdown,
		BranchName:     "hal/convert-standard-mode",
		ConvertMode:    AutoConvertModeStandard,
	}

	var gotOpts prd.ConvertOptions
	origConvertWithEngine := convertWithEngine
	convertWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, outPath string, opts prd.ConvertOptions, display *engine.Display) error {
		gotOpts = opts
		payload := `{"project":"test","branchName":"hal/convert-standard-mode","description":"desc","userStories":[]}`
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return err
		}
		return os.WriteFile(outPath, []byte(payload), 0644)
	}
	t.Cleanup(func() {
		convertWithEngine = origConvertWithEngine
	})

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(&bytes.Buffer{}), dir)
	if err := pipeline.runExplodeStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runExplodeStep returned error: %v", err)
	}

	if gotOpts.Granular {
		t.Fatal("convert options should set Granular=false for standard mode")
	}
	if state.ConvertMode != AutoConvertModeStandard {
		t.Fatalf("state.ConvertMode = %q, want %q", state.ConvertMode, AutoConvertModeStandard)
	}
}

func TestRunConvertStep_PostConvertBranchInvariantFailures(t *testing.T) {
	tests := []struct {
		name            string
		convertedBranch string
		convertMode     string
		wantErrSubstr   string
		wantCommandHint string
	}{
		{
			name:            "mismatched branch fails fast in granular mode",
			convertedBranch: "hal/unexpected-branch",
			convertMode:     AutoConvertModeGranular,
			wantErrSubstr:   "state.branchName=\"hal/expected-branch\"",
			wantCommandHint: "hal convert --granular --branch",
		},
		{
			name:            "missing converted branch fails fast in standard mode",
			convertedBranch: "",
			convertMode:     AutoConvertModeStandard,
			wantErrSubstr:   "is missing branchName",
			wantCommandHint: "hal convert --branch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, template.HalDir)
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("mkdir hal dir: %v", err)
			}

			sourceMarkdown := filepath.Join(halDir, "prd-source.md")
			if err := os.WriteFile(sourceMarkdown, []byte("# PRD: Convert Branch Invariant\n"), 0644); err != nil {
				t.Fatalf("write source markdown: %v", err)
			}

			state := &PipelineState{
				Step:           StepConvert,
				SourceMarkdown: sourceMarkdown,
				BranchName:     "hal/expected-branch",
				ConvertMode:    tt.convertMode,
			}

			var out bytes.Buffer
			display := engine.NewDisplay(&out)
			cfg := DefaultAutoConfig()
			pipeline := NewPipeline(&cfg, nil, display, dir)

			origConvertWithEngine := convertWithEngine
			convertWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, outPath string, opts prd.ConvertOptions, display *engine.Display) error {
				payload := `{"project":"test","description":"desc","userStories":[]}`
				if tt.convertedBranch != "" {
					payload = `{"project":"test","branchName":"` + tt.convertedBranch + `","description":"desc","userStories":[]}`
				}
				if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
					return err
				}
				return os.WriteFile(outPath, []byte(payload), 0644)
			}
			t.Cleanup(func() {
				convertWithEngine = origConvertWithEngine
			})

			err := pipeline.runExplodeStep(context.Background(), state, RunOptions{})
			if err == nil {
				t.Fatal("expected runExplodeStep to fail, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErrSubstr)
			}
			if !strings.Contains(err.Error(), tt.wantCommandHint) {
				t.Fatalf("error should include command hint %q, got %q", tt.wantCommandHint, err.Error())
			}

			if state.Step != StepConvert {
				t.Fatalf("state.Step = %q, want %q", state.Step, StepConvert)
			}
		})
	}
}
