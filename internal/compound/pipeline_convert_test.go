package compound

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/archive"
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

func TestRunConvertStep_ArchivesPriorCanonicalStateBeforeBranchChange(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	sourceMarkdown := filepath.Join(halDir, "prd-new.md")

	writeCompoundFile(t, filepath.Join(halDir, template.PRDFile), `{"project":"test","branchName":"hal/old-feature","description":"old","userStories":[]}`)
	writeCompoundFile(t, filepath.Join(halDir, template.ProgressFile), "existing progress")
	writeCompoundFile(t, filepath.Join(halDir, template.AutoStateFile), `{"step":"convert","branchName":"hal/new-feature"}`)
	writeCompoundFile(t, sourceMarkdown, "# PRD: New Feature\n")

	state := &PipelineState{
		Step:           StepConvert,
		SourceMarkdown: sourceMarkdown,
		BranchName:     "hal/new-feature",
		ConvertMode:    AutoConvertModeGranular,
	}

	var out bytes.Buffer
	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(&out), dir)

	origConvertWithEngine := convertWithEngine
	origCreateArchiveWithOptions := createArchiveWithOptions
	convertWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, outPath string, opts prd.ConvertOptions, display *engine.Display) error {
		payload := `{"project":"test","branchName":"hal/new-feature","description":"desc","userStories":[]}`
		return os.WriteFile(outPath, []byte(payload), 0644)
	}
	createArchiveWithOptions = archive.CreateWithOptions
	t.Cleanup(func() {
		convertWithEngine = origConvertWithEngine
		createArchiveWithOptions = origCreateArchiveWithOptions
	})

	if err := pipeline.runExplodeStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runExplodeStep returned error: %v", err)
	}

	if state.Step != StepValidate {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepValidate)
	}

	if got := readPRDBranchNameForCompoundTest(t, filepath.Join(halDir, template.PRDFile)); got != "hal/new-feature" {
		t.Fatalf("canonical prd branchName = %q, want %q", got, "hal/new-feature")
	}
	if _, err := os.Stat(sourceMarkdown); err != nil {
		t.Fatalf("expected source markdown to remain in place: %v", err)
	}
	if _, err := os.Stat(filepath.Join(halDir, template.AutoStateFile)); err != nil {
		t.Fatalf("expected auto state to remain in place: %v", err)
	}
	if _, err := os.Stat(filepath.Join(halDir, template.ProgressFile)); !os.IsNotExist(err) {
		t.Fatalf("expected progress to be archived, stat err=%v", err)
	}

	entries, err := os.ReadDir(filepath.Join(halDir, "archive"))
	if err != nil {
		t.Fatalf("read archive dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("archive entry count = %d, want 1", len(entries))
	}

	archiveDir := filepath.Join(halDir, "archive", entries[0].Name())
	if _, err := os.Stat(filepath.Join(archiveDir, template.PRDFile)); err != nil {
		t.Fatalf("expected archived prd.json: %v", err)
	}
	if got := readPRDBranchNameForCompoundTest(t, filepath.Join(archiveDir, template.PRDFile)); got != "hal/old-feature" {
		t.Fatalf("archived prd branchName = %q, want %q", got, "hal/old-feature")
	}
	if _, err := os.Stat(filepath.Join(archiveDir, template.ProgressFile)); err != nil {
		t.Fatalf("expected archived progress.txt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(archiveDir, filepath.Base(sourceMarkdown))); !os.IsNotExist(err) {
		t.Fatalf("source markdown should be excluded from archive, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(archiveDir, template.AutoStateFile)); !os.IsNotExist(err) {
		t.Fatalf("auto state should be excluded from archive, stat err=%v", err)
	}
}

func readPRDBranchNameForCompoundTest(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	prdFile := engine.PRD{}
	if err := json.Unmarshal(data, &prdFile); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}

	return prdFile.BranchName
}
