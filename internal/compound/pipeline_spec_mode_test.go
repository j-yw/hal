package compound

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

type promptCaptureEngine struct {
	prompt string
}

func (p *promptCaptureEngine) Name() string {
	return "test"
}

func (p *promptCaptureEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (p *promptCaptureEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	p.prompt = prompt
	return "", nil
}

func (p *promptCaptureEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	p.prompt = prompt
	return "# PRD: Generated\n", nil
}

func TestRunPRDStep_ModeAwarePromptOverride(t *testing.T) {
	tests := []struct {
		name             string
		mode             string
		wantModeLine     string
		wantGuidanceLine string
	}{
		{
			name:             "standard mode uses user stories",
			mode:             AutoConvertModeStandard,
			wantModeLine:     "Resolved convert mode for this run: standard",
			wantGuidanceLine: "Use US-XXX user story IDs",
		},
		{
			name:             "granular mode uses tasks",
			mode:             AutoConvertModeGranular,
			wantModeLine:     "Resolved convert mode for this run: granular",
			wantGuidanceLine: "Use T-XXX task IDs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, template.HalDir)
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("mkdir .hal: %v", err)
			}

			eng := &promptCaptureEngine{}
			cfg := DefaultAutoConfig()
			pipeline := NewPipeline(&cfg, eng, engine.NewDisplay(io.Discard), dir)

			state := &PipelineState{
				Step:        StepSpec,
				ConvertMode: tt.mode,
				Analysis: &AnalysisResult{
					PriorityItem:       "Mode-aware spec",
					Description:        "Generate mode-specific PRD",
					Rationale:          "Ensure convert mode policy is enforced",
					AcceptanceCriteria: []string{"Typecheck passes"},
					EstimatedTasks:     2,
					BranchName:         "mode-aware-spec",
				},
			}

			if err := pipeline.runPRDStep(context.Background(), state, RunOptions{}); err != nil {
				t.Fatalf("runPRDStep returned error: %v", err)
			}

			if !strings.Contains(eng.prompt, tt.wantModeLine) {
				t.Fatalf("prompt missing mode line %q\nprompt:\n%s", tt.wantModeLine, eng.prompt)
			}
			if !strings.Contains(eng.prompt, "mode override is authoritative for this run") {
				t.Fatalf("prompt missing authoritative override text\nprompt:\n%s", eng.prompt)
			}
			if !strings.Contains(eng.prompt, tt.wantGuidanceLine) {
				t.Fatalf("prompt missing mode-specific guidance %q\nprompt:\n%s", tt.wantGuidanceLine, eng.prompt)
			}
		})
	}
}
