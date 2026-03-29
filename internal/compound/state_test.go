package compound

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

func TestLoadState_LegacyMappings(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantStep   string
		wantSource string
		wantRun    *RunState
	}{
		{
			name: "maps prd step and prdPath",
			payload: `{
  "step": "prd",
  "branchName": "hal/feature",
  "prdPath": ".hal/prd-feature.md",
  "startedAt": "2026-03-29T00:00:00Z"
}`,
			wantStep:   StepSpec,
			wantSource: ".hal/prd-feature.md",
		},
		{
			name: "maps explode step",
			payload: `{
  "step": "explode",
  "branchName": "hal/feature",
  "startedAt": "2026-03-29T00:00:00Z"
}`,
			wantStep: StepConvert,
		},
		{
			name: "maps loop step and loop telemetry",
			payload: `{
  "step": "loop",
  "branchName": "hal/feature",
  "startedAt": "2026-03-29T00:00:00Z",
  "loopIterations": 7,
  "loopComplete": true,
  "loopMaxIterations": 25
}`,
			wantStep: StepRun,
			wantRun: &RunState{
				Iterations:    7,
				Complete:      true,
				MaxIterations: 25,
			},
		},
		{
			name: "maps pr step",
			payload: `{
  "step": "pr",
  "branchName": "hal/feature",
  "startedAt": "2026-03-29T00:00:00Z"
}`,
			wantStep: StepCI,
		},
		{
			name: "prefers sourceMarkdown when both paths exist",
			payload: `{
  "step": "spec",
  "branchName": "hal/feature",
  "sourceMarkdown": ".hal/prd-canonical.md",
  "prdPath": ".hal/prd-legacy.md",
  "startedAt": "2026-03-29T00:00:00Z"
}`,
			wantStep:   StepSpec,
			wantSource: ".hal/prd-canonical.md",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := newStateTestPipeline(t)
			if err := os.WriteFile(pipeline.statePath(), []byte(tt.payload), 0644); err != nil {
				t.Fatalf("write state: %v", err)
			}

			state := pipeline.loadState()
			if state == nil {
				t.Fatal("loadState returned nil")
			}
			if state.Step != tt.wantStep {
				t.Fatalf("state.Step = %q, want %q", state.Step, tt.wantStep)
			}
			if state.SourceMarkdown != tt.wantSource {
				t.Fatalf("state.SourceMarkdown = %q, want %q", state.SourceMarkdown, tt.wantSource)
			}
			if tt.wantRun == nil {
				if state.Run != nil {
					t.Fatalf("state.Run = %+v, want nil", state.Run)
				}
				return
			}
			if state.Run == nil {
				t.Fatal("state.Run is nil, want telemetry")
			}
			if state.Run.Iterations != tt.wantRun.Iterations {
				t.Fatalf("state.Run.Iterations = %d, want %d", state.Run.Iterations, tt.wantRun.Iterations)
			}
			if state.Run.Complete != tt.wantRun.Complete {
				t.Fatalf("state.Run.Complete = %v, want %v", state.Run.Complete, tt.wantRun.Complete)
			}
			if state.Run.MaxIterations != tt.wantRun.MaxIterations {
				t.Fatalf("state.Run.MaxIterations = %d, want %d", state.Run.MaxIterations, tt.wantRun.MaxIterations)
			}
		})
	}
}

func TestStateRoundTrip_UsesUnifiedSchema(t *testing.T) {
	pipeline := newStateTestPipeline(t)
	now := time.Date(2026, 3, 29, 12, 0, 0, 0, time.UTC)

	original := &PipelineState{
		Step:           StepRun,
		BaseBranch:     "develop",
		BranchName:     "hal/feature",
		SourceMarkdown: ".hal/prd-feature.md",
		ReportPath:     ".hal/reports/report.md",
		StartedAt:      now,
		Validation: &ValidationState{
			Attempts: 2,
			Status:   "passed",
		},
		Run: &RunState{
			Iterations:    5,
			Complete:      false,
			MaxIterations: 25,
		},
		Review: &ReviewState{Status: "pending"},
		CI:     &CIState{Status: "skipped", Reason: "skip_ci_flag"},
		Analysis: &AnalysisResult{
			PriorityItem:       "Top issue",
			Description:        "Fix top issue",
			Rationale:          "Blocks release",
			AcceptanceCriteria: []string{"AC-1", "AC-2"},
			EstimatedTasks:     4,
			BranchName:         "feature",
		},
	}

	if err := pipeline.saveState(original); err != nil {
		t.Fatalf("saveState: %v", err)
	}

	data, err := os.ReadFile(pipeline.statePath())
	if err != nil {
		t.Fatalf("read saved state: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal saved state: %v", err)
	}

	requiredKeys := []string{"step", "baseBranch", "branchName", "sourceMarkdown", "reportPath", "startedAt", "validation", "run", "review", "ci", "analysis"}
	for _, key := range requiredKeys {
		if _, ok := raw[key]; !ok {
			t.Fatalf("saved state missing key %q", key)
		}
	}

	legacyKeys := []string{"prdPath", "loopIterations", "loopComplete", "loopMaxIterations"}
	for _, key := range legacyKeys {
		if _, ok := raw[key]; ok {
			t.Fatalf("saved state should not include legacy key %q", key)
		}
	}

	loaded := pipeline.loadState()
	if loaded == nil {
		t.Fatal("loadState returned nil")
	}

	if loaded.Step != original.Step {
		t.Fatalf("loaded.Step = %q, want %q", loaded.Step, original.Step)
	}
	if loaded.SourceMarkdown != original.SourceMarkdown {
		t.Fatalf("loaded.SourceMarkdown = %q, want %q", loaded.SourceMarkdown, original.SourceMarkdown)
	}
	if loaded.Run == nil || loaded.Run.Iterations != original.Run.Iterations {
		t.Fatalf("loaded.Run = %+v, want iterations %d", loaded.Run, original.Run.Iterations)
	}
	if loaded.Validation == nil || loaded.Validation.Attempts != original.Validation.Attempts {
		t.Fatalf("loaded.Validation = %+v, want attempts %d", loaded.Validation, original.Validation.Attempts)
	}
	if loaded.CI == nil || loaded.CI.Reason != original.CI.Reason {
		t.Fatalf("loaded.CI = %+v, want reason %q", loaded.CI, original.CI.Reason)
	}
}

func newStateTestPipeline(t *testing.T) *Pipeline {
	t.Helper()

	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	cfg := DefaultAutoConfig()
	display := engine.NewDisplay(io.Discard)
	pipeline := NewPipeline(&cfg, nil, display, dir)
	return pipeline
}
