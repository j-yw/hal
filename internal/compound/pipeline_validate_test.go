package compound

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/jywlabs/hal/internal/template"
)

func TestRunValidateStep_FirstPassSuccessPersistsTelemetry(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	prdPath := filepath.Join(halDir, template.PRDFile)
	if err := os.WriteFile(prdPath, []byte(`{"project":"test","branchName":"hal/validate"}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{Step: StepValidate}

	validateCalls := 0
	origValidateWithEngine := validateWithEngine
	validateWithEngine = func(ctx context.Context, eng engine.Engine, gotPath string, display *engine.Display) (*prd.ValidationResult, error) {
		validateCalls++
		if gotPath != prdPath {
			t.Fatalf("validate path = %q, want %q", gotPath, prdPath)
		}
		return &prd.ValidationResult{Valid: true}, nil
	}
	t.Cleanup(func() {
		validateWithEngine = origValidateWithEngine
	})

	if err := pipeline.runValidateStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runValidateStep returned error: %v", err)
	}

	if validateCalls != 1 {
		t.Fatalf("validate calls = %d, want 1", validateCalls)
	}
	if state.Step != StepRun {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepRun)
	}
	if state.Validation == nil {
		t.Fatal("state.Validation = nil, want telemetry")
	}
	if state.Validation.Attempts != 1 {
		t.Fatalf("state.Validation.Attempts = %d, want 1", state.Validation.Attempts)
	}
	if state.Validation.Status != "passed" {
		t.Fatalf("state.Validation.Status = %q, want %q", state.Validation.Status, "passed")
	}

	saved := pipeline.loadState()
	if saved == nil {
		t.Fatal("saved state = nil")
	}
	if saved.Validation == nil {
		t.Fatal("saved.Validation = nil")
	}
	if saved.Validation.Attempts != 1 || saved.Validation.Status != "passed" {
		t.Fatalf("saved validation = %+v, want attempts=1 status=passed", saved.Validation)
	}
}

func TestRunValidateStep_SucceedsAfterRepairCycle(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	sourceMarkdown := filepath.Join(halDir, "prd-source.md")
	if err := os.WriteFile(sourceMarkdown, []byte("# PRD: Validate Repair\n"), 0644); err != nil {
		t.Fatalf("write source markdown: %v", err)
	}

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{
		Step:           StepValidate,
		SourceMarkdown: sourceMarkdown,
		BranchName:     "hal/validate-repair",
	}

	validateCalls := 0
	origValidateWithEngine := validateWithEngine
	validateWithEngine = func(ctx context.Context, eng engine.Engine, gotPath string, display *engine.Display) (*prd.ValidationResult, error) {
		validateCalls++
		switch validateCalls {
		case 1:
			return &prd.ValidationResult{Valid: false, Errors: []prd.Issue{{Message: "task too large"}}}, nil
		case 2:
			return &prd.ValidationResult{Valid: true}, nil
		default:
			t.Fatalf("unexpected validate call #%d", validateCalls)
			return nil, nil
		}
	}
	t.Cleanup(func() {
		validateWithEngine = origValidateWithEngine
	})

	convertCalls := 0
	origConvertWithEngine := convertWithEngine
	convertWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, outPath string, opts prd.ConvertOptions, display *engine.Display) error {
		convertCalls++
		if mdPath != sourceMarkdown {
			t.Fatalf("convert mdPath = %q, want %q", mdPath, sourceMarkdown)
		}
		payload := `{"project":"test","branchName":"hal/validate-repair","description":"desc","userStories":[]}`
		if err := os.WriteFile(outPath, []byte(payload), 0644); err != nil {
			return err
		}
		return nil
	}
	t.Cleanup(func() {
		convertWithEngine = origConvertWithEngine
	})

	if err := pipeline.runValidateStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("first runValidateStep returned error: %v", err)
	}
	if state.Step != StepConvert {
		t.Fatalf("state.Step after first validate = %q, want %q", state.Step, StepConvert)
	}
	if state.Validation == nil || state.Validation.Attempts != 1 || state.Validation.Status != "repairing" {
		t.Fatalf("validation telemetry after first attempt = %+v, want attempts=1 status=repairing", state.Validation)
	}

	state.Step = StepConvert
	if err := pipeline.runExplodeStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runExplodeStep returned error: %v", err)
	}
	if state.Step != StepValidate {
		t.Fatalf("state.Step after repair convert = %q, want %q", state.Step, StepValidate)
	}
	if convertCalls != 1 {
		t.Fatalf("convert calls = %d, want 1", convertCalls)
	}

	if err := pipeline.runValidateStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("second runValidateStep returned error: %v", err)
	}
	if validateCalls != 2 {
		t.Fatalf("validate calls = %d, want 2", validateCalls)
	}
	if state.Step != StepRun {
		t.Fatalf("state.Step after second validate = %q, want %q", state.Step, StepRun)
	}
	if state.Validation == nil || state.Validation.Attempts != 2 || state.Validation.Status != "passed" {
		t.Fatalf("validation telemetry after recovery = %+v, want attempts=2 status=passed", state.Validation)
	}
}

func TestRunValidateStep_FailsAfterMaxAttempts(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	prdPath := filepath.Join(halDir, template.PRDFile)
	if err := os.WriteFile(prdPath, []byte(`{"project":"test"}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{Step: StepValidate}

	validateCalls := 0
	origValidateWithEngine := validateWithEngine
	validateWithEngine = func(ctx context.Context, eng engine.Engine, gotPath string, display *engine.Display) (*prd.ValidationResult, error) {
		validateCalls++
		if gotPath != prdPath {
			t.Fatalf("validate path = %q, want %q", gotPath, prdPath)
		}
		return &prd.ValidationResult{Valid: false, Errors: []prd.Issue{{Message: "still invalid"}}}, nil
	}
	t.Cleanup(func() {
		validateWithEngine = origValidateWithEngine
	})

	for attempt := 1; attempt < maxValidationAttempts; attempt++ {
		err := pipeline.runValidateStep(context.Background(), state, RunOptions{})
		if err != nil {
			t.Fatalf("attempt %d returned unexpected error: %v", attempt, err)
		}
		if state.Step != StepConvert {
			t.Fatalf("attempt %d state.Step = %q, want %q", attempt, state.Step, StepConvert)
		}
		if state.Validation == nil {
			t.Fatalf("attempt %d state.Validation is nil", attempt)
		}
		if state.Validation.Attempts != attempt {
			t.Fatalf("attempt %d telemetry attempts=%d, want %d", attempt, state.Validation.Attempts, attempt)
		}
		if state.Validation.Status != "repairing" {
			t.Fatalf("attempt %d telemetry status=%q, want %q", attempt, state.Validation.Status, "repairing")
		}
		state.Step = StepValidate // Simulate successful repair convert and retry validation.
	}

	err := pipeline.runValidateStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected final validation attempt to fail")
	}
	if !strings.Contains(err.Error(), "PRD validation failed after 3 attempts") {
		t.Fatalf("error = %q, want max-attempts message", err.Error())
	}
	if validateCalls != maxValidationAttempts {
		t.Fatalf("validate calls = %d, want %d", validateCalls, maxValidationAttempts)
	}
	if state.Step != StepValidate {
		t.Fatalf("state.Step on terminal failure = %q, want %q", state.Step, StepValidate)
	}
	if state.Validation == nil {
		t.Fatal("state.Validation is nil")
	}
	if state.Validation.Attempts != maxValidationAttempts {
		t.Fatalf("state.Validation.Attempts = %d, want %d", state.Validation.Attempts, maxValidationAttempts)
	}
	if state.Validation.Status != "failed" {
		t.Fatalf("state.Validation.Status = %q, want %q", state.Validation.Status, "failed")
	}

	saved := pipeline.loadState()
	if saved == nil || saved.Validation == nil {
		t.Fatalf("saved state validation missing: %+v", saved)
	}
	if saved.Validation.Attempts != maxValidationAttempts || saved.Validation.Status != "failed" {
		t.Fatalf("saved validation telemetry = %+v, want attempts=%d status=failed", saved.Validation, maxValidationAttempts)
	}
}
