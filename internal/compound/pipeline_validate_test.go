package compound

import (
	"context"
	"errors"
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

	repairCalls := 0
	origRepairValidationWithEngine := repairValidationWithEngine
	repairValidationWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, gotPath string, result *prd.ValidationResult, display *engine.Display) error {
		repairCalls++
		t.Fatal("repairValidationWithEngine should not be called when validation passes")
		return nil
	}
	t.Cleanup(func() {
		repairValidationWithEngine = origRepairValidationWithEngine
	})

	if err := pipeline.runValidateStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("runValidateStep returned error: %v", err)
	}

	if validateCalls != 1 {
		t.Fatalf("validate calls = %d, want 1", validateCalls)
	}
	if repairCalls != 0 {
		t.Fatalf("repair calls = %d, want 0", repairCalls)
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

func TestRunValidateStep_SucceedsAfterValidationRepair(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	sourceMarkdown := filepath.Join(halDir, "prd-source.md")
	if err := os.WriteFile(sourceMarkdown, []byte("# PRD: Validate Repair\n"), 0644); err != nil {
		t.Fatalf("write source markdown: %v", err)
	}

	prdPath := filepath.Join(halDir, template.PRDFile)
	if err := os.WriteFile(prdPath, []byte(`{"project":"test","branchName":"hal/validate-repair"}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
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
		if gotPath != prdPath {
			t.Fatalf("validate path = %q, want %q", gotPath, prdPath)
		}
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

	repairCalls := 0
	origRepairValidationWithEngine := repairValidationWithEngine
	repairValidationWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, gotPath string, result *prd.ValidationResult, display *engine.Display) error {
		repairCalls++
		if gotPath != prdPath {
			t.Fatalf("repair prd path = %q, want %q", gotPath, prdPath)
		}
		if mdPath != sourceMarkdown {
			t.Fatalf("repair markdown path = %q, want %q", mdPath, sourceMarkdown)
		}
		if result == nil || result.Valid {
			t.Fatalf("repair result = %+v, want invalid validation result", result)
		}
		return nil
	}
	t.Cleanup(func() {
		repairValidationWithEngine = origRepairValidationWithEngine
	})

	if err := pipeline.runValidateStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("first runValidateStep returned error: %v", err)
	}
	if state.Step != StepValidate {
		t.Fatalf("state.Step after first validate = %q, want %q", state.Step, StepValidate)
	}
	if state.Validation == nil || state.Validation.Attempts != 1 || state.Validation.Status != "repairing" {
		t.Fatalf("validation telemetry after first attempt = %+v, want attempts=1 status=repairing", state.Validation)
	}
	if repairCalls != 1 {
		t.Fatalf("repair calls after first validate = %d, want 1", repairCalls)
	}

	if err := pipeline.runValidateStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("second runValidateStep returned error: %v", err)
	}
	if validateCalls != 2 {
		t.Fatalf("validate calls = %d, want 2", validateCalls)
	}
	if repairCalls != 1 {
		t.Fatalf("repair calls = %d, want 1", repairCalls)
	}
	if state.Step != StepRun {
		t.Fatalf("state.Step after second validate = %q, want %q", state.Step, StepRun)
	}
	if state.Validation == nil || state.Validation.Attempts != 2 || state.Validation.Status != "passed" {
		t.Fatalf("validation telemetry after recovery = %+v, want attempts=2 status=passed", state.Validation)
	}

	saved := pipeline.loadState()
	if saved == nil || saved.Validation == nil {
		t.Fatalf("saved validation telemetry missing: %+v", saved)
	}
	if saved.Validation.Attempts != 2 || saved.Validation.Status != "passed" {
		t.Fatalf("saved validation telemetry = %+v, want attempts=2 status=passed", saved.Validation)
	}
}

func TestRunValidateStep_InvalidResultKeepsRepairingWithoutTerminalFailure(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	sourceMarkdown := filepath.Join(halDir, "prd-source.md")
	if err := os.WriteFile(sourceMarkdown, []byte("# PRD: Validate Retry\n"), 0644); err != nil {
		t.Fatalf("write source markdown: %v", err)
	}

	prdPath := filepath.Join(halDir, template.PRDFile)
	if err := os.WriteFile(prdPath, []byte(`{"project":"test","branchName":"hal/validate-retry"}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{Step: StepValidate, SourceMarkdown: sourceMarkdown}

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

	repairCalls := 0
	origRepairValidationWithEngine := repairValidationWithEngine
	repairValidationWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, gotPath string, result *prd.ValidationResult, display *engine.Display) error {
		repairCalls++
		if gotPath != prdPath {
			t.Fatalf("repair prd path = %q, want %q", gotPath, prdPath)
		}
		if mdPath != sourceMarkdown {
			t.Fatalf("repair markdown path = %q, want %q", mdPath, sourceMarkdown)
		}
		if result == nil || result.Valid {
			t.Fatalf("repair result = %+v, want invalid validation result", result)
		}
		return nil
	}
	t.Cleanup(func() {
		repairValidationWithEngine = origRepairValidationWithEngine
	})

	const iterations = 5
	for attempt := 1; attempt <= iterations; attempt++ {
		err := pipeline.runValidateStep(context.Background(), state, RunOptions{})
		if err != nil {
			t.Fatalf("attempt %d returned unexpected error: %v", attempt, err)
		}
		if state.Step != StepValidate {
			t.Fatalf("attempt %d state.Step = %q, want %q", attempt, state.Step, StepValidate)
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
	}

	if validateCalls != iterations {
		t.Fatalf("validate calls = %d, want %d", validateCalls, iterations)
	}
	if repairCalls != iterations {
		t.Fatalf("repair calls = %d, want %d", repairCalls, iterations)
	}

	saved := pipeline.loadState()
	if saved == nil || saved.Validation == nil {
		t.Fatalf("saved state validation missing: %+v", saved)
	}
	if saved.Validation.Attempts != iterations || saved.Validation.Status != "repairing" {
		t.Fatalf("saved validation telemetry = %+v, want attempts=%d status=repairing", saved.Validation, iterations)
	}
}

func TestRunValidateStep_AllowsFinalVerificationAfterLastRepair(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	sourceMarkdown := filepath.Join(halDir, "prd-source.md")
	if err := os.WriteFile(sourceMarkdown, []byte("# PRD: Validate Final Pass\n"), 0644); err != nil {
		t.Fatalf("write source markdown: %v", err)
	}

	prdPath := filepath.Join(halDir, template.PRDFile)
	if err := os.WriteFile(prdPath, []byte(`{"project":"test","branchName":"hal/validate-final-pass"}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{
		Step:           StepValidate,
		SourceMarkdown: sourceMarkdown,
		Validation: &ValidationState{
			Attempts: defaultValidationMaxAttempts - 1,
		},
	}

	validateCalls := 0
	origValidateWithEngine := validateWithEngine
	validateWithEngine = func(ctx context.Context, eng engine.Engine, gotPath string, display *engine.Display) (*prd.ValidationResult, error) {
		validateCalls++
		if gotPath != prdPath {
			t.Fatalf("validate path = %q, want %q", gotPath, prdPath)
		}
		if validateCalls == 1 {
			return &prd.ValidationResult{Valid: false, Errors: []prd.Issue{{Message: "needs repair"}}}, nil
		}
		if validateCalls == 2 {
			return &prd.ValidationResult{Valid: true}, nil
		}
		t.Fatalf("unexpected validate call #%d", validateCalls)
		return nil, nil
	}
	t.Cleanup(func() {
		validateWithEngine = origValidateWithEngine
	})

	repairCalls := 0
	origRepairValidationWithEngine := repairValidationWithEngine
	repairValidationWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, gotPath string, result *prd.ValidationResult, display *engine.Display) error {
		repairCalls++
		if gotPath != prdPath {
			t.Fatalf("repair prd path = %q, want %q", gotPath, prdPath)
		}
		if mdPath != sourceMarkdown {
			t.Fatalf("repair markdown path = %q, want %q", mdPath, sourceMarkdown)
		}
		if result == nil || result.Valid {
			t.Fatalf("repair result = %+v, want invalid validation result", result)
		}
		return nil
	}
	t.Cleanup(func() {
		repairValidationWithEngine = origRepairValidationWithEngine
	})

	if err := pipeline.runValidateStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("first runValidateStep returned error: %v", err)
	}
	if state.Step != StepValidate {
		t.Fatalf("state.Step after first validate = %q, want %q", state.Step, StepValidate)
	}
	if state.Validation == nil || state.Validation.Attempts != defaultValidationMaxAttempts || state.Validation.Status != "repairing" {
		t.Fatalf("validation telemetry after repair = %+v, want attempts=%d status=repairing", state.Validation, defaultValidationMaxAttempts)
	}

	if err := pipeline.runValidateStep(context.Background(), state, RunOptions{}); err != nil {
		t.Fatalf("second runValidateStep returned error: %v", err)
	}
	if validateCalls != 2 {
		t.Fatalf("validate calls = %d, want 2", validateCalls)
	}
	if repairCalls != 1 {
		t.Fatalf("repair calls = %d, want 1", repairCalls)
	}
	if state.Step != StepRun {
		t.Fatalf("state.Step after second validate = %q, want %q", state.Step, StepRun)
	}
	if state.Validation == nil || state.Validation.Attempts != defaultValidationMaxAttempts+1 || state.Validation.Status != "passed" {
		t.Fatalf("validation telemetry after final pass = %+v, want attempts=%d status=passed", state.Validation, defaultValidationMaxAttempts+1)
	}
}

func TestValidationMaxAttempts_UsesDedicatedDefaultBudget(t *testing.T) {
	cfg := DefaultAutoConfig()
	cfg.MaxIterations = 1

	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), t.TempDir())
	if got := pipeline.validationMaxAttempts(); got != defaultValidationMaxAttempts {
		t.Fatalf("validationMaxAttempts = %d, want %d", got, defaultValidationMaxAttempts)
	}
}

func TestRunValidateStep_RetryableValidationErrorKeepsRetrying(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	prdPath := filepath.Join(halDir, template.PRDFile)
	if err := os.WriteFile(prdPath, []byte(`{"project":"test","branchName":"hal/validate-transient"}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{Step: StepValidate}

	oldRetryDelay := validationRetryDelay
	validationRetryDelay = 0
	t.Cleanup(func() {
		validationRetryDelay = oldRetryDelay
	})

	validateCalls := 0
	origValidateWithEngine := validateWithEngine
	validateWithEngine = func(ctx context.Context, eng engine.Engine, gotPath string, display *engine.Display) (*prd.ValidationResult, error) {
		validateCalls++
		if gotPath != prdPath {
			t.Fatalf("validate path = %q, want %q", gotPath, prdPath)
		}
		return nil, errors.New("engine prompt failed: temporary outage")
	}
	t.Cleanup(func() {
		validateWithEngine = origValidateWithEngine
	})

	repairCalls := 0
	origRepairValidationWithEngine := repairValidationWithEngine
	repairValidationWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, gotPath string, result *prd.ValidationResult, display *engine.Display) error {
		repairCalls++
		t.Fatal("repairValidationWithEngine should not be called when validation call itself fails")
		return nil
	}
	t.Cleanup(func() {
		repairValidationWithEngine = origRepairValidationWithEngine
	})

	err := pipeline.runValidateStep(context.Background(), state, RunOptions{})
	if err != nil {
		t.Fatalf("runValidateStep returned error for retryable validation failure: %v", err)
	}
	if validateCalls != 1 {
		t.Fatalf("validate calls = %d, want 1", validateCalls)
	}
	if repairCalls != 0 {
		t.Fatalf("repair calls = %d, want 0", repairCalls)
	}
	if state.Step != StepValidate {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepValidate)
	}
	if state.Validation == nil {
		t.Fatal("state.Validation is nil")
	}
	if state.Validation.Attempts != 1 {
		t.Fatalf("state.Validation.Attempts = %d, want 1", state.Validation.Attempts)
	}
	if state.Validation.Status != "repairing" {
		t.Fatalf("state.Validation.Status = %q, want %q", state.Validation.Status, "repairing")
	}

	saved := pipeline.loadState()
	if saved == nil || saved.Validation == nil {
		t.Fatalf("saved state validation missing: %+v", saved)
	}
	if saved.Validation.Attempts != 1 || saved.Validation.Status != "repairing" {
		t.Fatalf("saved validation telemetry = %+v, want attempts=1 status=repairing", saved.Validation)
	}
}

func TestRunValidateStep_RetryableValidationRepairErrorKeepsRetrying(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	sourceMarkdown := filepath.Join(halDir, "prd-source.md")
	if err := os.WriteFile(sourceMarkdown, []byte("# PRD: Validate Repair Error\n"), 0644); err != nil {
		t.Fatalf("write source markdown: %v", err)
	}

	prdPath := filepath.Join(halDir, template.PRDFile)
	if err := os.WriteFile(prdPath, []byte(`{"project":"test","branchName":"hal/validate-error"}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{Step: StepValidate, SourceMarkdown: sourceMarkdown}

	oldRetryDelay := validationRetryDelay
	validationRetryDelay = 0
	t.Cleanup(func() {
		validationRetryDelay = oldRetryDelay
	})

	origValidateWithEngine := validateWithEngine
	validateWithEngine = func(ctx context.Context, eng engine.Engine, gotPath string, display *engine.Display) (*prd.ValidationResult, error) {
		if gotPath != prdPath {
			t.Fatalf("validate path = %q, want %q", gotPath, prdPath)
		}
		return &prd.ValidationResult{Valid: false, Errors: []prd.Issue{{Message: "still invalid"}}}, nil
	}
	t.Cleanup(func() {
		validateWithEngine = origValidateWithEngine
	})

	origRepairValidationWithEngine := repairValidationWithEngine
	repairValidationWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, gotPath string, result *prd.ValidationResult, display *engine.Display) error {
		if gotPath != prdPath {
			t.Fatalf("repair prd path = %q, want %q", gotPath, prdPath)
		}
		if mdPath != sourceMarkdown {
			t.Fatalf("repair markdown path = %q, want %q", mdPath, sourceMarkdown)
		}
		return errors.New("repair prompt failed: prompt timed out")
	}
	t.Cleanup(func() {
		repairValidationWithEngine = origRepairValidationWithEngine
	})

	err := pipeline.runValidateStep(context.Background(), state, RunOptions{})
	if err != nil {
		t.Fatalf("runValidateStep returned error for retryable repair failure: %v", err)
	}
	if state.Step != StepValidate {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepValidate)
	}
	if state.Validation == nil {
		t.Fatal("state.Validation is nil")
	}
	if state.Validation.Attempts != 1 {
		t.Fatalf("state.Validation.Attempts = %d, want 1", state.Validation.Attempts)
	}
	if state.Validation.Status != "repairing" {
		t.Fatalf("state.Validation.Status = %q, want %q", state.Validation.Status, "repairing")
	}

	saved := pipeline.loadState()
	if saved == nil || saved.Validation == nil {
		t.Fatalf("saved state validation missing: %+v", saved)
	}
	if saved.Validation.Attempts != 1 || saved.Validation.Status != "repairing" {
		t.Fatalf("saved validation telemetry = %+v, want attempts=1 status=repairing", saved.Validation)
	}
}

func TestRunValidateStep_NonRetryableValidationRepairErrorStillKeepsRetrying(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	sourceMarkdown := filepath.Join(halDir, "prd-source.md")
	if err := os.WriteFile(sourceMarkdown, []byte("# PRD: Validate Repair Error\n"), 0644); err != nil {
		t.Fatalf("write source markdown: %v", err)
	}

	prdPath := filepath.Join(halDir, template.PRDFile)
	if err := os.WriteFile(prdPath, []byte(`{"project":"test","branchName":"hal/validate-error"}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{Step: StepValidate, SourceMarkdown: sourceMarkdown}

	oldRetryDelay := validationRetryDelay
	validationRetryDelay = 0
	t.Cleanup(func() {
		validationRetryDelay = oldRetryDelay
	})

	origValidateWithEngine := validateWithEngine
	validateWithEngine = func(ctx context.Context, eng engine.Engine, gotPath string, display *engine.Display) (*prd.ValidationResult, error) {
		return &prd.ValidationResult{Valid: false, Errors: []prd.Issue{{Message: "still invalid"}}}, nil
	}
	t.Cleanup(func() {
		validateWithEngine = origValidateWithEngine
	})

	origRepairValidationWithEngine := repairValidationWithEngine
	repairValidationWithEngine = func(ctx context.Context, eng engine.Engine, mdPath, gotPath string, result *prd.ValidationResult, display *engine.Display) error {
		if gotPath != prdPath {
			t.Fatalf("repair prd path = %q, want %q", gotPath, prdPath)
		}
		if mdPath != sourceMarkdown {
			t.Fatalf("repair markdown path = %q, want %q", mdPath, sourceMarkdown)
		}
		return errors.New("unexpected parser format")
	}
	t.Cleanup(func() {
		repairValidationWithEngine = origRepairValidationWithEngine
	})

	err := pipeline.runValidateStep(context.Background(), state, RunOptions{})
	if err != nil {
		t.Fatalf("runValidateStep returned error for non-retryable repair failure: %v", err)
	}
	if state.Step != StepValidate {
		t.Fatalf("state.Step = %q, want %q", state.Step, StepValidate)
	}
	if state.Validation == nil {
		t.Fatal("state.Validation is nil")
	}
	if state.Validation.Attempts != 1 {
		t.Fatalf("state.Validation.Attempts = %d, want 1", state.Validation.Attempts)
	}
	if state.Validation.Status != "repairing" {
		t.Fatalf("state.Validation.Status = %q, want %q", state.Validation.Status, "repairing")
	}

	saved := pipeline.loadState()
	if saved == nil || saved.Validation == nil {
		t.Fatalf("saved state validation missing: %+v", saved)
	}
	if saved.Validation.Attempts != 1 || saved.Validation.Status != "repairing" {
		t.Fatalf("saved validation telemetry = %+v, want attempts=1 status=repairing", saved.Validation)
	}
}

func TestRunValidateStep_CanceledValidationErrorIsTerminal(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	prdPath := filepath.Join(halDir, template.PRDFile)
	if err := os.WriteFile(prdPath, []byte(`{"project":"test","branchName":"hal/validate-canceled"}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	cfg := DefaultAutoConfig()
	pipeline := NewPipeline(&cfg, nil, engine.NewDisplay(io.Discard), dir)
	state := &PipelineState{Step: StepValidate}

	origValidateWithEngine := validateWithEngine
	validateWithEngine = func(ctx context.Context, eng engine.Engine, gotPath string, display *engine.Display) (*prd.ValidationResult, error) {
		if gotPath != prdPath {
			t.Fatalf("validate path = %q, want %q", gotPath, prdPath)
		}
		return nil, context.Canceled
	}
	t.Cleanup(func() {
		validateWithEngine = origValidateWithEngine
	})

	err := pipeline.runValidateStep(context.Background(), state, RunOptions{})
	if err == nil {
		t.Fatal("expected validation cancellation error")
	}
	if !strings.Contains(err.Error(), "failed to validate PRD on attempt 1") {
		t.Fatalf("error = %q, want validation-attempt prefix", err.Error())
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if state.Validation == nil {
		t.Fatal("state.Validation is nil")
	}
	if state.Validation.Status != "repairing" {
		t.Fatalf("state.Validation.Status = %q, want %q", state.Validation.Status, "repairing")
	}

	saved := pipeline.loadState()
	if saved == nil || saved.Validation == nil {
		t.Fatalf("saved state validation missing: %+v", saved)
	}
	if saved.Validation.Attempts != 1 || saved.Validation.Status != "repairing" {
		t.Fatalf("saved validation telemetry = %+v, want attempts=1 status=repairing", saved.Validation)
	}
}
