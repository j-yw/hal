package prd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
)

type fakeRepairEngine struct {
	streamPrompt func(context.Context, string, *engine.Display) (string, error)
	prompt       func(context.Context, string) (string, error)
}

func (f fakeRepairEngine) Name() string {
	return "fake"
}

func (f fakeRepairEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{Success: true}
}

func (f fakeRepairEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	if f.prompt != nil {
		return f.prompt(ctx, prompt)
	}
	return "", nil
}

func (f fakeRepairEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	if f.streamPrompt != nil {
		return f.streamPrompt(ctx, prompt, display)
	}
	return "", nil
}

func TestRepairValidationWithEngine_OutputFallbackSucceedsWhenFilesChanged(t *testing.T) {
	dir := t.TempDir()
	prdPath := filepath.Join(dir, "prd.json")
	if err := os.WriteFile(prdPath, []byte(`{"project":"test"}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}
	mdPath := filepath.Join(dir, "prd.md")
	if err := os.WriteFile(mdPath, []byte("# PRD\n"), 0644); err != nil {
		t.Fatalf("write prd.md: %v", err)
	}

	eng := fakeRepairEngine{
		streamPrompt: func(ctx context.Context, prompt string, display *engine.Display) (string, error) {
			if err := os.WriteFile(prdPath, []byte(`{"project":"test","fixed":true}`), 0644); err != nil {
				t.Fatalf("rewrite prd.json: %v", err)
			}
			return "", engine.NewOutputFallbackRequiredError(errors.New("no streamed text"))
		},
	}

	result := &ValidationResult{Valid: false, Errors: []Issue{{Message: "task too large", Severity: "error"}}}
	err := RepairValidationWithEngine(context.Background(), eng, mdPath, prdPath, result, engine.NewDisplay(io.Discard))
	if err != nil {
		t.Fatalf("RepairValidationWithEngine returned error: %v", err)
	}

	data, err := os.ReadFile(prdPath)
	if err != nil {
		t.Fatalf("read prd.json: %v", err)
	}
	if !strings.Contains(string(data), `"fixed":true`) {
		t.Fatalf("prd.json = %s, expected repaired content", string(data))
	}
}

func TestRepairValidationWithEngine_OutputFallbackFailsWhenNoFilesChanged(t *testing.T) {
	dir := t.TempDir()
	prdPath := filepath.Join(dir, "prd.json")
	if err := os.WriteFile(prdPath, []byte(`{"project":"test"}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	eng := fakeRepairEngine{
		streamPrompt: func(ctx context.Context, prompt string, display *engine.Display) (string, error) {
			return "", engine.NewOutputFallbackRequiredError(errors.New("no streamed text"))
		},
	}

	result := &ValidationResult{Valid: false, Errors: []Issue{{Message: "task too large", Severity: "error"}}}
	err := RepairValidationWithEngine(context.Background(), eng, "", prdPath, result, engine.NewDisplay(io.Discard))
	if err == nil {
		t.Fatal("expected repair error when output fallback has no file changes")
	}
	if !strings.Contains(err.Error(), "repair prompt failed") {
		t.Fatalf("error = %q, want repair failure", err.Error())
	}
}
