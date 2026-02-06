package loop

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestIsRetryable(t *testing.T) {
	r := &Runner{}

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		// Nil error
		{"nil error", nil, false},

		// Transient API errors — should be retryable
		{"rate limit", fmt.Errorf("rate limit exceeded"), true},
		{"429 status", fmt.Errorf("API returned 429"), true},
		{"503 status", fmt.Errorf("API returned 503"), true},
		{"overloaded", fmt.Errorf("model is overloaded"), true},
		{"connection reset", fmt.Errorf("connection reset by peer"), true},
		{"i/o timeout", fmt.Errorf("i/o timeout"), true},
		{"connection timeout", fmt.Errorf("connection timeout"), true},

		// Execution timeouts — should NOT be retryable (hung commands will hang again)
		{"execution timed out 15m", fmt.Errorf("execution timed out after 15m0s"), false},
		{"execution timed out 30m", fmt.Errorf("execution timed out after 30m0s"), false},
		{"prompt timed out", fmt.Errorf("prompt timed out after 15m0s"), false},

		// Other non-retryable errors
		{"generic error", fmt.Errorf("something went wrong"), false},
		{"file not found", fmt.Errorf("file not found: prompt.md"), false},
		{"unknown engine", fmt.Errorf("unknown engine: foo"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.isRetryable(tt.err)
			if got != tt.expected {
				t.Errorf("isRetryable(%q) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"Rate Limit exceeded", "rate limit", true},
		{"CONNECTION reset", "connection", true},
		{"hello world", "world", true},
		{"hello", "hello world", false}, // substr longer than s
		{"", "a", false},
		{"execution timed out after 15m0s", "timeout", false}, // "timeout" != "timed out"
		{"i/o timeout", "timeout", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			got := containsIgnoreCase(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("containsIgnoreCase(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestLoadPrompt_InjectsStandards(t *testing.T) {
	halDir := t.TempDir()

	// Write a prompt template with the {{STANDARDS}} placeholder
	promptContent := `# Agent Instructions

You are an autonomous coding agent.

{{STANDARDS}}

## Your Task

1. Read the PRD at ` + "`.hal/{{PRD_FILE}}`" + `
2. Read ` + "`.hal/{{PROGRESS_FILE}}`" + `
`
	if err := os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte(promptContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create standards directory with some standards
	engDir := filepath.Join(halDir, template.StandardsDir, "engine")
	if err := os.MkdirAll(engDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(engDir, "process-isolation.md"), []byte("# Process Isolation\n\nAlways use setsid."), 0644); err != nil {
		t.Fatal(err)
	}

	testStdDir := filepath.Join(halDir, template.StandardsDir, "testing")
	if err := os.MkdirAll(testStdDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testStdDir, "table-driven.md"), []byte("# Table-Driven Tests\n\nUse t.Run subtests."), 0644); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	r := &Runner{
		config: Config{
			Dir:          halDir,
			PRDFile:      "prd.json",
			ProgressFile: "progress.txt",
			Logger:       &logBuf,
		},
	}

	prompt, err := r.loadPrompt()
	if err != nil {
		t.Fatalf("loadPrompt() error: %v", err)
	}

	// Placeholder should be gone
	if strings.Contains(prompt, "{{STANDARDS}}") {
		t.Error("{{STANDARDS}} placeholder was not replaced")
	}

	// Standards content should be present
	if !strings.Contains(prompt, "## Project Standards") {
		t.Error("missing '## Project Standards' header")
	}
	if !strings.Contains(prompt, "Process Isolation") {
		t.Error("missing engine/process-isolation standard content")
	}
	if !strings.Contains(prompt, "Table-Driven Tests") {
		t.Error("missing testing/table-driven standard content")
	}

	// Other placeholders should also be replaced
	if !strings.Contains(prompt, ".hal/prd.json") {
		t.Error("{{PRD_FILE}} was not replaced")
	}
	if !strings.Contains(prompt, ".hal/progress.txt") {
		t.Error("{{PROGRESS_FILE}} was not replaced")
	}
}

func TestLoadPrompt_NoStandardsGraceful(t *testing.T) {
	halDir := t.TempDir()

	// Write a prompt template with the placeholder but NO standards directory
	promptContent := "# Agent\n\n{{STANDARDS}}\n\n## Task\n"
	if err := os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte(promptContent), 0644); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	r := &Runner{
		config: Config{
			Dir:          halDir,
			PRDFile:      "prd.json",
			ProgressFile: "progress.txt",
			Logger:       &logBuf,
		},
	}

	prompt, err := r.loadPrompt()
	if err != nil {
		t.Fatalf("loadPrompt() error: %v", err)
	}

	// Placeholder should be replaced with empty string
	if strings.Contains(prompt, "{{STANDARDS}}") {
		t.Error("{{STANDARDS}} placeholder was not replaced when no standards exist")
	}

	// Should still have the rest of the prompt
	if !strings.Contains(prompt, "# Agent") {
		t.Error("rest of prompt is missing")
	}
	if !strings.Contains(prompt, "## Task") {
		t.Error("rest of prompt is missing")
	}
}

func TestLoadPrompt_OldTemplateWithoutPlaceholder(t *testing.T) {
	halDir := t.TempDir()

	// Simulate a prompt.md that hasn't been migrated (no {{STANDARDS}})
	promptContent := "# Agent\n\n## Task\n\n1. Read the PRD at `.hal/{{PRD_FILE}}`\n"
	if err := os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte(promptContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create standards anyway
	sDir := filepath.Join(halDir, template.StandardsDir, "config")
	if err := os.MkdirAll(sDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sDir, "init.md"), []byte("# Init\n\nBe idempotent."), 0644); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	r := &Runner{
		config: Config{
			Dir:          halDir,
			PRDFile:      "prd.json",
			ProgressFile: "progress.txt",
			Logger:       &logBuf,
		},
	}

	prompt, err := r.loadPrompt()
	if err != nil {
		t.Fatalf("loadPrompt() error: %v", err)
	}

	// Without the placeholder, standards content won't appear — but it should not crash
	if strings.Contains(prompt, "{{STANDARDS}}") {
		t.Error("phantom {{STANDARDS}} placeholder appeared")
	}

	// The prompt should still work, just without standards
	if !strings.Contains(prompt, "# Agent") {
		t.Error("prompt content is missing")
	}
}
