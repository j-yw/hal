package prd

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
)

func TestExtractFeatureNameFromDescription(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test feature", "test-feature"},
		{"user authentication", "user-authentication"},
		{"Add Dark Mode", "add-dark-mode"},
		{"fix bug #123", "fix-bug-123"},
		{"a very long feature description that should be truncated to avoid excessively long filenames", "a-very-long-feature-description-that-should-be"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractFeatureNameFromDescription(tt.input)
			if got != tt.expected {
				t.Errorf("extractFeatureNameFromDescription(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestOutputPathIsHalFolder(t *testing.T) {
	// Verify markdown output path uses .hal folder
	featureName := extractFeatureNameFromDescription("test feature")
	outputPath := filepath.Join(template.HalDir, "prd-"+featureName+".md")

	expected := filepath.Join(template.HalDir, "prd-test-feature.md")
	if outputPath != expected {
		t.Errorf("markdown output path = %q, want %q", outputPath, expected)
	}

	// Verify it does NOT use tasks folder
	tasksPath := filepath.Join("tasks", "prd-"+featureName+".md")
	if outputPath == tasksPath {
		t.Error("output path should not use tasks folder")
	}
}

func TestJSONOutputPathIsHalFolder(t *testing.T) {
	// Verify JSON output path uses .hal folder
	outputPath := filepath.Join(template.HalDir, template.PRDFile)

	expected := template.HalDir + "/" + template.PRDFile
	if outputPath != expected {
		t.Errorf("JSON output path = %q, want %q", outputPath, expected)
	}
}

type sequenceMockEngine struct {
	promptResponses []string
	promptErrors    []error
	promptCalls     int
}

func (m *sequenceMockEngine) Name() string {
	return "mock-sequence"
}

func (m *sequenceMockEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (m *sequenceMockEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	i := m.promptCalls
	m.promptCalls++

	var response string
	if i < len(m.promptResponses) {
		response = m.promptResponses[i]
	}

	var err error
	if i < len(m.promptErrors) {
		err = m.promptErrors[i]
	}

	return response, err
}

func (m *sequenceMockEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	return m.Prompt(ctx, prompt)
}

func TestGenerateQuestions_PropagatesRepairPromptError(t *testing.T) {
	eng := &sequenceMockEngine{
		promptResponses: []string{
			`not-json`,
		},
		promptErrors: []error{
			nil,
			context.Canceled,
		},
	}

	_, err := generateQuestions(context.Background(), eng, "skill", "desc", "project", nil)
	if err == nil {
		t.Fatal("generateQuestions() expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("generateQuestions() error = %v, want context.Canceled", err)
	}
}
