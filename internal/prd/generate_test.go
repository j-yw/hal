package prd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

type streamFallbackMockEngine struct {
	streamResponse string
	streamErr      error
	streamCalls    int

	promptResponse string
	promptErr      error
	promptCalls    int
}

func (m *streamFallbackMockEngine) Name() string {
	return "mock-stream-fallback"
}

func (m *streamFallbackMockEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (m *streamFallbackMockEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	m.promptCalls++
	return m.promptResponse, m.promptErr
}

func (m *streamFallbackMockEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	m.streamCalls++
	return m.streamResponse, m.streamErr
}

func TestGenerateQuestions_DoesNotFallbackOnStreamTimeout(t *testing.T) {
	eng := &streamFallbackMockEngine{
		streamErr: fmt.Errorf("prompt timed out after 30s"),
	}

	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)
	_, err := generateQuestions(context.Background(), eng, "skill", "desc", "project", display)
	if err == nil {
		t.Fatal("generateQuestions() expected timeout error, got nil")
	}
	if eng.promptCalls != 0 {
		t.Fatalf("Prompt() calls = %d, want 0 when stream times out", eng.promptCalls)
	}
}

func TestGenerateQuestions_FallsBackOnNonTimeoutStreamError(t *testing.T) {
	eng := &streamFallbackMockEngine{
		streamErr:      fmt.Errorf("stream parse failed"),
		promptResponse: `{"questions":[{"number":1,"text":"Q?","options":[{"letter":"A","label":"Option A"},{"letter":"B","label":"Option B"},{"letter":"C","label":"Option C"},{"letter":"D","label":"Other (specify)"}]}]}`,
	}

	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)
	questions, err := generateQuestions(context.Background(), eng, "skill", "desc", "project", display)
	if err != nil {
		t.Fatalf("generateQuestions() error = %v, want nil", err)
	}
	if len(questions) != 1 {
		t.Fatalf("questions length = %d, want 1", len(questions))
	}
	if eng.promptCalls != 1 {
		t.Fatalf("Prompt() calls = %d, want 1 for stream fallback", eng.promptCalls)
	}
}

func TestGenerateQuestions_DoesNotFallbackOnOutputFallbackRequired(t *testing.T) {
	eng := &streamFallbackMockEngine{
		streamErr:      engine.NewOutputFallbackRequiredError(fmt.Errorf("prompt failed")),
		promptResponse: `{"questions":[{"number":1,"text":"Q?","options":[{"letter":"A","label":"Option A"},{"letter":"B","label":"Option B"},{"letter":"C","label":"Option C"},{"letter":"D","label":"Other (specify)"}]}]}`,
	}

	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)
	_, err := generateQuestions(context.Background(), eng, "skill", "desc", "project", display)
	if err == nil {
		t.Fatal("generateQuestions() expected output fallback error, got nil")
	}
	if !engine.RequiresOutputFallback(err) {
		t.Fatalf("generateQuestions() error = %v, want output fallback error", err)
	}
	if eng.promptCalls != 0 {
		t.Fatalf("Prompt() calls = %d, want 0 when output fallback is required", eng.promptCalls)
	}
}

func TestConvertPRDToJSON_UsesOutputFallbackWhenStreamRequiresFile(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)

	outPath := filepath.Join(tmpDir, template.HalDir, template.PRDFile)
	expectedJSON := promptResponseWithBranch(t, "hal/new-feature")
	eng := &mockEngine{
		promptError: engine.NewOutputFallbackRequiredError(fmt.Errorf("prompt failed")),
		promptHook: func() error {
			writeFile(t, outPath, expectedJSON)
			return nil
		},
	}

	var buf bytes.Buffer
	display := engine.NewDisplay(&buf)
	got, err := convertPRDToJSON(context.Background(), eng, "skill", "# PRD", outPath, display)
	if err != nil {
		t.Fatalf("convertPRDToJSON() error = %v, want nil", err)
	}
	want, err := extractJSONFromResponse(expectedJSON)
	if err != nil {
		t.Fatalf("extractJSONFromResponse() error = %v", err)
	}
	if got != want {
		t.Fatalf("convertPRDToJSON() = %q, want %q", got, want)
	}
}

func TestGenerateWithEngine_JSONOutputReplacesExistingCanonicalPRD(t *testing.T) {
	tmpDir := t.TempDir()
	chdirTo(t, tmpDir)

	halDir := filepath.Join(tmpDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(halDir, template.PRDFile)
	writePRDJSON(t, halDir, template.PRDFile, "hal/old-feature")

	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}
	if _, err := stdinWriter.WriteString("1A\n"); err != nil {
		t.Fatalf("failed to seed stdin: %v", err)
	}
	if err := stdinWriter.Close(); err != nil {
		t.Fatalf("failed to close stdin writer: %v", err)
	}
	origStdin := os.Stdin
	os.Stdin = stdinReader
	t.Cleanup(func() {
		os.Stdin = origStdin
		_ = stdinReader.Close()
	})

	eng := &sequenceMockEngine{
		promptResponses: []string{
			`{"questions":[{"number":1,"text":"Goal?","options":[{"letter":"A","label":"Option A"},{"letter":"B","label":"Option B"},{"letter":"C","label":"Option C"},{"letter":"D","label":"Other (specify)"}]}]}`,
			"# PRD: New Feature\n\n## Goal\nShip the new feature.",
			promptResponseWithBranch(t, "hal/something-else"),
		},
	}

	gotPath, err := GenerateWithEngine(context.Background(), eng, "new feature", "json", nil)
	if err != nil {
		t.Fatalf("GenerateWithEngine failed: %v", err)
	}
	if gotPath != filepath.Join(template.HalDir, template.PRDFile) {
		t.Fatalf("output path = %q, want %q", gotPath, filepath.Join(template.HalDir, template.PRDFile))
	}
	if got := readPRDBranchName(t, outPath); got != "hal/new-feature" {
		t.Fatalf("output branchName = %q, want %q", got, "hal/new-feature")
	}
}

func TestParseBatchAnswers(t *testing.T) {
	optionMap := map[int]map[string]string{
		1: {"A": "Option A", "B": "Option B", "C": "Option C", "D": "Other (specify)"},
		2: {"A": "Fast", "B": "Reliable", "C": "Cheap"},
		3: {"A": "Yes", "B": "No", "C": "Maybe"},
	}

	tests := []struct {
		name    string
		input   string
		want    map[int]string
		wantErr string
	}{
		{
			name:  "comma separated",
			input: "1A, 2B, 3C",
			want:  map[int]string{1: "Option A", 2: "Reliable", 3: "Maybe"},
		},
		{
			name:  "space separated",
			input: "1A 2B 3C",
			want:  map[int]string{1: "Option A", 2: "Reliable", 3: "Maybe"},
		},
		{
			name:  "no spaces",
			input: "1A,2B,3C",
			want:  map[int]string{1: "Option A", 2: "Reliable", 3: "Maybe"},
		},
		{
			name:  "lowercase",
			input: "1a, 2b, 3c",
			want:  map[int]string{1: "Option A", 2: "Reliable", 3: "Maybe"},
		},
		{
			name:  "mixed spacing",
			input: "1A,  2B,3C",
			want:  map[int]string{1: "Option A", 2: "Reliable", 3: "Maybe"},
		},
		{
			name:  "partial answers",
			input: "1B, 3A",
			want:  map[int]string{1: "Option B", 3: "Yes"},
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: "no answers provided",
		},
		{
			name:    "invalid token too short",
			input:   "A",
			wantErr: "invalid answer",
		},
		{
			name:    "unknown question number",
			input:   "9A",
			wantErr: "unknown question number 9",
		},
		{
			name:    "invalid option letter",
			input:   "1Z",
			wantErr: "invalid option Z for question 1",
		},
		{
			name:    "no letter suffix",
			input:   "123",
			wantErr: "invalid answer",
		},
		{
			name:    "no number prefix",
			input:   "AB",
			wantErr: "invalid answer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBatchAnswers(tt.input, optionMap)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseBatchAnswers(%q) = nil error, want error containing %q", tt.input, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseBatchAnswers(%q) error = %q, want containing %q", tt.input, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseBatchAnswers(%q) error = %v, want nil", tt.input, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseBatchAnswers(%q) = %d answers, want %d", tt.input, len(got), len(tt.want))
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("parseBatchAnswers(%q)[%d] = %q, want %q", tt.input, k, got[k], v)
				}
			}
		})
	}
}

func TestBuildAnswerExample(t *testing.T) {
	questions := []Question{
		{Number: 1, Options: []Option{{Letter: "A"}, {Letter: "B"}}},
		{Number: 2, Options: []Option{{Letter: "A"}, {Letter: "B"}}},
		{Number: 3, Options: []Option{{Letter: "A"}, {Letter: "B"}}},
	}

	got := buildAnswerExample(questions)
	if got != "1A, 2B, 3C" {
		t.Errorf("buildAnswerExample() = %q, want %q", got, "1A, 2B, 3C")
	}
}

func TestBuildOptionMap(t *testing.T) {
	questions := []Question{
		{Number: 1, Options: []Option{
			{Letter: "A", Label: "Alpha"},
			{Letter: "b", Label: "Beta"},
		}},
		{Number: 2, Options: []Option{
			{Letter: "A", Label: "Yes"},
		}},
	}

	got := buildOptionMap(questions)

	if got[1]["A"] != "Alpha" {
		t.Errorf("optionMap[1][A] = %q, want %q", got[1]["A"], "Alpha")
	}
	if got[1]["B"] != "Beta" {
		t.Errorf("optionMap[1][B] = %q, want %q", got[1]["B"], "Beta")
	}
	if got[2]["A"] != "Yes" {
		t.Errorf("optionMap[2][A] = %q, want %q", got[2]["A"], "Yes")
	}
}

func TestParseBatchAnswers_InvalidOptionShowsValidOptions(t *testing.T) {
	optionMap := map[int]map[string]string{
		1: {"A": "Alpha", "B": "Beta", "C": "Gamma"},
	}

	_, err := parseBatchAnswers("1Z", optionMap)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Verify the error message mentions valid options
	msg := err.Error()
	if !strings.Contains(msg, "invalid option Z for question 1") {
		t.Errorf("error = %q, want mention of invalid option", msg)
	}
	// Check that valid letters are mentioned (order may vary)
	for _, letter := range []string{"A", "B", "C"} {
		if !strings.Contains(msg, letter) {
			t.Errorf("error = %q, want mention of valid letter %s", msg, letter)
		}
	}
}

// Suppress unused import warnings — sort is used in error message validation above.
var _ = sort.Strings
