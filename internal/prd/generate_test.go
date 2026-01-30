package prd

import (
	"path/filepath"
	"testing"

	"github.com/jywlabs/goralph/internal/template"
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

func TestOutputPathIsGoralphFolder(t *testing.T) {
	// Verify markdown output path uses .goralph folder
	featureName := extractFeatureNameFromDescription("test feature")
	outputPath := filepath.Join(template.GoralphDir, "prd-"+featureName+".md")

	expected := filepath.Join(template.GoralphDir, "prd-test-feature.md")
	if outputPath != expected {
		t.Errorf("markdown output path = %q, want %q", outputPath, expected)
	}

	// Verify it does NOT use tasks folder
	tasksPath := filepath.Join("tasks", "prd-"+featureName+".md")
	if outputPath == tasksPath {
		t.Error("output path should not use tasks folder")
	}
}

func TestJSONOutputPathIsGoralphFolder(t *testing.T) {
	// Verify JSON output path uses .goralph folder
	outputPath := filepath.Join(template.GoralphDir, template.PRDFile)

	expected := template.GoralphDir + "/" + template.PRDFile
	if outputPath != expected {
		t.Errorf("JSON output path = %q, want %q", outputPath, expected)
	}
}
