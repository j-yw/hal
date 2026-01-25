package prompt

import (
	"strings"
	"testing"
)

func TestBuild(t *testing.T) {
	tests := []struct {
		name        string
		description string
		wantChecks  []string // Substrings that must be present
	}{
		{
			name:        "simple task",
			description: "Add a login button",
			wantChecks: []string{
				"Add a login button",
				"Implement",
				"commit",
				"DO NOT modify the PRD",
			},
		},
		{
			name:        "multi-line description",
			description: "Create a user authentication system\nwith support for OAuth2\nand session management",
			wantChecks: []string{
				"Create a user authentication system",
				"OAuth2",
				"session management",
				"commit",
				"DO NOT modify the PRD",
			},
		},
		{
			name:        "empty description",
			description: "",
			wantChecks: []string{
				"Implement",
				"commit",
				"DO NOT modify the PRD",
			},
		},
		{
			name:        "special characters",
			description: "Fix bug with `code blocks` and <html> tags",
			wantChecks: []string{
				"`code blocks`",
				"<html>",
				"commit",
				"DO NOT modify the PRD",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Build(tt.description)

			for _, check := range tt.wantChecks {
				if !strings.Contains(got, check) {
					t.Errorf("Build() missing expected substring %q\nGot:\n%s", check, got)
				}
			}
		})
	}
}

func TestBuildIncludesTaskDescription(t *testing.T) {
	description := "This is my unique task description"
	result := Build(description)

	if !strings.Contains(result, description) {
		t.Errorf("Build() should include task description\nWant substring: %q\nGot:\n%s", description, result)
	}
}

func TestBuildIncludesImplementAndCommitInstruction(t *testing.T) {
	result := Build("any task")

	// Check for implement instruction
	if !strings.Contains(strings.ToLower(result), "implement") {
		t.Error("Build() should include instruction to implement the task")
	}

	// Check for commit instruction
	if !strings.Contains(strings.ToLower(result), "commit") {
		t.Error("Build() should include instruction to commit changes")
	}
}

func TestBuildIncludesPRDProtection(t *testing.T) {
	result := Build("any task")

	// Check that it tells Claude not to modify PRD
	lowerResult := strings.ToLower(result)
	if !strings.Contains(lowerResult, "do not") || !strings.Contains(lowerResult, "prd") {
		t.Error("Build() should include instruction not to modify the PRD file")
	}
}
