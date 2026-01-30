package compound

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseReviewResponse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *parsedReview
		wantErr bool
	}{
		{
			name: "valid JSON",
			input: `{
				"summary": "Implemented feature X",
				"patterns": ["Pattern 1", "Pattern 2"],
				"issues": ["Issue 1"],
				"techDebt": ["Debt 1"],
				"recommendations": ["Rec 1", "Rec 2"]
			}`,
			want: &parsedReview{
				Summary:         "Implemented feature X",
				Patterns:        []string{"Pattern 1", "Pattern 2"},
				Issues:          []string{"Issue 1"},
				TechDebt:        []string{"Debt 1"},
				Recommendations: []string{"Rec 1", "Rec 2"},
			},
			wantErr: false,
		},
		{
			name: "JSON with markdown fences",
			input: "Here is the analysis:\n```json\n{\"summary\": \"Built thing\", \"patterns\": [], \"issues\": [], \"techDebt\": [], \"recommendations\": []}\n```\nDone!",
			want: &parsedReview{
				Summary:         "Built thing",
				Patterns:        []string{},
				Issues:          []string{},
				TechDebt:        []string{},
				Recommendations: []string{},
			},
			wantErr: false,
		},
		{
			name:    "missing summary",
			input:   `{"patterns": [], "issues": [], "techDebt": [], "recommendations": []}`,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "no JSON",
			input:   "This is not JSON at all",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			input:   `{"summary": "test", broken}`,
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseReviewResponse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseReviewResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil {
				if got.Summary != tt.want.Summary {
					t.Errorf("Summary = %q, want %q", got.Summary, tt.want.Summary)
				}
				if len(got.Patterns) != len(tt.want.Patterns) {
					t.Errorf("Patterns count = %d, want %d", len(got.Patterns), len(tt.want.Patterns))
				}
			}
		})
	}
}

func TestUpdateAgentsMD(t *testing.T) {
	t.Run("creates new file if missing", func(t *testing.T) {
		dir := t.TempDir()
		patterns := []string{"Pattern 1", "Pattern 2"}

		err := updateAgentsMD(dir, "feature/test", patterns)
		if err != nil {
			t.Fatalf("updateAgentsMD() error = %v", err)
		}

		// Read and verify content
		content, err := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
		if err != nil {
			t.Fatalf("Failed to read AGENTS.md: %v", err)
		}

		// Check header
		if !strings.Contains(string(content), "# Repository Guidelines") {
			t.Error("Missing header in new AGENTS.md")
		}

		// Check patterns
		if !strings.Contains(string(content), "Pattern 1") {
			t.Error("Missing Pattern 1")
		}
		if !strings.Contains(string(content), "Pattern 2") {
			t.Error("Missing Pattern 2")
		}

		// Check branch name
		if !strings.Contains(string(content), "feature/test") {
			t.Error("Missing branch name in section header")
		}
	})

	t.Run("appends to existing file", func(t *testing.T) {
		dir := t.TempDir()

		// Create initial AGENTS.md
		initialContent := "# Existing Content\n\nSome existing patterns.\n"
		if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(initialContent), 0644); err != nil {
			t.Fatalf("Failed to create initial AGENTS.md: %v", err)
		}

		patterns := []string{"New Pattern"}
		err := updateAgentsMD(dir, "feature/new", patterns)
		if err != nil {
			t.Fatalf("updateAgentsMD() error = %v", err)
		}

		content, _ := os.ReadFile(filepath.Join(dir, "AGENTS.md"))

		// Check original content preserved
		if !strings.Contains(string(content), "# Existing Content") {
			t.Error("Original content was not preserved")
		}

		// Check new pattern added
		if !strings.Contains(string(content), "New Pattern") {
			t.Error("New pattern was not added")
		}
	})
}

func TestGenerateReviewReport(t *testing.T) {
	dir := t.TempDir()

	rc := &reviewContext{
		BranchName:    "feature/test-feature",
		CommitHistory: "abc123 feat: Add thing\ndef456 fix: Fix thing",
	}

	pr := &parsedReview{
		Summary:         "Built a test feature",
		Patterns:        []string{"Test pattern"},
		Issues:          []string{"Had an issue"},
		TechDebt:        []string{"Missing tests"},
		Recommendations: []string{"Add more tests", "Refactor later"},
	}

	reportPath, err := generateReviewReport(dir, rc, pr)
	if err != nil {
		t.Fatalf("generateReviewReport() error = %v", err)
	}

	// Verify report was created in correct location
	if !strings.Contains(reportPath, ".goralph/reports/review-") {
		t.Errorf("Report path = %q, expected to contain .goralph/reports/review-", reportPath)
	}

	// Read and verify content
	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("Failed to read report: %v", err)
	}

	contentStr := string(content)

	// Check various sections
	checks := []struct {
		name    string
		content string
	}{
		{"title", "# Review Report: feature/test-feature"},
		{"summary header", "## Summary"},
		{"summary content", "Built a test feature"},
		{"commit history", "## What Was Built"},
		{"issues", "## Issues Encountered"},
		{"tech debt", "## Tech Debt Introduced"},
		{"recommendations", "## Recommendations for Next Priorities"},
		{"patterns", "## Patterns Discovered"},
	}

	for _, check := range checks {
		if !strings.Contains(contentStr, check.content) {
			t.Errorf("Report missing %s: %q", check.name, check.content)
		}
	}
}

func TestReviewContextHasAnyContext(t *testing.T) {
	tests := []struct {
		name string
		rc   *reviewContext
		want bool
	}{
		{
			name: "has progress",
			rc:   &reviewContext{ProgressContent: "some progress"},
			want: true,
		},
		{
			name: "has git diff",
			rc:   &reviewContext{GitDiff: "some diff"},
			want: true,
		},
		{
			name: "has commit history",
			rc:   &reviewContext{CommitHistory: "abc123 commit"},
			want: true,
		},
		{
			name: "has PRD",
			rc:   &reviewContext{PRDContent: "# PRD"},
			want: true,
		},
		{
			name: "has nothing",
			rc:   &reviewContext{},
			want: false,
		},
		{
			name: "only has warnings",
			rc:   &reviewContext{Warnings: []string{"some warning"}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rc.hasAnyContext(); got != tt.want {
				t.Errorf("hasAnyContext() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTruncateContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		maxLen  int
		want    string
	}{
		{
			name:    "short content unchanged",
			content: "short",
			maxLen:  100,
			want:    "short",
		},
		{
			name:    "long content truncated",
			content: "this is a long string that should be truncated",
			maxLen:  20,
			want:    "this is a long strin\n... (truncated)",
		},
		{
			name:    "exact length unchanged",
			content: "exact",
			maxLen:  5,
			want:    "exact",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateContent(tt.content, tt.maxLen); got != tt.want {
				t.Errorf("truncateContent() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildReviewPrompt(t *testing.T) {
	rc := &reviewContext{
		BranchName:      "feature/test",
		ProgressContent: "Progress log content",
		GitDiff:         "diff content",
		CommitHistory:   "commit history",
		PRDContent:      "PRD content",
		Warnings:        []string{"Warning 1"},
	}

	prompt := buildReviewPrompt(rc)

	// Verify all sections are included
	checks := []string{
		"**Branch:** feature/test",
		"### Progress Log",
		"Progress log content",
		"### Git Diff",
		"diff content",
		"### Commit History",
		"commit history",
		"### PRD Goals",
		"PRD content",
		"### Notes",
		"Warning 1",
	}

	for _, check := range checks {
		if !strings.Contains(prompt, check) {
			t.Errorf("Prompt missing: %q", check)
		}
	}
}

func TestFindPRDFile(t *testing.T) {
	dir := t.TempDir()
	goralphDir := filepath.Join(dir, ".goralph")
	if err := os.MkdirAll(goralphDir, 0755); err != nil {
		t.Fatalf("Failed to create .goralph: %v", err)
	}

	// Create a PRD file
	prdPath := filepath.Join(goralphDir, "prd-test-feature.md")
	if err := os.WriteFile(prdPath, []byte("# PRD"), 0644); err != nil {
		t.Fatalf("Failed to create PRD: %v", err)
	}

	t.Run("finds PRD by branch name", func(t *testing.T) {
		found := findPRDFile(dir, "ralph/test-feature")
		if found != prdPath {
			t.Errorf("findPRDFile() = %q, want %q", found, prdPath)
		}
	})

	t.Run("finds any PRD when branch doesn't match", func(t *testing.T) {
		found := findPRDFile(dir, "other/branch")
		if found == "" {
			t.Error("findPRDFile() should find any PRD when branch doesn't match")
		}
	})

	t.Run("returns empty for main branch with no PRDs matching", func(t *testing.T) {
		// Remove the PRD file
		os.Remove(prdPath)

		found := findPRDFile(dir, "main")
		if found != "" {
			t.Errorf("findPRDFile() = %q, want empty string", found)
		}
	})
}
