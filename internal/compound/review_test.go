package compound

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
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
			name:  "JSON with markdown fences",
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

	reportPath, err := generateReviewReport(dir, rc, pr, nil)
	if err != nil {
		t.Fatalf("generateReviewReport() error = %v", err)
	}

	// Verify report was created in correct location
	if !strings.Contains(reportPath, ".hal/reports/review-") {
		t.Errorf("Report path = %q, expected to contain .hal/reports/review-", reportPath)
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

	prompt := buildReviewPrompt(rc, nil)

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
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("Failed to create .hal: %v", err)
	}

	// Create a PRD file
	prdPath := filepath.Join(halDir, "prd-test-feature.md")
	if err := os.WriteFile(prdPath, []byte("# PRD"), 0644); err != nil {
		t.Fatalf("Failed to create PRD: %v", err)
	}

	t.Run("finds PRD by branch name", func(t *testing.T) {
		found := findPRDFile(dir, "hal/test-feature")
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

type reviewCaptureEngine struct {
	response   string
	promptSeen string
}

func (e *reviewCaptureEngine) Name() string { return "review-capture" }

func (e *reviewCaptureEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{Success: true}
}

func (e *reviewCaptureEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	return e.response, nil
}

func (e *reviewCaptureEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	e.promptSeen = prompt
	return e.response, nil
}

func TestBuildReviewPrompt_IncludesVerificationFactsAndNoClaimRule(t *testing.T) {
	rc := &reviewContext{BranchName: "feature/test"}
	checks := []VerificationCheck{{Name: "lint", OK: true, Output: "npm run lint"}}

	prompt := buildReviewPrompt(rc, checks)

	want := []string{
		"### Deterministic Verification Facts",
		"Do not claim lint, tests, build, typecheck, or CI passed unless a verification fact below explicitly says so.",
		"- `lint`: passed (npm run lint)",
	}
	for _, needle := range want {
		if !strings.Contains(prompt, needle) {
			t.Fatalf("prompt missing %q", needle)
		}
	}
}

func TestGenerateReviewReport_IncludesVerificationSection(t *testing.T) {
	dir := t.TempDir()
	rc := &reviewContext{BranchName: "feature/report"}
	pr := &parsedReview{Summary: "summary"}
	checks := []VerificationCheck{{Name: "ci", OK: false, Output: "status=failing"}}

	reportPath, err := generateReviewReport(dir, rc, pr, checks)
	if err != nil {
		t.Fatalf("generateReviewReport() error = %v", err)
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	got := string(content)
	want := []string{
		"## Verification",
		"- `ci`: failed; status=failing",
	}
	for _, needle := range want {
		if !strings.Contains(got, needle) {
			t.Fatalf("report missing %q", needle)
		}
	}
}

func TestReview_UsesProvidedVerificationChecks(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".hal"), 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hal", "progress.txt"), []byte("progress"), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}

	eng := &reviewCaptureEngine{response: `{"summary":"Built thing","patterns":[],"issues":[],"techDebt":[],"recommendations":[]}`}
	checks := []VerificationCheck{{Name: "test", OK: true, Output: "npm test"}}
	var displayBuf bytes.Buffer

	result, err := Review(context.Background(), eng, engine.NewDisplay(&displayBuf), dir, ReviewOptions{
		SkipAgents:   true,
		Verification: checks,
	})
	if err != nil {
		t.Fatalf("Review() error = %v", err)
	}
	if result == nil || strings.TrimSpace(result.ReportPath) == "" {
		t.Fatal("Review() did not return report path")
	}
	if !strings.Contains(eng.promptSeen, "- `test`: passed (npm test)") {
		t.Fatalf("prompt did not include verification facts: %q", eng.promptSeen)
	}
	content, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(content), "- `test`: passed; npm test") {
		t.Fatalf("report missing verification facts: %s", string(content))
	}
}
