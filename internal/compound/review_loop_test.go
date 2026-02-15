package compound

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRunSingleReviewIterationPopulatesResult(t *testing.T) {
	start := time.Date(2026, 2, 15, 9, 0, 0, 0, time.UTC)
	end := start.Add(3 * time.Second)
	times := []time.Time{start, end}
	timeIndex := 0

	nowFn := func() time.Time {
		if timeIndex >= len(times) {
			return times[len(times)-1]
		}
		current := times[timeIndex]
		timeIndex++
		return current
	}

	var gotDiffBase string
	var gotPrompt string

	deps := reviewIterationDeps{
		now:           nowFn,
		currentBranch: func() (string, error) { return "hal/report-review-split", nil },
		diffAgainstBase: func(baseBranch string) (string, error) {
			gotDiffBase = baseBranch
			return "diff --git a/cmd/review.go b/cmd/review.go\n+new line", nil
		},
		prompt: func(ctx context.Context, prompt string) (string, error) {
			gotPrompt = prompt
			return `{
				"summary": "Found two actionable issues",
				"issues": [
					{
						"id": "ISSUE-001",
						"title": "Missing nil check",
						"severity": "high",
						"file": "cmd/review.go",
						"line": 88,
						"rationale": "Can panic on nil dep",
						"suggestedFix": "Guard with nil check"
					},
					{
						"id": "ISSUE-002",
						"title": "Unwrapped error",
						"severity": "medium",
						"file": "internal/compound/review_loop.go",
						"line": 121,
						"rationale": "Loses root cause",
						"suggestedFix": "Wrap with %w"
					}
				]
			}`,
				nil
		},
	}

	result, err := runSingleReviewIteration(context.Background(), "develop", 5, deps)
	if err != nil {
		t.Fatalf("runSingleReviewIteration() unexpected error: %v", err)
	}

	if gotDiffBase != "develop" {
		t.Fatalf("diff base branch = %q, want %q", gotDiffBase, "develop")
	}

	requiredPromptSnippets := []string{"\"issues\"", "\"id\"", "\"title\"", "\"severity\"", "\"file\"", "\"line\"", "\"rationale\"", "\"suggestedFix\""}
	for _, snippet := range requiredPromptSnippets {
		if !strings.Contains(gotPrompt, snippet) {
			t.Fatalf("prompt missing required schema snippet %q", snippet)
		}
	}

	if result.BaseBranch != "develop" {
		t.Fatalf("BaseBranch = %q, want %q", result.BaseBranch, "develop")
	}
	if result.CurrentBranch != "hal/report-review-split" {
		t.Fatalf("CurrentBranch = %q, want %q", result.CurrentBranch, "hal/report-review-split")
	}
	if result.RequestedIterations != 5 {
		t.Fatalf("RequestedIterations = %d, want %d", result.RequestedIterations, 5)
	}
	if result.CompletedIterations != 1 {
		t.Fatalf("CompletedIterations = %d, want %d", result.CompletedIterations, 1)
	}
	if result.StartedAt != start {
		t.Fatalf("StartedAt = %v, want %v", result.StartedAt, start)
	}
	if result.EndedAt != end {
		t.Fatalf("EndedAt = %v, want %v", result.EndedAt, end)
	}

	if len(result.Iterations) != 1 {
		t.Fatalf("len(Iterations) = %d, want %d", len(result.Iterations), 1)
	}

	iteration := result.Iterations[0]
	if iteration.Iteration != 1 {
		t.Fatalf("Iteration number = %d, want %d", iteration.Iteration, 1)
	}
	if iteration.IssuesFound != 2 {
		t.Fatalf("IssuesFound = %d, want %d", iteration.IssuesFound, 2)
	}
	if iteration.ValidIssues != 2 {
		t.Fatalf("ValidIssues = %d, want %d", iteration.ValidIssues, 2)
	}
	if iteration.InvalidIssues != 0 {
		t.Fatalf("InvalidIssues = %d, want %d", iteration.InvalidIssues, 0)
	}
	if iteration.FixesApplied != 0 {
		t.Fatalf("FixesApplied = %d, want %d", iteration.FixesApplied, 0)
	}
	if iteration.Summary != "Found two actionable issues" {
		t.Fatalf("Summary = %q, want %q", iteration.Summary, "Found two actionable issues")
	}

	if result.Totals.IssuesFound != 2 || result.Totals.ValidIssues != 2 {
		t.Fatalf("Totals = %+v, want IssuesFound=2 ValidIssues=2", result.Totals)
	}
}

func TestRunSingleReviewIterationCodexFailure(t *testing.T) {
	deps := reviewIterationDeps{
		now:           time.Now,
		currentBranch: func() (string, error) { return "feature/test", nil },
		diffAgainstBase: func(baseBranch string) (string, error) {
			return "diff --git a/file b/file", nil
		},
		prompt: func(ctx context.Context, prompt string) (string, error) {
			return "", errors.New("codex command failed")
		},
	}

	_, err := runSingleReviewIteration(context.Background(), "develop", 1, deps)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "codex review failed: codex command failed") {
		t.Fatalf("error %q does not contain expected codex failure message", err.Error())
	}
}

func TestParseCodexReviewResponse(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantIssues int
		wantErr    string
	}{
		{
			name:       "valid json with markdown fence",
			input:      "```json\n{\"summary\":\"ok\",\"issues\":[{\"id\":\"ISSUE-1\",\"title\":\"t\",\"severity\":\"low\",\"file\":\"f.go\",\"line\":1,\"rationale\":\"why\",\"suggestedFix\":\"fix\"}]}\n```",
			wantIssues: 1,
		},
		{
			name:    "missing issue id",
			input:   `{"summary":"bad","issues":[{"title":"t","severity":"high","file":"f.go","line":1,"rationale":"why","suggestedFix":"fix"}]}`,
			wantErr: "missing required field: id",
		},
		{
			name:    "missing json object",
			input:   "no json here",
			wantErr: "no JSON object found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseCodexReviewResponse(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(parsed.Issues) != tt.wantIssues {
				t.Fatalf("len(parsed.Issues) = %d, want %d", len(parsed.Issues), tt.wantIssues)
			}
		})
	}
}

func TestBuildCodexReviewPromptIncludesRequiredIssueFields(t *testing.T) {
	prompt := buildCodexReviewPrompt("develop", "feature/test", "diff --git a/a.go b/a.go")

	required := []string{"id", "title", "severity", "file", "line", "rationale", "suggestedFix"}
	for _, field := range required {
		quoted := "\"" + field + "\""
		if !strings.Contains(prompt, quoted) {
			t.Fatalf("prompt missing required issue field %q", quoted)
		}
	}
}
