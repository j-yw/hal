package compound

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func testReviewBranchContext(baseBranch, currentBranch string) reviewBranchContext {
	return reviewBranchContext{
		BaseBranch:    baseBranch,
		CurrentBranch: currentBranch,
		MergeBase:     "abc123def456",
		DiffShortStat: "1 file changed, 1 insertion(+)",
		ChangedFiles: []reviewBranchFile{{
			Status:    "M",
			Path:      "cmd/review.go",
			Additions: "1",
			Deletions: "0",
		}},
		Commits:    []string{"1234567 feat: review loop test fixture"},
		InlineDiff: "diff --git a/cmd/review.go b/cmd/review.go\n+new line",
	}
}

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

	var gotContextBase string
	var gotContextCurrent string
	var reviewPrompt string
	var fixPrompt string
	promptCalls := 0

	deps := reviewIterationDeps{
		now:           nowFn,
		currentBranch: func() (string, error) { return "hal/report-review-split", nil },
		branchContext: func(baseBranch, currentBranch string) (reviewBranchContext, error) {
			gotContextBase = baseBranch
			gotContextCurrent = currentBranch
			return testReviewBranchContext(baseBranch, currentBranch), nil
		},
		prompt: func(ctx context.Context, prompt string) (string, error) {
			promptCalls++
			switch promptCalls {
			case 1:
				reviewPrompt = prompt
				return `{
					"summary": "Found two candidate issues",
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
			case 2:
				fixPrompt = prompt
				return `{
					"summary": "Applied 1 fix and skipped 1 invalid issue",
					"issues": [
						{
							"id": "ISSUE-001",
							"valid": true,
							"reason": "Issue is reproducible in current code",
							"fixed": true
						},
						{
							"id": "ISSUE-002",
							"valid": false,
							"reason": "False positive after inspecting actual error wrapping",
							"fixed": false
						}
					]
				}`,
					nil
			default:
				t.Fatalf("prompt called %d times, want 2", promptCalls)
				return "", nil
			}
		},
	}

	result, err := runSingleReviewIteration(context.Background(), "develop", 5, deps)
	if err != nil {
		t.Fatalf("runSingleReviewIteration() unexpected error: %v", err)
	}

	if gotContextBase != "develop" {
		t.Fatalf("context base branch = %q, want %q", gotContextBase, "develop")
	}
	if gotContextCurrent != "hal/report-review-split" {
		t.Fatalf("context current branch = %q, want %q", gotContextCurrent, "hal/report-review-split")
	}
	if promptCalls != 2 {
		t.Fatalf("prompt calls = %d, want %d", promptCalls, 2)
	}

	reviewPromptSnippets := []string{"\"issues\"", "\"id\"", "\"title\"", "\"severity\"", "\"file\"", "\"line\"", "\"rationale\"", "\"suggestedFix\"", "Merge base: abc123def456", "Changed files:", "Recent commits since merge-base:", "Inline diff preview:", "Use repository tools and shell commands", "Hard limit for this step: at most 8", "Do not run hal commands or go run . commands", "go test ./..."}
	for _, snippet := range reviewPromptSnippets {
		if !strings.Contains(reviewPrompt, snippet) {
			t.Fatalf("review prompt missing required schema snippet %q", snippet)
		}
	}
	if strings.Contains(reviewPrompt, "Do not run any tools or shell commands") {
		t.Fatalf("review prompt should allow tool usage, got: %q", reviewPrompt)
	}

	fixPromptSnippets := []string{"\"valid\"", "\"reason\"", "\"fixed\"", "Do NOT ask for confirmation", "Use repository tools and shell commands", "Hard limit for this step: at most 12", "Do not run hal commands or go run . commands", "go test ./..."}
	for _, snippet := range fixPromptSnippets {
		if !strings.Contains(fixPrompt, snippet) {
			t.Fatalf("fix prompt missing required schema snippet %q", snippet)
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
	if iteration.ValidIssues != 1 {
		t.Fatalf("ValidIssues = %d, want %d", iteration.ValidIssues, 1)
	}
	if iteration.InvalidIssues != 1 {
		t.Fatalf("InvalidIssues = %d, want %d", iteration.InvalidIssues, 1)
	}
	if iteration.FixesApplied != 1 {
		t.Fatalf("FixesApplied = %d, want %d", iteration.FixesApplied, 1)
	}
	if iteration.Summary != "Applied 1 fix and skipped 1 invalid issue" {
		t.Fatalf("Summary = %q, want %q", iteration.Summary, "Applied 1 fix and skipped 1 invalid issue")
	}
	if iteration.Status != "fixed" {
		t.Fatalf("Status = %q, want %q", iteration.Status, "fixed")
	}

	if result.Totals.IssuesFound != 2 || result.Totals.ValidIssues != 1 || result.Totals.InvalidIssues != 1 || result.Totals.FixesApplied != 1 {
		t.Fatalf("Totals = %+v, want IssuesFound=2 ValidIssues=1 InvalidIssues=1 FixesApplied=1", result.Totals)
	}
}

func TestRunReviewLoopStopsEarlyWhenNoValidIssues(t *testing.T) {
	start := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)
	end := start.Add(10 * time.Second)
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

	branchContextCalls := 0
	promptCalls := 0
	deps := reviewIterationDeps{
		now:           nowFn,
		currentBranch: func() (string, error) { return "hal/report-review-split", nil },
		branchContext: func(baseBranch, currentBranch string) (reviewBranchContext, error) {
			branchContextCalls++
			return testReviewBranchContext(baseBranch, currentBranch), nil
		},
		prompt: func(ctx context.Context, prompt string) (string, error) {
			promptCalls++
			switch promptCalls {
			case 1:
				return `{"summary":"Found one issue","issues":[{"id":"ISSUE-001","title":"Bug","severity":"high","file":"file.go","line":10,"rationale":"reason","suggestedFix":"fix"}]}`,
					nil
			case 2:
				return `{"summary":"Applied the valid fix","issues":[{"id":"ISSUE-001","valid":true,"reason":"real issue","fixed":true}]}`,
					nil
			case 3:
				return `{"summary":"No issues remain","issues":[]}`,
					nil
			default:
				t.Fatalf("prompt called %d times, want 3", promptCalls)
				return "", nil
			}
		},
	}

	result, err := runReviewLoop(context.Background(), "develop", 5, deps)
	if err != nil {
		t.Fatalf("runReviewLoop() unexpected error: %v", err)
	}

	if branchContextCalls != 2 {
		t.Fatalf("branch context calls = %d, want %d", branchContextCalls, 2)
	}
	if promptCalls != 3 {
		t.Fatalf("prompt calls = %d, want %d", promptCalls, 3)
	}

	if result.RequestedIterations != 5 {
		t.Fatalf("RequestedIterations = %d, want %d", result.RequestedIterations, 5)
	}
	if result.CompletedIterations != 2 {
		t.Fatalf("CompletedIterations = %d, want %d", result.CompletedIterations, 2)
	}
	if result.StopReason != "no_valid_issues" {
		t.Fatalf("StopReason = %q, want %q", result.StopReason, "no_valid_issues")
	}
	if result.StartedAt != start {
		t.Fatalf("StartedAt = %v, want %v", result.StartedAt, start)
	}
	if result.EndedAt != end {
		t.Fatalf("EndedAt = %v, want %v", result.EndedAt, end)
	}
	if len(result.Iterations) != 2 {
		t.Fatalf("len(Iterations) = %d, want %d", len(result.Iterations), 2)
	}

	if result.Iterations[0].ValidIssues != 1 {
		t.Fatalf("iteration[0].ValidIssues = %d, want %d", result.Iterations[0].ValidIssues, 1)
	}
	if result.Iterations[1].ValidIssues != 0 {
		t.Fatalf("iteration[1].ValidIssues = %d, want %d", result.Iterations[1].ValidIssues, 0)
	}

	if result.Totals.IssuesFound != 1 || result.Totals.ValidIssues != 1 || result.Totals.InvalidIssues != 0 || result.Totals.FixesApplied != 1 {
		t.Fatalf("Totals = %+v, want IssuesFound=1 ValidIssues=1 InvalidIssues=0 FixesApplied=1", result.Totals)
	}
}

func TestRunReviewLoopStopsAtMaxIterations(t *testing.T) {
	branchContextCalls := 0
	promptCalls := 0
	deps := reviewIterationDeps{
		now:           time.Now,
		currentBranch: func() (string, error) { return "hal/report-review-split", nil },
		branchContext: func(baseBranch, currentBranch string) (reviewBranchContext, error) {
			branchContextCalls++
			return testReviewBranchContext(baseBranch, currentBranch), nil
		},
		prompt: func(ctx context.Context, prompt string) (string, error) {
			promptCalls++
			switch promptCalls {
			case 1, 3:
				return `{"summary":"Found one issue","issues":[{"id":"ISSUE-001","title":"Bug","severity":"high","file":"file.go","line":10,"rationale":"reason","suggestedFix":"fix"}]}`,
					nil
			case 2, 4:
				return `{"summary":"Applied fix","issues":[{"id":"ISSUE-001","valid":true,"reason":"real issue","fixed":true}]}`,
					nil
			default:
				t.Fatalf("prompt called %d times, want 4", promptCalls)
				return "", nil
			}
		},
	}

	result, err := runReviewLoop(context.Background(), "develop", 2, deps)
	if err != nil {
		t.Fatalf("runReviewLoop() unexpected error: %v", err)
	}

	if branchContextCalls != 2 {
		t.Fatalf("branch context calls = %d, want %d", branchContextCalls, 2)
	}
	if promptCalls != 4 {
		t.Fatalf("prompt calls = %d, want %d", promptCalls, 4)
	}

	if result.CompletedIterations != 2 {
		t.Fatalf("CompletedIterations = %d, want %d", result.CompletedIterations, 2)
	}
	if result.StopReason != "max_iterations" {
		t.Fatalf("StopReason = %q, want %q", result.StopReason, "max_iterations")
	}
	if len(result.Iterations) != 2 {
		t.Fatalf("len(Iterations) = %d, want %d", len(result.Iterations), 2)
	}
	if result.Totals.IssuesFound != 2 || result.Totals.ValidIssues != 2 || result.Totals.InvalidIssues != 0 || result.Totals.FixesApplied != 2 {
		t.Fatalf("Totals = %+v, want IssuesFound=2 ValidIssues=2 InvalidIssues=0 FixesApplied=2", result.Totals)
	}
}

func TestRunReviewLoopCallsIterationCallbacks(t *testing.T) {
	type startCall struct {
		current int
		max     int
	}

	var starts []startCall
	var completes []int
	deps := reviewIterationDeps{
		now:           time.Now,
		currentBranch: func() (string, error) { return "feature/test", nil },
		branchContext: func(baseBranch, currentBranch string) (reviewBranchContext, error) {
			return testReviewBranchContext(baseBranch, currentBranch), nil
		},
		prompt: func(ctx context.Context, prompt string) (string, error) {
			return `{"summary":"No issues","issues":[]}`,
				nil
		},
		onIterationStart: func(current, max int) {
			starts = append(starts, startCall{current: current, max: max})
		},
		onIterationComplete: func(current int) {
			completes = append(completes, current)
		},
	}

	result, err := runReviewLoop(context.Background(), "develop", 3, deps)
	if err != nil {
		t.Fatalf("runReviewLoop() unexpected error: %v", err)
	}
	if result.CompletedIterations != 1 {
		t.Fatalf("CompletedIterations = %d, want %d", result.CompletedIterations, 1)
	}

	if len(starts) != 1 {
		t.Fatalf("start callbacks = %d, want %d", len(starts), 1)
	}
	if starts[0].current != 1 || starts[0].max != 3 {
		t.Fatalf("start callback = %+v, want current=1 max=3", starts[0])
	}

	if len(completes) != 1 {
		t.Fatalf("complete callbacks = %d, want %d", len(completes), 1)
	}
	if completes[0] != 1 {
		t.Fatalf("complete callback = %d, want %d", completes[0], 1)
	}
}

func TestRunSingleReviewIterationCodexFailure(t *testing.T) {
	deps := reviewIterationDeps{
		now:           time.Now,
		currentBranch: func() (string, error) { return "feature/test", nil },
		branchContext: func(baseBranch, currentBranch string) (reviewBranchContext, error) {
			return testReviewBranchContext(baseBranch, currentBranch), nil
		},
		prompt: func(ctx context.Context, prompt string) (string, error) {
			return "", errors.New("codex command failed")
		},
	}

	_, err := runSingleReviewIteration(context.Background(), "develop", 1, deps)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "review step failed: codex command failed") {
		t.Fatalf("error %q does not contain expected review-step failure message", err.Error())
	}
}

func TestRunSingleReviewIterationFixStepFailure(t *testing.T) {
	promptCalls := 0
	deps := reviewIterationDeps{
		now:           time.Now,
		currentBranch: func() (string, error) { return "feature/test", nil },
		branchContext: func(baseBranch, currentBranch string) (reviewBranchContext, error) {
			return testReviewBranchContext(baseBranch, currentBranch), nil
		},
		prompt: func(ctx context.Context, prompt string) (string, error) {
			promptCalls++
			if promptCalls == 1 {
				return `{
					"summary": "Found one issue",
					"issues": [
						{
							"id": "ISSUE-001",
							"title": "Bug",
							"severity": "high",
							"file": "file.go",
							"line": 1,
							"rationale": "reason",
							"suggestedFix": "fix"
						}
					]
				}`,
					nil
			}
			return "", errors.New("fix prompt failed")
		},
	}

	_, err := runSingleReviewIteration(context.Background(), "develop", 1, deps)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "fix step failed: fix prompt failed") {
		t.Fatalf("error %q does not contain expected fix-step failure message", err.Error())
	}
}

func TestBuildReviewLoopPromptTruncatesDiffOnUTF8Boundary(t *testing.T) {
	ctx := testReviewBranchContext("main", "feature/test")
	ctx.InlineDiff = strings.Repeat("a", reviewLoopInlineDiffMaxLen-1) + "étail"

	prompt := buildReviewLoopPrompt(ctx)
	if !utf8.ValidString(prompt) {
		t.Fatal("buildReviewLoopPrompt() produced invalid UTF-8")
	}
	if !strings.Contains(prompt, "... (truncated)") {
		t.Fatal("buildReviewLoopPrompt() should include truncation marker")
	}
	if strings.Contains(prompt, "étail") {
		t.Fatal("buildReviewLoopPrompt() should truncate before the split multibyte rune")
	}
}

func TestTruncateForPromptPreservesUTF8(t *testing.T) {
	content := strings.Repeat("b", reviewLoopPromptContextMaxLen-1) + "étail"

	truncated := truncateForPrompt(content, reviewLoopPromptContextMaxLen)
	if !utf8.ValidString(truncated) {
		t.Fatal("truncateForPrompt() produced invalid UTF-8")
	}
	if !strings.Contains(truncated, "... (truncated)") {
		t.Fatal("truncateForPrompt() should include truncation marker")
	}
	if strings.Contains(truncated, "étail") {
		t.Fatal("truncateForPrompt() should truncate before the split multibyte rune")
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
			name:    "missing top-level issues field",
			input:   `{"summary":"ok"}`,
			wantErr: "missing required top-level field: issues",
		},
		{
			name:    "missing issue id",
			input:   `{"summary":"bad","issues":[{"title":"t","severity":"high","file":"f.go","line":1,"rationale":"why","suggestedFix":"fix"}]}`,
			wantErr: "missing required field: id",
		},
		{
			name:    "duplicate issue ids are rejected",
			input:   `{"summary":"bad","issues":[{"id":"ISSUE-1","title":"t1","severity":"high","file":"f.go","line":1,"rationale":"why","suggestedFix":"fix"},{"id":" ISSUE-1 ","title":"t2","severity":"medium","file":"g.go","line":2,"rationale":"why","suggestedFix":"fix"}]}`,
			wantErr: "duplicate review issue id",
		},
		{
			name:    "unknown severity",
			input:   `{"summary":"bad","issues":[{"id":"ISSUE-1","title":"t","severity":"urgent","file":"f.go","line":1,"rationale":"why","suggestedFix":"fix"}]}`,
			wantErr: "severity must be one of low, medium, high, critical",
		},
		{
			name:    "missing json object",
			input:   "no json here",
			wantErr: "no JSON object found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseReviewLoopResponse(tt.input)
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

func TestParseCodexReviewResponseTrimsIssueIDs(t *testing.T) {
	parsed, err := parseReviewLoopResponse(`{"summary":"ok","issues":[{"id":" ISSUE-1 ","title":"t","severity":"low","file":"f.go","line":1,"rationale":"why","suggestedFix":"fix"}]}`)
	if err != nil {
		t.Fatalf("parseReviewLoopResponse() unexpected error: %v", err)
	}

	if len(parsed.Issues) != 1 {
		t.Fatalf("len(parsed.Issues) = %d, want 1", len(parsed.Issues))
	}
	if parsed.Issues[0].ID != "ISSUE-1" {
		t.Fatalf("parsed.Issues[0].ID = %q, want ISSUE-1", parsed.Issues[0].ID)
	}
}

func TestParseCodexFixResponse(t *testing.T) {
	reviewedIssues := []reviewLoopIssue{
		{
			ID:           "ISSUE-1",
			Title:        "Title 1",
			Severity:     "high",
			File:         "a.go",
			Line:         10,
			Rationale:    "why",
			SuggestedFix: "fix",
		},
		{
			ID:           "ISSUE-2",
			Title:        "Title 2",
			Severity:     "medium",
			File:         "b.go",
			Line:         20,
			Rationale:    "why",
			SuggestedFix: "fix",
		},
	}

	tests := []struct {
		name        string
		input       string
		wantValid   int
		wantInvalid int
		wantFixes   int
		wantErr     string
	}{
		{
			name: "valid response",
			input: `{
					"summary": "Applied one fix",
					"issues": [
						{"id":"ISSUE-1","valid":true,"reason":"real bug","fixed":true},
						{"id":"ISSUE-2","valid":false,"reason":"false positive","fixed":false}
					]
				}`,
			wantValid:   1,
			wantInvalid: 1,
			wantFixes:   1,
		},
		{
			name: "ids are matched after trimming whitespace",
			input: `{
					"summary": "Applied one fix",
					"issues": [
						{"id":" ISSUE-1 ","valid":true,"reason":"real bug","fixed":true},
						{"id":"ISSUE-2","valid":false,"reason":"false positive","fixed":false}
					]
				}`,
			wantValid:   1,
			wantInvalid: 1,
			wantFixes:   1,
		},
		{
			name:    "missing top-level issues field",
			input:   `{"summary":"bad"}`,
			wantErr: "missing required top-level field: issues",
		},
		{
			name:    "missing valid field",
			input:   `{"summary":"bad","issues":[{"id":"ISSUE-1","reason":"r","fixed":true}]}`,
			wantErr: "missing required field: valid",
		},
		{
			name:    "missing fix result for reviewed issue",
			input:   `{"summary":"partial","issues":[{"id":"ISSUE-1","valid":true,"reason":"r","fixed":true}]}`,
			wantErr: "missing fix result for review issue ids: ISSUE-2",
		},
		{
			name:    "unknown issue id",
			input:   `{"summary":"bad","issues":[{"id":"ISSUE-999","valid":true,"reason":"r","fixed":true}]}`,
			wantErr: "unknown review issue id",
		},
		{
			name: "invalid issue cannot be marked fixed",
			input: `{
					"summary":"bad",
					"issues":[
						{"id":"ISSUE-1","valid":false,"reason":"not a bug","fixed":true},
						{"id":"ISSUE-2","valid":true,"reason":"real bug","fixed":false}
					]
				}`,
			wantErr: "fixed must be false when valid is false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseReviewLoopFixResponse(tt.input, reviewedIssues)
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
			if parsed.ValidIssues != tt.wantValid {
				t.Fatalf("ValidIssues = %d, want %d", parsed.ValidIssues, tt.wantValid)
			}
			if parsed.InvalidIssues != tt.wantInvalid {
				t.Fatalf("InvalidIssues = %d, want %d", parsed.InvalidIssues, tt.wantInvalid)
			}
			if parsed.FixesApplied != tt.wantFixes {
				t.Fatalf("FixesApplied = %d, want %d", parsed.FixesApplied, tt.wantFixes)
			}
		})
	}
}

func TestBuildCodexReviewPromptIncludesRequiredIssueFields(t *testing.T) {
	ctx := testReviewBranchContext("develop", "feature/test")
	ctx.MergeBase = "deadbeef"
	ctx.DiffShortStat = "2 files changed, 5 insertions(+), 1 deletion(-)"
	ctx.ChangedFiles = []reviewBranchFile{
		{Status: "M", Path: "cmd/review.go", Additions: "4", Deletions: "1"},
		{Status: "A", Path: "internal/review/new.go", Additions: "1", Deletions: "0"},
	}
	prompt := buildReviewLoopPrompt(ctx)

	required := []string{"id", "title", "severity", "file", "line", "rationale", "suggestedFix"}
	for _, field := range required {
		quoted := "\"" + field + "\""
		if !strings.Contains(prompt, quoted) {
			t.Fatalf("prompt missing required issue field %q", quoted)
		}
	}

	if !strings.Contains(prompt, "Use repository tools and shell commands") {
		t.Fatalf("prompt should allow tool usage, got: %q", prompt)
	}
	if !strings.Contains(prompt, "Merge base: deadbeef") {
		t.Fatalf("prompt should include merge-base context, got: %q", prompt)
	}
	if !strings.Contains(prompt, "Changed files:") {
		t.Fatalf("prompt should include changed files, got: %q", prompt)
	}
	if !strings.Contains(prompt, "Recent commits since merge-base:") {
		t.Fatalf("prompt should include recent commits, got: %q", prompt)
	}
	if !strings.Contains(prompt, "git diff <merge-base> -- <path>") {
		t.Fatalf("prompt should instruct targeted diff usage, got: %q", prompt)
	}
	if !strings.Contains(prompt, "Hard limit for this step: at most 8") {
		t.Fatalf("prompt should enforce a review command budget, got: %q", prompt)
	}
	if !strings.Contains(prompt, "Do not run hal commands or go run . commands") {
		t.Fatalf("prompt should block recursive hal/go-run commands, got: %q", prompt)
	}
	if !strings.Contains(prompt, "go test ./...") {
		t.Fatalf("prompt should constrain expensive commands, got: %q", prompt)
	}
	if strings.Contains(prompt, "Do not run any tools or shell commands") {
		t.Fatalf("prompt should not forbid tools, got: %q", prompt)
	}
}

func TestBuildReviewLoopPromptOmitsInlineDiffForLargeContext(t *testing.T) {
	ctx := testReviewBranchContext("develop", "feature/test")
	ctx.InlineDiff = ""

	prompt := buildReviewLoopPrompt(ctx)
	if !strings.Contains(prompt, "Inline diff preview omitted because the change set is large or not a good fit for prompt embedding.") {
		t.Fatalf("prompt should explain omitted inline diff, got: %q", prompt)
	}
	if !strings.Contains(prompt, "git diff abc123def456 -- <path>") {
		t.Fatalf("prompt should include targeted diff command with merge-base, got: %q", prompt)
	}
}

func TestBuildCodexFixPromptIncludesRequiredFields(t *testing.T) {
	issues := []reviewLoopIssue{
		{
			ID:           "ISSUE-1",
			Title:        "Title",
			Severity:     "high",
			File:         "cmd/review.go",
			Line:         42,
			Rationale:    "Why",
			SuggestedFix: "Fix",
		},
	}

	prompt, err := buildReviewLoopFixPrompt("develop", "feature/test", issues)
	if err != nil {
		t.Fatalf("buildReviewLoopFixPrompt() unexpected error: %v", err)
	}

	required := []string{"\"id\"", "\"valid\"", "\"reason\"", "\"fixed\"", "Do NOT ask for confirmation", "Use repository tools and shell commands", "Hard limit for this step: at most 12", "Do not run hal commands or go run . commands", "go test ./..."}
	for _, field := range required {
		if !strings.Contains(prompt, field) {
			t.Fatalf("prompt missing required fix field or instruction %q", field)
		}
	}
}

func TestPromptWithRetryRetriesTransientErrors(t *testing.T) {
	promptCalls := 0
	sleepCalls := 0
	deps := reviewIterationDeps{
		prompt: func(ctx context.Context, prompt string) (string, error) {
			promptCalls++
			if promptCalls < 3 {
				return "", errors.New("rate limit exceeded")
			}
			return "ok", nil
		},
		sleep: func(ctx context.Context, d time.Duration) error {
			sleepCalls++
			return nil
		},
		maxRetries: 2,
		retryDelay: 10 * time.Millisecond,
	}

	got, err := promptWithRetry(context.Background(), deps, "prompt")
	if err != nil {
		t.Fatalf("promptWithRetry() unexpected error: %v", err)
	}
	if got != "ok" {
		t.Fatalf("promptWithRetry() = %q, want %q", got, "ok")
	}
	if promptCalls != 3 {
		t.Fatalf("prompt calls = %d, want %d", promptCalls, 3)
	}
	if sleepCalls != 2 {
		t.Fatalf("sleep calls = %d, want %d", sleepCalls, 2)
	}
}

func TestParseReviewResponseWithRepair(t *testing.T) {
	deps := reviewIterationDeps{
		prompt: func(ctx context.Context, prompt string) (string, error) {
			return `{"summary":"repaired","issues":[{"id":"ISSUE-1","title":"t","severity":"low","file":"f.go","line":1,"rationale":"why","suggestedFix":"fix"}]}`,
				nil
		},
		sleep:      func(ctx context.Context, d time.Duration) error { return nil },
		maxRetries: 0,
		retryDelay: time.Millisecond,
	}

	parsed, err := parseReviewResponseWithRepair(context.Background(), deps, "not-json")
	if err != nil {
		t.Fatalf("parseReviewResponseWithRepair() unexpected error: %v", err)
	}
	if parsed.Summary != "repaired" {
		t.Fatalf("summary = %q, want %q", parsed.Summary, "repaired")
	}
	if len(parsed.Issues) != 1 {
		t.Fatalf("len(issues) = %d, want %d", len(parsed.Issues), 1)
	}
}

func TestParseReviewResponseWithRepairIncompleteOutput(t *testing.T) {
	promptCalled := false
	deps := reviewIterationDeps{
		prompt: func(ctx context.Context, prompt string) (string, error) {
			promptCalled = true
			return "", nil
		},
		sleep:      func(ctx context.Context, d time.Duration) error { return nil },
		maxRetries: 0,
		retryDelay: time.Millisecond,
	}

	_, err := parseReviewResponseWithRepair(context.Background(), deps, "  \n\t")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var incompleteErr *IncompleteReviewOutputError
	if !errors.As(err, &incompleteErr) {
		t.Fatalf("expected IncompleteReviewOutputError, got %T (%v)", err, err)
	}
	if incompleteErr.Stage != "review" {
		t.Fatalf("Stage = %q, want %q", incompleteErr.Stage, "review")
	}
	if promptCalled {
		t.Fatal("repair prompt should not run for incomplete output")
	}
}

func TestCombineReviewBranchFilesMatchesNumstatByPath(t *testing.T) {
	files := combineReviewBranchFiles(
		"M\tchmod_only.sh\nM\ttracked.txt\n",
		"5\t3\ttracked.txt\n",
	)

	if len(files) != 2 {
		t.Fatalf("len(files) = %d, want 2", len(files))
	}
	if files[0].Path != "chmod_only.sh" {
		t.Fatalf("files[0].Path = %q, want %q", files[0].Path, "chmod_only.sh")
	}
	if files[0].Additions != "" || files[0].Deletions != "" {
		t.Fatalf("files[0] stats = +%q -%q, want empty stats", files[0].Additions, files[0].Deletions)
	}
	if files[1].Path != "tracked.txt" {
		t.Fatalf("files[1].Path = %q, want %q", files[1].Path, "tracked.txt")
	}
	if files[1].Additions != "5" || files[1].Deletions != "3" {
		t.Fatalf("files[1] stats = +%q -%q, want +%q -%q", files[1].Additions, files[1].Deletions, "5", "3")
	}
}

func TestShouldInlineReviewDiffUsesNumstatOutput(t *testing.T) {
	files := []reviewBranchFile{
		{Path: "chmod_only.sh"},
		{Path: "tracked.txt"},
	}

	if shouldInlineReviewDiff(files, "999999\t0\ttracked.txt\n") {
		t.Fatal("expected inline diff to be rejected for oversized numstat output")
	}
	if !shouldInlineReviewDiff(files, "5\t3\ttracked.txt\n") {
		t.Fatal("expected inline diff to be allowed for small numstat output")
	}
}

func TestParseFixResponseWithRepair(t *testing.T) {
	reviewed := []reviewLoopIssue{{
		ID:           "ISSUE-1",
		Title:        "t",
		Severity:     "low",
		File:         "f.go",
		Line:         1,
		Rationale:    "why",
		SuggestedFix: "fix",
	}}

	deps := reviewIterationDeps{
		prompt: func(ctx context.Context, prompt string) (string, error) {
			return `{"summary":"repaired fix","issues":[{"id":"ISSUE-1","valid":true,"reason":"real","fixed":true}]}`,
				nil
		},
		sleep:      func(ctx context.Context, d time.Duration) error { return nil },
		maxRetries: 0,
		retryDelay: time.Millisecond,
	}

	parsed, err := parseFixResponseWithRepair(context.Background(), deps, "invalid", reviewed)
	if err != nil {
		t.Fatalf("parseFixResponseWithRepair() unexpected error: %v", err)
	}
	if parsed.ValidIssues != 1 || parsed.FixesApplied != 1 || parsed.InvalidIssues != 0 {
		t.Fatalf("parsed = %+v, want Valid=1 Invalid=0 Fixes=1", parsed)
	}
}

func TestParseFixResponseWithRepairIncompleteOutput(t *testing.T) {
	reviewed := []reviewLoopIssue{{
		ID:           "ISSUE-1",
		Title:        "t",
		Severity:     "low",
		File:         "f.go",
		Line:         1,
		Rationale:    "why",
		SuggestedFix: "fix",
	}}

	promptCalled := false
	deps := reviewIterationDeps{
		prompt: func(ctx context.Context, prompt string) (string, error) {
			promptCalled = true
			return "", nil
		},
		sleep:      func(ctx context.Context, d time.Duration) error { return nil },
		maxRetries: 0,
		retryDelay: time.Millisecond,
	}

	_, err := parseFixResponseWithRepair(context.Background(), deps, "\n\t", reviewed)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var incompleteErr *IncompleteReviewOutputError
	if !errors.As(err, &incompleteErr) {
		t.Fatalf("expected IncompleteReviewOutputError, got %T (%v)", err, err)
	}
	if incompleteErr.Stage != "fix" {
		t.Fatalf("Stage = %q, want %q", incompleteErr.Stage, "fix")
	}
	if promptCalled {
		t.Fatal("repair prompt should not run for incomplete output")
	}
}
