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
	var reviewPrompt string
	var fixPrompt string
	promptCalls := 0

	deps := reviewIterationDeps{
		now:           nowFn,
		currentBranch: func() (string, error) { return "hal/report-review-split", nil },
		diffAgainstBase: func(baseBranch string) (string, error) {
			gotDiffBase = baseBranch
			return "diff --git a/cmd/review.go b/cmd/review.go\n+new line", nil
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

	if gotDiffBase != "develop" {
		t.Fatalf("diff base branch = %q, want %q", gotDiffBase, "develop")
	}
	if promptCalls != 2 {
		t.Fatalf("prompt calls = %d, want %d", promptCalls, 2)
	}

	reviewPromptSnippets := []string{"\"issues\"", "\"id\"", "\"title\"", "\"severity\"", "\"file\"", "\"line\"", "\"rationale\"", "\"suggestedFix\"", "Use repository tools and shell commands", "Hard limit for this step: at most 8", "Do not run hal commands or go run . commands", "go test ./..."}
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

	diffCalls := 0
	promptCalls := 0
	deps := reviewIterationDeps{
		now:           nowFn,
		currentBranch: func() (string, error) { return "hal/report-review-split", nil },
		diffAgainstBase: func(baseBranch string) (string, error) {
			diffCalls++
			return "diff --git a/file.go b/file.go", nil
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

	if diffCalls != 2 {
		t.Fatalf("diff calls = %d, want %d", diffCalls, 2)
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
	diffCalls := 0
	promptCalls := 0
	deps := reviewIterationDeps{
		now:           time.Now,
		currentBranch: func() (string, error) { return "hal/report-review-split", nil },
		diffAgainstBase: func(baseBranch string) (string, error) {
			diffCalls++
			return "diff --git a/file.go b/file.go", nil
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

	if diffCalls != 2 {
		t.Fatalf("diff calls = %d, want %d", diffCalls, 2)
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
		diffAgainstBase: func(baseBranch string) (string, error) {
			return "diff --git a/file.go b/file.go", nil
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
	if !strings.Contains(err.Error(), "review step failed: codex command failed") {
		t.Fatalf("error %q does not contain expected review-step failure message", err.Error())
	}
}

func TestRunSingleReviewIterationFixStepFailure(t *testing.T) {
	promptCalls := 0
	deps := reviewIterationDeps{
		now:           time.Now,
		currentBranch: func() (string, error) { return "feature/test", nil },
		diffAgainstBase: func(baseBranch string) (string, error) {
			return "diff --git a/file b/file", nil
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
	prompt := buildReviewLoopPrompt("develop", "feature/test", "diff --git a/a.go b/a.go")

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
