package compound

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestReviewLoopTerminalRenderNilResult(t *testing.T) {
	_, err := ReviewLoopTerminalRender(nil, 100)
	if err == nil {
		t.Fatal("expected error for nil result, got nil")
	}
	if !strings.Contains(err.Error(), "review loop result is required") {
		t.Fatalf("error = %q, want 'review loop result is required'", err.Error())
	}
}

func TestReviewLoopTerminalRenderDefaultWidth(t *testing.T) {
	result := &ReviewLoopResult{
		Command:       "hal review --base develop --iterations 3",
		BaseBranch:    "develop",
		CurrentBranch: "hal/test",
	}

	out, err := ReviewLoopTerminalRender(result, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == "" {
		t.Fatal("output is empty")
	}
}

func TestReviewLoopTerminalRenderContainsRequiredSections(t *testing.T) {
	result := &ReviewLoopResult{
		Command:             "hal review --base develop --iterations 3",
		Engine:              "codex",
		BaseBranch:          "develop",
		CurrentBranch:       "hal/test-feature",
		RequestedIterations: 3,
		CompletedIterations: 2,
		StopReason:          "no_valid_issues",
		StartedAt:           time.Date(2026, 3, 26, 10, 0, 0, 0, time.UTC),
		EndedAt:             time.Date(2026, 3, 26, 10, 5, 0, 0, time.UTC),
		Duration:            5 * time.Minute,
		Totals: ReviewLoopTotals{
			IssuesFound:   3,
			ValidIssues:   2,
			InvalidIssues: 1,
			FixesApplied:  2,
			FilesAffected: []string{"cmd/review.go", "internal/compound/render.go"},
		},
		Iterations: []ReviewLoopIteration{
			{
				Iteration:     1,
				IssuesFound:   3,
				ValidIssues:   2,
				InvalidIssues: 1,
				FixesApplied:  2,
				Summary:       "Applied two fixes",
				Status:        "fixed",
				Duration:      3 * time.Minute,
				Issues: []ReviewIssueDetail{
					{
						ID:           "ISSUE-001",
						Title:        "Missing error handling in config load",
						Severity:     "high",
						File:         "cmd/review.go",
						Line:         42,
						Rationale:    "Unchecked error may cause nil pointer dereference",
						SuggestedFix: "Add error check after LoadConfig call",
						Valid:        true,
						Fixed:        true,
					},
					{
						ID:       "ISSUE-002",
						Title:    "Unused import in test file",
						Severity: "low",
						File:     "cmd/review_test.go",
						Line:     5,
						Valid:    false,
						Fixed:    false,
						Reason:   "Import is used in a build-tagged test",
					},
					{
						ID:           "ISSUE-003",
						Title:        "Race condition in concurrent map access",
						Severity:     "critical",
						File:         "internal/compound/render.go",
						Line:         88,
						Rationale:    "Map is accessed from multiple goroutines without synchronization",
						SuggestedFix: "Use sync.Map or add a mutex",
						Valid:        true,
						Fixed:        true,
					},
				},
			},
			{
				Iteration:     2,
				IssuesFound:   0,
				ValidIssues:   0,
				InvalidIssues: 0,
				FixesApplied:  0,
				Summary:       "No issues remain",
				Status:        "clean",
				Duration:      2 * time.Minute,
			},
		},
	}

	out, err := ReviewLoopTerminalRender(result, 120)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requiredContent := []string{
		"Review Loop Summary",
		"Run Metadata",
		"codex",
		"develop",
		"hal/test-feature",
		"2 of 3 requested",
		"Totals",
		"Stop Reason",
		"Iteration 1",
		"Iteration 2",
		"Applied two fixes",
		"No issues remain",
		"Clean review pass",
	}
	for _, content := range requiredContent {
		if !strings.Contains(out, content) {
			t.Errorf("output missing required content %q", content)
		}
	}
}

func TestReviewLoopTerminalRenderIssueTable(t *testing.T) {
	result := &ReviewLoopResult{
		Command:             "hal review --base develop --iterations 1",
		BaseBranch:          "develop",
		CurrentBranch:       "hal/test",
		RequestedIterations: 1,
		CompletedIterations: 1,
		StopReason:          "single_iteration",
		Iterations: []ReviewLoopIteration{
			{
				Iteration:     1,
				IssuesFound:   2,
				ValidIssues:   2,
				InvalidIssues: 0,
				FixesApplied:  1,
				Summary:       "Partial fixes",
				Status:        "fixed",
				Issues: []ReviewIssueDetail{
					{
						ID:       "ISSUE-001",
						Title:    "Long file path handling",
						Severity: "high",
						File:     "internal/sandbox/provider_digitalocean.go",
						Line:     140,
						Valid:    true,
						Fixed:    true,
					},
					{
						ID:       "ISSUE-002",
						Title:    "Missing validation",
						Severity: "medium",
						File:     "cmd/review.go",
						Line:     55,
						Valid:    true,
						Fixed:    false,
					},
				},
			},
		},
		Totals: ReviewLoopTotals{
			IssuesFound:  2,
			ValidIssues:  2,
			FixesApplied: 1,
		},
	}

	out, err := ReviewLoopTerminalRender(result, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Table should contain file paths and issue titles
	tableContent := []string{
		"provider_digitalocean.go",
		"Long file path handling",
		"Missing validation",
		"cmd/review.go",
		"✓",
		"✗",
		"#",
		"Sev",
		"File",
		"Issue",
		"Fix",
	}
	for _, content := range tableContent {
		if !strings.Contains(out, content) {
			t.Errorf("table output missing %q", content)
		}
	}
}

func TestReviewLoopTerminalRenderTruncatesIssueTitlesSafely(t *testing.T) {
	result := &ReviewLoopResult{
		Iterations: []ReviewLoopIteration{
			{
				Iteration:    1,
				IssuesFound:  1,
				ValidIssues:  1,
				FixesApplied: 1,
				Summary:      "Applied one fix",
				Status:       "fixed",
				Issues: []ReviewIssueDetail{
					{
						Title:    strings.Repeat("界", 8) + "ab",
						Severity: "low",
						File:     "internal/compound/review_loop_render.go",
						Line:     222,
						Valid:    true,
						Fixed:    true,
					},
				},
			},
		},
	}

	out, err := ReviewLoopTerminalRender(result, 60)
	if err != nil {
		t.Fatalf("ReviewLoopTerminalRender() unexpected error: %v", err)
	}
	if !utf8.ValidString(out) {
		t.Fatal("ReviewLoopTerminalRender() returned invalid UTF-8")
	}
	if !strings.Contains(out, "...") {
		t.Fatal("expected truncated issue title with ellipsis in terminal output")
	}
}

func TestReviewLoopTerminalRenderNoIterations(t *testing.T) {
	result := &ReviewLoopResult{
		Command:       "hal review --base develop --iterations 1",
		BaseBranch:    "develop",
		CurrentBranch: "hal/test",
	}

	out, err := ReviewLoopTerminalRender(result, 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out, "No iterations were executed") {
		t.Errorf("output missing 'No iterations were executed'")
	}
}

func TestReviewLoopTerminalRenderInvalidIssueShowsSkip(t *testing.T) {
	result := &ReviewLoopResult{
		Command:             "hal review --base develop --iterations 1",
		BaseBranch:          "develop",
		CurrentBranch:       "hal/test",
		RequestedIterations: 1,
		CompletedIterations: 1,
		StopReason:          "single_iteration",
		Iterations: []ReviewLoopIteration{
			{
				Iteration:     1,
				IssuesFound:   1,
				ValidIssues:   0,
				InvalidIssues: 1,
				FixesApplied:  0,
				Summary:       "No valid issues",
				Status:        "reviewed",
				Issues: []ReviewIssueDetail{
					{
						ID:       "ISSUE-001",
						Title:    "False positive",
						Severity: "low",
						File:     "main.go",
						Line:     1,
						Valid:    false,
						Fixed:    false,
						Reason:   "Not actually an issue",
					},
				},
			},
		},
		Totals: ReviewLoopTotals{
			IssuesFound:   1,
			InvalidIssues: 1,
		},
	}

	out, err := ReviewLoopTerminalRender(result, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out, "skip") {
		t.Errorf("output should show 'skip' for invalid issues, got:\n%s", out)
	}
	if !strings.Contains(out, "Not actually an issue") {
		t.Errorf("output should show invalid reason")
	}
}

func TestReviewLoopTerminalRenderSeverityDistribution(t *testing.T) {
	result := &ReviewLoopResult{
		Command:             "hal review --base develop --iterations 1",
		BaseBranch:          "develop",
		CurrentBranch:       "hal/test",
		RequestedIterations: 1,
		CompletedIterations: 1,
		StopReason:          "single_iteration",
		Iterations: []ReviewLoopIteration{
			{
				Iteration:   1,
				IssuesFound: 3,
				ValidIssues: 3,
				Summary:     "Found issues",
				Status:      "reviewed",
				Issues: []ReviewIssueDetail{
					{ID: "1", Title: "A", Severity: "critical", File: "a.go", Line: 1, Valid: true},
					{ID: "2", Title: "B", Severity: "high", File: "b.go", Line: 1, Valid: true},
					{ID: "3", Title: "C", Severity: "high", File: "c.go", Line: 1, Valid: true},
				},
			},
		},
		Totals: ReviewLoopTotals{
			IssuesFound: 3,
			ValidIssues: 3,
		},
	}

	out, err := ReviewLoopTerminalRender(result, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out, "critical") {
		t.Errorf("output should contain severity 'critical'")
	}
	if !strings.Contains(out, "high") {
		t.Errorf("output should contain severity 'high'")
	}
}

func TestReviewLoopIssueAtTableRow(t *testing.T) {
	issues := []ReviewIssueDetail{
		{ID: "ISSUE-001", Severity: "high", Valid: true, Fixed: true},
		{ID: "ISSUE-002", Severity: "low", Valid: true, Fixed: false},
	}

	if _, ok := reviewLoopIssueAtTableRow(issues, 0); ok {
		t.Fatal("expected header row lookup to fail")
	}

	first, ok := reviewLoopIssueAtTableRow(issues, 1)
	if !ok {
		t.Fatal("expected first data row to resolve to an issue")
	}
	if first.ID != "ISSUE-001" {
		t.Fatalf("first row ID = %q, want %q", first.ID, "ISSUE-001")
	}

	second, ok := reviewLoopIssueAtTableRow(issues, 2)
	if !ok {
		t.Fatal("expected second data row to resolve to an issue")
	}
	if second.ID != "ISSUE-002" {
		t.Fatalf("second row ID = %q, want %q", second.ID, "ISSUE-002")
	}

	if _, ok := reviewLoopIssueAtTableRow(issues, 3); ok {
		t.Fatal("expected out-of-range row lookup to fail")
	}
}
