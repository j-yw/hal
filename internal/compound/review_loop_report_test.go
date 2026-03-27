package compound

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jywlabs/hal/internal/template"
)

func TestWriteReviewLoopJSONReportCreatesFileWithRequiredFields(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 2, 15, 18, 4, 5, 123000000, time.UTC)

	result := &ReviewLoopResult{
		Command:             "hal review --base develop --iterations 3",
		BaseBranch:          "develop",
		CurrentBranch:       "hal/report-review-split",
		RequestedIterations: 3,
		CompletedIterations: 2,
		StopReason:          "no_valid_issues",
		StartedAt:           time.Date(2026, 2, 15, 18, 0, 0, 0, time.UTC),
		EndedAt:             time.Date(2026, 2, 15, 18, 3, 0, 0, time.UTC),
		Totals: ReviewLoopTotals{
			IssuesFound:   3,
			ValidIssues:   2,
			InvalidIssues: 1,
			FixesApplied:  2,
		},
		Iterations: []ReviewLoopIteration{
			{
				Iteration:     1,
				IssuesFound:   3,
				ValidIssues:   2,
				InvalidIssues: 1,
				FixesApplied:  2,
				Summary:       "Applied fixes",
				Status:        "fixed",
			},
		},
	}

	reportPath, err := writeReviewLoopJSONReport(dir, result, func() time.Time { return now })
	if err != nil {
		t.Fatalf("writeReviewLoopJSONReport() unexpected error: %v", err)
	}

	wantPath := filepath.Join(dir, template.HalDir, "reports", "review-loop-2026-02-15-180405.123.json")
	if reportPath != wantPath {
		t.Fatalf("reportPath = %q, want %q", reportPath, wantPath)
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report file: %v", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(content, &top); err != nil {
		t.Fatalf("report JSON unmarshal failed: %v", err)
	}

	requiredTopLevelFields := []string{
		"command",
		"baseBranch",
		"currentBranch",
		"requestedIterations",
		"completedIterations",
		"stopReason",
		"startedAt",
		"endedAt",
		"totals",
		"iterations",
	}
	for _, field := range requiredTopLevelFields {
		if _, ok := top[field]; !ok {
			t.Fatalf("missing required top-level field %q", field)
		}
	}

	var iterations []map[string]json.RawMessage
	if err := json.Unmarshal(top["iterations"], &iterations); err != nil {
		t.Fatalf("iterations unmarshal failed: %v", err)
	}
	if len(iterations) != 1 {
		t.Fatalf("len(iterations) = %d, want %d", len(iterations), 1)
	}

	requiredIterationFields := []string{
		"iteration",
		"issuesFound",
		"validIssues",
		"invalidIssues",
		"fixesApplied",
		"summary",
		"status",
	}
	for _, field := range requiredIterationFields {
		if _, ok := iterations[0][field]; !ok {
			t.Fatalf("missing required iteration field %q", field)
		}
	}
}

func TestWriteReviewLoopMarkdownReportCreatesFileWithRequiredHeadings(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 2, 15, 18, 4, 5, 0, time.UTC)

	result := &ReviewLoopResult{
		Command:             "hal review --base develop --iterations 3",
		BaseBranch:          "develop",
		CurrentBranch:       "hal/report-review-split",
		RequestedIterations: 3,
		CompletedIterations: 2,
		StopReason:          "no_valid_issues",
		StartedAt:           time.Date(2026, 2, 15, 18, 0, 0, 0, time.UTC),
		EndedAt:             time.Date(2026, 2, 15, 18, 3, 0, 0, time.UTC),
		Totals: ReviewLoopTotals{
			IssuesFound:   2,
			ValidIssues:   1,
			InvalidIssues: 1,
			FixesApplied:  1,
		},
		Iterations: []ReviewLoopIteration{
			{
				Iteration:     1,
				IssuesFound:   2,
				ValidIssues:   1,
				InvalidIssues: 1,
				FixesApplied:  1,
				Summary:       "Applied one fix",
				Status:        "fixed",
			},
			{
				Iteration:     2,
				IssuesFound:   0,
				ValidIssues:   0,
				InvalidIssues: 0,
				FixesApplied:  0,
				Summary:       "No issues remain",
				Status:        "clean",
			},
		},
	}

	reportPath, err := writeReviewLoopMarkdownReport(dir, result, func() time.Time { return now })
	if err != nil {
		t.Fatalf("writeReviewLoopMarkdownReport() unexpected error: %v", err)
	}

	wantPath := filepath.Join(dir, template.HalDir, "reports", "review-loop-2026-02-15-180405.000.md")
	if reportPath != wantPath {
		t.Fatalf("reportPath = %q, want %q", reportPath, wantPath)
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read markdown report: %v", err)
	}

	text := string(content)
	requiredHeadings := []string{
		"# Review Loop Summary",
		"## Run Metadata",
		"## Iterations",
		"## Totals",
		"## Stop Reason",
	}
	for _, heading := range requiredHeadings {
		if !strings.Contains(text, heading) {
			t.Fatalf("markdown report missing required heading %q", heading)
		}
	}

	requiredContent := []string{
		"### Iteration 1",
		"### Iteration 2",
		"**Summary:** Applied one fix",
		"**Summary:** No issues remain",
		"- Issues Found: 2",
		"- Fixes Applied: 1",
		"Clean review pass",
		"Duration:",
	}
	for _, snippet := range requiredContent {
		if !strings.Contains(text, snippet) {
			t.Fatalf("markdown report missing required content %q", snippet)
		}
	}
}

func TestReviewLoopMarkdownTruncatesIssueTitlesSafely(t *testing.T) {
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
						Title:    strings.Repeat("界", 58) + "ab",
						Severity: "low",
						File:     "internal/compound/review_loop_report.go",
						Line:     181,
						Valid:    true,
						Fixed:    true,
					},
				},
			},
		},
	}

	markdown, err := ReviewLoopMarkdown(result)
	if err != nil {
		t.Fatalf("ReviewLoopMarkdown() unexpected error: %v", err)
	}
	if !utf8.ValidString(markdown) {
		t.Fatal("ReviewLoopMarkdown() returned invalid UTF-8")
	}
	if !strings.Contains(markdown, "... |") {
		t.Fatal("expected truncated issue title with ellipsis in markdown table")
	}
}

func TestReviewLoopMarkdownEscapesTableCells(t *testing.T) {
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
						Title:    "bad | title\nnext line",
						Severity: "low",
						File:     "internal/compound/review|loop_report.go",
						Line:     171,
						Valid:    true,
						Fixed:    true,
					},
				},
			},
		},
	}

	markdown, err := ReviewLoopMarkdown(result)
	if err != nil {
		t.Fatalf("ReviewLoopMarkdown() unexpected error: %v", err)
	}

	expectedRow := "| 1 | low | internal/compound/review\\|loop_report.go:171 | bad \\| title<br>next line | ✓ |"
	if !strings.Contains(markdown, expectedRow) {
		t.Fatalf("markdown report missing escaped table row %q", expectedRow)
	}
}

func TestHumanizeStopReasonNoValidIssuesAfterInvalidFindings(t *testing.T) {
	result := &ReviewLoopResult{
		CompletedIterations: 2,
		StopReason:          "no_valid_issues",
		Iterations: []ReviewLoopIteration{
			{
				Iteration:     1,
				IssuesFound:   1,
				ValidIssues:   1,
				InvalidIssues: 0,
			},
			{
				Iteration:     2,
				IssuesFound:   1,
				ValidIssues:   0,
				InvalidIssues: 1,
			},
		},
	}

	got := humanizeStopReason(result)
	want := "No valid issues remained in iteration 2; 1 finding(s) were ruled invalid."
	if got != want {
		t.Fatalf("humanizeStopReason() = %q, want %q", got, want)
	}
}

func TestWriteReviewLoopReportsUsesSharedTimestampForArtifacts(t *testing.T) {
	dir := t.TempDir()
	firstNow := time.Date(2026, 2, 15, 20, 30, 40, 321000000, time.UTC)
	secondNow := firstNow.Add(2 * time.Second)
	callCount := 0

	result := &ReviewLoopResult{
		Command:             "hal review --base develop --iterations 3",
		BaseBranch:          "develop",
		CurrentBranch:       "hal/report-review-split",
		RequestedIterations: 3,
	}

	jsonPath, markdownPath, err := writeReviewLoopReports(dir, result, func() time.Time {
		callCount++
		if callCount == 1 {
			return firstNow
		}
		return secondNow
	})
	if err != nil {
		t.Fatalf("writeReviewLoopReports() unexpected error: %v", err)
	}

	if callCount != 1 {
		t.Fatalf("now() call count = %d, want %d", callCount, 1)
	}

	wantJSONPath := filepath.Join(dir, template.HalDir, "reports", "review-loop-2026-02-15-203040.321.json")
	if jsonPath != wantJSONPath {
		t.Fatalf("jsonPath = %q, want %q", jsonPath, wantJSONPath)
	}

	wantMarkdownPath := filepath.Join(dir, template.HalDir, "reports", "review-loop-2026-02-15-203040.321.md")
	if markdownPath != wantMarkdownPath {
		t.Fatalf("markdownPath = %q, want %q", markdownPath, wantMarkdownPath)
	}
}

func TestWriteReviewLoopJSONReportNilResult(t *testing.T) {
	_, err := writeReviewLoopJSONReport(t.TempDir(), nil, time.Now)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "review loop result is required") {
		t.Fatalf("error %q does not contain expected message", err.Error())
	}
}

func TestCountSeverities_IgnoresInvalidIssues(t *testing.T) {
	counts := countSeverities([]ReviewLoopIteration{
		{
			Issues: []ReviewIssueDetail{
				{Severity: "critical", Valid: false},
				{Severity: "High", Valid: true},
				{Severity: " low ", Valid: true},
			},
		},
	})

	if _, ok := counts["critical"]; ok {
		t.Fatalf("countSeverities() counted invalid severity: %#v", counts)
	}
	if counts["high"] != 1 {
		t.Fatalf("countSeverities()[high] = %d, want 1", counts["high"])
	}
	if counts["low"] != 1 {
		t.Fatalf("countSeverities()[low] = %d, want 1", counts["low"])
	}
}

func TestWriteReviewLoopMarkdownReportNilResult(t *testing.T) {
	_, err := writeReviewLoopMarkdownReport(t.TempDir(), nil, time.Now)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "review loop result is required") {
		t.Fatalf("error %q does not contain expected message", err.Error())
	}
}
