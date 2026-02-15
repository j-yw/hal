package compound

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/template"
)

func TestWriteReviewLoopJSONReportCreatesFileWithRequiredFields(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 2, 15, 18, 4, 5, 123000000, time.UTC)

	result := &ReviewLoopResult{
		Command:             "hal review against develop 3",
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

	wantPath := filepath.Join(dir, template.HalDir, "reports", "review-loop-2026-02-15-180405-000.json")
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

func TestWriteReviewLoopJSONReportNilResult(t *testing.T) {
	_, err := writeReviewLoopJSONReport(t.TempDir(), nil, time.Now)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "review loop result is required") {
		t.Fatalf("error %q does not contain expected message", err.Error())
	}
}
