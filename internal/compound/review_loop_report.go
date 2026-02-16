package compound

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/template"
)

const reviewLoopReportTimestampFormat = "2006-01-02-150405.000"

// WriteReviewLoopJSONReport writes a review loop result artifact under
// .hal/reports/review-loop-<timestamp>.json.
func WriteReviewLoopJSONReport(dir string, result *ReviewLoopResult) (string, error) {
	return writeReviewLoopJSONReport(dir, result, time.Now)
}

// WriteReviewLoopReports writes paired review-loop JSON and markdown artifacts
// using one shared timestamp stem so paths can be reliably matched.
func WriteReviewLoopReports(dir string, result *ReviewLoopResult) (jsonPath string, markdownPath string, err error) {
	return writeReviewLoopReports(dir, result, time.Now)
}

func writeReviewLoopReports(dir string, result *ReviewLoopResult, now func() time.Time) (jsonPath string, markdownPath string, err error) {
	if result == nil {
		return "", "", fmt.Errorf("review loop result is required")
	}
	if now == nil {
		now = time.Now
	}

	timestamp := now()
	fixedNow := func() time.Time { return timestamp }

	jsonPath, err = writeReviewLoopJSONReport(dir, result, fixedNow)
	if err != nil {
		return "", "", fmt.Errorf("write JSON report: %w", err)
	}

	markdownPath, err = writeReviewLoopMarkdownReport(dir, result, fixedNow)
	if err != nil {
		return "", "", fmt.Errorf("write markdown report: %w", err)
	}

	return jsonPath, markdownPath, nil
}

func writeReviewLoopJSONReport(dir string, result *ReviewLoopResult, now func() time.Time) (string, error) {
	if result == nil {
		return "", fmt.Errorf("review loop result is required")
	}
	if now == nil {
		now = time.Now
	}

	reportsDir := filepath.Join(dir, template.HalDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	timestamp := reviewLoopReportTimestamp(result, now)
	reportPath := filepath.Join(reportsDir, fmt.Sprintf("review-loop-%s.json", timestamp))

	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal review loop result: %w", err)
	}
	payload = append(payload, '\n')

	if err := os.WriteFile(reportPath, payload, 0644); err != nil {
		return "", fmt.Errorf("failed to write review loop JSON report: %w", err)
	}

	return reportPath, nil
}

// WriteReviewLoopMarkdownReport writes a markdown summary artifact under
// .hal/reports/review-loop-<timestamp>.md.
func WriteReviewLoopMarkdownReport(dir string, result *ReviewLoopResult) (string, error) {
	return writeReviewLoopMarkdownReport(dir, result, time.Now)
}

func writeReviewLoopMarkdownReport(dir string, result *ReviewLoopResult, now func() time.Time) (string, error) {
	if result == nil {
		return "", fmt.Errorf("review loop result is required")
	}
	if now == nil {
		now = time.Now
	}

	reportsDir := filepath.Join(dir, template.HalDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	timestamp := reviewLoopReportTimestamp(result, now)
	reportPath := filepath.Join(reportsDir, fmt.Sprintf("review-loop-%s.md", timestamp))

	markdown, err := ReviewLoopMarkdown(result)
	if err != nil {
		return "", fmt.Errorf("failed to build review loop markdown: %w", err)
	}

	if err := os.WriteFile(reportPath, []byte(markdown), 0644); err != nil {
		return "", fmt.Errorf("failed to write review loop markdown report: %w", err)
	}

	return reportPath, nil
}

func reviewLoopReportTimestamp(result *ReviewLoopResult, now func() time.Time) string {
	timestamp := now()
	if timestamp.IsZero() {
		timestamp = result.StartedAt
	}
	return timestamp.Format(reviewLoopReportTimestampFormat)
}

// ReviewLoopMarkdown builds a human-readable markdown summary for a review loop result.
func ReviewLoopMarkdown(result *ReviewLoopResult) (string, error) {
	if result == nil {
		return "", fmt.Errorf("review loop result is required")
	}

	var sb strings.Builder

	sb.WriteString("# Review Loop Summary\n\n")

	sb.WriteString("## Run Metadata\n\n")
	sb.WriteString(fmt.Sprintf("- Command: `%s`\n", strings.TrimSpace(result.Command)))
	sb.WriteString(fmt.Sprintf("- Base Branch: `%s`\n", strings.TrimSpace(result.BaseBranch)))
	sb.WriteString(fmt.Sprintf("- Current Branch: `%s`\n", strings.TrimSpace(result.CurrentBranch)))
	sb.WriteString(fmt.Sprintf("- Requested Iterations: %d\n", result.RequestedIterations))
	sb.WriteString(fmt.Sprintf("- Completed Iterations: %d\n", result.CompletedIterations))
	sb.WriteString(fmt.Sprintf("- Started At: %s\n", formatReviewLoopTime(result.StartedAt)))
	sb.WriteString(fmt.Sprintf("- Ended At: %s\n\n", formatReviewLoopTime(result.EndedAt)))

	sb.WriteString("## Iterations\n\n")
	if len(result.Iterations) == 0 {
		sb.WriteString("No iterations were executed.\n\n")
	} else {
		for _, iteration := range result.Iterations {
			sb.WriteString(fmt.Sprintf("### Iteration %d\n", iteration.Iteration))
			sb.WriteString(fmt.Sprintf("- Issues Found: %d\n", iteration.IssuesFound))
			sb.WriteString(fmt.Sprintf("- Valid Issues: %d\n", iteration.ValidIssues))
			sb.WriteString(fmt.Sprintf("- Invalid Issues: %d\n", iteration.InvalidIssues))
			sb.WriteString(fmt.Sprintf("- Fixes Applied: %d\n", iteration.FixesApplied))
			sb.WriteString(fmt.Sprintf("- Summary: %s\n", strings.TrimSpace(iteration.Summary)))
			sb.WriteString(fmt.Sprintf("- Status: %s\n\n", strings.TrimSpace(iteration.Status)))
		}
	}

	sb.WriteString("## Totals\n\n")
	sb.WriteString(fmt.Sprintf("- Issues Found: %d\n", result.Totals.IssuesFound))
	sb.WriteString(fmt.Sprintf("- Valid Issues: %d\n", result.Totals.ValidIssues))
	sb.WriteString(fmt.Sprintf("- Invalid Issues: %d\n", result.Totals.InvalidIssues))
	sb.WriteString(fmt.Sprintf("- Fixes Applied: %d\n\n", result.Totals.FixesApplied))

	sb.WriteString("## Stop Reason\n\n")
	stopReason := strings.TrimSpace(result.StopReason)
	if stopReason == "" {
		stopReason = "unknown"
	}
	sb.WriteString(stopReason)
	sb.WriteString("\n")

	return sb.String(), nil
}

func formatReviewLoopTime(t time.Time) string {
	if t.IsZero() {
		return "n/a"
	}
	return t.Format(time.RFC3339)
}
