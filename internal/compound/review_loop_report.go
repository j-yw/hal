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
	if result.Engine != "" {
		sb.WriteString(fmt.Sprintf("- Engine: %s\n", strings.TrimSpace(result.Engine)))
	}
	sb.WriteString(fmt.Sprintf("- Base Branch: `%s`\n", strings.TrimSpace(result.BaseBranch)))
	sb.WriteString(fmt.Sprintf("- Current Branch: `%s`\n", strings.TrimSpace(result.CurrentBranch)))
	sb.WriteString(fmt.Sprintf("- Requested Iterations: %d\n", result.RequestedIterations))
	sb.WriteString(fmt.Sprintf("- Completed Iterations: %d\n", result.CompletedIterations))
	sb.WriteString(fmt.Sprintf("- Started At: %s\n", formatReviewLoopTime(result.StartedAt)))
	sb.WriteString(fmt.Sprintf("- Ended At: %s\n", formatReviewLoopTime(result.EndedAt)))
	if !result.StartedAt.IsZero() && !result.EndedAt.IsZero() {
		sb.WriteString(fmt.Sprintf("- Duration: %s\n", formatDuration(result.EndedAt.Sub(result.StartedAt))))
	}
	sb.WriteString(fmt.Sprintf("- Outcome: %s\n", synthesizeOutcome(result)))
	sb.WriteString("\n")

	sb.WriteString("## Iterations\n\n")
	if len(result.Iterations) == 0 {
		sb.WriteString("No iterations were executed.\n\n")
	} else {
		for _, iteration := range result.Iterations {
			sb.WriteString(fmt.Sprintf("### Iteration %d\n\n", iteration.Iteration))
			sb.WriteString(fmt.Sprintf("- Issues Found: %d (%d valid, %d invalid)\n", iteration.IssuesFound, iteration.ValidIssues, iteration.InvalidIssues))
			sb.WriteString(fmt.Sprintf("- Fixes Applied: %d/%d\n", iteration.FixesApplied, iteration.ValidIssues))
			if iteration.Duration > 0 {
				sb.WriteString(fmt.Sprintf("- Duration: %s\n", formatDuration(iteration.Duration)))
			}

			// Render per-issue details when available
			if len(iteration.Issues) > 0 {
				sb.WriteString("\n| # | Severity | File | Issue | Fixed |\n")
				sb.WriteString("|---|----------|------|-------|-------|\n")
				for i, issue := range iteration.Issues {
					fileLoc := issue.File
					if issue.Line > 0 {
						fileLoc = fmt.Sprintf("%s:%d", issue.File, issue.Line)
					}
					fixMark := "—"
					if !issue.Valid {
						fixMark = "invalid"
					} else if issue.Fixed {
						fixMark = "✓"
					} else {
						fixMark = "✗"
					}
					title := issue.Title
					if len(title) > 60 {
						title = truncateUTF8(title, 57) + "..."
					}
					sb.WriteString(fmt.Sprintf(
						"| %d | %s | %s | %s | %s |\n",
						i+1,
						escapeMarkdownTableCell(issue.Severity),
						escapeMarkdownTableCell(fileLoc),
						escapeMarkdownTableCell(title),
						escapeMarkdownTableCell(fixMark),
					))
				}

				// Show rationale/reason for each issue when available
				hasDetails := false
				for _, issue := range iteration.Issues {
					if issue.Rationale != "" || issue.SuggestedFix != "" || issue.Reason != "" {
						hasDetails = true
						break
					}
				}
				if hasDetails {
					sb.WriteString("\n**Details:**\n")
					for i, issue := range iteration.Issues {
						if issue.Rationale != "" || issue.SuggestedFix != "" || issue.Reason != "" {
							sb.WriteString(fmt.Sprintf("%d. **%s**", i+1, issue.Title))
							if !issue.Valid && issue.Reason != "" {
								sb.WriteString(fmt.Sprintf(" — *invalid: %s*", issue.Reason))
							} else if issue.Rationale != "" {
								sb.WriteString(fmt.Sprintf(" — %s", issue.Rationale))
							}
							if issue.SuggestedFix != "" {
								sb.WriteString(fmt.Sprintf(" *Fix: %s*", issue.SuggestedFix))
							}
							sb.WriteString("\n")
						}
					}
				}
			}

			sb.WriteString(fmt.Sprintf("\n**Summary:** %s\n\n", strings.TrimSpace(iteration.Summary)))
		}
	}

	sb.WriteString("## Totals\n\n")
	sb.WriteString(fmt.Sprintf("- Issues Found: %d\n", result.Totals.IssuesFound))
	sb.WriteString(fmt.Sprintf("- Valid Issues: %d\n", result.Totals.ValidIssues))
	sb.WriteString(fmt.Sprintf("- Invalid Issues: %d\n", result.Totals.InvalidIssues))
	sb.WriteString(fmt.Sprintf("- Fixes Applied: %d\n", result.Totals.FixesApplied))
	if result.Totals.ValidIssues > 0 {
		fixRate := result.Totals.FixesApplied * 100 / result.Totals.ValidIssues
		sb.WriteString(fmt.Sprintf("- Fix rate: %d%%\n", fixRate))
	}
	if result.Duration > 0 {
		sb.WriteString(fmt.Sprintf("- Duration: %s\n", formatDuration(result.Duration)))
	}

	// Severity distribution across all iterations
	severityCounts := countSeverities(result.Iterations)
	if len(severityCounts) > 0 {
		sb.WriteString("- Severity: ")
		first := true
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if count, ok := severityCounts[sev]; ok {
				if !first {
					sb.WriteString(", ")
				}
				sb.WriteString(fmt.Sprintf("%d %s", count, sev))
				first = false
			}
		}
		sb.WriteString("\n")
	}

	if len(result.Totals.FilesAffected) > 0 {
		sb.WriteString(fmt.Sprintf("- Files Affected: %d", len(result.Totals.FilesAffected)))
		if len(result.Totals.FilesAffected) <= 10 {
			sb.WriteString(" — ")
			sb.WriteString(strings.Join(result.Totals.FilesAffected, ", "))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("\n")

	sb.WriteString("## Stop Reason\n\n")
	sb.WriteString(humanizeStopReason(result))
	sb.WriteString("\n")

	return sb.String(), nil
}

func escapeMarkdownTableCell(value string) string {
	normalized := strings.ReplaceAll(value, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	normalized = strings.ReplaceAll(normalized, "|", "\\|")
	return strings.ReplaceAll(normalized, "\n", "<br>")
}

// synthesizeOutcome produces a high-level outcome line from review loop results.
func synthesizeOutcome(result *ReviewLoopResult) string {
	if result.Totals.IssuesFound == 0 {
		return "Clean — no issues found."
	}
	if result.Totals.ValidIssues == 0 {
		return fmt.Sprintf("Reviewed — %d issue(s) found, none valid.", result.Totals.IssuesFound)
	}
	if result.Totals.FixesApplied == result.Totals.ValidIssues {
		return fmt.Sprintf("All %d valid issue(s) fixed.", result.Totals.ValidIssues)
	}
	return fmt.Sprintf("%d/%d valid issue(s) fixed, %d remaining.",
		result.Totals.FixesApplied, result.Totals.ValidIssues,
		result.Totals.ValidIssues-result.Totals.FixesApplied)
}

// countSeverities tallies severity levels across all iteration issue details.
func countSeverities(iterations []ReviewLoopIteration) map[string]int {
	counts := make(map[string]int)
	for _, iter := range iterations {
		for _, issue := range iter.Issues {
			sev := strings.ToLower(strings.TrimSpace(issue.Severity))
			if sev != "" {
				counts[sev]++
			}
		}
	}
	return counts
}

// humanizeStopReason converts internal stop reason codes to user-friendly text.
func humanizeStopReason(result *ReviewLoopResult) string {
	if result == nil {
		return "Unknown."
	}

	completedIterations := result.CompletedIterations
	switch strings.TrimSpace(result.StopReason) {
	case "no_valid_issues":
		if len(result.Iterations) > 0 {
			last := result.Iterations[len(result.Iterations)-1]
			iteration := last.Iteration
			if iteration == 0 {
				iteration = completedIterations
			}
			switch {
			case last.ValidIssues == 0 && last.IssuesFound == 0:
				return fmt.Sprintf("Clean review pass — no issues found in iteration %d.", iteration)
			case last.ValidIssues == 0 && last.InvalidIssues > 0:
				return fmt.Sprintf("No valid issues remained in iteration %d; %d finding(s) were ruled invalid.", iteration, last.InvalidIssues)
			case last.ValidIssues == 0:
				return fmt.Sprintf("No valid issues remained in iteration %d.", iteration)
			}
		}
		return fmt.Sprintf("No valid issues remained after iteration %d.", completedIterations)
	case "max_iterations":
		return fmt.Sprintf("Reached maximum of %d iterations.", completedIterations)
	case "single_iteration":
		return "Single iteration completed."
	case "":
		return "Unknown."
	default:
		return strings.TrimSpace(result.StopReason)
	}
}

func formatReviewLoopTime(t time.Time) string {
	if t.IsZero() {
		return "n/a"
	}
	return t.Format(time.RFC3339)
}

// formatDuration renders a duration as a human-friendly string.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	d = d.Round(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
