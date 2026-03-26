package compound

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

// Terminal color palette — consistent with engine/styles.go
var (
	colorSuccess  = lipgloss.Color("#00D787")
	colorError    = lipgloss.Color("#FF5F87")
	colorWarning  = lipgloss.Color("#FFAF00")
	colorInfo     = lipgloss.Color("#5FAFFF")
	colorMuted    = lipgloss.Color("#888888")
	colorAccent   = lipgloss.Color("#AF87FF")
	colorCritical = lipgloss.Color("#FF5F87")
	colorHigh     = lipgloss.Color("#FFAF00")
	colorMedium   = lipgloss.Color("#5FAFFF")
	colorLow      = lipgloss.Color("#888888")
)

// Text styles for terminal rendering
var (
	styleTitle    = lipgloss.NewStyle().Foreground(colorInfo).Bold(true)
	styleMuted    = lipgloss.NewStyle().Foreground(colorMuted)
	styleSuccess  = lipgloss.NewStyle().Foreground(colorSuccess).Bold(true)
	styleError    = lipgloss.NewStyle().Foreground(colorError).Bold(true)
	styleWarning  = lipgloss.NewStyle().Foreground(colorWarning)
	styleBold     = lipgloss.NewStyle().Bold(true)
	styleAccent   = lipgloss.NewStyle().Foreground(colorAccent)
	styleDetail   = lipgloss.NewStyle().Foreground(colorMuted).Italic(true)
	styleSevHigh  = lipgloss.NewStyle().Foreground(colorHigh).Bold(true)
	styleSevCrit  = lipgloss.NewStyle().Foreground(colorCritical).Bold(true)
	styleSevMed   = lipgloss.NewStyle().Foreground(colorMedium)
	styleSevLow   = lipgloss.NewStyle().Foreground(colorLow)
	styleFixed    = lipgloss.NewStyle().Foreground(colorSuccess)
	styleNotFixed = lipgloss.NewStyle().Foreground(colorError)
	styleInvalid  = lipgloss.NewStyle().Foreground(colorMuted).Italic(true)
)

// ReviewLoopTerminalRender produces styled terminal output for a review loop
// result using lipgloss. The width parameter controls table sizing; pass 0 to
// use a sensible default (100).
func ReviewLoopTerminalRender(result *ReviewLoopResult, width int) (string, error) {
	if result == nil {
		return "", fmt.Errorf("review loop result is required")
	}
	if width <= 0 {
		width = 100
	}

	var sb strings.Builder

	// ── Header ──────────────────────────────────────
	sb.WriteString("\n")
	sb.WriteString(styleTitle.Render("Review Loop Summary"))
	sb.WriteString("\n\n")

	// ── Run Metadata ────────────────────────────────
	sb.WriteString(styleBold.Render("Run Metadata"))
	sb.WriteString("\n")
	sb.WriteString(renderMetaLine("Command", result.Command))
	if result.Engine != "" {
		sb.WriteString(renderMetaLine("Engine", result.Engine))
	}
	sb.WriteString(renderMetaLine("Base Branch", result.BaseBranch))
	sb.WriteString(renderMetaLine("Current Branch", result.CurrentBranch))
	sb.WriteString(renderMetaLine("Iterations", fmt.Sprintf("%d of %d requested", result.CompletedIterations, result.RequestedIterations)))
	if !result.StartedAt.IsZero() && !result.EndedAt.IsZero() {
		sb.WriteString(renderMetaLine("Duration", formatDuration(result.EndedAt.Sub(result.StartedAt))))
	}
	sb.WriteString(renderMetaLine("Outcome", synthesizeOutcome(result)))
	sb.WriteString("\n")

	// ── Iterations ──────────────────────────────────
	if len(result.Iterations) == 0 {
		sb.WriteString(styleMuted.Render("  No iterations were executed."))
		sb.WriteString("\n")
	} else {
		for _, iteration := range result.Iterations {
			sb.WriteString(renderIteration(iteration, width))
		}
	}

	// ── Totals ──────────────────────────────────────
	sb.WriteString(styleBold.Render("Totals"))
	sb.WriteString("\n")
	sb.WriteString(renderMetaLine("Issues Found", fmt.Sprintf("%d", result.Totals.IssuesFound)))
	sb.WriteString(renderMetaLine("Valid Issues", fmt.Sprintf("%d", result.Totals.ValidIssues)))
	sb.WriteString(renderMetaLine("Invalid Issues", fmt.Sprintf("%d", result.Totals.InvalidIssues)))
	sb.WriteString(renderMetaLine("Fixes Applied", fmt.Sprintf("%d", result.Totals.FixesApplied)))
	if result.Totals.ValidIssues > 0 {
		fixRate := result.Totals.FixesApplied * 100 / result.Totals.ValidIssues
		sb.WriteString(renderMetaLine("Fix Rate", fmt.Sprintf("%d%%", fixRate)))
	}
	if result.Duration > 0 {
		sb.WriteString(renderMetaLine("Duration", formatDuration(result.Duration)))
	}

	// Severity distribution
	severityCounts := countSeverities(result.Iterations)
	if len(severityCounts) > 0 {
		var parts []string
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if count, ok := severityCounts[sev]; ok {
				parts = append(parts, renderSeverityCount(sev, count))
			}
		}
		sb.WriteString(renderMetaLine("Severity", strings.Join(parts, styleMuted.Render(", "))))
	}

	if len(result.Totals.FilesAffected) > 0 {
		val := fmt.Sprintf("%d", len(result.Totals.FilesAffected))
		if len(result.Totals.FilesAffected) <= 10 {
			val += styleMuted.Render(" — ") + strings.Join(result.Totals.FilesAffected, ", ")
		}
		sb.WriteString(renderMetaLine("Files Affected", val))
	}
	sb.WriteString("\n")

	// ── Stop Reason ─────────────────────────────────
	sb.WriteString(styleBold.Render("Stop Reason"))
	sb.WriteString("\n")
	sb.WriteString("  ")
	sb.WriteString(humanizeStopReason(result))
	sb.WriteString("\n\n")

	return sb.String(), nil
}

func renderMetaLine(label, value string) string {
	return fmt.Sprintf("  %s %s\n", styleMuted.Render(label+":"), value)
}

func renderSeverityCount(sev string, count int) string {
	style := severityStyle(sev)
	return fmt.Sprintf("%d %s", count, style.Render(sev))
}

func renderIteration(iteration ReviewLoopIteration, width int) string {
	var sb strings.Builder

	// Iteration header
	header := fmt.Sprintf("Iteration %d", iteration.Iteration)
	sb.WriteString(styleAccent.Render(header))
	sb.WriteString("\n")

	// Stats line
	stats := fmt.Sprintf("  %s %d (%d valid, %d invalid)  %s %d/%d",
		styleMuted.Render("Issues:"),
		iteration.IssuesFound,
		iteration.ValidIssues,
		iteration.InvalidIssues,
		styleMuted.Render("Fixes:"),
		iteration.FixesApplied,
		iteration.ValidIssues,
	)
	if iteration.Duration > 0 {
		stats += fmt.Sprintf("  %s %s", styleMuted.Render("Duration:"), formatDuration(iteration.Duration))
	}
	sb.WriteString(stats)
	sb.WriteString("\n")

	// Issue table
	if len(iteration.Issues) > 0 {
		sb.WriteString(renderIssueTable(iteration.Issues, width))
	}

	// Details (rationale/reason) below the table
	hasDetails := false
	for _, issue := range iteration.Issues {
		if issue.Rationale != "" || issue.Reason != "" {
			hasDetails = true
			break
		}
	}
	if hasDetails {
		sb.WriteString("\n")
		for i, issue := range iteration.Issues {
			if issue.Rationale == "" && issue.Reason == "" {
				continue
			}
			num := styleMuted.Render(fmt.Sprintf("  %d.", i+1))
			title := styleBold.Render(issue.Title)
			sb.WriteString(fmt.Sprintf("%s %s\n", num, title))
			if !issue.Valid && issue.Reason != "" {
				sb.WriteString(fmt.Sprintf("     %s\n", styleInvalid.Render("invalid: "+issue.Reason)))
			} else if issue.Rationale != "" {
				sb.WriteString(fmt.Sprintf("     %s\n", styleDetail.Render(issue.Rationale)))
			}
			if issue.SuggestedFix != "" {
				sb.WriteString(fmt.Sprintf("     %s %s\n", styleMuted.Render("Fix:"), styleDetail.Render(issue.SuggestedFix)))
			}
		}
	}

	// Summary
	if summary := strings.TrimSpace(iteration.Summary); summary != "" {
		sb.WriteString("\n  ")
		sb.WriteString(styleMuted.Render("Summary: "))
		sb.WriteString(summary)
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	return sb.String()
}

func renderIssueTable(issues []ReviewIssueDetail, width int) string {
	// Build rows
	rows := make([][]string, 0, len(issues))
	for i, issue := range issues {
		num := fmt.Sprintf("%d", i+1)
		sev := issue.Severity
		fileLoc := issue.File
		if issue.Line > 0 {
			fileLoc = fmt.Sprintf("%s:%d", issue.File, issue.Line)
		}

		title := issue.Title
		// Truncate title to fit — leave room for other columns.
		maxTitle := width/3 - 2
		if maxTitle < 20 {
			maxTitle = 20
		}
		if len(title) > maxTitle {
			title = title[:maxTitle-3] + "..."
		}

		fixMark := "—"
		if !issue.Valid {
			fixMark = "skip"
		} else if issue.Fixed {
			fixMark = "✓"
		} else {
			fixMark = "✗"
		}

		rows = append(rows, []string{num, sev, fileLoc, title, fixMark})
	}

	// Build table
	t := table.New().
		Headers("#", "Sev", "File", "Issue", "Fix").
		Rows(rows...).
		Border(lipgloss.NormalBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(colorMuted)).
		Width(width).
		StyleFunc(func(row, col int) lipgloss.Style {
			// Header row
			if row == table.HeaderRow {
				return lipgloss.NewStyle().
					Foreground(colorMuted).
					Bold(true).
					Padding(0, 1)
			}

			base := lipgloss.NewStyle().Padding(0, 1)

			switch col {
			case 0: // #
				return base.Foreground(colorMuted)
			case 1: // Severity
				if row >= 0 && row < len(issues) {
					return base.Foreground(severityColor(issues[row].Severity)).Bold(true)
				}
				return base
			case 2: // File
				return base.Foreground(colorInfo)
			case 3: // Issue
				return base
			case 4: // Fix
				if row >= 0 && row < len(issues) {
					if !issues[row].Valid {
						return base.Foreground(colorMuted).Italic(true)
					}
					if issues[row].Fixed {
						return base.Foreground(colorSuccess)
					}
					return base.Foreground(colorError)
				}
				return base
			}
			return base
		})

	return "\n" + t.Render() + "\n"
}

func severityColor(sev string) lipgloss.Color {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return colorCritical
	case "high":
		return colorHigh
	case "medium":
		return colorMedium
	case "low":
		return colorLow
	default:
		return colorMuted
	}
}

func severityStyle(sev string) lipgloss.Style {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return styleSevCrit
	case "high":
		return styleSevHigh
	case "medium":
		return styleSevMed
	case "low":
		return styleSevLow
	default:
		return styleMuted
	}
}
