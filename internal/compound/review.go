package compound

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
)

// reviewContext holds gathered context for the review.
type reviewContext struct {
	ProgressContent string
	GitDiff         string
	CommitHistory   string
	PRDContent      string
	PRDJSONContent  string
	AutoPRDContent  string
	BranchName      string
	Warnings        []string
}

// parsedReview holds the parsed AI response.
type parsedReview struct {
	Summary         string   `json:"summary"`
	Patterns        []string `json:"patterns"`
	Issues          []string `json:"issues"`
	TechDebt        []string `json:"techDebt"`
	Recommendations []string `json:"recommendations"`
}

// Review analyzes the work session and generates a report.
// Returns ReviewResult with report path and summary.
func Review(ctx context.Context, eng engine.Engine, display *engine.Display, dir string, opts ReviewOptions) (*ReviewResult, error) {
	// 1. Gather context (graceful degradation)
	rc, err := gatherReviewContext(dir)
	if err != nil {
		return nil, err
	}

	// 2. Show warnings from context gathering
	for _, w := range rc.Warnings {
		display.ShowInfo("   Note: %s\n", w)
	}

	// 3. Build and execute prompt
	prompt := buildReviewPrompt(rc)
	if opts.DryRun {
		display.ShowInfo("   Would analyze branch: %s\n", rc.BranchName)
		display.ShowInfo("   Context available:\n")
		if rc.ProgressContent != "" {
			display.ShowInfo("     - Progress log (%d bytes)\n", len(rc.ProgressContent))
		}
		if rc.GitDiff != "" {
			display.ShowInfo("     - Git diff (%d bytes)\n", len(rc.GitDiff))
		}
		if rc.CommitHistory != "" {
			display.ShowInfo("     - Commit history\n")
		}
		if rc.PRDContent != "" {
			display.ShowInfo("     - PRD content (%d bytes)\n", len(rc.PRDContent))
		}
		if rc.PRDJSONContent != "" {
			display.ShowInfo("     - PRD JSON (%d bytes)\n", len(rc.PRDJSONContent))
		}
		if rc.AutoPRDContent != "" {
			display.ShowInfo("     - Auto PRD JSON (%d bytes)\n", len(rc.AutoPRDContent))
		}
		return &ReviewResult{}, nil
	}

	display.StartSpinner("Analyzing work session...")
	response, err := eng.StreamPrompt(ctx, prompt, display)
	display.StopSpinner()
	if err != nil {
		return nil, fmt.Errorf("review failed: %w", err)
	}

	// 4. Parse response
	parsed, err := parseReviewResponse(response)
	if err != nil {
		// Save raw response to report if parsing fails
		display.ShowInfo("   Warning: Could not parse AI response, saving raw output\n")
		reportPath, saveErr := saveRawReviewReport(dir, rc, response)
		if saveErr != nil {
			return nil, fmt.Errorf("parse failed and could not save raw report: %w", err)
		}
		return &ReviewResult{
			ReportPath: reportPath,
			Summary:    "Review completed but response parsing failed - see raw output in report",
		}, nil
	}

	// 5. Update AGENTS.md (unless skipped)
	if !opts.SkipAgents && len(parsed.Patterns) > 0 {
		if err := updateAgentsMD(dir, rc.BranchName, parsed.Patterns); err != nil {
			display.ShowInfo("   Warning: Could not update AGENTS.md: %s\n", err.Error())
		} else {
			display.ShowInfo("   Added %d patterns to AGENTS.md\n", len(parsed.Patterns))
		}
	}

	// 6. Generate report
	reportPath, err := generateReviewReport(dir, rc, parsed)
	if err != nil {
		return nil, err
	}

	return &ReviewResult{
		ReportPath:      reportPath,
		Summary:         parsed.Summary,
		PatternsAdded:   parsed.Patterns,
		Recommendations: parsed.Recommendations,
	}, nil
}

// gatherReviewContext collects available context for the review.
func gatherReviewContext(dir string) (*reviewContext, error) {
	rc := &reviewContext{}

	// Get current branch
	branch, err := CurrentBranch()
	if err != nil {
		rc.Warnings = append(rc.Warnings, "Could not determine current branch")
		rc.BranchName = "unknown"
	} else {
		rc.BranchName = branch
		if branch == "main" || branch == "master" {
			rc.Warnings = append(rc.Warnings, "On main/master branch - reviewing from commit history only")
		}
	}

	// Read progress log
	progressPath := filepath.Join(dir, template.HalDir, template.ProgressFile)
	if content, err := os.ReadFile(progressPath); err == nil {
		rc.ProgressContent = string(content)
	} else {
		rc.Warnings = append(rc.Warnings, "No progress log found, reviewing from git history only")
	}

	// Get git diff (staged and unstaged)
	rc.GitDiff = getGitDiff()
	if rc.GitDiff == "" && rc.BranchName != "main" && rc.BranchName != "master" {
		// Try diff against main/master
		rc.GitDiff = getGitDiffAgainstMain()
	}

	// Get commit history
	rc.CommitHistory = getCommitHistory(rc.BranchName)

	// Find and read PRD (markdown)
	prdPath := findPRDFile(dir, rc.BranchName)
	if prdPath != "" {
		if content, err := os.ReadFile(prdPath); err == nil {
			rc.PRDContent = string(content)
		}
	} else {
		rc.Warnings = append(rc.Warnings, "No PRD found, generating recommendations without goal context")
	}

	// Read JSON PRDs for task completion status
	halDir := filepath.Join(dir, template.HalDir)
	if content, err := os.ReadFile(filepath.Join(halDir, template.PRDFile)); err == nil {
		rc.PRDJSONContent = string(content)
	}
	if content, err := os.ReadFile(filepath.Join(halDir, template.AutoPRDFile)); err == nil {
		rc.AutoPRDContent = string(content)
	}

	// Check if we have anything to review
	if !rc.hasAnyContext() {
		return nil, fmt.Errorf("nothing to review: no progress log, commits, diff, or PRD found")
	}

	return rc, nil
}

// hasAnyContext checks if we have any context to review.
func (rc *reviewContext) hasAnyContext() bool {
	return rc.ProgressContent != "" ||
		rc.GitDiff != "" ||
		rc.CommitHistory != "" ||
		rc.PRDContent != "" ||
		rc.PRDJSONContent != "" ||
		rc.AutoPRDContent != ""
}

// buildReviewPrompt constructs the prompt for the review engine.
func buildReviewPrompt(rc *reviewContext) string {
	var sb strings.Builder

	// Load the review skill content
	skillContent := skills.SkillContent["review"]
	sb.WriteString(skillContent)

	sb.WriteString("\n\n---\n\n## Context for This Review\n\n")
	sb.WriteString(fmt.Sprintf("**Branch:** %s\n\n", rc.BranchName))

	if rc.ProgressContent != "" {
		sb.WriteString("### Progress Log\n```\n")
		sb.WriteString(truncateContent(rc.ProgressContent, 10000))
		sb.WriteString("\n```\n\n")
	}

	if rc.GitDiff != "" {
		sb.WriteString("### Git Diff\n```diff\n")
		sb.WriteString(truncateContent(rc.GitDiff, 15000))
		sb.WriteString("\n```\n\n")
	}

	if rc.CommitHistory != "" {
		sb.WriteString("### Commit History\n```\n")
		sb.WriteString(truncateContent(rc.CommitHistory, 3000))
		sb.WriteString("\n```\n\n")
	}

	if rc.PRDContent != "" {
		sb.WriteString("### PRD Goals\n```markdown\n")
		sb.WriteString(truncateContent(rc.PRDContent, 8000))
		sb.WriteString("\n```\n\n")
	}

	if rc.PRDJSONContent != "" {
		sb.WriteString("### PRD Task Status (prd.json)\n```json\n")
		sb.WriteString(truncateContent(rc.PRDJSONContent, 5000))
		sb.WriteString("\n```\n\n")
	}

	if rc.AutoPRDContent != "" {
		sb.WriteString("### Auto PRD Task Status (auto-prd.json)\n```json\n")
		sb.WriteString(truncateContent(rc.AutoPRDContent, 5000))
		sb.WriteString("\n```\n\n")
	}

	if len(rc.Warnings) > 0 {
		sb.WriteString("### Notes\n")
		for _, w := range rc.Warnings {
			sb.WriteString(fmt.Sprintf("- %s\n", w))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Now analyze this context and return the JSON output as specified above.\n")

	return sb.String()
}

// parseReviewResponse extracts the parsedReview from the engine response.
func parseReviewResponse(response string) (*parsedReview, error) {
	response = strings.TrimSpace(response)

	// Try to find JSON in the response (handle markdown code fences)
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")

	if jsonStart == -1 || jsonEnd == -1 || jsonEnd < jsonStart {
		return nil, fmt.Errorf("no JSON object found in response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]

	var result parsedReview
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate we got something useful
	if result.Summary == "" {
		return nil, fmt.Errorf("missing required field: summary")
	}

	return &result, nil
}

// updateAgentsMD appends patterns to AGENTS.md in a dated section.
func updateAgentsMD(dir, branch string, patterns []string) error {
	agentsPath := filepath.Join(dir, "AGENTS.md")

	// Read existing content or create header
	var existing string
	if content, err := os.ReadFile(agentsPath); err == nil {
		existing = string(content)
	} else if os.IsNotExist(err) {
		existing = "# Repository Guidelines\n\nThis file provides guidance for AI agents working with this codebase.\n"
	} else {
		return fmt.Errorf("failed to read AGENTS.md: %w", err)
	}

	// Build new section
	date := time.Now().Format("2006-01-02")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n## Patterns from %s (%s)\n\n", branch, date))
	for _, pattern := range patterns {
		sb.WriteString(fmt.Sprintf("- %s\n", pattern))
	}

	// Append to existing content
	newContent := existing + sb.String()

	// Write back
	if err := os.WriteFile(agentsPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write AGENTS.md: %w", err)
	}

	return nil
}

// generateReviewReport creates a markdown report file.
func generateReviewReport(dir string, rc *reviewContext, pr *parsedReview) (string, error) {
	reportsDir := filepath.Join(dir, ".hal", "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	now := time.Now()
	timestamp := now.Format("2006-01-02-150405-000")
	reportPath := filepath.Join(reportsDir, fmt.Sprintf("review-%s.md", timestamp))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Review Report: %s\n\n", rc.BranchName))
	sb.WriteString(fmt.Sprintf("Date: %s\n\n", now.Format("2006-01-02 15:04")))

	sb.WriteString("## Summary\n\n")
	sb.WriteString(pr.Summary)
	sb.WriteString("\n\n")

	if rc.CommitHistory != "" {
		sb.WriteString("## What Was Built\n\n```\n")
		sb.WriteString(truncateContent(rc.CommitHistory, 2000))
		sb.WriteString("\n```\n\n")
	}

	if len(pr.Issues) > 0 {
		sb.WriteString("## Issues Encountered\n\n")
		for _, issue := range pr.Issues {
			sb.WriteString(fmt.Sprintf("- %s\n", issue))
		}
		sb.WriteString("\n")
	}

	if len(pr.TechDebt) > 0 {
		sb.WriteString("## Tech Debt Introduced\n\n")
		for _, debt := range pr.TechDebt {
			sb.WriteString(fmt.Sprintf("- %s\n", debt))
		}
		sb.WriteString("\n")
	}

	if len(pr.Recommendations) > 0 {
		sb.WriteString("## Recommendations for Next Priorities\n\n")
		for i, rec := range pr.Recommendations {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
		sb.WriteString("\n")
	}

	if len(pr.Patterns) > 0 {
		sb.WriteString("## Patterns Discovered\n\n")
		sb.WriteString("These patterns have been added to AGENTS.md:\n\n")
		for _, pattern := range pr.Patterns {
			sb.WriteString(fmt.Sprintf("- %s\n", pattern))
		}
	}

	if err := os.WriteFile(reportPath, []byte(sb.String()), 0644); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	return reportPath, nil
}

// saveRawReviewReport saves raw AI response when parsing fails.
func saveRawReviewReport(dir string, rc *reviewContext, response string) (string, error) {
	reportsDir := filepath.Join(dir, ".hal", "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create reports directory: %w", err)
	}

	now := time.Now()
	timestamp := now.Format("2006-01-02-150405-000")
	reportPath := filepath.Join(reportsDir, fmt.Sprintf("review-%s.md", timestamp))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Review Report: %s\n\n", rc.BranchName))
	sb.WriteString(fmt.Sprintf("Date: %s\n\n", now.Format("2006-01-02 15:04")))
	sb.WriteString("**Note:** AI response could not be parsed. Raw output below.\n\n")
	sb.WriteString("## Raw Response\n\n```\n")
	sb.WriteString(response)
	sb.WriteString("\n```\n")

	if err := os.WriteFile(reportPath, []byte(sb.String()), 0644); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	return reportPath, nil
}

// Helper functions for gathering git context

func getGitDiff() string {
	// Get both staged and unstaged changes
	cmd := exec.Command("git", "diff", "HEAD")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return ""
	}
	return stdout.String()
}

func getGitDiffAgainstMain() string {
	// Try main first, then master
	for _, base := range []string{"main", "master"} {
		cmd := exec.Command("git", "diff", base+"...HEAD")
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil && stdout.Len() > 0 {
			return stdout.String()
		}
	}
	return ""
}

func getCommitHistory(branch string) string {
	// Get commits on this branch (try against main/master)
	for _, base := range []string{"main", "master"} {
		cmd := exec.Command("git", "log", "--oneline", base+"..HEAD")
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		if err := cmd.Run(); err == nil && stdout.Len() > 0 {
			return stdout.String()
		}
	}

	// Fallback: recent commits on current branch
	cmd := exec.Command("git", "log", "--oneline", "-20")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err == nil {
		return stdout.String()
	}
	return ""
}

func findPRDFile(dir, branch string) string {
	halDir := filepath.Join(dir, ".hal")

	// Try branch-specific PRD first
	if branch != "" && branch != "main" && branch != "master" {
		// Extract feature name from branch (e.g., "hal/compound-engineering" -> "compound-engineering")
		parts := strings.Split(branch, "/")
		feature := parts[len(parts)-1]

		// Try various patterns
		patterns := []string{
			fmt.Sprintf("prd-%s.md", feature),
			fmt.Sprintf("prd-feature-specification-%s.md", feature),
		}

		for _, pattern := range patterns {
			path := filepath.Join(halDir, pattern)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	// Try to find any PRD file
	entries, err := os.ReadDir(halDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "prd-") && strings.HasSuffix(entry.Name(), ".md") {
			return filepath.Join(halDir, entry.Name())
		}
	}

	return ""
}

func truncateContent(content string, maxLen int) string {
	if len(content) <= maxLen {
		return content
	}
	return content[:maxLen] + "\n... (truncated)"
}
