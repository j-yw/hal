package compound

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/engine"
)

const reviewLoopDiffMaxLen = 20000

// RunSingleReviewIteration executes one Codex review iteration and records the
// parsed output into the shared ReviewLoopResult contract.
func RunSingleReviewIteration(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
	if eng == nil {
		return nil, fmt.Errorf("engine is required")
	}

	return runSingleReviewIteration(ctx, baseBranch, requestedIterations, reviewIterationDeps{
		now:             time.Now,
		currentBranch:   CurrentBranch,
		diffAgainstBase: gitDiffAgainstBaseBranch,
		prompt:          eng.Prompt,
	})
}

type reviewIterationDeps struct {
	now             func() time.Time
	currentBranch   func() (string, error)
	diffAgainstBase func(baseBranch string) (string, error)
	prompt          func(ctx context.Context, prompt string) (string, error)
}

type codexReviewResponse struct {
	Summary string             `json:"summary"`
	Issues  []codexReviewIssue `json:"issues"`
}

type codexReviewIssue struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	Rationale    string `json:"rationale"`
	SuggestedFix string `json:"suggestedFix"`
}

type codexFixResponse struct {
	Summary string          `json:"summary"`
	Issues  []codexFixIssue `json:"issues"`
}

type codexFixIssue struct {
	ID     string `json:"id"`
	Valid  *bool  `json:"valid"`
	Reason string `json:"reason"`
	Fixed  *bool  `json:"fixed"`
}

type codexFixOutcome struct {
	Summary       string
	ValidIssues   int
	InvalidIssues int
	FixesApplied  int
}

func runSingleReviewIteration(ctx context.Context, baseBranch string, requestedIterations int, deps reviewIterationDeps) (*ReviewLoopResult, error) {
	baseBranch = strings.TrimSpace(baseBranch)
	if baseBranch == "" {
		return nil, fmt.Errorf("base branch is required")
	}
	if requestedIterations <= 0 {
		return nil, fmt.Errorf("requested iterations must be a positive integer")
	}

	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.currentBranch == nil {
		deps.currentBranch = CurrentBranch
	}
	if deps.diffAgainstBase == nil {
		deps.diffAgainstBase = gitDiffAgainstBaseBranch
	}
	if deps.prompt == nil {
		return nil, fmt.Errorf("prompt function is required")
	}

	startedAt := deps.now()

	currentBranch, err := deps.currentBranch()
	if err != nil {
		return nil, fmt.Errorf("failed to determine current branch: %w", err)
	}

	diff, err := deps.diffAgainstBase(baseBranch)
	if err != nil {
		return nil, fmt.Errorf("failed to diff against base branch %q: %w", baseBranch, err)
	}

	reviewPrompt := buildCodexReviewPrompt(baseBranch, currentBranch, diff)
	reviewResponse, err := deps.prompt(ctx, reviewPrompt)
	if err != nil {
		return nil, fmt.Errorf("codex review failed: %w", err)
	}

	parsedReview, err := parseCodexReviewResponse(reviewResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse codex review output: %w", err)
	}

	issuesFound := len(parsedReview.Issues)
	summary := strings.TrimSpace(parsedReview.Summary)
	if summary == "" {
		if issuesFound == 0 {
			summary = "No issues found"
		} else {
			summary = fmt.Sprintf("Found %d issues", issuesFound)
		}
	}

	validIssues := issuesFound
	invalidIssues := 0
	fixesApplied := 0
	status := "reviewed"

	if issuesFound > 0 {
		fixPrompt, err := buildCodexFixPrompt(baseBranch, currentBranch, parsedReview.Issues)
		if err != nil {
			return nil, fmt.Errorf("failed to build codex fix prompt: %w", err)
		}

		fixResponse, err := deps.prompt(ctx, fixPrompt)
		if err != nil {
			return nil, fmt.Errorf("codex fix step failed: %w", err)
		}

		parsedFix, err := parseCodexFixResponse(fixResponse, parsedReview.Issues)
		if err != nil {
			return nil, fmt.Errorf("failed to parse codex fix output: %w", err)
		}

		validIssues = parsedFix.ValidIssues
		invalidIssues = parsedFix.InvalidIssues
		fixesApplied = parsedFix.FixesApplied
		status = "fixed"

		if strings.TrimSpace(parsedFix.Summary) != "" {
			summary = strings.TrimSpace(parsedFix.Summary)
		}
	}

	iteration := ReviewLoopIteration{
		Iteration:     1,
		IssuesFound:   issuesFound,
		ValidIssues:   validIssues,
		InvalidIssues: invalidIssues,
		FixesApplied:  fixesApplied,
		Summary:       summary,
		Status:        status,
	}

	endedAt := deps.now()

	return &ReviewLoopResult{
		Command:             fmt.Sprintf("hal review against %s %d", baseBranch, requestedIterations),
		BaseBranch:          baseBranch,
		CurrentBranch:       currentBranch,
		RequestedIterations: requestedIterations,
		CompletedIterations: 1,
		StopReason:          "single_iteration",
		StartedAt:           startedAt,
		EndedAt:             endedAt,
		Totals: ReviewLoopTotals{
			IssuesFound:   issuesFound,
			ValidIssues:   validIssues,
			InvalidIssues: invalidIssues,
			FixesApplied:  fixesApplied,
		},
		Iterations: []ReviewLoopIteration{iteration},
	}, nil
}

func gitDiffAgainstBaseBranch(baseBranch string) (string, error) {
	mergeBaseCmd := exec.Command("git", "merge-base", baseBranch, "HEAD")
	var mergeBaseStdout, mergeBaseStderr bytes.Buffer
	mergeBaseCmd.Stdout = &mergeBaseStdout
	mergeBaseCmd.Stderr = &mergeBaseStderr

	if err := mergeBaseCmd.Run(); err != nil {
		return "", fmt.Errorf("git merge-base %s HEAD failed: %w (stderr: %s)", baseBranch, err, strings.TrimSpace(mergeBaseStderr.String()))
	}

	mergeBase := strings.TrimSpace(mergeBaseStdout.String())
	if mergeBase == "" {
		return "", fmt.Errorf("git merge-base %s HEAD returned empty output", baseBranch)
	}

	cmd := exec.Command("git", "diff", mergeBase)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git diff %s failed: %w (stderr: %s)", mergeBase, err, strings.TrimSpace(stderr.String()))
	}

	return stdout.String(), nil
}

func buildCodexReviewPrompt(baseBranch, currentBranch, diff string) string {
	var sb strings.Builder

	sb.WriteString("You are a strict code reviewer. Review the current branch changes against the base branch and return machine-readable findings.\n\n")
	sb.WriteString(fmt.Sprintf("Base branch: %s\n", baseBranch))
	sb.WriteString(fmt.Sprintf("Current branch: %s\n\n", currentBranch))

	diff = strings.TrimSpace(diff)
	if diff == "" {
		diff = "(No diff found between base branch and current branch.)"
	}

	sb.WriteString("Diff to review:\n```diff\n")
	sb.WriteString(truncateReviewDiff(diff, reviewLoopDiffMaxLen))
	sb.WriteString("\n```\n\n")

	sb.WriteString(`Return ONLY valid JSON (no markdown fences, no prose) with this schema:
{
  "summary": "short summary of findings",
  "issues": [
    {
      "id": "ISSUE-001",
      "title": "brief issue title",
      "severity": "low|medium|high|critical",
      "file": "relative/path/to/file.go",
      "line": 42,
      "rationale": "why this matters",
      "suggestedFix": "specific fix guidance"
    }
  ]
}

Rules:
- Include every detected issue in the issues array.
- If there are no issues, return "issues": [] and explain that in summary.
`)

	return sb.String()
}

func buildCodexFixPrompt(baseBranch, currentBranch string, issues []codexReviewIssue) (string, error) {
	issueJSON, err := json.MarshalIndent(issues, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal review issues: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("You previously reviewed this branch and identified candidate issues. Validate each issue, then fix only the valid ones.\n\n")
	sb.WriteString(fmt.Sprintf("Base branch: %s\n", baseBranch))
	sb.WriteString(fmt.Sprintf("Current branch: %s\n\n", currentBranch))
	sb.WriteString("Issues to validate and fix:\n")
	sb.Write(issueJSON)
	sb.WriteString("\n\n")

	sb.WriteString(`Instructions:
- Validate each issue against the current repository state.
- Apply code changes only for valid issues.
- Invalid issues must not be fixed.
- Do NOT ask for confirmation; apply fixes directly.
- Return ONLY valid JSON (no markdown fences, no prose) with this schema:
{
  "summary": "short summary of validation and fixes",
  "issues": [
    {
      "id": "ISSUE-001",
      "valid": true,
      "reason": "why this issue is valid or invalid",
      "fixed": true
    }
  ]
}

Rules:
- Include every input issue exactly once in the output "issues" array.
- Use fixed=false for every issue where valid=false.
`)

	return sb.String(), nil
}

func truncateReviewDiff(diff string, maxLen int) string {
	if len(diff) <= maxLen {
		return diff
	}
	return diff[:maxLen] + "\n... (truncated)"
}

func parseCodexReviewResponse(response string) (*codexReviewResponse, error) {
	jsonStr, err := extractJSONObject(response)
	if err != nil {
		return nil, err
	}

	var parsed codexReviewResponse
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	for i, issue := range parsed.Issues {
		if err := validateCodexReviewIssue(i, issue); err != nil {
			return nil, err
		}
	}

	return &parsed, nil
}

func parseCodexFixResponse(response string, reviewedIssues []codexReviewIssue) (*codexFixOutcome, error) {
	if len(reviewedIssues) == 0 {
		return &codexFixOutcome{}, nil
	}

	jsonStr, err := extractJSONObject(response)
	if err != nil {
		return nil, err
	}

	var parsed codexFixResponse
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	reviewedByID := make(map[string]struct{}, len(reviewedIssues))
	for _, issue := range reviewedIssues {
		reviewedByID[issue.ID] = struct{}{}
	}

	fixByID := make(map[string]codexFixIssue, len(parsed.Issues))
	for i, issue := range parsed.Issues {
		if err := validateCodexFixIssue(i, issue); err != nil {
			return nil, err
		}
		if _, ok := reviewedByID[issue.ID]; !ok {
			return nil, fmt.Errorf("issue[%d] references unknown review issue id %q", i, issue.ID)
		}
		if _, exists := fixByID[issue.ID]; exists {
			return nil, fmt.Errorf("duplicate fix result for issue id %q", issue.ID)
		}
		fixByID[issue.ID] = issue
	}

	outcome := &codexFixOutcome{Summary: strings.TrimSpace(parsed.Summary)}
	for _, reviewed := range reviewedIssues {
		fixIssue, ok := fixByID[reviewed.ID]
		if !ok {
			outcome.InvalidIssues++
			continue
		}

		if fixIssue.Valid != nil && *fixIssue.Valid {
			outcome.ValidIssues++
			if fixIssue.Fixed != nil && *fixIssue.Fixed {
				outcome.FixesApplied++
			}
			continue
		}

		outcome.InvalidIssues++
	}

	return outcome, nil
}

func extractJSONObject(response string) (string, error) {
	response = strings.TrimSpace(response)

	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	if jsonStart == -1 || jsonEnd == -1 || jsonEnd < jsonStart {
		return "", fmt.Errorf("no JSON object found in response")
	}

	return response[jsonStart : jsonEnd+1], nil
}

func validateCodexReviewIssue(index int, issue codexReviewIssue) error {
	if strings.TrimSpace(issue.ID) == "" {
		return fmt.Errorf("issue[%d] missing required field: id", index)
	}
	if strings.TrimSpace(issue.Title) == "" {
		return fmt.Errorf("issue[%d] missing required field: title", index)
	}
	if strings.TrimSpace(issue.Severity) == "" {
		return fmt.Errorf("issue[%d] missing required field: severity", index)
	}
	if strings.TrimSpace(issue.File) == "" {
		return fmt.Errorf("issue[%d] missing required field: file", index)
	}
	if issue.Line <= 0 {
		return fmt.Errorf("issue[%d] line must be greater than 0", index)
	}
	if strings.TrimSpace(issue.Rationale) == "" {
		return fmt.Errorf("issue[%d] missing required field: rationale", index)
	}
	if strings.TrimSpace(issue.SuggestedFix) == "" {
		return fmt.Errorf("issue[%d] missing required field: suggestedFix", index)
	}

	return nil
}

func validateCodexFixIssue(index int, issue codexFixIssue) error {
	if strings.TrimSpace(issue.ID) == "" {
		return fmt.Errorf("issue[%d] missing required field: id", index)
	}
	if issue.Valid == nil {
		return fmt.Errorf("issue[%d] missing required field: valid", index)
	}
	if strings.TrimSpace(issue.Reason) == "" {
		return fmt.Errorf("issue[%d] missing required field: reason", index)
	}
	if issue.Fixed == nil {
		return fmt.Errorf("issue[%d] missing required field: fixed", index)
	}

	return nil
}
