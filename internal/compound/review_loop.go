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

	prompt := buildCodexReviewPrompt(baseBranch, currentBranch, diff)
	response, err := deps.prompt(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("codex review failed: %w", err)
	}

	parsed, err := parseCodexReviewResponse(response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse codex review output: %w", err)
	}

	issuesFound := len(parsed.Issues)
	summary := strings.TrimSpace(parsed.Summary)
	if summary == "" {
		if issuesFound == 0 {
			summary = "No issues found"
		} else {
			summary = fmt.Sprintf("Found %d issues", issuesFound)
		}
	}

	iteration := ReviewLoopIteration{
		Iteration:     1,
		IssuesFound:   issuesFound,
		ValidIssues:   issuesFound,
		InvalidIssues: 0,
		FixesApplied:  0,
		Summary:       summary,
		Status:        "reviewed",
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
			ValidIssues:   issuesFound,
			InvalidIssues: 0,
			FixesApplied:  0,
		},
		Iterations: []ReviewLoopIteration{iteration},
	}, nil
}

func gitDiffAgainstBaseBranch(baseBranch string) (string, error) {
	cmd := exec.Command("git", "diff", baseBranch+"...HEAD")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git diff %s...HEAD failed: %w (stderr: %s)", baseBranch, err, strings.TrimSpace(stderr.String()))
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

func truncateReviewDiff(diff string, maxLen int) string {
	if len(diff) <= maxLen {
		return diff
	}
	return diff[:maxLen] + "\n... (truncated)"
}

func parseCodexReviewResponse(response string) (*codexReviewResponse, error) {
	response = strings.TrimSpace(response)

	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	if jsonStart == -1 || jsonEnd == -1 || jsonEnd < jsonStart {
		return nil, fmt.Errorf("no JSON object found in response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]

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
