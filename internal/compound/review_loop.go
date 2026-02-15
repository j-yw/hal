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
	"github.com/jywlabs/hal/internal/skills"
)

const (
	reviewLoopDiffMaxLen    = 20000
	reviewPromptMaxRetries  = 2
	reviewPromptBaseBackoff = 2 * time.Second
)

// RunReviewLoop executes review iterations up to requestedIterations.
// It stops early when an iteration reports zero valid issues.
func RunReviewLoop(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
	if eng == nil {
		return nil, fmt.Errorf("engine is required")
	}

	return runReviewLoop(ctx, baseBranch, requestedIterations, reviewIterationDeps{
		now:             time.Now,
		currentBranch:   CurrentBranch,
		diffAgainstBase: gitDiffAgainstBaseBranch,
		prompt: func(ctx context.Context, prompt string) (string, error) {
			// Use StreamPrompt to avoid no-TTY hangs in detached runs and keep
			// event handling behavior consistent with other command flows.
			return eng.StreamPrompt(ctx, prompt, nil)
		},
		maxRetries: reviewPromptMaxRetries,
		retryDelay: reviewPromptBaseBackoff,
	})
}

// RunCodexReviewLoop is kept for compatibility with older callers.
func RunCodexReviewLoop(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
	return RunReviewLoop(ctx, eng, baseBranch, requestedIterations)
}

// RunReviewIteration executes one review iteration and records the parsed output
// into the shared ReviewLoopResult contract.
func RunReviewIteration(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
	if eng == nil {
		return nil, fmt.Errorf("engine is required")
	}

	return runSingleReviewIteration(ctx, baseBranch, requestedIterations, reviewIterationDeps{
		now:             time.Now,
		currentBranch:   CurrentBranch,
		diffAgainstBase: gitDiffAgainstBaseBranch,
		prompt: func(ctx context.Context, prompt string) (string, error) {
			// Use StreamPrompt to avoid no-TTY hangs in detached runs and keep
			// event handling behavior consistent with other command flows.
			return eng.StreamPrompt(ctx, prompt, nil)
		},
		maxRetries: reviewPromptMaxRetries,
		retryDelay: reviewPromptBaseBackoff,
	})
}

// RunSingleReviewIteration is kept for compatibility with older callers.
func RunSingleReviewIteration(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
	return RunReviewIteration(ctx, eng, baseBranch, requestedIterations)
}

type reviewIterationDeps struct {
	now             func() time.Time
	currentBranch   func() (string, error)
	diffAgainstBase func(baseBranch string) (string, error)
	prompt          func(ctx context.Context, prompt string) (string, error)
	sleep           func(ctx context.Context, d time.Duration) error
	maxRetries      int
	retryDelay      time.Duration
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

func runReviewLoop(ctx context.Context, baseBranch string, requestedIterations int, deps reviewIterationDeps) (*ReviewLoopResult, error) {
	baseBranch, deps, err := normalizeReviewLoopDeps(baseBranch, requestedIterations, deps)
	if err != nil {
		return nil, err
	}

	startedAt := deps.now()

	currentBranch, err := deps.currentBranch()
	if err != nil {
		return nil, fmt.Errorf("failed to determine current branch: %w", err)
	}

	result := &ReviewLoopResult{
		Command:             fmt.Sprintf("hal review against %s %d", baseBranch, requestedIterations),
		BaseBranch:          baseBranch,
		CurrentBranch:       currentBranch,
		RequestedIterations: requestedIterations,
		StartedAt:           startedAt,
		Iterations:          make([]ReviewLoopIteration, 0, requestedIterations),
	}

	for i := 1; i <= requestedIterations; i++ {
		iteration, err := runReviewIteration(ctx, baseBranch, currentBranch, deps)
		if err != nil {
			return nil, fmt.Errorf("iteration %d failed: %w", i, err)
		}
		iteration.Iteration = i

		result.Iterations = append(result.Iterations, iteration)
		result.CompletedIterations = i
		result.Totals.IssuesFound += iteration.IssuesFound
		result.Totals.ValidIssues += iteration.ValidIssues
		result.Totals.InvalidIssues += iteration.InvalidIssues
		result.Totals.FixesApplied += iteration.FixesApplied

		if iteration.ValidIssues == 0 {
			result.StopReason = "no_valid_issues"
			break
		}
	}

	if result.StopReason == "" {
		result.StopReason = "max_iterations"
	}

	result.EndedAt = deps.now()
	return result, nil
}

// runCodexReviewLoop is kept for compatibility with older tests/callers.
func runCodexReviewLoop(ctx context.Context, baseBranch string, requestedIterations int, deps reviewIterationDeps) (*ReviewLoopResult, error) {
	return runReviewLoop(ctx, baseBranch, requestedIterations, deps)
}

func runSingleReviewIteration(ctx context.Context, baseBranch string, requestedIterations int, deps reviewIterationDeps) (*ReviewLoopResult, error) {
	baseBranch, deps, err := normalizeReviewLoopDeps(baseBranch, requestedIterations, deps)
	if err != nil {
		return nil, err
	}

	startedAt := deps.now()

	currentBranch, err := deps.currentBranch()
	if err != nil {
		return nil, fmt.Errorf("failed to determine current branch: %w", err)
	}

	iteration, err := runReviewIteration(ctx, baseBranch, currentBranch, deps)
	if err != nil {
		return nil, err
	}
	iteration.Iteration = 1

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
			IssuesFound:   iteration.IssuesFound,
			ValidIssues:   iteration.ValidIssues,
			InvalidIssues: iteration.InvalidIssues,
			FixesApplied:  iteration.FixesApplied,
		},
		Iterations: []ReviewLoopIteration{iteration},
	}, nil
}

func runReviewIteration(ctx context.Context, baseBranch, currentBranch string, deps reviewIterationDeps) (ReviewLoopIteration, error) {
	diff, err := deps.diffAgainstBase(baseBranch)
	if err != nil {
		return ReviewLoopIteration{}, fmt.Errorf("failed to diff against base branch %q: %w", baseBranch, err)
	}

	reviewPrompt := buildCodexReviewPrompt(baseBranch, currentBranch, diff)
	reviewResponse, err := promptWithRetry(ctx, deps, reviewPrompt)
	if err != nil {
		return ReviewLoopIteration{}, fmt.Errorf("review step failed: %w", err)
	}

	parsedReview, err := parseReviewResponseWithRepair(ctx, deps, reviewResponse)
	if err != nil {
		return ReviewLoopIteration{}, fmt.Errorf("failed to parse review output: %w", err)
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

	iteration := ReviewLoopIteration{
		IssuesFound:   issuesFound,
		ValidIssues:   issuesFound,
		InvalidIssues: 0,
		FixesApplied:  0,
		Summary:       summary,
		Status:        "reviewed",
	}

	if issuesFound == 0 {
		return iteration, nil
	}

	fixPrompt, err := buildCodexFixPrompt(baseBranch, currentBranch, parsedReview.Issues)
	if err != nil {
		return ReviewLoopIteration{}, fmt.Errorf("failed to build fix prompt: %w", err)
	}

	fixResponse, err := promptWithRetry(ctx, deps, fixPrompt)
	if err != nil {
		return ReviewLoopIteration{}, fmt.Errorf("fix step failed: %w", err)
	}

	parsedFix, err := parseFixResponseWithRepair(ctx, deps, fixResponse, parsedReview.Issues)
	if err != nil {
		return ReviewLoopIteration{}, fmt.Errorf("failed to parse fix output: %w", err)
	}

	iteration.ValidIssues = parsedFix.ValidIssues
	iteration.InvalidIssues = parsedFix.InvalidIssues
	iteration.FixesApplied = parsedFix.FixesApplied
	iteration.Status = "fixed"
	if strings.TrimSpace(parsedFix.Summary) != "" {
		iteration.Summary = strings.TrimSpace(parsedFix.Summary)
	}

	return iteration, nil
}

func normalizeReviewLoopDeps(baseBranch string, requestedIterations int, deps reviewIterationDeps) (string, reviewIterationDeps, error) {
	baseBranch = strings.TrimSpace(baseBranch)
	if baseBranch == "" {
		return "", deps, fmt.Errorf("base branch is required")
	}
	if requestedIterations <= 0 {
		return "", deps, fmt.Errorf("requested iterations must be a positive integer")
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
		return "", deps, fmt.Errorf("prompt function is required")
	}
	if deps.sleep == nil {
		deps.sleep = sleepWithContext
	}
	if deps.maxRetries < 0 {
		return "", deps, fmt.Errorf("max retries must be greater than or equal to 0")
	}
	if deps.retryDelay <= 0 {
		deps.retryDelay = reviewPromptBaseBackoff
	}

	return baseBranch, deps, nil
}

func promptWithRetry(ctx context.Context, deps reviewIterationDeps, prompt string) (string, error) {
	attempts := deps.maxRetries + 1
	if attempts <= 0 {
		attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		response, err := deps.prompt(ctx, prompt)
		if err == nil {
			return response, nil
		}

		lastErr = err
		if !isRetryablePromptError(err) || attempt == attempts-1 {
			break
		}

		delay := retryBackoff(deps.retryDelay, attempt)
		if err := deps.sleep(ctx, delay); err != nil {
			return "", err
		}
	}

	return "", lastErr
}

func parseReviewResponseWithRepair(ctx context.Context, deps reviewIterationDeps, response string) (*codexReviewResponse, error) {
	parsed, err := parseCodexReviewResponse(response)
	if err == nil {
		return parsed, nil
	}

	repairPrompt := buildReviewRepairPrompt(response)
	repaired, repairErr := promptWithRetry(ctx, deps, repairPrompt)
	if repairErr != nil {
		return nil, fmt.Errorf("initial parse error (%v); JSON repair failed: %w", err, repairErr)
	}

	repairedParsed, repairParseErr := parseCodexReviewResponse(repaired)
	if repairParseErr != nil {
		return nil, fmt.Errorf("initial parse error (%v); repaired output parse failed: %w", err, repairParseErr)
	}

	return repairedParsed, nil
}

func parseFixResponseWithRepair(ctx context.Context, deps reviewIterationDeps, response string, reviewedIssues []codexReviewIssue) (*codexFixOutcome, error) {
	parsed, err := parseCodexFixResponse(response, reviewedIssues)
	if err == nil {
		return parsed, nil
	}

	repairPrompt, repairPromptErr := buildFixRepairPrompt(reviewedIssues, response)
	if repairPromptErr != nil {
		return nil, fmt.Errorf("initial parse error (%v); failed to build JSON repair prompt: %w", err, repairPromptErr)
	}

	repaired, repairErr := promptWithRetry(ctx, deps, repairPrompt)
	if repairErr != nil {
		return nil, fmt.Errorf("initial parse error (%v); JSON repair failed: %w", err, repairErr)
	}

	repairedParsed, repairParseErr := parseCodexFixResponse(repaired, reviewedIssues)
	if repairParseErr != nil {
		return nil, fmt.Errorf("initial parse error (%v); repaired output parse failed: %w", err, repairParseErr)
	}

	return repairedParsed, nil
}

func buildReviewRepairPrompt(rawResponse string) string {
	return fmt.Sprintf(`The previous response did not match the required JSON schema for review findings.

Previous response:
%s

Return ONLY valid JSON (no markdown fences, no prose) with this exact shape:
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

If there are no issues, return "issues": [] and explain that in summary.`, truncateForPrompt(rawResponse, reviewLoopDiffMaxLen))
}

func buildFixRepairPrompt(reviewedIssues []codexReviewIssue, rawResponse string) (string, error) {
	issuesJSON, err := json.MarshalIndent(reviewedIssues, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal reviewed issues: %w", err)
	}

	return fmt.Sprintf(`The previous response did not match the required JSON schema for fix validation.

Input issues (must be preserved by id):
%s

Previous response:
%s

Return ONLY valid JSON (no markdown fences, no prose) with this exact shape:
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
- Include every input issue id exactly once in output issues[]
- Set fixed=false whenever valid=false`, string(issuesJSON), truncateForPrompt(rawResponse, reviewLoopDiffMaxLen)), nil
}

func retryBackoff(base time.Duration, attempt int) time.Duration {
	delay := base * time.Duration(1<<attempt)
	if delay > 2*time.Minute {
		return 2 * time.Minute
	}
	return delay
}

func isRetryablePromptError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	retryablePatterns := []string{
		"rate limit",
		"timeout",
		"timed out",
		"connection",
		"temporary",
		"overloaded",
		"503",
		"429",
	}
	for _, pattern := range retryablePatterns {
		if strings.Contains(msg, pattern) {
			return true
		}
	}

	return false
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func truncateForPrompt(content string, maxLen int) string {
	trimmed := strings.TrimSpace(content)
	if len(trimmed) <= maxLen {
		return trimmed
	}
	return trimmed[:maxLen] + "\n... (truncated)"
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

func reviewLoopSkillPreamble() string {
	content, err := skills.LoadSkill("review-loop")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(content)
}

func buildCodexReviewPrompt(baseBranch, currentBranch, diff string) string {
	var sb strings.Builder

	if preamble := reviewLoopSkillPreamble(); preamble != "" {
		sb.WriteString(preamble)
		sb.WriteString("\n\n")
	}

	sb.WriteString("You are a strict static analyzer. Evaluate the current branch changes against the base branch and return machine-readable findings.\n\n")
	sb.WriteString(fmt.Sprintf("Base branch: %s\n", baseBranch))
	sb.WriteString(fmt.Sprintf("Current branch: %s\n\n", currentBranch))

	diff = strings.TrimSpace(diff)
	if diff == "" {
		diff = "(No diff found between base branch and current branch.)"
	}

	sb.WriteString("Diff to analyze:\n```diff\n")
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
- Do not run any tools or shell commands. Evaluate only the provided diff context.
`)

	return sb.String()
}

func buildCodexFixPrompt(baseBranch, currentBranch string, issues []codexReviewIssue) (string, error) {
	issueJSON, err := json.MarshalIndent(issues, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal review issues: %w", err)
	}

	var sb strings.Builder
	if preamble := reviewLoopSkillPreamble(); preamble != "" {
		sb.WriteString(preamble)
		sb.WriteString("\n\n")
	}

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
