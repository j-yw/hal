package compound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/skills"
)

const (
	reviewLoopInlineDiffMaxLen     = 20000
	reviewLoopPromptContextMaxLen  = 20000
	reviewLoopInlineDiffMaxFiles   = 12
	reviewLoopInlineDiffMaxChanges = 400
	reviewLoopPromptMaxFiles       = 120
	reviewLoopPromptMaxCommits     = 20
	reviewPromptMaxRetries         = 2
	reviewPromptBaseBackoff        = 2 * time.Second
)

var errNoJSONObject = errors.New("no JSON object found in response")

// IncompleteReviewOutputError indicates the model stream ended without
// returning a parseable JSON payload for the current review stage.
type IncompleteReviewOutputError struct {
	Stage string
}

func (e *IncompleteReviewOutputError) Error() string {
	stage := strings.TrimSpace(e.Stage)
	if stage == "" {
		stage = "review"
	}
	return fmt.Sprintf("%s output was incomplete: stream ended without a JSON payload (likely interrupted upstream session; retry the command)", stage)
}

// RunReviewLoop executes review iterations up to requestedIterations.
// It stops early when an iteration reports zero valid issues.
func RunReviewLoop(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
	return RunReviewLoopWithDisplay(ctx, eng, nil, baseBranch, requestedIterations)
}

// RunReviewLoopWithDisplay executes the review loop with an optional display.
// When display is provided, engine stream events are rendered through it.
func RunReviewLoopWithDisplay(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
	if eng == nil {
		return nil, fmt.Errorf("engine is required")
	}

	return runReviewLoop(ctx, baseBranch, requestedIterations, newReviewIterationDeps(eng, display))
}

// RunCodexReviewLoop is kept for compatibility with older callers.
func RunCodexReviewLoop(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
	return RunReviewLoop(ctx, eng, baseBranch, requestedIterations)
}

// RunReviewIteration executes one review iteration and records the parsed output
// into the shared ReviewLoopResult contract.
func RunReviewIteration(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
	return RunReviewIterationWithDisplay(ctx, eng, nil, baseBranch, requestedIterations)
}

// RunReviewIterationWithDisplay executes one review iteration with an optional
// display for engine stream events.
func RunReviewIterationWithDisplay(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
	if eng == nil {
		return nil, fmt.Errorf("engine is required")
	}

	return runSingleReviewIteration(ctx, baseBranch, requestedIterations, newReviewIterationDeps(eng, display))
}

// RunSingleReviewIteration is kept for compatibility with older callers.
func RunSingleReviewIteration(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*ReviewLoopResult, error) {
	return RunReviewIteration(ctx, eng, baseBranch, requestedIterations)
}

func newReviewIterationDeps(eng engine.Engine, display *engine.Display) reviewIterationDeps {
	deps := reviewIterationDeps{
		now:           time.Now,
		currentBranch: CurrentBranch,
		branchContext: gitReviewBranchContext,
		prompt: func(ctx context.Context, prompt string) (string, error) {
			// Use StreamPrompt to avoid no-TTY hangs in detached runs and keep
			// event handling behavior consistent with other command flows.
			return eng.StreamPrompt(ctx, prompt, display)
		},
		maxRetries: reviewPromptMaxRetries,
		retryDelay: reviewPromptBaseBackoff,
	}

	if display != nil {
		deps.onIterationStart = func(current, max int) {
			display.ShowIterationHeader(current, max, nil)
		}
		deps.onIterationComplete = func(current int) {
			display.ShowIterationComplete(current)
		}
	}

	return deps
}

type reviewIterationDeps struct {
	now                 func() time.Time
	currentBranch       func() (string, error)
	branchContext       func(baseBranch, currentBranch string) (reviewBranchContext, error)
	prompt              func(ctx context.Context, prompt string) (string, error)
	sleep               func(ctx context.Context, d time.Duration) error
	onIterationStart    func(current, max int)
	onIterationComplete func(current int)
	maxRetries          int
	retryDelay          time.Duration
}

type reviewBranchContext struct {
	BaseBranch    string
	CurrentBranch string
	MergeBase     string
	DiffShortStat string
	ChangedFiles  []reviewBranchFile
	Commits       []string
	InlineDiff    string
}

type reviewBranchFile struct {
	Status    string
	Path      string
	Additions string
	Deletions string
}

type reviewLoopResponse struct {
	Summary string            `json:"summary"`
	Issues  []reviewLoopIssue `json:"issues"`
}

type reviewLoopIssue struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	Rationale    string `json:"rationale"`
	SuggestedFix string `json:"suggestedFix"`
}

type reviewLoopFixResponse struct {
	Summary string               `json:"summary"`
	Issues  []reviewLoopFixIssue `json:"issues"`
}

type reviewLoopFixIssue struct {
	ID     string `json:"id"`
	Valid  *bool  `json:"valid"`
	Reason string `json:"reason"`
	Fixed  *bool  `json:"fixed"`
}

type reviewLoopFixOutcome struct {
	Summary       string
	ValidIssues   int
	InvalidIssues int
	FixesApplied  int
	PerIssue      []reviewLoopFixResult // per-issue valid/fixed keyed by ID
}

// reviewLoopFixResult holds the fix-phase outcome for a single issue.
type reviewLoopFixResult struct {
	ID     string
	Valid  bool
	Fixed  bool
	Reason string
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
		Command:             fmt.Sprintf("hal review --base %s --iterations %d", baseBranch, requestedIterations),
		BaseBranch:          baseBranch,
		CurrentBranch:       currentBranch,
		RequestedIterations: requestedIterations,
		StartedAt:           startedAt,
		Iterations:          make([]ReviewLoopIteration, 0, requestedIterations),
	}

	for i := 1; i <= requestedIterations; i++ {
		deps.onIterationStart(i, requestedIterations)

		iteration, err := runReviewIteration(ctx, baseBranch, currentBranch, deps)
		if err != nil {
			deps.onIterationComplete(i)
			return nil, fmt.Errorf("iteration %d failed: %w", i, err)
		}
		iteration.Iteration = i

		result.Iterations = append(result.Iterations, iteration)
		result.CompletedIterations = i
		result.Totals.IssuesFound += iteration.IssuesFound
		result.Totals.ValidIssues += iteration.ValidIssues
		result.Totals.InvalidIssues += iteration.InvalidIssues
		result.Totals.FixesApplied += iteration.FixesApplied

		deps.onIterationComplete(i)

		if iteration.ValidIssues == 0 {
			result.StopReason = "no_valid_issues"
			break
		}
	}

	if result.StopReason == "" {
		result.StopReason = "max_iterations"
	}

	result.EndedAt = deps.now()
	result.Duration = result.EndedAt.Sub(result.StartedAt)
	result.Totals.FilesAffected = collectFilesAffected(result.Iterations)
	return result, nil
}

// collectFilesAffected gathers unique file paths from all iteration issue details.
func collectFilesAffected(iterations []ReviewLoopIteration) []string {
	seen := make(map[string]struct{})
	for _, iter := range iterations {
		for _, issue := range iter.Issues {
			f := strings.TrimSpace(issue.File)
			if f != "" {
				seen[f] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	files := make([]string, 0, len(seen))
	for f := range seen {
		files = append(files, f)
	}
	sort.Strings(files)
	return files
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

	deps.onIterationStart(1, requestedIterations)

	iteration, err := runReviewIteration(ctx, baseBranch, currentBranch, deps)
	if err != nil {
		deps.onIterationComplete(1)
		return nil, err
	}
	iteration.Iteration = 1
	deps.onIterationComplete(1)

	endedAt := deps.now()

	return &ReviewLoopResult{
		Command:             fmt.Sprintf("hal review --base %s --iterations %d", baseBranch, requestedIterations),
		BaseBranch:          baseBranch,
		CurrentBranch:       currentBranch,
		RequestedIterations: requestedIterations,
		CompletedIterations: 1,
		StopReason:          "single_iteration",
		StartedAt:           startedAt,
		EndedAt:             endedAt,
		Duration:            endedAt.Sub(startedAt),
		Totals: ReviewLoopTotals{
			IssuesFound:   iteration.IssuesFound,
			ValidIssues:   iteration.ValidIssues,
			InvalidIssues: iteration.InvalidIssues,
			FixesApplied:  iteration.FixesApplied,
			FilesAffected: collectFilesAffected([]ReviewLoopIteration{iteration}),
		},
		Iterations: []ReviewLoopIteration{iteration},
	}, nil
}

func runReviewIteration(ctx context.Context, baseBranch, currentBranch string, deps reviewIterationDeps) (ReviewLoopIteration, error) {
	iterStart := deps.now()

	branchContext, err := deps.branchContext(baseBranch, currentBranch)
	if err != nil {
		return ReviewLoopIteration{}, fmt.Errorf("failed to gather review context against base branch %q: %w", baseBranch, err)
	}

	reviewPrompt := buildReviewLoopPrompt(branchContext)
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
		iteration.Duration = deps.now().Sub(iterStart)
		return iteration, nil
	}

	fixPrompt, err := buildReviewLoopFixPrompt(baseBranch, currentBranch, parsedReview.Issues)
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

	// Build per-issue detail by merging review findings with fix outcomes.
	iteration.Issues = buildIssueDetails(parsedReview.Issues, parsedFix.PerIssue)

	iteration.Duration = deps.now().Sub(iterStart)
	return iteration, nil
}

// buildIssueDetails merges review-phase issue data with fix-phase outcomes
// into a single per-issue detail list suitable for reporting.
func buildIssueDetails(reviewIssues []reviewLoopIssue, fixResults []reviewLoopFixResult) []ReviewIssueDetail {
	fixByID := make(map[string]reviewLoopFixResult, len(fixResults))
	for _, fr := range fixResults {
		fixByID[fr.ID] = fr
	}

	details := make([]ReviewIssueDetail, 0, len(reviewIssues))
	for _, ri := range reviewIssues {
		id := strings.TrimSpace(ri.ID)
		detail := ReviewIssueDetail{
			ID:           id,
			Title:        strings.TrimSpace(ri.Title),
			Severity:     strings.TrimSpace(ri.Severity),
			File:         strings.TrimSpace(ri.File),
			Line:         ri.Line,
			Rationale:    strings.TrimSpace(ri.Rationale),
			SuggestedFix: strings.TrimSpace(ri.SuggestedFix),
			Valid:        true, // default: valid unless fix phase says otherwise
			Fixed:        false,
		}
		if fr, ok := fixByID[id]; ok {
			detail.Valid = fr.Valid
			detail.Fixed = fr.Fixed
			detail.Reason = fr.Reason
		}
		details = append(details, detail)
	}
	return details
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
	if deps.branchContext == nil {
		deps.branchContext = gitReviewBranchContext
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
	if deps.onIterationStart == nil {
		deps.onIterationStart = func(current, max int) {}
	}
	if deps.onIterationComplete == nil {
		deps.onIterationComplete = func(current int) {}
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

func parseReviewResponseWithRepair(ctx context.Context, deps reviewIterationDeps, response string) (*reviewLoopResponse, error) {
	parsed, err := parseReviewLoopResponse(response)
	if err == nil {
		return parsed, nil
	}

	if isIncompleteReviewOutput(response, err) {
		return nil, &IncompleteReviewOutputError{Stage: "review"}
	}

	repairPrompt := buildReviewRepairPrompt(response)
	repaired, repairErr := promptWithRetry(ctx, deps, repairPrompt)
	if repairErr != nil {
		return nil, fmt.Errorf("initial parse error (%v); JSON repair failed: %w", err, repairErr)
	}

	repairedParsed, repairParseErr := parseReviewLoopResponse(repaired)
	if repairParseErr != nil {
		if isIncompleteReviewOutput(repaired, repairParseErr) {
			return nil, &IncompleteReviewOutputError{Stage: "review"}
		}
		return nil, fmt.Errorf("initial parse error (%v); repaired output parse failed: %w", err, repairParseErr)
	}

	return repairedParsed, nil
}

func parseFixResponseWithRepair(ctx context.Context, deps reviewIterationDeps, response string, reviewedIssues []reviewLoopIssue) (*reviewLoopFixOutcome, error) {
	parsed, err := parseReviewLoopFixResponse(response, reviewedIssues)
	if err == nil {
		return parsed, nil
	}

	if isIncompleteReviewOutput(response, err) {
		return nil, &IncompleteReviewOutputError{Stage: "fix"}
	}

	repairPrompt, repairPromptErr := buildFixRepairPrompt(reviewedIssues, response)
	if repairPromptErr != nil {
		return nil, fmt.Errorf("initial parse error (%v); failed to build JSON repair prompt: %w", err, repairPromptErr)
	}

	repaired, repairErr := promptWithRetry(ctx, deps, repairPrompt)
	if repairErr != nil {
		return nil, fmt.Errorf("initial parse error (%v); JSON repair failed: %w", err, repairErr)
	}

	repairedParsed, repairParseErr := parseReviewLoopFixResponse(repaired, reviewedIssues)
	if repairParseErr != nil {
		if isIncompleteReviewOutput(repaired, repairParseErr) {
			return nil, &IncompleteReviewOutputError{Stage: "fix"}
		}
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

If there are no issues, return "issues": [] and explain that in summary.`, truncateForPrompt(rawResponse, reviewLoopPromptContextMaxLen))
}

func buildFixRepairPrompt(reviewedIssues []reviewLoopIssue, rawResponse string) (string, error) {
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
- Set fixed=false whenever valid=false`, string(issuesJSON), truncateForPrompt(rawResponse, reviewLoopPromptContextMaxLen)), nil
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
	return truncateUTF8(trimmed, maxLen) + "\n... (truncated)"
}

func gitReviewBranchContext(baseBranch, currentBranch string) (reviewBranchContext, error) {
	mergeBase, err := gitCommandOutput("merge-base", baseBranch, "HEAD")
	if err != nil {
		return reviewBranchContext{}, err
	}
	mergeBase = strings.TrimSpace(mergeBase)
	if mergeBase == "" {
		return reviewBranchContext{}, fmt.Errorf("git merge-base %s HEAD returned empty output", baseBranch)
	}

	nameStatus, err := gitCommandOutput("diff", "--name-status", mergeBase)
	if err != nil {
		return reviewBranchContext{}, err
	}
	numstat, err := gitCommandOutput("diff", "--numstat", mergeBase)
	if err != nil {
		return reviewBranchContext{}, err
	}
	shortStat, err := gitCommandOutput("diff", "--shortstat", mergeBase)
	if err != nil {
		return reviewBranchContext{}, err
	}
	commits, err := gitCommandOutput("log", "--oneline", "--no-merges", mergeBase+"..HEAD")
	if err != nil {
		return reviewBranchContext{}, err
	}

	changedFiles := combineReviewBranchFiles(nameStatus, numstat)
	ctx := reviewBranchContext{
		BaseBranch:    baseBranch,
		CurrentBranch: currentBranch,
		MergeBase:     mergeBase,
		DiffShortStat: strings.TrimSpace(shortStat),
		ChangedFiles:  changedFiles,
		Commits:       splitNonEmptyLines(commits),
	}

	if shouldInlineReviewDiff(changedFiles, numstat) {
		diff, err := gitCommandOutput("diff", mergeBase)
		if err != nil {
			return reviewBranchContext{}, err
		}
		ctx.InlineDiff = truncateReviewDiff(strings.TrimSpace(diff), reviewLoopInlineDiffMaxLen)
	}

	return ctx, nil
}

func reviewLoopSkillPreamble() string {
	content, err := skills.LoadSkill("review-loop")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(content)
}

func gitCommandOutput(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s failed: %w (stderr: %s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}

	return stdout.String(), nil
}

func combineReviewBranchFiles(nameStatusOutput, numstatOutput string) []reviewBranchFile {
	nameStatusLines := splitNonEmptyLines(nameStatusOutput)
	numstats := parseReviewBranchNumstats(numstatOutput)
	files := make([]reviewBranchFile, 0, len(nameStatusLines))

	for _, line := range nameStatusLines {
		file := parseReviewBranchFile(line)
		for _, key := range reviewBranchFileMatchKeys(file.Path) {
			if stat, ok := numstats[key]; ok {
				applyReviewBranchNumstat(&file, stat)
				break
			}
		}
		files = append(files, file)
	}

	return files
}

type reviewBranchNumstat struct {
	Path      string
	Additions string
	Deletions string
}

func parseReviewBranchFile(line string) reviewBranchFile {
	parts := strings.Split(line, "\t")
	if len(parts) == 0 {
		return reviewBranchFile{}
	}

	status := normalizeReviewBranchStatus(parts[0])
	path := ""

	switch {
	case len(parts) >= 3 && (status == "R" || status == "C"):
		path = strings.TrimSpace(parts[1]) + " -> " + strings.TrimSpace(parts[2])
	case len(parts) >= 2:
		path = strings.TrimSpace(parts[len(parts)-1])
	default:
		path = strings.TrimSpace(line)
	}

	return reviewBranchFile{
		Status: status,
		Path:   path,
	}
}

func normalizeReviewBranchStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return "?"
	}
	switch status[0] {
	case 'R', 'C':
		return status[:1]
	default:
		return status
	}
}

func parseReviewBranchNumstats(output string) map[string]reviewBranchNumstat {
	lines := splitNonEmptyLines(output)
	stats := make(map[string]reviewBranchNumstat, len(lines))
	for _, line := range lines {
		stat, ok := parseReviewBranchNumstat(line)
		if !ok || stat.Path == "" {
			continue
		}
		stats[stat.Path] = stat
	}
	return stats
}

func parseReviewBranchNumstat(line string) (reviewBranchNumstat, bool) {
	parts := strings.SplitN(line, "\t", 3)
	if len(parts) < 3 {
		return reviewBranchNumstat{}, false
	}
	return reviewBranchNumstat{
		Additions: strings.TrimSpace(parts[0]),
		Deletions: strings.TrimSpace(parts[1]),
		Path:      strings.TrimSpace(parts[2]),
	}, true
}

func reviewBranchFileMatchKeys(path string) []string {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}

	keys := []string{path}
	if before, after, ok := strings.Cut(path, " -> "); ok {
		before = strings.TrimSpace(before)
		after = strings.TrimSpace(after)
		if before != "" {
			keys = append(keys, before)
		}
		if after != "" && after != before {
			keys = append(keys, after)
		}
	}
	return keys
}

func applyReviewBranchNumstat(file *reviewBranchFile, stat reviewBranchNumstat) {
	if file == nil {
		return
	}
	file.Additions = stat.Additions
	file.Deletions = stat.Deletions
	if strings.TrimSpace(file.Path) == "" {
		file.Path = stat.Path
	}
}

func splitNonEmptyLines(content string) []string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func shouldInlineReviewDiff(files []reviewBranchFile, numstatOutput string) bool {
	if len(files) == 0 || len(files) > reviewLoopInlineDiffMaxFiles {
		return false
	}

	totalChangedLines := 0
	for _, line := range splitNonEmptyLines(numstatOutput) {
		stat, ok := parseReviewBranchNumstat(line)
		if !ok {
			return false
		}
		if stat.Additions == "-" || stat.Deletions == "-" {
			return false
		}
		if n, err := strconv.Atoi(stat.Additions); err == nil {
			totalChangedLines += n
		}
		if n, err := strconv.Atoi(stat.Deletions); err == nil {
			totalChangedLines += n
		}
	}

	return totalChangedLines <= reviewLoopInlineDiffMaxChanges
}

func buildReviewLoopPrompt(ctx reviewBranchContext) string {
	var sb strings.Builder

	if preamble := reviewLoopSkillPreamble(); preamble != "" {
		sb.WriteString(preamble)
		sb.WriteString("\n\n")
	}

	sb.WriteString("You are a strict static analyzer. Evaluate the current branch changes against the base branch and return machine-readable findings.\n\n")
	sb.WriteString("Start from the branch review context below, then inspect only the directly related repository files and targeted diffs before finalizing findings.\n\n")
	sb.WriteString(fmt.Sprintf("Base branch: %s\n", ctx.BaseBranch))
	sb.WriteString(fmt.Sprintf("Current branch: %s\n", ctx.CurrentBranch))
	sb.WriteString(fmt.Sprintf("Merge base: %s\n\n", ctx.MergeBase))

	if strings.TrimSpace(ctx.DiffShortStat) != "" {
		sb.WriteString("Diff summary:\n")
		sb.WriteString(ctx.DiffShortStat)
		sb.WriteString("\n\n")
	}

	sb.WriteString("Changed files:\n")
	writeReviewLoopChangedFiles(&sb, ctx.ChangedFiles)
	sb.WriteString("\n")

	if len(ctx.Commits) > 0 {
		sb.WriteString("Recent commits since merge-base:\n")
		writeReviewLoopCommits(&sb, ctx.Commits)
		sb.WriteString("\n")
	}

	if inlineDiff := strings.TrimSpace(ctx.InlineDiff); inlineDiff != "" {
		sb.WriteString("Inline diff preview:\n```diff\n")
		sb.WriteString(truncateReviewDiff(inlineDiff, reviewLoopInlineDiffMaxLen))
		sb.WriteString("\n```\n\n")
	} else {
		sb.WriteString("Inline diff preview omitted because the change set is large or not a good fit for prompt embedding.\n")
		sb.WriteString("Fetch targeted diffs as needed with `git diff ")
		sb.WriteString(ctx.MergeBase)
		sb.WriteString(" -- <path>`.\n\n")
	}

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
- Start from the changed files, diff summary, and recent commits above.
- If an inline diff preview is present, use it as a starting point only; do not assume it is exhaustive.
- When you need patch detail, fetch targeted diffs with git diff <merge-base> -- <path>.
- Avoid running git diff <merge-base> for the entire repo unless the changed file list is very small and you still need it.
- Use repository tools and shell commands to inspect code and validate findings.
- Keep analysis diff-driven: start with changed files, then inspect only directly related code paths as needed.
- Hard limit for this step: at most 8 total tool/command calls.
- Do not run hal commands or go run . commands.
- Avoid broad or expensive commands (for example: avoid full-repo sweeps and go test ./...).
- If tests are needed, run at most one focused test command for a specific package/file.
- In this review step, do not edit or write files.
- After gathering enough evidence (or hitting the tool limit), return final JSON immediately and stop exploring.
- Include every detected issue in the issues array.
- If there are no issues, return "issues": [] and explain that in summary.
`)

	return sb.String()
}

func writeReviewLoopChangedFiles(sb *strings.Builder, files []reviewBranchFile) {
	if len(files) == 0 {
		sb.WriteString("- (no changed files reported)\n")
		return
	}

	limit := len(files)
	if limit > reviewLoopPromptMaxFiles {
		limit = reviewLoopPromptMaxFiles
	}

	for _, file := range files[:limit] {
		sb.WriteString("- ")
		if file.Status != "" {
			sb.WriteString(file.Status)
			sb.WriteString(" ")
		}
		path := strings.TrimSpace(file.Path)
		if path == "" {
			path = "(unknown path)"
		}
		sb.WriteString(path)

		switch {
		case file.Additions == "-" || file.Deletions == "-":
			sb.WriteString(" (binary)")
		case file.Additions != "" || file.Deletions != "":
			sb.WriteString(" (+")
			sb.WriteString(zeroIfEmpty(file.Additions))
			sb.WriteString(" -")
			sb.WriteString(zeroIfEmpty(file.Deletions))
			sb.WriteString(")")
		}
		sb.WriteString("\n")
	}

	if len(files) > limit {
		sb.WriteString(fmt.Sprintf("- ... %d more files omitted\n", len(files)-limit))
	}
}

func writeReviewLoopCommits(sb *strings.Builder, commits []string) {
	limit := len(commits)
	if limit > reviewLoopPromptMaxCommits {
		limit = reviewLoopPromptMaxCommits
	}
	for _, commit := range commits[:limit] {
		sb.WriteString("- ")
		sb.WriteString(commit)
		sb.WriteString("\n")
	}
	if len(commits) > limit {
		sb.WriteString(fmt.Sprintf("- ... %d more commits omitted\n", len(commits)-limit))
	}
}

func zeroIfEmpty(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "0"
	}
	return value
}

func buildReviewLoopFixPrompt(baseBranch, currentBranch string, issues []reviewLoopIssue) (string, error) {
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
- Use repository tools and shell commands as needed to validate or reproduce each issue.
- Keep validation targeted to files/functions tied to each issue.
- Hard limit for this step: at most 12 total tool/command calls.
- Do not run hal commands or go run . commands.
- Avoid broad or expensive commands (for example: avoid go test ./...).
- Apply code changes only for valid issues.
- Invalid issues must not be fixed.
- After applying fixes, run at most one focused check relevant to changed files/packages.
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
- After all issues are decided/fixed, return final JSON immediately and stop exploring.
`)

	return sb.String(), nil
}

func truncateReviewDiff(diff string, maxLen int) string {
	if len(diff) <= maxLen {
		return diff
	}
	return truncateUTF8(diff, maxLen) + "\n... (truncated)"
}

func truncateUTF8(content string, maxLen int) string {
	if maxLen <= 0 || content == "" {
		return ""
	}
	if len(content) <= maxLen {
		return content
	}

	truncated := content[:maxLen]
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}

func parseReviewLoopResponse(response string) (*reviewLoopResponse, error) {
	jsonStr, err := extractJSONObject(response)
	if err != nil {
		return nil, err
	}

	jsonBytes := []byte(jsonStr)
	if err := validateTopLevelJSONFields(jsonBytes, "summary", "issues"); err != nil {
		return nil, err
	}

	var parsed reviewLoopResponse
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	seenIDs := make(map[string]struct{}, len(parsed.Issues))
	for i, issue := range parsed.Issues {
		if err := validateReviewLoopIssue(i, issue); err != nil {
			return nil, err
		}

		id := strings.TrimSpace(issue.ID)
		parsed.Issues[i].ID = id
		if _, exists := seenIDs[id]; exists {
			return nil, fmt.Errorf("duplicate review issue id %q", id)
		}
		seenIDs[id] = struct{}{}
	}

	return &parsed, nil
}

func parseReviewLoopFixResponse(response string, reviewedIssues []reviewLoopIssue) (*reviewLoopFixOutcome, error) {
	if len(reviewedIssues) == 0 {
		return &reviewLoopFixOutcome{}, nil
	}

	jsonStr, err := extractJSONObject(response)
	if err != nil {
		return nil, err
	}

	jsonBytes := []byte(jsonStr)
	if err := validateTopLevelJSONFields(jsonBytes, "summary", "issues"); err != nil {
		return nil, err
	}

	var parsed reviewLoopFixResponse
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	reviewedByID := make(map[string]struct{}, len(reviewedIssues))
	for _, issue := range reviewedIssues {
		reviewedByID[strings.TrimSpace(issue.ID)] = struct{}{}
	}

	fixByID := make(map[string]reviewLoopFixIssue, len(parsed.Issues))
	for i, issue := range parsed.Issues {
		if err := validateReviewLoopFixIssue(i, issue); err != nil {
			return nil, err
		}

		id := strings.TrimSpace(issue.ID)
		parsed.Issues[i].ID = id
		issue.ID = id
		if _, ok := reviewedByID[id]; !ok {
			return nil, fmt.Errorf("issue[%d] references unknown review issue id %q", i, issue.ID)
		}
		if _, exists := fixByID[id]; exists {
			return nil, fmt.Errorf("duplicate fix result for issue id %q", issue.ID)
		}
		fixByID[id] = issue
	}

	var missingIDs []string
	for _, reviewed := range reviewedIssues {
		id := strings.TrimSpace(reviewed.ID)
		if _, ok := fixByID[id]; !ok {
			missingIDs = append(missingIDs, id)
		}
	}
	if len(missingIDs) > 0 {
		sort.Strings(missingIDs)
		return nil, fmt.Errorf("missing fix result for review issue ids: %s", strings.Join(missingIDs, ", "))
	}

	outcome := &reviewLoopFixOutcome{
		Summary:  strings.TrimSpace(parsed.Summary),
		PerIssue: make([]reviewLoopFixResult, 0, len(reviewedIssues)),
	}
	for _, reviewed := range reviewedIssues {
		fixIssue := fixByID[strings.TrimSpace(reviewed.ID)]
		valid := fixIssue.Valid != nil && *fixIssue.Valid
		fixed := valid && fixIssue.Fixed != nil && *fixIssue.Fixed

		if valid {
			outcome.ValidIssues++
			if fixed {
				outcome.FixesApplied++
			}
		} else {
			outcome.InvalidIssues++
		}

		outcome.PerIssue = append(outcome.PerIssue, reviewLoopFixResult{
			ID:     strings.TrimSpace(reviewed.ID),
			Valid:  valid,
			Fixed:  fixed,
			Reason: strings.TrimSpace(fixIssue.Reason),
		})
	}

	return outcome, nil
}

func validateTopLevelJSONFields(jsonBytes []byte, fields ...string) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(jsonBytes, &top); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	for _, field := range fields {
		value, ok := top[field]
		if !ok {
			return fmt.Errorf("missing required top-level field: %s", field)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("top-level field %q must not be null", field)
		}
	}

	return nil
}

func isIncompleteReviewOutput(response string, parseErr error) bool {
	if parseErr == nil {
		return false
	}

	trimmed := strings.TrimSpace(response)
	if trimmed == "" {
		return errors.Is(parseErr, errNoJSONObject)
	}

	if isUnexpectedEndOfJSONError(parseErr) {
		return true
	}

	if errors.Is(parseErr, errNoJSONObject) {
		return strings.Contains(trimmed, "{") && !strings.Contains(trimmed, "}")
	}

	return false
}

func isUnexpectedEndOfJSONError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) && strings.Contains(strings.ToLower(syntaxErr.Error()), "unexpected end of json input") {
		return true
	}

	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "unexpected end of json input") || strings.Contains(errMsg, "unexpected eof")
}

func extractJSONObject(response string) (string, error) {
	response = strings.TrimSpace(response)

	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	if jsonStart == -1 || jsonEnd == -1 || jsonEnd < jsonStart {
		return "", errNoJSONObject
	}

	return response[jsonStart : jsonEnd+1], nil
}

func validateReviewLoopIssue(index int, issue reviewLoopIssue) error {
	if strings.TrimSpace(issue.ID) == "" {
		return fmt.Errorf("issue[%d] missing required field: id", index)
	}
	if strings.TrimSpace(issue.Title) == "" {
		return fmt.Errorf("issue[%d] missing required field: title", index)
	}
	severity := strings.TrimSpace(issue.Severity)
	if severity == "" {
		return fmt.Errorf("issue[%d] missing required field: severity", index)
	}
	switch severity {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("issue[%d] severity must be one of low, medium, high, critical", index)
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

func validateReviewLoopFixIssue(index int, issue reviewLoopFixIssue) error {
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
	if issue.Valid != nil && issue.Fixed != nil && !*issue.Valid && *issue.Fixed {
		return fmt.Errorf("issue[%d] fixed must be false when valid is false", index)
	}

	return nil
}
