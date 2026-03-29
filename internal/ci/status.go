package ci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	statusPageSize = 100

	defaultWaitPollInterval = 30 * time.Second
	defaultWaitTimeout      = 30 * time.Minute
	defaultNoChecksGrace    = 90 * time.Second
)

// WaitOptions configures WaitForChecks polling behavior.
type WaitOptions struct {
	PollInterval  time.Duration
	Timeout       time.Duration
	NoChecksGrace time.Duration
}

type waitForChecksDeps struct {
	getStatus func(context.Context) (StatusResult, error)
	newTicker func(time.Duration) waitTicker
	after     func(time.Duration) <-chan time.Time
}

type waitTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type realWaitTicker struct {
	ticker *time.Ticker
}

func newRealWaitTicker(d time.Duration) waitTicker {
	return realWaitTicker{ticker: time.NewTicker(d)}
}

func (t realWaitTicker) Chan() <-chan time.Time {
	return t.ticker.C
}

func (t realWaitTicker) Stop() {
	t.ticker.Stop()
}

type statusDeps struct {
	resolveRepo            func(context.Context) (GitHubRepository, error)
	currentBranch          func(context.Context) (string, error)
	currentHeadSHA         func(context.Context) (string, error)
	findPRHeadSHA          func(context.Context, GitHubRepository, string) (string, error)
	listCheckRunsPage      func(context.Context, GitHubRepository, string, int, int) ([]checkRunData, error)
	listCommitStatusesPage func(context.Context, GitHubRepository, string, int, int) ([]commitStatusData, error)
}

type checkRunData struct {
	Name       string
	Status     string
	Conclusion string
	URL        string
}

type commitStatusData struct {
	Context string
	State   string
	URL     string
}

// GetStatus aggregates CI state from both GitHub check-runs and commit statuses.
func GetStatus(ctx context.Context) (StatusResult, error) {
	return getStatusWithDeps(ctx, statusDeps{})
}

// WaitForChecks polls status until checks complete, timeout, or no checks are detected.
func WaitForChecks(ctx context.Context, opts WaitOptions) (StatusResult, error) {
	return waitForChecksWithDeps(ctx, opts, waitForChecksDeps{})
}

func waitForChecksWithDeps(ctx context.Context, opts WaitOptions, deps waitForChecksDeps) (StatusResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = waitOptionsWithDefaults(opts)

	if deps.getStatus == nil {
		deps.getStatus = GetStatus
	}
	if deps.newTicker == nil {
		deps.newTicker = newRealWaitTicker
	}
	if deps.after == nil {
		deps.after = time.After
	}

	ticker := deps.newTicker(opts.PollInterval)
	defer ticker.Stop()

	timeoutCh := deps.after(opts.Timeout)
	noChecksCh := deps.after(opts.NoChecksGrace)

	for {
		result, err := deps.getStatus(ctx)
		if err != nil {
			return StatusResult{}, err
		}
		result.Wait = true

		if result.Status != StatusPending {
			result.WaitTerminalReason = WaitTerminalReasonCompleted
			return result, nil
		}

		if result.ChecksDiscovered {
			noChecksCh = nil
		}

		select {
		case <-ctx.Done():
			return StatusResult{}, ctx.Err()
		case <-timeoutCh:
			result.WaitTerminalReason = WaitTerminalReasonTimeout
			return result, nil
		case <-noChecksCh:
			confirm, err := deps.getStatus(ctx)
			if err != nil {
				return StatusResult{}, err
			}
			confirm.Wait = true
			if confirm.Status != StatusPending {
				confirm.WaitTerminalReason = WaitTerminalReasonCompleted
				return confirm, nil
			}
			if confirm.ChecksDiscovered {
				noChecksCh = nil
				continue
			}
			confirm.WaitTerminalReason = WaitTerminalReasonNoChecksDetected
			return confirm, nil
		case <-ticker.Chan():
		}
	}
}

func waitOptionsWithDefaults(opts WaitOptions) WaitOptions {
	if opts.PollInterval <= 0 {
		opts.PollInterval = defaultWaitPollInterval
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultWaitTimeout
	}
	if opts.NoChecksGrace <= 0 {
		opts.NoChecksGrace = defaultNoChecksGrace
	}
	return opts
}

func getStatusWithDeps(ctx context.Context, deps statusDeps) (StatusResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if deps.resolveRepo == nil {
		deps.resolveRepo = ResolveGitHubRepository
	}
	if deps.currentBranch == nil {
		deps.currentBranch = gitCurrentBranch
	}
	if deps.currentHeadSHA == nil {
		deps.currentHeadSHA = gitCurrentHEADSHA
	}
	if deps.findPRHeadSHA == nil {
		deps.findPRHeadSHA = findPRHeadSHA
	}
	if deps.listCheckRunsPage == nil {
		deps.listCheckRunsPage = listCheckRunsPage
	}
	if deps.listCommitStatusesPage == nil {
		deps.listCommitStatusesPage = listCommitStatusesPage
	}

	repo, err := deps.resolveRepo(ctx)
	if err != nil {
		return StatusResult{}, err
	}

	branch, err := deps.currentBranch(ctx)
	if err != nil {
		return StatusResult{}, err
	}

	sha, err := resolveStatusSHA(ctx, deps, repo, branch)
	if err != nil {
		return StatusResult{}, err
	}

	checks, err := aggregateStatusChecks(ctx, deps, repo, sha)
	if err != nil {
		return StatusResult{}, err
	}

	totals, status := summarizeAggregatedChecks(checks)
	checksDiscovered := len(checks) > 0
	if !checksDiscovered {
		status = StatusPending
	}

	return StatusResult{
		ContractVersion:  StatusContractVersion,
		Branch:           branch,
		SHA:              sha,
		Status:           status,
		ChecksDiscovered: checksDiscovered,
		Wait:             false,
		Checks:           checks,
		Totals:           totals,
		Summary:          statusSummary(status, totals, checksDiscovered),
	}, nil
}

func resolveStatusSHA(ctx context.Context, deps statusDeps, repo GitHubRepository, branch string) (string, error) {
	prHeadSHA, err := deps.findPRHeadSHA(ctx, repo, branch)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(prHeadSHA) != "" {
		return strings.TrimSpace(prHeadSHA), nil
	}

	sha, err := deps.currentHeadSHA(ctx)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(sha), nil
}

func aggregateStatusChecks(ctx context.Context, deps statusDeps, repo GitHubRepository, sha string) ([]StatusCheck, error) {
	checkRuns, err := listAllCheckRuns(ctx, deps, repo, sha)
	if err != nil {
		return nil, err
	}
	commitStatuses, err := listAllCommitStatuses(ctx, deps, repo, sha)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	checks := make([]StatusCheck, 0, len(checkRuns)+len(commitStatuses))

	for _, run := range checkRuns {
		key := checkContextKey(run.Name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		checks = append(checks, StatusCheck{
			Key:    key,
			Source: CheckSourceCheckRun,
			Name:   run.Name,
			Status: mapCheckRunStatus(run.Status, run.Conclusion),
			URL:    strings.TrimSpace(run.URL),
		})
	}

	for _, status := range commitStatuses {
		key := statusContextKey(status.Context)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		checks = append(checks, StatusCheck{
			Key:    key,
			Source: CheckSourceStatus,
			Name:   status.Context,
			Status: mapCommitStatusState(status.State),
			URL:    strings.TrimSpace(status.URL),
		})
	}

	sort.Slice(checks, func(i, j int) bool {
		return checks[i].Key < checks[j].Key
	})

	return checks, nil
}

func listAllCheckRuns(ctx context.Context, deps statusDeps, repo GitHubRepository, sha string) ([]checkRunData, error) {
	all := make([]checkRunData, 0)
	for page := 1; ; page++ {
		pageRuns, err := deps.listCheckRunsPage(ctx, repo, sha, page, statusPageSize)
		if err != nil {
			return nil, fmt.Errorf("list check-runs page %d: %w", page, err)
		}
		all = append(all, pageRuns...)
		if len(pageRuns) < statusPageSize {
			break
		}
	}
	return all, nil
}

func listAllCommitStatuses(ctx context.Context, deps statusDeps, repo GitHubRepository, sha string) ([]commitStatusData, error) {
	all := make([]commitStatusData, 0)
	for page := 1; ; page++ {
		pageStatuses, err := deps.listCommitStatusesPage(ctx, repo, sha, page, statusPageSize)
		if err != nil {
			return nil, fmt.Errorf("list commit statuses page %d: %w", page, err)
		}
		all = append(all, pageStatuses...)
		if len(pageStatuses) < statusPageSize {
			break
		}
	}
	return all, nil
}

func summarizeAggregatedChecks(checks []StatusCheck) (StatusTotals, string) {
	totals := StatusTotals{}
	for _, check := range checks {
		switch check.Status {
		case StatusPassing:
			totals.Passing++
		case StatusFailing:
			totals.Failing++
		case StatusPending:
			totals.Pending++
		default:
			// Treat unknown check states as pending for safety.
			totals.Pending++
		}
	}

	if totals.Pending > 0 {
		return totals, StatusPending
	}
	if totals.Failing > 0 {
		return totals, StatusFailing
	}
	if totals.Passing > 0 {
		return totals, StatusPassing
	}
	return totals, StatusPending
}

func statusSummary(status string, totals StatusTotals, checksDiscovered bool) string {
	if !checksDiscovered {
		return "no CI contexts discovered; status pending"
	}
	return fmt.Sprintf("status=%s (passing=%d, failing=%d, pending=%d)", status, totals.Passing, totals.Failing, totals.Pending)
}

func checkContextKey(name string) string {
	return "check:" + strings.TrimSpace(name)
}

func statusContextKey(contextName string) string {
	return "status:" + strings.TrimSpace(contextName)
}

func mapCheckRunStatus(runStatus string, conclusion string) string {
	runStatus = strings.ToLower(strings.TrimSpace(runStatus))
	conclusion = strings.ToLower(strings.TrimSpace(conclusion))

	switch runStatus {
	case "queued", "in_progress":
		return StatusPending
	case "completed":
		switch conclusion {
		case "failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale":
			return StatusFailing
		case "success", "neutral", "skipped":
			return StatusPassing
		default:
			return StatusPending
		}
	default:
		return StatusPending
	}
}

func mapCommitStatusState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "success":
		return StatusPassing
	case "failure", "error":
		return StatusFailing
	case "pending":
		return StatusPending
	default:
		return StatusPending
	}
}

func gitCurrentBranch(ctx context.Context) (string, error) {
	branch, err := runGit(ctx, "branch", "--show-current")
	if err != nil {
		return "", fmt.Errorf("get current branch: %w", err)
	}
	if branch == "" {
		return "", fmt.Errorf("get current branch: empty branch name")
	}
	return branch, nil
}

func gitCurrentHEADSHA(ctx context.Context) (string, error) {
	sha, err := runGit(ctx, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("get HEAD sha: %w", err)
	}
	if sha == "" {
		return "", fmt.Errorf("get HEAD sha: empty sha")
	}
	return sha, nil
}

func runGit(ctx context.Context, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if stderrText != "" {
			return "", fmt.Errorf("git %s failed: %s: %w", strings.Join(args, " "), stderrText, err)
		}
		return "", fmt.Errorf("git %s failed: %w", strings.Join(args, " "), err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

type ghPullRequest struct {
	Head struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

func findPRHeadSHA(ctx context.Context, repo GitHubRepository, branch string) (string, error) {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return "", nil
	}

	query := url.Values{}
	query.Set("state", "open")
	query.Set("head", repo.Owner+":"+branch)
	query.Set("per_page", "1")
	query.Set("page", "1")

	endpoint := fmt.Sprintf("/repos/%s/%s/pulls?%s", repo.Owner, repo.Name, query.Encode())
	var pulls []ghPullRequest
	if err := ghAPI(ctx, endpoint, &pulls); err != nil {
		return "", fmt.Errorf("find pull request for branch %q: %w", branch, err)
	}
	if len(pulls) == 0 {
		return "", nil
	}
	return strings.TrimSpace(pulls[0].Head.SHA), nil
}

type ghCheckRunsResponse struct {
	CheckRuns []ghCheckRun `json:"check_runs"`
}

type ghCheckRun struct {
	Name       string  `json:"name"`
	Status     string  `json:"status"`
	Conclusion *string `json:"conclusion"`
	HTMLURL    string  `json:"html_url"`
}

func listCheckRunsPage(ctx context.Context, repo GitHubRepository, sha string, page int, perPage int) ([]checkRunData, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/commits/%s/check-runs?per_page=%d&page=%d", repo.Owner, repo.Name, sha, perPage, page)
	response := ghCheckRunsResponse{}
	if err := ghAPI(ctx, endpoint, &response); err != nil {
		return nil, err
	}

	runs := make([]checkRunData, 0, len(response.CheckRuns))
	for _, run := range response.CheckRuns {
		conclusion := ""
		if run.Conclusion != nil {
			conclusion = *run.Conclusion
		}
		runs = append(runs, checkRunData{
			Name:       strings.TrimSpace(run.Name),
			Status:     strings.TrimSpace(run.Status),
			Conclusion: strings.TrimSpace(conclusion),
			URL:        strings.TrimSpace(run.HTMLURL),
		})
	}
	return runs, nil
}

type ghCommitStatus struct {
	Context   string `json:"context"`
	State     string `json:"state"`
	TargetURL string `json:"target_url"`
}

func listCommitStatusesPage(ctx context.Context, repo GitHubRepository, sha string, page int, perPage int) ([]commitStatusData, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/commits/%s/statuses?per_page=%d&page=%d", repo.Owner, repo.Name, sha, perPage, page)
	response := make([]ghCommitStatus, 0)
	if err := ghAPI(ctx, endpoint, &response); err != nil {
		return nil, err
	}

	statuses := make([]commitStatusData, 0, len(response))
	for _, status := range response {
		statuses = append(statuses, commitStatusData{
			Context: strings.TrimSpace(status.Context),
			State:   strings.TrimSpace(status.State),
			URL:     strings.TrimSpace(status.TargetURL),
		})
	}
	return statuses, nil
}

func ghAPI(ctx context.Context, endpoint string, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}

	cmd := exec.CommandContext(ctx, "gh", "api", "-H", "Accept: application/vnd.github+json", endpoint)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if stderrText != "" {
			return fmt.Errorf("gh api %s failed: %s: %w", endpoint, stderrText, err)
		}
		return fmt.Errorf("gh api %s failed: %w", endpoint, err)
	}

	if err := json.Unmarshal(stdout.Bytes(), out); err != nil {
		return fmt.Errorf("decode gh api response for %s: %w", endpoint, err)
	}
	return nil
}
