package ci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	statusPageSize = 100

	defaultWaitPollInterval = 30 * time.Second
	defaultWaitTimeout      = 30 * time.Minute
	defaultNoChecksGrace    = 90 * time.Second
	defaultGitHubAPITimeout = 30 * time.Second
)

var ghHTTPStatusCodePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\(http\s+(\d{3})\)`),
	regexp.MustCompile(`(?i)\bhttp(?:\s+status)?(?:\s+code)?\s*[:=]?\s*(\d{3})\b`),
	regexp.MustCompile(`(?i)\bstatus\s+code\s*[:=]?\s*(\d{3})\b`),
}

var githubAPITokenHTTPClient = &http.Client{
	Timeout: defaultGitHubAPITimeout,
}

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
	if ctx == nil {
		ctx = context.Background()
	}

	client, err := SelectGitHubClient(ctx)
	if err != nil {
		return StatusResult{}, err
	}
	return getStatusWithClient(ctx, client)
}

// GetStatusInDir aggregates CI state from the repository rooted at dir.
func GetStatusInDir(ctx context.Context, dir string) (StatusResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	client, err := SelectGitHubClient(ctx)
	if err != nil {
		return StatusResult{}, err
	}
	return getStatusInDirWithClient(ctx, dir, client)
}

// WaitForChecks polls status until checks complete, timeout, or no checks are detected.
func WaitForChecks(ctx context.Context, opts WaitOptions) (StatusResult, error) {
	return waitForChecksWithDeps(ctx, opts, waitForChecksDeps{})
}

// WaitForChecksInDir polls status in the repository rooted at dir until checks complete,
// timeout, or no checks are detected.
func WaitForChecksInDir(ctx context.Context, dir string, opts WaitOptions) (StatusResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	client, err := SelectGitHubClient(ctx)
	if err != nil {
		return StatusResult{}, err
	}

	return waitForChecksWithDeps(ctx, opts, waitForChecksDeps{
		getStatus: func(callCtx context.Context) (StatusResult, error) {
			return getStatusInDirWithClient(callCtx, dir, client)
		},
	})
}

func getStatusWithClient(ctx context.Context, client ClientSelection) (StatusResult, error) {
	return getStatusWithDeps(ctx, statusDeps{
		findPRHeadSHA: func(callCtx context.Context, repo GitHubRepository, branch string) (string, error) {
			return findPRHeadSHAWithClient(callCtx, client, repo, branch)
		},
		listCheckRunsPage: func(callCtx context.Context, repo GitHubRepository, sha string, page int, perPage int) ([]checkRunData, error) {
			return listCheckRunsPageWithClient(callCtx, client, repo, sha, page, perPage)
		},
		listCommitStatusesPage: func(callCtx context.Context, repo GitHubRepository, sha string, page int, perPage int) ([]commitStatusData, error) {
			return listCommitStatusesPageWithClient(callCtx, client, repo, sha, page, perPage)
		},
	})
}

func getStatusInDirWithClient(ctx context.Context, dir string, client ClientSelection) (StatusResult, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return getStatusWithClient(ctx, client)
	}

	return getStatusWithDeps(ctx, statusDeps{
		resolveRepo: func(callCtx context.Context) (GitHubRepository, error) {
			return ResolveGitHubRepositoryInDir(callCtx, dir)
		},
		currentBranch: func(callCtx context.Context) (string, error) {
			return gitCurrentBranchInDir(callCtx, dir)
		},
		currentHeadSHA: func(callCtx context.Context) (string, error) {
			return gitCurrentHEADSHAInDir(callCtx, dir)
		},
		findPRHeadSHA: func(callCtx context.Context, repo GitHubRepository, branch string) (string, error) {
			return findPRHeadSHAWithClient(callCtx, client, repo, branch)
		},
		listCheckRunsPage: func(callCtx context.Context, repo GitHubRepository, sha string, page int, perPage int) ([]checkRunData, error) {
			return listCheckRunsPageWithClient(callCtx, client, repo, sha, page, perPage)
		},
		listCommitStatusesPage: func(callCtx context.Context, repo GitHubRepository, sha string, page int, perPage int) ([]commitStatusData, error) {
			return listCommitStatusesPageWithClient(callCtx, client, repo, sha, page, perPage)
		},
	})
}

func waitForChecksWithDeps(ctx context.Context, opts WaitOptions, deps waitForChecksDeps) (StatusResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = waitOptionsWithDefaults(opts)

	if deps.getStatus == nil {
		client, err := SelectGitHubClient(ctx)
		if err != nil {
			return StatusResult{}, err
		}
		deps.getStatus = func(callCtx context.Context) (StatusResult, error) {
			return getStatusWithClient(callCtx, client)
		}
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
	return gitCurrentHEADSHAInDir(ctx, "")
}

func gitCurrentHEADSHAInDir(ctx context.Context, dir string) (string, error) {
	sha, err := runGitInDir(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("get HEAD sha: %w", err)
	}
	if sha == "" {
		return "", fmt.Errorf("get HEAD sha: empty sha")
	}
	return sha, nil
}

func runGit(ctx context.Context, args ...string) (string, error) {
	return runGitInDir(ctx, "", args...)
}

func runGitInDir(ctx context.Context, dir string, args ...string) (string, error) {
	out, err := runGitRawInDir(ctx, dir, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func runGitRaw(ctx context.Context, args ...string) (string, error) {
	return runGitRawInDir(ctx, "", args...)
}

func runGitRawInDir(ctx context.Context, dir string, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}
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

	return strings.TrimRight(stdout.String(), "\r\n"), nil
}

type ghPullRequest struct {
	Head struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

func findPRHeadSHA(ctx context.Context, repo GitHubRepository, branch string) (string, error) {
	client, err := SelectGitHubClient(ctx)
	if err != nil {
		return "", err
	}
	return findPRHeadSHAWithClient(ctx, client, repo, branch)
}

func findPRHeadSHAWithClient(ctx context.Context, client ClientSelection, repo GitHubRepository, branch string) (string, error) {
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
	if err := ghAPIWithClient(ctx, client, githubAPIRequest{Method: http.MethodGet, Endpoint: endpoint}, &pulls); err != nil {
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
	client, err := SelectGitHubClient(ctx)
	if err != nil {
		return nil, err
	}
	return listCheckRunsPageWithClient(ctx, client, repo, sha, page, perPage)
}

func listCheckRunsPageWithClient(ctx context.Context, client ClientSelection, repo GitHubRepository, sha string, page int, perPage int) ([]checkRunData, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/commits/%s/check-runs?per_page=%d&page=%d", repo.Owner, repo.Name, sha, perPage, page)
	response := ghCheckRunsResponse{}
	if err := ghAPIWithClient(ctx, client, githubAPIRequest{Method: http.MethodGet, Endpoint: endpoint}, &response); err != nil {
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
	client, err := SelectGitHubClient(ctx)
	if err != nil {
		return nil, err
	}
	return listCommitStatusesPageWithClient(ctx, client, repo, sha, page, perPage)
}

func listCommitStatusesPageWithClient(ctx context.Context, client ClientSelection, repo GitHubRepository, sha string, page int, perPage int) ([]commitStatusData, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/commits/%s/statuses?per_page=%d&page=%d", repo.Owner, repo.Name, sha, perPage, page)
	response := make([]ghCommitStatus, 0)
	if err := ghAPIWithClient(ctx, client, githubAPIRequest{Method: http.MethodGet, Endpoint: endpoint}, &response); err != nil {
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
	client, err := SelectGitHubClient(ctx)
	if err != nil {
		return err
	}
	return ghAPIWithClient(ctx, client, githubAPIRequest{Method: http.MethodGet, Endpoint: endpoint}, out)
}

type githubAPIRequest struct {
	Method   string
	Endpoint string
	Body     any
}

type githubAPIHTTPError struct {
	Method     string
	Endpoint   string
	StatusCode int
	Body       string
}

func (e *githubAPIHTTPError) Error() string {
	if e == nil {
		return "github api request failed"
	}
	if e.Body != "" {
		return fmt.Sprintf("github api %s %s failed: HTTP %d: %s", e.Method, e.Endpoint, e.StatusCode, e.Body)
	}
	return fmt.Sprintf("github api %s %s failed: HTTP %d", e.Method, e.Endpoint, e.StatusCode)
}

func isGitHubAPIHTTPStatus(err error, statusCode int) bool {
	var apiErr *githubAPIHTTPError
	return errors.As(err, &apiErr) && apiErr.StatusCode == statusCode
}

func ghAPIWithClient(ctx context.Context, client ClientSelection, req githubAPIRequest, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	endpoint := strings.TrimSpace(req.Endpoint)
	if endpoint == "" {
		return fmt.Errorf("github api endpoint must not be empty")
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	req.Method = method
	req.Endpoint = endpoint

	switch client.Kind {
	case ClientKindAPI:
		token := strings.TrimSpace(client.Token)
		if token == "" {
			return ErrInvalidEnvToken
		}
		return ghAPIWithToken(ctx, req, token, out)
	case ClientKindGH:
		return ghAPIWithGH(ctx, req, out)
	default:
		return fmt.Errorf("unsupported GitHub client kind %q", client.Kind)
	}
}

func ghAPIWithToken(ctx context.Context, req githubAPIRequest, token string, out any) error {
	var reqBody io.Reader
	if req.Body != nil {
		payload, err := json.Marshal(req.Body)
		if err != nil {
			return fmt.Errorf("encode github api request body for %s %s: %w", req.Method, req.Endpoint, err)
		}
		reqBody = bytes.NewReader(payload)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, "https://api.github.com"+req.Endpoint, reqBody)
	if err != nil {
		return fmt.Errorf("build github api request %s %s: %w", req.Method, req.Endpoint, err)
	}
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if req.Body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := githubAPITokenHTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("github api %s %s failed: %w", req.Method, req.Endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read github api response for %s %s: %w", req.Method, req.Endpoint, err)
	}
	body = bytes.TrimSpace(body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &githubAPIHTTPError{
			Method:     req.Method,
			Endpoint:   req.Endpoint,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(body)),
		}
	}

	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode github api response for %s %s: %w", req.Method, req.Endpoint, err)
	}
	return nil
}

func ghAPIWithGH(ctx context.Context, req githubAPIRequest, out any) error {
	args := []string{"api", "-H", "Accept: application/vnd.github+json"}
	if req.Method != http.MethodGet {
		args = append(args, "-X", req.Method)
	}

	var stdin *bytes.Reader
	if req.Body != nil {
		payload, err := json.Marshal(req.Body)
		if err != nil {
			return fmt.Errorf("encode gh api request body for %s %s: %w", req.Method, req.Endpoint, err)
		}
		stdin = bytes.NewReader(payload)
		args = append(args, "-H", "Content-Type: application/json", "--input", "-")
	}
	args = append(args, req.Endpoint)

	cmd := exec.CommandContext(ctx, "gh", args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if apiErr := ghAPIHTTPErrorFromStderr(req, stderrText); apiErr != nil {
			return apiErr
		}
		if stderrText != "" {
			return fmt.Errorf("gh api %s %s failed: %s: %w", req.Method, req.Endpoint, stderrText, err)
		}
		return fmt.Errorf("gh api %s %s failed: %w", req.Method, req.Endpoint, err)
	}

	if out == nil {
		return nil
	}
	body := bytes.TrimSpace(stdout.Bytes())
	if len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode gh api response for %s %s: %w", req.Method, req.Endpoint, err)
	}
	return nil
}

func ghAPIHTTPErrorFromStderr(req githubAPIRequest, stderrText string) *githubAPIHTTPError {
	statusCode, ok := parseHTTPStatusCode(stderrText)
	if !ok {
		return nil
	}
	return &githubAPIHTTPError{
		Method:     req.Method,
		Endpoint:   req.Endpoint,
		StatusCode: statusCode,
		Body:       strings.TrimSpace(stderrText),
	}
}

func parseHTTPStatusCode(text string) (int, bool) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0, false
	}

	for _, pattern := range ghHTTPStatusCodePatterns {
		matches := pattern.FindStringSubmatch(trimmed)
		if len(matches) != 2 {
			continue
		}
		code, err := strconv.Atoi(matches[1])
		if err != nil {
			continue
		}
		if code >= 100 && code <= 599 {
			return code, true
		}
	}

	return 0, false
}
