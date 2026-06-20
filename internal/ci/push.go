package ci

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const defaultPushTitlePrefix = "hal ci: "

var (
	// ErrAmbiguousOpenPullRequest is returned when a branch maps to multiple open pull requests.
	ErrAmbiguousOpenPullRequest = errors.New("ci ambiguous open pull request selection")
	// ErrOpenPullRequestBaseMismatch is returned when an explicit base does not match existing open pull requests for a branch.
	ErrOpenPullRequestBaseMismatch = errors.New("ci open pull request base mismatch")
)

// FindOpenPullRequestForBranch resolves the open pull request for the given branch.
// Returns (nil, nil) when no open pull request exists.
func FindOpenPullRequestForBranch(ctx context.Context, branch string) (*PullRequest, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	branch = strings.TrimSpace(branch)
	if branch == "" {
		return nil, fmt.Errorf("find open pull request: empty branch name")
	}

	repo, err := ResolveGitHubRepository(ctx)
	if err != nil {
		return nil, err
	}

	pr, err := findOpenPullRequest(ctx, repo, branch)
	if err != nil {
		return nil, fmt.Errorf("find open pull request for branch %q: %w", branch, err)
	}
	return pr, nil
}

// PushOptions configures push and pull-request creation behavior.
type PushOptions struct {
	BaseRef string
	Title   string
	Body    string
	Draft   *bool
}

type createPullRequestOptions struct {
	Repo    GitHubRepository
	BaseRef string
	HeadRef string
	Title   string
	Body    string
	Draft   bool
}

type pushDeps struct {
	currentBranch func(context.Context) (string, error)
	pushBranch    func(context.Context, string) error
	resolveRepo   func(context.Context) (GitHubRepository, error)
	resolveBaseRef func(context.Context, GitHubRepository, string) (string, error)
	findOpenPR    func(context.Context, GitHubRepository, string, string) (*PullRequest, error)
	createPR      func(context.Context, createPullRequestOptions) (string, error)
}

// PushAndCreatePR pushes the current branch and creates or reuses an open pull request.
func PushAndCreatePR(ctx context.Context, opts PushOptions) (PushResult, error) {
	return pushAndCreatePRWithDeps(ctx, opts, pushDeps{})
}

// PushAndCreatePRInDir pushes the current branch and creates or reuses an open pull request
// within the provided repository directory.
func PushAndCreatePRInDir(ctx context.Context, dir string, opts PushOptions) (PushResult, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return PushAndCreatePR(ctx, opts)
	}

	return pushAndCreatePRWithDeps(ctx, opts, pushDeps{
		currentBranch: func(ctx context.Context) (string, error) {
			return gitCurrentBranchInDir(ctx, dir)
		},
		pushBranch: func(ctx context.Context, branch string) error {
			return gitPushBranchInDir(ctx, dir, branch)
		},
		resolveRepo: func(ctx context.Context) (GitHubRepository, error) {
			return ResolveGitHubRepositoryInDir(ctx, dir)
		},
	})
}

func pushAndCreatePRWithDeps(ctx context.Context, opts PushOptions, deps pushDeps) (PushResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if deps.currentBranch == nil {
		deps.currentBranch = gitCurrentBranch
	}
	if deps.pushBranch == nil {
		deps.pushBranch = gitPushBranch
	}
	if deps.resolveRepo == nil {
		deps.resolveRepo = ResolveGitHubRepository
	}
	if deps.resolveBaseRef == nil {
		deps.resolveBaseRef = resolvePullRequestBaseRef
	}
	if deps.findOpenPR == nil {
		deps.findOpenPR = findOpenPullRequestForBase
	}
	if deps.createPR == nil {
		deps.createPR = createPullRequest
	}

	branch, err := deps.currentBranch(ctx)
	if err != nil {
		return PushResult{}, err
	}
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return PushResult{}, fmt.Errorf("get current branch: empty branch name")
	}

	repo, err := deps.resolveRepo(ctx)
	if err != nil {
		return PushResult{}, err
	}

	if err := deps.pushBranch(ctx, branch); err != nil {
		return PushResult{}, err
	}

	requestedBaseRef := strings.TrimSpace(opts.BaseRef)
	existingLookupBaseRef := requestedBaseRef
	existingPR, err := deps.findOpenPR(ctx, repo, branch, existingLookupBaseRef)
	if err != nil {
		return PushResult{}, err
	}
	if existingPR != nil {
		existing := *existingPR
		existing.Existing = true
		if strings.TrimSpace(existing.HeadRef) == "" {
			existing.HeadRef = branch
		}
		return buildPushResult(branch, existing), nil
	}

	baseRef := requestedBaseRef
	if baseRef == "" {
		baseRef, err = deps.resolveBaseRef(ctx, repo, "")
		if err != nil {
			return PushResult{}, err
		}
	}

	createOpts := defaultCreatePullRequestOptions(branch, opts)
	createOpts.Repo = repo
	createOpts.BaseRef = baseRef
	prURL, err := deps.createPR(ctx, createOpts)
	if err != nil {
		return PushResult{}, err
	}

	createdPR, err := deps.findOpenPR(ctx, repo, branch, baseRef)
	if err != nil || createdPR == nil {
		createdPR = &PullRequest{
			URL:     strings.TrimSpace(prURL),
			Title:   createOpts.Title,
			HeadRef: branch,
			BaseRef: createOpts.BaseRef,
			Draft:   createOpts.Draft,
		}
	}

	created := *createdPR
	created.Existing = false
	if strings.TrimSpace(created.URL) == "" {
		created.URL = strings.TrimSpace(prURL)
	}
	if strings.TrimSpace(created.Title) == "" {
		created.Title = createOpts.Title
	}
	if strings.TrimSpace(created.HeadRef) == "" {
		created.HeadRef = branch
	}

	return buildPushResult(branch, created), nil
}

func buildPushResult(branch string, pr PullRequest) PushResult {
	summary := fmt.Sprintf("pushed branch %s and created pull request", branch)
	if pr.Existing {
		summary = fmt.Sprintf("pushed branch %s and reused existing pull request", branch)
	}
	return PushResult{
		ContractVersion: PushContractVersion,
		Branch:          branch,
		Pushed:          true,
		DryRun:          false,
		PullRequest:     pr,
		Summary:         summary,
	}
}

func defaultCreatePullRequestOptions(branch string, opts PushOptions) createPullRequestOptions {
	draft := true
	if opts.Draft != nil {
		draft = *opts.Draft
	}

	title := strings.TrimSpace(opts.Title)
	if title == "" {
		title = defaultPushPRTitle(branch)
	}

	body := opts.Body
	if strings.TrimSpace(body) == "" {
		body = defaultPushPRBody(branch)
	}

	return createPullRequestOptions{
		BaseRef: strings.TrimSpace(opts.BaseRef),
		HeadRef: branch,
		Title:   title,
		Body:    body,
		Draft:   draft,
	}
}

func defaultPushPRTitle(branch string) string {
	return defaultPushTitlePrefix + branch
}

func defaultPushPRBody(branch string) string {
	return fmt.Sprintf("Automated pull request created by `hal ci push` for branch `%s`.", branch)
}

func resolvePullRequestBaseRef(ctx context.Context, repo GitHubRepository, baseRef string) (string, error) {
	baseRef = strings.TrimSpace(baseRef)
	if baseRef != "" {
		return baseRef, nil
	}

	client, err := SelectGitHubClient(ctx)
	if err != nil {
		return "", err
	}

	return defaultBranch(ctx, client, repo)
}

func gitPushBranch(ctx context.Context, branch string) error {
	return gitPushBranchInDir(ctx, "", branch)
}

func gitCurrentBranchInDir(ctx context.Context, dir string) (string, error) {
	branch, err := runGitInDir(ctx, dir, "branch", "--show-current")
	if err != nil {
		return "", fmt.Errorf("get current branch: %w", err)
	}
	if branch == "" {
		return "", fmt.Errorf("get current branch: empty branch name")
	}
	return branch, nil
}

func gitPushBranchInDir(ctx context.Context, dir string, branch string) error {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return fmt.Errorf("push branch: empty branch name")
	}

	if _, err := runGitInDir(ctx, dir, "push", "-u", "origin", branch); err != nil {
		return fmt.Errorf("push branch %q: %w", branch, err)
	}
	return nil
}

type ghOpenPullRequest struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	Title   string `json:"title"`
	Draft   bool   `json:"draft"`
	Head    struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

func findOpenPullRequest(ctx context.Context, repo GitHubRepository, branch string) (*PullRequest, error) {
	return findOpenPullRequestForBase(ctx, repo, branch, "")
}

func findOpenPullRequestForBase(ctx context.Context, repo GitHubRepository, branch, baseRef string) (*PullRequest, error) {
	pulls, err := listOpenPullRequestsForBranch(ctx, repo, branch)
	if err != nil {
		return nil, err
	}
	return selectOpenPullRequest(branch, baseRef, pulls)
}

func listOpenPullRequestsForBranch(ctx context.Context, repo GitHubRepository, branch string) ([]ghOpenPullRequest, error) {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return nil, nil
	}

	query := url.Values{}
	query.Set("state", "open")
	query.Set("head", repo.Owner+":"+branch)
	query.Set("per_page", "100")

	var pulls []ghOpenPullRequest
	for page := 1; ; page++ {
		query.Set("page", strconv.Itoa(page))
		endpoint := fmt.Sprintf("/repos/%s/%s/pulls?%s", repo.Owner, repo.Name, query.Encode())
		var pagePulls []ghOpenPullRequest
		if err := ghAPI(ctx, endpoint, &pagePulls); err != nil {
			return nil, fmt.Errorf("find open pull request for branch %q: %w", branch, err)
		}
		pulls = append(pulls, pagePulls...)
		if len(pagePulls) < 100 {
			break
		}
	}
	return pulls, nil
}

func selectOpenPullRequest(branch, baseRef string, pulls []ghOpenPullRequest) (*PullRequest, error) {
	branch = strings.TrimSpace(branch)
	if branch == "" || len(pulls) == 0 {
		return nil, nil
	}

	baseRef = strings.TrimSpace(baseRef)
	candidates := pulls
	if baseRef != "" {
		filtered := make([]ghOpenPullRequest, 0, len(pulls))
		for _, pull := range pulls {
			if strings.TrimSpace(pull.Base.Ref) == baseRef {
				filtered = append(filtered, pull)
			}
		}
		if len(filtered) == 0 && len(pulls) > 0 {
			if len(pulls) == 1 {
				existingBase := strings.TrimSpace(pulls[0].Base.Ref)
				return nil, fmt.Errorf("%w: branch %q has open pull request with base %q; requested %q", ErrOpenPullRequestBaseMismatch, branch, existingBase, baseRef)
			}
			return nil, fmt.Errorf("%w: branch %q has %d open pull requests but none target base %q", ErrOpenPullRequestBaseMismatch, branch, len(pulls), baseRef)
		}
		candidates = filtered
	}

	if len(candidates) == 0 {
		return nil, nil
	}
	if len(candidates) > 1 {
		if baseRef == "" {
			return nil, fmt.Errorf("%w: branch %q has %d open pull requests", ErrAmbiguousOpenPullRequest, branch, len(candidates))
		}
		return nil, fmt.Errorf("%w: branch %q with base %q has %d open pull requests", ErrAmbiguousOpenPullRequest, branch, baseRef, len(candidates))
	}

	pull := candidates[0]
	pr := PullRequest{
		Number:   pull.Number,
		URL:      strings.TrimSpace(pull.HTMLURL),
		Title:    strings.TrimSpace(pull.Title),
		HeadRef:  strings.TrimSpace(pull.Head.Ref),
		HeadSHA:  strings.TrimSpace(pull.Head.SHA),
		BaseRef:  strings.TrimSpace(pull.Base.Ref),
		Draft:    pull.Draft,
		Existing: true,
	}
	return &pr, nil
}

func createPullRequest(ctx context.Context, opts createPullRequestOptions) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	client, err := SelectGitHubClient(ctx)
	if err != nil {
		return "", err
	}

	baseRef := strings.TrimSpace(opts.BaseRef)
	if baseRef == "" {
		baseRef, err = defaultBranch(ctx, client, opts.Repo)
		if err != nil {
			return "", err
		}
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/pulls", opts.Repo.Owner, opts.Repo.Name)
	request := map[string]any{
		"title": opts.Title,
		"head":  opts.HeadRef,
		"base":  baseRef,
		"body":  opts.Body,
		"draft": opts.Draft,
	}

	var response struct {
		HTMLURL string `json:"html_url"`
	}
	if err := ghAPIWithClient(ctx, client, githubAPIRequest{
		Method:   http.MethodPost,
		Endpoint: endpoint,
		Body:     request,
	}, &response); err != nil {
		return "", fmt.Errorf("create pull request failed: %w", err)
	}

	prURL := strings.TrimSpace(response.HTMLURL)
	if prURL == "" {
		return "", fmt.Errorf("create pull request failed: empty pull request URL")
	}
	return prURL, nil
}

func defaultBranch(ctx context.Context, client ClientSelection, repo GitHubRepository) (string, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s", repo.Owner, repo.Name)
	var response struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := ghAPIWithClient(ctx, client, githubAPIRequest{
		Method:   http.MethodGet,
		Endpoint: endpoint,
	}, &response); err != nil {
		return "", fmt.Errorf("resolve default branch for pull request: %w", err)
	}

	baseRef := strings.TrimSpace(response.DefaultBranch)
	if baseRef == "" {
		return "", fmt.Errorf("resolve default branch for pull request: empty default branch")
	}
	return baseRef, nil
}
