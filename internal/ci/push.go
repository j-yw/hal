package ci

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

const defaultPushTitlePrefix = "hal ci: "

// PushOptions configures push and pull-request creation behavior.
type PushOptions struct {
	BaseRef string
	Title   string
	Body    string
	Draft   *bool
}

type createPullRequestOptions struct {
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
	findOpenPR    func(context.Context, GitHubRepository, string) (*PullRequest, error)
	createPR      func(context.Context, createPullRequestOptions) (string, error)
}

// PushAndCreatePR pushes the current branch and creates or reuses an open pull request.
func PushAndCreatePR(ctx context.Context, opts PushOptions) (PushResult, error) {
	return pushAndCreatePRWithDeps(ctx, opts, pushDeps{})
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
	if deps.findOpenPR == nil {
		deps.findOpenPR = findOpenPullRequest
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

	if err := deps.pushBranch(ctx, branch); err != nil {
		return PushResult{}, err
	}

	repo, err := deps.resolveRepo(ctx)
	if err != nil {
		return PushResult{}, err
	}

	existingPR, err := deps.findOpenPR(ctx, repo, branch)
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

	createOpts := defaultCreatePullRequestOptions(branch, opts)
	prURL, err := deps.createPR(ctx, createOpts)
	if err != nil {
		return PushResult{}, err
	}

	createdPR, err := deps.findOpenPR(ctx, repo, branch)
	if err != nil {
		return PushResult{}, err
	}
	if createdPR == nil {
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

func gitPushBranch(ctx context.Context, branch string) error {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return fmt.Errorf("push branch: empty branch name")
	}

	if _, err := runGit(ctx, "push", "-u", "origin", branch); err != nil {
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
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return nil, nil
	}

	query := url.Values{}
	query.Set("state", "open")
	query.Set("head", repo.Owner+":"+branch)
	query.Set("per_page", "1")
	query.Set("page", "1")

	endpoint := fmt.Sprintf("/repos/%s/%s/pulls?%s", repo.Owner, repo.Name, query.Encode())
	var pulls []ghOpenPullRequest
	if err := ghAPI(ctx, endpoint, &pulls); err != nil {
		return nil, fmt.Errorf("find open pull request for branch %q: %w", branch, err)
	}
	if len(pulls) == 0 {
		return nil, nil
	}

	pr := PullRequest{
		Number:   pulls[0].Number,
		URL:      strings.TrimSpace(pulls[0].HTMLURL),
		Title:    strings.TrimSpace(pulls[0].Title),
		HeadRef:  strings.TrimSpace(pulls[0].Head.Ref),
		HeadSHA:  strings.TrimSpace(pulls[0].Head.SHA),
		BaseRef:  strings.TrimSpace(pulls[0].Base.Ref),
		Draft:    pulls[0].Draft,
		Existing: true,
	}
	return &pr, nil
}

func createPullRequest(ctx context.Context, opts createPullRequestOptions) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	args := []string{"pr", "create", "--head", opts.HeadRef, "--title", opts.Title, "--body", opts.Body}
	if opts.BaseRef != "" {
		args = append(args, "--base", opts.BaseRef)
	}
	if opts.Draft {
		args = append(args, "--draft")
	}

	cmd := exec.CommandContext(ctx, "gh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if stderrText != "" {
			return "", fmt.Errorf("create pull request failed: %s: %w", stderrText, err)
		}
		return "", fmt.Errorf("create pull request failed: %w", err)
	}

	prURL := strings.TrimSpace(stdout.String())
	if prURL == "" {
		return "", fmt.Errorf("create pull request failed: empty pull request URL")
	}
	return prURL, nil
}
