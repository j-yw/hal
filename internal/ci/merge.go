package ci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

const defaultMergeStrategy = "squash"

var (
	// ErrMergeInvalidStrategy is returned when merge strategy is unsupported.
	ErrMergeInvalidStrategy = errors.New("ci merge strategy must be one of squash, merge, rebase")

	// ErrMergeRequiresPassingStatus is returned when merge runs against non-passing checks.
	ErrMergeRequiresPassingStatus = errors.New("ci merge requires passing status")

	// ErrMergeNoChecksDisallowed is returned when no checks were discovered and override is disabled.
	ErrMergeNoChecksDisallowed = errors.New("ci merge blocked: no checks discovered")

	// ErrMergePRNotFound is returned when there is no open pull request for the current branch.
	ErrMergePRNotFound = errors.New("ci merge requires an open pull request for the current branch")

	// ErrMergeHeadDrift is returned when the expected PR head SHA differs from current PR head SHA.
	ErrMergeHeadDrift = errors.New("ci merge aborted: pull request head changed")

	// ErrRemoteBranchNotFound is returned when deleting a remote branch returns HTTP 404.
	ErrRemoteBranchNotFound = errors.New("remote branch not found")
)

// MergeOptions configures safe pull request merge behavior.
type MergeOptions struct {
	Strategy      string
	DeleteBranch  bool
	AllowNoChecks bool
}

type mergeDeps struct {
	currentBranch      func(context.Context) (string, error)
	resolveRepo        func(context.Context) (GitHubRepository, error)
	getStatus          func(context.Context) (StatusResult, error)
	findOpenPR         func(context.Context, GitHubRepository, string) (*PullRequest, error)
	mergePullRequest   func(context.Context, GitHubRepository, int, string) (string, error)
	deleteRemoteBranch func(context.Context, GitHubRepository, string) error
}

// MergePR merges the open pull request for the current branch with CI safety guards.
func MergePR(ctx context.Context, opts MergeOptions) (MergeResult, error) {
	return mergePRWithDeps(ctx, opts, mergeDeps{})
}

func mergePRWithDeps(ctx context.Context, opts MergeOptions, deps mergeDeps) (MergeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	strategy, err := normalizeMergeStrategy(opts.Strategy)
	if err != nil {
		return MergeResult{}, err
	}

	if deps.currentBranch == nil {
		deps.currentBranch = gitCurrentBranch
	}
	if deps.resolveRepo == nil {
		deps.resolveRepo = ResolveGitHubRepository
	}
	if deps.getStatus == nil {
		deps.getStatus = GetStatus
	}
	if deps.findOpenPR == nil {
		deps.findOpenPR = findOpenPullRequest
	}
	if deps.mergePullRequest == nil {
		deps.mergePullRequest = mergePullRequest
	}
	if deps.deleteRemoteBranch == nil {
		deps.deleteRemoteBranch = deleteRemoteBranch
	}

	branch, err := deps.currentBranch(ctx)
	if err != nil {
		return MergeResult{}, err
	}
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return MergeResult{}, fmt.Errorf("get current branch: empty branch name")
	}

	repo, err := deps.resolveRepo(ctx)
	if err != nil {
		return MergeResult{}, err
	}

	status, err := deps.getStatus(ctx)
	if err != nil {
		return MergeResult{}, err
	}
	if !status.ChecksDiscovered {
		if !opts.AllowNoChecks {
			return MergeResult{}, fmt.Errorf("%w; rerun with --allow-no-checks to override", ErrMergeNoChecksDisallowed)
		}
	} else if status.Status != StatusPassing {
		return MergeResult{}, fmt.Errorf("%w: got %q; run 'hal ci status' and 'hal ci fix' before retrying", ErrMergeRequiresPassingStatus, status.Status)
	}

	pr, err := deps.findOpenPR(ctx, repo, branch)
	if err != nil {
		return MergeResult{}, fmt.Errorf("find open pull request for branch %q: %w", branch, err)
	}
	if pr == nil {
		return MergeResult{}, fmt.Errorf("%w: branch %q", ErrMergePRNotFound, branch)
	}

	expectedHeadSHA := strings.TrimSpace(status.SHA)
	currentHeadSHA := strings.TrimSpace(pr.HeadSHA)
	if expectedHeadSHA != "" && currentHeadSHA != "" && expectedHeadSHA != currentHeadSHA {
		return MergeResult{}, fmt.Errorf("%w: expected %s but found %s; rerun 'hal ci status' and retry merge", ErrMergeHeadDrift, expectedHeadSHA, currentHeadSHA)
	}

	mergeCommitSHA, err := deps.mergePullRequest(ctx, repo, pr.Number, strategy)
	if err != nil {
		return MergeResult{}, err
	}

	result := MergeResult{
		ContractVersion: MergeContractVersion,
		PRNumber:        pr.Number,
		Strategy:        strategy,
		Merged:          true,
		MergeCommitSHA:  strings.TrimSpace(mergeCommitSHA),
	}

	if opts.DeleteBranch {
		branchToDelete := strings.TrimSpace(pr.HeadRef)
		if branchToDelete == "" {
			branchToDelete = branch
		}
		if err := deps.deleteRemoteBranch(ctx, repo, branchToDelete); err != nil {
			switch {
			case errors.Is(err, ErrRemoteBranchNotFound):
				// Ignore; branch is already gone.
			default:
				result.DeleteWarning = fmt.Sprintf("delete remote branch %q: %v", branchToDelete, err)
			}
		} else {
			result.BranchDeleted = true
		}
	}

	result.Summary = mergeSummary(result, opts.DeleteBranch)
	return result, nil
}

func normalizeMergeStrategy(strategy string) (string, error) {
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	if strategy == "" {
		strategy = defaultMergeStrategy
	}

	switch strategy {
	case "squash", "merge", "rebase":
		return strategy, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrMergeInvalidStrategy, strategy)
	}
}

func mergeSummary(result MergeResult, deleteBranchRequested bool) string {
	summary := fmt.Sprintf("merged pull request #%d using %s strategy", result.PRNumber, result.Strategy)
	if !deleteBranchRequested {
		return summary
	}

	if result.BranchDeleted {
		return summary + " and deleted the remote branch"
	}
	if result.DeleteWarning != "" {
		return summary + "; warning: " + result.DeleteWarning
	}
	return summary + "; remote branch already absent"
}

type ghMergeResponse struct {
	SHA string `json:"sha"`
}

func mergePullRequest(ctx context.Context, repo GitHubRepository, prNumber int, strategy string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/pulls/%d/merge", repo.Owner, repo.Name, prNumber)
	cmd := exec.CommandContext(ctx, "gh", "api", "-X", "PUT", "-H", "Accept: application/vnd.github+json", endpoint, "-f", "merge_method="+strategy)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if stderrText != "" {
			return "", fmt.Errorf("merge pull request #%d failed: %s: %w", prNumber, stderrText, err)
		}
		return "", fmt.Errorf("merge pull request #%d failed: %w", prNumber, err)
	}

	var response ghMergeResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return "", fmt.Errorf("decode merge response for pull request #%d: %w", prNumber, err)
	}

	sha := strings.TrimSpace(response.SHA)
	if sha == "" {
		return "", fmt.Errorf("merge pull request #%d failed: empty merge commit sha", prNumber)
	}
	return sha, nil
}

func deleteRemoteBranch(ctx context.Context, repo GitHubRepository, branch string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	branch = strings.TrimSpace(branch)
	if branch == "" {
		return fmt.Errorf("delete remote branch: empty branch name")
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s", repo.Owner, repo.Name, url.PathEscape(branch))
	cmd := exec.CommandContext(ctx, "gh", "api", "-X", "DELETE", "-H", "Accept: application/vnd.github+json", endpoint)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if isHTTP404Error(stderrText) {
			return fmt.Errorf("%w: %s", ErrRemoteBranchNotFound, branch)
		}
		if stderrText != "" {
			return fmt.Errorf("delete remote branch %q failed: %s: %w", branch, stderrText, err)
		}
		return fmt.Errorf("delete remote branch %q failed: %w", branch, err)
	}

	return nil
}

func isHTTP404Error(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	return strings.Contains(lower, "http 404") || strings.Contains(lower, "404 not found")
}
