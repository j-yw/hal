package ci

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

var (
	// ErrMissingOriginRemote is returned when git remote origin is not configured.
	ErrMissingOriginRemote = errors.New("git remote \"origin\" is not configured")

	// ErrNonGitHubOriginRemote is returned when origin does not point to github.com.
	ErrNonGitHubOriginRemote = errors.New("origin remote is not a GitHub repository")

	// ErrInvalidGitHubOriginRemote is returned when a github.com remote cannot be parsed as owner/repo.
	ErrInvalidGitHubOriginRemote = errors.New("origin remote must include owner and repository name")
)

const githubOriginGuidance = "set origin to git@github.com:<owner>/<repo>.git or https://github.com/<owner>/<repo>.git"

// GitHubRepository identifies a GitHub repository by owner and name.
type GitHubRepository struct {
	Owner string
	Name  string
}

// FullName returns the owner/name repository identifier.
func (r GitHubRepository) FullName() string {
	if r.Owner == "" || r.Name == "" {
		return ""
	}
	return r.Owner + "/" + r.Name
}

type githubRepoResolverDeps struct {
	originRemoteURL func(context.Context) (string, error)
}

// ResolveGitHubRepository reads the git origin remote and requires it to be a GitHub repository.
func ResolveGitHubRepository(ctx context.Context) (GitHubRepository, error) {
	return resolveGitHubRepositoryWithDeps(ctx, githubRepoResolverDeps{
		originRemoteURL: gitOriginRemoteURL,
	})
}

func resolveGitHubRepositoryWithDeps(ctx context.Context, deps githubRepoResolverDeps) (GitHubRepository, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if deps.originRemoteURL == nil {
		deps.originRemoteURL = gitOriginRemoteURL
	}

	remoteURL, err := deps.originRemoteURL(ctx)
	if err != nil {
		if errors.Is(err, ErrMissingOriginRemote) {
			return GitHubRepository{}, missingOriginRemoteError()
		}
		return GitHubRepository{}, err
	}

	repo, err := ParseGitHubRepository(remoteURL)
	if err != nil {
		return GitHubRepository{}, err
	}
	return repo, nil
}

// ParseGitHubRepository parses common GitHub SSH/HTTPS remote URLs.
func ParseGitHubRepository(remoteURL string) (GitHubRepository, error) {
	remoteURL = strings.TrimSpace(remoteURL)
	if remoteURL == "" {
		return GitHubRepository{}, missingOriginRemoteError()
	}

	if strings.Contains(remoteURL, "://") {
		parsed, err := url.Parse(remoteURL)
		if err != nil {
			return GitHubRepository{}, nonGitHubOriginRemoteError(remoteURL)
		}
		if !strings.EqualFold(parsed.Hostname(), "github.com") {
			return GitHubRepository{}, nonGitHubOriginRemoteError(remoteURL)
		}
		return parseGitHubRepoPath(parsed.Path, remoteURL)
	}

	hostAndPath := strings.SplitN(remoteURL, ":", 2)
	if len(hostAndPath) == 2 {
		host := hostAndPath[0]
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
		if !strings.EqualFold(host, "github.com") {
			return GitHubRepository{}, nonGitHubOriginRemoteError(remoteURL)
		}
		return parseGitHubRepoPath(hostAndPath[1], remoteURL)
	}

	return GitHubRepository{}, nonGitHubOriginRemoteError(remoteURL)
}

func parseGitHubRepoPath(path string, remoteURL string) (GitHubRepository, error) {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")
	path = strings.TrimSuffix(path, ".git")

	segments := strings.Split(path, "/")
	if len(segments) != 2 || segments[0] == "" || segments[1] == "" {
		return GitHubRepository{}, invalidGitHubOriginRemoteError(remoteURL)
	}

	return GitHubRepository{Owner: segments[0], Name: segments[1]}, nil
}

func gitOriginRemoteURL(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	cmd := exec.CommandContext(ctx, "git", "remote", "get-url", "origin")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if isMissingOriginRemote(strings.TrimSpace(stderr.String())) {
			return "", ErrMissingOriginRemote
		}
		return "", fmt.Errorf("failed to read git origin remote: %w", err)
	}

	remoteURL := strings.TrimSpace(stdout.String())
	if remoteURL == "" {
		return "", ErrMissingOriginRemote
	}
	return remoteURL, nil
}

func isMissingOriginRemote(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "no such remote") && strings.Contains(lower, "origin")
}

func missingOriginRemoteError() error {
	return fmt.Errorf("%w; %s", ErrMissingOriginRemote, githubOriginGuidance)
}

func nonGitHubOriginRemoteError(remoteURL string) error {
	return fmt.Errorf("%w: %q; %s", ErrNonGitHubOriginRemote, remoteURL, githubOriginGuidance)
}

func invalidGitHubOriginRemoteError(remoteURL string) error {
	return fmt.Errorf("%w: %q; %s", ErrInvalidGitHubOriginRemote, remoteURL, githubOriginGuidance)
}
