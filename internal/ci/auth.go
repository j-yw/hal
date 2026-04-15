package ci

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	githubTokenEnv                = "GITHUB_TOKEN"
	ghTokenEnv                    = "GH_TOKEN"
	gitHubTokenValidationTimeout  = 10 * time.Second
)

// ClientKind identifies which GitHub client path should be used.
type ClientKind string

const (
	ClientKindAPI ClientKind = "api"
	ClientKindGH  ClientKind = "gh"
)

var (
	gitHubTokenValidationHTTPClient = &http.Client{Timeout: gitHubTokenValidationTimeout}

	// ErrInvalidEnvToken is returned when an env token is present but invalid.
	// This must remain exact so callers can provide deterministic corrective guidance.
	ErrInvalidEnvToken = errors.New("invalid GitHub token in environment; set a valid $GITHUB_TOKEN/$GH_TOKEN or unset it to use 'gh auth login'")

	// ErrNoGitHubAuth is returned when neither env token auth nor gh auth is available.
	ErrNoGitHubAuth = errors.New("no GitHub auth found: set $GITHUB_TOKEN/$GH_TOKEN or run 'gh auth login'")
)

// ClientSelection describes which client path should be used for GitHub operations.
type ClientSelection struct {
	Kind  ClientKind
	Token string
}

type clientSelectorDeps struct {
	getenv          func(string) string
	validateToken   func(context.Context, string) error
	ghAuthenticated func(context.Context) bool
}

type tokenValidatorDeps struct {
	validateRequest func(*http.Request) (*http.Response, error)
}

// SelectGitHubClient resolves the deterministic auth/client path.
//
// Precedence:
//   - Environment token ($GITHUB_TOKEN, then $GH_TOKEN) -> API client
//   - Authenticated gh CLI -> gh client
//   - Otherwise ErrNoGitHubAuth
//
// If an environment token is present but fails validation, ErrInvalidEnvToken is
// returned and no gh fallback is attempted.
func SelectGitHubClient(ctx context.Context) (ClientSelection, error) {
	return selectGitHubClientWithDeps(ctx, clientSelectorDeps{
		getenv:          os.Getenv,
		validateToken:   validateEnvToken,
		ghAuthenticated: isGHAuthenticated,
	})
}

func selectGitHubClientWithDeps(ctx context.Context, deps clientSelectorDeps) (ClientSelection, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if deps.getenv == nil {
		deps.getenv = os.Getenv
	}
	if deps.validateToken == nil {
		deps.validateToken = validateEnvToken
	}
	if deps.ghAuthenticated == nil {
		deps.ghAuthenticated = isGHAuthenticated
	}

	if token, ok := envToken(deps.getenv); ok {
		if err := deps.validateToken(ctx, token); err != nil {
			if errors.Is(err, ErrInvalidEnvToken) {
				return ClientSelection{}, ErrInvalidEnvToken
			}
			return ClientSelection{}, err
		}
		return ClientSelection{Kind: ClientKindAPI, Token: token}, nil
	}

	if deps.ghAuthenticated(ctx) {
		return ClientSelection{Kind: ClientKindGH}, nil
	}

	return ClientSelection{}, ErrNoGitHubAuth
}

func envToken(getenv func(string) string) (string, bool) {
	for _, key := range []string{githubTokenEnv, ghTokenEnv} {
		token := strings.TrimSpace(getenv(key))
		if token != "" {
			return token, true
		}
	}
	return "", false
}

func validateEnvToken(ctx context.Context, token string) error {
	return validateEnvTokenWithDeps(ctx, token, tokenValidatorDeps{
		validateRequest: validateGitHubTokenRequest,
	})
}

func validateEnvTokenWithDeps(ctx context.Context, token string, deps tokenValidatorDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrInvalidEnvToken
	}
	if strings.ContainsAny(token, " \t\n\r") {
		return ErrInvalidEnvToken
	}
	if len(token) < 20 {
		return ErrInvalidEnvToken
	}

	if deps.validateRequest == nil {
		deps.validateRequest = validateGitHubTokenRequest
	}

	// /rate_limit is available to both user and non-user tokens while still
	// returning 401 for invalid credentials.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/rate_limit", nil)
	if err != nil {
		return ErrInvalidEnvToken
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := deps.validateRequest(req)
	if err != nil {
		return fmt.Errorf("validate GitHub token request: %w", err)
	}
	defer resp.Body.Close()
	// Treat only 401 as definitively invalid. Other statuses (for example 403)
	// can occur for valid tokens depending on org policy or temporary limits.
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrInvalidEnvToken
	}
	return nil
}

func validateGitHubTokenRequest(req *http.Request) (*http.Response, error) {
	return gitHubTokenValidationHTTPClient.Do(req)
}

func isGHAuthenticated(ctx context.Context) bool {
	return isGHAuthenticatedWithRunner(ctx, runGHCommand)
}

func isGHAuthenticatedWithRunner(ctx context.Context, run func(context.Context, string, ...string) error) bool {
	if run == nil {
		run = runGHCommand
	}
	return run(ctx, "gh", "auth", "status", "--hostname", "github.com") == nil
}

func runGHCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}
