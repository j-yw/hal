package ci

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
)

const (
	githubTokenEnv = "GITHUB_TOKEN"
	ghTokenEnv     = "GH_TOKEN"
)

// ClientKind identifies which GitHub client path should be used.
type ClientKind string

const (
	ClientKindAPI ClientKind = "api"
	ClientKindGH  ClientKind = "gh"
)

var (
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
			return ClientSelection{}, ErrInvalidEnvToken
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

func validateEnvToken(_ context.Context, token string) error {
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
	return nil
}

func isGHAuthenticated(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "gh", "auth", "status")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}
