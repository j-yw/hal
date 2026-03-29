package ci

import (
	"context"
	"errors"
	"testing"
)

func TestSelectGitHubClientWithDeps_ValidEnvTokenUsesAPIClient(t *testing.T) {
	var validateCalls, ghAuthCalls int

	selection, err := selectGitHubClientWithDeps(context.Background(), clientSelectorDeps{
		getenv: func(key string) string {
			if key == githubTokenEnv {
				return "ghp_12345678901234567890"
			}
			return ""
		},
		validateToken: func(_ context.Context, token string) error {
			validateCalls++
			if token != "ghp_12345678901234567890" {
				t.Fatalf("token = %q, want %q", token, "ghp_12345678901234567890")
			}
			return nil
		},
		ghAuthenticated: func(context.Context) bool {
			ghAuthCalls++
			return true
		},
	})
	if err != nil {
		t.Fatalf("selectGitHubClientWithDeps() error = %v", err)
	}

	if selection.Kind != ClientKindAPI {
		t.Fatalf("selection.Kind = %q, want %q", selection.Kind, ClientKindAPI)
	}
	if selection.Token != "ghp_12345678901234567890" {
		t.Fatalf("selection.Token = %q, want %q", selection.Token, "ghp_12345678901234567890")
	}
	if validateCalls != 1 {
		t.Fatalf("validateToken calls = %d, want 1", validateCalls)
	}
	if ghAuthCalls != 0 {
		t.Fatalf("ghAuthenticated calls = %d, want 0", ghAuthCalls)
	}
}

func TestSelectGitHubClientWithDeps_InvalidEnvTokenReturnsCorrectiveError(t *testing.T) {
	var ghAuthCalls int

	_, err := selectGitHubClientWithDeps(context.Background(), clientSelectorDeps{
		getenv: func(key string) string {
			if key == githubTokenEnv {
				return "ghp_invalid"
			}
			return ""
		},
		validateToken: func(context.Context, string) error {
			return errors.New("token rejected")
		},
		ghAuthenticated: func(context.Context) bool {
			ghAuthCalls++
			return true
		},
	})
	if !errors.Is(err, ErrInvalidEnvToken) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidEnvToken)
	}
	if err.Error() != ErrInvalidEnvToken.Error() {
		t.Fatalf("error text = %q, want %q", err.Error(), ErrInvalidEnvToken.Error())
	}
	if ghAuthCalls != 0 {
		t.Fatalf("ghAuthenticated calls = %d, want 0 (no fallback on invalid env token)", ghAuthCalls)
	}
}

func TestSelectGitHubClientWithDeps_FallsBackToGHWhenAuthenticated(t *testing.T) {
	var validateCalls int

	selection, err := selectGitHubClientWithDeps(context.Background(), clientSelectorDeps{
		getenv: func(string) string { return "" },
		validateToken: func(context.Context, string) error {
			validateCalls++
			return nil
		},
		ghAuthenticated: func(context.Context) bool {
			return true
		},
	})
	if err != nil {
		t.Fatalf("selectGitHubClientWithDeps() error = %v", err)
	}
	if selection.Kind != ClientKindGH {
		t.Fatalf("selection.Kind = %q, want %q", selection.Kind, ClientKindGH)
	}
	if selection.Token != "" {
		t.Fatalf("selection.Token = %q, want empty", selection.Token)
	}
	if validateCalls != 0 {
		t.Fatalf("validateToken calls = %d, want 0", validateCalls)
	}
}

func TestSelectGitHubClientWithDeps_NoAuthReturnsError(t *testing.T) {
	_, err := selectGitHubClientWithDeps(context.Background(), clientSelectorDeps{
		getenv:          func(string) string { return "" },
		validateToken:   func(context.Context, string) error { return nil },
		ghAuthenticated: func(context.Context) bool { return false },
	})
	if !errors.Is(err, ErrNoGitHubAuth) {
		t.Fatalf("error = %v, want %v", err, ErrNoGitHubAuth)
	}
	if err.Error() != ErrNoGitHubAuth.Error() {
		t.Fatalf("error text = %q, want %q", err.Error(), ErrNoGitHubAuth.Error())
	}
}

func TestSelectGitHubClientWithDeps_UsesGHTokenWhenGitHubTokenUnset(t *testing.T) {
	selection, err := selectGitHubClientWithDeps(context.Background(), clientSelectorDeps{
		getenv: func(key string) string {
			if key == ghTokenEnv {
				return "gho_12345678901234567890"
			}
			return ""
		},
		validateToken:   func(context.Context, string) error { return nil },
		ghAuthenticated: func(context.Context) bool { return true },
	})
	if err != nil {
		t.Fatalf("selectGitHubClientWithDeps() error = %v", err)
	}
	if selection.Kind != ClientKindAPI {
		t.Fatalf("selection.Kind = %q, want %q", selection.Kind, ClientKindAPI)
	}
	if selection.Token != "gho_12345678901234567890" {
		t.Fatalf("selection.Token = %q, want %q", selection.Token, "gho_12345678901234567890")
	}
}

func TestValidateEnvToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{name: "valid token", token: "ghp_12345678901234567890", wantErr: false},
		{name: "empty token", token: "", wantErr: true},
		{name: "too short", token: "short-token", wantErr: true},
		{name: "contains whitespace", token: "ghp_1234 5678901234567890", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEnvToken(context.Background(), tt.token)
			gotErr := err != nil
			if gotErr != tt.wantErr {
				t.Fatalf("validateEnvToken(%q) error = %v, wantErr %v", tt.token, err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, ErrInvalidEnvToken) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidEnvToken)
			}
		})
	}
}
