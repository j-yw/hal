package ci

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
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
			return ErrInvalidEnvToken
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

func TestSelectGitHubClientWithDeps_TokenValidationTransportErrorPassesThrough(t *testing.T) {
	var ghAuthCalls int
	wantErr := errors.New("validate GitHub token request: context deadline exceeded")

	_, err := selectGitHubClientWithDeps(context.Background(), clientSelectorDeps{
		getenv: func(key string) string {
			if key == githubTokenEnv {
				return "ghp_12345678901234567890"
			}
			return ""
		},
		validateToken: func(context.Context, string) error {
			return wantErr
		},
		ghAuthenticated: func(context.Context) bool {
			ghAuthCalls++
			return true
		},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped %v", err, wantErr)
	}
	if errors.Is(err, ErrInvalidEnvToken) {
		t.Fatalf("error = %v, should not be classified as %v", err, ErrInvalidEnvToken)
	}
	if ghAuthCalls != 0 {
		t.Fatalf("ghAuthenticated calls = %d, want 0 (no fallback when env token validation fails)", ghAuthCalls)
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
		name           string
		token          string
		responseCode   int
		requestErr     error
		wantErr        bool
		wantRequest    bool
		wantInvalidErr bool
	}{
		{
			name:           "valid token",
			token:          "ghp_12345678901234567890",
			responseCode:   http.StatusOK,
			wantErr:        false,
			wantRequest:    true,
			wantInvalidErr: false,
		},
		{
			name:           "forbidden can still be valid token",
			token:          "ghp_12345678901234567890",
			responseCode:   http.StatusForbidden,
			wantErr:        false,
			wantRequest:    true,
			wantInvalidErr: false,
		},
		{name: "empty token", token: "", wantErr: true, wantRequest: false, wantInvalidErr: true},
		{name: "too short", token: "short-token", wantErr: true, wantRequest: false, wantInvalidErr: true},
		{name: "contains whitespace", token: "ghp_1234 5678901234567890", wantErr: true, wantRequest: false, wantInvalidErr: true},
		{
			name:           "auth rejected",
			token:          "ghp_12345678901234567890",
			responseCode:   http.StatusUnauthorized,
			wantErr:        true,
			wantRequest:    true,
			wantInvalidErr: true,
		},
		{
			name:           "request error",
			token:          "ghp_12345678901234567890",
			requestErr:     errors.New("network failure"),
			wantErr:        true,
			wantRequest:    true,
			wantInvalidErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestCalls := 0
			err := validateEnvTokenWithDeps(context.Background(), tt.token, tokenValidatorDeps{
				validateRequest: func(req *http.Request) (*http.Response, error) {
					requestCalls++
					if req.URL == nil || req.URL.Path != "/rate_limit" {
						t.Fatalf("request path = %v, want /rate_limit", req.URL)
					}
					if tt.requestErr != nil {
						return nil, tt.requestErr
					}
					code := tt.responseCode
					if code == 0 {
						code = http.StatusOK
					}
					return &http.Response{
						StatusCode: code,
						Body:       io.NopCloser(strings.NewReader("{}")),
					}, nil
				},
			})
			gotErr := err != nil
			if gotErr != tt.wantErr {
				t.Fatalf("validateEnvToken(%q) error = %v, wantErr %v", tt.token, err, tt.wantErr)
			}
			if tt.wantRequest && requestCalls != 1 {
				t.Fatalf("validate request calls = %d, want 1", requestCalls)
			}
			if !tt.wantRequest && requestCalls != 0 {
				t.Fatalf("validate request calls = %d, want 0", requestCalls)
			}
			if tt.wantErr && tt.wantInvalidErr && !errors.Is(err, ErrInvalidEnvToken) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidEnvToken)
			}
			if tt.wantErr && !tt.wantInvalidErr && errors.Is(err, ErrInvalidEnvToken) {
				t.Fatalf("error = %v, should not be classified as %v", err, ErrInvalidEnvToken)
			}
		})
	}
}

func TestIsGHAuthenticatedWithRunner_ScopesAuthToGitHubDotCom(t *testing.T) {
	var gotName string
	var gotArgs []string

	ok := isGHAuthenticatedWithRunner(context.Background(), func(_ context.Context, name string, args ...string) error {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return nil
	})
	if !ok {
		t.Fatalf("isGHAuthenticatedWithRunner() = false, want true")
	}
	if gotName != "gh" {
		t.Fatalf("command name = %q, want %q", gotName, "gh")
	}
	wantArgs := []string{"auth", "status", "--hostname", "github.com"}
	if len(gotArgs) != len(wantArgs) {
		t.Fatalf("args len = %d, want %d (%v)", len(gotArgs), len(wantArgs), gotArgs)
	}
	for i := range wantArgs {
		if gotArgs[i] != wantArgs[i] {
			t.Fatalf("arg[%d] = %q, want %q", i, gotArgs[i], wantArgs[i])
		}
	}
}

func TestIsGHAuthenticatedWithRunner_ReturnsFalseOnError(t *testing.T) {
	ok := isGHAuthenticatedWithRunner(context.Background(), func(context.Context, string, ...string) error {
		return errors.New("not authenticated")
	})
	if ok {
		t.Fatalf("isGHAuthenticatedWithRunner() = true, want false")
	}
}
