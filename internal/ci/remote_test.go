package ci

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseGitHubRepository_CommonFormats(t *testing.T) {
	tests := []struct {
		name      string
		remoteURL string
		wantOwner string
		wantName  string
	}{
		{
			name:      "ssh scp style",
			remoteURL: "git@github.com:acme/hal.git",
			wantOwner: "acme",
			wantName:  "hal",
		},
		{
			name:      "ssh url style",
			remoteURL: "ssh://git@github.com/acme/hal.git",
			wantOwner: "acme",
			wantName:  "hal",
		},
		{
			name:      "https style",
			remoteURL: "https://github.com/acme/hal.git",
			wantOwner: "acme",
			wantName:  "hal",
		},
		{
			name:      "https without dot git",
			remoteURL: "https://github.com/acme/hal",
			wantOwner: "acme",
			wantName:  "hal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, err := ParseGitHubRepository(tt.remoteURL)
			if err != nil {
				t.Fatalf("ParseGitHubRepository(%q) error = %v", tt.remoteURL, err)
			}

			if repo.Owner != tt.wantOwner {
				t.Fatalf("repo.Owner = %q, want %q", repo.Owner, tt.wantOwner)
			}
			if repo.Name != tt.wantName {
				t.Fatalf("repo.Name = %q, want %q", repo.Name, tt.wantName)
			}
			if repo.FullName() != tt.wantOwner+"/"+tt.wantName {
				t.Fatalf("repo.FullName() = %q, want %q", repo.FullName(), tt.wantOwner+"/"+tt.wantName)
			}
		})
	}
}

func TestResolveGitHubRepositoryWithDeps_MissingOriginRemote(t *testing.T) {
	_, err := resolveGitHubRepositoryWithDeps(context.Background(), githubRepoResolverDeps{
		originRemoteURL: func(context.Context) (string, error) {
			return "", ErrMissingOriginRemote
		},
	})
	if !errors.Is(err, ErrMissingOriginRemote) {
		t.Fatalf("error = %v, want %v", err, ErrMissingOriginRemote)
	}
	if !strings.Contains(err.Error(), "set origin to git@github.com") {
		t.Fatalf("error text = %q, want actionable guidance", err.Error())
	}
}

func TestResolveGitHubRepositoryWithDeps_NonGitHubRemote(t *testing.T) {
	_, err := resolveGitHubRepositoryWithDeps(context.Background(), githubRepoResolverDeps{
		originRemoteURL: func(context.Context) (string, error) {
			return "git@gitlab.com:acme/hal.git", nil
		},
	})
	if !errors.Is(err, ErrNonGitHubOriginRemote) {
		t.Fatalf("error = %v, want %v", err, ErrNonGitHubOriginRemote)
	}
	if !strings.Contains(err.Error(), "git@gitlab.com:acme/hal.git") {
		t.Fatalf("error text = %q, want remote URL included", err.Error())
	}
	if !strings.Contains(err.Error(), "https://github.com/<owner>/<repo>.git") {
		t.Fatalf("error text = %q, want actionable guidance", err.Error())
	}
}

func TestResolveGitHubRepositoryWithDeps_GitHubRemote(t *testing.T) {
	repo, err := resolveGitHubRepositoryWithDeps(context.Background(), githubRepoResolverDeps{
		originRemoteURL: func(context.Context) (string, error) {
			return "git@github.com:acme/hal.git", nil
		},
	})
	if err != nil {
		t.Fatalf("resolveGitHubRepositoryWithDeps() error = %v", err)
	}
	if repo.Owner != "acme" {
		t.Fatalf("repo.Owner = %q, want %q", repo.Owner, "acme")
	}
	if repo.Name != "hal" {
		t.Fatalf("repo.Name = %q, want %q", repo.Name, "hal")
	}
}

func TestParseGitHubRepository_InvalidGitHubPath(t *testing.T) {
	_, err := ParseGitHubRepository("https://github.com/acme")
	if !errors.Is(err, ErrInvalidGitHubOriginRemote) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidGitHubOriginRemote)
	}
}
