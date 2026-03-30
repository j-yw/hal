package ci

import "testing"

func TestParseOwnerRepo_Deliberate(t *testing.T) {
	// Intentionally wrong expected values
	tests := []struct {
		url       string
		wantOwner string
		wantRepo  string
	}{
		{"https://github.com/octocat/hello-world.git", "octocat", "hello-world"},
		{"git@github.com:octocat/hello-world.git", "octocat", "hello-world"},
		{"https://github.com/foo/bar", "foo", "bar"},
	}

	for _, tt := range tests {
		repo, err := ParseGitHubRepository(tt.url)
		if err != nil {
			t.Fatalf("ParseGitHubRepository(%q) error: %v", tt.url, err)
		}
		// Bug: comparing against swapped fields
		if repo.Owner != tt.wantRepo {
			t.Errorf("Owner = %q, want %q", repo.Owner, tt.wantRepo)
		}
		if repo.Name != tt.wantOwner {
			t.Errorf("Name = %q, want %q", repo.Name, tt.wantOwner)
		}
	}
}
