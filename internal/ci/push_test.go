package ci

import (
	"context"
	"fmt"
	"testing"
)

func TestPushAndCreatePRWithDeps_PushesCurrentBranchAndReusesExistingPR(t *testing.T) {
	t.Parallel()

	const branch = "hal/ci-push"
	const prURL = "https://github.com/acme/repo/pull/42"

	pushedBranch := ""
	createCalls := 0
	findCalls := 0

	result, err := pushAndCreatePRWithDeps(context.Background(), PushOptions{}, pushDeps{
		currentBranch: func(context.Context) (string, error) {
			return branch, nil
		},
		pushBranch: func(_ context.Context, gotBranch string) error {
			pushedBranch = gotBranch
			return nil
		},
		resolveRepo: func(context.Context) (GitHubRepository, error) {
			return GitHubRepository{Owner: "acme", Name: "repo"}, nil
		},
		findOpenPR: func(_ context.Context, repo GitHubRepository, gotBranch string) (*PullRequest, error) {
			findCalls++
			if repo.FullName() != "acme/repo" {
				t.Fatalf("repo = %q, want %q", repo.FullName(), "acme/repo")
			}
			if gotBranch != branch {
				t.Fatalf("branch = %q, want %q", gotBranch, branch)
			}
			return &PullRequest{
				Number:   42,
				URL:      prURL,
				Title:    "existing pr",
				HeadRef:  branch,
				HeadSHA:  "abc123",
				BaseRef:  "main",
				Draft:    true,
				Existing: true,
			}, nil
		},
		createPR: func(context.Context, createPullRequestOptions) (string, error) {
			createCalls++
			return "", nil
		},
	})
	if err != nil {
		t.Fatalf("pushAndCreatePRWithDeps() error = %v", err)
	}

	if pushedBranch != branch {
		t.Fatalf("pushed branch = %q, want %q", pushedBranch, branch)
	}
	if findCalls != 1 {
		t.Fatalf("findOpenPR calls = %d, want 1", findCalls)
	}
	if createCalls != 0 {
		t.Fatalf("createPR calls = %d, want 0", createCalls)
	}
	if !result.Pushed {
		t.Fatal("result.Pushed = false, want true")
	}
	if result.Branch != branch {
		t.Fatalf("result.Branch = %q, want %q", result.Branch, branch)
	}
	if result.PullRequest.Number != 42 {
		t.Fatalf("result.PullRequest.Number = %d, want 42", result.PullRequest.Number)
	}
	if result.PullRequest.URL != prURL {
		t.Fatalf("result.PullRequest.URL = %q, want %q", result.PullRequest.URL, prURL)
	}
	if !result.PullRequest.Existing {
		t.Fatal("result.PullRequest.Existing = false, want true")
	}
}

func TestPushAndCreatePRWithDeps_DefaultsDraftTitleBodyDeterministically(t *testing.T) {
	t.Parallel()

	const branch = "hal/new-feature"
	const createdURL = "https://github.com/acme/repo/pull/7"

	createCalls := 0
	findCalls := 0
	capturedCreate := createPullRequestOptions{}

	result, err := pushAndCreatePRWithDeps(context.Background(), PushOptions{}, pushDeps{
		currentBranch: func(context.Context) (string, error) {
			return branch, nil
		},
		pushBranch: func(_ context.Context, gotBranch string) error {
			if gotBranch != branch {
				t.Fatalf("pushed branch = %q, want %q", gotBranch, branch)
			}
			return nil
		},
		resolveRepo: func(context.Context) (GitHubRepository, error) {
			return GitHubRepository{Owner: "acme", Name: "repo"}, nil
		},
		findOpenPR: func(context.Context, GitHubRepository, string) (*PullRequest, error) {
			findCalls++
			switch findCalls {
			case 1:
				return nil, nil
			case 2:
				return &PullRequest{
					Number:   7,
					URL:      createdURL,
					Title:    capturedCreate.Title,
					HeadRef:  branch,
					HeadSHA:  "def456",
					BaseRef:  "main",
					Draft:    capturedCreate.Draft,
					Existing: false,
				}, nil
			default:
				return nil, fmt.Errorf("unexpected findOpenPR call %d", findCalls)
			}
		},
		createPR: func(_ context.Context, createOpts createPullRequestOptions) (string, error) {
			createCalls++
			capturedCreate = createOpts
			return createdURL, nil
		},
	})
	if err != nil {
		t.Fatalf("pushAndCreatePRWithDeps() error = %v", err)
	}

	if createCalls != 1 {
		t.Fatalf("createPR calls = %d, want 1", createCalls)
	}
	if findCalls != 2 {
		t.Fatalf("findOpenPR calls = %d, want 2", findCalls)
	}

	if !capturedCreate.Draft {
		t.Fatal("createPR draft = false, want true by default")
	}
	if capturedCreate.Title != "hal ci: hal/new-feature" {
		t.Fatalf("createPR title = %q, want %q", capturedCreate.Title, "hal ci: hal/new-feature")
	}
	if capturedCreate.Body != "Automated pull request created by `hal ci push` for branch `hal/new-feature`." {
		t.Fatalf("createPR body = %q, want deterministic default", capturedCreate.Body)
	}
	if capturedCreate.HeadRef != branch {
		t.Fatalf("createPR headRef = %q, want %q", capturedCreate.HeadRef, branch)
	}

	if result.PullRequest.Number != 7 {
		t.Fatalf("result.PullRequest.Number = %d, want 7", result.PullRequest.Number)
	}
	if result.PullRequest.Existing {
		t.Fatal("result.PullRequest.Existing = true, want false")
	}
	if !result.PullRequest.Draft {
		t.Fatal("result.PullRequest.Draft = false, want true")
	}
}

func TestPushAndCreatePRWithDeps_ExplicitDraftFalseOverridesDefault(t *testing.T) {
	t.Parallel()

	const branch = "hal/non-draft"
	draft := false

	createCalls := 0
	findCalls := 0
	capturedCreate := createPullRequestOptions{}

	_, err := pushAndCreatePRWithDeps(context.Background(), PushOptions{Draft: &draft}, pushDeps{
		currentBranch: func(context.Context) (string, error) {
			return branch, nil
		},
		pushBranch: func(context.Context, string) error {
			return nil
		},
		resolveRepo: func(context.Context) (GitHubRepository, error) {
			return GitHubRepository{Owner: "acme", Name: "repo"}, nil
		},
		findOpenPR: func(context.Context, GitHubRepository, string) (*PullRequest, error) {
			findCalls++
			switch findCalls {
			case 1:
				return nil, nil
			case 2:
				return &PullRequest{Number: 11, URL: "https://github.com/acme/repo/pull/11", HeadRef: branch, Draft: false}, nil
			default:
				return nil, fmt.Errorf("unexpected findOpenPR call %d", findCalls)
			}
		},
		createPR: func(_ context.Context, createOpts createPullRequestOptions) (string, error) {
			createCalls++
			capturedCreate = createOpts
			return "https://github.com/acme/repo/pull/11", nil
		},
	})
	if err != nil {
		t.Fatalf("pushAndCreatePRWithDeps() error = %v", err)
	}

	if createCalls != 1 {
		t.Fatalf("createPR calls = %d, want 1", createCalls)
	}
	if capturedCreate.Draft {
		t.Fatal("createPR draft = true, want false when explicitly requested")
	}
}

func TestDefaultPushPRTitleAndBody_Deterministic(t *testing.T) {
	t.Parallel()

	branch := "hal/ci-gap-free"
	if got, want := defaultPushPRTitle(branch), "hal ci: hal/ci-gap-free"; got != want {
		t.Fatalf("defaultPushPRTitle(%q) = %q, want %q", branch, got, want)
	}
	if got, want := defaultPushPRBody(branch), "Automated pull request created by `hal ci push` for branch `hal/ci-gap-free`."; got != want {
		t.Fatalf("defaultPushPRBody(%q) = %q, want %q", branch, got, want)
	}
}
