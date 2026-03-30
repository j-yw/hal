package ci

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestPushAndCreatePRWithDeps_PushesCurrentBranchAndReusesExistingPRWithoutImplicitBaseFilter(t *testing.T) {
	t.Parallel()

	const branch = "hal/ci-push"
	const prURL = "https://github.com/acme/repo/pull/42"

	pushedBranch := ""
	createCalls := 0
	findCalls := 0
	resolveBaseRefCalled := false

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
		resolveBaseRef: func(context.Context, GitHubRepository, string) (string, error) {
			resolveBaseRefCalled = true
			return "main", nil
		},
		findOpenPR: func(_ context.Context, repo GitHubRepository, gotBranch, gotBaseRef string) (*PullRequest, error) {
			findCalls++
			if repo.FullName() != "acme/repo" {
				t.Fatalf("repo = %q, want %q", repo.FullName(), "acme/repo")
			}
			if gotBranch != branch {
				t.Fatalf("branch = %q, want %q", gotBranch, branch)
			}
			if gotBaseRef != "" {
				t.Fatalf("baseRef = %q, want empty for implicit-base lookup", gotBaseRef)
			}
			return &PullRequest{
				Number:   42,
				URL:      prURL,
				Title:    "existing pr",
				HeadRef:  branch,
				HeadSHA:  "abc123",
				BaseRef:  "release/1.2",
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
	if resolveBaseRefCalled {
		t.Fatal("resolveBaseRef called = true, want false when existing PR is found without explicit base")
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
	if result.PullRequest.BaseRef != "release/1.2" {
		t.Fatalf("result.PullRequest.BaseRef = %q, want %q", result.PullRequest.BaseRef, "release/1.2")
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
		resolveBaseRef: func(context.Context, GitHubRepository, string) (string, error) {
			return "main", nil
		},
		findOpenPR: func(_ context.Context, _ GitHubRepository, gotBranch, gotBaseRef string) (*PullRequest, error) {
			findCalls++
			if gotBranch != branch {
				t.Fatalf("branch = %q, want %q", gotBranch, branch)
			}
			switch findCalls {
			case 1:
				if gotBaseRef != "" {
					t.Fatalf("first lookup baseRef = %q, want empty", gotBaseRef)
				}
				return nil, nil
			case 2:
				if gotBaseRef != "main" {
					t.Fatalf("second lookup baseRef = %q, want %q", gotBaseRef, "main")
				}
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
	if capturedCreate.BaseRef != "main" {
		t.Fatalf("createPR baseRef = %q, want %q", capturedCreate.BaseRef, "main")
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
		resolveBaseRef: func(context.Context, GitHubRepository, string) (string, error) {
			return "main", nil
		},
		findOpenPR: func(context.Context, GitHubRepository, string, string) (*PullRequest, error) {
			findCalls++
			switch findCalls {
			case 1:
				return nil, nil
			case 2:
				return &PullRequest{Number: 11, URL: "https://github.com/acme/repo/pull/11", HeadRef: branch, BaseRef: "main", Draft: false}, nil
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

func TestPushAndCreatePRWithDeps_ImplicitBaseLookupThenResolvedBaseLookupAfterCreate(t *testing.T) {
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
		resolveBaseRef: func(context.Context, GitHubRepository, string) (string, error) {
			return "main", nil
		},
		findOpenPR: func(_ context.Context, _ GitHubRepository, gotBranch, gotBaseRef string) (*PullRequest, error) {
			findCalls++
			if gotBranch != branch {
				t.Fatalf("branch = %q, want %q", gotBranch, branch)
			}
			switch findCalls {
			case 1:
				if gotBaseRef != "" {
					t.Fatalf("first lookup baseRef = %q, want empty", gotBaseRef)
				}
				return nil, nil
			case 2:
				if gotBaseRef != "main" {
					t.Fatalf("second lookup baseRef = %q, want %q", gotBaseRef, "main")
				}
				return nil, nil
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

func TestPushAndCreatePRWithDeps_CreateSuccessLookupFailureFallsBackToCreateResult(t *testing.T) {
	t.Parallel()

	const branch = "hal/fallback-on-read-error"
	const createdURL = "https://github.com/acme/repo/pull/99"

	createCalls := 0
	findCalls := 0
	capturedCreate := createPullRequestOptions{}

	result, err := pushAndCreatePRWithDeps(context.Background(), PushOptions{}, pushDeps{
		currentBranch: func(context.Context) (string, error) {
			return branch, nil
		},
		pushBranch: func(context.Context, string) error {
			return nil
		},
		resolveRepo: func(context.Context) (GitHubRepository, error) {
			return GitHubRepository{Owner: "acme", Name: "repo"}, nil
		},
		resolveBaseRef: func(context.Context, GitHubRepository, string) (string, error) {
			return "develop", nil
		},
		findOpenPR: func(context.Context, GitHubRepository, string, string) (*PullRequest, error) {
			findCalls++
			switch findCalls {
			case 1:
				return nil, nil
			case 2:
				return nil, errors.New("transient list failure")
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

	if result.PullRequest.Existing {
		t.Fatal("result.PullRequest.Existing = true, want false")
	}
	if result.PullRequest.URL != createdURL {
		t.Fatalf("result.PullRequest.URL = %q, want %q", result.PullRequest.URL, createdURL)
	}
	if result.PullRequest.Title != capturedCreate.Title {
		t.Fatalf("result.PullRequest.Title = %q, want %q", result.PullRequest.Title, capturedCreate.Title)
	}
	if result.PullRequest.HeadRef != branch {
		t.Fatalf("result.PullRequest.HeadRef = %q, want %q", result.PullRequest.HeadRef, branch)
	}
	if result.PullRequest.BaseRef != "develop" {
		t.Fatalf("result.PullRequest.BaseRef = %q, want %q", result.PullRequest.BaseRef, "develop")
	}
	if result.PullRequest.Draft != capturedCreate.Draft {
		t.Fatalf("result.PullRequest.Draft = %t, want %t", result.PullRequest.Draft, capturedCreate.Draft)
	}
}

func TestPushAndCreatePRWithDeps_ResolveRepoFailureDoesNotPush(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("resolve repo failed")
	pushCalled := false

	_, err := pushAndCreatePRWithDeps(context.Background(), PushOptions{}, pushDeps{
		currentBranch: func(context.Context) (string, error) {
			return "hal/ci-push", nil
		},
		pushBranch: func(context.Context, string) error {
			pushCalled = true
			return nil
		},
		resolveRepo: func(context.Context) (GitHubRepository, error) {
			return GitHubRepository{}, expectedErr
		},
		resolveBaseRef: func(context.Context, GitHubRepository, string) (string, error) {
			t.Fatal("resolveBaseRef should not be called when resolveRepo fails")
			return "", nil
		},
		findOpenPR: func(context.Context, GitHubRepository, string, string) (*PullRequest, error) {
			t.Fatal("findOpenPR should not be called when resolveRepo fails")
			return nil, nil
		},
		createPR: func(context.Context, createPullRequestOptions) (string, error) {
			t.Fatal("createPR should not be called when resolveRepo fails")
			return "", nil
		},
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("pushAndCreatePRWithDeps() error = %v, want %v", err, expectedErr)
	}
	if pushCalled {
		t.Fatal("pushBranch should not be called when resolveRepo fails")
	}
}

func TestSelectOpenPullRequest_FiltersByBase(t *testing.T) {
	t.Parallel()

	prMain := ghOpenPullRequest{Number: 11, HTMLURL: "https://github.com/acme/repo/pull/11", Title: "main target"}
	prMain.Head.Ref = "hal/ci-push"
	prMain.Head.SHA = "aaa111"
	prMain.Base.Ref = "main"

	prDevelop := ghOpenPullRequest{Number: 12, HTMLURL: "https://github.com/acme/repo/pull/12", Title: "develop target"}
	prDevelop.Head.Ref = "hal/ci-push"
	prDevelop.Head.SHA = "bbb222"
	prDevelop.Base.Ref = "develop"

	pr, err := selectOpenPullRequest("hal/ci-push", "develop", []ghOpenPullRequest{prMain, prDevelop})
	if err != nil {
		t.Fatalf("selectOpenPullRequest() error = %v", err)
	}
	if pr == nil {
		t.Fatal("selectOpenPullRequest() returned nil PR")
	}
	if pr.Number != 12 {
		t.Fatalf("pr.Number = %d, want 12", pr.Number)
	}
	if pr.BaseRef != "develop" {
		t.Fatalf("pr.BaseRef = %q, want %q", pr.BaseRef, "develop")
	}
}

func TestSelectOpenPullRequest_AmbiguousWithoutBase(t *testing.T) {
	t.Parallel()

	prMain := ghOpenPullRequest{Number: 11}
	prMain.Base.Ref = "main"
	prDevelop := ghOpenPullRequest{Number: 12}
	prDevelop.Base.Ref = "develop"

	_, err := selectOpenPullRequest("hal/ci-push", "", []ghOpenPullRequest{prMain, prDevelop})
	if !errors.Is(err, ErrAmbiguousOpenPullRequest) {
		t.Fatalf("errors.Is(err, ErrAmbiguousOpenPullRequest) = false, err=%v", err)
	}
}

func TestSelectOpenPullRequest_ReturnsBaseMismatchForSingleHeadMatch(t *testing.T) {
	t.Parallel()

	prDevelop := ghOpenPullRequest{Number: 12, HTMLURL: "https://github.com/acme/repo/pull/12", Title: "develop target"}
	prDevelop.Head.Ref = "hal/ci-push"
	prDevelop.Head.SHA = "bbb222"
	prDevelop.Base.Ref = "develop"

	pr, err := selectOpenPullRequest("hal/ci-push", "main", []ghOpenPullRequest{prDevelop})
	if !errors.Is(err, ErrOpenPullRequestBaseMismatch) {
		t.Fatalf("errors.Is(err, ErrOpenPullRequestBaseMismatch) = false, err=%v", err)
	}
	if pr != nil {
		t.Fatalf("selectOpenPullRequest() = %+v, want nil", pr)
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
