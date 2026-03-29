package ci

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestMergePRWithDeps_RejectsInvalidStrategy(t *testing.T) {
	t.Parallel()

	depsCalled := false
	_, err := mergePRWithDeps(context.Background(), MergeOptions{Strategy: "fast-forward"}, mergeDeps{
		currentBranch: func(context.Context) (string, error) {
			depsCalled = true
			return "hal/ci-merge", nil
		},
	})
	if err == nil {
		t.Fatal("mergePRWithDeps() error = nil, want non-nil")
	}
	if !errors.Is(err, ErrMergeInvalidStrategy) {
		t.Fatalf("errors.Is(err, ErrMergeInvalidStrategy) = false, err=%v", err)
	}
	if depsCalled {
		t.Fatal("strategy should be validated before evaluating dependencies")
	}
}

func TestMergePRWithDeps_BlocksNonPassingStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status StatusResult
	}{
		{
			name: "failing",
			status: StatusResult{
				Status:           StatusFailing,
				ChecksDiscovered: true,
				SHA:              "head-sha",
			},
		},
		{
			name: "pending",
			status: StatusResult{
				Status:           StatusPending,
				ChecksDiscovered: true,
				SHA:              "head-sha",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findCalled := false
			mergeCalled := false

			_, err := mergePRWithDeps(context.Background(), MergeOptions{}, mergeDeps{
				currentBranch: func(context.Context) (string, error) {
					return "hal/ci-merge", nil
				},
				resolveRepo: func(context.Context) (GitHubRepository, error) {
					return GitHubRepository{Owner: "acme", Name: "repo"}, nil
				},
				getStatus: func(context.Context) (StatusResult, error) {
					return tt.status, nil
				},
				findOpenPR: func(context.Context, GitHubRepository, string) (*PullRequest, error) {
					findCalled = true
					return &PullRequest{Number: 7, HeadSHA: "head-sha"}, nil
				},
				mergePullRequest: func(context.Context, GitHubRepository, int, string) (string, error) {
					mergeCalled = true
					return "merge-sha", nil
				},
			})
			if err == nil {
				t.Fatal("mergePRWithDeps() error = nil, want non-nil")
			}
			if !errors.Is(err, ErrMergeRequiresPassingStatus) {
				t.Fatalf("errors.Is(err, ErrMergeRequiresPassingStatus) = false, err=%v", err)
			}
			if findCalled {
				t.Fatal("findOpenPR should not be called when status is not passing")
			}
			if mergeCalled {
				t.Fatal("mergePullRequest should not be called when status is not passing")
			}
		})
	}
}

func TestMergePRWithDeps_AllowNoChecksBehavior(t *testing.T) {
	t.Parallel()

	const branch = "hal/no-checks"
	const sha = "head-sha"

	t.Run("blocks when override disabled", func(t *testing.T) {
		t.Parallel()

		findCalled := false
		_, err := mergePRWithDeps(context.Background(), MergeOptions{}, mergeDeps{
			currentBranch: func(context.Context) (string, error) {
				return branch, nil
			},
			resolveRepo: func(context.Context) (GitHubRepository, error) {
				return GitHubRepository{Owner: "acme", Name: "repo"}, nil
			},
			getStatus: func(context.Context) (StatusResult, error) {
				return StatusResult{Status: StatusPending, ChecksDiscovered: false, SHA: sha}, nil
			},
			findOpenPR: func(context.Context, GitHubRepository, string) (*PullRequest, error) {
				findCalled = true
				return &PullRequest{Number: 9, HeadSHA: sha}, nil
			},
		})
		if err == nil {
			t.Fatal("mergePRWithDeps() error = nil, want non-nil")
		}
		if !errors.Is(err, ErrMergeNoChecksDisallowed) {
			t.Fatalf("errors.Is(err, ErrMergeNoChecksDisallowed) = false, err=%v", err)
		}
		if findCalled {
			t.Fatal("findOpenPR should not be called when no-check override is disabled")
		}
	})

	t.Run("allows merge when override enabled", func(t *testing.T) {
		t.Parallel()

		mergeCalled := false
		deleteCalled := false

		result, err := mergePRWithDeps(context.Background(), MergeOptions{AllowNoChecks: true}, mergeDeps{
			currentBranch: func(context.Context) (string, error) {
				return branch, nil
			},
			resolveRepo: func(context.Context) (GitHubRepository, error) {
				return GitHubRepository{Owner: "acme", Name: "repo"}, nil
			},
			getStatus: func(context.Context) (StatusResult, error) {
				return StatusResult{Status: StatusPending, ChecksDiscovered: false, SHA: sha}, nil
			},
			findOpenPR: func(context.Context, GitHubRepository, string) (*PullRequest, error) {
				return &PullRequest{Number: 9, HeadSHA: sha, HeadRef: branch}, nil
			},
			mergePullRequest: func(_ context.Context, _ GitHubRepository, prNumber int, strategy string) (string, error) {
				mergeCalled = true
				if prNumber != 9 {
					t.Fatalf("prNumber = %d, want 9", prNumber)
				}
				if strategy != "squash" {
					t.Fatalf("strategy = %q, want default \"squash\"", strategy)
				}
				return "merged-sha", nil
			},
			deleteRemoteBranch: func(context.Context, GitHubRepository, string) error {
				deleteCalled = true
				return nil
			},
		})
		if err != nil {
			t.Fatalf("mergePRWithDeps() error = %v", err)
		}
		if !mergeCalled {
			t.Fatal("mergePullRequest was not called")
		}
		if deleteCalled {
			t.Fatal("deleteRemoteBranch should not be called when DeleteBranch is false")
		}
		if result.ContractVersion != MergeContractVersion {
			t.Fatalf("result.ContractVersion = %q, want %q", result.ContractVersion, MergeContractVersion)
		}
		if !result.Merged {
			t.Fatal("result.Merged = false, want true")
		}
		if result.Strategy != "squash" {
			t.Fatalf("result.Strategy = %q, want %q", result.Strategy, "squash")
		}
		if result.PRNumber != 9 {
			t.Fatalf("result.PRNumber = %d, want 9", result.PRNumber)
		}
		if result.MergeCommitSHA != "merged-sha" {
			t.Fatalf("result.MergeCommitSHA = %q, want %q", result.MergeCommitSHA, "merged-sha")
		}
	})
}

func TestMergePRWithDeps_BlocksHeadDrift(t *testing.T) {
	t.Parallel()

	mergeCalled := false
	_, err := mergePRWithDeps(context.Background(), MergeOptions{}, mergeDeps{
		currentBranch: func(context.Context) (string, error) {
			return "hal/ci-merge", nil
		},
		resolveRepo: func(context.Context) (GitHubRepository, error) {
			return GitHubRepository{Owner: "acme", Name: "repo"}, nil
		},
		getStatus: func(context.Context) (StatusResult, error) {
			return StatusResult{Status: StatusPassing, ChecksDiscovered: true, SHA: "old-sha"}, nil
		},
		findOpenPR: func(context.Context, GitHubRepository, string) (*PullRequest, error) {
			return &PullRequest{Number: 22, HeadSHA: "new-sha"}, nil
		},
		mergePullRequest: func(context.Context, GitHubRepository, int, string) (string, error) {
			mergeCalled = true
			return "", nil
		},
	})
	if err == nil {
		t.Fatal("mergePRWithDeps() error = nil, want non-nil")
	}
	if !errors.Is(err, ErrMergeHeadDrift) {
		t.Fatalf("errors.Is(err, ErrMergeHeadDrift) = false, err=%v", err)
	}
	if !strings.Contains(err.Error(), "old-sha") || !strings.Contains(err.Error(), "new-sha") {
		t.Fatalf("drift error should include both shas, got %q", err)
	}
	if mergeCalled {
		t.Fatal("mergePullRequest should not be called when head drift is detected")
	}
}

func TestMergePRWithDeps_DeleteBranchWarnings(t *testing.T) {
	t.Parallel()

	const branch = "hal/ci-merge"

	tests := []struct {
		name              string
		deleteErr         error
		wantBranchDeleted bool
		wantWarning       string
	}{
		{
			name:              "delete success",
			deleteErr:         nil,
			wantBranchDeleted: true,
			wantWarning:       "",
		},
		{
			name:              "ignore 404",
			deleteErr:         fmt.Errorf("%w: already deleted", ErrRemoteBranchNotFound),
			wantBranchDeleted: false,
			wantWarning:       "",
		},
		{
			name:              "non-404 warning",
			deleteErr:         errors.New("permission denied"),
			wantBranchDeleted: false,
			wantWarning:       "permission denied",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			deleteCalls := 0

			result, err := mergePRWithDeps(context.Background(), MergeOptions{Strategy: "merge", DeleteBranch: true}, mergeDeps{
				currentBranch: func(context.Context) (string, error) {
					return branch, nil
				},
				resolveRepo: func(context.Context) (GitHubRepository, error) {
					return GitHubRepository{Owner: "acme", Name: "repo"}, nil
				},
				getStatus: func(context.Context) (StatusResult, error) {
					return StatusResult{Status: StatusPassing, ChecksDiscovered: true, SHA: "head-sha"}, nil
				},
				findOpenPR: func(context.Context, GitHubRepository, string) (*PullRequest, error) {
					return &PullRequest{Number: 42, HeadSHA: "head-sha", HeadRef: branch}, nil
				},
				mergePullRequest: func(_ context.Context, _ GitHubRepository, prNumber int, strategy string) (string, error) {
					if prNumber != 42 {
						t.Fatalf("prNumber = %d, want 42", prNumber)
					}
					if strategy != "merge" {
						t.Fatalf("strategy = %q, want %q", strategy, "merge")
					}
					return "merge-commit-sha", nil
				},
				deleteRemoteBranch: func(_ context.Context, _ GitHubRepository, gotBranch string) error {
					deleteCalls++
					if gotBranch != branch {
						t.Fatalf("delete branch = %q, want %q", gotBranch, branch)
					}
					return tt.deleteErr
				},
			})
			if err != nil {
				t.Fatalf("mergePRWithDeps() error = %v", err)
			}
			if deleteCalls != 1 {
				t.Fatalf("deleteRemoteBranch calls = %d, want 1", deleteCalls)
			}
			if !result.Merged {
				t.Fatal("result.Merged = false, want true")
			}
			if result.Strategy != "merge" {
				t.Fatalf("result.Strategy = %q, want %q", result.Strategy, "merge")
			}
			if result.BranchDeleted != tt.wantBranchDeleted {
				t.Fatalf("result.BranchDeleted = %t, want %t", result.BranchDeleted, tt.wantBranchDeleted)
			}
			if tt.wantWarning == "" {
				if result.DeleteWarning != "" {
					t.Fatalf("result.DeleteWarning = %q, want empty", result.DeleteWarning)
				}
			} else if !strings.Contains(result.DeleteWarning, tt.wantWarning) {
				t.Fatalf("result.DeleteWarning = %q, want to contain %q", result.DeleteWarning, tt.wantWarning)
			}
		})
	}
}
