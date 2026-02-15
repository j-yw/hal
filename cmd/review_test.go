package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestReviewCommandUsageAndExamples(t *testing.T) {
	if reviewCmd.Use != "review against <base-branch> [iterations]" {
		t.Fatalf("reviewCmd.Use = %q, want %q", reviewCmd.Use, "review against <base-branch> [iterations]")
	}

	examples := []string{
		"hal review against develop",
		"hal review against origin/main 5",
	}
	for _, example := range examples {
		if !strings.Contains(reviewCmd.Example, example) {
			t.Fatalf("reviewCmd.Example = %q, missing %q", reviewCmd.Example, example)
		}
	}
}

func TestRunReviewWithDeps(t *testing.T) {
	tests := []struct {
		name               string
		args               []string
		branchExists       bool
		branchErr          error
		runErr             error
		wantErr            string
		wantRun            bool
		expectBranchLookup bool
		wantBranch         string
		wantRequest        reviewRequest
	}{
		{
			name:               "valid args default iterations",
			args:               []string{"against", "develop"},
			branchExists:       true,
			wantRun:            true,
			expectBranchLookup: true,
			wantBranch:         "develop",
			wantRequest: reviewRequest{
				BaseBranch: "develop",
				Iterations: 10,
			},
		},
		{
			name:               "valid args explicit iterations",
			args:               []string{"against", "origin/main", "5"},
			branchExists:       true,
			wantRun:            true,
			expectBranchLookup: true,
			wantBranch:         "origin/main",
			wantRequest: reviewRequest{
				BaseBranch: "origin/main",
				Iterations: 5,
			},
		},
		{
			name:               "missing branch",
			args:               []string{"against", "missing-branch"},
			branchExists:       false,
			wantErr:            "base branch missing-branch not found",
			expectBranchLookup: true,
			wantBranch:         "missing-branch",
		},
		{
			name:    "non-numeric iterations",
			args:    []string{"against", "develop", "nope"},
			wantErr: "iterations must be a positive integer",
		},
		{
			name:    "zero iterations",
			args:    []string{"against", "develop", "0"},
			wantErr: "iterations must be a positive integer",
		},
		{
			name:               "base branch check failure",
			args:               []string{"against", "develop"},
			branchErr:          errors.New("git unavailable"),
			wantErr:            "failed to verify base branch \"develop\": git unavailable",
			expectBranchLookup: true,
			wantBranch:         "develop",
		},
		{
			name:    "invalid syntax",
			args:    []string{"develop"},
			wantErr: reviewUsage,
		},
		{
			name:               "run loop failure bubbles up",
			args:               []string{"against", "develop"},
			branchExists:       true,
			runErr:             errors.New("loop failed"),
			wantErr:            "loop failed",
			wantRun:            true,
			expectBranchLookup: true,
			wantBranch:         "develop",
			wantRequest: reviewRequest{
				BaseBranch: "develop",
				Iterations: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var branchChecked bool
			var gotBranch string
			var runCalled bool
			var gotRequest reviewRequest

			deps := reviewDeps{
				baseBranchExists: func(branch string) (bool, error) {
					branchChecked = true
					gotBranch = branch
					return tt.branchExists, tt.branchErr
				},
				runLoop: func(ctx context.Context, req reviewRequest) error {
					runCalled = true
					gotRequest = req
					return tt.runErr
				},
			}

			err := runReviewWithDeps(context.Background(), tt.args, deps)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if runCalled != tt.wantRun {
				t.Fatalf("runCalled = %v, want %v", runCalled, tt.wantRun)
			}
			if branchChecked != tt.expectBranchLookup {
				t.Fatalf("branchChecked = %v, want %v", branchChecked, tt.expectBranchLookup)
			}

			if tt.expectBranchLookup && gotBranch != tt.wantBranch {
				t.Fatalf("baseBranchExists called with %q, want %q", gotBranch, tt.wantBranch)
			}
			if tt.wantRun && gotRequest != tt.wantRequest {
				t.Fatalf("request = %+v, want %+v", gotRequest, tt.wantRequest)
			}
		})
	}
}
