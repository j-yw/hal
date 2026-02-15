package cmd

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

const reviewUsage = "usage: hal review against <base-branch> [iterations]"

type reviewRequest struct {
	BaseBranch string
	Iterations int
}

type reviewDeps struct {
	baseBranchExists func(branch string) (bool, error)
	runLoop          func(ctx context.Context, req reviewRequest) error
}

var defaultReviewDeps = reviewDeps{
	baseBranchExists: gitBranchResolvable,
	runLoop: func(ctx context.Context, req reviewRequest) error {
		return fmt.Errorf("review loop is not implemented yet")
	},
}

var reviewCmd = &cobra.Command{
	Use:   "review against <base-branch> [iterations]",
	Short: "Run an iterative review loop against a base branch",
	Long: `Run an iterative review-and-fix loop against a base branch.

This command powers branch-vs-branch review loops.
Use 'hal report' for legacy session reporting.`,
	Example: `  hal review against develop
  hal review against origin/main 5`,
	RunE: runReview,
}

func init() {
	rootCmd.AddCommand(reviewCmd)
}

func runReview(cmd *cobra.Command, args []string) error {
	return runReviewWithDeps(context.Background(), args, defaultReviewDeps)
}

func runReviewWithDeps(ctx context.Context, args []string, deps reviewDeps) error {
	if deps.baseBranchExists == nil {
		deps.baseBranchExists = gitBranchResolvable
	}
	if deps.runLoop == nil {
		deps.runLoop = defaultReviewDeps.runLoop
	}

	req, err := parseReviewRequest(args, deps.baseBranchExists)
	if err != nil {
		return err
	}

	return deps.runLoop(ctx, req)
}

func parseReviewRequest(args []string, branchExistsFn func(branch string) (bool, error)) (reviewRequest, error) {
	if len(args) < 2 || len(args) > 3 || args[0] != "against" {
		return reviewRequest{}, fmt.Errorf(reviewUsage)
	}

	baseBranch := strings.TrimSpace(args[1])
	if baseBranch == "" {
		return reviewRequest{}, fmt.Errorf(reviewUsage)
	}

	iterations := 10
	if len(args) == 3 {
		parsedIterations, err := strconv.Atoi(args[2])
		if err != nil || parsedIterations <= 0 {
			return reviewRequest{}, fmt.Errorf("iterations must be a positive integer")
		}
		iterations = parsedIterations
	}

	if branchExistsFn == nil {
		branchExistsFn = gitBranchResolvable
	}

	exists, err := branchExistsFn(baseBranch)
	if err != nil {
		return reviewRequest{}, fmt.Errorf("failed to verify base branch %q: %w", baseBranch, err)
	}
	if !exists {
		return reviewRequest{}, fmt.Errorf("base branch %s not found", baseBranch)
	}

	return reviewRequest{
		BaseBranch: baseBranch,
		Iterations: iterations,
	}, nil
}

func gitBranchResolvable(branch string) (bool, error) {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return false, nil
	}

	exists, err := gitRefExists(branch)
	if err != nil || exists {
		return exists, err
	}

	if strings.Contains(branch, "/") {
		return false, nil
	}

	return gitRefExists("origin/" + branch)
}

func gitRefExists(ref string) (bool, error) {
	cmd := exec.Command("git", "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	err := cmd.Run()
	if err == nil {
		return true, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}

	return false, err
}
