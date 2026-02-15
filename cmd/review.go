package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
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
	runLoop:          runCodexReviewLoop,
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

type codexReviewLoopDeps struct {
	newEngine           func(name string) (engine.Engine, error)
	runLoop             func(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*compound.ReviewLoopResult, error)
	writeJSONReport     func(dir string, result *compound.ReviewLoopResult) (string, error)
	writeMarkdownReport func(dir string, result *compound.ReviewLoopResult) (string, error)
	buildMarkdown       func(result *compound.ReviewLoopResult) (string, error)
	renderMarkdown      func(markdown string) (string, error)
}

var defaultCodexReviewLoopDeps = codexReviewLoopDeps{
	newEngine:           newEngine,
	runLoop:             compound.RunCodexReviewLoop,
	writeJSONReport:     compound.WriteReviewLoopJSONReport,
	writeMarkdownReport: compound.WriteReviewLoopMarkdownReport,
	buildMarkdown:       compound.ReviewLoopMarkdown,
	renderMarkdown:      renderMarkdownWithGlamour,
}

func runCodexReviewLoop(ctx context.Context, req reviewRequest) error {
	return runCodexReviewLoopWithDeps(ctx, req, os.Stdout, defaultCodexReviewLoopDeps)
}

func runCodexReviewLoopWithDeps(ctx context.Context, req reviewRequest, out io.Writer, deps codexReviewLoopDeps) error {
	if deps.newEngine == nil {
		deps.newEngine = newEngine
	}
	if deps.runLoop == nil {
		deps.runLoop = compound.RunCodexReviewLoop
	}
	if deps.writeJSONReport == nil {
		deps.writeJSONReport = compound.WriteReviewLoopJSONReport
	}
	if deps.writeMarkdownReport == nil {
		deps.writeMarkdownReport = compound.WriteReviewLoopMarkdownReport
	}
	if deps.buildMarkdown == nil {
		deps.buildMarkdown = compound.ReviewLoopMarkdown
	}
	if deps.renderMarkdown == nil {
		deps.renderMarkdown = renderMarkdownWithGlamour
	}

	eng, err := deps.newEngine("codex")
	if err != nil {
		return fmt.Errorf("failed to create codex engine: %w", err)
	}

	result, err := deps.runLoop(ctx, eng, req.BaseBranch, req.Iterations)
	if err != nil {
		return fmt.Errorf("codex review loop failed: %w", err)
	}

	if _, err := deps.writeJSONReport(".", result); err != nil {
		return fmt.Errorf("failed to write review loop JSON report: %w", err)
	}

	if _, err := deps.writeMarkdownReport(".", result); err != nil {
		return fmt.Errorf("failed to write review loop markdown report: %w", err)
	}

	markdown, err := deps.buildMarkdown(result)
	if err != nil {
		return fmt.Errorf("failed to build review loop markdown summary: %w", err)
	}

	rendered, err := deps.renderMarkdown(markdown)
	if err != nil {
		return fmt.Errorf("failed to render review loop markdown summary: %w", err)
	}

	if out != nil {
		fmt.Fprint(out, rendered)
	}

	return nil
}

func renderMarkdownWithGlamour(markdown string) (string, error) {
	renderer, err := glamour.NewTermRenderer(glamour.WithAutoStyle())
	if err != nil {
		return "", fmt.Errorf("failed to create glamour renderer: %w", err)
	}

	rendered, err := renderer.Render(markdown)
	if err != nil {
		return "", fmt.Errorf("failed to render markdown with glamour: %w", err)
	}

	return rendered, nil
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
