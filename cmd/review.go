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
	Engine     string
}

type reviewDeps struct {
	resolveBaseBranch func(branch string) (string, error)
	runLoop           func(ctx context.Context, req reviewRequest, out io.Writer) error
}

var defaultReviewDeps = reviewDeps{
	resolveBaseBranch: gitResolveBranchRef,
	runLoop:           runReviewLoopCommand,
}

var reviewEngineFlag string

var reviewCmd = &cobra.Command{
	Use:   "review against <base-branch> [iterations]",
	Short: "Run an iterative review loop against a base branch",
	Long: `Run an iterative review-and-fix loop against a base branch.

This command powers branch-vs-branch review loops.
Use 'hal report' for legacy session reporting.`,
	Example: `  hal review against develop
  hal review against origin/main 5
  hal review against develop 3 -e codex
  hal review -e pi against develop 3
  hal review -e claude against develop 3`,
	RunE: runReview,
}

func init() {
	reviewCmd.Flags().StringVarP(&reviewEngineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")
	rootCmd.AddCommand(reviewCmd)
}

func runReview(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	engineName := reviewEngineFlag
	out := io.Writer(os.Stdout)
	if cmd != nil {
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		var err error
		engineName, err = cmd.Flags().GetString("engine")
		if err != nil {
			return err
		}
		out = cmd.OutOrStdout()
	}

	return runReviewWithDeps(ctx, args, engineName, out, defaultReviewDeps)
}

func runReviewWithDeps(ctx context.Context, args []string, engineName string, out io.Writer, deps reviewDeps) error {
	if deps.resolveBaseBranch == nil {
		deps.resolveBaseBranch = gitResolveBranchRef
	}
	if deps.runLoop == nil {
		deps.runLoop = defaultReviewDeps.runLoop
	}
	if out == nil {
		out = os.Stdout
	}

	req, err := parseReviewRequest(args, deps.resolveBaseBranch)
	if err != nil {
		return err
	}
	req.Engine = normalizeReviewEngine(engineName)

	return deps.runLoop(ctx, req, out)
}

type reviewLoopDeps struct {
	newEngine           func(name string) (engine.Engine, error)
	runLoop             func(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*compound.ReviewLoopResult, error)
	writeJSONReport     func(dir string, result *compound.ReviewLoopResult) (string, error)
	writeMarkdownReport func(dir string, result *compound.ReviewLoopResult) (string, error)
	buildMarkdown       func(result *compound.ReviewLoopResult) (string, error)
	renderMarkdown      func(markdown string) (string, error)
}

var defaultReviewLoopDeps = reviewLoopDeps{
	newEngine:           newEngine,
	runLoop:             compound.RunReviewLoopWithDisplay,
	writeJSONReport:     compound.WriteReviewLoopJSONReport,
	writeMarkdownReport: compound.WriteReviewLoopMarkdownReport,
	buildMarkdown:       compound.ReviewLoopMarkdown,
	renderMarkdown:      renderMarkdownWithGlamour,
}

func runReviewLoopCommand(ctx context.Context, req reviewRequest, out io.Writer) error {
	if out == nil {
		out = os.Stdout
	}
	return runReviewLoopWithDeps(ctx, req, out, defaultReviewLoopDeps)
}

func runReviewLoopWithDeps(ctx context.Context, req reviewRequest, out io.Writer, deps reviewLoopDeps) error {
	if deps.newEngine == nil {
		deps.newEngine = newEngine
	}
	if deps.runLoop == nil {
		deps.runLoop = compound.RunReviewLoopWithDisplay
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

	engineName := normalizeReviewEngine(req.Engine)
	eng, err := deps.newEngine(engineName)
	if err != nil {
		return fmt.Errorf("failed to create %s engine: %w", engineName, err)
	}

	var display *engine.Display
	if shouldShowInteractiveReviewProgress(out) {
		display = engine.NewDisplay(out)
		display.ShowCommandHeader("Review", fmt.Sprintf("against %s (%d iterations)", req.BaseBranch, req.Iterations), buildHeaderCtx(engineName))
	}

	result, err := deps.runLoop(ctx, eng, display, req.BaseBranch, req.Iterations)
	if err != nil {
		return fmt.Errorf("review loop failed with %s: %w", engineName, err)
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

func normalizeReviewEngine(name string) string {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return "codex"
	}
	return normalized
}

func shouldShowInteractiveReviewProgress(out io.Writer) bool {
	if out == nil {
		return false
	}
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	return file == os.Stdout
}

func parseReviewRequest(args []string, resolveBranchFn func(branch string) (string, error)) (reviewRequest, error) {
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

	if resolveBranchFn == nil {
		resolveBranchFn = gitResolveBranchRef
	}

	resolvedBaseBranch, err := resolveBranchFn(baseBranch)
	if err != nil {
		return reviewRequest{}, fmt.Errorf("failed to verify base branch %q: %w", baseBranch, err)
	}
	if strings.TrimSpace(resolvedBaseBranch) == "" {
		return reviewRequest{}, fmt.Errorf("base branch %s not found", baseBranch)
	}

	return reviewRequest{
		BaseBranch: resolvedBaseBranch,
		Iterations: iterations,
	}, nil
}

func gitResolveBranchRef(branch string) (string, error) {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return "", nil
	}

	exists, err := gitRefExists(branch)
	if err != nil {
		return "", err
	}
	if exists {
		return branch, nil
	}

	if strings.HasPrefix(branch, "origin/") {
		return "", nil
	}

	remoteBranch := "origin/" + branch
	exists, err = gitRefExists(remoteBranch)
	if err != nil {
		return "", err
	}
	if exists {
		return remoteBranch, nil
	}

	return "", nil
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
