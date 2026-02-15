package cmd

import (
	"context"
	"encoding/json"
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

const (
	reviewUsage       = "usage: hal review against <base-branch> [iterations]"
	reviewOutputJSON  = "json"
	reviewOutputHuman = "human"
	reviewOutputBoth  = "both"
)

type reviewRequest struct {
	BaseBranch string
	Iterations int
	OutputMode string
	Engine     string
}

type reviewDeps struct {
	baseBranchExists func(branch string) (bool, error)
	runLoop          func(ctx context.Context, req reviewRequest) error
}

var defaultReviewDeps = reviewDeps{
	baseBranchExists: gitBranchResolvable,
	runLoop:          runReviewLoopCommand,
}

var reviewOutputFlag string
var reviewEngineFlag string

var reviewCmd = &cobra.Command{
	Use:   "review against <base-branch> [iterations]",
	Short: "Run an iterative review loop against a base branch",
	Long: `Run an iterative review-and-fix loop against a base branch.

This command powers branch-vs-branch review loops.
Use 'hal report' for legacy session reporting.`,
	Example: `  hal review against develop
  hal review against origin/main 5
  hal review against develop 3 -e codex`,
	RunE: runReview,
}

func init() {
	reviewCmd.Flags().StringVar(&reviewOutputFlag, "output", reviewOutputBoth, "Output mode: human, json, both")
	reviewCmd.Flags().StringVarP(&reviewEngineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")
	rootCmd.AddCommand(reviewCmd)
}

func runReview(cmd *cobra.Command, args []string) error {
	outputMode := reviewOutputFlag
	engineName := reviewEngineFlag
	if cmd != nil {
		var err error
		outputMode, err = cmd.Flags().GetString("output")
		if err != nil {
			return err
		}
		engineName, err = cmd.Flags().GetString("engine")
		if err != nil {
			return err
		}
	}

	return runReviewWithDeps(context.Background(), args, outputMode, engineName, defaultReviewDeps)
}

func runReviewWithDeps(ctx context.Context, args []string, outputMode, engineName string, deps reviewDeps) error {
	if deps.baseBranchExists == nil {
		deps.baseBranchExists = gitBranchResolvable
	}
	if deps.runLoop == nil {
		deps.runLoop = defaultReviewDeps.runLoop
	}

	normalizedOutputMode, err := normalizeReviewOutputMode(outputMode)
	if err != nil {
		return err
	}

	req, err := parseReviewRequest(args, deps.baseBranchExists)
	if err != nil {
		return err
	}
	req.OutputMode = normalizedOutputMode
	req.Engine = normalizeReviewEngine(engineName)

	return deps.runLoop(ctx, req)
}

type reviewLoopDeps struct {
	newEngine           func(name string) (engine.Engine, error)
	runLoop             func(ctx context.Context, eng engine.Engine, baseBranch string, requestedIterations int) (*compound.ReviewLoopResult, error)
	writeJSONReport     func(dir string, result *compound.ReviewLoopResult) (string, error)
	writeMarkdownReport func(dir string, result *compound.ReviewLoopResult) (string, error)
	buildMarkdown       func(result *compound.ReviewLoopResult) (string, error)
	renderMarkdown      func(markdown string) (string, error)
}

var defaultReviewLoopDeps = reviewLoopDeps{
	newEngine:           newEngine,
	runLoop:             compound.RunReviewLoop,
	writeJSONReport:     compound.WriteReviewLoopJSONReport,
	writeMarkdownReport: compound.WriteReviewLoopMarkdownReport,
	buildMarkdown:       compound.ReviewLoopMarkdown,
	renderMarkdown:      renderMarkdownWithGlamour,
}

func runReviewLoopCommand(ctx context.Context, req reviewRequest) error {
	return runReviewLoopWithDeps(ctx, req, os.Stdout, defaultReviewLoopDeps)
}

func runReviewLoopWithDeps(ctx context.Context, req reviewRequest, out io.Writer, deps reviewLoopDeps) error {
	if deps.newEngine == nil {
		deps.newEngine = newEngine
	}
	if deps.runLoop == nil {
		deps.runLoop = compound.RunReviewLoop
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

	outputMode, err := normalizeReviewOutputMode(req.OutputMode)
	if err != nil {
		return err
	}

	engineName := normalizeReviewEngine(req.Engine)
	eng, err := deps.newEngine(engineName)
	if err != nil {
		return fmt.Errorf("failed to create %s engine: %w", engineName, err)
	}

	result, err := deps.runLoop(ctx, eng, req.BaseBranch, req.Iterations)
	if err != nil {
		return fmt.Errorf("review loop failed with %s: %w", engineName, err)
	}

	if _, err := deps.writeJSONReport(".", result); err != nil {
		return fmt.Errorf("failed to write review loop JSON report: %w", err)
	}

	if _, err := deps.writeMarkdownReport(".", result); err != nil {
		return fmt.Errorf("failed to write review loop markdown report: %w", err)
	}

	switch outputMode {
	case reviewOutputJSON:
		if err := writeReviewLoopJSONOutput(out, result); err != nil {
			return err
		}
		return nil
	case reviewOutputHuman, reviewOutputBoth:
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

func normalizeReviewOutputMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", reviewOutputBoth:
		return reviewOutputBoth, nil
	case reviewOutputHuman:
		return reviewOutputHuman, nil
	case reviewOutputJSON:
		return reviewOutputJSON, nil
	default:
		return "", fmt.Errorf("output must be one of: human, json, both")
	}
}

func normalizeReviewEngine(name string) string {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return "codex"
	}
	return normalized
}

func writeReviewLoopJSONOutput(out io.Writer, result *compound.ReviewLoopResult) error {
	if out == nil {
		return nil
	}

	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal review loop result JSON output: %w", err)
	}
	payload = append(payload, '\n')

	if _, err := out.Write(payload); err != nil {
		return fmt.Errorf("failed to write review loop JSON output: %w", err)
	}

	return nil
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
