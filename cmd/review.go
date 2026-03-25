package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	reviewUsage        = "usage: hal review --base <base-branch> [iterations]"
	reviewAgainstUsage = "usage: hal review against <base-branch> [iterations]"
)

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

var (
	reviewEngineFlag     string
	reviewBaseFlag       string
	reviewIterationsFlag int
	reviewJSONFlag       bool
)

var reviewCmd = &cobra.Command{
	Use:   "review --base <base-branch> [iterations]",
	Short: "Run an iterative review loop against a base branch",
	Long: `Run an iterative review-and-fix loop against a base branch.

This command powers branch-vs-branch review loops.
Use 'hal report' for legacy session reporting.`,
	Example: `  hal review --base develop
  hal review --base develop --json
  hal review --base origin/main 5
  hal review --base develop --iterations 3 -e codex
  hal review against develop 3   # Deprecated alias`,
	Args: cobra.ArbitraryArgs,
	RunE: runReview,
}

func init() {
	reviewCmd.Flags().StringVar(&reviewBaseFlag, "base", "", "Base branch to review against")
	reviewCmd.Flags().IntVarP(&reviewIterationsFlag, "iterations", "i", 10, "Maximum review iterations")
	reviewCmd.Flags().StringVarP(&reviewEngineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")
	reviewCmd.Flags().BoolVar(&reviewJSONFlag, "json", false, "Output machine-readable JSON result (skip terminal rendering)")
	rootCmd.AddCommand(reviewCmd)
}

func runReview(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	out := io.Writer(os.Stdout)
	errOut := io.Writer(os.Stderr)
	engineName := reviewEngineFlag
	baseBranch := reviewBaseFlag
	iterations := reviewIterationsFlag
	baseChanged := false
	iterationsChanged := false

	if cmd != nil {
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		out = cmd.OutOrStdout()
		errOut = cmd.ErrOrStderr()

		var err error
		engineName, err = cmd.Flags().GetString("engine")
		if err != nil {
			return err
		}
		baseBranch, err = cmd.Flags().GetString("base")
		if err != nil {
			return err
		}
		iterations, err = cmd.Flags().GetInt("iterations")
		if err != nil {
			return err
		}

		baseChanged = cmd.Flags().Changed("base")
		iterationsChanged = cmd.Flags().Changed("iterations")
	}

	resolvedEngine, err := resolveEngine(cmd, "engine", engineName, ".")
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	req, err := parseReviewRequest(args, baseBranch, baseChanged, iterations, iterationsChanged, defaultReviewDeps.resolveBaseBranch, errOut)
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}
	req.Engine = resolvedEngine

	if reviewJSONFlag {
		return runReviewLoopJSON(ctx, req, out, defaultReviewLoopDeps)
	}
	return defaultReviewDeps.runLoop(ctx, req, out)
}

// runReviewWithDeps is a legacy helper used by tests to validate parsing and deps wiring.
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

	req, err := parseReviewRequest(args, "", false, 10, false, deps.resolveBaseBranch, nil)
	if err != nil {
		return err
	}
	req.Engine = normalizeReviewEngine(engineName)

	return deps.runLoop(ctx, req, out)
}

type reviewLoopDeps struct {
	newEngine           func(name string) (engine.Engine, error)
	runLoop             func(ctx context.Context, eng engine.Engine, display *engine.Display, baseBranch string, requestedIterations int) (*compound.ReviewLoopResult, error)
	writeReports        func(dir string, result *compound.ReviewLoopResult) (jsonPath string, markdownPath string, err error)
	writeJSONReport     func(dir string, result *compound.ReviewLoopResult) (string, error)
	writeMarkdownReport func(dir string, result *compound.ReviewLoopResult) (string, error)
	buildMarkdown       func(result *compound.ReviewLoopResult) (string, error)
	renderMarkdown      func(markdown string) (string, error)
}

var defaultReviewLoopDeps = reviewLoopDeps{
	newEngine:           newEngine,
	runLoop:             compound.RunReviewLoopWithDisplay,
	writeReports:        compound.WriteReviewLoopReports,
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
	if deps.writeReports == nil && deps.writeJSONReport == nil && deps.writeMarkdownReport == nil {
		deps.writeReports = compound.WriteReviewLoopReports
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
	result.Engine = engineName

	if deps.writeReports != nil {
		if _, _, err := deps.writeReports(".", result); err != nil {
			return fmt.Errorf("failed to write review loop reports: %w", err)
		}
	} else {
		if _, err := deps.writeJSONReport(".", result); err != nil {
			return fmt.Errorf("failed to write review loop JSON report: %w", err)
		}

		if _, err := deps.writeMarkdownReport(".", result); err != nil {
			return fmt.Errorf("failed to write review loop markdown report: %w", err)
		}
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

func runReviewLoopJSON(ctx context.Context, req reviewRequest, out io.Writer, deps reviewLoopDeps) error {
	if deps.newEngine == nil {
		deps.newEngine = newEngine
	}
	if deps.runLoop == nil {
		deps.runLoop = compound.RunReviewLoopWithDisplay
	}
	if deps.writeReports == nil && deps.writeJSONReport == nil && deps.writeMarkdownReport == nil {
		deps.writeReports = compound.WriteReviewLoopReports
	}
	if deps.writeJSONReport == nil {
		deps.writeJSONReport = compound.WriteReviewLoopJSONReport
	}
	if deps.writeMarkdownReport == nil {
		deps.writeMarkdownReport = compound.WriteReviewLoopMarkdownReport
	}

	engineName := normalizeReviewEngine(req.Engine)
	eng, err := deps.newEngine(engineName)
	if err != nil {
		return fmt.Errorf("failed to create %s engine: %w", engineName, err)
	}

	result, err := deps.runLoop(ctx, eng, nil, req.BaseBranch, req.Iterations)
	if err != nil {
		return fmt.Errorf("review loop failed with %s: %w", engineName, err)
	}
	result.Engine = engineName

	// Write reports
	if deps.writeReports != nil {
		if _, _, err := deps.writeReports(".", result); err != nil {
			return fmt.Errorf("failed to write review loop reports: %w", err)
		}
	} else {
		if _, err := deps.writeJSONReport(".", result); err != nil {
			return fmt.Errorf("failed to write review loop JSON report: %w", err)
		}
		if _, err := deps.writeMarkdownReport(".", result); err != nil {
			return fmt.Errorf("failed to write review loop markdown report: %w", err)
		}
	}

	// Output as JSON to stdout
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal review result: %w", err)
	}
	fmt.Fprintln(out, string(data))
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
	return term.IsTerminal(int(file.Fd()))
}

func parseReviewRequest(
	args []string,
	baseFlag string,
	baseFlagChanged bool,
	iterationsFlag int,
	iterationsFlagChanged bool,
	resolveBranchFn func(branch string) (string, error),
	warnW io.Writer,
) (reviewRequest, error) {
	var (
		baseBranch string
		iterations int
	)

	if len(args) > 0 && args[0] == "against" {
		if baseFlagChanged {
			return reviewRequest{}, fmt.Errorf("cannot use --base with deprecated 'against' syntax")
		}
		if iterationsFlagChanged {
			return reviewRequest{}, fmt.Errorf("cannot use --iterations with deprecated 'against' syntax")
		}
		if len(args) < 2 || len(args) > 3 {
			return reviewRequest{}, fmt.Errorf(reviewAgainstUsage)
		}

		baseBranch = strings.TrimSpace(args[1])
		if baseBranch == "" {
			return reviewRequest{}, fmt.Errorf(reviewAgainstUsage)
		}

		aliasIterations := []string{}
		if len(args) == 3 {
			aliasIterations = []string{args[2]}
		}
		parsedIterations, err := parseIterations(aliasIterations, 10, false, 10)
		if err != nil {
			return reviewRequest{}, err
		}
		iterations = parsedIterations

		warnDeprecated(warnW, "'hal review against <base-branch> [iterations]' is deprecated; use 'hal review --base <base-branch> [iterations]'")
	} else {
		if len(args) > 1 {
			return reviewRequest{}, fmt.Errorf(reviewUsage)
		}

		baseBranch = strings.TrimSpace(baseFlag)
		if baseBranch == "" {
			return reviewRequest{}, fmt.Errorf("--base is required (or use deprecated 'against' syntax)")
		}

		parsedIterations, err := parseIterations(args, iterationsFlag, iterationsFlagChanged, 10)
		if err != nil {
			return reviewRequest{}, err
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
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		return true, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() == 1 {
			return false, nil
		}

		stderrMsg := strings.TrimSpace(stderr.String())
		if stderrMsg != "" {
			return false, fmt.Errorf("git rev-parse --verify %q failed: %s", ref, stderrMsg)
		}
	}

	return false, fmt.Errorf("git rev-parse --verify %q failed: %w", ref, err)
}
