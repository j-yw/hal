package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	ci "github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/spf13/cobra"
)

var (
	ciPushDryRunFlag bool
	ciPushJSONFlag   bool

	ciStatusWaitFlag          bool
	ciStatusTimeoutFlag       time.Duration
	ciStatusPollIntervalFlag  time.Duration
	ciStatusNoChecksGraceFlag time.Duration
	ciStatusJSONFlag          bool

	ciFixMaxAttemptsFlag int
	ciFixEngineFlag      string
	ciFixJSONFlag        bool

	ciMergeStrategyFlag      string
	ciMergeDeleteBranchFlag  bool
	ciMergeAllowNoChecksFlag bool
	ciMergeDryRunFlag        bool
	ciMergeJSONFlag          bool
)

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "Run CI workflow commands",
	Long: `Run CI-aware workflow commands.

Use subcommands to push branches, inspect CI status, apply fixes, and merge safely.

Examples:
  hal ci push
  hal ci status --wait
  hal ci fix --max-attempts 2
  hal ci merge --strategy squash`,
	Example: `  hal ci push
  hal ci status --wait
  hal ci fix --max-attempts 2
  hal ci merge --strategy squash`,
}

var ciPushCmd = &cobra.Command{
	Use:   "push",
	Short: "Push current branch and create or reuse a pull request",
	Args:  noArgsValidation(),
	Long: `Push the current branch to origin and create or reuse an open pull request.

By default, this command delegates to the shared CI core operation.
Use --dry-run to preview behavior with no remote side effects.
Use --json for machine-readable output.`,
	Example: `  hal ci push
  hal ci push --dry-run
  hal ci push --json`,
	RunE: runCIPush,
}

var ciStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show aggregated CI status for the current branch",
	Args:  noArgsValidation(),
	Long: `Show aggregated CI status for the current branch.

By default, this command returns the latest aggregated status immediately.
Use --wait to poll until checks complete, timeout, or no checks are detected.
Use --json for machine-readable output.`,
	Example: `  hal ci status
  hal ci status --wait
  hal ci status --wait --json`,
	RunE: runCIStatus,
}

var ciFixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Auto-fix failing CI checks using an engine",
	Args:  noArgsValidation(),
	Long: `Apply focused CI fixes for failing checks using the configured engine.

The command retries up to --max-attempts. Each attempt uses the shared
single-attempt CI fix core operation and waits for fresh CI status before
continuing. Use --json for machine-readable output.`,
	Example: `  hal ci fix
  hal ci fix --max-attempts 3
  hal ci fix -e claude
  hal ci fix --json`,
	RunE: runCIFix,
}

var ciMergeCmd = &cobra.Command{
	Use:   "merge",
	Short: "Merge the open pull request for the current branch",
	Args:  noArgsValidation(),
	Long: `Merge the open pull request for the current branch with CI safety guards.

By default this command uses the squash strategy and requires passing CI
status. Use --allow-no-checks only when you intentionally want to override
no-check safety guards. Use --dry-run to preview behavior without merge or
remote branch deletion side effects. Use --json for machine-readable output.`,
	Example: `  hal ci merge
  hal ci merge --strategy rebase
  hal ci merge --delete-branch
  hal ci merge --dry-run --json`,
	RunE: runCIMerge,
}

func init() {
	ciPushCmd.Flags().BoolVar(&ciPushDryRunFlag, "dry-run", false, "Preview push/PR behavior without remote side effects")
	ciPushCmd.Flags().BoolVar(&ciPushJSONFlag, "json", false, "Output machine-readable JSON result")

	ciStatusCmd.Flags().BoolVar(&ciStatusWaitFlag, "wait", false, "Wait for checks to complete, timeout, or no-check detection")
	ciStatusCmd.Flags().DurationVar(&ciStatusTimeoutFlag, "timeout", 0, "Wait timeout override (default: internal ci wait timeout)")
	ciStatusCmd.Flags().DurationVar(&ciStatusPollIntervalFlag, "poll-interval", 0, "Polling interval override while waiting (default: internal ci poll interval)")
	ciStatusCmd.Flags().DurationVar(&ciStatusNoChecksGraceFlag, "no-checks-grace", 0, "No-checks grace override before returning no_checks_detected")
	ciStatusCmd.Flags().BoolVar(&ciStatusJSONFlag, "json", false, "Output machine-readable JSON result")

	ciFixCmd.Flags().IntVar(&ciFixMaxAttemptsFlag, "max-attempts", 3, "Max fix attempts before stopping")
	ciFixCmd.Flags().StringVarP(&ciFixEngineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")
	ciFixCmd.Flags().BoolVar(&ciFixJSONFlag, "json", false, "Output machine-readable JSON result")

	ciMergeCmd.Flags().StringVar(&ciMergeStrategyFlag, "strategy", "squash", "Merge strategy (squash, merge, rebase)")
	ciMergeCmd.Flags().BoolVar(&ciMergeDeleteBranchFlag, "delete-branch", false, "Delete remote branch after successful merge")
	ciMergeCmd.Flags().BoolVar(&ciMergeAllowNoChecksFlag, "allow-no-checks", false, "Allow merge when no CI checks are discovered")
	ciMergeCmd.Flags().BoolVar(&ciMergeDryRunFlag, "dry-run", false, "Preview merge behavior without merge or remote branch deletion side effects")
	ciMergeCmd.Flags().BoolVar(&ciMergeJSONFlag, "json", false, "Output machine-readable JSON result")

	ciCmd.AddCommand(ciPushCmd)
	ciCmd.AddCommand(ciStatusCmd)
	ciCmd.AddCommand(ciFixCmd)
	ciCmd.AddCommand(ciMergeCmd)
	rootCmd.AddCommand(ciCmd)
}

type ciPushDeps struct {
	pushAndCreatePR func(context.Context, ci.PushOptions) (ci.PushResult, error)
	currentBranch   func(context.Context) (string, error)
}

var defaultCIPushDeps = ciPushDeps{
	pushAndCreatePR: ci.PushAndCreatePR,
	currentBranch:   ciCurrentBranch,
}

type ciPushRunOptions struct {
	DryRun bool
	JSON   bool
}

type ciStatusDeps struct {
	getStatus     func(context.Context) (ci.StatusResult, error)
	waitForChecks func(context.Context, ci.WaitOptions) (ci.StatusResult, error)
}

var defaultCIStatusDeps = ciStatusDeps{
	getStatus:     ci.GetStatus,
	waitForChecks: ci.WaitForChecks,
}

type ciStatusRunOptions struct {
	Wait          bool
	Timeout       time.Duration
	PollInterval  time.Duration
	NoChecksGrace time.Duration
	JSON          bool
}

type ciFixDeps struct {
	newEngine     func(string) (engine.Engine, error)
	resolveEngine func(string) (string, error)
	getStatus     func(context.Context) (ci.StatusResult, error)
	waitForChecks func(context.Context, ci.WaitOptions) (ci.StatusResult, error)
	fixWithEngine func(context.Context, ci.StatusResult, ci.FixOptions) (ci.FixResult, error)
}

var defaultCIFixDeps = ciFixDeps{
	newEngine:     newEngine,
	getStatus:     ci.GetStatus,
	waitForChecks: ci.WaitForChecks,
	fixWithEngine: ci.FixWithEngine,
}

type ciFixRunOptions struct {
	MaxAttempts int
	Engine      string
	JSON        bool
}

type ciMergeDeps struct {
	mergePR       func(context.Context, ci.MergeOptions) (ci.MergeResult, error)
	currentBranch func(context.Context) (string, error)
}

var defaultCIMergeDeps = ciMergeDeps{
	mergePR:       ci.MergePR,
	currentBranch: ciCurrentBranch,
}

type ciMergeRunOptions struct {
	Strategy      string
	DeleteBranch  bool
	AllowNoChecks bool
	DryRun        bool
	JSON          bool
}

const ciFieldValueColumn = 10

func ciWriteField(out io.Writer, label string, value string) {
	padding := ciFieldValueColumn - len(label)
	if padding < 1 {
		padding = 1
	}
	fmt.Fprintf(out, "%s%s%s\n", engine.StyleBold.Render(label), strings.Repeat(" ", padding), value)
}

func ciShortSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) > 7 {
		sha = sha[:7]
	}
	return sha
}

func ciRenderStatusValue(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case ci.StatusPassing:
		return engine.StyleSuccess.Render("✓ passing")
	case ci.StatusFailing:
		return engine.StyleError.Render("✗ failing")
	case ci.StatusPending:
		return engine.StyleWarning.Render("⚠ pending")
	default:
		return engine.StyleMuted.Render(strings.TrimSpace(status))
	}
}

func ciRenderCheckIcon(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case ci.StatusPassing:
		return engine.StyleSuccess.Render("✓")
	case ci.StatusFailing:
		return engine.StyleError.Render("✗")
	default:
		return engine.StyleWarning.Render("⚠")
	}
}

func ciRenderTotals(totals ci.StatusTotals) string {
	parts := make([]string, 0, 3)
	if totals.Passing > 0 {
		parts = append(parts, fmt.Sprintf("%d passing", totals.Passing))
	}
	if totals.Failing > 0 {
		parts = append(parts, fmt.Sprintf("%d failing", totals.Failing))
	}
	if totals.Pending > 0 {
		parts = append(parts, fmt.Sprintf("%d pending", totals.Pending))
	}
	if len(parts) == 0 {
		return "0 checks"
	}
	return strings.Join(parts, " · ")
}

func runCIPush(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	out := io.Writer(os.Stdout)
	opts := ciPushRunOptions{
		DryRun: ciPushDryRunFlag,
		JSON:   ciPushJSONFlag,
	}

	if cmd != nil {
		out = cmd.OutOrStdout()
		if flags := cmd.Flags(); flags != nil {
			if flags.Lookup("dry-run") != nil {
				v, err := flags.GetBool("dry-run")
				if err != nil {
					return err
				}
				opts.DryRun = v
			}
			if flags.Lookup("json") != nil {
				v, err := flags.GetBool("json")
				if err != nil {
					return err
				}
				opts.JSON = v
			}
		}
	}

	return runCIPushWithDeps(ctx, opts, out, defaultCIPushDeps)
}

func runCIPushWithDeps(ctx context.Context, opts ciPushRunOptions, out io.Writer, deps ciPushDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		out = os.Stdout
	}
	if deps.pushAndCreatePR == nil {
		deps.pushAndCreatePR = defaultCIPushDeps.pushAndCreatePR
	}
	if deps.currentBranch == nil {
		deps.currentBranch = defaultCIPushDeps.currentBranch
	}

	var (
		result ci.PushResult
		err    error
	)

	if opts.DryRun {
		branch, branchErr := deps.currentBranch(ctx)
		if branchErr != nil {
			return branchErr
		}
		result = ci.PushResult{
			ContractVersion: ci.PushContractVersion,
			Branch:          branch,
			Pushed:          false,
			DryRun:          true,
			PullRequest: ci.PullRequest{
				HeadRef:  branch,
				Draft:    true,
				Existing: false,
			},
			Summary: fmt.Sprintf("dry-run: would push branch %s and create or reuse a pull request", branch),
		}
	} else {
		result, err = deps.pushAndCreatePR(ctx, ci.PushOptions{})
		if err != nil {
			return err
		}
	}

	if opts.JSON {
		data, marshalErr := json.MarshalIndent(result, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("failed to marshal ci push result: %w", marshalErr)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	if result.DryRun {
		fmt.Fprintf(out, "%s\n", engine.StyleTitle.Render("CI Push (dry run)"))
		ciWriteField(out, "Branch:", engine.StyleInfo.Render(result.Branch))
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s\n", engine.StyleMuted.Render("Would push branch and create or reuse a pull request."))
		return nil
	}

	fmt.Fprintf(out, "%s\n", engine.StyleTitle.Render("CI Push"))
	ciWriteField(out, "Branch:", engine.StyleInfo.Render(result.Branch))
	ciWriteField(out, "Status:", engine.StyleSuccess.Render("✓ Pushed"))

	if result.PullRequest.URL == "" {
		return nil
	}

	fmt.Fprintln(out)
	prLabel := "PR:"
	if result.PullRequest.Number > 0 {
		prLabel = fmt.Sprintf("PR #%d:", result.PullRequest.Number)
	}
	ciWriteField(out, prLabel, engine.StyleInfo.Render(result.PullRequest.URL))

	prDetail := "Draft"
	if !result.PullRequest.Draft {
		prDetail = "Ready for review"
	}
	if result.PullRequest.Existing {
		prDetail += " · Existing"
	} else {
		prDetail += " · New"
	}
	fmt.Fprintf(out, "%s%s\n", strings.Repeat(" ", ciFieldValueColumn), engine.StyleMuted.Render(prDetail))
	return nil
}

func runCIStatus(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	out := io.Writer(os.Stdout)
	opts := ciStatusRunOptions{
		Wait:          ciStatusWaitFlag,
		Timeout:       ciStatusTimeoutFlag,
		PollInterval:  ciStatusPollIntervalFlag,
		NoChecksGrace: ciStatusNoChecksGraceFlag,
		JSON:          ciStatusJSONFlag,
	}

	if cmd != nil {
		out = cmd.OutOrStdout()
		if flags := cmd.Flags(); flags != nil {
			if flags.Lookup("wait") != nil {
				v, err := flags.GetBool("wait")
				if err != nil {
					return err
				}
				opts.Wait = v
			}
			if flags.Lookup("timeout") != nil {
				v, err := flags.GetDuration("timeout")
				if err != nil {
					return err
				}
				opts.Timeout = v
			}
			if flags.Lookup("poll-interval") != nil {
				v, err := flags.GetDuration("poll-interval")
				if err != nil {
					return err
				}
				opts.PollInterval = v
			}
			if flags.Lookup("no-checks-grace") != nil {
				v, err := flags.GetDuration("no-checks-grace")
				if err != nil {
					return err
				}
				opts.NoChecksGrace = v
			}
			if flags.Lookup("json") != nil {
				v, err := flags.GetBool("json")
				if err != nil {
					return err
				}
				opts.JSON = v
			}
		}
	}

	return runCIStatusWithDeps(ctx, opts, out, defaultCIStatusDeps)
}

func runCIStatusWithDeps(ctx context.Context, opts ciStatusRunOptions, out io.Writer, deps ciStatusDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		out = os.Stdout
	}
	if deps.getStatus == nil {
		deps.getStatus = defaultCIStatusDeps.getStatus
	}
	if deps.waitForChecks == nil {
		deps.waitForChecks = defaultCIStatusDeps.waitForChecks
	}

	var (
		result ci.StatusResult
		err    error
	)

	if opts.Wait {
		result, err = deps.waitForChecks(ctx, ci.WaitOptions{
			PollInterval:  opts.PollInterval,
			Timeout:       opts.Timeout,
			NoChecksGrace: opts.NoChecksGrace,
		})
	} else {
		result, err = deps.getStatus(ctx)
	}
	if err != nil {
		return err
	}

	if opts.JSON {
		data, marshalErr := json.MarshalIndent(result, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("failed to marshal ci status result: %w", marshalErr)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	fmt.Fprintf(out, "%s\n", engine.StyleTitle.Render("CI Status"))
	ciWriteField(out, "Branch:", engine.StyleInfo.Render(result.Branch))
	ciWriteField(out, "SHA:", engine.StyleMuted.Render(ciShortSHA(result.SHA)))
	ciWriteField(out, "Status:", ciRenderStatusValue(result.Status))

	if opts.Wait && strings.TrimSpace(result.WaitTerminalReason) != "" {
		ciWriteField(out, "Wait:", engine.StyleMuted.Render(result.WaitTerminalReason))
	}

	if !result.ChecksDiscovered {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s\n", engine.StyleMuted.Render("No CI checks discovered."))
		return nil
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s\n", engine.StyleBold.Render("Checks:"))
	for _, check := range result.Checks {
		name := strings.TrimSpace(check.Name)
		if name == "" {
			name = strings.TrimSpace(check.Key)
		}
		if name == "" {
			name = "(unnamed check)"
		}
		fmt.Fprintf(out, "  %s  %s\n", ciRenderCheckIcon(check.Status), name)
	}

	fmt.Fprintln(out)
	ciWriteField(out, "Totals:", engine.StyleMuted.Render(ciRenderTotals(result.Totals)))
	return nil
}

func runCIFix(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	out := io.Writer(os.Stdout)
	opts := ciFixRunOptions{
		MaxAttempts: ciFixMaxAttemptsFlag,
		Engine:      ciFixEngineFlag,
		JSON:        ciFixJSONFlag,
	}

	if cmd != nil {
		out = cmd.OutOrStdout()
		if flags := cmd.Flags(); flags != nil {
			if flags.Lookup("max-attempts") != nil {
				v, err := flags.GetInt("max-attempts")
				if err != nil {
					return err
				}
				opts.MaxAttempts = v
			}
			if flags.Lookup("engine") != nil {
				v, err := flags.GetString("engine")
				if err != nil {
					return err
				}
				opts.Engine = v
			}
			if flags.Lookup("json") != nil {
				v, err := flags.GetBool("json")
				if err != nil {
					return err
				}
				opts.JSON = v
			}
		}
	}

	if opts.MaxAttempts <= 0 {
		err := fmt.Errorf("--max-attempts must be greater than 0")
		if cmd != nil {
			return exitWithCode(cmd, ExitCodeValidation, err)
		}
		return err
	}

	deps := defaultCIFixDeps
	deps.resolveEngine = func(engineName string) (string, error) {
		resolvedEngine, err := resolveEngine(cmd, "engine", engineName, ".")
		if err != nil {
			if cmd != nil {
				return "", exitWithCode(cmd, ExitCodeValidation, err)
			}
			return "", err
		}
		return resolvedEngine, nil
	}

	return runCIFixWithDeps(ctx, opts, out, deps)
}

func runCIFixWithDeps(ctx context.Context, opts ciFixRunOptions, out io.Writer, deps ciFixDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		out = os.Stdout
	}
	if opts.MaxAttempts <= 0 {
		return fmt.Errorf("--max-attempts must be greater than 0")
	}

	if deps.newEngine == nil {
		deps.newEngine = defaultCIFixDeps.newEngine
	}
	if deps.getStatus == nil {
		deps.getStatus = defaultCIFixDeps.getStatus
	}
	if deps.waitForChecks == nil {
		deps.waitForChecks = defaultCIFixDeps.waitForChecks
	}
	if deps.fixWithEngine == nil {
		deps.fixWithEngine = defaultCIFixDeps.fixWithEngine
	}

	var (
		eng           engine.Engine
		attempts      int
		lastFixResult ci.FixResult
	)

	for attempts < opts.MaxAttempts {
		status, err := deps.getStatus(ctx)
		if err != nil {
			return err
		}

		if status.Status != ci.StatusFailing {
			if attempts > 0 {
				if status.Status == ci.StatusPassing {
					return writeCIFixResult(out, opts.JSON, lastFixResult)
				}
				return fmt.Errorf("ci status is %s after attempt %d; run 'hal ci status --wait' for details", status.Status, attempts)
			}
			result := ci.FixResult{
				ContractVersion: ci.FixContractVersion,
				Attempt:         attempts,
				MaxAttempts:     opts.MaxAttempts,
				Applied:         false,
				Branch:          status.Branch,
				Pushed:          false,
				Summary:         fmt.Sprintf("ci status is %s; no fix attempt needed", status.Status),
			}
			return writeCIFixResult(out, opts.JSON, result)
		}

		if eng == nil {
			if deps.resolveEngine != nil {
				resolvedEngine, err := deps.resolveEngine(opts.Engine)
				if err != nil {
					return err
				}
				opts.Engine = resolvedEngine
				deps.resolveEngine = nil
			}

			created, err := deps.newEngine(opts.Engine)
			if err != nil {
				return fmt.Errorf("failed to create engine: %w", err)
			}
			eng = created
		}

		attempt := attempts + 1
		fixResult, err := deps.fixWithEngine(ctx, status, ci.FixOptions{
			Engine:      eng,
			Attempt:     attempt,
			MaxAttempts: opts.MaxAttempts,
		})
		if err != nil {
			return err
		}
		lastFixResult = fixResult

		verified, err := deps.waitForChecks(ctx, ci.WaitOptions{})
		if err != nil {
			return err
		}
		if verified.Status == ci.StatusPassing {
			return writeCIFixResult(out, opts.JSON, fixResult)
		}
		if verified.Status != ci.StatusFailing {
			return fmt.Errorf("ci status is %s after attempt %d; run 'hal ci status --wait' for details", verified.Status, attempt)
		}
		if attempt >= opts.MaxAttempts {
			return fmt.Errorf("ci status is %s after %d attempt(s); run 'hal ci status --wait' for details", verified.Status, attempt)
		}

		attempts = attempt
	}

	return fmt.Errorf("ci fix did not run")
}

func runCIMerge(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	out := io.Writer(os.Stdout)
	opts := ciMergeRunOptions{
		Strategy:      ciMergeStrategyFlag,
		DeleteBranch:  ciMergeDeleteBranchFlag,
		AllowNoChecks: ciMergeAllowNoChecksFlag,
		DryRun:        ciMergeDryRunFlag,
		JSON:          ciMergeJSONFlag,
	}

	if cmd != nil {
		out = cmd.OutOrStdout()
		if flags := cmd.Flags(); flags != nil {
			if flags.Lookup("strategy") != nil {
				v, err := flags.GetString("strategy")
				if err != nil {
					return err
				}
				opts.Strategy = v
			}
			if flags.Lookup("delete-branch") != nil {
				v, err := flags.GetBool("delete-branch")
				if err != nil {
					return err
				}
				opts.DeleteBranch = v
			}
			if flags.Lookup("allow-no-checks") != nil {
				v, err := flags.GetBool("allow-no-checks")
				if err != nil {
					return err
				}
				opts.AllowNoChecks = v
			}
			if flags.Lookup("dry-run") != nil {
				v, err := flags.GetBool("dry-run")
				if err != nil {
					return err
				}
				opts.DryRun = v
			}
			if flags.Lookup("json") != nil {
				v, err := flags.GetBool("json")
				if err != nil {
					return err
				}
				opts.JSON = v
			}
		}
	}

	return runCIMergeWithDeps(ctx, opts, out, defaultCIMergeDeps)
}

func runCIMergeWithDeps(ctx context.Context, opts ciMergeRunOptions, out io.Writer, deps ciMergeDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		out = os.Stdout
	}
	if deps.mergePR == nil {
		deps.mergePR = defaultCIMergeDeps.mergePR
	}
	if deps.currentBranch == nil {
		deps.currentBranch = defaultCIMergeDeps.currentBranch
	}

	strategy, err := ci.NormalizeMergeStrategy(opts.Strategy)
	if err != nil {
		return err
	}

	var result ci.MergeResult

	if opts.DryRun {
		branch, branchErr := deps.currentBranch(ctx)
		if branchErr != nil {
			return branchErr
		}
		branch = strings.TrimSpace(branch)
		if branch == "" {
			return fmt.Errorf("get current branch: empty branch name")
		}

		summary := fmt.Sprintf("dry-run: would merge pull request for branch %s using %s strategy", branch, strategy)
		if opts.DeleteBranch {
			summary += " and delete the remote branch"
		}

		result = ci.MergeResult{
			ContractVersion: ci.MergeContractVersion,
			Strategy:        strategy,
			DryRun:          true,
			Merged:          false,
			BranchDeleted:   false,
			Summary:         summary,
		}
	} else {
		result, err = deps.mergePR(ctx, ci.MergeOptions{
			Strategy:      strategy,
			DeleteBranch:  opts.DeleteBranch,
			AllowNoChecks: opts.AllowNoChecks,
		})
		if err != nil {
			return err
		}
	}

	if opts.JSON {
		data, marshalErr := json.MarshalIndent(result, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("failed to marshal ci merge result: %w", marshalErr)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	if result.DryRun {
		fmt.Fprintf(out, "%s\n", engine.StyleTitle.Render("CI Merge (dry run)"))
		ciWriteField(out, "Strategy:", result.Strategy)
		fmt.Fprintln(out)
		if opts.DeleteBranch {
			fmt.Fprintf(out, "%s\n", engine.StyleMuted.Render("Would merge pull request and delete the remote branch."))
		} else {
			fmt.Fprintf(out, "%s\n", engine.StyleMuted.Render("Would merge pull request."))
		}
		return nil
	}

	fmt.Fprintf(out, "%s\n", engine.StyleTitle.Render("CI Merge"))
	if result.PRNumber > 0 {
		ciWriteField(out, "PR:", engine.StyleInfo.Render(fmt.Sprintf("#%d", result.PRNumber)))
	}
	ciWriteField(out, "Strategy:", result.Strategy)
	statusValue := engine.StyleMuted.Render("Not merged")
	if result.Merged {
		statusValue = engine.StyleSuccess.Render("✓ Merged")
	}
	ciWriteField(out, "Status:", statusValue)

	sha := ciShortSHA(result.MergeCommitSHA)
	if sha != "" {
		fmt.Fprintln(out)
		ciWriteField(out, "Commit:", engine.StyleMuted.Render(sha))
	}
	if result.BranchDeleted {
		ciWriteField(out, "Branch:", engine.StyleSuccess.Render("✓ Deleted"))
	} else if strings.TrimSpace(result.DeleteWarning) != "" {
		ciWriteField(out, "Branch:", engine.StyleWarning.Render("⚠ "+result.DeleteWarning))
	} else if opts.DeleteBranch {
		ciWriteField(out, "Branch:", engine.StyleMuted.Render("Already absent"))
	}
	return nil
}

func writeCIFixResult(out io.Writer, jsonMode bool, result ci.FixResult) error {
	if jsonMode {
		data, marshalErr := json.MarshalIndent(result, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("failed to marshal ci fix result: %w", marshalErr)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	fmt.Fprintf(out, "%s\n", engine.StyleTitle.Render("CI Fix"))

	if !result.Applied {
		summary := strings.TrimSpace(result.Summary)
		if summary == "" {
			summary = "no fix attempt needed"
		}

		lower := strings.ToLower(summary)
		render := engine.StyleMuted.Render
		if strings.Contains(lower, "status is passing") {
			render = engine.StyleSuccess.Render
			summary = "✓ " + summary
		} else if strings.Contains(lower, "status is pending") {
			render = engine.StyleWarning.Render
			summary = "⚠ " + summary
		}

		ciWriteField(out, "Status:", render(summary))
		return nil
	}

	if strings.TrimSpace(result.Branch) != "" {
		ciWriteField(out, "Branch:", engine.StyleInfo.Render(result.Branch))
	}
	if result.MaxAttempts > 0 {
		ciWriteField(out, "Attempt:", fmt.Sprintf("%d/%d", result.Attempt, result.MaxAttempts))
	}
	ciWriteField(out, "Status:", engine.StyleSuccess.Render("✓ Fix applied"))

	sha := ciShortSHA(result.CommitSHA)
	if sha != "" {
		fmt.Fprintln(out)
		ciWriteField(out, "Commit:", engine.StyleMuted.Render(sha))
	}
	if result.Pushed {
		ciWriteField(out, "Pushed:", engine.StyleSuccess.Render("✓"))
	}
	if len(result.FilesChanged) > 0 {
		ciWriteField(out, "Files:", engine.StyleMuted.Render(strings.Join(result.FilesChanged, ", ")))
	}
	return nil
}

func ciCurrentBranch(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	cmd := exec.CommandContext(ctx, "git", "branch", "--show-current")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		stderrText := strings.TrimSpace(stderr.String())
		if stderrText != "" {
			return "", fmt.Errorf("get current branch failed: %s: %w", stderrText, err)
		}
		return "", fmt.Errorf("get current branch failed: %w", err)
	}

	branch := strings.TrimSpace(stdout.String())
	if branch == "" {
		return "", fmt.Errorf("get current branch: empty branch name")
	}

	return branch, nil
}
