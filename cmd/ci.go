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
)

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "Run CI workflow commands",
	Long: `Run CI-aware workflow commands.

Use subcommands to push branches, inspect CI status, apply fixes, and merge safely.

Examples:
  hal ci push
  hal ci push --dry-run
  hal ci push --json`,
	Example: `  hal ci push
  hal ci push --dry-run
  hal ci push --json`,
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

func init() {
	ciPushCmd.Flags().BoolVar(&ciPushDryRunFlag, "dry-run", false, "Preview push/PR behavior without remote side effects")
	ciPushCmd.Flags().BoolVar(&ciPushJSONFlag, "json", false, "Output machine-readable JSON result")

	ciStatusCmd.Flags().BoolVar(&ciStatusWaitFlag, "wait", false, "Wait for checks to complete, timeout, or no-check detection")
	ciStatusCmd.Flags().DurationVar(&ciStatusTimeoutFlag, "timeout", 0, "Wait timeout override (default: internal ci wait timeout)")
	ciStatusCmd.Flags().DurationVar(&ciStatusPollIntervalFlag, "poll-interval", 0, "Polling interval override while waiting (default: internal ci poll interval)")
	ciStatusCmd.Flags().DurationVar(&ciStatusNoChecksGraceFlag, "no-checks-grace", 0, "No-checks grace override before returning no_checks_detected")
	ciStatusCmd.Flags().BoolVar(&ciStatusJSONFlag, "json", false, "Output machine-readable JSON result")

	ciCmd.AddCommand(ciPushCmd)
	ciCmd.AddCommand(ciStatusCmd)
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
		fmt.Fprintf(out, "Dry run: would push branch %s and create or reuse a pull request.\n", result.Branch)
		return nil
	}

	fmt.Fprintln(out, result.Summary)
	if result.PullRequest.URL == "" {
		return nil
	}

	label := "Pull request"
	if result.PullRequest.Existing {
		label = "Pull request (existing)"
	}
	fmt.Fprintf(out, "%s: %s\n", label, result.PullRequest.URL)
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

	if opts.Wait && strings.TrimSpace(result.WaitTerminalReason) != "" {
		fmt.Fprintf(out, "Wait terminal reason: %s\n", result.WaitTerminalReason)
	}
	if strings.TrimSpace(result.Summary) != "" {
		fmt.Fprintln(out, result.Summary)
		return nil
	}

	fmt.Fprintf(out, "status=%s\n", result.Status)
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
