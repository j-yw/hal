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

	ci "github.com/jywlabs/hal/internal/ci"
	"github.com/spf13/cobra"
)

var (
	ciPushDryRunFlag bool
	ciPushJSONFlag   bool
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

func init() {
	ciPushCmd.Flags().BoolVar(&ciPushDryRunFlag, "dry-run", false, "Preview push/PR behavior without remote side effects")
	ciPushCmd.Flags().BoolVar(&ciPushJSONFlag, "json", false, "Output machine-readable JSON result")

	ciCmd.AddCommand(ciPushCmd)
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
